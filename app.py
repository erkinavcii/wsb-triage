import html
import inspect
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import analyzer
import intel_client
import pipeline
import sandbox_manager
import vt_client
import yara_scanner

BASE_DIR = Path(__file__).parent.resolve()
UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR = BASE_DIR / "static"
PORT = int(os.environ.get("SAFEBOX_PORT", "8765"))
API_TOKEN = os.environ.get("SAFEBOX_TOKEN") or secrets.token_hex(16)
TOKEN_FILE = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()) / "SafeBox" / "session.token"

app = FastAPI(title="SafeBox - Zararlı Yazılım & Sandbox Analiz Merkezi")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
watcher = pipeline.DownloadWatcher()


ALLOWED_ORIGINS = {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}", f"http://[::1]:{PORT}"}


def _extract_token(request: Request) -> Optional[str]:
    if "x-safebox-token" in request.headers:
        return request.headers.get("x-safebox-token")
    return request.cookies.get("safebox_token")


def _is_authenticated(request: Request) -> bool:
    tok = _extract_token(request)
    return bool(tok) and secrets.compare_digest(tok, API_TOKEN)


@app.middleware("http")
async def local_only(request: Request, call_next):
    # 1) Host check blocks DNS rebinding.
    host = request.headers.get("host", "").rsplit(":", 1)[0].strip("[]").lower()
    if host not in ("127.0.0.1", "localhost", "::1"):
        return JSONResponse({"detail": "Sadece yerel erişim."}, status_code=403)
    # 2) CSRF: a page on another site (or another local port) must not trigger actions here.
    #    Browsers always send Sec-Fetch-Site and send Origin on POST; non-browser clients send neither.
    is_page = request.method == "GET" and (request.url.path == "/" or request.url.path.startswith("/static/"))
    if not is_page:
        origin = request.headers.get("origin")
        site = request.headers.get("sec-fetch-site")
        if (origin and origin not in ALLOWED_ORIGINS) or (site and site not in ("same-origin", "none")):
            return JSONResponse({"detail": "Başka bir siteden gelen istek reddedildi."}, status_code=403)

    # 3) Local API Token check: protect ALL API endpoints (/api/*), except /api/health and /api/auth.
    open_api = (request.url.path == "/api/health" and request.method in ("GET", "HEAD")) or (
        request.url.path == "/api/auth" and request.method == "POST"
    )
    if request.url.path.startswith("/api/") and not open_api:
        if not _is_authenticated(request):
            return JSONResponse({"detail": "Yetkisiz erişim: API belirteci (token) eksik veya geçersiz."}, status_code=401)

    # 4) Upload size: checked before the body is read (Starlette spools the whole upload to a temp file first).
    if request.url.path == "/api/upload":
        problem = _upload_problem(request.headers.get("content-length"))
        if problem:
            return JSONResponse({"detail": problem[1]}, status_code=problem[0])
    response = await call_next(request)
    # Content-Security-Policy & security headers (strict script-src 'self' & style-src 'self' for main panel)
    is_html_report = (
        request.url.path.endswith("/report")
        and request.query_params.get("format") == "html"
        and response.status_code < 400
    )
    if is_html_report:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "style-src 'unsafe-inline'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'none';"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'none';"
        )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    if not request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    return response


MAX_UPLOAD_BYTES = 4 * 1024 ** 3        # bigger files: pick them by path (no copy needed)
DISK_RESERVE_BYTES = 2 * 1024 ** 3      # always leave this much free


def _upload_problem(content_length: Optional[str]):
    if not content_length or not content_length.isdigit():
        return 411, "Yükleme boyutu bilinmiyor; dosyayı yol seçerek analiz edin."
    size = int(content_length)
    if size > MAX_UPLOAD_BYTES:
        return 413, (f"Dosya {size / 1024 ** 3:.1f} GB; panele bırakma sınırı {MAX_UPLOAD_BYTES // 1024 ** 3} GB. "
                     "Büyük dosyaları 'Dosya' / 'Klasör' butonuyla yol seçerek analiz edin (kopyalama gerekmez).")
    import tempfile
    # the upload is written twice (temp spool + uploads/), possibly on the same drive
    for d in {Path(tempfile.gettempdir()).anchor, UPLOADS_DIR.anchor}:
        free = shutil.disk_usage(d).free
        need = size * (2 if Path(tempfile.gettempdir()).anchor == UPLOADS_DIR.anchor else 1) + DISK_RESERVE_BYTES
        if free < need:
            return 507, f"{d} sürücüsünde yeterli boş alan yok ({free / 1024 ** 3:.1f} GB boş, {need / 1024 ** 3:.1f} GB gerekli)."
    return None


# ------------------------------------------------------------------ models
class ApiKeyRequest(BaseModel):
    api_key: str


class IntelConfigRequest(BaseModel):
    vt_api_key: Optional[str] = None
    mb_api_key: Optional[str] = None
    ha_api_key: Optional[str] = None
    mb_enabled: Optional[bool] = None
    circl_enabled: Optional[bool] = None
    tf_enabled: Optional[bool] = None
    clear_vt: bool = False
    clear_mb: bool = False
    clear_ha: bool = False


class YaraRuleRequest(BaseModel):
    name: str
    content: str


class VtUploadRequest(BaseModel):
    file_path: str


class VboxHardenRequest(BaseModel):
    vm_name: str


class PathRequest(BaseModel):
    path: str


class JobRequest(BaseModel):
    path: str
    password: Optional[str] = ""
    target: Optional[str] = ""
    target_args: Optional[str] = ""
    dll_export: Optional[str] = ""
    duration_min: Optional[int] = 10
    network: Optional[bool] = True
    vt_upload: Optional[bool] = True
    max_vt: Optional[int] = 12
    run_sandbox: Optional[bool] = True
    keep_sandbox_open: Optional[bool] = False
    show_sandbox_window: Optional[bool] = False
    enable_vgpu: Optional[bool] = False
    simulate_user: Optional[bool] = True
    notify: Optional[bool] = True
    memory_mb: Optional[int] = 4096
    run_as_standard_user: Optional[bool] = False
    seed_honeyfiles: Optional[bool] = True
    fake_net: Optional[bool] = False
    sandbox_backend: Optional[str] = "wsb"
    vbox_vm: Optional[str] = ""
    vbox_snapshot: Optional[str] = ""
    vbox_user: Optional[str] = ""
    vbox_password: Optional[str] = ""


class SandboxStartRequest(BaseModel):
    target: Optional[str] = None
    target_args: Optional[str] = None
    dll_export: Optional[str] = None
    duration_min: Optional[int] = None
    memory_mb: Optional[int] = None
    network: Optional[bool] = None
    keep_sandbox_open: Optional[bool] = None
    show_sandbox_window: Optional[bool] = None
    enable_vgpu: Optional[bool] = None
    simulate_user: Optional[bool] = None
    run_as_standard_user: Optional[bool] = None
    seed_honeyfiles: Optional[bool] = None
    fake_net: Optional[bool] = None
    sandbox_backend: Optional[str] = None
    vbox_vm: Optional[str] = None
    vbox_snapshot: Optional[str] = None
    vbox_user: Optional[str] = None
    vbox_password: Optional[str] = None


class SandboxWindowRequest(BaseModel):
    mode: Optional[str] = "front"


class WatchRequest(BaseModel):
    folder: Optional[str] = None
    enabled: bool = False
    auto_start: bool = False


class ContextMenuRequest(BaseModel):
    enabled: bool


class AuthRequest(BaseModel):
    token: str


# ------------------------------------------------------------------ pages / status
@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/auth")
def auth(req: AuthRequest):
    if not secrets.compare_digest(req.token.strip(), API_TOKEN):
        raise HTTPException(401, "Geçersiz erişim belirteci (token).")
    resp = JSONResponse({"status": "ok"})
    resp.set_cookie("safebox_token", API_TOKEN, httponly=True, samesite="strict", path="/")
    return resp


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, token: Optional[str] = None):
    if token is not None:
        if not secrets.compare_digest(token.strip(), API_TOKEN):
            return HTMLResponse((STATIC_DIR / "auth.html").read_text(encoding="utf-8"), status_code=401)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie("safebox_token", API_TOKEN, httponly=True, samesite="strict", path="/")
        return resp
    if not _is_authenticated(request):
        return HTMLResponse((STATIC_DIR / "auth.html").read_text(encoding="utf-8"), status_code=401)
    html_text = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    safe_tok = html.escape(API_TOKEN, quote=True)
    return HTMLResponse(
        html_text.replace('<meta name="safebox-token" content="" />', f'<meta name="safebox-token" content="{safe_tok}" />')
    )


def _mask_key(k: str) -> str:
    if not k:
        return ""
    return (k[:4] + "..." + k[-4:]) if len(k) > 8 else "****"


@app.get("/api/system-status")
def system_status():
    caps = sandbox_manager.get_system_capabilities()
    key = vt_client.get_api_key()
    caps["vt_api_configured"] = bool(key)
    caps["vt_api_masked"] = _mask_key(key)
    caps["procmon"] = any((BASE_DIR / "sandbox" / n).exists() for n in ("Procmon64.exe", "Procmon.exe"))
    caps["yara"] = yara_scanner.rules_status()
    icfg = pipeline._get_intel_config()
    caps["mb_enabled"] = icfg["mb_enabled"]
    caps["circl_enabled"] = bool(icfg.get("circl_enabled", False))
    caps["tf_enabled"] = bool(icfg.get("tf_enabled", False))
    caps["mb_api_configured"] = bool(icfg["mb_api_key"])
    caps["mb_api_masked"] = _mask_key(icfg["mb_api_key"])
    caps["ha_api_configured"] = bool(icfg["ha_api_key"])
    caps["ha_api_masked"] = _mask_key(icfg["ha_api_key"])
    caps["context_menu"] = sandbox_manager.context_menu_status()
    return caps


# ------------------------------------------------------------------ VirusTotal (manual buttons)
@app.post("/api/vt/config")
def save_vt_config(req: ApiKeyRequest):
    vt_client.set_api_key(req.api_key)
    return {"status": "ok", "configured": bool(req.api_key.strip())}


@app.post("/api/intel/config")
def save_intel_config(req: IntelConfigRequest):
    if req.clear_vt:
        vt_client.set_api_key("")
    elif req.vt_api_key is not None and req.vt_api_key.strip():
        vt_client.set_api_key(req.vt_api_key.strip())
    mb_val = "" if req.clear_mb else (req.mb_api_key.strip() if req.mb_api_key and req.mb_api_key.strip() else None)
    ha_val = "" if req.clear_ha else (req.ha_api_key.strip() if req.ha_api_key and req.ha_api_key.strip() else None)
    sig_params = inspect.signature(intel_client.set_intel_config).parameters
    kwargs = {"mb_api_key": mb_val, "ha_api_key": ha_val, "mb_enabled": req.mb_enabled}
    fallback_extra = {}
    if "circl_enabled" in sig_params:
        kwargs["circl_enabled"] = req.circl_enabled
    elif req.circl_enabled is not None:
        fallback_extra["circl_enabled"] = bool(req.circl_enabled)
    if "tf_enabled" in sig_params:
        kwargs["tf_enabled"] = req.tf_enabled
    elif req.tf_enabled is not None:
        fallback_extra["tf_enabled"] = bool(req.tf_enabled)
    icfg = intel_client.set_intel_config(**kwargs)
    if fallback_extra:
        raw_cfg = vt_client.load_config()
        raw_cfg.update(fallback_extra)
        vt_client.save_config(raw_cfg)
    icfg = pipeline._get_intel_config()
    return {
        "status": "ok",
        "vt_configured": bool(vt_client.get_api_key()),
        "mb_enabled": icfg["mb_enabled"],
        "circl_enabled": bool(icfg.get("circl_enabled", False)),
        "tf_enabled": bool(icfg.get("tf_enabled", False)),
        "mb_configured": bool(icfg["mb_api_key"]),
        "ha_configured": bool(icfg["ha_api_key"]),
    }


@app.get("/api/intel/query/{sha256}")
def intel_query_hash(sha256: str):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise HTTPException(400, "Geçersiz SHA-256")
    icfg = pipeline._get_intel_config()
    q_params = inspect.signature(intel_client.query_hash_intel).parameters
    kwargs = {}
    if "run_circl" in q_params:
        kwargs["run_circl"] = bool(icfg.get("circl_enabled", False))
    if "run_tf" in q_params:
        kwargs["run_tf"] = bool(icfg.get("tf_enabled", False))
    return intel_client.query_hash_intel(sha256, **kwargs)


@app.get("/api/vt/query/{sha256}")
def vt_query_hash(sha256: str):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise HTTPException(400, "Geçersiz SHA-256")
    return vt_client.query_virustotal_hash(sha256)


@app.post("/api/vt/upload")
def vt_upload_file(req: VtUploadRequest):
    p = Path(req.file_path).resolve()
    if not pipeline.is_sample_file(p):
        raise HTTPException(400, "Sadece analiz edilen örneklerin dosyaları yüklenebilir.")
    return vt_client.upload_file_to_virustotal(str(p))


# ------------------------------------------------------------------ analysis jobs
_BATCH_RX = re.compile(r"[a-f0-9]{8,32}")


def _safe_relpath(rel: str, fallback: str) -> List[str]:
    """Browser-supplied relative path -> safe path components (no '..', no drive/root, no reserved characters)."""
    parts = []
    for comp in re.split(r"[\\/]+", rel or ""):
        comp = comp.strip().rstrip(". ")
        if not comp or comp in (".", ".."):
            continue
        comp = re.sub(r'[<>:"|?*\x00-\x1f]', "_", comp)[:120]
        if comp:
            parts.append(comp)
    parts = parts[-20:]
    return parts or [Path(fallback).name or "yuklenen_dosya.bin"]


def _dir_size(d: Path) -> int:
    return sum(p.stat().st_size for p in d.rglob("*") if p.is_file()) if d.exists() else 0


@app.post("/api/upload")
def upload_file(file: UploadFile = File(...), batch: Optional[str] = Form(None), relpath: Optional[str] = Form(None)):
    """Single file -> uploads/<name>/<name>. Several files/folders dropped together -> one batch folder
    uploads/batch_<id>/<relative path>, analysed as one sample (the panel then starts a job on batch_dir)."""
    safe_name = Path(file.filename or "yuklenen_dosya.bin").name
    batch_dir = None
    if batch is not None:
        if not _BATCH_RX.fullmatch(batch):
            raise HTTPException(400, "Geçersiz yükleme grubu.")
        batch_dir = (UPLOADS_DIR / f"batch_{batch}").resolve()
        dest = batch_dir.joinpath(*_safe_relpath(relpath or "", safe_name)).resolve()
        if batch_dir not in dest.parents:
            raise HTTPException(400, "Geçersiz dosya yolu.")
        already = _dir_size(batch_dir)
        dest.parent.mkdir(parents=True, exist_ok=True)
    else:
        already = 0
        dest_dir = UPLOADS_DIR / re.sub(r"[^\w.-]", "_", safe_name)[:60]
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / safe_name
    written = 0
    try:
        with open(dest, "wb") as buf:
            while chunk := file.file.read(8 * 1024 * 1024):
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:      # Content-Length can lie; enforce the real size too
                    raise HTTPException(413, f"Dosya {MAX_UPLOAD_BYTES // 1024 ** 3} GB sınırını aşıyor.")
                if already + written > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"Birlikte bırakılan dosyaların toplamı {MAX_UPLOAD_BYTES // 1024 ** 3} GB sınırını aşıyor.")
                buf.write(chunk)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    out = {"path": str(dest)}
    if batch_dir is not None:
        out["batch_dir"] = str(batch_dir)
    return out


@app.post("/api/jobs")
def start_job(req: JobRequest):
    try:
        job = pipeline.create_job(req.path, req.model_dump())
    except pipeline.PipelineError as e:
        raise HTTPException(400, str(e))
    return {"id": job.id}


@app.get("/api/jobs")
def jobs():
    return pipeline.list_jobs()


@app.get("/api/compare")
def compare(base: str, target: str):
    if base == target:
        raise HTTPException(400, "Karşılaştırmak için iki farklı analiz seçin.")
    return pipeline.compare_jobs(_job(base), _job(target))


def _job(case_id: str) -> pipeline.Job:
    job = pipeline.get_job(case_id)
    if not job:
        raise HTTPException(404, "Analiz bulunamadı")
    return job


@app.get("/api/jobs/{case_id}")
def job_state(case_id: str):
    job = _job(case_id)
    st = job.snapshot()
    st["case_dir"] = str(job.case_dir)
    st["has_pcap"] = (job.output_dir / "capture.pcapng").exists()
    st["has_procmon"] = (job.output_dir / "procmon.pml").exists()
    st["procmon_summary"] = pipeline._read_json(job.output_dir / "procmon_summary.json")
    st["has_report"] = (job.case_dir / "report.md").exists()
    st["screenshots"] = pipeline.list_screenshots(job)
    st["has_live_screen"] = pipeline.live_screen_path(job) is not None
    st["runnable_targets"] = pipeline.list_runnable_targets(job)
    return st


@app.post("/api/jobs/{case_id}/sandbox")
def job_run_sandbox(case_id: str, req: Optional[SandboxStartRequest] = Body(default=None)):
    job = _job(case_id)
    try:
        overrides = req.model_dump(exclude_none=True) if req else None
        pipeline.start_sandbox_later(job, overrides=overrides)
    except pipeline.PipelineError as e:
        raise HTTPException(409, str(e))
    return {"status": "started"}


@app.post("/api/jobs/{case_id}/cancel")
def job_cancel(case_id: str):
    try:
        pipeline.request_cancel(_job(case_id))
    except pipeline.PipelineError as e:
        raise HTTPException(409, str(e))
    return {"status": "ok"}


@app.delete("/api/jobs/{case_id}")
def job_delete(case_id: str):
    try:
        pipeline.delete_job(case_id)
    except pipeline.PipelineError as e:
        raise HTTPException(409, str(e))
    return {"status": "deleted"}


class CleanupRequest(BaseModel):
    days: int = 30


@app.post("/api/jobs-cleanup")
def jobs_cleanup(req: CleanupRequest):
    if req.days < 1:
        raise HTTPException(400, "En az 1 gün.")
    return {"deleted": pipeline.cleanup_jobs(req.days)}


@app.post("/api/jobs/{case_id}/stop")
def job_stop(case_id: str):
    pipeline.request_stop(_job(case_id))
    return {"status": "ok"}


@app.get("/api/jobs/{case_id}/report", response_class=PlainTextResponse)
def job_report(case_id: str, format: str = "md"):
    job = _job(case_id)
    if format == "html":
        p = job.case_dir / "report.html"
        if not p.exists():
            raise HTTPException(404, "HTML rapor henüz yok")
        return HTMLResponse(p.read_text(encoding="utf-8"))
    elif format == "json":
        p = job.case_dir / "state.json"
        if not p.exists():
            raise HTTPException(404, "Rapor henüz yok")
        return JSONResponse(json.loads(p.read_text(encoding="utf-8")))
    p = job.case_dir / "report.md"
    if not p.exists():
        raise HTTPException(404, "Rapor henüz yok")
    return p.read_text(encoding="utf-8")


@app.get("/api/jobs/{case_id}/iocs")
def job_iocs(case_id: str, format: str = "stix", include_noise: bool = False):
    job = _job(case_id)
    fmt = (format or "stix").lower()
    if fmt == "csv":
        data = pipeline.export_iocs_csv(job, include_noise=include_noise)
        return Response(
            content=data,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="iocs_{job.id}.csv"'},
        )
    if fmt in ("stix", "json"):
        bundle = pipeline.export_iocs_stix(job, include_noise=include_noise)
        return JSONResponse(
            content=bundle,
            media_type="application/stix+json",
            headers={"Content-Disposition": f'attachment; filename="iocs_{job.id}.stix.json"'},
        )
    raise HTTPException(400, "Geçersiz format (csv veya stix olmalı).")


@app.get("/api/jobs/{case_id}/live-screen")
def job_live_screen(case_id: str):
    p = pipeline.live_screen_path(_job(case_id))
    if not p:
        raise HTTPException(404, "Canlı görüntü henüz yok")
    try:
        data = p.read_bytes()
    except OSError:                      # the sandbox is overwriting it right now
        raise HTTPException(503, "Görüntü yazılıyor, birazdan tekrar deneyin")
    return Response(content=data, media_type="image/png")


@app.get("/api/jobs/{case_id}/screenshots/{name}")
def job_screenshot(case_id: str, name: str):
    job = _job(case_id)
    scr_dir = job.output_dir / "screenshots"
    p = scr_dir / name
    if not pipeline.is_valid_screenshot_file(p, scr_dir):
        raise HTTPException(404, "Ekran görüntüsü bulunamadı")
    return Response(
        content=p.read_bytes(),
        media_type="image/png",
        headers={"Content-Disposition": f'inline; filename="{p.name}"'},
    )


@app.post("/api/jobs/{case_id}/open")
def job_open(case_id: str, what: str = "folder"):
    job = _job(case_id)
    if what == "pcap":
        p = job.output_dir / "capture.pcapng"
        if not p.exists():
            raise HTTPException(404, "Ağ kaydı yok")
        if not sandbox_manager.tshark_path():
            raise HTTPException(400, "Wireshark kurulu değil")
        os.startfile(str(p))
    elif what == "procmon":
        p = job.output_dir / "procmon.pml"
        if not p.exists():
            raise HTTPException(404, "Process Monitor kaydı yok")
        os.startfile(str(p))
    elif what == "report":
        p = job.case_dir / "report.md"
        if not p.exists():
            raise HTTPException(404, "Rapor henüz yok")
        os.startfile(str(p))
    else:
        os.startfile(str(job.case_dir))
    return {"status": "ok"}


def _format_hex_dump(data: bytes) -> str:
    lines: list[str] = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hex_part:<47}  |{ascii_part}|")
    return "\n".join(lines)


@app.get("/api/jobs/{case_id}/preview")
def job_preview_file(case_id: str, file_path: str, mode: str = "text"):
    job = _job(case_id)
    if mode not in ("text", "strings", "hex"):
        raise HTTPException(400, "Geçersiz önizleme modu (text, strings veya hex olmalı).")
    try:
        raw_p = Path(file_path)
        if raw_p.is_symlink():
            raise HTTPException(400, "Sembolik bağlantılar önizlenemez.")
        p = raw_p.resolve()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, "Geçersiz dosya yolu.")
    allowed_roots = [job.input_dir.resolve(), job.unpacked_dir.resolve()]
    if not any(r in p.parents for r in allowed_roots):
        raise HTTPException(400, "Yalnızca bu analizin örnek dosyaları önizlenebilir.")
    if not p.is_file():
        raise HTTPException(404, "Dosya bulunamadı.")

    total_size = p.stat().st_size
    limit = 16384 if mode == "hex" else 131072
    with open(p, "rb") as f:
        data = f.read(limit)
    truncated = total_size > len(data)

    if mode == "hex":
        content = _format_hex_dump(data)
    elif mode == "strings":
        content = analyzer.extract_printable_strings(data, min_len=4)[:120000]
    else:
        decoded = data.decode("utf-8", errors="replace")
        non_print = sum(1 for c in decoded[:4096] if ord(c) < 32 and c not in "\r\n\t")
        prefix = ""
        if decoded and (non_print / max(1, min(len(decoded), 4096))) > 0.25:
            prefix = "[İkili dosya — metin görünümü]\n\n"
        content = prefix + decoded

    return {
        "file": p.name,
        "mode": mode,
        "size": total_size,
        "truncated": truncated,
        "content": content,
    }


# ------------------------------------------------------------------ downloads watcher
@app.get("/api/watch")
def watch_status():
    return watcher.status()


@app.post("/api/watch")
def watch_configure(req: WatchRequest):
    return watcher.configure(req.folder, req.enabled, req.auto_start)


# ------------------------------------------------------------------ helpers
@app.get("/api/browse-dialog")
def browse_dialog(mode: str = "file"):
    if mode == "folder":
        ps = ("Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.FolderBrowserDialog; "
              "$f.Description = 'Analiz edilecek klasoru secin'; if ($f.ShowDialog() -eq 'OK') { Write-Output $f.SelectedPath }")
    else:
        ps = ("Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.OpenFileDialog; "
              "$f.Title = 'Analiz edilecek dosyayi veya arsivi secin'; if ($f.ShowDialog() -eq 'OK') { Write-Output $f.FileName }")
    proc = subprocess.run(["powershell", "-NoProfile", "-Sta", "-Command", ps], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return {"selected_path": proc.stdout.strip()}


@app.post("/api/sandbox/focus")
def sandbox_focus(req: Optional[SandboxWindowRequest] = None):
    return sandbox_manager.arrange_sandbox_window((req.mode if req else "front") != "back")


@app.post("/api/sandbox/enable")
def enable_wsb():
    return sandbox_manager.enable_windows_sandbox_feature()


@app.post("/api/vbox/harden")
def harden_vbox(req: VboxHardenRequest):
    return sandbox_manager.harden_and_snapshot_virtualbox_vm(req.vm_name)


@app.get("/api/vbox/snapshots/{vm_name}")
def vbox_snapshots(vm_name: str):
    return {"vm_name": vm_name, "snapshots": sandbox_manager.list_vbox_snapshots(vm_name)}


@app.get("/api/yara/rules")
def yara_rules_list():
    return {"status": yara_scanner.rules_status(), "files": yara_scanner.list_rule_files()}


@app.get("/api/yara/rules/{name}")
def yara_rule_read(name: str):
    try:
        return {"name": name, "content": yara_scanner.read_rule_file(name)}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError:
        raise HTTPException(404, "YARA kural dosyası bulunamadı.")


@app.post("/api/yara/rules")
def yara_rule_save(req: YaraRuleRequest):
    try:
        return yara_scanner.save_custom_rule_file(req.name, req.content)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.delete("/api/yara/rules/{name}")
def yara_rule_delete(name: str):
    try:
        return yara_scanner.delete_custom_rule_file(name)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError:
        raise HTTPException(404, "YARA kural dosyası bulunamadı.")


@app.post("/api/context-menu")
def toggle_context_menu(req: ContextMenuRequest):
    return sandbox_manager.set_context_menu(req.enabled)


@app.post("/api/demo")
def make_demo():
    """Creates a harmless folder that imitates a cracked installer (tampered DLL + fake loader script)."""
    demo_dir = BASE_DIR / "demo_supheli_paket"
    demo_dir.mkdir(parents=True, exist_ok=True)
    (demo_dir / "crack_loader_demo.bat").write_text(
        "@echo off\n"
        "REM --- SAFEBOX TESTI ICIN ZARARSIZ SIMULASYON ---\n"
        "echo SafeBox demo > \"%TEMP%\\safebox_demo_test.txt\"\n"
        "copy /y \"%~dp0Signed_Installer_Helper.exe\" \"%APPDATA%\\safebox_demo_dropped.exe\" >nul\n"
        "REM schtasks /create /tn \"UpdaterTask\" /tr \"powershell -WindowStyle Hidden -enc AAAA\"\n"
        "REM \\Google\\Chrome\\User Data\\Default\\Login Data\n"
        "REM https://api.telegram.org/bot123456:ABCDEF/sendMessage\n"
        "REM VIRTUALBOX VMWARE SbieDll.dll\n"
        "ping -n 5 127.0.0.1 >nul\n",
        encoding="utf-8",
    )
    notepad = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe"
    if notepad.exists():
        shutil.copy2(notepad, demo_dir / "Signed_Installer_Helper.exe")
        shutil.copy2(notepad, demo_dir / "amtlib.dll")
        with open(demo_dir / "amtlib.dll", "ab") as f:
            f.write(b"\x00PATCHED_BY_CRACK_SIMULATION_CryptUnprotectData_VirtualAllocEx\x00")
    return {"path": str(demo_dir), "target": "crack_loader_demo.bat"}


if __name__ == "__main__":
    import uvicorn
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(API_TOKEN, encoding="utf-8")
    if os.name != "nt":
        os.chmod(TOKEN_FILE, 0o600)
    print(f"SafeBox Web Panel: http://127.0.0.1:{PORT}/?token={API_TOKEN}", flush=True)
    try:
        uvicorn.run(app, host="127.0.0.1", port=PORT)
    finally:
        TOKEN_FILE.unlink(missing_ok=True)
