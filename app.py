import json
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import analyzer
import pipeline
import sandbox_manager
import vt_client

BASE_DIR = Path(__file__).parent.resolve()
UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR = BASE_DIR / "static"
PORT = int(os.environ.get("SAFEBOX_PORT", "8765"))
API_TOKEN = os.environ.get("SAFEBOX_TOKEN") or secrets.token_hex(16)

app = FastAPI(title="SafeBox - Zararlı Yazılım & Sandbox Analiz Merkezi")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
watcher = pipeline.DownloadWatcher()


ALLOWED_ORIGINS = {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}", f"http://[::1]:{PORT}"}


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

    # 3) Local API Token check: protect mutating API endpoints (/api/jobs, /api/watch, etc.)
    # Browser UI sends X-SafeBox-Token (passed via initial index HTML) or cookie
    if request.url.path.startswith("/api/") and request.method not in ("GET", "HEAD", "OPTIONS"):
        token = request.headers.get("X-SafeBox-Token") or request.cookies.get("safebox_token")
        if not token or not secrets.compare_digest(token, API_TOKEN):
            return JSONResponse({"detail": "Yetkisiz erişim: API belirteci (token) eksik veya geçersiz."}, status_code=401)

    # 4) Upload size: checked before the body is read (Starlette spools the whole upload to a temp file first).
    if request.url.path == "/api/upload":
        problem = _upload_problem(request.headers.get("content-length"))
        if problem:
            return JSONResponse({"detail": problem[1]}, status_code=problem[0])
            return JSONResponse({"detail": problem[1]}, status_code=problem[0])
    response = await call_next(request)
    # Content-Security-Policy & security headers
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "script-src 'self' 'unsafe-eval' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
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
    duration_min: Optional[int] = 10
    network: Optional[bool] = True
    vt_upload: Optional[bool] = True
    max_vt: Optional[int] = 12
    run_sandbox: Optional[bool] = True
    keep_sandbox_open: Optional[bool] = False
    memory_mb: Optional[int] = 4096


class WatchRequest(BaseModel):
    folder: Optional[str] = None
    enabled: bool = False
    auto_start: bool = False


# ------------------------------------------------------------------ pages / status
@app.get("/", response_class=HTMLResponse)
async def index():
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    resp = HTMLResponse(html.replace('window.__SAFEBOX_TOKEN__ = "";', f'window.__SAFEBOX_TOKEN__ = "{API_TOKEN}";'))
    resp.set_cookie("safebox_token", API_TOKEN, httponly=True, samesite="strict")
    return resp


@app.get("/api/system-status")
def system_status():
    caps = sandbox_manager.get_system_capabilities()
    key = vt_client.get_api_key()
    caps["vt_api_configured"] = bool(key)
    caps["vt_api_masked"] = (key[:4] + "..." + key[-4:]) if len(key) > 8 else ""
    caps["procmon"] = any((BASE_DIR / "sandbox" / n).exists() for n in ("Procmon64.exe", "Procmon.exe"))
    return caps


# ------------------------------------------------------------------ VirusTotal (manual buttons)
@app.post("/api/vt/config")
def save_vt_config(req: ApiKeyRequest):
    vt_client.set_api_key(req.api_key)
    return {"status": "ok", "configured": bool(req.api_key.strip())}


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
@app.post("/api/upload")
def upload_file(file: UploadFile = File(...)):
    safe_name = Path(file.filename or "yuklenen_dosya.bin").name
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
                buf.write(chunk)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return {"path": str(dest)}


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
    st["has_report"] = (job.case_dir / "report.md").exists()
    return st


@app.post("/api/jobs/{case_id}/sandbox")
def job_run_sandbox(case_id: str):
    job = _job(case_id)
    try:
        pipeline.start_sandbox_later(job)
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
    elif what == "report":
        os.startfile(str(job.case_dir / "report.md"))
    else:
        os.startfile(str(job.case_dir))
    return {"status": "ok"}


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


@app.post("/api/sandbox/enable")
def enable_wsb():
    return sandbox_manager.enable_windows_sandbox_feature()


@app.post("/api/vbox/harden")
def harden_vbox(req: VboxHardenRequest):
    return sandbox_manager.harden_and_snapshot_virtualbox_vm(req.vm_name)


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
    uvicorn.run(app, host="127.0.0.1", port=PORT)
