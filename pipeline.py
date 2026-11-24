"""SafeBox automatic analysis pipeline.

extract -> inventory (hash + Authenticode) -> static (PE/strings) -> VirusTotal -> Windows Sandbox -> report

Each analysis is a "case" folder under cases/:
    input/   sample copy / extracted archive (mapped read-only into the sandbox)
    tools/   monitor script + config (read-only in the sandbox; host writes stop.flag here)
    output/  written by the sandbox: live.json, behavior.json, capture.pcapng, timeline.log
    state.json, inventory.json, report.md
"""
import csv
import hashlib
import inspect
import io
import ipaddress
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import traceback
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import analyzer
import intel_client
import sandbox_manager as sbm
import vt_client

BASE_DIR = Path(__file__).parent.resolve()
CASES_DIR = BASE_DIR / "cases"
CASES_DIR.mkdir(parents=True, exist_ok=True)
MONITOR_SCRIPT = BASE_DIR / "sandbox" / "Inside-Sandbox.ps1"
NO_WINDOW = 0x08000000

ARCHIVE_EXT = {".rar", ".zip", ".7z", ".001", ".cab", ".iso", ".gz", ".tgz", ".tar", ".xz", ".bz2"}
SCRIPT_EXT = {".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar", ".msi", ".scr", ".com", ".reg", ".pif"}
DOC_EXT = {".lnk", ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".pdf"}
RUNNABLE_EXT = SCRIPT_EXT | {".exe", ".dll"}
NAME_RX = re.compile(r"crack|patch|activat|keygen|loader|inject|amtlib|genp|unlock|bypass|kms|serial|license", re.I)

STAGES = [
    ("extract", "Dosyayı hazırla / arşivi aç"),
    ("inventory", "Hash & dijital imza"),
    ("static", "Statik analiz (PE, metin izleri)"),
    ("vt", "VirusTotal"),
    ("sandbox", "Windows Sandbox (canlı izleme)"),
    ("report", "Ağ özeti & rapor"),
]

DEFAULT_OPTIONS = {
    "password": "",
    "target": "",
    "target_args": "",
    "dll_export": "",
    "duration_min": 10,
    "network": True,
    "vt_upload": True,
    "max_vt": 12,
    "run_sandbox": True,
    "keep_sandbox_open": False,
    "simulate_user": True,
    "notify": True,
    "memory_mb": 4096,
    "run_as_standard_user": False,
    "seed_honeyfiles": True,
    "fake_net": False,
    "sandbox_backend": "wsb",
    "vbox_vm": "",
    "vbox_snapshot": "",
    "vbox_user": "",
    "vbox_password": "",
}

COPY_INTO_SANDBOX_MAX_MB = 1024   # samples above this run directly from the read-only mapped folder
MAX_UNPACK_RATIO = 1000            # unpacked/packed above this (and > 1 GB) = zip bomb
DISK_RESERVE_BYTES = 2 * 1024 ** 3  # keep this much free when extracting
TSHARK_TIMEOUT_SEC = 300          # per tshark query; a timeout gives a partial network summary, not a failed analysis
SIGCHECK_BATCH = 500              # files per Authenticode check run
MONITOR_DEAD_SEC = 180            # no live.json update for this long while observing -> monitor considered killed
AV_SETTLE_SEC = 3                 # pause before hashing so real-time antivirus can quarantine files first

JOBS: Dict[str, "Job"] = {}
JOBS_LOCK = threading.Lock()
SANDBOX_LOCK = threading.Lock()


class PipelineError(Exception):
    pass


class Cancelled(Exception):
    """Raised at a safe point after the user pressed 'İptal'."""


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def _write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


# ======================================================================== Job
class Job:
    def __init__(self, case_dir: Path, state: Dict[str, Any], password: str = "", vbox_password: str = ""):
        self.case_dir = case_dir
        self.state = state
        self.lock = threading.RLock()
        # Passwords live only in memory: never in state.json, never in API responses.
        self.password = password
        self.vbox_password = vbox_password

    def check_cancel(self) -> None:
        if self.state.get("cancel_requested"):
            raise Cancelled()

    def snapshot(self) -> Dict[str, Any]:
        """Deep copy of the state that is safe to serialize while worker threads keep changing it."""
        for _ in range(20):
            try:
                with self.lock:
                    return json.loads(json.dumps(self.state, ensure_ascii=False))
            except RuntimeError:          # "dictionary changed size during iteration" from an unlocked writer
                time.sleep(0.01)
        with self.lock:
            return json.loads(json.dumps(self.state, ensure_ascii=False))

    @property
    def id(self) -> str:
        return self.state["id"]

    def opt(self, key: str) -> Any:
        return self.state["options"].get(key, DEFAULT_OPTIONS.get(key))

    @property
    def input_dir(self) -> Path:
        """Sample root: the user's own folder (mapped read-only, never copied) or case/input for files/archives."""
        p = self.state.get("input_path")
        return Path(p) if p else self.case_dir / "input"

    @property
    def output_dir(self) -> Path:
        return self.case_dir / "output"

    @property
    def tools_dir(self) -> Path:
        return self.case_dir / "tools"

    @property
    def unpacked_dir(self) -> Path:
        """Extracted installer payloads (MSI/NSIS/SFX) inspected statically without altering sandbox input."""
        return self.case_dir / "unpacked"

    def save(self) -> None:
        snap = self.snapshot()
        with self.lock:
            _write_json(self.case_dir / "state.json", snap)

    def log(self, msg: str) -> None:
        with self.lock:
            self.state["log"].append({"t": datetime.now().strftime("%H:%M:%S"), "msg": msg})
            self.state["log"] = self.state["log"][-300:]
        self.save()

    def stage(self, key: str, status: str, msg: Optional[str] = None) -> None:
        with self.lock:
            st = self.state["stages"][key]
            st["status"] = status
            if msg is not None:
                st["msg"] = msg
            if status == "running" and not st.get("started"):
                st["started"] = _now()
            if status in ("done", "error", "skipped", "unavailable"):
                st["ended"] = _now()
        self.save()

    def summary(self) -> Dict[str, Any]:
        s = self.state
        return {"id": s["id"], "sample": s["sample"], "created": s["created"], "status": s["status"],
                "verdict": (s.get("verdict") or {}).get("level", "pending")}


def _new_state(case_id: str, sample: str, options: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": case_id,
        "sample": sample,
        "created": _now(),
        "status": "running",
        "options": options,
        "stages": {k: {"label": label, "status": "pending", "msg": ""} for k, label in STAGES},
        "log": [],
        "inventory": {},
        "static": [],
        "vt": [],
        "sandbox": {"live": None, "status_text": ""},
        "behavior": None,
        "network": None,
        "verdict": {"level": "pending", "red": [], "notes": []},
    }


def create_job(sample_path: str, options: Optional[Dict[str, Any]] = None) -> Job:
    src = Path(sample_path.strip().strip('"').strip("'"))
    if not src.exists():
        raise PipelineError(f"Dosya veya klasör bulunamadı: {src}")
    opts = dict(DEFAULT_OPTIONS)
    opts.update({k: v for k, v in (options or {}).items() if k in DEFAULT_OPTIONS and v is not None})
    try:
        opts["memory_mb"] = max(1024, min(65536, int(opts.get("memory_mb") or 4096)))
    except (TypeError, ValueError):
        opts["memory_mb"] = 4096
    try:
        opts["duration_min"] = max(1, min(180, int(opts.get("duration_min") or 10)))
    except (TypeError, ValueError):
        opts["duration_min"] = 10
    password = opts.pop("password", "") or ""
    opts["has_password"] = bool(password)
    vbox_password = opts.pop("vbox_password", "") or ""
    opts["has_vbox_password"] = bool(vbox_password)
    opts["sandbox_backend"] = "vbox" if opts.get("sandbox_backend") == "vbox" else "wsb"
    safe = re.sub(r"[^\w.-]", "_", src.name)[:40] or "sample"
    case_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}_{safe}"
    if (CASES_DIR / case_id).exists():      # two jobs for the same file within one second
        case_id = f"{case_id}_{uuid.uuid4().hex[:4]}"
    case_dir = CASES_DIR / case_id
    for sub in ("input", "output", "tools"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    job = Job(case_dir, _new_state(case_id, str(src.resolve()), opts), password, vbox_password=vbox_password)
    job.save()
    with JOBS_LOCK:
        JOBS[case_id] = job
    threading.Thread(target=run_job, args=(job,), daemon=True, name=f"job-{case_id}").start()
    return job


def get_job(case_id: str) -> Optional[Job]:
    with JOBS_LOCK:
        if case_id in JOBS:
            return JOBS[case_id]
    case_dir = CASES_DIR / case_id
    if not re.fullmatch(r"[\w.-]+", case_id) or not case_dir.is_dir():
        return None
    state = _read_json(case_dir / "state.json")
    if not state:
        return None
    job = Job(case_dir, state)
    with JOBS_LOCK:
        JOBS[case_id] = job
    return job


def is_sample_file(path: Path) -> bool:
    """True if path is a file inside some analysis' sample root (case input folder or the user's mapped folder)."""
    path = Path(path).resolve()
    if not path.is_file():
        return False
    roots = [CASES_DIR.resolve()]
    for d in CASES_DIR.iterdir():
        st = _read_json(d / "state.json") if d.is_dir() else None
        if st and st.get("input_path"):
            roots.append(Path(st["input_path"]).resolve())
    return any(r == path or r in path.parents for r in roots)


def list_jobs(limit: int = 30) -> List[Dict[str, Any]]:
    out = []
    for d in sorted(CASES_DIR.iterdir(), reverse=True)[:limit]:
        if d.is_dir():
            job = get_job(d.name)
            if job:
                out.append(job.summary())
    return out


def load_interrupted() -> None:
    """Marks cases that were running when the server stopped."""
    for d in CASES_DIR.iterdir():
        state = _read_json(d / "state.json") if d.is_dir() else None
        if state and state.get("status") == "running":
            state["status"] = "interrupted"
            for st in state["stages"].values():
                if st["status"] == "running":
                    st["status"] = "error"
                    st["msg"] = "Sunucu kapandığı için yarıda kaldı."
            _write_json(d / "state.json", state)


# ======================================================================== runner
def _mark_cancelled(job: Job, current: Optional[str]) -> None:
    job.log("Analiz kullanıcı tarafından iptal edildi.")
    for key, st in job.state["stages"].items():
        if st["status"] in ("pending", "running", "queued", "waiting"):
            job.stage(key, "skipped", "İptal edildi." if key == current or st["status"] != "pending" else "İptal nedeniyle atlandı.")
    job.state["status"] = "cancelled"
    job.state.pop("cancel_requested", None)


def run_job(job: Job) -> None:
    current = None
    try:
        for key, fn in (("extract", stage_extract), ("inventory", stage_inventory), ("static", stage_static), ("vt", stage_vt)):
            job.check_cancel()
            current = key
            fn(job)
            compute_verdict(job)
        job.check_cancel()
        current = "sandbox"
        if job.opt("run_sandbox"):
            stage_sandbox(job)
        else:
            job.stage("sandbox", "waiting", "Hazır. Örneği izole ortamda çalıştırmak için 'Sandbox'ta Çalıştır' butonuna basın.")
        current = "report"
        stage_report(job)
        job.state["status"] = "waiting_sandbox" if job.state["stages"]["sandbox"]["status"] == "waiting" else "done"
    except Cancelled:
        _mark_cancelled(job, current)
    except Exception as e:
        job.log(f"HATA ({current}): {e}")
        if current:
            job.stage(current, "error", str(e))
        job.state["status"] = "error"
        traceback.print_exc()
    finally:
        compute_verdict(job)
        job.save()
        if job.state.get("status") in ("done", "waiting_sandbox", "error"):
            _maybe_notify_job(job)


_NOTIFY_PS = (
    "Add-Type -AssemblyName System.Windows.Forms, System.Drawing; "
    "$n = New-Object System.Windows.Forms.NotifyIcon; "
    "$ic = $env:SAFEBOX_NOTIFY_ICON; "
    "$n.Icon = if ($ic -eq 'Error') { [System.Drawing.SystemIcons]::Error } "
    "elseif ($ic -eq 'Warning') { [System.Drawing.SystemIcons]::Warning } "
    "else { [System.Drawing.SystemIcons]::Information }; "
    "$n.BalloonTipIcon = $ic; "
    "$n.BalloonTipTitle = [string]$env:SAFEBOX_NOTIFY_TITLE; "
    "$n.BalloonTipText = [string]$env:SAFEBOX_NOTIFY_MSG; "
    "$n.Visible = $true; $n.ShowBalloonTip(7000); Start-Sleep -Seconds 7; $n.Dispose()"
)


_NOTIFY_ALLOW = True


def notify_desktop(title: str, message: str, level: str = "info") -> bool:
    """Fires a non-blocking Windows system tray notification using constant PowerShell + env vars."""
    if os.name != "nt" or not _NOTIFY_ALLOW:
        return False
    icon = {"red": "Error", "error": "Error", "yellow": "Warning", "warning": "Warning"}.get(level, "Info")
    env = os.environ.copy()
    env["SAFEBOX_NOTIFY_TITLE"] = re.sub(r"[\r\n\x00]+", " ", str(title or "SafeBox"))[:80]
    env["SAFEBOX_NOTIFY_MSG"] = re.sub(r"[\r\n\x00]+", " ", str(message or ""))[:220]
    env["SAFEBOX_NOTIFY_ICON"] = icon
    try:
        subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", _NOTIFY_PS],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=NO_WINDOW,
        )
        return True
    except OSError:
        return False


def _maybe_notify_job(job: Job) -> None:
    if not job.opt("notify"):
        return
    s = job.snapshot()
    v = s.get("verdict") or {}
    lvl = v.get("level") or "pending"
    sample_name = Path(s.get("sample") or "örnek").name
    st = s.get("status")
    if lvl == "red":
        first = (v.get("red") or ["Kırmızı bayrak tespit edildi"])[0]
        notify_desktop(f"SafeBox KRİTİK: {sample_name}", first, level="red")
    elif st == "error":
        notify_desktop(f"SafeBox hata: {sample_name}", "Analiz hata ile sonlandı; ayrıntılar için panele bakın.", level="error")
    elif lvl == "yellow":
        first = (v.get("notes") or ["İncelenmesi gereken bulgular var"])[0]
        notify_desktop(f"SafeBox inceleme: {sample_name}", first, level="yellow")
    elif st == "done":
        notify_desktop(f"SafeBox tamamlandı: {sample_name}", "Otomatik kontroller kırmızı bayrak bulmadı.", level="info")


def request_cancel(job: Job) -> None:
    """Stops a running analysis at the next safe point. A running sandbox is ended early (results so far are kept)."""
    with job.lock:
        if job.state["status"] != "running":
            raise PipelineError("Bu analiz çalışmıyor.")
        job.state["cancel_requested"] = True
    if job.state["stages"]["sandbox"]["status"] == "running":
        request_stop(job)
    job.log("İptal isteği alındı.")


def delete_job(case_id: str) -> None:
    job = get_job(case_id)
    if not job:
        raise PipelineError("Analiz bulunamadı.")
    if job.state["status"] == "running":
        raise PipelineError("Çalışan bir analiz silinemez; önce iptal edin.")
    case_dir = job.case_dir.resolve()
    if case_dir.parent != CASES_DIR.resolve():          # never delete anything outside cases/
        raise PipelineError("Geçersiz analiz klasörü.")
    sample = Path(job.state.get("sample", ""))
    with JOBS_LOCK:
        JOBS.pop(case_id, None)
    shutil.rmtree(case_dir, ignore_errors=True)
    # a file dropped onto the panel lives in uploads/<name>/: remove it too if no other analysis uses it
    uploads = (BASE_DIR / "uploads").resolve()
    try:
        up_dir = sample.resolve().parent
    except OSError:
        return
    if up_dir.parent == uploads and not any(
            (_read_json(d / "state.json") or {}).get("sample") == str(sample) for d in CASES_DIR.iterdir() if d.is_dir()):
        shutil.rmtree(up_dir, ignore_errors=True)


def cleanup_jobs(days: int) -> List[str]:
    """Deletes finished analyses older than `days` days. Returns the deleted ids."""
    limit = time.time() - days * 86400
    removed = []
    for d in list(CASES_DIR.iterdir()):
        st = _read_json(d / "state.json") if d.is_dir() else None
        if not st or st.get("status") == "running":
            continue
        try:
            created = datetime.strptime(st["created"], "%Y-%m-%d %H:%M:%S").timestamp()
        except (KeyError, ValueError):
            continue
        if created < limit:
            try:
                delete_job(d.name)
                removed.append(d.name)
            except PipelineError:
                pass
    return removed


_SANDBOX_OVERRIDE_KEYS = {
    "target", "target_args", "dll_export", "duration_min", "memory_mb",
    "network", "keep_sandbox_open", "simulate_user", "run_as_standard_user",
    "seed_honeyfiles", "fake_net", "sandbox_backend", "vbox_vm", "vbox_snapshot", "vbox_user",
}


def list_runnable_targets(job: Job) -> List[str]:
    """Returns relative paths of runnable candidates under job.input_dir ordered by likelihood."""
    inp = job.input_dir
    if not inp.is_dir():
        return []
    deprio_rx = re.compile(r"(uninst|unins\d|crash|helper|vc_?redist|vcredist|dotnet|ndp\d|directx|dxsetup|redist|updater|elevat|report|cleanup|repair)", re.I)
    inst_rx = re.compile(r"^(set-?up|install|autorun|autoplay|start)", re.I)
    cands = [p for p in inp.rglob("*") if p.is_file() and p.suffix.lower() in RUNNABLE_EXT]

    def sort_key(p: Path):
        ext = p.suffix.lower()
        if ext == ".dll":
            rank = 10
        elif deprio_rx.search(p.name):
            rank = 9
        elif inst_rx.search(p.name):
            rank = 0
        elif NAME_RX.search(p.name):
            rank = 1
        else:
            rank = 5
        rel = p.relative_to(inp)
        return (rank, 0 if ext in (".exe", ".msi") else 1, len(rel.parts), -p.stat().st_size)

    cands.sort(key=sort_key)
    return [str(p.relative_to(inp)) for p in cands[:100]]


def start_sandbox_later(job: Job, overrides: Optional[Dict[str, Any]] = None) -> None:
    # Check-and-set under the job lock: a double click, or a click while the job is queued/running, must not start a
    # second sandbox thread on the same case folder.
    with job.lock:
        if job.state["status"] == "running" or job.state["stages"]["sandbox"]["status"] in ("running", "queued"):
            raise PipelineError("Bu analiz zaten çalışıyor ya da sandbox sırasında bekliyor.")
        if overrides:
            opts = job.state.setdefault("options", dict(DEFAULT_OPTIONS))
            for k in _SANDBOX_OVERRIDE_KEYS:
                if k in overrides and overrides[k] is not None:
                    opts[k] = overrides[k]
            try:
                opts["memory_mb"] = max(1024, min(65536, int(opts.get("memory_mb") or 4096)))
            except (TypeError, ValueError):
                opts["memory_mb"] = 4096
            try:
                opts["duration_min"] = max(1, min(180, int(opts.get("duration_min") or 10)))
            except (TypeError, ValueError):
                opts["duration_min"] = 10
            opts["sandbox_backend"] = "vbox" if opts.get("sandbox_backend") == "vbox" else "wsb"
            if overrides.get("vbox_password"):
                job.vbox_password = str(overrides["vbox_password"])
                opts["has_vbox_password"] = True
            opts.pop("vbox_password", None)
            opts.pop("password", None)
        job.state["status"] = "running"
        job.state["stages"]["sandbox"]["status"] = "queued"
        job.state["stages"]["sandbox"]["msg"] = "Başlatılıyor..."
    job.save()

    def _run():
        try:
            stage_sandbox(job)
            stage_report(job)
            job.state["status"] = "done"
        except Cancelled:
            _mark_cancelled(job, "sandbox")
        except Exception as e:
            job.log(f"HATA (sandbox): {e}")
            job.stage("sandbox", "error", str(e))
            job.state["status"] = "error"
        finally:
            compute_verdict(job)
            job.save()
            if job.state.get("status") in ("done", "error"):
                _maybe_notify_job(job)
    threading.Thread(target=_run, daemon=True).start()


# ======================================================================== 1. extract
def _seven_zip_version(exe: str) -> Optional[float]:
    try:
        out = subprocess.run([exe], capture_output=True, text=True, timeout=10, errors="replace", creationflags=NO_WINDOW).stdout
        m = re.search(r"7-Zip\s+(?:\(\w\)\s+)?(\d+)\.(\d+)", out)
        return float(f"{m.group(1)}.{m.group(2)}") if m else None
    except Exception:
        return None


def _check_unpacked_size(job: Job, total: int, src: Path) -> None:
    """Refuse archives that would fill the disk (zip bombs, or simply too big for the free space)."""
    packed = max(1, _archive_set_size(src))
    free = shutil.disk_usage(job.case_dir).free
    gb = lambda n: f"{n / 1024 ** 3:.1f} GB" if n >= 1024 ** 3 else f"{n / 1024 ** 2:.1f} MB"  # noqa: E731
    if total > MAX_UNPACK_RATIO * packed and total > 1024 ** 3:
        raise PipelineError(f"Arşiv açılınca {gb(total)} olacak ama kendisi {gb(packed)} ({total // packed}x). "
                            "Bu bir zip bombası olabilir, açılmadı.")
    if total + DISK_RESERVE_BYTES > free:
        raise PipelineError(f"Arşiv açılınca {gb(total)} olacak, diskte {gb(free)} boş alan var "
                            f"({gb(DISK_RESERVE_BYTES)} pay bırakılıyor). Yer açıp tekrar deneyin.")
    job.log(f"Arşiv açılınca yaklaşık {gb(total)} olacak; diskte {gb(free)} boş alan var.")


def _archive_set_size(src: Path) -> int:
    """Size of the archive including all volumes of a multi-part set."""
    name = src.name
    for rx in (r"^(.*\.part)\d+(\.rar)$", r"^(.*)\.\d{3}$"):
        m = re.match(rx, name, re.I)
        if m:
            stem = re.escape(m.group(1))
            pat = re.compile(stem + (r"\d+" + re.escape(m.group(2)) if m.lastindex == 2 else r"\.\d{3}") + "$", re.I)
            return sum(p.stat().st_size for p in src.parent.iterdir() if p.is_file() and pat.match(p.name))
    return src.stat().st_size


INSTALLER_EXT = {".msi", ".msix", ".cab", ".exe", ".asar"}
MAX_INSTALLER_UNPACK_BYTES = 512 * 1024 * 1024
_NON_CONTAINER_7Z_TYPES = {"pe", "elf", "macho", "coff", "te"}
_ASAR_KEEP_EXT = {".js", ".mjs", ".cjs", ".ts", ".json", ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".hta"}


def _unpack_asar(cand: Path, dest_dir: Path) -> int:
    """Pure-Python Electron .asar archive extractor (capped at 200 files / 50 MB with path-traversal guard)."""
    try:
        fsize = cand.stat().st_size
        if fsize < 20 or fsize > MAX_INSTALLER_UNPACK_BYTES:
            return 0
        with open(cand, "rb") as f:
            hdr = f.read(16)
            if len(hdr) < 16 or struct.unpack_from("<I", hdr, 0)[0] != 4:
                return 0
            hdr_size = struct.unpack_from("<I", hdr, 4)[0]
            json_len = struct.unpack_from("<I", hdr, 12)[0]
            if hdr_size < 8 or hdr_size > 16 * 1024 * 1024 or json_len == 0 or json_len > hdr_size:
                return 0
            data_offset = 8 + hdr_size
            if data_offset >= fsize:
                return 0
            manifest_raw = f.read(json_len).decode("utf-8", errors="strict")
            manifest = json.loads(manifest_raw)
            files_root = (manifest or {}).get("files")
            if not isinstance(files_root, dict):
                return 0

            dest_dir.mkdir(parents=True, exist_ok=True)
            root_resolved = dest_dir.resolve()
            extracted = 0
            total_written = 0
            stack = [(files_root, Path("."))]
            while stack and extracted < 200 and total_written < 50 * 1024 * 1024:
                node, rel = stack.pop()
                for name, meta in node.items():
                    if not isinstance(meta, dict):
                        continue
                    safe_rel = rel / name
                    if isinstance(meta.get("files"), dict):
                        stack.append((meta["files"], safe_rel))
                        continue
                    if "offset" not in meta or "size" not in meta:
                        continue
                    if Path(name).suffix.lower() not in _ASAR_KEEP_EXT:
                        continue
                    try:
                        off = int(meta["offset"])
                        sz = int(meta["size"])
                    except (TypeError, ValueError):
                        continue
                    if off < 0 or sz <= 0 or sz > 10 * 1024 * 1024 or data_offset + off + sz > fsize:
                        continue
                    target = (root_resolved / safe_rel).resolve()
                    if target != root_resolved and root_resolved not in target.parents:
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    f.seek(data_offset + off)
                    chunk = f.read(sz)
                    target.write_bytes(chunk)
                    extracted += 1
                    total_written += len(chunk)
                    if extracted >= 200 or total_written >= 50 * 1024 * 1024:
                        break
            return extracted
    except Exception:
        return 0


def _unpack_inno(job: Job, cand: Path, dest_dir: Path) -> int:
    inno = sbm.innoextract_path()
    if not inno:
        try:
            head = cand.read_bytes()[:4 * 1024 * 1024]
            if b"Inno Setup" in head:
                job.log(f"'{cand.name}' Inno Setup kurulumu görünüyor; içeriği açmak için PATH'e innoextract.exe ekleyebilirsiniz.")
        except OSError:
            pass
        return 0
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run([inno, "-e", "-s", "-d", str(dest_dir), str(cand)], capture_output=True, text=True,
                       timeout=300, errors="replace", creationflags=NO_WINDOW)
        return sum(1 for p in dest_dir.rglob("*") if p.is_file())
    except Exception:
        return 0


def _unpack_one_installer(job: Job, sz: str, cand: Path, dest_dir: Path, depth: int = 0) -> int:
    """Uses 7-Zip / ASAR / innoextract to unpack installer containers for static/VT inspection.
    Never unpacks bare PE section tables (Type = PE only). Returns extracted file count."""
    if cand.suffix.lower() == ".asar":
        return _unpack_asar(cand, dest_dir)
    if not sz:
        return _unpack_inno(job, cand, dest_dir) if cand.suffix.lower() == ".exe" else 0
    try:
        lp = subprocess.run([sz, "l", "-slt", "-p", str(cand)], capture_output=True, text=True,
                            timeout=120, errors="replace", creationflags=NO_WINDOW)
    except Exception:
        return 0
    if lp.returncode != 0:
        return _unpack_inno(job, cand, dest_dir) if cand.suffix.lower() == ".exe" else 0
    types = [m.strip() for m in re.findall(r"^Type = (.+)$", lp.stdout or "", re.M)]
    if not types or all(t.lower() in _NON_CONTAINER_7Z_TYPES for t in types):
        return _unpack_inno(job, cand, dest_dir) if cand.suffix.lower() == ".exe" else 0
    body = (lp.stdout or "").split("\n----------", 1)[-1]
    total_size = sum(int(x) for x in re.findall(r"^Size = (\d+)", body, re.M))
    _check_unpacked_size(job, total_size, cand)
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run([sz, "x", "-y", "-p", f"-o{dest_dir}", str(cand)], capture_output=True,
                       text=True, timeout=600, errors="replace", creationflags=NO_WINDOW)
    except Exception as e:
        job.log(f"Kurulum içi açma atlandı ({cand.name}): {e}")
        return 0
    if depth == 0:
        # MSI Compound containers often wrap their actual files in inner .cab streams.
        cabs = [p for p in dest_dir.rglob("*.cab") if p.is_file() and p.stat().st_size <= MAX_INSTALLER_UNPACK_BYTES][:3]
        for idx, cab in enumerate(cabs, 1):
            _unpack_one_installer(job, sz, cab, dest_dir / f"_cab_{idx}_{cab.stem}", depth=1)
    return sum(1 for p in dest_dir.rglob("*") if p.is_file())


def _unpack_installers(job: Job, inp: Path) -> int:
    """Inspects MSI/NSIS/SFX/ASAR/Inno installers in input_dir and extracts inner payloads into unpacked_dir."""
    sz = sbm.seven_zip_path()
    cands = sorted(
        (p for p in inp.rglob("*")
         if p.is_file() and p.suffix.lower() in INSTALLER_EXT and p.stat().st_size <= MAX_INSTALLER_UNPACK_BYTES),
        key=lambda p: (0 if p.suffix.lower() == ".asar" else 1, p.stat().st_size),
    )[:5]
    unpacked_total = 0
    for idx, cand in enumerate(cands, 1):
        job.check_cancel()
        safe_cand = re.sub(r"[^\w.-]", "_", cand.name)[:40]
        sub = job.unpacked_dir / f"{idx}_{safe_cand}"
        n = _unpack_one_installer(job, sz, cand, sub)
        if n > 0:
            unpacked_total += n
            job.log(f"Kurulum paketinin içi açıldı ({cand.name}): {n} dosya çıkarıldı -> static/VT envanterine eklenecek.")
        elif sub.exists() and not any(sub.rglob("*")):
            shutil.rmtree(sub, ignore_errors=True)
    return unpacked_total


NESTED_SMALL_ARCHIVE_BYTES = 32 * 1024 * 1024
NESTED_SMALL_MAX_EXTRACTED_BYTES = 128 * 1024 * 1024
NESTED_MAX_ARCHIVE_BYTES = 10 * 1024 ** 3
NESTED_INNER_SMALL_ARCHIVE_BYTES = 64 * 1024 * 1024
NESTED_LARGE_MAX_ENTRIES = 40
NESTED_LARGE_MAX_EXTRACTED_BYTES = 650 * 1024 * 1024
NESTED_TEMP_INNER_ARC_MAX_BYTES = 4 * 1024 ** 3
NESTED_LARGE_INNER_ARCHIVE_LIMIT = 4

_NESTED_SCRIPT_EXT = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".wsf", ".hta", ".reg", ".lnk", ".msi"}
_NESTED_CONFIG_EXT = {".pimx", ".iss"}
_NESTED_SIG_NAME_RX = re.compile(r"(runonce|patch.*\.log|unlicensed|blocker|crack|keygen|amtlib)", re.I)
_NESTED_INNER_ARC_RX = re.compile(r"(phsp|core|unpp|crack|patch|activat|setup|install|app)", re.I)
_NESTED_ASSET_ARC_RX = re.compile(r"(models|profile|cameraraw|assets|fonts|presets|samples|help|locale|_[a-z]{2}_[A-Z]{2}_)", re.I)
_NESTED_HIGH_ARC_RX = re.compile(r"(unpp|unlicensed|blocker|crack|patch|activat|keygen|core)", re.I)
_NESTED_EXE_KW_RX = re.compile(r"(photoshop|setup|install|patch|crack|loader)", re.I)
_VENDOR_JS_RX = re.compile(r"(^|[\\/])(jquery(\.min)?|bootstrap(\.min)?|carousel)\.js$", re.I)
_CONFIG_FILE_NAME_RX = re.compile(r"(patch.*\.log|runonce.*)", re.I)
_NON_EXEC_DATA_EXT = {
    ".txt", ".md", ".rtf", ".json", ".xml", ".css", ".html", ".htm", ".svg",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".woff", ".woff2", ".ttf",
    ".exv", ".map", ".yml", ".yaml", ".nfo", ".sfv", ".md5", ".sha",
}


def _clean_archive_entry_path(raw_path: str) -> Optional[str]:
    """Validates and normalizes an archive member path, returning None on traversal/invalid paths."""
    if not raw_path or "\x00" in raw_path or "\n" in raw_path or "\r" in raw_path:
        return None
    stripped = raw_path.strip().lstrip("/\\")
    if not stripped:
        return None
    parts = [p for p in re.split(r"[/\\]+", stripped) if p and p != "."]
    if not parts or any(p == ".." for p in parts) or ":" in parts[0]:
        return None
    return "/".join(parts)


def _parse_7z_slt_entries(stdout: str) -> List[Dict[str, Any]]:
    """Parses `7z l -slt` stdout into file entries with path and uncompressed size."""
    body = (stdout or "").split("\n----------", 1)[-1]
    entries: List[Dict[str, Any]] = []
    for block in re.split(r"\r?\n\r?\n", body):
        kv: Dict[str, str] = {}
        for line in block.splitlines():
            if " = " in line:
                k, v = line.split(" = ", 1)
                kv[k.strip()] = v.strip()
        raw_path = kv.get("Path", "")
        if not raw_path:
            continue
        is_dir = kv.get("Folder") == "+" or kv.get("Attributes", "").startswith("D")
        if is_dir:
            continue
        clean = _clean_archive_entry_path(raw_path)
        if not clean:
            continue
        try:
            sz = max(0, int(kv.get("Size") or 0))
        except ValueError:
            sz = 0
        entries.append({
            "clean": clean,
            "list_path": raw_path.strip().lstrip("/\\"),
            "size": sz,
        })
    return entries


def _select_large_archive_entries(
    entries: List[Dict[str, Any]], depth: int, max_depth: int, free_bytes: int
) -> List[Dict[str, Any]]:
    """Selects up to 40 high-signal entries (capped at 650 MB and DISK_RESERVE_BYTES) from a large archive."""
    budget_bytes = min(NESTED_LARGE_MAX_EXTRACTED_BYTES, max(0, free_bytes - DISK_RESERVE_BYTES))
    if budget_bytes <= 0:
        return []

    tier_scripts: List[tuple] = []
    tier_small_arcs: List[tuple] = []
    tier_low_small_arcs: List[tuple] = []
    tier_large_arcs: List[tuple] = []
    tier_exes: List[tuple] = []
    tier_configs: List[tuple] = []

    for e in entries:
        clean = e["clean"]
        p = PurePosixPath(clean)
        name = p.name
        ext = p.suffix.lower()
        sz = e["size"]
        pdepth = len(p.parts)

        if ext in _NESTED_SCRIPT_EXT or _CONFIG_FILE_NAME_RX.search(name) or (
            ext not in _NON_EXEC_DATA_EXT and ext not in ARCHIVE_EXT and (NAME_RX.search(name) or _NESTED_SIG_NAME_RX.search(name))
        ):
            tier_scripts.append(((0 if _NESTED_SIG_NAME_RX.search(name) else 1, pdepth, sz, clean.lower()), e))
            continue

        if depth < max_depth and ext in ARCHIVE_EXT and not is_later_volume(name) and sz <= NESTED_MAX_ARCHIVE_BYTES:
            is_asset_or_locale = bool(_NESTED_ASSET_ARC_RX.search(clean)) and not bool(_NESTED_HIGH_ARC_RX.search(clean))
            if sz <= NESTED_INNER_SMALL_ARCHIVE_BYTES:
                if is_asset_or_locale:
                    tier_low_small_arcs.append(((pdepth, sz, clean.lower()), e))
                else:
                    tier_small_arcs.append(((0 if _NESTED_HIGH_ARC_RX.search(clean) else (1 if _NESTED_INNER_ARC_RX.search(clean) else 2), pdepth, sz, clean.lower()), e))
            elif not is_asset_or_locale and _NESTED_INNER_ARC_RX.search(clean):
                marked = {**e, "_large_inner_arc": True}
                tier_large_arcs.append(((0 if NAME_RX.search(clean) else 1, 0 if _NESTED_HIGH_ARC_RX.search(clean) else 1, pdepth, sz, clean.lower()), marked))
            continue

        if ext in {".exe", ".sys"} or (ext == ".dll" and (name.lower() in analyzer.SUSPICIOUS_FILENAMES or NAME_RX.search(name))):
            is_huge_node = 1 if (name.lower() == "node.exe" and sz > 50 * 1024 * 1024) else 0
            has_kw = 0 if _NESTED_EXE_KW_RX.search(clean) else 1
            is_susp_dll = 0 if (ext == ".dll" or NAME_RX.search(name)) else 1
            tier_exes.append(((is_huge_node, has_kw, is_susp_dll, pdepth, sz, clean.lower()), e))
            continue

        if ext in _NESTED_CONFIG_EXT:
            tier_configs.append(((pdepth, sz, clean.lower()), e))

    tier_scripts.sort(key=lambda x: x[0])
    tier_small_arcs.sort(key=lambda x: x[0])
    tier_low_small_arcs.sort(key=lambda x: x[0])
    tier_large_arcs.sort(key=lambda x: x[0])
    tier_exes.sort(key=lambda x: x[0])
    tier_configs.sort(key=lambda x: x[0])

    ordered = (
        [e for _, e in tier_scripts]
        + [e for _, e in tier_exes[:20]]
        + [e for _, e in tier_large_arcs[:NESTED_LARGE_INNER_ARCHIVE_LIMIT]]
        + [e for _, e in tier_small_arcs[:10]]
        + [e for _, e in tier_exes[20:]]
        + [e for _, e in tier_configs]
        + [e for _, e in tier_small_arcs[10:]]
        + [e for _, e in tier_low_small_arcs[:4]]
    )

    selected: List[Dict[str, Any]] = []
    seen_paths: set = set()
    used_bytes = 0
    oversized_arc_used = False
    oversized_arc_bytes = 0
    for e in ordered:
        if len(selected) >= NESTED_LARGE_MAX_ENTRIES:
            break
        key = e["clean"].lower()
        if key in seen_paths:
            continue
        sz = e["size"]
        if used_bytes + sz <= budget_bytes:
            seen_paths.add(key)
            selected.append(e)
            used_bytes += sz
        elif (
            e.get("_large_inner_arc")
            and not oversized_arc_used
            and sz <= NESTED_TEMP_INNER_ARC_MAX_BYTES
            and (used_bytes + sz) <= max(0, free_bytes - DISK_RESERVE_BYTES - 1024 ** 3)
        ):
            seen_paths.add(key)
            selected.append(e)
            oversized_arc_used = True
            oversized_arc_bytes = sz
    _ = oversized_arc_bytes
    return selected


def _extract_zip_members(
    zf: zipfile.ZipFile, items: List[tuple], dest_root: Path, pw: str, byte_cap: int
) -> int:
    """Streams selected ZipInfo entries into dest_root with zip-slip and total byte guards."""
    pwd_bytes = pw.encode() if pw else None
    extracted = 0
    total_written = 0
    dest_root.mkdir(parents=True, exist_ok=True)
    for info, clean in items:
        target = (dest_root / clean).resolve()
        if target != dest_root and dest_root not in target.parents:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info, pwd=pwd_bytes) as src_f, open(target, "wb") as dst_f:
            while True:
                chunk = src_f.read(1024 * 1024)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > byte_cap:
                    break
                dst_f.write(chunk)
        extracted += 1
        if total_written > byte_cap:
            break
    return extracted


def _extract_7z_selected(job: Job, sz: str, arc: Path, dest_dir: Path, list_paths: List[str], pw: str) -> int:
    """Extracts only validated relative paths from an archive using 7-Zip @listfile."""
    if not sz or not list_paths:
        return 0
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()
    safe_paths: List[str] = []
    for lp in list_paths:
        clean = _clean_archive_entry_path(lp)
        if not clean:
            continue
        target = (dest_root / clean).resolve()
        if target != dest_root and dest_root not in target.parents:
            continue
        stripped = lp.strip().lstrip("/\\")
        if stripped and "\x00" not in stripped and "\n" not in stripped and "\r" not in stripped:
            safe_paths.append(stripped)
    if not safe_paths:
        return 0
    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", suffix=".txt", dir=job.case_dir, delete=False
        ) as tf:
            tf.write("\n".join(safe_paths) + "\n")
            tmp_path = Path(tf.name)
        cmd = [sz, "x", "-y", "-scsUTF-8", f"-p{pw or 'no-password'}", f"-o{dest_dir}", str(arc), f"@{tmp_path}"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=1800, errors="replace", creationflags=NO_WINDOW)
        return sum(1 for p in dest_dir.rglob("*") if p.is_file())
    except Exception as e:
        job.log(f"Seçici 7-Zip açma hatası ({arc.name}): {e}")
        return 0
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def _unpack_small_nested(job: Job, sz: str, arc: Path, dest_dir: Path, pw: str) -> int:
    """Extracts all files from a small (<= 32 MB) nested archive safely. Returns -1 if unpacked > 128 MB."""
    if arc.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(arc) as zf:
                items: List[tuple] = []
                total_sz = 0
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    clean = _clean_archive_entry_path(info.filename)
                    if not clean:
                        job.log(f"İç arşivde güvenli olmayan yol atlandı ({arc.name}): {info.filename}")
                        return 0
                    total_sz += max(0, info.file_size)
                    items.append((info, clean))
                if not items:
                    return 0
                _check_unpacked_size(job, total_sz, arc)
                if total_sz > NESTED_SMALL_MAX_EXTRACTED_BYTES:
                    return -1
                return _extract_zip_members(zf, items, dest_dir, pw, NESTED_SMALL_MAX_EXTRACTED_BYTES)
        except (NotImplementedError, RuntimeError, zipfile.BadZipFile):
            if not sz:
                return 0
    if not sz:
        return 0
    try:
        lp = subprocess.run(
            [sz, "l", "-slt", f"-p{pw or 'no-password'}", str(arc)],
            capture_output=True, text=True, timeout=120, errors="replace", creationflags=NO_WINDOW,
        )
    except Exception:
        return 0
    if lp.returncode != 0:
        return 0
    entries = _parse_7z_slt_entries(lp.stdout or "")
    if not entries:
        return 0
    total_sz = sum(e["size"] for e in entries)
    _check_unpacked_size(job, total_sz, arc)
    if total_sz > NESTED_SMALL_MAX_EXTRACTED_BYTES:
        return -1
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [sz, "x", "-y", f"-p{pw or 'no-password'}", f"-o{dest_dir}", str(arc)],
            capture_output=True, text=True, timeout=600, errors="replace", creationflags=NO_WINDOW,
        )
    except Exception as e:
        job.log(f"Küçük iç arşiv açılamadı ({arc.name}): {e}")
        return 0
    return sum(1 for p in dest_dir.rglob("*") if p.is_file())


def _unpack_large_nested(
    job: Job, sz: str, arc: Path, dest_dir: Path, pw: str, depth: int, max_depth: int
) -> int:
    """Lists entries of a large (> 32 MB) archive without full extraction and extracts only high-signal targets."""
    free_bytes = shutil.disk_usage(job.case_dir).free
    if arc.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(arc) as zf:
                entries: List[Dict[str, Any]] = []
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    clean = _clean_archive_entry_path(info.filename)
                    if not clean:
                        continue
                    entries.append({"clean": clean, "list_path": info.filename.lstrip("/\\"), "size": max(0, info.file_size), "zip_info": info})
                selected = _select_large_archive_entries(entries, depth, max_depth, free_bytes)
                if not selected:
                    return 0
                _check_unpacked_size(job, sum(e["size"] for e in selected), arc)
                byte_cap = NESTED_LARGE_MAX_EXTRACTED_BYTES + sum(
                    e["size"] for e in selected if e.get("_large_inner_arc") and e["size"] > NESTED_LARGE_MAX_EXTRACTED_BYTES
                )
                try:
                    return _extract_zip_members(
                        zf, [(e["zip_info"], e["clean"]) for e in selected], dest_dir, pw, byte_cap
                    )
                except (NotImplementedError, RuntimeError):
                    if not sz:
                        return 0
                    return _extract_7z_selected(job, sz, arc, dest_dir, [e["list_path"] for e in selected], pw)
        except zipfile.BadZipFile:
            if not sz:
                return 0
    if not sz:
        return 0
    try:
        lp = subprocess.run(
            [sz, "l", "-slt", f"-p{pw or 'no-password'}", str(arc)],
            capture_output=True, text=True, timeout=600, errors="replace", creationflags=NO_WINDOW,
        )
    except Exception as e:
        job.log(f"Büyük arşiv listelenemedi ({arc.name}): {e}")
        return 0
    if lp.returncode != 0:
        return 0
    entries = _parse_7z_slt_entries(lp.stdout or "")
    selected = _select_large_archive_entries(entries, depth, max_depth, free_bytes)
    if not selected:
        return 0
    _check_unpacked_size(job, sum(e["size"] for e in selected), arc)
    return _extract_7z_selected(job, sz, arc, dest_dir, [e["list_path"] for e in selected], pw)


def _unpack_nested_archives(job: Job, inp: Path, max_depth: int = 2) -> int:
    """Scans inp and existing unpacked_dir up to max_depth for nested archives and selectively unpacks them
    into job.unpacked_dir (never writing into inp, which may be a read-only user folder)."""
    sz = sbm.seven_zip_path()
    pw = job.password or ""
    seen: set = set()
    unpacked_total = 0
    counter = 0

    for depth in range(max_depth + 1):
        roots = [inp, job.unpacked_dir] if depth == 0 else [job.unpacked_dir]
        cands: List[Path] = []
        for root in roots:
            if not root.is_dir():
                continue
            for p in root.rglob("*"):
                if not p.is_file():
                    continue
                if p.suffix.lower() not in ARCHIVE_EXT or is_later_volume(p.name):
                    continue
                try:
                    rp = p.resolve()
                    fsize = p.stat().st_size
                except OSError:
                    continue
                if rp in seen or fsize > NESTED_MAX_ARCHIVE_BYTES:
                    continue
                if depth == 0 and p.suffix.lower() == ".cab" and job.unpacked_dir.is_dir():
                    safe_cab = re.sub(r"[^\w.-]", "_", p.name)[:40]
                    if any(d.is_dir() and d.name.endswith(f"_{safe_cab}") for d in job.unpacked_dir.iterdir()):
                        seen.add(rp)
                        continue
                seen.add(rp)
                cands.append(p)
        if not cands:
            break
        cands.sort(key=lambda p: (0 if NAME_RX.search(p.name) else 1, p.stat().st_size, str(p)))
        for arc in cands:
            job.check_cancel()
            counter += 1
            safe_name = re.sub(r"[^\w.-]", "_", arc.name)[:40]
            dest = job.unpacked_dir / f"nested_{depth}_{counter}_{safe_name}"
            fsize = arc.stat().st_size
            try:
                if fsize <= NESTED_SMALL_ARCHIVE_BYTES:
                    n = _unpack_small_nested(job, sz, arc, dest, pw)
                    if n == -1:
                        n = _unpack_large_nested(job, sz, arc, dest, pw, depth, max_depth)
                else:
                    n = _unpack_large_nested(job, sz, arc, dest, pw, depth, max_depth)
            except PipelineError as e:
                job.log(f"İç arşiv atlandı ({arc.name}): {e}")
                n = 0
            if n > 0:
                unpacked_total += n
                job.log(f"İç arşiv seçici açıldı ({arc.name}, derinlik {depth}): {n} dosya çıkarıldı.")
            elif dest.exists() and not any(dest.rglob("*")):
                shutil.rmtree(dest, ignore_errors=True)
            if depth >= 1 and fsize > NESTED_INNER_SMALL_ARCHIVE_BYTES and job.unpacked_dir.resolve() in arc.resolve().parents:
                arc.unlink(missing_ok=True)
                job.log(f"Geçici büyük iç arşiv temizlendi: {arc.name}")
    return unpacked_total


def stage_extract(job: Job) -> None:
    job.stage("extract", "running", "Hazırlanıyor...")
    src = Path(job.state["sample"])
    if src.is_file() and is_later_volume(src.name):
        raise PipelineError(f"'{src.name}' çok parçalı bir arşivin ara parçası. İlk parçayı (.part1.rar / .001 / .rar) seçin; "
                            "diğer parçalar aynı klasörden otomatik okunur.")
    is_archive = src.is_file() and (src.suffix.lower() in ARCHIVE_EXT or re.search(r"\.part0*1\.rar$", src.name, re.I))
    if src.is_dir():
        home = Path.home().resolve()
        broad = {home, home / "Downloads", home / "Desktop", home / "Documents", Path(src.anchor).resolve(), home.parent}
        if src.resolve() in broad:
            raise PipelineError(f"'{src}' çok geniş bir klasör: sandbox içindeki program buradaki tüm dosyalarını okuyabilirdi. "
                                "Sadece kurulumun kendi klasörünü seçin.")
        # The user's folder is mapped read-only into the sandbox as-is: no multi-GB copy on the host.
        job.state["input_path"] = str(src.resolve())
        empty_input = job.case_dir / "input"
        if empty_input.exists() and not any(empty_input.iterdir()):
            empty_input.rmdir()
        job.log(f"Klasör kopyalanmadan kullanılıyor (sandbox'a salt okunur bağlanacak): {src}")
    inp = job.input_dir
    if src.is_dir():
        pass
    elif is_archive:
        sz = sbm.seven_zip_path()
        pw = job.password or ""
        if sz:
            ver = _seven_zip_version(sz)
            if ver is not None and ver < 25.0:
                job.log(f"UYARI: 7-Zip {ver} eski. 25.00 öncesi sürümlerde arşiv yol aşımı açıkları var (CVE-2025-11001/11002); güncelleyin.")
            job.stage("extract", "running", "Arşiv içeriği listeleniyor...")
            lp = subprocess.run([sz, "l", "-slt", f"-p{pw or 'no-password'}", str(src)], capture_output=True,
                                text=True, timeout=600, errors="replace", creationflags=NO_WINDOW)
            if lp.returncode == 0:   # if listing fails (e.g. encrypted headers, wrong password) extraction reports why
                body = lp.stdout.split("\n----------", 1)[-1]
                _check_unpacked_size(job, sum(int(x) for x in re.findall(r"^Size = (\d+)", body, re.M)), src)
            job.stage("extract", "running", "7-Zip ile açılıyor (hiçbir şey çalıştırılmıyor)...")
            p = subprocess.run([sz, "x", "-y", f"-p{pw or 'no-password'}", f"-o{inp}", str(src)], capture_output=True,
                               text=True, timeout=7200, errors="replace", creationflags=NO_WINDOW)
            out = (p.stdout or "") + (p.stderr or "")
            if p.returncode != 0:
                if "Wrong password" in out or "Cannot open encrypted archive" in out:
                    raise PipelineError("Arşiv şifresi yanlış veya girilmemiş.")
                if "Missing volume" in out or "Unexpected end of archive" in out:
                    raise PipelineError("Çok parçalı arşivin bazı parçaları eksik (hepsi aynı klasörde olmalı).")
                job.log(f"7-Zip çıkış kodu {p.returncode}: bazı dosyalar açılamadı (antivirüs engellemiş olabilir). {out.strip()[-300:]}")
        elif src.suffix.lower() == ".zip":
            job.log("7-Zip bulunamadı, Python zipfile ile açılıyor.")
            root = inp.resolve()
            with zipfile.ZipFile(src) as zf:
                for name in zf.namelist():   # zipfile already strips '..'; this is an extra guard against path escapes
                    dest = (root / name).resolve()
                    if dest != root and root not in dest.parents:
                        raise PipelineError(f"Arşivde klasör dışına yazmaya çalışan dosya yolu var: {name}")
                _check_unpacked_size(job, sum(i.file_size for i in zf.infolist()), src)
                zf.extractall(inp, pwd=pw.encode() if pw else None)
        else:
            raise PipelineError(f"{src.suffix} arşivini açmak için 7-Zip gerekli (https://www.7-zip.org, 25.01+). Kurup tekrar deneyin.")
    else:
        shutil.copy2(src, inp / src.name)
    count = sum(1 for _ in inp.rglob("*") if _.is_file())
    if count == 0:
        raise PipelineError("Hazırlanan klasörde hiç dosya yok (arşiv boş, şifre yanlış veya antivirüs hepsini silmiş olabilir).")
    unpacked_count = _unpack_installers(job, inp) + _unpack_nested_archives(job, inp)
    msg = f"{count} dosya hazır" + (f" (+ kurulum içi {unpacked_count} dosya çıkarıldı)." if unpacked_count else ".")
    job.stage("extract", "done", msg)


# ======================================================================== 2. inventory
# Failures must be loud: a check that silently returns nothing makes every program look unsigned.
SIGCHECK_PS1 = r"""param([string]$ListFile, [string]$OutFile)
$ErrorActionPreference = 'Stop'
$fatal = $null
try { Import-Module Microsoft.PowerShell.Security -ErrorAction Stop }
catch { $fatal = "Microsoft.PowerShell.Security yuklenemedi: " + $_.Exception.Message }
$out = New-Object System.Collections.ArrayList
foreach ($p in [IO.File]::ReadAllLines($ListFile)) {
    if (-not $p) { continue }
    $st = 'Error'; $msg = ''; $signer = ''; $issuer = ''
    if ($fatal) { $msg = $fatal }
    else {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
            $st = [string]$s.Status; $msg = [string]$s.StatusMessage
            if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject; $issuer = $s.SignerCertificate.Issuer }
        } catch { $msg = "Get-AuthenticodeSignature: " + $_.Exception.Message }
    }
    [void]$out.Add([pscustomobject]@{ Path = $p; Status = $st; Message = $msg; Signer = $signer; Issuer = $issuer })
}
[IO.File]::WriteAllText($OutFile, (ConvertTo-Json -InputObject @($out) -Depth 3 -Compress), (New-Object System.Text.UTF8Encoding($false)))
"""


def _windows_powershell() -> List[str]:
    """Windows PowerShell 5.1 by full path, so a PowerShell 7 on PATH can't be picked up instead."""
    exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return [str(exe) if exe.exists() else "powershell"]


def _windows_powershell_env() -> Dict[str, str]:
    """Environment without an inherited PSModulePath. When the panel is started from PowerShell 7 (or on CI runners),
    PSModulePath lists PowerShell 7 module folders, and Windows PowerShell 5.1 may load their incompatible copy of
    Microsoft.PowerShell.Security. Without the variable, 5.1 uses its own default module path."""
    return {k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"}


def check_signatures(case_dir: Path, paths: List[str], progress=None):
    """Authenticode check in batches -> (results by path, number of files whose batch timed out).
    A batch that times out (huge installers, busy disk) leaves its files 'Unknown' instead of failing the analysis."""
    res: Dict[str, Dict[str, str]] = {}
    if not paths:
        return res, 0
    ps1, lst, out = case_dir / "_sigcheck.ps1", case_dir / "_sigcheck_in.txt", case_dir / "_sigcheck_out.json"
    ps1.write_text(SIGCHECK_PS1, encoding="utf-8")
    timed_out = 0
    try:
        for start in range(0, len(paths), SIGCHECK_BATCH):
            batch = paths[start:start + SIGCHECK_BATCH]
            if progress:
                progress(start, len(paths))
            lst.write_text("\n".join(batch), encoding="utf-8-sig")
            out.unlink(missing_ok=True)
            try:
                proc = subprocess.run(_windows_powershell() + ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1),
                                                                 "-ListFile", str(lst), "-OutFile", str(out)],
                                      capture_output=True, text=True, errors="replace", env=_windows_powershell_env(),
                                      timeout=max(120, len(batch) // 2), creationflags=NO_WINDOW)
            except subprocess.TimeoutExpired:
                timed_out += len(batch)
                continue
            items = _read_json(out)
            if not isinstance(items, list):
                # the script itself did not run (or crashed before writing): keep PowerShell's own error text
                why = ((proc.stderr or "") + (proc.stdout or "")).strip().splitlines()
                detail = " ".join(why[-3:])[:400] or f"çıkış kodu {proc.returncode}"
                for p in batch:
                    res[p] = {"status": "Error", "message": f"PowerShell imza kontrolü çalışmadı: {detail}", "signer": "", "issuer": ""}
                continue
            for item in items:
                res[item["Path"]] = {"status": item.get("Status") or "Unknown", "message": item.get("Message") or "",
                                     "signer": item.get("Signer") or "", "issuer": item.get("Issuer") or ""}
    finally:
        for f in (ps1, lst, out):
            f.unlink(missing_ok=True)
    for p in paths:
        res.setdefault(p, {"status": "Unknown", "message": "imza kontrolü zaman aşımına uğradı" if timed_out else "kontrol edilemedi",
                           "signer": "", "issuer": ""})
    return res, timed_out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stage_inventory(job: Job) -> None:
    job.stage("inventory", "running", "Dosyalar hash'leniyor...")
    time.sleep(AV_SETTLE_SEC)  # let real-time antivirus act, so quarantined files show up as missing
    inp = job.input_dir
    file_entries: List[tuple[Path, str, bool]] = [
        (p, str(p.relative_to(inp)), False) for p in inp.rglob("*") if p.is_file()
    ]
    unpacked = job.unpacked_dir
    if unpacked.is_dir():
        for p in unpacked.rglob("*"):
            if p.is_file():
                file_entries.append((p, f"[paket içi] {p.relative_to(unpacked)}", True))
    items: List[Dict[str, Any]] = []
    for i, (p, rel_name, is_unpacked) in enumerate(file_entries, 1):
        if i % 100 == 0:
            job.check_cancel()
            job.stage("inventory", "running", f"Hash: {i} / {len(file_entries)} dosya")
        rec = {"rel": rel_name, "path": str(p), "size": 0, "sha256": None, "is_pe": False,
               "is_script": p.suffix.lower() in SCRIPT_EXT,
               "is_doc": p.suffix.lower() in DOC_EXT,
               "config_flag": bool(p.suffix.lower() in {".pimx", ".iss"} or _CONFIG_FILE_NAME_RX.search(p.name)),
               "spoof_flag": False,
               "name_flag": bool(NAME_RX.search(p.name)) or p.name.lower() in analyzer.SUSPICIOUS_FILENAMES,
               "sig": None, "missing": False, "unpacked": is_unpacked}
        try:
            rec["size"] = p.stat().st_size
            with open(p, "rb") as f:
                head = f.read(64)
            rec["is_pe"] = head[:2] == b"MZ"
            rec["spoof_flag"] = bool(analyzer.detect_spoofing(p, head))
            rec["sha256"] = _sha256(p)
        except Exception:
            rec["missing"] = not p.exists()
            if rec["missing"]:
                job.log(f"Dosya kayboldu (antivirüs karantinası?): {rec['rel']}")
        items.append(rec)

    to_sign = [r["path"] for r in items if (r["is_pe"] or r["is_script"]) and not r["missing"]]
    job.stage("inventory", "running", f"{len(to_sign)} dosyanın dijital imzası kontrol ediliyor...")
    sigs, sig_timeouts = check_signatures(
        job.case_dir, to_sign, lambda done, total: job.stage("inventory", "running", f"Dijital imza: {done} / {total} dosya"))
    if sig_timeouts:
        job.log(f"UYARI: {sig_timeouts} dosyanın imza kontrolü zaman aşımına uğradı; bunlar 'Unknown' (imzasız gibi) sayıldı.")
    sig_errors = [v for v in sigs.values() if v.get("status") == "Error"]
    if sig_errors:
        job.log(f"UYARI: {len(sig_errors)} dosyanın dijital imzası kontrol edilemedi: {sig_errors[0]['message'][:300]}")
    for r in items:
        if r["path"] in sigs:
            r["sig"] = sigs[r["path"]]

    src = Path(job.state["sample"])
    original = None
    if src.is_file():
        original = {"rel": f"[orijinal] {src.name}", "path": str(src), "size": src.stat().st_size, "sha256": _sha256(src),
                    "is_pe": False, "is_script": False, "name_flag": False, "sig": None, "missing": False, "original": True}
    _write_json(job.case_dir / "inventory.json", {"original": original, "files": items})

    pe = [r for r in items if r["is_pe"]]
    unsigned = [r for r in pe if not r["sig"] or r["sig"]["status"] != "Valid"]
    mismatch = [r for r in items if r["sig"] and r["sig"]["status"] == "HashMismatch"]
    missing = [r for r in items if r["missing"]]
    job.state["inventory"] = {
        "files": len(items), "pe": len(pe), "unsigned": len(unsigned), "hash_mismatch": len(mismatch), "missing": len(missing),
        "sig_errors": len(sig_errors), "sig_error_msg": sig_errors[0]["message"][:300] if sig_errors else "",
        "original_sha256": original["sha256"] if original else None,
        "unsigned_list": [{"rel": r["rel"], "status": (r["sig"] or {}).get("status", "Unknown"), "sha256": r["sha256"]} for r in unsigned[:80]],
        "missing_list": [r["rel"] for r in missing[:50]],
    }
    job.stage("inventory", "done", f"{len(items)} dosya, {len(pe)} çalıştırılabilir, {len(unsigned)} imzasız, {len(mismatch)} imzası bozuk.")


def _load_inventory(job: Job) -> Dict[str, Any]:
    return _read_json(job.case_dir / "inventory.json") or {"original": None, "files": []}


# ======================================================================== 3. static
def _candidate_score(r: Dict[str, Any]) -> int:
    if r.get("missing") or not r.get("sha256"):
        return 0
    status = (r.get("sig") or {}).get("status")
    score = 0
    if r.get("spoof_flag"):
        score += 120
    if r["name_flag"]:
        if r["is_pe"] or r["is_script"] or r.get("is_doc") or r.get("config_flag"):
            score += 100
        else:
            score += 10
    if status == "HashMismatch":
        score += 80
    if r["is_script"]:
        score += 50
    if r.get("config_flag"):
        score += 45
    if r["is_pe"] and status != "Valid":
        score += 40
    if r.get("is_doc"):
        score += 30
    if r["rel"].lower().endswith(".exe"):
        score += 10
    if _VENDOR_JS_RX.search(r["rel"]) and not r["name_flag"] and not r.get("spoof_flag"):
        score = max(1, score - 45)
    return score


def stage_static(job: Job) -> None:
    job.stage("static", "running", "Şüpheli dosyalar seçiliyor...")
    inv = _load_inventory(job)
    ranked = sorted((r for r in inv["files"] if _candidate_score(r) > 0), key=lambda r: (-_candidate_score(r), r["size"]))
    picks = ranked[:40]
    if not picks:
        picks = sorted((r for r in inv["files"] if r["is_pe"] and r["sha256"]), key=lambda r: -r["size"])[:5]
    results = []
    for i, r in enumerate(picks, 1):
        job.check_cancel()
        job.stage("static", "running", f"İnceleniyor ({i}/{len(picks)}): {r['rel']}")
        try:
            res = analyzer.analyze_single_file(r["path"], r["sig"] or {"status": "Unknown", "message": "", "signer": "", "issuer": ""})
            res["rel"] = r["rel"]
            results.append(res)
        except Exception as e:
            job.log(f"Statik analiz hatası {r['rel']}: {e}")
    results.sort(key=lambda x: -x["risk_score"])
    job.state["static"] = results
    top = results[0]["risk_score"] if results else 0
    job.stage("static", "done", f"{len(results)} dosya incelendi, en yüksek statik risk {top}/100.")


# ======================================================================== 4. VirusTotal
def _uploadable(r: Dict[str, Any], inv: Dict[str, Any]) -> bool:
    """Only programs and scripts ever leave the machine. Uploads become downloadable by paying VT users, so documents,
    photos or an archive of personal files must never be sent - even if their name looks suspicious ('license.pdf').
    The original archive is uploaded only if it actually contains programs/scripts."""
    if r.get("original"):
        src = Path(r["path"])
        if src.suffix.lower() in SCRIPT_EXT:
            return True
        try:
            with open(src, "rb") as f:
                if f.read(2) == b"MZ":
                    return True
        except OSError:
            return False
        return any(x.get("is_pe") or x.get("is_script") for x in inv.get("files", []))
    return bool(r.get("is_pe") or r.get("is_script"))


def _select_vt_picks(job: Job, inv: Dict[str, Any]) -> List[Dict[str, Any]]:
    by_sha: Dict[str, Dict[str, Any]] = {}
    order: List[Dict[str, Any]] = []
    if inv.get("original"):
        order.append(inv["original"])
    static_paths = {s["file_path"]: s["risk_score"] for s in job.state["static"]}
    files_by_path = {r["path"]: r for r in inv["files"]}
    for s in job.state["static"]:
        r = files_by_path.get(s["file_path"])
        if r:
            order.append(r)
    for r in sorted(inv["files"], key=lambda r: (-_candidate_score(r), r["size"])):
        if _candidate_score(r) > 0 and r["path"] not in static_paths:
            order.append(r)
    for r in order:
        if r.get("sha256") and r["sha256"] not in by_sha:
            by_sha[r["sha256"]] = r
    return list(by_sha.values())[: int(job.opt("max_vt")) + (1 if inv.get("original") else 0)]


def _get_intel_config() -> Dict[str, Any]:
    """Reads intel config with vt_client fallback for circl_enabled/tf_enabled across branches."""
    icfg = dict(intel_client.get_intel_config())
    if "circl_enabled" not in icfg or "tf_enabled" not in icfg:
        raw = vt_client.load_config()
        icfg.setdefault("circl_enabled", bool(raw.get("circl_enabled", False)))
        icfg.setdefault("tf_enabled", bool(raw.get("tf_enabled", False)))
    return icfg


def _has_intel_sources() -> bool:
    if intel_client.has_configured_sources():
        return True
    icfg = _get_intel_config()
    return bool(icfg.get("circl_enabled") or icfg.get("tf_enabled"))


def _call_query_hash_intel(sha256: str, run_mb: bool, run_ha: bool, run_circl: bool, run_tf: bool) -> Dict[str, Any]:
    sig = inspect.signature(intel_client.query_hash_intel)
    kwargs: Dict[str, Any] = {"run_mb": run_mb, "run_ha": run_ha}
    if "run_circl" in sig.parameters:
        kwargs["run_circl"] = run_circl
    if "run_tf" in sig.parameters:
        kwargs["run_tf"] = run_tf
    return intel_client.query_hash_intel(sha256, **kwargs)


def _query_extra_intel_for_entries(job: Job, picks: List[Dict[str, Any]], entries: List[Dict[str, Any]], indices: List[int]) -> int:
    icfg = _get_intel_config()
    run_mb = bool(icfg.get("mb_enabled") or icfg.get("mb_api_key"))
    run_ha = bool(icfg.get("ha_api_key"))
    run_circl = bool(icfg.get("circl_enabled"))
    run_tf = bool(icfg.get("tf_enabled"))
    if not (run_mb or run_ha or run_circl or run_tf) or not indices:
        return 0
    hits = 0
    for idx in indices:
        job.check_cancel()
        r, e = picks[idx], entries[idx]
        job.stage("vt", "running", f"Ek istihbarat (MB/HA/CIRCL/TF) sorgusu: {r['rel']}")
        res = _call_query_hash_intel(r["sha256"], run_mb=run_mb, run_ha=run_ha, run_circl=run_circl, run_tf=run_tf)
        e["intel"] = res
        summary = res.get("summary") or ("CIRCL Hashlookup: bilinen temiz (NSRL)" if res.get("known_good") else "")
        if res.get("any_found"):
            hits += 1
            if "kota" in e["status"].lower():
                e["status"] += f" — {summary}"
            else:
                e["status"] = summary or "Ek istihbaratta kayıtlı"
        elif "kota" in e["status"].lower():
            e["status"] += " (ek istihbarat temiz)"
        elif not e["result"]:
            e["status"] = "VT/ek istihbaratta yok"
        compute_verdict(job)
        job.save()
    return hits


def stage_vt(job: Job) -> None:
    key = vt_client.get_api_key()
    intel_backup = _has_intel_sources()
    if not key and not intel_backup:
        job.stage("vt", "skipped", "API anahtarı yok. Sağ üstten anahtar girerseniz bu adım otomatik çalışır.")
        return
    inv = _load_inventory(job)
    picks = _select_vt_picks(job, inv)
    entries: List[Dict[str, Any]] = [{"rel": r["rel"], "sha256": r["sha256"], "size": r["size"], "status": "Sırada", "result": None,
                                      "gui_url": f"https://www.virustotal.com/gui/file/{r['sha256']}"} for r in picks]
    job.state["vt"] = entries
    if not key:
        hits = _query_extra_intel_for_entries(job, picks, entries, list(range(len(picks))))
        job.stage("vt", "done", f"VT anahtarı yok — ek istihbaratta {len(picks)} dosya hash'i sorgulandı ({hits} eşleşme).")
        return

    # Phase 1: hash lookups for every pick, so already-known malware shows up immediately.
    # Phase 2: upload the unknown ones.  Phase 3: wait for all pending scans together.
    unknown: List[int] = []
    quota = False                       # once the quota is used up, every further call is pointless
    fallback_indices: List[int] = []
    for i, (r, e) in enumerate(zip(picks, entries)):
        job.check_cancel()
        if quota:
            e["status"] = "Sorgulanmadı (VirusTotal kotası doldu)"
            fallback_indices.append(i)
            continue
        job.stage("vt", "running", f"1/3 Hash sorgusu ({i + 1}/{len(picks)}): {r['rel']} — ücretsiz API dakikada 4 istek kabul eder")
        try:
            e["result"] = vt_client.lookup(r["sha256"], key)
            if e["result"]:
                e["status"] = "VT'de kayıtlı"
            elif not job.opt("vt_upload"):
                e["status"] = "VT'de yok (yükleme kapalı)"
                fallback_indices.append(i)
            elif not _uploadable(r, inv):
                e["status"] = "VT'de yok (program değil; gizlilik için yüklenmedi)"
            elif r["size"] > vt_client.MAX_UPLOAD:
                e["status"] = "VT'de yok (650 MB'tan büyük, yüklenemez)"
                fallback_indices.append(i)
            else:
                e["status"] = "VT'de yok — yüklenecek"
                unknown.append(i)
        except vt_client.VtQuotaError:
            quota = True
            e["status"] = "Sorgulanmadı (VirusTotal kotası doldu)"
            fallback_indices.append(i)
        except Exception as ex:
            e["status"] = f"Hata: {ex}"
            fallback_indices.append(i)
        compute_verdict(job)
        job.save()

    pending: Dict[int, str] = {}
    for n, i in enumerate(unknown, 1):
        job.check_cancel()
        r, e = picks[i], entries[i]
        if quota:
            e["status"] = "VT'de yok — yüklenmedi (kota doldu)"
            fallback_indices.append(i)
            continue
        job.stage("vt", "running", f"2/3 Yükleniyor ({n}/{len(unknown)}): {r['rel']} ({r['size'] / 1048576:.1f} MB)")
        try:
            pending[i] = vt_client.upload(r["path"], key)
            e["status"] = "Yüklendi — taranıyor"
        except vt_client.VtQuotaError:
            quota = True
            e["status"] = "VT'de yok — yüklenmedi (kota doldu)"
            fallback_indices.append(i)
        except Exception as ex:
            e["status"] = f"Yükleme hatası: {ex}"
            fallback_indices.append(i)
        job.save()

    deadline = time.time() + 10 * 60
    while pending and time.time() < deadline and not quota:
        for i, aid in list(pending.items()):
            job.check_cancel()
            job.stage("vt", "running", f"3/3 VirusTotal taramaları bekleniyor ({len(pending)} dosya kaldı): {picks[i]['rel']}")
            try:
                if vt_client.analysis_done(aid, key):
                    entries[i]["result"] = vt_client.lookup(picks[i]["sha256"], key)
                    entries[i]["status"] = "Yüklendi ve tarandı"
                    del pending[i]
                    compute_verdict(job)
                    job.save()
            except vt_client.VtQuotaError:
                quota = True
                fallback_indices.append(i)
                break
            except Exception as ex:
                entries[i]["status"] = f"Hata: {ex}"
                del pending[i]
            if time.time() >= deadline:
                break
    for i in pending:
        if i not in fallback_indices:
            entries[i]["status"] = "Yüklendi, tarama sonucu alınamadı (VT linkinden sonra bakın)"
    if intel_backup and fallback_indices:
        _query_extra_intel_for_entries(job, picks, entries, sorted(set(fallback_indices)))
    flagged = sum(1 for e in job.state["vt"] if (e["result"] and e["result"]["stats"]["malicious"] > 0) or (e.get("intel") or {}).get("malicious"))
    if quota:
        job.log(vt_client.QUOTA_MSG)
        job.stage("vt", "done", f"Kota doldu: {sum(1 for e in entries if e['result'])} / {len(picks)} dosya sorgulanabildi, "
                                f"{flagged} tanesi işaretlendi. Kalanlar yarın tekrar denenebilir.")
    else:
        job.stage("vt", "done", f"{len(picks)} dosya sorgulandı, {flagged} tanesi en az bir motor tarafından işaretlendi.")


def _check_dropped_files_vt(job: Job, beh: Dict[str, Any]) -> None:
    """Queries VirusTotal (and MalwareBazaar/Hybrid Analysis/CIRCL/ThreatFox fallback) by SHA-256 for dropped executables.
    Only hash lookup is performed (no uploads, zero data leakage risk)."""
    key = vt_client.get_api_key()
    intel_backup = _has_intel_sources()
    if not key and not intel_backup:
        return
    dropped = (beh.get("Files") or {}).get("DroppedHashes") or []
    if not isinstance(dropped, list) or not dropped:
        return

    seen_shas = {str(e.get("sha256") or "").strip().lower() for e in job.state.get("vt", []) if e.get("sha256")}
    new_drops: List[Dict[str, Any]] = []
    for item in dropped:
        if not isinstance(item, dict):
            continue
        raw_sha = item.get("SHA256")
        if not isinstance(raw_sha, str):
            continue
        sha = raw_sha.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha) or sha in seen_shas:
            continue
        seen_shas.add(sha)
        raw_path = item.get("Path")
        safe_path = raw_path if isinstance(raw_path, str) and raw_path.strip() else "unknown.exe"
        try:
            safe_size = max(0, int(item.get("Size") or 0))
        except (TypeError, ValueError):
            safe_size = 0
        new_drops.append({"Path": safe_path, "SHA256": sha, "Size": safe_size})
        if len(new_drops) >= 10:
            break
    if not new_drops:
        return

    msg = f"Sandbox içinde bırakılan {len(new_drops)} yeni çalıştırılabilir dosyanın hash'i sorgulanıyor..."
    job.log(msg)
    job.stage("sandbox", "running", msg)
    icfg = _get_intel_config() if intel_backup else {}
    run_mb = bool(icfg.get("mb_enabled") or icfg.get("mb_api_key"))
    run_ha = bool(icfg.get("ha_api_key"))
    run_circl = bool(icfg.get("circl_enabled"))
    run_tf = bool(icfg.get("tf_enabled"))
    quota = False
    for item in new_drops:
        job.check_cancel()
        sha = item["SHA256"]
        p_name = Path(item["Path"]).name or "unknown.exe"
        rel_label = f"[bırakılan] {p_name}"
        entry: Dict[str, Any] = {
            "rel": rel_label,
            "path": item["Path"],
            "sha256": sha,
            "size": item["Size"],
            "status": "Sırada",
            "result": None,
            "gui_url": f"https://www.virustotal.com/gui/file/{sha}",
            "dropped": True,
        }
        need_fallback = False
        if key and not quota:
            try:
                res = vt_client.lookup(sha, key)
                if res:
                    entry["result"] = res
                    entry["status"] = "VT'de kayıtlı (bırakılan dosya)"
                else:
                    entry["status"] = "VT'de yok (bırakılan dosya)"
                    need_fallback = True
            except vt_client.VtQuotaError:
                quota = True
                entry["status"] = "Sorgulanmadı (VirusTotal kotası doldu)"
                need_fallback = True
            except Exception as ex:
                entry["status"] = f"Hata: {ex}"
                need_fallback = True
        else:
            need_fallback = True
            entry["status"] = "Sorgulanmadı (VirusTotal kotası doldu)" if quota else "VT anahtarı yok"

        if need_fallback and (run_mb or run_ha or run_circl or run_tf):
            ires = _call_query_hash_intel(sha, run_mb=run_mb, run_ha=run_ha, run_circl=run_circl, run_tf=run_tf)
            entry["intel"] = ires
            if ires.get("any_found"):
                summary = ires.get("summary") or ("CIRCL Hashlookup: bilinen temiz (NSRL)" if ires.get("known_good") else "kayıtlı")
                entry["status"] = f"{summary} (bırakılan dosya)"
            elif not key:
                entry["status"] = "Ek istihbaratta yok (bırakılan dosya)"

        job.state["vt"].append(entry)
        compute_verdict(job)
        job.save()

    if quota:
        job.log(vt_client.QUOTA_MSG)


# ======================================================================== 5. sandbox
def _observe_sandbox_loop(job: Job, out: Path, duration: int, check_alive_fn) -> None:
    started = time.time()
    deadline = started + duration + 15 * 60
    done_flag = out / "done.flag"
    misses = 0
    # Heartbeat: while observing, the monitor rewrites live.json every ~5 s.
    last_beat, last_beat_t, sample_started_t, max_gap = None, None, None, 0.0
    job.state["sandbox"].pop("monitor_lost", None)
    job.state["sandbox"].pop("monitor_max_gap", None)
    while not done_flag.exists():
        time.sleep(4)
        now = time.time()
        live = sanitize_sandbox_json(_read_json(out / "live.json"))
        if live:
            job.state["sandbox"]["live"] = live
            beat = (live.get("Updated"), live.get("SecondsLeft"), live.get("Phase"))
            if beat != last_beat:
                if last_beat_t is not None:
                    max_gap = max(max_gap, now - last_beat_t)
                last_beat, last_beat_t = beat, now
        if sample_started_t is None and _timeline_has(out, ("Sample started", "No runnable file")):
            sample_started_t = now
        status = (out / "status.txt").read_text(encoding="utf-8", errors="replace").strip() if (out / "status.txt").exists() else ""
        if status:
            job.state["sandbox"]["status_text"] = status
            job.state["stages"]["sandbox"]["msg"] = status
        observing = (live or {}).get("Phase", "observing") == "observing"
        silent_since = last_beat_t if last_beat_t is not None else sample_started_t
        if observing and silent_since is not None and now - silent_since > MONITOR_DEAD_SEC:
            job.state["sandbox"]["monitor_lost"] = {"after_sec": int(now - (sample_started_t or started)),
                                                    "silent_sec": int(now - silent_since),
                                                    "last_update": (live or {}).get("Updated")}
            job.log(f"İzleyici {int(now - silent_since)} sn'dir yanıt vermiyor — örnek izleme scriptini durdurmuş olabilir. "
                    "O ana kadar toplanan veriler saklandı.")
            job.save()
            break
        job.save()
        if now > deadline:
            job.log("Sandbox zaman aşımına uğradı.")
            break
        if time.time() - started > 90:
            state = check_alive_fn()          # None = check failed (busy system): not evidence of closing
            misses = misses + 1 if state is False else 0
            if misses >= 3:
                job.log("Sandbox penceresi izleme bitmeden kapatıldı.")
                break
    live = sanitize_sandbox_json(_read_json(out / "live.json"))
    if live:
        job.state["sandbox"]["live"] = live
    if max_gap > 60:
        job.state["sandbox"]["monitor_max_gap"] = int(max_gap)


def stage_sandbox(job: Job) -> None:
    backend = "vbox" if job.opt("sandbox_backend") == "vbox" else "wsb"
    if backend == "wsb" and not sbm.windows_sandbox_available():
        job.stage("sandbox", "unavailable", "Windows Sandbox kapalı. Üstteki 'Windows Sandbox'ı Etkinleştir' butonunu kullanıp bilgisayarı yeniden başlatın.")
        return
    if backend == "vbox" and not sbm.vbox_manage_path():
        job.stage("sandbox", "unavailable", "VirtualBox (VBoxManage.exe) bulunamadı.")
        return
    # Only one sandbox/VM instance runs at a time: wait in line instead of failing.
    if not SANDBOX_LOCK.acquire(blocking=False):
        job.stage("sandbox", "queued", "Sırada: başka bir analizin sandbox'ı bitince otomatik başlayacak.")
        job.log("Sandbox meşgul, sıraya alındı.")
        while not SANDBOX_LOCK.acquire(timeout=5):
            job.check_cancel()
        job.log("Sıra geldi, sandbox hazırlanıyor.")
    try:
        out = job.output_dir
        if any(out.iterdir()):
            prev = job.case_dir / f"output_prev_{datetime.now().strftime('%H%M%S')}"
            out.rename(prev)
            out.mkdir()
        tools = job.tools_dir
        (tools / "stop.flag").unlink(missing_ok=True)
        shutil.copy2(MONITOR_SCRIPT, tools / "Inside-Sandbox.ps1")
        for pm in ("Procmon64.exe", "Procmon.exe"):
            if (BASE_DIR / "sandbox" / pm).exists():
                shutil.copy2(BASE_DIR / "sandbox" / pm, tools / pm)
                job.log("Process Monitor da sandbox içinde çalışacak.")
                break
        duration = int(job.opt("duration_min")) * 60
        _write_json(tools / "config.json", {
            "Target": job.opt("target") or "",
            "TargetArgs": job.opt("target_args") or "",
            "DllExport": job.opt("dll_export") or "",
            "RunAsStandardUser": bool(job.opt("run_as_standard_user")),
            "SeedHoneyfiles": True if job.opt("seed_honeyfiles") is None else bool(job.opt("seed_honeyfiles")),
            "DurationSeconds": duration,
            "CopyMaxMB": COPY_INTO_SANDBOX_MAX_MB,
            "BlockLan": bool(job.opt("network")),
            "FakeNet": bool(job.opt("fake_net")),
            "SimulateUser": bool(job.opt("simulate_user")),
        })

        net = "açık (trafik kaydediliyor)" if job.opt("network") else "kapalı"
        wsb_sid: Optional[str] = None
        used_vbox_snap = ""
        vbox_vm = str(job.opt("vbox_vm") or "").strip()

        if backend == "vbox":
            job.stage("sandbox", "running", f"VirtualBox VM ({vbox_vm}) temiz snapshot'tan başlatılıyor (internet {net}, {job.opt('duration_min')} dk)...")
            used_vbox_snap = sbm.vbox_start_analysis(
                vbox_vm,
                str(job.opt("vbox_snapshot") or ""),
                job.input_dir,
                tools,
                out,
                bool(job.opt("network")),
                str(job.opt("vbox_user") or ""),
                job.vbox_password or "",
                log_cb=job.log,
            )
            job.log(f"VirtualBox VM '{vbox_vm}' başlatıldı (snapshot: {used_vbox_snap}).")
            _observe_sandbox_loop(job, out, duration, lambda: sbm._vm_state(vbox_vm) == "running")
        else:
            if sbm.sandbox_state() is True:
                raise PipelineError("Açık bir Windows Sandbox penceresi var (aynı anda yalnızca bir tane açılabilir). Kapatıp tekrar deneyin.")
            wsb = job.case_dir / "analysis.wsb"
            wsb.write_text(sbm.build_wsb(job.case_dir, bool(job.opt("network")), int(job.opt("memory_mb")), job.input_dir), encoding="utf-8")
            job.stage("sandbox", "running", f"Sandbox açılıyor (internet {net}, {job.opt('duration_min')} dk)...")
            job.log("Windows Sandbox başlatıldı. Örnek bir kurulum penceresi açarsa sandbox penceresinin içinden ilerleyebilirsiniz.")
            wsb_sid = sbm.launch_sandbox(wsb)
            _observe_sandbox_loop(job, out, duration, sbm.sandbox_state)

        if job.state.pop("cancel_requested", None):
            job.log("İptal: izleme erken bitirildi, o ana kadar toplanan sonuçlar raporlanıyor.")
        if not job.opt("keep_sandbox_open"):
            if backend == "vbox":
                job.log(f"VirtualBox VM kapatılıp temiz snapshot'a ({used_vbox_snap}) geri döndürülüyor.")
                sbm.vbox_stop_and_restore(vbox_vm, used_vbox_snap)
            else:
                job.log("Sandbox kapatılıyor (içindeki her şey silinir).")
                sbm.stop_sandbox(wsb_sid)
        elif job.state["sandbox"].get("monitor_lost"):
            job.log("İzleyici durdu; 'kapatma' seçili olmadığı için ortam açık bırakıldı. İçindekileri ana bilgisayara kopyalamayın.")

        quarantined = quarantine_output(out)
        job.state["sandbox"]["quarantined"] = quarantined
        job.state["sandbox"]["screenshots"] = list_screenshots(job)
        if quarantined:
            job.log(f"output klasöründe beklenmeyen {len(quarantined)} dosya karantinaya alındı (.quarantine): {', '.join(quarantined[:10])}")
        beh = sanitize_sandbox_json(_read_json(out / "behavior.json"))
        if beh:
            beh.get("Files", {}).pop("NewFilesSample", None)
            job.state["behavior"] = beh
            _check_dropped_files_vt(job, beh)
            job.stage("sandbox", "done", f"Tamamlandı. Ağ kaydı: {beh.get('CaptureStatus')}")
        elif job.state["sandbox"].get("monitor_lost"):
            job.stage("sandbox", "error", "İzleyici yanıt vermeyi bıraktı (örnek tarafından durdurulmuş olabilir). Son canlı veriler aşağıda.")
        else:
            job.stage("sandbox", "error", "Sandbox davranış raporu (behavior.json) oluşmadı.")
    finally:
        SANDBOX_LOCK.release()


# Files the monitor itself writes into output/. Anything else was put there by something inside the sandbox.
OUTPUT_ALLOWLIST = {"live.json", "behavior.json", "status.txt", "timeline.log", "capture.pcapng", "procmon.pml", "procmon_summary.json", "done.flag"}
_SCREENSHOT_NAME_RX = re.compile(r"^scr_\d{3}\.png$")
_MAX_SCREENSHOTS = 30
_MAX_SCREENSHOT_BYTES = 10 * 1024 * 1024


def is_valid_screenshot_file(p: Path, screenshots_dir: Path) -> bool:
    """True only for non-symlink scr_NNN.png files inside screenshots/ with valid PNG+IHDR headers."""
    try:
        if p.parent.resolve() != screenshots_dir.resolve() or p.is_symlink() or not p.is_file():
            return False
        if not _SCREENSHOT_NAME_RX.fullmatch(p.name):
            return False
        st = p.stat()
        if st.st_size < 33 or st.st_size > _MAX_SCREENSHOT_BYTES:
            return False
        with open(p, "rb") as f:
            hdr = f.read(24)
        return len(hdr) == 24 and hdr[:8] == b"\x89PNG\r\n\x1a\n" and hdr[12:16] == b"IHDR"
    except OSError:
        return False


def list_screenshots(job: Job) -> List[str]:
    """Returns validated screenshot filenames stored in output/screenshots."""
    scr_dir = job.output_dir / "screenshots"
    if not scr_dir.is_dir():
        return []
    names = [p.name for p in sorted(scr_dir.iterdir()) if is_valid_screenshot_file(p, scr_dir)]
    return names[:_MAX_SCREENSHOTS]


def quarantine_output(out: Path) -> List[str]:
    """Renames every unexpected file in output/ to *.quarantine and marks it as downloaded from the internet (MOTW),
    so a double-click cannot run something a sample dropped there."""
    moved: List[str] = []
    if not out.exists():
        return moved
    scr_dir = out / "screenshots"
    keep_shots: set = set()
    if scr_dir.is_dir():
        for sp in sorted(scr_dir.iterdir()):
            if is_valid_screenshot_file(sp, scr_dir):
                keep_shots.add(sp)
                if len(keep_shots) >= _MAX_SCREENSHOTS:
                    break
    for p in sorted(out.rglob("*"), key=lambda x: len(x.parts), reverse=True):
        if not p.is_file() or p.name.endswith(".quarantine"):
            continue
        if p.parent == out and p.name in OUTPUT_ALLOWLIST:
            continue
        if p in keep_shots:
            continue
        try:
            target = p.with_name(p.name + ".quarantine")
            p.rename(target)
            try:
                with open(f"{target}:Zone.Identifier", "w", encoding="ascii") as ads:
                    ads.write("[ZoneTransfer]\r\nZoneId=3\r\n")
            except OSError:
                pass
            moved.append(str(p.relative_to(out)))
        except OSError:
            moved.append(f"{p.relative_to(out)} (yeniden adlandırılamadı)")
    return moved


def _timeline_has(out: Path, needles) -> bool:
    try:
        text = (out / "timeline.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(n in text for n in needles)


# ------------------------------------------------------------------ sandbox output is attacker-controlled
_STR_LISTS = [("Persistence", "Services"), ("Persistence", "Drivers"), ("Persistence", "Tasks"), ("Persistence", "RunKeys"),
              ("Persistence", "Startup"), ("Persistence", "WmiSubscriptions"), ("Persistence", "ComHijacks"),
              ("Persistence", "AppInitDlls"), ("Persistence", "BitsJobs"), ("Persistence", "PsProfiles"), ("Persistence", "ActiveSetup"),
              ("Defender", "Added"), ("Defender", "ThreatsDetected"), ("Hosts", "Added"),
              ("Hosts", "Removed"), ("Firewall", "Added"), ("Files", "NewExecutables"), ("Files", "ModifiedExecutables"),
              ("Network", "NewListening"), ("Network", "UdpEndpoints"), ("HoneyfileAlerts",),
              ("LanBlock", "Details"), ("LanBlock", "Exempt"), ("LanBlock", "Ranges"),
              ("Quick", "Services"), ("Quick", "Tasks"), ("Quick", "RunKeys"), ("Quick", "Startup"), ("Quick", "Defender"), ("Quick", "Hosts")]
_OBJ_LISTS = [("Processes",), ("Connections",), ("Network", "Connections"), ("Network", "DnsCache"), ("Files", "DroppedHashes")]
_INTS = [("Files", "NewCount"), ("Files", "ModifiedCount"), ("SecondsLeft",), ("ProcessCount",), ("SampleProcessCount",),
         ("SuspiciousCount",), ("ConnectionCount",)]
_BOOLS = [("LanBlock", "Requested"), ("LanBlock", "Applied"), ("LanBlock", "Tampered"), ("StoppedEarly",), ("Admin",)]
_STRS = [("RunMode",), ("Target",), ("Started",), ("Ended",), ("CaptureStatus",), ("LanBlock", "Status")]


_CAPPED_STR_LISTS = ("MemoryFindings", "FakeNetRequests", "AutoClicks")


def sanitize_sandbox_json(d: Any) -> Optional[Dict[str, Any]]:
    """Coerces live.json / behavior.json to the expected shape. A sample inside the sandbox can write these files,
    so wrong types must not crash the verdict code or reach the panel as something other than plain values."""
    if not isinstance(d, dict):
        return None

    def parent(path):
        node = d
        for k in path[:-1]:
            node = node.get(k)
            if not isinstance(node, dict):
                return None
        return node if path[-1] in node else None

    for section in ("Persistence", "Defender", "Hosts", "Firewall", "Files", "Network", "LanBlock", "Quick"):
        if section in d and d[section] is not None and not isinstance(d[section], dict):
            d[section] = {}
    for path in _STR_LISTS:
        p = parent(path)
        if p is not None:
            v = p[path[-1]]
            p[path[-1]] = [str(x) for x in v if isinstance(x, (str, int, float))][:5000] if isinstance(v, list) else []
    for key in _CAPPED_STR_LISTS:
        if key in d:
            v = d[key]
            d[key] = [str(x)[:400] for x in v if isinstance(x, (str, int, float))][:200] if isinstance(v, list) else []
    for path in _OBJ_LISTS:
        p = parent(path)
        if p is not None:
            v = p[path[-1]]
            p[path[-1]] = [x for x in v if isinstance(x, dict)][:5000] if isinstance(v, list) else []
    for path in _INTS:
        p = parent(path)
        if p is not None:
            try:
                p[path[-1]] = int(p[path[-1]])
            except (TypeError, ValueError):
                p[path[-1]] = 0
    for path in _BOOLS:
        p = parent(path)
        if p is not None:
            p[path[-1]] = p[path[-1]] is True
    for path in _STRS:
        p = parent(path)
        if p is not None:
            v = p[path[-1]]
            p[path[-1]] = str(v)[:500] if isinstance(v, (str, int, float)) else ""
    return d


def request_stop(job: Job) -> None:
    (job.tools_dir / "stop.flag").write_text(_now(), encoding="utf-8")
    job.log("İzlemeyi erken bitirme isteği gönderildi.")


# ======================================================================== 6. network + report
# Domains only Microsoft itself uses (pure background noise of a fresh Windows).
NOISE = ("microsoft.com", "windowsupdate.com", "windows.com", "msftconnecttest.com", "msftncsi.com", "live.com",
         "live.net", "bing.com", "bing.net", "msn.com", "office.com", "office.net", "office365.com", "microsoftonline.com", "msedge.net",
         "akadns.net", "digicert.com", "verisign.com", "sectigo.com", "globalsign.com", "lencr.org", "msocsp.com", "skype.com",
         "xboxlive.com", "microsoftstore.com", "onestore.ms", "aka.ms", "msauth.net", "msftauth.net", "gfx.ms", "sfx.ms",
         "login.windows.net", "graph.windows.net", "delivery.mp.microsoft.com")
ADOBE = ("adobe.com", "adobe.io", "adobelogin.com", "adobess.com", "adobedtm.com", "typekit.net", "behance.net", "adobecc.com", "adobe.net", "omtrdc.net")
# Infrastructure anyone can rent: Windows uses some of it too, but so does malware (e.g. data sent to *.blob.core.windows.net).
SHARED_CLOUD = ("windows.net", "azureedge.net", "azurefd.net", "trafficmanager.net", "azurewebsites.net", "cloudapp.azure.com",
                "akamaized.net", "akamaiedge.net", "akamaihd.net", "edgekey.net", "edgesuite.net", "amazonaws.com", "cloudfront.net",
                "googleusercontent.com", "storage.googleapis.com", "appspot.com", "firebaseio.com", "firebasestorage.googleapis.com",
                "digitaloceanspaces.com", "r2.dev", "herokuapp.com", "vercel.app", "netlify.app", "github.io", "fastly.net",
                "b-cdn.net", "backblazeb2.com")
# Services that cracked installers have no business talking to, and that stealers/loaders use all the time:
# C2 over chat APIs, paste sites, tunnels, dynamic DNS, anonymous file drops, and "what is my IP" lookups.
ABUSED = ("api.telegram.org", "t.me", "discord.com", "discordapp.com", "discordapp.net", "pastebin.com", "paste.ee", "hastebin.com",
          "rentry.co", "raw.githubusercontent.com", "gist.githubusercontent.com", "ngrok.io", "ngrok-free.app", "ngrok.app",
          "trycloudflare.com", "workers.dev", "duckdns.org", "no-ip.com", "ddns.net", "hopto.org", "zapto.org", "sytes.net",
          "serveo.net", "transfer.sh", "file.io", "gofile.io", "catbox.moe", "anonfiles.com", "temp.sh", "bashupload.com",
          "api.ipify.org", "ipify.org", "ip-api.com", "ipinfo.io", "icanhazip.com", "checkip.amazonaws.com", "ifconfig.me",
          "myexternalip.com", "ipwho.is", "ipapi.co", "wtfismyip.com", "freegeoip.app")

CLASS_ABUSED = "KÖTÜYE KULLANIMA AÇIK SERVİS — incele"
CLASS_CLOUD = "Paylaşımlı bulut / CDN — incele"
CLASS_UNKNOWN = "BİLİNMEYEN — incele"


def _match(d: str, suffixes) -> bool:
    return any(d == s or d.endswith("." + s) for s in suffixes)


def domain_class(d: str) -> str:
    raw = (d or "").strip().lower().rstrip(".")
    if not raw:
        return "Yerel (gürültü)"
    if raw.startswith("[") and "]" in raw:
        host_only = raw[1:raw.index("]")]
    elif raw.count(":") == 1:
        host_only = raw.split(":", 1)[0]
    else:
        host_only = raw
    host_only = host_only.rstrip(".")
    if not host_only:
        return "Yerel (gürültü)"
    if _match(host_only, ABUSED):
        return CLASS_ABUSED
    if _match(host_only, ADOBE):
        return "Adobe"
    if _match(host_only, NOISE):
        return "Windows/Microsoft (gürültü)"
    if _match(host_only, SHARED_CLOUD):
        return CLASS_CLOUD
    ip_obj = _clean_ip(host_only)
    if ip_obj and (ip_obj.is_multicast or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_private or ip_obj.is_unspecified):
        return "Yerel (gürültü)"
    if (
        host_only.endswith((".arpa", ".local", ".mshome.net", ".home.arpa", ".internal", ".lan"))
        or host_only == "wpad"
        or host_only.startswith("wpad.")
        or "." not in host_only
    ):
        return "Yerel (gürültü)"
    return CLASS_UNKNOWN


def _tshark_fields(tshark: str, pcap: Path, flt: str, fields: List[str]) -> List[List[str]]:
    """Raises subprocess.TimeoutExpired on very large captures; network_summary() turns that into a partial result."""
    args = [tshark, "-r", str(pcap), "-Y", flt, "-T", "fields", "-E", "separator=|"]
    for f in fields:
        args += ["-e", f]
    p = subprocess.run(args, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_SEC, errors="replace", creationflags=NO_WINDOW)
    return [line.split("|") for line in p.stdout.splitlines() if line.strip("|").strip()]


def _count(values: List[str]) -> List[Dict[str, Any]]:
    c: Dict[str, int] = {}
    for v in values:
        if v:
            c[v] = c.get(v, 0) + 1
    return [{"name": k, "count": n, "class": domain_class(k)} for k, n in sorted(c.items(), key=lambda kv: -kv[1])]


def correlate_network_processes(
    net: Optional[Dict[str, Any]],
    behavior: Optional[Dict[str, Any]],
    domain_ips: Optional[Dict[str, set]] = None,
) -> Optional[Dict[str, Any]]:
    """Attaches Sandbox process names (and FromSample flags) to tshark DNS/SNI/HTTP/TCP rows."""
    if not net:
        return net
    conns = ((behavior or {}).get("Network") or {}).get("Connections") or []
    ip_port_map: Dict[tuple, Dict[str, bool]] = {}
    ip_map: Dict[str, Dict[str, bool]] = {}
    for c in conns:
        if not isinstance(c, dict):
            continue
        ip = str(c.get("Remote") or "").strip().lower()
        proc = str(c.get("Process") or "").strip()
        if not ip or not proc:
            continue
        fs = bool(c.get("FromSample"))
        try:
            port = str(int(c.get("Port")))
        except (TypeError, ValueError):
            port = ""
        if port:
            cur_ep = ip_port_map.setdefault((ip, port), {})
            cur_ep[proc] = cur_ep.get(proc, False) or fs
        cur_ip = ip_map.setdefault(ip, {})
        cur_ip[proc] = cur_ip.get(proc, False) or fs

    dom_ips: Dict[str, set] = {k.lower().rstrip("."): set(v) for k, v in (domain_ips or {}).items()}
    for row in ((behavior or {}).get("Network") or {}).get("DnsCache") or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("Name") or "").strip().lower().rstrip(".")
        if not name:
            continue
        for tok in re.split(r"[,;\s]+", str(row.get("Data") or "")):
            tok = tok.strip().lower()
            if _clean_ip(tok):
                dom_ips.setdefault(name, set()).add(tok)

    def _finish_procs(score_map: Dict[str, bool]) -> tuple[List[str], bool]:
        ordered = sorted(score_map.items(), key=lambda kv: (not kv[1], kv[0].lower()))
        return [p for p, _ in ordered[:6]], any(fs for _, fs in ordered)

    def _procs_for_endpoints(endpoints: List[tuple], fallback_domain: str = "") -> tuple[List[str], bool]:
        merged: Dict[str, bool] = {}
        for ip, port in endpoints:
            ip_l = str(ip or "").strip().lower()
            if not ip_l:
                continue
            src = ip_port_map.get((ip_l, str(port or ""))) or ip_map.get(ip_l) or {}
            for p, fs in src.items():
                merged[p] = merged.get(p, False) or fs
        if not merged and fallback_domain:
            for ip_l in dom_ips.get(fallback_domain.lower().rstrip("."), ()):
                for p, fs in (ip_map.get(ip_l) or {}).items():
                    merged[p] = merged.get(p, False) or fs
        return _finish_procs(merged)

    for d in net.get("dns") or []:
        dom = str(d.get("name") or "").lower().rstrip(".")
        procs, fs = _procs_for_endpoints([], dom)
        if procs:
            d["processes"] = procs
            d["from_sample"] = fs
        else:
            d.setdefault("processes", [])
            d.setdefault("from_sample", False)

    for row in net.get("sni") or []:
        dom = str(row.get("name") or "").lower().rstrip(".")
        eps = [tuple(x) for x in (row.pop("_endpoints", None) or ())]
        procs, fs = _procs_for_endpoints(eps, dom)
        if procs or not row.get("processes"):
            row["processes"] = procs
            row["from_sample"] = fs

    for h in net.get("http") or []:
        host = str(h.get("host") or "").split(":", 1)[0].lower().rstrip(".")
        eps = [tuple(x) for x in (h.pop("_endpoints", None) or ())]
        procs, fs = _procs_for_endpoints(eps, host)
        if procs or not h.get("processes"):
            h["processes"] = procs
            h["from_sample"] = fs

    for t in net.get("tcp_targets") or []:
        raw_t = str(t.get("target") or "")
        ip_part, _, port_part = raw_t.rpartition(":")
        procs, fs = _procs_for_endpoints([(ip_part or raw_t, port_part if ip_part else "")])
        if procs or not t.get("processes"):
            t["processes"] = procs
            t["from_sample"] = fs

    for u in net.get("udp_targets") or []:
        raw_t = str(u.get("target") or "")
        ip_part, _, port_part = raw_t.rpartition(":")
        procs, fs = _procs_for_endpoints([(ip_part or raw_t, port_part if ip_part else "")])
        if procs or not u.get("processes"):
            u["processes"] = procs
            u["from_sample"] = fs

    return net


DOH_DOMAINS = (
    "dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com",
    "dns.quad9.net", "doh.opendns.com", "dns.adguard.com", "dns.nextdns.io",
)


def network_summary(pcap: Path, behavior: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    tshark = sbm.tshark_path()
    if not tshark or not pcap.exists():
        return None
    failed: List[str] = []

    def q(label, flt, fields):
        try:
            return _tshark_fields(tshark, pcap, flt, fields)
        except (subprocess.TimeoutExpired, OSError):
            failed.append(label)
            return []

    dns = [n for row in q("DNS", "dns.flags.response == 0", ["dns.qry.name"]) for n in row[0].split(",")]
    domain_ips: Dict[str, set] = {}
    for row in q("DNS yanıtı", "dns.flags.response == 1", ["dns.qry.name", "dns.a", "dns.aaaa"]):
        row += [""] * (3 - len(row))
        qnames = [x.strip().lower().rstrip(".") for x in row[0].split(",") if x.strip()]
        ips = [x.strip().lower() for field in (row[1], row[2]) for x in field.split(",") if _clean_ip(x)]
        for qn in qnames:
            for ip in ips:
                domain_ips.setdefault(qn, set()).add(ip)

    sni_names: List[str] = []
    sni_eps: Dict[str, set] = {}
    for row in q("TLS SNI", "tls.handshake.type == 1", ["tls.handshake.extensions_server_name", "ip.dst", "ipv6.dst", "tcp.dstport"]):
        row += [""] * (4 - len(row))
        sname = row[0].strip()
        if not sname:
            continue
        sni_names.append(sname)
        ep_ip = (row[1] or row[2]).strip().lower()
        if ep_ip:
            sni_eps.setdefault(sname, set()).add((ep_ip, row[3].strip()))

    for row in q("QUIC SNI", "quic && tls.handshake.extensions_server_name", ["tls.handshake.extensions_server_name", "ip.dst", "ipv6.dst", "udp.dstport"]):
        row += [""] * (4 - len(row))
        sname = row[0].strip()
        if not sname:
            continue
        sni_names.append(sname)
        ep_ip = (row[1] or row[2]).strip().lower()
        if ep_ip:
            sni_eps.setdefault(sname, set()).add((ep_ip, row[3].strip()))

    http = q("HTTP", "http.request", ["http.host", "http.request.method", "http.request.uri", "ip.dst", "ipv6.dst", "tcp.dstport"])
    syn = q("TCP", "tcp.flags.syn == 1 && tcp.flags.ack == 0", ["ip.dst", "ipv6.dst", "tcp.dstport"])
    targets: Dict[str, int] = {}
    for row in syn:
        row += [""] * (3 - len(row))
        t = f"{row[0] or row[1]}:{row[2]}"
        targets[t] = targets.get(t, 0) + 1

    udp_raw = q("UDP", "udp && !(dns || mdns || nbns || ssdp || dhcp || dhcpv6)", ["ip.dst", "ipv6.dst", "udp.dstport"])
    udp_targets: Dict[str, int] = {}
    for row in udp_raw:
        row += [""] * (3 - len(row))
        dst_ip = (row[0] or row[1]).strip()
        ip_obj = _clean_ip(dst_ip)
        if not ip_obj or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_loopback:
            continue
        t = f"{dst_ip}:{row[2]}"
        udp_targets[t] = udp_targets.get(t, 0) + 1

    seen: set = set()
    http_rows: List[Dict[str, Any]] = []
    http_eps: Dict[tuple, set] = {}
    for row in http:
        row += [""] * (6 - len(row))
        if row[1].strip().upper() in ("M-SEARCH", "NOTIFY") and not row[5].strip():
            continue
        k = tuple(row[:3])
        ep_ip = (row[3] or row[4]).strip().lower()
        if ep_ip:
            http_eps.setdefault(k, set()).add((ep_ip, row[5].strip()))
        if k not in seen:
            seen.add(k)
            http_rows.append({"host": row[0], "method": row[1], "uri": row[2][:200], "class": domain_class(row[0]), "_k": k})

    sni_rows = _count(sni_names)
    for r in sni_rows:
        if r["name"] in sni_eps:
            r["_endpoints"] = list(sni_eps[r["name"]])
    for h in http_rows:
        hk = h.pop("_k", None)
        if hk and hk in http_eps:
            h["_endpoints"] = list(http_eps[hk])

    dns_rows = _count(dns)
    doh_domains = sorted({
        d["name"] for d in (dns_rows + sni_rows)
        if d.get("name") and _match(d["name"].lower().rstrip("."), DOH_DOMAINS)
    })

    summary = {
        "dns": dns_rows,
        "sni": sni_rows,
        "http": http_rows[:200],
        "tcp_targets": [{"target": k, "count": v} for k, v in sorted(targets.items(), key=lambda kv: -kv[1])[:100]],
        "udp_targets": [{"target": k, "count": v} for k, v in sorted(udp_targets.items(), key=lambda kv: -kv[1])[:100]],
        "doh_domains": doh_domains,
        "partial": failed,
    }
    return correlate_network_processes(summary, behavior, domain_ips)


SEVERE_RX = re.compile(r"trojan|stealer|backdoor|\brat\b|miner|coinmin|xmrig|redline|lumma|vidar|raccoon|stealc|agenttesla|remcos|njrat|asyncrat|dropper|downloader|ransom|spyware|banker|infostealer", re.I)
TOOL_RX = re.compile(r"hacktool|riskware|crack|keygen|patch|pua|pup|activator|kms", re.I)


_FAKENET_FILE_EXT_SKIP = (
    ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ".txt", ".log", ".json", ".xml", ".html", ".php", ".asp", ".aspx", ".zip", ".msi", ".arpa",
)
_URL_RX = re.compile(r"https?://[^\s\"'<>]+", re.I)
_HOST_HDR_RX = re.compile(r"\bHost:\s*([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)", re.I)
_DOM_TOK_RX = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b", re.I)


def _extract_fakenet_targets(items: List[str]) -> tuple[List[str], List[str]]:
    """Extracts deduplicated domains and URLs from FakeNetRequests log lines."""
    domains: List[str] = []
    urls: List[str] = []
    seen_d: set = set()
    seen_u: set = set()

    def _add_dom(raw_d: str) -> None:
        dom = raw_d.strip().lower().rstrip(".")
        if not dom or dom in seen_d or _clean_ip(dom):
            return
        seen_d.add(dom)
        domains.append(dom)

    for raw in items or []:
        s = str(raw or "").strip()
        if not s:
            continue
        for u in _URL_RX.findall(s):
            if u not in seen_u:
                seen_u.add(u)
                urls.append(u)
            host = (urlparse(u).hostname or "").lower().rstrip(".")
            if host:
                _add_dom(host)
        for hm in _HOST_HDR_RX.findall(s):
            _add_dom(hm)
        for tok in _DOM_TOK_RX.findall(s):
            tl = tok.lower()
            if _clean_ip(tl) or tl.endswith(_FAKENET_FILE_EXT_SKIP):
                continue
            _add_dom(tl)
    return domains, urls


def compute_verdict(job: Job) -> None:
    s = job.state
    red: List[str] = []
    notes: List[str] = []
    known_good: List[str] = []
    for e in s.get("vt") or []:
        intel = e.get("intel") or {}
        mb = intel.get("malwarebazaar") or {}
        ha = intel.get("hybrid_analysis") or {}
        tf = intel.get("threatfox") or {}
        circl = intel.get("circl") or {}
        if mb.get("found"):
            red.append(f"MalwareBazaar: '{e['rel']}' bilinen zararlı örnektir ({mb.get('family') or 'kayıtlı'}).")
        if ha.get("found"):
            v_ha = (ha.get("verdict") or "").lower()
            if v_ha == "malicious" or (ha.get("threat_score") or 0) >= 70:
                red.append(f"Hybrid Analysis: '{e['rel']}' zararlı olarak sınıflandırılmış ({ha.get('family') or v_ha}).")
            elif v_ha == "suspicious":
                notes.append(f"Hybrid Analysis: '{e['rel']}' şüpheli işaretlenmiş ({ha.get('family') or v_ha}).")
        if tf.get("found"):
            red.append(f"ThreatFox: '{e['rel']}' bilinen zararlı IOC'sidir ({tf.get('family') or tf.get('threat_type') or 'kayıtlı'}).")
        if circl.get("found") and circl.get("verdict") == "malicious":
            red.append(f"CIRCL Hashlookup: '{e['rel']}' zararlı olarak işaretli ({circl.get('known_malicious') or 'KnownMalicious'}).")
        elif intel.get("known_good") or (circl.get("found") and circl.get("verdict") == "known_good" and not intel.get("malicious")):
            prod = circl.get("product_name") or circl.get("file_name") or ""
            known_good.append(f"{e['rel']}" + (f" ({prod})" if prod else ""))
        r = e.get("result")
        if not r:
            continue
        mal = r["stats"]["malicious"]
        txt = r.get("suggested_threat_label", "") + " " + " ".join(x["result"] for x in r.get("flagged_engines", []))
        if mal and SEVERE_RX.search(txt):
            red.append(f"VirusTotal: '{e['rel']}' zararlı yazılım ailesi olarak tespit edildi ({mal} motor): {r.get('suggested_threat_label')}")
        elif mal >= 3 and TOOL_RX.search(txt):
            notes.append(f"VirusTotal: '{e['rel']}' {mal} motor tarafından HackTool/Crack olarak işaretlendi (crack'lerde beklenir ama değiştirilmiş dosyadır).")
        elif mal >= 3:
            red.append(f"VirusTotal: '{e['rel']}' {mal} motor tarafından zararlı işaretlendi.")
        elif mal > 0:
            notes.append(f"VirusTotal: '{e['rel']}' {mal} motor tarafından işaretlendi (düşük, motor adlarına bakın).")
    inv = s.get("inventory") or {}
    if inv.get("missing"):
        red.append(f"{inv['missing']} dosya açıldıktan sonra kayboldu — büyük ihtimalle Windows Defender karantinaya aldı.")
    if inv.get("hash_mismatch"):
        notes.append(f"{inv['hash_mismatch']} dosyanın imzası bozuk (HashMismatch) — orijinal dosya sonradan değiştirilmiş (crack/yama).")
    if inv.get("sig_errors"):
        notes.append(f"{inv['sig_errors']} dosyanın dijital imzası kontrol edilemedi, bu yüzden imzasız sayıldı "
                     f"(imza sonuçları güvenilir değil): {inv.get('sig_error_msg', '')}")
    for st in s.get("static") or []:
        sig = st.get("signature") or {}
        sig_status = sig.get("status")
        for sf in st.get("spoof_flags") or []:
            if str(sf.get("severity") or "").lower() in ("critical", "high"):
                red.append(f"Uzantı/Biçim kandırmacası '{st.get('rel', '')}': {sf.get('reason', '')}")
        for ym in st.get("yara_matches") or []:
            sev = str(ym.get("severity") or "medium").lower()
            desc = ym.get("description") or ym.get("rule")
            if sev in ("critical", "high"):
                red.append(f"YARA [{ym.get('rule')}]: '{st.get('rel', '')}' ({desc})")
            else:
                notes.append(f"YARA [{ym.get('rule')}]: '{st.get('rel', '')}' ({desc})")
        for ff in st.get("format_findings") or []:
            sev = str(ff.get("severity") or "medium").lower()
            msg_ff = f"{ff.get('category')}: '{st.get('rel', '')}' — {ff.get('description', '')}"
            if sev in ("critical", "high"):
                red.append(msg_ff)
            else:
                notes.append(msg_ff)
        score = int(st.get("risk_score") or 0)
        if sig_status != "Valid" and score >= 75:
            red.append(f"Statik analiz: '{st.get('rel', '')}' çok yüksek risk puanı aldı ({score}/100).")
        elif score >= 65:
            notes.append(f"Statik analiz: '{st.get('rel', '')}' yüksek risk puanı aldı ({score}/100).")

        crit = [f["category"] for f in st.get("string_findings", []) if f.get("severity") == "critical"]
        if not crit:
            continue
        if sig_status == "Valid":
            signer = (sig.get("signer") or "").split(",")[0].replace("CN=", "")
            notes.append(f"Statik: '{st['rel']}' imzalı ({signer}) ama şu izleri içeriyor: {', '.join(crit)} — "
                         "gömülü tarayıcı motorlarında normal olabilir; imzalı zararlılar da olur, VT ve sandbox sonucuyla birlikte değerlendirin.")
        else:
            notes.append(f"Statik: '{st['rel']}' imzasız ve şu izleri içeriyor: {', '.join(crit)}")

    b = s.get("behavior")
    live = (s.get("sandbox") or {}).get("live") or {}
    sbx = s.get("sandbox") or {}
    if sbx.get("monitor_lost"):
        ml = sbx["monitor_lost"]
        red.append(f"Sandbox izleyicisi örnek çalıştırıldıktan ~{ml.get('after_sec')} sn sonra yanıt vermeyi bıraktı "
                   f"({ml.get('silent_sec')} sn sessizlik) — örnek analiz aracını durdurmuş olabilir (anti-analiz davranışı).")
    elif sbx.get("monitor_max_gap"):
        notes.append(f"Sandbox izleyicisi bir ara {sbx['monitor_max_gap']} sn yanıt vermedi (sistem çok yoğun olabilir).")
    if sbx.get("quarantined"):
        red.append(f"Sandbox içinden analiz klasörüne beklenmeyen {len(sbx['quarantined'])} dosya yazıldı (karantinaya alındı): "
                   + ", ".join(sbx["quarantined"][:5]))
    lan = (b or {}).get("LanBlock") or live.get("LanBlock") or {}
    if lan.get("Tampered"):
        red.append("Yerel ağ engeli sandbox içinde kaldırıldı/kapatıldı — örnek ağ korumasını devre dışı bırakmaya çalıştı: "
                   + ", ".join(lan.get("Details") or []))
    elif lan.get("Requested") and not lan.get("Applied") and (b or live):
        notes.append(f"Yerel ağ engeli uygulanamadı ({lan.get('Status')}); sandbox ev ağınıza erişebilirdi.")
    if b:
        P = b.get("Persistence") or {}
        D = b.get("Defender") or {}
        if D.get("ThreatsDetected"):
            red.append(f"Sandbox içindeki Defender tehdit buldu: {'; '.join(D['ThreatsDetected'][:5])}")
        if D.get("Added"):
            red.append(f"Defender ayarları değiştirildi (istisna eklendi / koruma kapatıldı): {'; '.join(D['Added'][:5])}")
        if b.get("HoneyfileAlerts"):
            confirmed_honey = [
                a for a in b["HoneyfileAlerts"]
                if any(tok in str(a) for tok in ("DELETED", "MODIFIED", "(Modified)", " read by "))
            ]
            unverified_honey = [a for a in b["HoneyfileAlerts"] if a not in confirmed_honey]
            if confirmed_honey:
                red.append(f"Yem dosyalara (honeyfile) erişildi/değiştirildi: {'; '.join(confirmed_honey[:4])}")
            if unverified_honey:
                notes.append(f"Yem dosya erişim izi (işlem doğrulanamadı, arka plan taraması olabilir): {'; '.join(unverified_honey[:3])}")
        if P.get("Services"):
            red.append(f"{len(P['Services'])} yeni servis kuruldu.")
        if P.get("Drivers"):
            red.append(f"{len(P['Drivers'])} yeni sürücü kuruldu.")
        if P.get("Startup"):
            red.append(f"Başlangıç klasörüne {len(P['Startup'])} dosya eklendi.")
        if P.get("WmiSubscriptions"):
            red.append(f"WMI olay aboneliği kalıcılığı eklendi ({len(P['WmiSubscriptions'])} kayıt).")
        if P.get("AppInitDlls"):
            red.append(f"AppInit_DLLs / LogonScript kalıcılığı eklendi: {'; '.join(P['AppInitDlls'][:3])}")
        if P.get("BitsJobs"):
            red.append(f"BITS arka plan aktarım görevi oluşturuldu ({len(P['BitsJobs'])} görev).")
        if P.get("PsProfiles"):
            red.append(f"PowerShell profil dosyası oluşturuldu/değiştirildi ({len(P['PsProfiles'])}).")
        if P.get("ComHijacks"):
            notes.append(f"HKCU COM sınıfı kaydı eklendi ({len(P['ComHijacks'])}) — COM hijacking ihtimali.")
        if P.get("ActiveSetup"):
            notes.append(f"Active Setup kalıcılık kaydı eklendi ({len(P['ActiveSetup'])}).")
        if P.get("Tasks"):
            notes.append(f"{len(P['Tasks'])} yeni zamanlanmış görev — ürüne mi ait kontrol edin.")
        if P.get("RunKeys"):
            notes.append(f"{len(P['RunKeys'])} otomatik başlatma kaydı eklendi/değişti.")
        if (b.get("Hosts") or {}).get("Added"):
            notes.append(f"hosts dosyası değişti ({len(b['Hosts']['Added'])} satır) — crack'ler lisans sunucusunu genelde böyle engeller.")
        if (b.get("Hosts") or {}).get("Removed"):
            notes.append(f"hosts dosyasından {len(b['Hosts']['Removed'])} satır silindi.")
        if (b.get("Firewall") or {}).get("Added"):
            notes.append(f"{len(b['Firewall']['Added'])} güvenlik duvarı kuralı eklendi — crack'ler ürünün internetini genelde böyle keser.")
        new_listen = (b.get("Network") or {}).get("NewListening") or []
        if new_listen:
            red.append(f"Yeni dinleyici (listening) TCP portu açıldı: {'; '.join(new_listen[:4])}")
        sus = [p for p in b.get("Processes") or [] if p.get("Suspicious")]
        if sus:
            red.append(f"{len(sus)} işlem şüpheli komut satırıyla çalıştı (gizli/şifreli PowerShell, indirme, Defender müdahalesi...).")
        mod_exec = (b.get("Files") or {}).get("ModifiedExecutables") or []
        if mod_exec:
            red.append(f"Mevcut {len(mod_exec)} çalıştırılabilir dosya değiştirildi: {', '.join(mod_exec[:4])}")
        for dh in (b.get("Files") or {}).get("DroppedHashes") or []:
            if not isinstance(dh, dict):
                continue
            d_flags = dh.get("Flags") or []
            if isinstance(d_flags, list) and d_flags:
                red.append(f"Bırakılan dosya '{Path(str(dh.get('Path') or 'dosya')).name}' şüpheli dizgeler içeriyor: {', '.join(str(x) for x in d_flags[:4])}")
            elif dh.get("SigStatus") not in ("Valid", None, "") and float(dh.get("Entropy") or 0) > 7.2:
                notes.append(f"Bırakılan imzasız dosya '{Path(str(dh.get('Path') or 'dosya')).name}' yüksek entropili ({dh.get('Entropy')}/8).")
        dropped = [f for f in (b.get("Files") or {}).get("NewExecutables") or [] if re.search(r"\\AppData\\|\\Temp\\|\\ProgramData\\|\\Users\\Public\\", f, re.I)]
        if dropped:
            notes.append(f"AppData/Temp/ProgramData içine {len(dropped)} yeni çalıştırılabilir dosya bırakıldı.")
        conns = [c for c in (b.get("Network") or {}).get("Connections") or [] if c.get("FromSample")]
        if conns:
            notes.append(f"Örneğin başlattığı işlemler {len(conns)} ağ bağlantısı açtı.")
        mem_findings = b.get("MemoryFindings") or []
        if mem_findings:
            red.append(f"Canlı işlem belleğinde zararlı/şüpheli izler tespit edildi ({len(mem_findings)}): "
                       + "; ".join(str(x) for x in mem_findings[:5]))
        fakenet_reqs = b.get("FakeNetRequests") or []
        if fakenet_reqs:
            fn_domains, _ = _extract_fakenet_targets(fakenet_reqs)
            abused_fn = [d for d in fn_domains if domain_class(d) == CLASS_ABUSED]
            if abused_fn:
                red.append(f"FakeNet tuzağı kötüye kullanılan servise istek yakaladı: {', '.join(abused_fn[:8])}")
            notes.append(f"FakeNet tuzağı {len(fakenet_reqs)} ağ isteği yakaladı: {'; '.join(str(x) for x in fakenet_reqs[:4])}")
        run_mode = b.get("RunMode") or ""
        if isinstance(run_mode, str) and "in-place" in run_mode:
            notes.append("Kurulum boyutu büyük olduğu için salt okunur paylaşılan klasörden yerinde çalıştırıldı. Kurulum kendi klasörüne dosya yazmaya çalıştıysa hata vermiş olabilir.")
    elif live:
        q = live.get("Quick") or {}
        if q.get("Defender"):
            red.append("Canlı: Defender ayarları değişti.")
        if q.get("Services"):
            red.append(f"Canlı: {len(q['Services'])} yeni servis.")
        if live.get("SuspiciousCount"):
            red.append(f"Canlı: {live['SuspiciousCount']} şüpheli komut satırı.")
    pm_sum = _read_json(job.output_dir / "procmon_summary.json")
    if isinstance(pm_sum, dict) and isinstance(pm_sum.get("SensitiveEvents"), list) and pm_sum["SensitiveEvents"]:
        red.append(f"Procmon: hassas sistem/kimlik dosyalarına erişim tespit edildi ({len(pm_sum['SensitiveEvents'])} olay).")
    net = s.get("network")
    if net:
        names = (net.get("dns") or []) + (net.get("sni") or []) + [{"name": h["host"], "class": h["class"]} for h in net.get("http") or []]
        by_class = lambda c: sorted({d["name"] for d in names if d.get("class") == c and d.get("name")})  # noqa: E731
        abused, cloud, unk = by_class(CLASS_ABUSED), by_class(CLASS_CLOUD), by_class(CLASS_UNKNOWN)
        if abused:
            red.append(f"Zararlıların sık kullandığı servislerle iletişim (sohbet API'si, paste sitesi, tünel, IP sorgulama...): {', '.join(abused[:10])}")
        if unk:
            notes.append(f"{len(unk)} bilinmeyen (Microsoft/Adobe dışı) alan adıyla iletişim: {', '.join(unk[:10])}")
        if cloud:
            notes.append(f"{len(cloud)} paylaşımlı bulut/CDN adresi (Windows'un kendi trafiği de olabilir, zararlılar da kullanır): {', '.join(cloud[:8])}")
        if net.get("doh_domains"):
            notes.append(f"DNS-over-HTTPS (DoH) sunucusu tespit edildi: {', '.join(str(x) for x in net['doh_domains'][:5])} — şifreli DNS sorguları normal DNS listesinde görünmeyebilir.")
        if net.get("partial"):
            notes.append(f"Ağ özeti kısmi: {', '.join(net['partial'])} sorgusu zaman aşımına uğradı (kayıt çok büyük). Tamamı için kaydı Wireshark'ta açın.")
    # Coverage: "no red flags" must not look like a clean bill of health when checks did not actually run.
    stg = s["stages"]
    finished = s.get("status") not in ("running",)
    missing = []
    if finished:
        if stg["vt"]["status"] != "done":
            missing.append("VirusTotal")
            notes.append(f"VirusTotal kontrolü yapılmadı ({stg['vt'].get('msg') or stg['vt']['status']}).")
        if stg["sandbox"]["status"] != "done":
            missing.append("Sandbox")
            notes.append("Sandbox adımı çalışmadı: dosyanın davranışı (işlemler, ağ, kalıcılık) incelenmedi; "
                         "bu sonuç sadece statik kontrollere dayanıyor.")
    level = "red" if red else ("yellow" if notes else ("green" if finished else "pending"))
    verdict_obj: Dict[str, Any] = {"level": level, "red": red, "notes": notes, "not_run": missing}
    if known_good:
        verdict_obj["known_good"] = known_good
    s["verdict"] = verdict_obj


def stage_report(job: Job) -> None:
    job.stage("report", "running", "Rapor hazırlanıyor...")
    pcap = job.output_dir / "capture.pcapng"
    if pcap.exists():
        if sbm.tshark_path():
            job.stage("report", "running", "Ağ kaydı tshark ile özetleniyor...")
            job.state["network"] = network_summary(pcap, job.state.get("behavior"))
        else:
            job.log("capture.pcapng hazır; otomatik özet için Wireshark kurun (tshark ile gelir).")
    if job.state.get("network") and job.state.get("behavior"):
        correlate_network_processes(job.state["network"], job.state.get("behavior"))
    compute_verdict(job)
    write_report(job)
    job.stage("report", "done", "report.md yazıldı.")


def write_report(job: Job) -> None:
    s = job.state
    v = s["verdict"]
    L: List[str] = [f"# SafeBox analiz raporu", "", f"- **Örnek:** {s['sample']}", f"- **Tarih:** {s['created']}",
                    f"- **Sonuç seviyesi:** {v['level']}", ""]
    L += ["## Bulgular", ""]
    L += [f"- **KIRMIZI:** {x}" for x in v["red"]] + [f"- NOT: {x}" for x in v["notes"]]
    if v.get("known_good"):
        L.append(f"- BİLGİ (CIRCL NSRL bilinen temiz): {', '.join(v['known_good'][:10])}")
    if not v["red"] and not v["notes"]:
        L.append("- Otomatik kontroller kırmızı bayrak bulmadı. Bu dosyanın temiz olduğunu **kanıtlamaz**.")
    inv = s.get("inventory") or {}
    L += ["", "## Envanter", "", f"{inv.get('files', 0)} dosya, {inv.get('pe', 0)} çalıştırılabilir, {inv.get('unsigned', 0)} imzasız, "
          f"{inv.get('hash_mismatch', 0)} imzası bozuk, {inv.get('missing', 0)} kayıp.", ""]
    L += ["## VirusTotal", "", "| Dosya | Durum | Zararlı | Etiket | Link |", "|---|---|---|---|---|"]
    for e in s.get("vt") or []:
        r = e.get("result") or {}
        mal = f"{r['stats']['malicious']}/{r['stats']['total']}" if r else "-"
        intel = e.get("intel") or {}
        lbl = (r.get("suggested_threat_label", "") if r else "") or intel.get("summary", "") or ("CIRCL NSRL (bilinen temiz)" if intel.get("known_good") else "")
        L.append(f"| {e['rel']} | {e['status']} | {mal} | {lbl} | [VT]({e['gui_url']}) |")
    L += ["", "## Statik analiz (en riskli 15)", ""]
    yara_rows: List[str] = []
    for st in (s.get("static") or [])[:15]:
        L.append(f"- **{st['rel']}** — risk {st['risk_score']}/100, imza: {(st.get('signature') or {}).get('status')}; " + "; ".join(st.get("risk_reasons", [])[:4]))
        pe = st.get("pe_info") or {}
        if pe.get("is_pe"):
            pe_bits = [x for x in (
                pe.get("architecture"),
                f"derleme: {pe['compile_time']}" if pe.get("compile_time") else "",
                f"import: {pe.get('total_imports', 0)}",
                f"imphash: `{pe['imphash']}`" if pe.get("imphash") else "",
                ".NET (CLR)" if pe.get("is_dotnet") else "",
                f"Overlay: {round(pe['overlay']['size'] / 1048576, 2)} MB" if pe.get("overlay") else "",
            ) if x]
            if pe_bits:
                L.append(f"  - PE: {' | '.join(pe_bits)}")
        if st.get("interesting_ips"):
            L.append(f"  - Dizge içi IP'ler: `{', '.join(st['interesting_ips'][:10])}`")
        if st.get("deobfuscated_snippets"):
            L.append(f"  - Çözülen gizli komut ({len(st['deobfuscated_snippets'])}): `{st['deobfuscated_snippets'][0].get('decoded', '')[:140]}`")
        for ym in st.get("yara_matches") or []:
            yara_rows.append(f"- **{st['rel']}** → `{ym.get('rule')}` ({ym.get('severity')}): {ym.get('description', '')}")
    if yara_rows:
        L += ["", "### YARA eşleşmeleri", ""] + yara_rows
    b = s.get("behavior")
    if b:
        L += ["", "## Sandbox davranışı", "", f"- Çalıştırılan: `{b.get('Target')}` ({b.get('RunMode')})",
              f"- İzleme: {b.get('Started')} → {b.get('Ended')}", f"- Ağ kaydı: {b.get('CaptureStatus')}",
              f"- Yerel ağ engeli: {(b.get('LanBlock') or {}).get('Status')}" + (" — **KALDIRILMAYA ÇALIŞILDI**" if (b.get('LanBlock') or {}).get('Tampered') else ""), ""]
        sections = [("Yem dosya (honeyfile) uyarıları", b.get("HoneyfileAlerts")),
                    ("Defender değişiklikleri", (b.get("Defender") or {}).get("Added")), ("Defender tespitleri", (b.get("Defender") or {}).get("ThreatsDetected")),
                    ("Yeni servisler", (b.get("Persistence") or {}).get("Services")), ("Yeni sürücüler", (b.get("Persistence") or {}).get("Drivers")),
                    ("Yeni zamanlanmış görevler", (b.get("Persistence") or {}).get("Tasks")), ("Otomatik başlatma kayıtları", (b.get("Persistence") or {}).get("RunKeys")),
                    ("Başlangıç klasörü", (b.get("Persistence") or {}).get("Startup")),
                    ("WMI kalıcılık abonelikleri", (b.get("Persistence") or {}).get("WmiSubscriptions")),
                    ("COM hijacking kayıtları", (b.get("Persistence") or {}).get("ComHijacks")),
                    ("AppInit / LogonScript", (b.get("Persistence") or {}).get("AppInitDlls")),
                    ("BITS görevleri", (b.get("Persistence") or {}).get("BitsJobs")),
                    ("PowerShell profilleri", (b.get("Persistence") or {}).get("PsProfiles")),
                    ("Active Setup kayıtları", (b.get("Persistence") or {}).get("ActiveSetup")),
                    ("hosts eklenen satırlar", (b.get("Hosts") or {}).get("Added")),
                    ("hosts silinen satırlar", (b.get("Hosts") or {}).get("Removed")),
                    ("Güvenlik duvarı kuralları", (b.get("Firewall") or {}).get("Added")),
                    ("Yeni dinleyici portlar (TCP)", (b.get("Network") or {}).get("NewListening")),
                    ("Bellek taraması bulguları (MemoryFindings)", b.get("MemoryFindings")),
                    ("FakeNet yakalanan istekler", b.get("FakeNetRequests")),
                    ("Otomatik kurulum tıklamaları (AutoClicks)", b.get("AutoClicks")),
                    ("Yeni çalıştırılabilir dosyalar", (b.get("Files") or {}).get("NewExecutables")),
                    ("Değiştirilen çalıştırılabilir dosyalar", (b.get("Files") or {}).get("ModifiedExecutables"))]
        for title, items in sections:
            items = items or []
            L.append(f"### {title} ({len(items)})")
            L += [f"- `{x}`" for x in items[:60]] + [""]
        L.append("### İşlemler")
        for p in (b.get("Processes") or [])[:150]:
            flag = (" **ŞÜPHELİ**" if p.get("Suspicious") else "") + (" [örnek]" if p.get("InTree") else "")
            L.append(f"- {p.get('FirstSeen')} {p.get('Name')} ({p.get('Pid')}){flag}: `{(p.get('CommandLine') or '')[:220]}`")
        L += ["", "### TCP bağlantıları"]
        for c in ((b.get("Network") or {}).get("Connections") or [])[:150]:
            L.append(f"- {c.get('FirstSeen')} {c.get('Process')} → {c.get('Remote')}:{c.get('Port')}" + (" [örnek]" if c.get("FromSample") else ""))
    shots = list_screenshots(job)
    if shots:
        L += ["", f"### Sandbox ekran görüntüleri ({len(shots)})", ""] + [f"- `output/screenshots/{name}`" for name in shots]
    net = s.get("network")
    if net:
        def _ptag(row):
            ps = row.get("processes") or []
            if not ps:
                return ""
            return f" (`{', '.join(ps[:3])}`" + (" [örnek]" if row.get("from_sample") else "") + ")"
        L += ["", "## Ağ özeti (tshark)", "", "### DNS"] + [f"- {d['name']} ×{d['count']}{_ptag(d)} — {d['class']}" for d in net["dns"][:100]]
        L += ["", "### TLS / QUIC SNI"] + [f"- {d['name']} ×{d['count']}{_ptag(d)} — {d['class']}" for d in net["sni"][:100]]
        L += ["", "### HTTP"] + [f"- {h['method']} http://{h['host']}{h['uri']}{_ptag(h)} — {h['class']}" for h in net["http"][:100]]
        if net.get("udp_targets"):
            L += ["", "### UDP hedefleri"] + [f"- {u['target']} ×{u['count']}{_ptag(u)}" for u in net["udp_targets"][:60]]
        if net.get("doh_domains"):
            L += ["", "### Tespit edilen DoH sunucuları"] + [f"- `{d}`" for d in net["doh_domains"]]
    L += ["", "## Sınırlar", "", "- Zararlılar sandbox'ı fark edip sessiz kalabilir veya izleme süresinden uzun bekleyebilir.",
          "- Windows arka plan trafiği kayda karışır; 'gürültü' sınıflandırması tahmindir.", "- Temiz sonuç riski azaltır, güvenli olduğunu kanıtlamaz."]
    (job.case_dir / "report.md").write_text("\n".join(L), encoding="utf-8")
    write_html_report(job, L)


def _render_plain_bold(text: str) -> str:
    """Escapes HTML everywhere while converting **bold** spans safely."""
    out: List[str] = []
    pos = 0
    for m in re.finditer(r"\*\*([^*]+)\*\*", text):
        out.append(escape_html(text[pos:m.start()]))
        out.append(f"<strong>{escape_html(m.group(1))}</strong>")
        pos = m.end()
    out.append(escape_html(text[pos:]))
    return "".join(out)


def _render_inline_md(text: str) -> str:
    """Safely converts `code` and **bold** spans while HTML-escaping all text segments."""
    out: List[str] = []
    pos = 0
    for m in re.finditer(r"`([^`]+)`", text):
        out.append(_render_plain_bold(text[pos:m.start()]))
        out.append(f"<code>{escape_html(m.group(1))}</code>")
        pos = m.end()
    out.append(_render_plain_bold(text[pos:]))
    return "".join(out)


def write_html_report(job: Job, md_lines: List[str]) -> None:
    """Generates a standalone, self-contained HTML report with all dynamic content escaped."""
    s = job.state
    v = s.get("verdict", {})
    lvl = v.get("level", "pending")
    badge_color = {"red": "#ef4444", "yellow": "#f59e0b", "green": "#10b981", "pending": "#64748b"}.get(lvl, "#64748b")

    html_parts: List[str] = []
    in_table = False
    in_list = False

    def close_blocks(keep_table: bool = False, keep_list: bool = False) -> None:
        nonlocal in_table, in_list
        if in_table and not keep_table:
            in_table = False
            html_parts.append("</tbody></table></div>")
        if in_list and not keep_list:
            in_list = False
            html_parts.append("</ul>")

    def render_cell(c: str) -> str:
        m = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", c.strip())
        if m and re.fullmatch(r"https?://[^\s<>\"]+", m.group(2), re.I):
            return f'<a href="{escape_html(m.group(2))}" target="_blank" rel="noopener noreferrer">{escape_html(m.group(1))}</a>'
        return escape_html(c)

    for line in md_lines:
        line_s = line.strip()
        if line_s.startswith("|") and line_s.endswith("|"):
            cells = [c.strip() for c in line_s.strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue
            close_blocks(keep_table=True)
            if not in_table:
                in_table = True
                html_parts.append('<div class="table-wrap"><table>')
                row_html = "".join(f"<th>{escape_html(c)}</th>" for c in cells)
                html_parts.append(f"<thead><tr>{row_html}</tr></thead><tbody>")
            else:
                row_html = "".join(f"<td>{render_cell(c)}</td>" for c in cells)
                html_parts.append(f"<tr>{row_html}</tr>")
            continue

        is_bullet = line_s.startswith("- ") and not line_s.startswith("- **KIRMIZI:**") and not line_s.startswith("- NOT:")
        if is_bullet:
            close_blocks(keep_list=True)
            if not in_list:
                in_list = True
                html_parts.append("<ul>")
            html_parts.append(f"<li>{_render_inline_md(line_s[2:])}</li>")
            continue

        close_blocks()
        if line_s.startswith("# "):
            html_parts.append(f"<h1>{escape_html(line_s[2:])}</h1>")
        elif line_s.startswith("## "):
            html_parts.append(f"<h2>{escape_html(line_s[3:])}</h2>")
        elif line_s.startswith("### "):
            html_parts.append(f"<h3>{escape_html(line_s[4:])}</h3>")
        elif line_s.startswith("- **KIRMIZI:**"):
            html_parts.append(f'<div class="item-red"><b>🚨 KIRMIZI:</b> {escape_html(line_s[14:].strip())}</div>')
        elif line_s.startswith("- NOT:"):
            html_parts.append(f'<div class="item-note"><b>ℹ️ NOT:</b> {escape_html(line_s[6:].strip())}</div>')
        elif line_s:
            html_parts.append(f"<p>{_render_inline_md(line_s)}</p>")

    close_blocks()

    body_html = "\n".join(html_parts)
    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <title>SafeBox Analiz Raporu - {escape_html(Path(s.get('sample', 'sample')).name)}</title>
  <style>
    body {{ background: #0b0f19; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; padding: 2rem; max-width: 1000px; margin: 0 auto; line-height: 1.5; }}
    h1 {{ color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem; }}
    h2 {{ color: #94a3b8; margin-top: 1.5rem; border-bottom: 1px solid #1e293b; padding-bottom: 0.3rem; }}
    h3 {{ color: #cbd5e1; margin-top: 1rem; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: bold; background: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color}66; margin-bottom: 1rem; }}
    .item-red {{ background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #fca5a5; padding: 0.5rem 0.75rem; border-radius: 8px; margin: 0.3rem 0; font-size: 0.9rem; }}
    .item-note {{ background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.4); color: #fde68a; padding: 0.5rem 0.75rem; border-radius: 8px; margin: 0.3rem 0; font-size: 0.9rem; }}
    code {{ background: #1e293b; color: #38bdf8; padding: 0.15rem 0.3rem; border-radius: 4px; font-family: Consolas, monospace; font-size: 0.85em; }}
    ul {{ padding-left: 1.25rem; margin: 0.4rem 0; }}
    li {{ margin: 0.25rem 0; }}
    .table-wrap {{ overflow-x: auto; margin: 1rem 0; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    th, td {{ padding: 0.5rem; text-align: left; border: 1px solid #1e293b; }}
    th {{ background: #111827; color: #94a3b8; }}
    a {{ color: #38bdf8; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <div class="badge">SONUÇ: {escape_html(lvl.upper())}</div>
  {body_html}
</body>
</html>"""
    (job.case_dir / "report.html").write_text(html, encoding="utf-8")


def escape_html(s: Any) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


_NOISE_DOMAIN_CLASSES = {"Windows/Microsoft (gürültü)", "Yerel (gürültü)"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _csv_safe(val: Any) -> str:
    s = str(val or "")
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def _stix_escape(val: Any) -> str:
    return str(val or "").replace("\\", "\\\\").replace("'", "\\'")


def _clean_ip(raw: Any) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    txt = str(raw or "").strip()
    if not txt:
        return None
    if txt.startswith("[") and "]" in txt:
        txt = txt[1:txt.index("]")]
    try:
        return ipaddress.ip_address(txt)
    except ValueError:
        return None


def collect_iocs(job: Job, include_noise: bool = False) -> List[Dict[str, Any]]:
    """Extracts deduplicated file hashes, domains, IPs, and URLs from job state & inventory."""
    s = job.snapshot()
    found: Dict[tuple, Dict[str, Any]] = {}

    def add(ioc_type: str, value: str, source: str, classification: str = "",
            context: str = "", malicious: bool = False) -> None:
        v = str(value or "").strip()
        if not v:
            return
        norm = v.lower() if ioc_type in ("sha256", "domain", "ipv4", "ipv6") else v
        key = (ioc_type, norm)
        cur = found.get(key)
        if cur is None:
            found[key] = {
                "type": ioc_type,
                "value": norm if ioc_type in ("sha256", "domain", "ipv4", "ipv6") else v,
                "source": source,
                "classification": classification,
                "context": context[:300],
                "malicious": bool(malicious),
            }
            return
        if malicious:
            cur["malicious"] = True
        if source and source not in cur["source"].split(", "):
            cur["source"] = f"{cur['source']}, {source}"
        if classification and classification not in cur["classification"]:
            cur["classification"] = f"{cur['classification']}; {classification}" if cur["classification"] else classification
        if context and context not in cur["context"] and len(cur["context"]) < 240:
            cur["context"] = f"{cur['context']} | {context}"[:300] if cur["context"] else context[:300]

    # 1. File hashes (inventory + static + VT + sandbox dropped hashes)
    orig_sha = (s.get("inventory") or {}).get("original_sha256")
    if orig_sha and _SHA256_RE.fullmatch(orig_sha.lower()):
        add("sha256", orig_sha.lower(), "sample", "Orijinal örnek", Path(s.get("sample", "")).name)

    inv = _load_inventory(job)
    for rec in inv.get("files") or []:
        sha = (rec.get("sha256") or "").strip().lower()
        if _SHA256_RE.fullmatch(sha):
            sig_st = ((rec.get("sig") or {}).get("status")) or ""
            add("sha256", sha, "sample", f"İmza: {sig_st}" if sig_st else "Envanter",
                rec.get("rel", ""), malicious=(sig_st == "HashMismatch"))

    for st in s.get("static") or []:
        sha = (st.get("sha256") or (st.get("hashes") or {}).get("sha256") or "").strip().lower()
        if _SHA256_RE.fullmatch(sha):
            score = int(st.get("risk_score") or 0)
            yara = [m.get("rule") for m in (st.get("yara_matches") or []) if m.get("rule")]
            cls = f"Risk {score}/100" + (f" [YARA: {', '.join(yara[:3])}]" if yara else "")
            add("sha256", sha, "static", cls, st.get("rel", ""),
                malicious=(score >= 50 or bool(yara)))
        for ip_raw in st.get("interesting_ips") or []:
            ip_part = str(ip_raw).strip().rsplit(":", 1)[0] if ":" in str(ip_raw) else str(ip_raw).strip()
            ip_obj = _clean_ip(ip_part)
            if ip_obj and not (ip_obj.is_unspecified or ip_obj.is_loopback or ip_obj.is_multicast):
                itype = "ipv6" if ip_obj.version == 6 else "ipv4"
                add(itype, str(ip_obj), "static", "Statik dizge içi IP", f"{st.get('rel', '')} ({ip_raw})")
        for u in st.get("interesting_urls") or []:
            u = str(u).strip()
            if u.startswith(("http://", "https://")):
                host = (urlparse(u).hostname or "").lower().rstrip(".")
                dcls = domain_class(host) if host else CLASS_UNKNOWN
                if host and (include_noise or dcls not in _NOISE_DOMAIN_CLASSES):
                    add("domain", host, "static", dcls, f"URL içinde: {st.get('rel', '')}",
                        malicious=(dcls == CLASS_ABUSED))
                if include_noise or not host or dcls not in _NOISE_DOMAIN_CLASSES:
                    add("url", u, "static", dcls, st.get("rel", ""), malicious=(dcls == CLASS_ABUSED))

    for e in s.get("vt") or []:
        sha = (e.get("sha256") or "").strip().lower()
        if _SHA256_RE.fullmatch(sha):
            r = e.get("result") or {}
            mal = int((r.get("stats") or {}).get("malicious") or 0) if r else 0
            tot = int((r.get("stats") or {}).get("total") or 0) if r else 0
            intel = e.get("intel") or {}
            intel_mal = bool(intel.get("malicious") or (intel.get("threatfox") or {}).get("found"))
            lbl = (r.get("suggested_threat_label") if r else "") or intel.get("summary") or e.get("status") or ""
            cls = f"VT {mal}/{tot} ({lbl})" if tot else f"VT/İstihbarat: {lbl}"
            add("sha256", sha, "vt", cls, e.get("rel", ""), malicious=(mal > 0 or intel_mal))

    b = s.get("behavior") or {}
    for d in (b.get("Files") or {}).get("DroppedHashes") or []:
        if not isinstance(d, dict):
            continue
        sha = str(d.get("SHA256") or "").strip().lower()
        if _SHA256_RE.fullmatch(sha):
            add("sha256", sha, "dropped", "Sandbox'ta yeni oluşturulan dosya", str(d.get("Path") or ""))

    # 2. Domains & URLs from network summary + sandbox DNS cache
    net = s.get("network") or {}
    for entry in (net.get("dns") or []) + (net.get("sni") or []):
        dom = str(entry.get("name") or "").strip().lower().rstrip(".")
        if not dom or _clean_ip(dom):
            continue
        dcls = entry.get("class") or domain_class(dom)
        if include_noise or dcls not in _NOISE_DOMAIN_CLASSES:
            add("domain", dom, "network", dcls, f"×{entry.get('count', 1)}",
                malicious=(dcls == CLASS_ABUSED))

    for row in net.get("http") or []:
        host = str(row.get("host") or "").strip().lower().rstrip(".")
        uri = str(row.get("uri") or "")
        method = str(row.get("method") or "GET")
        dcls = row.get("class") or (domain_class(host) if host else CLASS_UNKNOWN)
        if host and not _clean_ip(host) and (include_noise or dcls not in _NOISE_DOMAIN_CLASSES):
            add("domain", host, "network", dcls, f"HTTP {method}", malicious=(dcls == CLASS_ABUSED))
        if host and (include_noise or dcls not in _NOISE_DOMAIN_CLASSES):
            add("url", f"http://{host}{uri}", "network", dcls, f"HTTP {method}",
                malicious=(dcls == CLASS_ABUSED))

    for dns_row in (b.get("Network") or {}).get("DnsCache") or []:
        if not isinstance(dns_row, dict):
            continue
        dom = str(dns_row.get("Name") or "").strip().lower().rstrip(".")
        if not dom or _clean_ip(dom):
            continue
        dcls = domain_class(dom)
        if include_noise or dcls not in _NOISE_DOMAIN_CLASSES:
            add("domain", dom, "behavior", dcls, f"DnsCache -> {dns_row.get('Data') or ''}",
                malicious=(dcls == CLASS_ABUSED))

    fn_domains, fn_urls = _extract_fakenet_targets(b.get("FakeNetRequests") or [])
    for dom in fn_domains:
        dcls = domain_class(dom)
        if include_noise or dcls not in _NOISE_DOMAIN_CLASSES:
            add("domain", dom, "fakenet", dcls, "FakeNet tuzağı", malicious=(dcls == CLASS_ABUSED))
    for u in fn_urls:
        host = (urlparse(u).hostname or "").lower().rstrip(".")
        dcls = domain_class(host) if host else CLASS_UNKNOWN
        if include_noise or not host or dcls not in _NOISE_DOMAIN_CLASSES:
            add("url", u, "fakenet", dcls, "FakeNet tuzağı", malicious=(dcls == CLASS_ABUSED))

    # 3. IP addresses from sandbox connections + tshark SYN targets
    for conn in (b.get("Network") or {}).get("Connections") or []:
        if not isinstance(conn, dict):
            continue
        ip_obj = _clean_ip(conn.get("Remote"))
        if not ip_obj or ip_obj.is_unspecified or ip_obj.is_loopback or ip_obj.is_multicast:
            continue
        from_sample = bool(conn.get("FromSample"))
        if (ip_obj.is_private or ip_obj.is_link_local) and not (include_noise or from_sample):
            continue
        itype = "ipv6" if ip_obj.version == 6 else "ipv4"
        proc = str(conn.get("Process") or "")
        port = conn.get("Port") or ""
        cls = "Yerel/LAN (örnek)" if (ip_obj.is_private or ip_obj.is_link_local) else ("Örnek bağlantısı" if from_sample else "Dış IP")
        add(itype, str(ip_obj), "behavior", cls, f"{proc}:{port}".strip(":"), malicious=from_sample)

    for tgt in net.get("tcp_targets") or []:
        raw_t = str(tgt.get("target") or "")
        ip_part = raw_t.rsplit(":", 1)[0] if ":" in raw_t else raw_t
        ip_obj = _clean_ip(ip_part)
        if not ip_obj or ip_obj.is_unspecified or ip_obj.is_loopback or ip_obj.is_multicast:
            continue
        if (ip_obj.is_private or ip_obj.is_link_local) and not include_noise:
            continue
        itype = "ipv6" if ip_obj.version == 6 else "ipv4"
        add(itype, str(ip_obj), "network", "Dış IP (SYN)", f"{raw_t} ×{tgt.get('count', 1)}")

    order = {"sha256": 0, "domain": 1, "ipv4": 2, "ipv6": 3, "url": 4}
    return sorted(found.values(), key=lambda x: (not x["malicious"], order.get(x["type"], 9), x["value"]))


def export_iocs_csv(job: Job, include_noise: bool = False) -> str:
    """Exports extracted job IOCs as formula-safe CSV text."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["type", "value", "malicious", "source", "classification", "context"])
    for item in collect_iocs(job, include_noise=include_noise):
        val = item["value"] if item["type"] in ("sha256", "domain", "ipv4", "ipv6") else _csv_safe(item["value"])
        w.writerow([
            item["type"],
            val,
            "true" if item["malicious"] else "false",
            _csv_safe(item["source"]),
            _csv_safe(item["classification"]),
            _csv_safe(item["context"]),
        ])
    return buf.getvalue()


def export_iocs_stix(job: Job, include_noise: bool = False) -> Dict[str, Any]:
    """Exports extracted job IOCs as a STIX 2.1 Bundle dictionary."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'safebox-analyzer:identity')}"
    objects: List[Dict[str, Any]] = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": ts,
        "modified": ts,
        "name": "SafeBox Analyzer",
        "identity_class": "system",
    }]
    for item in collect_iocs(job, include_noise=include_noise):
        t, v = item["type"], item["value"]
        esc_v = _stix_escape(v)
        if t == "sha256":
            pattern = f"[file:hashes.'SHA-256' = '{esc_v}']"
        elif t == "domain":
            pattern = f"[domain-name:value = '{esc_v}']"
        elif t == "ipv4":
            pattern = f"[ipv4-addr:value = '{esc_v}']"
        elif t == "ipv6":
            pattern = f"[ipv6-addr:value = '{esc_v}']"
        elif t == "url":
            pattern = f"[url:value = '{esc_v}']"
        else:
            continue
        ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'{job.id}:{t}:{v}')}"
        labels = [x for x in (item["source"], item["classification"]) if x]
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": ts,
            "modified": ts,
            "valid_from": ts,
            "created_by_ref": identity_id,
            "name": f"{t}: {v[:120]}",
            "description": item["context"] or item["classification"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "indicator_types": ["malicious-activity"] if item["malicious"] else ["anomalous-activity"],
            "confidence": 85 if item["malicious"] else 40,
            "labels": labels[:6],
        })
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, f'safebox-bundle:{job.id}')}",
        "objects": objects,
    }


def compare_jobs(base_job: Job, target_job: Job) -> Dict[str, Any]:
    """Computes static, signature, YARA, behavioral, and network deltas from base (official) to target (patched/crack)."""
    b_st = base_job.snapshot()
    t_st = target_job.snapshot()

    def _inv_map(job: Job) -> Dict[str, Dict[str, Any]]:
        inv = _load_inventory(job)
        out_map: Dict[str, Dict[str, Any]] = {}
        for rec in inv.get("files") or []:
            rel = str(rec.get("rel") or "").strip()
            if rel:
                out_map[rel.lower()] = rec
        return out_map

    b_files = _inv_map(base_job)
    t_files = _inv_map(target_job)
    added_files: List[Dict[str, Any]] = []
    removed_files: List[str] = []
    modified_files: List[Dict[str, Any]] = []

    for k, tr in sorted(t_files.items()):
        br = b_files.get(k)
        t_sig = ((tr.get("sig") or {}).get("status")) or "Unknown"
        if br is None:
            added_files.append({"rel": tr.get("rel", ""), "size": tr.get("size", 0), "sha256": tr.get("sha256", ""), "sig": t_sig})
        else:
            b_sha = (br.get("sha256") or "").lower()
            t_sha = (tr.get("sha256") or "").lower()
            b_sig = ((br.get("sig") or {}).get("status")) or "Unknown"
            if b_sha and t_sha and b_sha != t_sha:
                modified_files.append({
                    "rel": tr.get("rel", ""),
                    "base_sha256": b_sha,
                    "target_sha256": t_sha,
                    "base_sig": b_sig,
                    "target_sig": t_sig,
                    "sig_broken": (b_sig == "Valid" and t_sig != "Valid") or t_sig == "HashMismatch",
                })
    for k, br in sorted(b_files.items()):
        if k not in t_files:
            removed_files.append(str(br.get("rel") or ""))

    b_static = {str(x.get("rel") or "").lower(): x for x in (b_st.get("static") or [])}
    t_static = {str(x.get("rel") or "").lower(): x for x in (t_st.get("static") or [])}
    static_deltas: List[Dict[str, Any]] = []
    for k, ts in sorted(t_static.items()):
        bs = b_static.get(k) or {}
        b_score = int(bs.get("risk_score") or 0)
        t_score = int(ts.get("risk_score") or 0)
        b_yara = {m.get("rule") for m in (bs.get("yara_matches") or []) if m.get("rule")}
        t_yara = [m.get("rule") for m in (ts.get("yara_matches") or []) if m.get("rule") and m.get("rule") not in b_yara]
        b_reasons = set(bs.get("risk_reasons") or [])
        new_reasons = [r for r in (ts.get("risk_reasons") or []) if r not in b_reasons]
        if (not bs and t_score >= 20) or (t_score > b_score) or t_yara:
            static_deltas.append({
                "rel": ts.get("rel", ""),
                "base_score": b_score if bs else None,
                "target_score": t_score,
                "score_delta": t_score - b_score,
                "new_yara": t_yara,
                "new_reasons": new_reasons[:5],
            })
    static_deltas.sort(key=lambda x: (-len(x["new_yara"]), -x["score_delta"], -x["target_score"]))

    b_beh = b_st.get("behavior") or {}
    t_beh = t_st.get("behavior") or {}

    def _diff_list(b_items, t_items) -> List[str]:
        bset = {str(x) for x in (b_items or [])}
        seen = set()
        res = []
        for x in (t_items or []):
            s_val = str(x)
            if s_val not in bset and s_val not in seen:
                seen.add(s_val)
                res.append(s_val)
        return res

    b_per, t_per = b_beh.get("Persistence") or {}, t_beh.get("Persistence") or {}
    behavior_diff = {
        "has_behavior_both": bool(b_beh and t_beh),
        "services": _diff_list(b_per.get("Services"), t_per.get("Services")),
        "drivers": _diff_list(b_per.get("Drivers"), t_per.get("Drivers")),
        "tasks": _diff_list(b_per.get("Tasks"), t_per.get("Tasks")),
        "runkeys": _diff_list((b_per.get("RunKeys") or []) + (b_per.get("Startup") or []), (t_per.get("RunKeys") or []) + (t_per.get("Startup") or [])),
        "wmi_subscriptions": _diff_list(b_per.get("WmiSubscriptions"), t_per.get("WmiSubscriptions")),
        "com_hijacks": _diff_list(b_per.get("ComHijacks"), t_per.get("ComHijacks")),
        "appinit_dlls": _diff_list(b_per.get("AppInitDlls"), t_per.get("AppInitDlls")),
        "bits_jobs": _diff_list(b_per.get("BitsJobs"), t_per.get("BitsJobs")),
        "ps_profiles": _diff_list(b_per.get("PsProfiles"), t_per.get("PsProfiles")),
        "defender": _diff_list((b_beh.get("Defender") or {}).get("Added") or [], (t_beh.get("Defender") or {}).get("Added") or []),
        "hosts": _diff_list((b_beh.get("Hosts") or {}).get("Added"), (t_beh.get("Hosts") or {}).get("Added")),
        "hosts_removed": _diff_list((b_beh.get("Hosts") or {}).get("Removed"), (t_beh.get("Hosts") or {}).get("Removed")),
        "firewall": _diff_list((b_beh.get("Firewall") or {}).get("Added"), (t_beh.get("Firewall") or {}).get("Added")),
        "dropped_executables": _diff_list((b_beh.get("Files") or {}).get("NewExecutables"), (t_beh.get("Files") or {}).get("NewExecutables")),
        "modified_executables": _diff_list((b_beh.get("Files") or {}).get("ModifiedExecutables"), (t_beh.get("Files") or {}).get("ModifiedExecutables")),
        "new_listening": _diff_list((b_beh.get("Network") or {}).get("NewListening"), (t_beh.get("Network") or {}).get("NewListening")),
        "honeyfile_alerts": _diff_list(b_beh.get("HoneyfileAlerts"), t_beh.get("HoneyfileAlerts")),
        "memory_findings": _diff_list(b_beh.get("MemoryFindings"), t_beh.get("MemoryFindings")),
        "fakenet_requests": _diff_list(b_beh.get("FakeNetRequests"), t_beh.get("FakeNetRequests")),
        "suspicious_processes": _diff_list(
            [f"{p.get('Name')}: {p.get('CommandLine') or ''}" for p in (b_beh.get("Processes") or []) if isinstance(p, dict) and p.get("Suspicious")],
            [f"{p.get('Name')}: {p.get('CommandLine') or ''}" for p in (t_beh.get("Processes") or []) if isinstance(p, dict) and p.get("Suspicious")],
        ),
    }

    b_iocs = collect_iocs(base_job)
    t_iocs = collect_iocs(target_job)
    b_net_vals = {(x["type"], x["value"]) for x in b_iocs if x["type"] in ("domain", "ipv4", "ipv6")}
    extra_domains = [x for x in t_iocs if x["type"] == "domain" and ("domain", x["value"]) not in b_net_vals]
    extra_ips = [x for x in t_iocs if x["type"] in ("ipv4", "ipv6") and (x["type"], x["value"]) not in b_net_vals]

    highlights: List[str] = []
    if modified_files:
        broken = sum(1 for m in modified_files if m["sig_broken"])
        highlights.append(f"{len(modified_files)} dosya resmi sürümden farklı hash'e sahip" + (f" ({broken} imzası bozulmuş/HashMismatch)" if broken else "") + ".")
    if added_files:
        highlights.append(f"Hedef pakette resmi sürüme ek {len(added_files)} yeni dosya var.")
    if static_deltas:
        yara_hits = sum(len(d["new_yara"]) for d in static_deltas)
        highlights.append(f"{len(static_deltas)} dosyada statik risk artışı" + (f" ve {yara_hits} yeni YARA eşleşmesi" if yara_hits else "") + ".")
    pers_cnt = sum(len(behavior_diff[k]) for k in (
        "services", "drivers", "tasks", "runkeys", "wmi_subscriptions", "com_hijacks", "appinit_dlls", "bits_jobs", "ps_profiles",
        "defender", "firewall", "modified_executables", "new_listening", "honeyfile_alerts", "memory_findings", "fakenet_requests",
    ))
    if pers_cnt:
        highlights.append(f"Hedef sandbox'ta fazladan {pers_cnt} kalıcılık/güvenlik/davranış farkı bıraktı.")
    if extra_domains or extra_ips:
        highlights.append(f"Hedef fazladan {len(extra_domains)} alan adı ve {len(extra_ips)} IP ile iletişim kurdu.")

    return {
        "base": {"id": base_job.id, "sample": b_st.get("sample", ""), "verdict": (b_st.get("verdict") or {}).get("level", "pending")},
        "target": {"id": target_job.id, "sample": t_st.get("sample", ""), "verdict": (t_st.get("verdict") or {}).get("level", "pending")},
        "highlights": highlights,
        "files": {
            "modified": modified_files[:100],
            "added": added_files[:100],
            "removed": removed_files[:100],
        },
        "static_deltas": static_deltas[:40],
        "behavior_diff": behavior_diff,
        "network_diff": {
            "extra_domains": extra_domains[:100],
            "extra_ips": extra_ips[:100],
        },
    }


# ======================================================================== downloads watcher
def _file_in_use(path: Path) -> bool:
    """True if another process still has the file open (e.g. a downloader writing to it).
    Opening with share mode 0 fails with ERROR_SHARING_VIOLATION while any other handle is open."""
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    GENERIC_READ, OPEN_EXISTING, INVALID = 0x80000000, 3, wintypes.HANDLE(-1).value
    h = k32.CreateFileW(str(path), GENERIC_READ, 0, None, OPEN_EXISTING, 0, None)
    if h == INVALID:
        return ctypes.get_last_error() in (32, 33)   # sharing / lock violation
    k32.CloseHandle(h)
    return False



def is_later_volume(name: str) -> bool:
    """True for the 2nd+ volume of a multi-part archive (analysing those alone is pointless; part 1 pulls them in).
    name.part1.rar / .part01.rar / .part001.rar and name.001 are the first volume; .r00, .r01 ... follow a name.rar."""
    n = name.lower()
    m = re.search(r"\.part(\d+)\.rar$", n)
    if m:
        return int(m.group(1)) > 1
    if re.search(r"\.r\d{2}$", n):
        return True
    m = re.search(r"\.(\d{3})$", n)          # 7-Zip / HJSplit style: .001, .002 ...
    if m:
        return int(m.group(1)) > 1
    return False


class DownloadWatcher:
    IGNORE = (".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload", ".!ut")
    STABLE_POLLS = 3   # 3 polls x 5 s with an unchanged size
    SETTINGS = BASE_DIR / "watch.json"

    def __init__(self):
        cfg = _read_json(self.SETTINGS) or {}
        self.folder = cfg.get("folder") or str(Path.home() / "Downloads")
        self.enabled = bool(cfg.get("enabled", False))
        self.auto_start = bool(cfg.get("auto_start", False))
        self.found: List[Dict[str, Any]] = []
        self._seen: Dict[str, Any] = {}
        self._baseline: Dict[str, Any] = {}
        self._lock = threading.Lock()
        if self.enabled:
            self._take_baseline()
        threading.Thread(target=self._loop, daemon=True, name="download-watcher").start()

    def _take_baseline(self) -> None:
        """Files already in the folder when watching starts are not 'new'. Anything that appears later - downloaded,
        moved or copied in, whatever its modification date - is. A baseline file that changes (size/mtime) counts as new."""
        self._baseline = {}
        try:
            for p in Path(self.folder).iterdir():
                if p.is_file():
                    st = p.stat()
                    self._baseline[str(p)] = (st.st_size, st.st_mtime_ns)
        except OSError:
            pass
        self._seen.clear()

    def configure(self, folder: Optional[str], enabled: bool, auto_start: bool) -> Dict[str, Any]:
        with self._lock:
            changed_folder = bool(folder and Path(folder).is_dir() and folder != self.folder)
            if folder and Path(folder).is_dir():
                self.folder = folder
            if (enabled and not self.enabled) or (enabled and changed_folder):
                self._take_baseline()
            self.enabled, self.auto_start = enabled, auto_start
            _write_json(self.SETTINGS, {"folder": self.folder, "enabled": self.enabled, "auto_start": self.auto_start})
        return self.status()

    def status(self) -> Dict[str, Any]:
        return {"folder": self.folder, "enabled": self.enabled, "auto_start": self.auto_start, "found": self.found[-30:]}

    def _loop(self) -> None:
        while True:
            time.sleep(5)
            if not self.enabled:
                continue
            try:
                self.poll_once()
            except Exception:
                traceback.print_exc()

    def poll_once(self) -> None:
        """One scan of the folder (the background loop calls this every 5 s)."""
        with self._lock:
            for p in Path(self.folder).iterdir():
                if not p.is_file() or p.name.lower().endswith(self.IGNORE):
                    continue
                st = p.stat()
                key = str(p)
                if self._baseline.get(key) == (st.st_size, st.st_mtime_ns):
                    continue
                if any(f["path"] == key for f in self.found):
                    continue
                prev_size, stable = self._seen.get(key, (None, 0))
                stable = stable + 1 if prev_size == st.st_size and st.st_size > 0 else 0
                self._seen[key] = (st.st_size, stable)
                # finished = same size for STABLE_POLLS polls in a row AND no other process holds the file open
                if stable >= self.STABLE_POLLS and not _file_in_use(p):
                    later_part = is_later_volume(p.name)
                    item = {"path": key, "name": p.name, "size": st.st_size, "time": _now(), "job": None, "later_part": later_part}
                    self.found.append(item)
                    if self.auto_start and not later_part:
                        # automatic runs never upload anything: hash lookups only (the user did not pick this file)
                        job = create_job(key, {"run_sandbox": False, "vt_upload": False})
                        item["job"] = job.id


load_interrupted()
