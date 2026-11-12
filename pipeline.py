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
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time
import traceback
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import analyzer
import sandbox_manager as sbm
import vt_client

BASE_DIR = Path(__file__).parent.resolve()
CASES_DIR = BASE_DIR / "cases"
CASES_DIR.mkdir(parents=True, exist_ok=True)
MONITOR_SCRIPT = BASE_DIR / "sandbox" / "Inside-Sandbox.ps1"
NO_WINDOW = 0x08000000

ARCHIVE_EXT = {".rar", ".zip", ".7z", ".001", ".cab", ".iso", ".gz", ".tgz", ".tar", ".xz", ".bz2"}
SCRIPT_EXT = {".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar", ".msi", ".scr", ".com", ".reg", ".pif"}
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
    "duration_min": 10,
    "network": True,
    "vt_upload": True,
    "max_vt": 12,
    "run_sandbox": True,
    "keep_sandbox_open": False,
    "memory_mb": 4096,
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
    def __init__(self, case_dir: Path, state: Dict[str, Any], password: str = ""):
        self.case_dir = case_dir
        self.state = state
        self.lock = threading.RLock()
        # The archive password lives only in memory: never in state.json, never in API responses.
        self.password = password

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
    safe = re.sub(r"[^\w.-]", "_", src.name)[:40] or "sample"
    case_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}_{safe}"
    if (CASES_DIR / case_id).exists():      # two jobs for the same file within one second
        case_id = f"{case_id}_{uuid.uuid4().hex[:4]}"
    case_dir = CASES_DIR / case_id
    for sub in ("input", "output", "tools"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    job = Job(case_dir, _new_state(case_id, str(src.resolve()), opts), password)
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


def start_sandbox_later(job: Job) -> None:
    # Check-and-set under the job lock: a double click, or a click while the job is queued/running, must not start a
    # second sandbox thread on the same case folder.
    with job.lock:
        if job.state["status"] == "running" or job.state["stages"]["sandbox"]["status"] in ("running", "queued"):
            raise PipelineError("Bu analiz zaten çalışıyor ya da sandbox sırasında bekliyor.")
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


INSTALLER_EXT = {".msi", ".msix", ".cab", ".exe"}
MAX_INSTALLER_UNPACK_BYTES = 512 * 1024 * 1024
_NON_CONTAINER_7Z_TYPES = {"pe", "elf", "macho", "coff", "te"}


def _unpack_one_installer(job: Job, sz: str, cand: Path, dest_dir: Path, depth: int = 0) -> int:
    """Uses 7-Zip to unpack MSI/NSIS/SFX/CAB installer containers for static/VT inspection.
    Never unpacks bare PE section tables (Type = PE only). Returns extracted file count."""
    try:
        lp = subprocess.run([sz, "l", "-slt", "-p", str(cand)], capture_output=True, text=True,
                            timeout=120, errors="replace", creationflags=NO_WINDOW)
    except Exception:
        return 0
    if lp.returncode != 0:
        return 0
    types = [m.strip() for m in re.findall(r"^Type = (.+)$", lp.stdout or "", re.M)]
    if not types or all(t.lower() in _NON_CONTAINER_7Z_TYPES for t in types):
        return 0
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
    """Inspects MSI/NSIS/SFX installers in input_dir and extracts inner payloads into unpacked_dir."""
    sz = sbm.seven_zip_path()
    if not sz:
        return 0
    cands = sorted(
        (p for p in inp.rglob("*")
         if p.is_file() and p.suffix.lower() in INSTALLER_EXT and p.stat().st_size <= MAX_INSTALLER_UNPACK_BYTES),
        key=lambda p: p.stat().st_size,
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
    unpacked_count = _unpack_installers(job, inp)
    msg = f"{count} dosya hazır" + (f" (+ kurulum içi {unpacked_count} dosya çıkarıldı)." if unpacked_count else ".")
    job.stage("extract", "done", msg)


# ======================================================================== 2. inventory
SIGCHECK_PS1 = r"""param([string]$ListFile, [string]$OutFile)
$ErrorActionPreference = 'SilentlyContinue'
$out = New-Object System.Collections.ArrayList
foreach ($p in [IO.File]::ReadAllLines($ListFile)) {
    if (-not $p) { continue }
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $signer = ''; $issuer = ''
    if ($s -and $s.SignerCertificate) { $signer = $s.SignerCertificate.Subject; $issuer = $s.SignerCertificate.Issuer }
    $st = 'Unknown'; $msg = ''
    if ($s) { $st = [string]$s.Status; $msg = $s.StatusMessage }
    [void]$out.Add([pscustomobject]@{ Path = $p; Status = $st; Message = $msg; Signer = $signer; Issuer = $issuer })
}
[IO.File]::WriteAllText($OutFile, (ConvertTo-Json -InputObject @($out) -Depth 3 -Compress), (New-Object System.Text.UTF8Encoding($false)))
"""


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
                subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1), "-ListFile", str(lst), "-OutFile", str(out)],
                               capture_output=True, timeout=max(120, len(batch) // 2), creationflags=NO_WINDOW)
            except subprocess.TimeoutExpired:
                timed_out += len(batch)
                continue
            for item in _read_json(out) or []:
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
               "name_flag": bool(NAME_RX.search(p.name)) or p.name.lower() in analyzer.SUSPICIOUS_FILENAMES,
               "sig": None, "missing": False, "unpacked": is_unpacked}
        try:
            rec["size"] = p.stat().st_size
            with open(p, "rb") as f:
                rec["is_pe"] = f.read(2) == b"MZ"
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
    if r["name_flag"]:
        score += 100
    if status == "HashMismatch":
        score += 80
    if r["is_script"]:
        score += 50
    if r["is_pe"] and status != "Valid":
        score += 40
    if r["rel"].lower().endswith(".exe"):
        score += 10
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


def stage_vt(job: Job) -> None:
    key = vt_client.get_api_key()
    if not key:
        job.stage("vt", "skipped", "API anahtarı yok. Sağ üstten anahtar girerseniz bu adım otomatik çalışır.")
        return
    inv = _load_inventory(job)
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
    picks = list(by_sha.values())[: int(job.opt("max_vt")) + (1 if inv.get("original") else 0)]

    # Phase 1: hash lookups for every pick, so already-known malware shows up immediately.
    # Phase 2: upload the unknown ones.  Phase 3: wait for all pending scans together.
    entries: List[Dict[str, Any]] = [{"rel": r["rel"], "sha256": r["sha256"], "size": r["size"], "status": "Sırada", "result": None,
                                      "gui_url": f"https://www.virustotal.com/gui/file/{r['sha256']}"} for r in picks]
    job.state["vt"] = entries
    unknown: List[int] = []
    quota = False                       # once the quota is used up, every further call is pointless
    for i, (r, e) in enumerate(zip(picks, entries)):
        job.check_cancel()
        if quota:
            e["status"] = "Sorgulanmadı (VirusTotal kotası doldu)"
            continue
        job.stage("vt", "running", f"1/3 Hash sorgusu ({i + 1}/{len(picks)}): {r['rel']} — ücretsiz API dakikada 4 istek kabul eder")
        try:
            e["result"] = vt_client.lookup(r["sha256"], key)
            if e["result"]:
                e["status"] = "VT'de kayıtlı"
            elif not job.opt("vt_upload"):
                e["status"] = "VT'de yok (yükleme kapalı)"
            elif not _uploadable(r, inv):
                e["status"] = "VT'de yok (program değil; gizlilik için yüklenmedi)"
            elif r["size"] > vt_client.MAX_UPLOAD:
                e["status"] = "VT'de yok (650 MB'tan büyük, yüklenemez)"
            else:
                e["status"] = "VT'de yok — yüklenecek"
                unknown.append(i)
        except vt_client.VtQuotaError:
            quota = True
            e["status"] = "Sorgulanmadı (VirusTotal kotası doldu)"
        except Exception as ex:
            e["status"] = f"Hata: {ex}"
        compute_verdict(job)
        job.save()

    pending: Dict[int, str] = {}
    for n, i in enumerate(unknown, 1):
        job.check_cancel()
        r, e = picks[i], entries[i]
        if quota:
            e["status"] = "VT'de yok — yüklenmedi (kota doldu)"
            continue
        job.stage("vt", "running", f"2/3 Yükleniyor ({n}/{len(unknown)}): {r['rel']} ({r['size'] / 1048576:.1f} MB)")
        try:
            pending[i] = vt_client.upload(r["path"], key)
            e["status"] = "Yüklendi — taranıyor"
        except vt_client.VtQuotaError:
            quota = True
            e["status"] = "VT'de yok — yüklenmedi (kota doldu)"
        except Exception as ex:
            e["status"] = f"Yükleme hatası: {ex}"
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
                break
            except Exception as ex:
                entries[i]["status"] = f"Hata: {ex}"
                del pending[i]
            if time.time() >= deadline:
                break
    for i in pending:
        entries[i]["status"] = "Yüklendi, tarama sonucu alınamadı (VT linkinden sonra bakın)"
    flagged = sum(1 for e in job.state["vt"] if e["result"] and e["result"]["stats"]["malicious"] > 0)
    if quota:
        job.log(vt_client.QUOTA_MSG)
        job.stage("vt", "done", f"Kota doldu: {sum(1 for e in entries if e['result'])} / {len(picks)} dosya sorgulanabildi, "
                                f"{flagged} tanesi işaretlendi. Kalanlar yarın tekrar denenebilir.")
    else:
        job.stage("vt", "done", f"{len(picks)} dosya sorgulandı, {flagged} tanesi en az bir motor tarafından işaretlendi.")


def _check_dropped_files_vt(job: Job, beh: Dict[str, Any]) -> None:
    """Queries VirusTotal by SHA-256 for executables dropped inside the sandbox during analysis.
    Only hash lookup is performed (no uploads, zero data leakage risk)."""
    key = vt_client.get_api_key()
    if not key:
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

    msg = f"Sandbox içinde bırakılan {len(new_drops)} yeni çalıştırılabilir dosyanın hash'i VirusTotal'de sorgulanıyor..."
    job.log(msg)
    job.stage("sandbox", "running", msg)
    quota = False
    for item in new_drops:
        job.check_cancel()
        if quota:
            break
        sha = item["SHA256"]
        p_name = Path(item["Path"]).name or "unknown.exe"
        rel_label = f"[bırakılan] {p_name}"
        entry = {
            "rel": rel_label,
            "path": item["Path"],
            "sha256": sha,
            "size": item["Size"],
            "status": "Sırada",
            "result": None,
            "gui_url": f"https://www.virustotal.com/gui/file/{sha}",
            "dropped": True,
        }
        try:
            res = vt_client.lookup(sha, key)
            if res:
                entry["result"] = res
                entry["status"] = "VT'de kayıtlı (bırakılan dosya)"
            else:
                entry["status"] = "VT'de yok (bırakılan dosya)"
        except vt_client.VtQuotaError:
            quota = True
            entry["status"] = "Sorgulanmadı (VirusTotal kotası doldu)"
        except Exception as ex:
            entry["status"] = f"Hata: {ex}"
        job.state["vt"].append(entry)
        compute_verdict(job)
        job.save()

    if quota:
        job.log(vt_client.QUOTA_MSG)


# ======================================================================== 5. sandbox
def stage_sandbox(job: Job) -> None:
    if not sbm.WSB_EXE.exists():
        job.stage("sandbox", "unavailable", "Windows Sandbox kapalı. Üstteki 'Windows Sandbox'ı Etkinleştir' butonunu kullanıp bilgisayarı yeniden başlatın.")
        return
    # Windows Sandbox runs one instance per machine: wait in line instead of failing.
    if not SANDBOX_LOCK.acquire(blocking=False):
        job.stage("sandbox", "queued", "Sırada: başka bir analizin sandbox'ı bitince otomatik başlayacak.")
        job.log("Sandbox meşgul, sıraya alındı.")
        while not SANDBOX_LOCK.acquire(timeout=5):
            job.check_cancel()          # cancelling while queued just leaves the queue
        job.log("Sıra geldi, sandbox hazırlanıyor.")
    try:
        if sbm.sandbox_state() is True:
            raise PipelineError("Açık bir Windows Sandbox penceresi var (aynı anda yalnızca bir tane açılabilir). Kapatıp tekrar deneyin.")
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
            "DurationSeconds": duration,
            "CopyMaxMB": COPY_INTO_SANDBOX_MAX_MB,   # bigger samples run in place from the read-only share
            "BlockLan": bool(job.opt("network")),     # internet allowed, home network / host blocked
        })
        wsb = job.case_dir / "analysis.wsb"
        wsb.write_text(sbm.build_wsb(job.case_dir, bool(job.opt("network")), int(job.opt("memory_mb")), job.input_dir), encoding="utf-8")

        net = "açık (trafik kaydediliyor)" if job.opt("network") else "kapalı"
        job.stage("sandbox", "running", f"Sandbox açılıyor (internet {net}, {job.opt('duration_min')} dk)...")
        job.log("Windows Sandbox başlatıldı. Örnek bir kurulum penceresi açarsa sandbox penceresinin içinden ilerleyebilirsiniz.")
        sbm.launch_sandbox(wsb)
        started = time.time()
        deadline = started + duration + 15 * 60
        done_flag = out / "done.flag"
        misses = 0
        # Heartbeat: while observing, the monitor rewrites live.json every ~5 s. A sample running as admin can kill the
        # monitor (anti-analysis); then live.json stops changing and no done.flag ever comes.
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
                state = sbm.sandbox_state()          # None = check failed (busy system): not evidence of closing
                misses = misses + 1 if state is False else 0
                if misses >= 3:                      # ~3 consecutive clear "not running" answers
                    job.log("Sandbox penceresi izleme bitmeden kapatıldı.")
                    break
        live = sanitize_sandbox_json(_read_json(out / "live.json"))
        if live:
            job.state["sandbox"]["live"] = live
        if max_gap > 60:
            job.state["sandbox"]["monitor_max_gap"] = int(max_gap)
        if job.state.pop("cancel_requested", None):
            # cancel during the sandbox = stop observing now, but keep and report what was collected
            job.log("İptal: izleme erken bitirildi, o ana kadar toplanan sonuçlar raporlanıyor.")
        if not job.opt("keep_sandbox_open"):
            job.log("Sandbox kapatılıyor (içindeki her şey silinir).")
            sbm.stop_sandbox()
        elif job.state["sandbox"].get("monitor_lost"):
            job.log("İzleyici durdu; 'kapatma' seçili olmadığı için sandbox açık bırakıldı. İçindekileri ana bilgisayara kopyalamayın.")
        quarantined = quarantine_output(out)
        job.state["sandbox"]["quarantined"] = quarantined
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
OUTPUT_ALLOWLIST = {"live.json", "behavior.json", "status.txt", "timeline.log", "capture.pcapng", "procmon.pml", "done.flag"}


def quarantine_output(out: Path) -> List[str]:
    """Renames every unexpected file in output/ to *.quarantine and marks it as downloaded from the internet (MOTW),
    so a double-click cannot run something a sample dropped there."""
    moved: List[str] = []
    if not out.exists():
        return moved
    for p in sorted(out.rglob("*"), key=lambda x: len(x.parts), reverse=True):
        if not p.is_file() or (p.parent == out and p.name in OUTPUT_ALLOWLIST) or p.name.endswith(".quarantine"):
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
              ("Persistence", "Startup"), ("Defender", "Added"), ("Defender", "ThreatsDetected"), ("Hosts", "Added"),
              ("Hosts", "Removed"), ("Firewall", "Added"), ("Files", "NewExecutables"), ("Files", "ModifiedExecutables"),
              ("Network", "NewListening"), ("LanBlock", "Details"), ("LanBlock", "Exempt"), ("LanBlock", "Ranges"),
              ("Quick", "Services"), ("Quick", "Tasks"), ("Quick", "RunKeys"), ("Quick", "Startup"), ("Quick", "Defender"), ("Quick", "Hosts")]
_OBJ_LISTS = [("Processes",), ("Connections",), ("Network", "Connections"), ("Network", "DnsCache"), ("Files", "DroppedHashes")]
_INTS = [("Files", "NewCount"), ("Files", "ModifiedCount"), ("SecondsLeft",), ("ProcessCount",), ("SampleProcessCount",),
         ("SuspiciousCount",), ("ConnectionCount",)]
_BOOLS = [("LanBlock", "Requested"), ("LanBlock", "Applied"), ("LanBlock", "Tampered"), ("StoppedEarly",), ("Admin",)]
_STRS = [("RunMode",), ("Target",), ("Started",), ("Ended",), ("CaptureStatus",), ("LanBlock", "Status")]


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
    d = (d or "").lower().rstrip(".")
    if _match(d, ABUSED):
        return CLASS_ABUSED
    if _match(d, ADOBE):
        return "Adobe"
    if _match(d, NOISE):
        return "Windows/Microsoft (gürültü)"
    if _match(d, SHARED_CLOUD):
        return CLASS_CLOUD
    if d.endswith((".arpa", ".local")) or d == "wpad":
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


def network_summary(pcap: Path) -> Optional[Dict[str, Any]]:
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
    sni = [row[0] for row in q("TLS SNI", "tls.handshake.type == 1", ["tls.handshake.extensions_server_name"])]
    http = q("HTTP", "http.request", ["http.host", "http.request.method", "http.request.uri"])
    syn = q("TCP", "tcp.flags.syn == 1 && tcp.flags.ack == 0", ["ip.dst", "ipv6.dst", "tcp.dstport"])
    targets: Dict[str, int] = {}
    for row in syn:
        row += [""] * (3 - len(row))
        t = f"{row[0] or row[1]}:{row[2]}"
        targets[t] = targets.get(t, 0) + 1
    seen, http_rows = set(), []
    for row in http:
        row += [""] * (3 - len(row))
        k = tuple(row[:3])
        if k not in seen:
            seen.add(k)
            http_rows.append({"host": row[0], "method": row[1], "uri": row[2][:200], "class": domain_class(row[0])})
    return {"dns": _count(dns), "sni": _count(sni), "http": http_rows[:200],
            "tcp_targets": [{"target": k, "count": v} for k, v in sorted(targets.items(), key=lambda kv: -kv[1])[:100]],
            "partial": failed}


SEVERE_RX = re.compile(r"trojan|stealer|backdoor|\brat\b|miner|coinmin|xmrig|redline|lumma|vidar|raccoon|stealc|agenttesla|remcos|njrat|asyncrat|dropper|downloader|ransom|spyware|banker|infostealer", re.I)
TOOL_RX = re.compile(r"hacktool|riskware|crack|keygen|patch|pua|pup|activator|kms", re.I)


def compute_verdict(job: Job) -> None:
    s = job.state
    red: List[str] = []
    notes: List[str] = []
    for e in s.get("vt") or []:
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
    for st in s.get("static") or []:
        crit = [f["category"] for f in st.get("string_findings", []) if f.get("severity") == "critical"]
        if not crit:
            continue
        sig = st.get("signature") or {}
        if sig.get("status") == "Valid":
            # Signed does not mean safe (stolen certificates), but embedded browser engines (CEF/Electron) legitimately
            # contain browser-profile strings, so this stays a note.
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
        if P.get("Services"):
            red.append(f"{len(P['Services'])} yeni servis kuruldu.")
        if P.get("Drivers"):
            red.append(f"{len(P['Drivers'])} yeni sürücü kuruldu.")
        if P.get("Startup"):
            red.append(f"Başlangıç klasörüne {len(P['Startup'])} dosya eklendi.")
        if P.get("Tasks"):
            notes.append(f"{len(P['Tasks'])} yeni zamanlanmış görev — ürüne mi ait kontrol edin.")
        if P.get("RunKeys"):
            notes.append(f"{len(P['RunKeys'])} otomatik başlatma kaydı eklendi/değişti.")
        if (b.get("Hosts") or {}).get("Added"):
            notes.append(f"hosts dosyası değişti ({len(b['Hosts']['Added'])} satır) — crack'ler lisans sunucusunu genelde böyle engeller.")
        if (b.get("Firewall") or {}).get("Added"):
            notes.append(f"{len(b['Firewall']['Added'])} güvenlik duvarı kuralı eklendi — crack'ler ürünün internetini genelde böyle keser.")
        sus = [p for p in b.get("Processes") or [] if p.get("Suspicious")]
        if sus:
            red.append(f"{len(sus)} işlem şüpheli komut satırıyla çalıştı (gizli/şifreli PowerShell, indirme, Defender müdahalesi...).")
        dropped = [f for f in (b.get("Files") or {}).get("NewExecutables") or [] if re.search(r"\\AppData\\|\\Temp\\|\\ProgramData\\|\\Users\\Public\\", f, re.I)]
        if dropped:
            notes.append(f"AppData/Temp/ProgramData içine {len(dropped)} yeni çalıştırılabilir dosya bırakıldı.")
        conns = [c for c in (b.get("Network") or {}).get("Connections") or [] if c.get("FromSample")]
        if conns:
            notes.append(f"Örneğin başlattığı işlemler {len(conns)} ağ bağlantısı açtı.")
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
    s["verdict"] = {"level": level, "red": red, "notes": notes, "not_run": missing}


def stage_report(job: Job) -> None:
    job.stage("report", "running", "Rapor hazırlanıyor...")
    pcap = job.output_dir / "capture.pcapng"
    if pcap.exists():
        if sbm.tshark_path():
            job.stage("report", "running", "Ağ kaydı tshark ile özetleniyor...")
            job.state["network"] = network_summary(pcap)
        else:
            job.log("capture.pcapng hazır; otomatik özet için Wireshark kurun (tshark ile gelir).")
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
    if not v["red"] and not v["notes"]:
        L.append("- Otomatik kontroller kırmızı bayrak bulmadı. Bu dosyanın temiz olduğunu **kanıtlamaz**.")
    inv = s.get("inventory") or {}
    L += ["", "## Envanter", "", f"{inv.get('files', 0)} dosya, {inv.get('pe', 0)} çalıştırılabilir, {inv.get('unsigned', 0)} imzasız, "
          f"{inv.get('hash_mismatch', 0)} imzası bozuk, {inv.get('missing', 0)} kayıp.", ""]
    L += ["## VirusTotal", "", "| Dosya | Durum | Zararlı | Etiket | Link |", "|---|---|---|---|---|"]
    for e in s.get("vt") or []:
        r = e.get("result") or {}
        mal = f"{r['stats']['malicious']}/{r['stats']['total']}" if r else "-"
        L.append(f"| {e['rel']} | {e['status']} | {mal} | {r.get('suggested_threat_label', '') if r else ''} | [VT]({e['gui_url']}) |")
    L += ["", "## Statik analiz (en riskli 15)", ""]
    yara_rows: List[str] = []
    for st in (s.get("static") or [])[:15]:
        L.append(f"- **{st['rel']}** — risk {st['risk_score']}/100, imza: {(st.get('signature') or {}).get('status')}; " + "; ".join(st.get("risk_reasons", [])[:4]))
        for ym in st.get("yara_matches") or []:
            yara_rows.append(f"- **{st['rel']}** → `{ym.get('rule')}` ({ym.get('severity')}): {ym.get('description', '')}")
    if yara_rows:
        L += ["", "### YARA eşleşmeleri", ""] + yara_rows
    b = s.get("behavior")
    if b:
        L += ["", "## Sandbox davranışı", "", f"- Çalıştırılan: `{b.get('Target')}` ({b.get('RunMode')})",
              f"- İzleme: {b.get('Started')} → {b.get('Ended')}", f"- Ağ kaydı: {b.get('CaptureStatus')}",
              f"- Yerel ağ engeli: {(b.get('LanBlock') or {}).get('Status')}" + (" — **KALDIRILMAYA ÇALIŞILDI**" if (b.get('LanBlock') or {}).get('Tampered') else ""), ""]
        sections = [("Defender değişiklikleri", (b.get("Defender") or {}).get("Added")), ("Defender tespitleri", (b.get("Defender") or {}).get("ThreatsDetected")),
                    ("Yeni servisler", (b.get("Persistence") or {}).get("Services")), ("Yeni sürücüler", (b.get("Persistence") or {}).get("Drivers")),
                    ("Yeni zamanlanmış görevler", (b.get("Persistence") or {}).get("Tasks")), ("Otomatik başlatma kayıtları", (b.get("Persistence") or {}).get("RunKeys")),
                    ("Başlangıç klasörü", (b.get("Persistence") or {}).get("Startup")), ("hosts eklenen satırlar", (b.get("Hosts") or {}).get("Added")),
                    ("Güvenlik duvarı kuralları", (b.get("Firewall") or {}).get("Added")), ("Yeni çalıştırılabilir dosyalar", (b.get("Files") or {}).get("NewExecutables"))]
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
    net = s.get("network")
    if net:
        L += ["", "## Ağ özeti (tshark)", "", "### DNS"] + [f"- {d['name']} ×{d['count']} — {d['class']}" for d in net["dns"][:100]]
        L += ["", "### TLS SNI"] + [f"- {d['name']} ×{d['count']} — {d['class']}" for d in net["sni"][:100]]
        L += ["", "### HTTP"] + [f"- {h['method']} http://{h['host']}{h['uri']} — {h['class']}" for h in net["http"][:100]]
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
        sha = (st.get("sha256") or "").strip().lower()
        if _SHA256_RE.fullmatch(sha):
            score = int(st.get("risk_score") or 0)
            yara = [m.get("rule") for m in (st.get("yara_matches") or []) if m.get("rule")]
            cls = f"Risk {score}/100" + (f" [YARA: {', '.join(yara[:3])}]" if yara else "")
            add("sha256", sha, "static", cls, st.get("rel", ""),
                malicious=(score >= 50 or bool(yara)))
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
            lbl = r.get("suggested_threat_label") or e.get("status") or ""
            cls = f"VT {mal}/{tot} ({lbl})" if tot else f"VT: {lbl}"
            add("sha256", sha, "vt", cls, e.get("rel", ""), malicious=(mal > 0))

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
