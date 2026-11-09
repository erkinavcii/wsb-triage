"""SafeBox automatic analysis pipeline.

extract -> inventory (hash + Authenticode) -> static (PE/strings) -> VirusTotal -> Windows Sandbox -> report

Each analysis is a "case" folder under cases/:
    input/   sample copy / extracted archive (mapped read-only into the sandbox)
    tools/   monitor script + config (read-only in the sandbox; host writes stop.flag here)
    output/  written by the sandbox: live.json, behavior.json, capture.pcapng, timeline.log
    state.json, inventory.json, report.md
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import traceback
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

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
MONITOR_DEAD_SEC = 180            # no live.json update for this long while observing -> monitor considered killed

JOBS: Dict[str, "Job"] = {}
JOBS_LOCK = threading.Lock()
SANDBOX_LOCK = threading.Lock()


class PipelineError(Exception):
    pass


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
    def __init__(self, case_dir: Path, state: Dict[str, Any]):
        self.case_dir = case_dir
        self.state = state
        self.lock = threading.RLock()

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

    def save(self) -> None:
        with self.lock:
            _write_json(self.case_dir / "state.json", self.state)

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
    safe = re.sub(r"[^\w.-]", "_", src.name)[:40] or "sample"
    case_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}_{safe}"
    case_dir = CASES_DIR / case_id
    for sub in ("input", "output", "tools"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)
    job = Job(case_dir, _new_state(case_id, str(src.resolve()), opts))
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
def run_job(job: Job) -> None:
    current = None
    try:
        for key, fn in (("extract", stage_extract), ("inventory", stage_inventory), ("static", stage_static), ("vt", stage_vt)):
            current = key
            fn(job)
            compute_verdict(job)
        current = "sandbox"
        if job.opt("run_sandbox"):
            stage_sandbox(job)
        else:
            job.stage("sandbox", "waiting", "Hazır. Örneği izole ortamda çalıştırmak için 'Sandbox'ta Çalıştır' butonuna basın.")
        current = "report"
        stage_report(job)
        job.state["status"] = "waiting_sandbox" if job.state["stages"]["sandbox"]["status"] == "waiting" else "done"
    except Exception as e:
        job.log(f"HATA ({current}): {e}")
        if current:
            job.stage(current, "error", str(e))
        job.state["status"] = "error"
        traceback.print_exc()
    finally:
        compute_verdict(job)
        job.save()


def start_sandbox_later(job: Job) -> None:
    def _run():
        job.state["status"] = "running"
        try:
            stage_sandbox(job)
            stage_report(job)
            job.state["status"] = "done"
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


def stage_extract(job: Job) -> None:
    job.stage("extract", "running", "Hazırlanıyor...")
    src = Path(job.state["sample"])
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
        pw = job.opt("password") or ""
        if sz:
            ver = _seven_zip_version(sz)
            if ver is not None and ver < 25.0:
                job.log(f"UYARI: 7-Zip {ver} eski. 25.00 öncesi sürümlerde arşiv yol aşımı açıkları var (CVE-2025-11001/11002); güncelleyin.")
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
                zf.extractall(inp, pwd=pw.encode() if pw else None)
        else:
            raise PipelineError(f"{src.suffix} arşivini açmak için 7-Zip gerekli (https://www.7-zip.org, 25.01+). Kurup tekrar deneyin.")
    else:
        shutil.copy2(src, inp / src.name)
    count = sum(1 for _ in inp.rglob("*") if _.is_file())
    if count == 0:
        raise PipelineError("Hazırlanan klasörde hiç dosya yok (arşiv boş, şifre yanlış veya antivirüs hepsini silmiş olabilir).")
    job.stage("extract", "done", f"{count} dosya hazır.")


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


def check_signatures(case_dir: Path, paths: List[str]) -> Dict[str, Dict[str, str]]:
    if not paths:
        return {}
    ps1, lst, out = case_dir / "_sigcheck.ps1", case_dir / "_sigcheck_in.txt", case_dir / "_sigcheck_out.json"
    ps1.write_text(SIGCHECK_PS1, encoding="utf-8")
    lst.write_text("\n".join(paths), encoding="utf-8-sig")
    subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1), "-ListFile", str(lst), "-OutFile", str(out)],
                   capture_output=True, timeout=max(120, len(paths) // 5), creationflags=NO_WINDOW)
    res: Dict[str, Dict[str, str]] = {}
    for item in _read_json(out) or []:
        res[item["Path"]] = {"status": item.get("Status") or "Unknown", "message": item.get("Message") or "",
                             "signer": item.get("Signer") or "", "issuer": item.get("Issuer") or ""}
    for f in (ps1, lst, out):
        f.unlink(missing_ok=True)
    return res


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stage_inventory(job: Job) -> None:
    job.stage("inventory", "running", "Dosyalar hash'leniyor...")
    time.sleep(3)  # let real-time antivirus act, so quarantined files show up as missing
    inp = job.input_dir
    files = [p for p in inp.rglob("*") if p.is_file()]
    items: List[Dict[str, Any]] = []
    for i, p in enumerate(files, 1):
        if i % 100 == 0:
            job.stage("inventory", "running", f"Hash: {i} / {len(files)} dosya")
        rec = {"rel": str(p.relative_to(inp)), "path": str(p), "size": 0, "sha256": None, "is_pe": False,
               "is_script": p.suffix.lower() in SCRIPT_EXT, "name_flag": bool(NAME_RX.search(p.name)) or p.name.lower() in analyzer.SUSPICIOUS_FILENAMES,
               "sig": None, "missing": False}
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
    sigs = check_signatures(job.case_dir, to_sign)
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
    for i, (r, e) in enumerate(zip(picks, entries)):
        job.stage("vt", "running", f"1/3 Hash sorgusu ({i + 1}/{len(picks)}): {r['rel']} — ücretsiz API dakikada 4 istek kabul eder")
        try:
            e["result"] = vt_client.lookup(r["sha256"], key)
            if e["result"]:
                e["status"] = "VT'de kayıtlı"
            elif not job.opt("vt_upload"):
                e["status"] = "VT'de yok (yükleme kapalı)"
            elif r["size"] > vt_client.MAX_UPLOAD:
                e["status"] = "VT'de yok (650 MB'tan büyük, yüklenemez)"
            else:
                e["status"] = "VT'de yok — yüklenecek"
                unknown.append(i)
        except Exception as ex:
            e["status"] = f"Hata: {ex}"
        compute_verdict(job)
        job.save()

    pending: Dict[int, str] = {}
    for n, i in enumerate(unknown, 1):
        r, e = picks[i], entries[i]
        job.stage("vt", "running", f"2/3 Yükleniyor ({n}/{len(unknown)}): {r['rel']} ({r['size'] / 1048576:.1f} MB)")
        try:
            pending[i] = vt_client.upload(r["path"], key)
            e["status"] = "Yüklendi — taranıyor"
        except Exception as ex:
            e["status"] = f"Yükleme hatası: {ex}"
        job.save()

    deadline = time.time() + 10 * 60
    while pending and time.time() < deadline:
        for i, aid in list(pending.items()):
            job.stage("vt", "running", f"3/3 VirusTotal taramaları bekleniyor ({len(pending)} dosya kaldı): {picks[i]['rel']}")
            try:
                if vt_client.analysis_done(aid, key):
                    entries[i]["result"] = vt_client.lookup(picks[i]["sha256"], key)
                    entries[i]["status"] = "Yüklendi ve tarandı"
                    del pending[i]
                    compute_verdict(job)
                    job.save()
            except Exception as ex:
                entries[i]["status"] = f"Hata: {ex}"
                del pending[i]
            if time.time() >= deadline:
                break
    for i in pending:
        entries[i]["status"] = "Yüklendi, tarama hâlâ sırada (VT linkinden sonra bakın)"
    flagged = sum(1 for e in job.state["vt"] if e["result"] and e["result"]["stats"]["malicious"] > 0)
    job.stage("vt", "done", f"{len(picks)} dosya sorgulandı, {flagged} tanesi en az bir motor tarafından işaretlendi.")


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
            pass
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
            live = _read_json(out / "live.json")
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
        live = _read_json(out / "live.json")
        if live:
            job.state["sandbox"]["live"] = live
        if max_gap > 60:
            job.state["sandbox"]["monitor_max_gap"] = int(max_gap)
        if not job.opt("keep_sandbox_open"):
            job.log("Sandbox kapatılıyor (içindeki her şey silinir).")
            sbm.stop_sandbox()
        elif job.state["sandbox"].get("monitor_lost"):
            job.log("İzleyici durdu; 'kapatma' seçili olmadığı için sandbox açık bırakıldı. İçindekileri ana bilgisayara kopyalamayın.")
        quarantined = quarantine_output(out)
        job.state["sandbox"]["quarantined"] = quarantined
        if quarantined:
            job.log(f"output klasöründe beklenmeyen {len(quarantined)} dosya karantinaya alındı (.quarantine): {', '.join(quarantined[:10])}")
        beh = _read_json(out / "behavior.json")
        if beh:
            beh.get("Files", {}).pop("NewFilesSample", None)
            job.state["behavior"] = beh
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


def request_stop(job: Job) -> None:
    (job.tools_dir / "stop.flag").write_text(_now(), encoding="utf-8")
    job.log("İzlemeyi erken bitirme isteği gönderildi.")


# ======================================================================== 6. network + report
NOISE = ("microsoft.com", "windowsupdate.com", "windows.com", "windows.net", "msftconnecttest.com", "msftncsi.com", "live.com",
         "live.net", "bing.com", "bing.net", "msn.com", "office.com", "office.net", "office365.com", "microsoftonline.com", "msedge.net",
         "azureedge.net", "azurefd.net", "trafficmanager.net", "akamaized.net", "akamaiedge.net", "akadns.net", "digicert.com",
         "verisign.com", "sectigo.com", "globalsign.com", "lencr.org", "msocsp.com", "skype.com", "xboxlive.com", "microsoftstore.com",
         "onestore.ms", "aka.ms", "msauth.net", "msftauth.net", "gfx.ms", "sfx.ms")
ADOBE = ("adobe.com", "adobe.io", "adobelogin.com", "adobess.com", "adobedtm.com", "typekit.net", "behance.net", "adobecc.com", "adobe.net", "omtrdc.net")


def domain_class(d: str) -> str:
    d = (d or "").lower().rstrip(".")
    if any(d == s or d.endswith("." + s) for s in ADOBE):
        return "Adobe"
    if any(d == s or d.endswith("." + s) for s in NOISE):
        return "Windows/Microsoft (gürültü)"
    if d.endswith((".arpa", ".local")) or d == "wpad":
        return "Yerel (gürültü)"
    return "BİLİNMEYEN — incele"


def _tshark_fields(tshark: str, pcap: Path, flt: str, fields: List[str]) -> List[List[str]]:
    args = [tshark, "-r", str(pcap), "-Y", flt, "-T", "fields", "-E", "separator=|"]
    for f in fields:
        args += ["-e", f]
    p = subprocess.run(args, capture_output=True, text=True, timeout=600, errors="replace", creationflags=NO_WINDOW)
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
    dns = [n for row in _tshark_fields(tshark, pcap, "dns.flags.response == 0", ["dns.qry.name"]) for n in row[0].split(",")]
    sni = [row[0] for row in _tshark_fields(tshark, pcap, "tls.handshake.type == 1", ["tls.handshake.extensions_server_name"])]
    http = _tshark_fields(tshark, pcap, "http.request", ["http.host", "http.request.method", "http.request.uri"])
    syn = _tshark_fields(tshark, pcap, "tcp.flags.syn == 1 && tcp.flags.ack == 0", ["ip.dst", "ipv6.dst", "tcp.dstport"])
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
            "tcp_targets": [{"target": k, "count": v} for k, v in sorted(targets.items(), key=lambda kv: -kv[1])[:100]]}


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
        unk = sorted({d["name"] for d in (net.get("dns") or []) + (net.get("sni") or []) if d["class"].startswith("BİLİNMEYEN")})
        if unk:
            notes.append(f"{len(unk)} bilinmeyen (Microsoft/Adobe dışı) alan adıyla iletişim: {', '.join(unk[:10])}")
    level = "red" if red else ("yellow" if notes else ("green" if s["stages"]["vt"]["status"] == "done" or b else "pending"))
    s["verdict"] = {"level": level, "red": red, "notes": notes}


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
    for st in (s.get("static") or [])[:15]:
        L.append(f"- **{st['rel']}** — risk {st['risk_score']}/100, imza: {(st.get('signature') or {}).get('status')}; " + "; ".join(st.get("risk_reasons", [])[:4]))
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
        self._seen: Dict[str, int] = {}
        self._since = time.time()
        self._lock = threading.Lock()
        threading.Thread(target=self._loop, daemon=True, name="download-watcher").start()

    def configure(self, folder: Optional[str], enabled: bool, auto_start: bool) -> Dict[str, Any]:
        with self._lock:
            if folder and Path(folder).is_dir():
                if folder != self.folder:
                    self._seen.clear()
                self.folder = folder
            if enabled and not self.enabled:
                self._since = time.time()
                self._seen.clear()
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
                with self._lock:
                    for p in Path(self.folder).iterdir():
                        if not p.is_file() or p.name.lower().endswith(self.IGNORE):
                            continue
                        st = p.stat()
                        if st.st_mtime < self._since:
                            continue
                        key = str(p)
                        if any(f["path"] == key for f in self.found):
                            continue
                        prev_size, stable = self._seen.get(key, (None, 0))
                        stable = stable + 1 if prev_size == st.st_size and st.st_size > 0 else 0
                        self._seen[key] = (st.st_size, stable)
                        # finished = same size for STABLE_POLLS polls in a row AND no other process holds the file open
                        if stable >= self.STABLE_POLLS and not _file_in_use(p):
                            later_part = bool(re.search(r"\.(part0*([2-9]|\d{2,})\.rar|r\d\d|0*([2-9]|\d{2,})\d*)$", p.name, re.I)) and not p.name.lower().endswith(".001")
                            item = {"path": key, "name": p.name, "size": st.st_size, "time": _now(), "job": None, "later_part": later_part}
                            self.found.append(item)
                            if self.auto_start and not later_part:
                                job = create_job(key, {"run_sandbox": False})
                                item["job"] = job.id
            except Exception:
                traceback.print_exc()


load_interrupted()
