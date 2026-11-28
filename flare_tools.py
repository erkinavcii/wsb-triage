"""capa (what a program can do) and FLOSS (strings it hides and only builds at run time), both from Mandiant (Apache-2.0).

The standalone executables live outside this repository, in %LOCALAPPDATA%\\SafeBox\\flare, and are pinned by SHA-256:
they run on the host and read suspicious files (they never execute them), so a swapped file must not be started.
Without them this step is skipped and the panel says so.

capa reports dozens of capabilities for ordinary programs (notepad.exe: 36, among them "hide graphical window", "open
clipboard" and "anti-debugging"), so a capability on its own is never a red finding. Only a few groups are carried
into the verdict, as notes, and the combined rules in pipeline.py decide whether they add up to something."""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import hashlib

_HOME = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "SafeBox"
FLARE_DIR = Path(os.environ.get("SAFEBOX_FLARE_DIR") or (_HOME / "flare"))
CAPA_SHA256 = (os.environ.get("SAFEBOX_CAPA_SHA256") or "edda89c65a445ce45b35959459932880d78b9f886065336eb3d1e38152b6c01f").lower()
FLOSS_SHA256 = (os.environ.get("SAFEBOX_FLOSS_SHA256") or "944d876e3ce4b4190a58cce6a0c96a5cdc47db40b75d86d717ffe612bde88ca3").lower()
CAPA_VERSION = "v10.0.0"
FLOSS_VERSION = "v3.2.0"

# Both build a full vivisect workspace and slow down steeply with size. Measured (two at a time): notepad.exe 0.35 MB
# capa 34 s / FLOSS 52 s; Magnify.exe 1.3 MB capa 6 min / FLOSS > 10 min; a 3.6 MB and a 7.6 MB program did not
# finish in 5 and 19 minutes. Most stealers are well under these limits; large installers are left to the other checks.
CAPA_MAX_BYTES = 2 * 1024 * 1024
FLOSS_MAX_BYTES = 1 * 1024 * 1024
TOOL_TIMEOUT_SEC = 420            # per tool and file
MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_STRINGS = 300                 # per FLOSS kind
NO_WINDOW = 0x08000000

# Capability groups carried into the verdict. Prefixes are capa rule namespaces (capa-rules v10.0.0 layout).
CAPA_GROUPS: List[Tuple[str, str, Tuple[str, ...]]] = [
    ("family", "Zararlı ailesi kuralı", ("malware-family",)),
    ("inject", "Süreç enjeksiyonu / kabuk kodu çalıştırma", ("host-interaction/process/inject", "load-code/shellcode")),
    ("credentials", "Tarayıcı, parola ya da kart verisi toplama", ("collection/browser", "collection/password-manager",
                                                                   "collection/credit-card", "collection/file-managers",
                                                                   "host-interaction/process/dump")),
    ("spy", "Tuş kaydı / ekran, kamera ya da mikrofon kaydı", ("collection/keylog", "collection/screenshot",
                                                                "collection/microphone", "collection/webcam")),
    ("evasion", "Sanal makine / antivirüs tespiti, iz silme", ("anti-analysis/anti-vm", "anti-analysis/anti-av",
                                                               "anti-analysis/anti-emulation", "anti-analysis/anti-forensic")),
    ("persistence", "Kalıcılık kurma (başlangıç, servis, görev)", ("persistence",)),
    ("impact", "Kurtarmayı engelleme / disk silme", ("impact",)),
    ("c2", "Uzaktan komut alma / dosya aktarma (C2)", ("communication/c2",)),
]
GROUP_LABELS = {k: label for k, label, _ in CAPA_GROUPS}

_hash_cache: Dict[str, Tuple[Tuple[int, float], bool]] = {}
_hash_lock = threading.Lock()


def _pinned_ok(exe: Path, want: str) -> bool:
    try:
        st = exe.stat()
    except OSError:
        return False
    key = (st.st_size, st.st_mtime)
    with _hash_lock:
        hit = _hash_cache.get(str(exe))
        if hit and hit[0] == key:
            return hit[1]
    h = hashlib.sha256()
    try:
        with open(exe, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return False
    ok = h.hexdigest() == want
    with _hash_lock:
        _hash_cache[str(exe)] = (key, ok)
    return ok


def capa_available() -> bool:
    return _pinned_ok(FLARE_DIR / "capa.exe", CAPA_SHA256)


def floss_available() -> bool:
    return _pinned_ok(FLARE_DIR / "floss.exe", FLOSS_SHA256)


def _ns_in(ns: str, prefix: str) -> bool:
    return ns == prefix or ns.startswith(prefix + "/")


def capa_groups(capabilities: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """{group key: [rule names]} for the capability groups the verdict looks at."""
    out: Dict[str, List[str]] = {}
    for c in capabilities:
        ns = str(c.get("namespace") or "")
        for key, _, prefixes in CAPA_GROUPS:
            if any(_ns_in(ns, p) for p in prefixes):
                names = out.setdefault(key, [])
                if c.get("name") and c["name"] not in names:
                    names.append(str(c["name"]))
    return out


def parse_capa(raw: Dict[str, Any]) -> Dict[str, Any]:
    """capa -j output -> capabilities (library rules left out), groups and ATT&CK techniques. capa itself is trusted,
    but it reports on an untrusted file, so only plain, capped values are kept."""
    caps: List[Dict[str, Any]] = []
    attack: Dict[str, Dict[str, str]] = {}
    rules = raw.get("rules") if isinstance(raw, dict) else None
    for name, r in (rules.items() if isinstance(rules, dict) else []):
        meta = (r or {}).get("meta") if isinstance(r, dict) else None
        if not isinstance(meta, dict) or meta.get("lib") or meta.get("is_subscope_rule"):
            continue
        ids = []
        for a in meta.get("attack") or []:
            if isinstance(a, dict) and a.get("id"):
                tid = str(a["id"])[:16]
                ids.append(tid)
                attack.setdefault(tid, {"id": tid, "technique": str(a.get("technique") or "")[:120],
                                        "subtechnique": str(a.get("subtechnique") or "")[:120],
                                        "tactic": str(a.get("tactic") or "")[:60]})
        matches = r.get("matches")
        caps.append({"name": str(name)[:160], "namespace": str(meta.get("namespace") or "")[:120], "attack": ids,
                     "count": len(matches) if isinstance(matches, (list, dict)) else 0})
    caps.sort(key=lambda c: (c["namespace"], c["name"]))
    return {"capabilities": caps[:400], "groups": capa_groups(caps), "attack": list(attack.values())[:80]}


def parse_floss(raw: Dict[str, Any]) -> Dict[str, Any]:
    """FLOSS -j output -> the strings it rebuilt (decoded, stack, tight), deduplicated and capped."""
    strings = raw.get("strings") if isinstance(raw, dict) else None
    out: Dict[str, Any] = {"decoded": [], "stack": [], "tight": [], "total": 0}
    if not isinstance(strings, dict):
        return out
    seen = set()
    for kind, key in (("decoded", "decoded_strings"), ("stack", "stack_strings"), ("tight", "tight_strings")):
        for s in strings.get(key) or []:
            text = s.get("string") if isinstance(s, dict) else None
            if not isinstance(text, str):
                continue
            text = text.strip()
            if len(text) < 4 or text in seen:
                continue
            seen.add(text)
            out["total"] += 1
            if len(out[kind]) < MAX_STRINGS:
                out[kind].append(text[:300])
    return out


def _kill_tree(p: "subprocess.Popen[bytes]") -> None:
    """capa.exe and floss.exe are PyInstaller one-file builds: the started process unpacks itself and runs the real
    work in a child process. Killing only the parent left that child running (seen live: 20+ minutes, 1.7 GB each),
    so the whole tree goes."""
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True, timeout=30,
                           creationflags=NO_WINDOW)
        except (OSError, subprocess.TimeoutExpired):
            pass
    if p.poll() is None:
        p.kill()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        pass


def _run_tool(cmd: List[str], out_file: Path, timeout: int, should_stop: Callable[[], bool]) -> Tuple[str, str]:
    """Runs a tool with its JSON written to out_file. Returns (status, error): done / error / timeout / cancelled."""
    try:
        with open(out_file, "wb") as fh:
            p = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                 cwd=str(FLARE_DIR), creationflags=NO_WINDOW)
    except OSError as e:
        return "error", f"{type(e).__name__}: {e}"[:300]
    t0 = time.monotonic()
    err_box: List[bytes] = []
    reader = threading.Thread(target=lambda: err_box.append(p.stderr.read() if p.stderr else b""), daemon=True)
    reader.start()
    status = "done"
    while p.poll() is None:
        if should_stop():
            status = "cancelled"
            break
        if time.monotonic() - t0 > timeout:
            status = "timeout"
            break
        time.sleep(0.5)
    if p.poll() is None:
        _kill_tree(p)
    reader.join(5)
    err = (err_box[0] if err_box else b"").decode("utf-8", "replace").strip()
    if status == "done" and p.returncode != 0:
        # FLOSS / capa explain refusals on stderr (".NET file", "unsupported format"): keep the last line.
        return "error", (err.splitlines()[-1] if err else f"çıkış kodu {p.returncode}")[:300]
    return status, ""


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if path.stat().st_size > MAX_OUTPUT_BYTES:
            return None
        data = json.loads(path.read_bytes().decode("utf-8-sig", "replace") or "{}")
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def run_capa(path: str, work: Path, tag: str, should_stop: Callable[[], bool], timeout: int = TOOL_TIMEOUT_SEC) -> Dict[str, Any]:
    out = work / f"{tag}_capa.json"
    status, err = _run_tool([str(FLARE_DIR / "capa.exe"), "-j", "-q", "--", path], out, timeout, should_stop)
    if status != "done":
        return {"status": status, "error": err}
    raw = _load_json(out)
    if raw is None:
        return {"status": "error", "error": "capa çıktısı okunamadı"}
    return {"status": "done", **parse_capa(raw)}


def run_floss(path: str, work: Path, tag: str, should_stop: Callable[[], bool], timeout: int = TOOL_TIMEOUT_SEC) -> Dict[str, Any]:
    out = work / f"{tag}_floss.json"
    status, err = _run_tool([str(FLARE_DIR / "floss.exe"), "-j", "-q", "--only", "decoded", "stack", "tight", "--", path],
                            out, timeout, should_stop)
    if status != "done":
        return {"status": status, "error": err}
    raw = _load_json(out)
    if raw is None:
        return {"status": "error", "error": "FLOSS çıktısı okunamadı"}
    return {"status": "done", **parse_floss(raw)}


def analyze_files(items: List[Dict[str, Any]], work: Path, should_stop: Callable[[], bool], budget_sec: int,
                  progress: Optional[Callable[[str], None]] = None, workers: int = 2) -> List[Dict[str, Any]]:
    """items: [{"label", "path", "size"}]. Runs capa and FLOSS on each (two at a time: both are single-threaded and
    slow). Work not started within budget_sec is marked "skipped" so one huge file cannot hold up the report."""
    work.mkdir(parents=True, exist_ok=True)
    use_capa, use_floss = capa_available(), floss_available()
    deadline = time.monotonic() + budget_sec
    results: List[Dict[str, Any]] = [{"label": it["label"], "path": it["path"]} for it in items]
    tasks = []
    for i, it in enumerate(items):
        size = int(it.get("size") or 0)
        if use_capa:
            tasks.append((i, "capa") if size <= CAPA_MAX_BYTES else None)
            if size > CAPA_MAX_BYTES:
                results[i]["capa"] = {"status": "skipped", "error": "dosya capa için çok büyük"}
        if use_floss:
            tasks.append((i, "floss") if size <= FLOSS_MAX_BYTES else None)
            if size > FLOSS_MAX_BYTES:
                results[i]["floss"] = {"status": "skipped", "error": "dosya FLOSS için çok büyük"}
    tasks = [t for t in tasks if t]
    done_count = [0]
    lock = threading.Lock()

    def one(task):
        i, tool = task
        if should_stop() or time.monotonic() > deadline:
            res = {"status": "skipped", "error": "süre sınırı"}
        else:
            left = max(10, int(deadline - time.monotonic()))
            fn = run_capa if tool == "capa" else run_floss
            res = fn(items[i]["path"], work, f"{i:02d}", should_stop, min(TOOL_TIMEOUT_SEC, left))
        with lock:
            results[i][tool] = res
            done_count[0] += 1
            n = done_count[0]
        if progress:
            progress(f"capa / FLOSS: {n}/{len(tasks)} ({items[i]['label']})")

    if tasks:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            list(ex.map(one, tasks))
    return results


_URL_RX = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}", re.I)
_HOST_RX = re.compile(r"^https?://([^/:?#]+)", re.I)


def floss_urls(floss: Dict[str, Any]) -> List[str]:
    found: List[str] = []
    for kind in ("decoded", "stack", "tight"):
        for s in floss.get(kind) or []:
            for m in _URL_RX.findall(str(s)):
                if m not in found:
                    found.append(m)
    return found[:50]


def url_host(url: str) -> str:
    m = _HOST_RX.match(url)
    return m.group(1).lower().rstrip(".") if m else ""
