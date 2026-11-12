"""SafeBox right-click context menu launcher: enqueues a file or folder into the local SafeBox panel."""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any, Callable, Optional

BASE_DIR = Path(__file__).parent.resolve()
PORT = int(os.environ.get("SAFEBOX_PORT", "8765"))
TOKEN_FILE = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()) / "SafeBox" / "session.token"
NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008


def _is_healthy(base_url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base_url}/api/health", timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _read_token(token_file: Path = TOKEN_FILE) -> str:
    try:
        return token_file.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _ensure_server(base_url: str, base_dir: Path = BASE_DIR, token_file: Path = TOKEN_FILE) -> str:
    tok = _read_token(token_file)
    if _is_healthy(base_url) and tok:
        return tok
    py = Path(sys.executable)
    py_exe = py.with_name("python.exe") if py.name.lower() == "pythonw.exe" and py.with_name("python.exe").exists() else py
    flags = NO_WINDOW | DETACHED_PROCESS if os.name == "nt" else 0
    subprocess.Popen(
        [str(py_exe), str(base_dir / "app.py")],
        cwd=str(base_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    deadline = time.time() + 18.0
    while time.time() < deadline:
        time.sleep(0.4)
        tok = _read_token(token_file)
        if _is_healthy(base_url) and tok:
            return tok
    raise RuntimeError("SafeBox yerel sunucusu başlatılamadı.")


def enqueue_path(
    target_path: str,
    base_url: Optional[str] = None,
    base_dir: Path = BASE_DIR,
    token_file: Path = TOKEN_FILE,
    opener: Callable[[str], Any] = webbrowser.open,
) -> str:
    url = (base_url or f"http://127.0.0.1:{PORT}").rstrip("/")
    tok = _ensure_server(url, base_dir=base_dir, token_file=token_file)
    payload = json.dumps({
        "path": str(Path(target_path).resolve()),
        "run_sandbox": False,
        "vt_upload": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{url}/api/jobs",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-SafeBox-Token": tok,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    job_id = str(data.get("id") or "")
    panel_url = f"{url}/?token={urllib.parse.quote(tok)}" + (f"#{urllib.parse.quote(job_id)}" if job_id else "")
    opener(panel_url)
    return job_id


if __name__ == "__main__":
    if len(sys.argv) < 2 or not sys.argv[1].strip():
        sys.exit(1)
    try:
        enqueue_path(sys.argv[1])
    except Exception as exc:
        if os.name == "nt":
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, f"SafeBox başlatılamadı:\n{exc}", "SafeBox", 0x10)
        sys.exit(1)
