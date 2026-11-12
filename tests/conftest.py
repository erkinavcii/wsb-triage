"""Shared fixtures. Every test runs against a throw-away cases/ folder, never talks to VirusTotal and never starts a
real Windows Sandbox."""
import os
import shutil
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pipeline  # noqa: E402
import vt_client  # noqa: E402

WINDOWS = os.name == "nt"
SYSTEM32 = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"
windows_only = pytest.mark.skipif(not WINDOWS, reason="needs Windows (Authenticode, PowerShell, System32 binaries)")


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Own cases/ folder, no antivirus pause, no VT key, no network."""
    cases = tmp_path / "cases"
    cases.mkdir()
    monkeypatch.setattr(pipeline, "CASES_DIR", cases)
    monkeypatch.setattr(pipeline, "AV_SETTLE_SEC", 0)
    monkeypatch.setattr(vt_client, "get_api_key", lambda: "")

    def no_network(*a, **k):
        raise AssertionError("a test tried to reach the network")
    monkeypatch.setattr(vt_client.requests, "get", no_network)
    monkeypatch.setattr(vt_client.requests, "post", no_network)
    with pipeline.JOBS_LOCK:
        pipeline.JOBS.clear()
    yield cases
    with pipeline.JOBS_LOCK:
        pipeline.JOBS.clear()


class FakeVT:
    """Stand-in for vt_client's network functions. Records what would have been uploaded."""

    def __init__(self):
        self.known = {}          # sha256 -> summary returned by lookup
        self.uploads = []        # file names
        self.lookups = []        # sha256 values
        self.lookup_delay = 0.0

    def lookup(self, sha, key=None):
        self.lookups.append(sha)
        if self.lookup_delay:
            time.sleep(self.lookup_delay)
        return self.known.get(sha)

    def upload(self, path, key=None):
        self.uploads.append(Path(path).name)
        return "analysis-id"

    def analysis_done(self, aid, key=None):
        return True


@pytest.fixture
def fake_vt(monkeypatch):
    vt = FakeVT()
    monkeypatch.setattr(vt_client, "get_api_key", lambda: "test-key")
    monkeypatch.setattr(vt_client, "lookup", vt.lookup)
    monkeypatch.setattr(vt_client, "upload", vt.upload)
    monkeypatch.setattr(vt_client, "analysis_done", vt.analysis_done)
    return vt


def wait_job(job, timeout=120):
    t0 = time.time()
    while job.state["status"] == "running" and time.time() - t0 < timeout:
        time.sleep(0.1)
    assert job.state["status"] != "running", "job did not finish in time"
    return job


@pytest.fixture
def run_job():
    """Runs an analysis without the sandbox and waits for it."""
    def _run(path, **opts):
        opts.setdefault("run_sandbox", False)
        return wait_job(pipeline.create_job(str(path), opts))
    return _run


@pytest.fixture
def unsigned_exe():
    """Returns a factory making real PE files whose Authenticode signature is broken (so they count as candidates)."""
    def _make(dest: Path, salt: bytes = b"") -> Path:
        shutil.copy2(SYSTEM32 / "whoami.exe", dest)
        with open(dest, "ab") as f:
            f.write(b"unsigned-now" + salt)
        return dest
    return _make


def bare_job(tmp_path, case_id="t"):
    """A Job object without a worker thread, for testing verdict/sandbox logic directly."""
    case = tmp_path / "cases" / case_id
    for sub in ("input", "output", "tools"):
        (case / sub).mkdir(parents=True, exist_ok=True)
    return pipeline.Job(case, pipeline._new_state(case_id, str(tmp_path / "sample.exe"), dict(pipeline.DEFAULT_OPTIONS)))
