"""Job management: double sandbox start (A5), snapshot under concurrent writes, cancel, delete, cleanup (A12),
downloads watcher (A4), output quarantine."""
import json
import os
import threading
import time
from pathlib import Path

import pytest

import pipeline
from conftest import bare_job, wait_job


def test_sandbox_cannot_start_twice(tmp_path, monkeypatch):
    job = bare_job(tmp_path)
    job.state["status"] = "done"
    job.state["stages"]["sandbox"]["status"] = "waiting"
    gate = threading.Event()
    monkeypatch.setattr(pipeline, "stage_sandbox", lambda j: gate.wait(5))
    monkeypatch.setattr(pipeline, "stage_report", lambda j: None)
    results = []
    for _ in range(3):
        try:
            pipeline.start_sandbox_later(job)
            results.append("started")
        except pipeline.PipelineError:
            results.append("refused")
    gate.set()
    assert results == ["started", "refused", "refused"]
    wait_job(job, 10)
    assert job.state["status"] == "done"


def test_snapshot_survives_concurrent_writers(tmp_path):
    job = bare_job(tmp_path)
    stop = False

    def writer():
        i = 0
        while not stop:
            job.state["sandbox"][f"k{i % 500}"] = i          # unlocked writes that change the dict size
            job.state["sandbox"].pop(f"k{(i + 250) % 500}", None)
            i += 1
    t = threading.Thread(target=writer)
    t.start()
    errors = 0
    try:
        for _ in range(1000):
            try:
                job.snapshot()
            except RuntimeError:
                errors += 1
    finally:
        stop = True
        t.join()
    assert errors == 0


def test_cancel_during_vt(tmp_path, fake_vt):
    d = tmp_path / "pkg"
    d.mkdir()
    for n in range(6):
        (d / f"t{n}.bat").write_text(f"@echo {n}")
    fake_vt.lookup_delay = 1.0
    job = pipeline.create_job(str(d), {"run_sandbox": False, "vt_upload": False})
    t0 = time.time()
    while job.state["stages"]["vt"]["status"] != "running":
        assert time.time() - t0 < 60
        time.sleep(0.05)
    pipeline.request_cancel(job)
    t1 = time.time()
    wait_job(job, 30)
    assert time.time() - t1 < 5
    assert job.state["status"] == "cancelled"
    assert job.state["stages"]["vt"]["status"] == "skipped"
    assert job.state["stages"]["report"]["status"] == "skipped"
    with pytest.raises(pipeline.PipelineError):
        pipeline.request_cancel(job)


def test_delete_removes_case_and_uploaded_copy_only(tmp_path, monkeypatch, run_job):
    base = tmp_path / "base"
    (base / "uploads" / "x.bat").mkdir(parents=True)
    monkeypatch.setattr(pipeline, "BASE_DIR", base)
    up = base / "uploads" / "x.bat" / "x.bat"
    up.write_text("@echo uploaded")
    mine = tmp_path / "mine"
    mine.mkdir()
    (mine / "keep.bat").write_text("@echo mine")

    j1 = run_job(up)
    j2 = run_job(mine)
    pipeline.delete_job(j1.id)
    assert not j1.case_dir.exists()
    assert not up.parent.exists()                 # the copy dropped onto the panel goes too
    pipeline.delete_job(j2.id)
    assert (mine / "keep.bat").exists()           # the user's own folder is never touched


def test_delete_refuses_running_and_bad_ids(tmp_path):
    job = bare_job(tmp_path, "running-case")
    job.save()
    with pytest.raises(pipeline.PipelineError, match="Çalışan"):
        pipeline.delete_job("running-case")
    for bad in ("..", "../x", "nope"):
        with pytest.raises(pipeline.PipelineError):
            pipeline.delete_job(bad)


def test_cleanup_deletes_only_old_finished(tmp_path, run_job):
    s = tmp_path / "a.bat"
    s.write_text("@echo a")
    old, new = run_job(s), run_job(s)
    st = json.loads((old.case_dir / "state.json").read_text(encoding="utf-8"))
    st["created"] = "2020-01-01 00:00:00"
    (old.case_dir / "state.json").write_text(json.dumps(st), encoding="utf-8")
    pipeline.JOBS.pop(old.id, None)
    assert pipeline.cleanup_jobs(30) == [old.id]
    assert new.case_dir.exists()


def test_interrupted_jobs_are_marked(isolated, tmp_path):
    job = bare_job(tmp_path, "half")
    job.state["stages"]["vt"]["status"] = "running"
    job.save()
    pipeline.load_interrupted()
    st = json.loads((job.case_dir / "state.json").read_text(encoding="utf-8"))
    assert st["status"] == "interrupted"
    assert st["stages"]["vt"]["status"] == "error"


def test_is_sample_file(tmp_path, run_job):
    mine = tmp_path / "mine"
    mine.mkdir()
    (mine / "a.bat").write_text("@echo a")
    run_job(mine)
    assert pipeline.is_sample_file(mine / "a.bat")
    other = tmp_path / "secret.txt"
    other.write_text("x")
    assert not pipeline.is_sample_file(other)


# ---------------------------------------------------------------- output quarantine
def test_unexpected_output_files_are_quarantined(tmp_path):
    out = tmp_path / "output"
    (out / "sub").mkdir(parents=True)
    (out / "behavior.json").write_text("{}")
    (out / "evil.exe").write_bytes(b"MZ")
    (out / "sub" / "x.dll").write_bytes(b"MZ")
    moved = pipeline.quarantine_output(out)
    assert sorted(moved) == sorted(["evil.exe", str(Path("sub") / "x.dll")])
    assert (out / "evil.exe.quarantine").exists() and not (out / "evil.exe").exists()
    assert (out / "behavior.json").exists()
    if os.name == "nt":
        assert "ZoneId=3" in Path(f"{out / 'evil.exe.quarantine'}:Zone.Identifier").read_text()


# ---------------------------------------------------------------- A4 watcher
@pytest.fixture
def watcher(tmp_path, monkeypatch):
    folder = tmp_path / "Downloads"
    folder.mkdir()
    monkeypatch.setattr(pipeline, "_file_in_use", lambda p: False)
    w = pipeline.DownloadWatcher.__new__(pipeline.DownloadWatcher)
    w.folder, w.enabled, w.auto_start, w.found, w._seen, w._baseline = str(folder), True, False, [], {}, {}
    w._lock = threading.Lock()
    return w, folder


def _poll(w, n=4):
    for _ in range(n):
        w.poll_once()
    return sorted(x["name"] for x in w.found)


def test_watcher_ignores_files_present_at_start(watcher):
    w, folder = watcher
    (folder / "old.exe").write_bytes(b"old")
    w._take_baseline()
    assert _poll(w) == []


def test_watcher_sees_moved_in_file_with_old_date(watcher, tmp_path):
    w, folder = watcher
    w._take_baseline()
    src = tmp_path / "moved.exe"
    src.write_bytes(b"moved")
    os.utime(src, (946684800, 946684800))                  # year 2000
    src.replace(folder / "moved.exe")
    assert _poll(w) == ["moved.exe"]


def test_watcher_sees_overwritten_baseline_file(watcher):
    w, folder = watcher
    (folder / "a.exe").write_bytes(b"old")
    w._take_baseline()
    (folder / "a.exe").write_bytes(b"new content")
    assert _poll(w) == ["a.exe"]


def test_watcher_waits_for_stable_size_and_skips_partials(watcher):
    w, folder = watcher
    w._take_baseline()
    (folder / "x.crdownload").write_bytes(b"partial")
    f = folder / "grow.exe"
    f.write_bytes(b"1")
    w.poll_once()
    f.write_bytes(b"12")
    w.poll_once()
    w.poll_once()
    assert w.found == []                                    # size changed: not stable yet
    assert _poll(w, 2) == ["grow.exe"]


def test_watcher_auto_start_skips_later_volumes_and_never_uploads(watcher, monkeypatch):
    w, folder = watcher
    w.auto_start = True
    calls = []
    monkeypatch.setattr(pipeline, "create_job", lambda path, opts: calls.append((Path(path).name, opts)) or
                        type("J", (), {"id": "job1"})())
    w._take_baseline()
    (folder / "a.part2.rar").write_bytes(b"Rar!")
    (folder / "a.part1.rar").write_bytes(b"Rar!")
    _poll(w)
    assert calls == [("a.part1.rar", {"run_sandbox": False, "vt_upload": False})]
    assert {x["name"]: x["later_part"] for x in w.found} == {"a.part1.rar": False, "a.part2.rar": True}


# ---------------------------------------------------------------- VirusTotal next to the sandbox
def _pkg(tmp_path, n=4):
    d = tmp_path / "pkg"
    d.mkdir()
    for i in range(n):
        (d / f"t{i}.bat").write_text(f"@echo {i}")
    return d


def test_sandbox_starts_without_waiting_for_virustotal(tmp_path, monkeypatch, fake_vt):
    fake_vt.lookup_delay = 0.5
    seen = {}

    def fake_sandbox(job):
        seen["vt_at_sandbox_start"] = job.state["stages"]["vt"]["status"]
        job.stage("sandbox", "running", "izleniyor")
        time.sleep(0.2)
        job.stage("sandbox", "done", "ok")
    monkeypatch.setattr(pipeline, "stage_sandbox", fake_sandbox)
    job = pipeline.create_job(str(_pkg(tmp_path)), {"run_sandbox": True, "vt_upload": False, "notify": False})
    wait_job(job, 60)
    assert seen["vt_at_sandbox_start"] in ("pending", "running")       # sandbox did not wait for VT
    assert job.state["status"] == "done"
    assert job.state["stages"]["vt"]["status"] == "done"                # report waited for VT
    assert job.state["stages"]["report"]["status"] == "done"
    assert len(fake_vt.lookups) == 4
    assert "VirusTotal" not in job.state["verdict"]["not_run"]


def test_cancel_during_sandbox_also_stops_virustotal(tmp_path, monkeypatch, fake_vt):
    fake_vt.lookup_delay = 1.0

    def fake_sandbox(job):
        job.stage("sandbox", "running", "izleniyor")
        while not job.state.get("cancel_requested"):
            time.sleep(0.05)
        job.state.pop("cancel_requested", None)                       # like the real stage: finish early
        job.stage("sandbox", "done", "erken bitti")
    monkeypatch.setattr(pipeline, "stage_sandbox", fake_sandbox)
    job = pipeline.create_job(str(_pkg(tmp_path, 8)), {"run_sandbox": True, "vt_upload": False, "notify": False})
    t0 = time.time()
    while job.state["stages"]["sandbox"]["status"] != "running":
        assert time.time() - t0 < 30
        time.sleep(0.05)
    pipeline.request_cancel(job)
    t1 = time.time()
    wait_job(job, 30)
    assert time.time() - t1 < 5
    assert job.state["stages"]["vt"]["status"] == "skipped"
    assert len(fake_vt.lookups) < 8


def test_sandbox_error_keeps_virustotal_results(tmp_path, monkeypatch, fake_vt):
    fake_vt.lookup_delay = 0.3

    def broken_sandbox(job):
        raise pipeline.PipelineError("sandbox açılamadı")
    monkeypatch.setattr(pipeline, "stage_sandbox", broken_sandbox)
    job = pipeline.create_job(str(_pkg(tmp_path)), {"run_sandbox": True, "vt_upload": False, "notify": False})
    wait_job(job, 60)
    assert job.state["status"] == "error"
    assert job.state["stages"]["sandbox"]["status"] == "error"
    assert job.state["stages"]["vt"]["status"] == "done"
    assert job.state["stages"]["report"]["status"] == "pending"


def test_show_window_waits_for_desktop_and_reopens_lost_viewer(tmp_path, monkeypatch):
    job = bare_job(tmp_path)
    job.state["status"] = "running"
    job.state["stages"]["sandbox"]["status"] = "running"
    monkeypatch.setattr(pipeline, "_WINDOW_SETTLE_SEC", 0.0)
    monkeypatch.setattr(pipeline, "_WINDOW_WATCH_SEC", 0.1)
    arranged = []
    monkeypatch.setattr(pipeline.sbm, "arrange_sandbox_window",
                        lambda front=True, reconnect=True: arranged.append((front, reconnect)) or {"message": "ok"})
    monkeypatch.setattr(pipeline.sbm, "find_windows_of", lambda names: [])        # viewer gone
    monkeypatch.setattr(pipeline.sbm, "sandbox_state", lambda: True)               # sandbox still running
    pipeline._arrange_sandbox_window_when_ready(job, True)
    time.sleep(0.5)
    assert arranged == []                                   # desktop not up yet: the connecting window is left alone
    (job.output_dir / "status.txt").write_text("Izleniyor", encoding="utf-8")
    t0 = time.time()
    while len(arranged) < 4 and time.time() - t0 < 10:
        time.sleep(0.05)
    job.state["status"] = "done"
    assert arranged[0] == (True, True)
    assert len(arranged) == 4                               # first arrange + at most 3 reconnects
