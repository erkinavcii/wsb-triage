"""VirusTotal: what may leave the machine (A1), quota handling (A10), streamed uploads (A11)."""
import email.parser
import io
import shutil
import zipfile

import pytest

import pipeline
import vt_client
from conftest import bare_job, windows_only


def _statuses(job):
    return {e["rel"]: e["status"] for e in job.state["vt"]}


@windows_only
def test_only_programs_are_uploaded_from_a_folder(tmp_path, fake_vt, run_job, unsigned_exe):
    d = tmp_path / "pkg"
    d.mkdir()
    unsigned_exe(d / "setup.exe")
    (d / "license.pdf").write_bytes(b"%PDF-1.7 personal contract")   # suspicious name, but a document
    (d / "foto.jpg").write_bytes(b"\xff\xd8\xff personal photo")
    job = run_job(d, vt_upload=True)
    assert fake_vt.uploads == ["setup.exe"]
    assert "gizlilik" in _statuses(job)["license.pdf"]


def test_archive_of_documents_is_not_uploaded(tmp_path, fake_vt, run_job):
    z = tmp_path / "kisisel.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("banka_dokumu.pdf", "%PDF private")
        zf.writestr("license_key.txt", "ABCD-1234")
    job = run_job(z, vt_upload=True)
    assert fake_vt.uploads == []
    assert "gizlilik" in _statuses(job)["[orijinal] kisisel.zip"]


@windows_only
def test_archive_with_a_program_may_be_uploaded(tmp_path, fake_vt, run_job, unsigned_exe):
    exe = unsigned_exe(tmp_path / "setup.exe")
    z = tmp_path / "program.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.write(exe, "setup.exe")
    run_job(z, vt_upload=True)
    assert "program.zip" in fake_vt.uploads


@windows_only
def test_automatic_runs_upload_nothing(tmp_path, fake_vt, run_job, unsigned_exe):
    d = tmp_path / "pkg"
    d.mkdir()
    unsigned_exe(d / "setup.exe")
    job = run_job(d, vt_upload=False)
    assert fake_vt.uploads == []
    assert fake_vt.lookups, "hash lookups still happen"
    assert "yükleme kapalı" in _statuses(job)["setup.exe"]


def test_watcher_starts_jobs_without_upload():
    src = (pipeline.BASE_DIR / "pipeline.py").read_text(encoding="utf-8")
    assert '"vt_upload": False' in src.split("def poll_once", 1)[1]


def test_known_malware_turns_verdict_red(tmp_path, fake_vt, run_job):
    s = tmp_path / "loader.bat"
    s.write_text("@echo off")
    sha = pipeline._sha256(s)
    fake_vt.known[sha] = {"stats": {"malicious": 12, "suspicious": 0, "undetected": 50, "harmless": 0, "total": 62},
                          "suggested_threat_label": "trojan.lumma/stealer", "flagged_engines": []}
    job = run_job(s)
    assert job.state["verdict"]["level"] == "red"
    assert any("zararlı yazılım ailesi" in r for r in job.state["verdict"]["red"])


def test_dropped_files_queried_on_vt(tmp_path, fake_vt):
    job = bare_job(tmp_path)
    dropped_sha = "c" * 64
    fake_vt.known[dropped_sha] = {
        "stats": {"malicious": 8, "suspicious": 0, "undetected": 50, "harmless": 0, "total": 58},
        "suggested_threat_label": "trojan.stealer", "flagged_engines": []
    }
    beh = {
        "Files": {
            "DroppedHashes": [
                {"Path": "C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\payload.exe", "SHA256": dropped_sha, "Size": 12345}
            ]
        }
    }
    pipeline._check_dropped_files_vt(job, beh)
    assert len(job.state["vt"]) == 1
    e = job.state["vt"][0]
    assert e["dropped"] is True
    assert e["sha256"] == dropped_sha
    assert "payload.exe" in e["rel"]
    assert e["result"]["stats"]["malicious"] == 8
    pipeline.compute_verdict(job)
    assert any("payload.exe" in r for r in job.state["verdict"]["red"])


# ---------------------------------------------------------------- A10
class _Resp:
    def __init__(self, code, body=None):
        self.status_code, self._body, self.text = code, body or {}, ""

    def json(self):
        return self._body


def test_second_429_means_quota_and_stops(monkeypatch):
    calls = []
    monkeypatch.setattr(vt_client.requests, "get", lambda *a, **k: (calls.append(1), _Resp(429))[1])
    monkeypatch.setattr(vt_client.time, "sleep", lambda s: None)
    monkeypatch.setattr(vt_client, "MIN_INTERVAL_SEC", 0)
    with pytest.raises(vt_client.VtQuotaError):
        vt_client.lookup("0" * 64, "k")
    assert len(calls) == 2


def test_quota_stops_the_whole_vt_stage(tmp_path, monkeypatch, run_job):
    calls = []
    monkeypatch.setattr(vt_client, "get_api_key", lambda: "k")
    monkeypatch.setattr(vt_client.requests, "get", lambda *a, **k: (calls.append(1), _Resp(429))[1])
    monkeypatch.setattr(vt_client.time, "sleep", lambda s: None)
    monkeypatch.setattr(vt_client, "MIN_INTERVAL_SEC", 0)
    d = tmp_path / "pkg"
    d.mkdir()
    for n in range(4):
        (d / f"tool{n}.bat").write_text(f"@echo {n}")
    job = run_job(d)
    assert len(calls) == 2                        # not 2 per file
    assert "Kota doldu" in job.state["stages"]["vt"]["msg"]
    assert all("kota" in e["status"].lower() for e in job.state["vt"])


def test_404_is_not_found_and_401_is_bad_key(monkeypatch):
    monkeypatch.setattr(vt_client, "MIN_INTERVAL_SEC", 0)
    monkeypatch.setattr(vt_client.requests, "get", lambda *a, **k: _Resp(404))
    assert vt_client.lookup("0" * 64, "k") is None
    monkeypatch.setattr(vt_client.requests, "get", lambda *a, **k: _Resp(401))
    with pytest.raises(vt_client.VtError, match="401"):
        vt_client.lookup("0" * 64, "k")


def test_summarize_flags_families_and_crack_tools():
    data = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 5, "suspicious": 1, "undetected": 60, "harmless": 0},
        "last_analysis_results": {"E1": {"category": "malicious", "result": "HackTool.Crack"},
                                  "E2": {"category": "undetected", "result": None}},
        "popular_threat_classification": {"suggested_threat_label": "hacktool.keygen"}}}}
    s = vt_client.summarize(data, "a" * 64)
    assert s["stats"]["total"] == 66
    assert s["looks_like_crack_tool"] and not s["has_dangerous_malware_family"]
    assert [e["engine"] for e in s["flagged_engines"]] == ["E1"]


# ---------------------------------------------------------------- A11
def test_streaming_multipart_is_valid_and_lazy(tmp_path):
    f = tmp_path / "sample file.exe"
    payload = bytes(range(256)) * 4000
    f.write_bytes(payload)
    body = vt_client.StreamingMultipart(str(f))
    try:
        assert len(body) == body.len
        chunks = []
        while True:
            c = body.read(7777)                      # odd chunk size crosses the part boundaries
            if not c:
                break
            assert len(c) <= 7777
            chunks.append(c)
        raw = b"".join(chunks)
    finally:
        body.close()
    assert len(raw) == body.len
    msg = email.parser.BytesParser().parsebytes(b"Content-Type: " + body.content_type.encode() + b"\r\n\r\n" + raw)
    parts = msg.get_payload()
    assert len(parts) == 1
    assert parts[0].get_param("name", header="content-disposition") == "file"
    assert parts[0].get_filename() == "sample_file.exe"          # sanitized
    assert parts[0].get_payload(decode=True) == payload


def test_upload_refuses_files_over_the_limit(tmp_path, monkeypatch):
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 100)
    monkeypatch.setattr(vt_client, "MAX_UPLOAD", 50)
    with pytest.raises(vt_client.VtError, match="650"):
        vt_client.upload(str(f), "k")


def test_upload_sends_the_stream(tmp_path, monkeypatch):
    f = tmp_path / "s.exe"
    f.write_bytes(b"MZ" + b"\0" * 1000)
    seen = {}

    def fake_post(url, headers=None, data=None, timeout=None):
        seen["ctype"] = headers["Content-Type"]
        seen["body"] = data.read(10 ** 6)
        return _Resp(200, {"data": {"id": "aid-1"}})
    monkeypatch.setattr(vt_client.requests, "post", fake_post)
    monkeypatch.setattr(vt_client, "_throttle", lambda: None)
    assert vt_client.upload(str(f), "k") == "aid-1"
    assert seen["ctype"].startswith("multipart/form-data; boundary=")
    assert b"MZ" in seen["body"]


def test_dropped_files_vt_rejects_hostile_and_deduplicates_case(tmp_path, fake_vt):
    job = bare_job(tmp_path)
    existing = "a" * 64
    dup_hash = "b" * 64
    job.state["vt"] = [{"rel": "orig.exe", "sha256": existing, "status": "ok", "result": None, "gui_url": ""}]
    beh = {
        "Files": {
            "DroppedHashes": [
                "not-a-dict",
                {"Path": "C:\\bad1.exe", "SHA256": "../../uploads/secret", "Size": 10},
                {"Path": "C:\\bad2.exe", "SHA256": None, "Size": 10},
                {"Path": "C:\\same_as_orig.exe", "SHA256": existing.upper(), "Size": 10},
                {"Path": None, "SHA256": dup_hash.upper(), "Size": "not-an-int"},
                {"Path": "C:\\Temp\\copy2.exe", "SHA256": dup_hash.lower(), "Size": 50},
            ]
        }
    }
    pipeline._check_dropped_files_vt(job, beh)
    assert fake_vt.lookups == [dup_hash]
    assert len(job.state["vt"]) == 2
    assert job.state["vt"][1]["rel"] == "[bırakılan] unknown.exe"
    assert job.state["vt"][1]["size"] == 0


def test_intel_client_malwarebazaar_and_hybrid_analysis_fallback(tmp_path, monkeypatch, run_job):
    import intel_client
    cfg_file = tmp_path / "config.json"
    monkeypatch.setattr(vt_client, "CONFIG_PATH", cfg_file)
    monkeypatch.setattr(vt_client, "get_api_key", lambda: "")
    intel_client.set_intel_config(mb_api_key="mb-k", ha_api_key="ha-k", mb_enabled=True)

    s = tmp_path / "dropper.bat"
    s.write_text("@echo evil")
    sha = pipeline._sha256(s)

    def fake_post(url, data=None, headers=None, timeout=None):
        assert url == intel_client.MB_API_URL
        assert headers.get("Auth-Key") == "mb-k"
        return _Resp(200, {"query_status": "ok", "data": [{"signature": "LummaStealer", "tags": ["stealer"]}]})

    def fake_get(url, headers=None, timeout=None):
        assert sha in url and headers.get("api-key") == "ha-k"
        return _Resp(200, {"verdict": "malicious", "threat_score": 95, "vx_family": "Lumma", "av_detect": 40})

    monkeypatch.setattr(intel_client.requests, "post", fake_post)
    monkeypatch.setattr(intel_client.requests, "get", fake_get)

    job = run_job(s)
    assert job.state["stages"]["vt"]["status"] == "done"
    assert job.state["vt"][0]["intel"]["malicious"] is True
    assert job.state["verdict"]["level"] == "red"
    assert any("MalwareBazaar" in r for r in job.state["verdict"]["red"])
    assert any("Hybrid Analysis" in r for r in job.state["verdict"]["red"])
