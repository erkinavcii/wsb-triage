"""Link analysis: a URL is opened in Edge inside the sandbox; downloads are analyzed statically, never run."""
import pytest

import pipeline
from conftest import bare_job, wait_job


@pytest.mark.parametrize("text,ok", [
    ("https://example.com/a?b=1", True), ("HTTP://Example.com", True), (r"C:\x\y.exe", None),
    ("ftp://x.com", False), ("javascript://x.com", False), ("https://user:pw@x.com/", False),
    ('https://x.com/"a', False), ("https://x.com/a b", False), ("https://x.com/a\b", False), ("https://", False),
])
def test_parse_url_sample(text, ok):
    if ok is False:
        with pytest.raises(pipeline.PipelineError):
            pipeline.parse_url_sample(text)
    elif ok is None:
        assert pipeline.parse_url_sample(text) is None
    else:
        assert pipeline.parse_url_sample(text) == text


def test_vt_url_id_matches_virustotal_docs():
    import vt_client
    assert vt_client.url_id("http://example.com/") == "aHR0cDovL2V4YW1wbGUuY29tLw"


def test_url_job_skips_file_stages_and_forces_safe_options(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(pipeline, "stage_sandbox", lambda j: seen.setdefault("opts", dict(j.state["options"])) and j.stage("sandbox", "done", "ok"))
    job = pipeline.create_job("https://example.com/landing", {"network": False, "simulate_user": True, "notify": False})
    wait_job(job, 30)
    st = job.state
    assert st["mode"] == "url" and st["sample"] == "https://example.com/landing" and st["status"] == "done"
    assert all(st["stages"][k]["status"] == "skipped" for k in ("extract", "inventory", "static"))
    o = seen["opts"]
    assert o["url"] == "https://example.com/landing" and o["network"] is True and o["decrypt_https"] is True
    assert o["simulate_user"] is False
    assert job.id.split("_", 1)[1] == "example.com"


def test_downloads_are_decoded_analyzed_and_not_left_in_output(tmp_path, monkeypatch):
    job = bare_job(tmp_path)
    out = job.output_dir
    d = out / pipeline.DOWNLOADS_DIR
    d.mkdir(parents=True)
    key = pipeline.MEMDUMP_KEY
    data = b"@echo off\r\npowershell -w hidden -enc SQBFAFgA\r\n"
    (d / "00_invoice.bat.xdl").write_bytes(bytes(b ^ key[i % len(key)] for i, b in enumerate(data)))
    (d / "..bad.xdl").write_bytes(b"x")
    monkeypatch.setattr(pipeline, "check_signatures", lambda case_dir, paths: ({}, 0))
    got = pipeline._collect_downloads(job, out)
    assert [p.name for p in got] == ["00_invoice.bat"] and got[0].read_bytes() == data
    assert not d.exists()
    pipeline._analyze_downloads(job, got)
    assert job.state["downloads"][0]["name"] == "invoice.bat" and len(job.state["downloads"][0]["sha256"]) == 64
    assert any(s["rel"] == "[indirilen] invoice.bat" for s in job.state["static"])


def _url_job(tmp_path, beh, **state):
    job = bare_job(tmp_path)
    job.state["mode"] = "url"
    job.state["sample"] = "https://start.example/x"
    job.state.update(state)
    job.state["behavior"] = pipeline.sanitize_sandbox_json(beh)
    return job


def test_url_verdict_ignores_edge_footprint_and_flags_what_edge_should_not_do(tmp_path):
    edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    beh = {"Target": "https://start.example/x", "Url": "https://start.example/x",
           "Processes": [{"Name": "msedge.exe", "Pid": 1, "InTree": True, "Path": edge},
                         {"Name": "identity_helper.exe", "Pid": 2, "InTree": True, "Path": ""},
                         {"Name": "powershell.exe", "Pid": 3, "InTree": True, "Path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                          "CommandLine": "powershell -enc AAAA"}],
           "Persistence": {"RunKeys": [r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run :: MicrosoftEdgeAutoLaunch_1 = msedge.exe"],
                           "Tasks": [r"\MicrosoftEdgeUpdateTaskMachineCore | C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"]},
           "Files": {"NewExecutables": [r"C:\SandboxWork\edge-profile\Default\Extensions\x.js",
                                        r"C:\Users\WDAGUtilityAccount\AppData\Local\Temp\dropper.exe"]}}
    job = _url_job(tmp_path, beh, url_vt={"malicious": 7, "suspicious": 1, "flagged": [{"engine": "E", "result": "phishing"}]},
                   downloads=[{"name": "invoice.zip", "size": 10, "sha256": "a" * 64}, {"name": "x.exe", "size": 5, "missing": True}])
    job.state["behavior"]["Https"] = {"Requested": True, "Status": "done", "flows": [
        {"host": "start.example", "status": 302}, {"host": "hop.example", "status": 301}, {"host": "final.example", "status": 200}],
        "tls_failed": []}
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    red, notes = " ".join(v["red"]), " ".join(v["notes"])
    assert "7 motor tarafından zararlı/oltalama" in red and "phishing" in red
    assert "beklenmeyen bir program başlattı" in red and "powershell.exe" in red and "identity_helper" not in red
    assert "kayboldu" in red and "x.exe" in red
    assert "start.example → hop.example" in notes and "invoice.zip" in notes
    assert "otomatik başlatma" not in notes and "zamanlanmış görev" not in notes
    assert "1 yeni çalıştırılabilir dosya" in notes                   # dropper.exe yes, Edge profile file no
    assert "çalıştırılacak dosya bulunamadı" not in notes and "Kurulum başlamamış" not in notes


def test_monitor_opens_links_in_edge_and_saves_downloads():
    from pathlib import Path
    ps = (Path(pipeline.__file__).parent / "sandbox" / "Inside-Sandbox.ps1").read_text(encoding="utf-8")
    assert "function Save-Downloads" in ps and "--user-data-dir=" in ps and "HideFirstRunExperience" in ps
    assert "Downloads       = @($downloads)" in ps and "Url             = [string]$cfg.Url" in ps


def test_link_run_false_positives_seen_live_are_notes_or_gone(tmp_path):
    """Official 7-Zip installer opened as a link: was red/10 before these fixes."""
    beh = {"Target": "https://www.7-zip.org/a/7z2409-x64.exe", "Url": "https://www.7-zip.org/a/7z2409-x64.exe",
           "Processes": [{"Name": "msedge.exe", "Pid": 1, "InTree": True}],
           "HoneyfileAlerts": [r"ACCESSED (infostealer read by msedge.exe pid=8368): C:\Users\x\AppData\Local\Google\Chrome\User Data\Local State"],
           "MemoryFindings": ["[msedge.exe:8536] NtUnmapViewOfSection", "[msedge.exe:8536] https://perfetto.dev/docs/x"]}
    job = _url_job(tmp_path, beh, url_vt={"malicious": 1, "suspicious": 0}, status="done")
    job.state["vt"] = [{"rel": "[indirilen] 7z.exe", "sha256": "a" * 64, "status": "VT'de kayıtlı",
                        "result": {"stats": {"malicious": 1}, "suggested_threat_label": "trojan", "flagged_engines": []}}]
    job.state["behavior"]["MemoryYara"] = [
        {"proc": "msedge.exe", "pid": i, "rule": "SafeBox_Office_Macro_Dropper", "severity": "high", "description": "x"} for i in (1, 2, 3)]
    job.state["behavior"]["Https"] = {"Requested": True, "Status": "done", "tls_failed": ["www.7-zip.org", "arc.msn.com"], "flows": [
        {"host": "www.7-zip.org", "status": 302, "method": "GET"},
        {"host": "www.googleapis.com", "status": 200, "method": "POST", "req_bytes": 119, "url": "https://www.googleapis.com/chromewebstore/v1.1/items/verify"}]}
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    notes = " ".join(v["notes"])
    assert v["red"] == [] and v["level"] == "yellow" and v["score"] <= 4
    assert "1 motor tarafından işaretlendi (düşük" in notes and "Tarayıcının kendisi yem dosya okudu" in notes
    assert "Office_Macro" not in notes and "perfetto" not in notes and "chromewebstore" not in notes
    assert "arc.msn.com" in notes and "www.7-zip.org" not in notes.split("çözülemedi")[1].split(".")[0]
