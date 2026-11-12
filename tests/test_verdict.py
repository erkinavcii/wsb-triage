"""Verdict logic: sandbox JSON is untrusted (A2), domain classes (A6), helper timeouts (A7), coverage notes (A12)."""
import json
import subprocess
from pathlib import Path

import pytest

import pipeline
import sandbox_manager as sbm
from conftest import bare_job, windows_only

EVIL = {
    "Files": {"NewCount": "<img src=x onerror=alert(1)>", "NewExecutables": "C:\\x.exe", "ModifiedCount": None},
    "Persistence": {"Services": "not-a-list", "Tasks": [{"x": 1}, "real task"], "RunKeys": [1, 2]},
    "Defender": {"ThreatsDetected": [{"Name": "<script>"}], "Added": None},
    "Processes": "oops", "Network": {"Connections": [1, {"Remote": "1.2.3.4"}]},
    "LanBlock": {"Tampered": "yes", "Details": "string", "Applied": 1},
    "Hosts": "bad",
}


def test_sanitize_coerces_types():
    clean = pipeline.sanitize_sandbox_json(json.loads(json.dumps(EVIL)))
    assert clean["Files"]["NewCount"] == 0
    assert clean["Files"]["ModifiedCount"] == 0
    assert clean["Files"]["NewExecutables"] == []
    assert clean["Persistence"]["Services"] == []
    assert clean["Persistence"]["Tasks"] == ["real task"]
    assert clean["Persistence"]["RunKeys"] == ["1", "2"]
    assert clean["Defender"]["ThreatsDetected"] == []
    assert clean["Processes"] == []
    assert clean["Network"]["Connections"] == [{"Remote": "1.2.3.4"}]
    assert clean["LanBlock"]["Tampered"] is False                 # only a real JSON true counts
    assert clean["LanBlock"]["Applied"] is False
    assert clean["Hosts"] == {}


@pytest.mark.parametrize("bad", [None, [], "x", 5])
def test_sanitize_rejects_non_objects(bad):
    assert pipeline.sanitize_sandbox_json(bad) is None


def test_verdict_survives_hostile_behavior(tmp_path):
    job = bare_job(tmp_path)
    job.state["behavior"] = pipeline.sanitize_sandbox_json(json.loads(json.dumps(EVIL)))
    pipeline.compute_verdict(job)
    assert job.state["verdict"]["level"] in ("yellow", "pending", "red")


def test_panel_escapes_box_titles():
    html = (pipeline.BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")
    assert "asNum" in html and "asArr" in html


# ---------------------------------------------------------------- A6
@pytest.mark.parametrize("domain,cls", [
    ("foo.blob.core.windows.net", pipeline.CLASS_CLOUD),
    ("login.windows.net", "Windows/Microsoft (gürültü)"),
    ("settings-win.data.microsoft.com", "Windows/Microsoft (gürültü)"),
    ("api.telegram.org", pipeline.CLASS_ABUSED),
    ("api.ipify.org", pipeline.CLASS_ABUSED),
    ("abc.trycloudflare.com", pipeline.CLASS_ABUSED),
    ("x.cloudfront.net", pipeline.CLASS_CLOUD),
    ("ims-na1.adobelogin.com", "Adobe"),
    ("evil-c2.xyz", pipeline.CLASS_UNKNOWN),
    ("notmicrosoft.com", pipeline.CLASS_UNKNOWN),              # suffix match must respect label boundaries
    ("1.168.192.in-addr.arpa", "Yerel (gürültü)"),
])
def test_domain_class(domain, cls):
    assert pipeline.domain_class(domain) == cls


def test_network_verdict(tmp_path):
    job = bare_job(tmp_path)
    job.state["network"] = {"dns": pipeline._count(["api.ipify.org", "x.blob.core.windows.net", "evil-c2.xyz"]),
                            "sni": [], "http": [], "tcp_targets": [], "partial": ["HTTP"]}
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert v["level"] == "red"
    assert any("api.ipify.org" in r for r in v["red"])
    assert any("evil-c2.xyz" in n for n in v["notes"])
    assert any("blob.core.windows.net" in n for n in v["notes"])
    assert any("kısmi" in n for n in v["notes"])


def test_sandbox_red_flags(tmp_path):
    job = bare_job(tmp_path)
    job.state["behavior"] = pipeline.sanitize_sandbox_json({
        "Persistence": {"Services": ["EvilSvc"], "Startup": ["x.lnk"]},
        "Defender": {"Added": ["ExclusionPath C:\\"]},
        "LanBlock": {"Tampered": True, "Details": ["rule deleted"]},
        "Processes": [{"Name": "powershell.exe", "Suspicious": True}],
    })
    pipeline.compute_verdict(job)
    red = " | ".join(job.state["verdict"]["red"])
    for needle in ("servis", "Başlangıç", "Defender", "Yerel ağ engeli", "şüpheli komut"):
        assert needle in red


def test_monitor_lost_is_red(tmp_path):
    job = bare_job(tmp_path)
    job.state["sandbox"]["monitor_lost"] = {"after_sec": 40, "silent_sec": 200}
    pipeline.compute_verdict(job)
    assert any("anti-analiz" in r for r in job.state["verdict"]["red"])


# ---------------------------------------------------------------- A12 coverage
def test_green_needs_every_check(tmp_path):
    job = bare_job(tmp_path)
    job.state["status"] = "done"
    job.state["stages"]["vt"]["status"] = "skipped"
    job.state["stages"]["sandbox"]["status"] = "waiting"
    pipeline.compute_verdict(job)
    assert job.state["verdict"]["level"] == "yellow"
    assert set(job.state["verdict"]["not_run"]) == {"VirusTotal", "Sandbox"}
    job.state["stages"]["vt"]["status"] = "done"
    job.state["stages"]["sandbox"]["status"] = "done"
    pipeline.compute_verdict(job)
    assert job.state["verdict"]["level"] == "green"


# ---------------------------------------------------------------- A7
@windows_only
def test_signature_timeout_does_not_fail(tmp_path, monkeypatch):
    def slow(args, **kw):
        raise subprocess.TimeoutExpired(args, kw.get("timeout", 1))
    monkeypatch.setattr(pipeline.subprocess, "run", slow)
    res, timed_out = pipeline.check_signatures(tmp_path, [str(Path(sbm.WSB_EXE).parent / "notepad.exe")])
    assert timed_out == 1
    assert list(res.values())[0]["status"] == "Unknown"


def test_tshark_timeout_gives_partial_summary(tmp_path, monkeypatch):
    pcap = tmp_path / "c.pcapng"
    pcap.write_bytes(b"x")
    monkeypatch.setattr(sbm, "tshark_path", lambda: "tshark.exe")

    def run(args, **kw):
        if "http.request" in args:
            raise subprocess.TimeoutExpired(args, 1)

        class P:
            stdout = "evil-c2.xyz\n" if "dns.flags.response == 0" in args else ""
        return P()
    monkeypatch.setattr(pipeline.subprocess, "run", run)
    ns = pipeline.network_summary(pcap)
    assert ns["partial"] == ["HTTP"]
    assert ns["dns"][0]["name"] == "evil-c2.xyz"


@windows_only
def test_signatures_are_read(tmp_path, unsigned_exe):
    good = str(Path(sbm.WSB_EXE).parent / "whoami.exe")
    bad = str(unsigned_exe(tmp_path / "w.exe"))
    res, timed_out = pipeline.check_signatures(tmp_path, [good, bad])
    assert timed_out == 0
    assert res[good]["status"] == "Valid"
    assert res[bad]["status"] != "Valid"
