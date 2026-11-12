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
    js = (pipeline.BASE_DIR / "static" / "app.js").read_text(encoding="utf-8")
    assert "<script>" not in html and "<style>" not in html
    assert "asNum" in js and "asArr" in js


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


def test_in_place_run_mode_note_and_non_string_safety(tmp_path):
    job = bare_job(tmp_path)
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"RunMode": "in-place (read-only share)"})
    pipeline.compute_verdict(job)
    assert any("salt okunur" in n for n in job.state["verdict"]["notes"])

    # Hostile non-string RunMode in behavior JSON must never raise TypeError
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"RunMode": 12345})
    assert job.state["behavior"]["RunMode"] == "12345"
    pipeline.compute_verdict(job)


def test_write_html_report_escapes_xss_and_renders_markdown(tmp_path):
    job = bare_job(tmp_path)
    md = [
        "# Başlık <script>alert(1)</script>",
        "- plain <img src=x onerror=alert(1)> bullet",
        "- **`<code>`** ve `a*b<x>` ve **kalın <svg onload=1>**",
        "- **KIRMIZI:** saldırı <b>raw</b>",
        "| Ad | Link |",
        "|---|---|",
        "| bad | [x](javascript:alert(1)) |",
        "| ok | [VT](https://www.virustotal.com/gui/file/abc) |",
    ]
    pipeline.write_html_report(job, md)
    html_out = (job.case_dir / "report.html").read_text(encoding="utf-8")
    assert "<script>" not in html_out
    assert "<img " not in html_out
    assert "<svg " not in html_out
    assert "<b " not in html_out and "<b>raw</b>" not in html_out
    assert 'href="javascript:' not in html_out
    assert "<ul>" in html_out and "</ul>" in html_out
    assert "<code>&lt;code&gt;</code>" in html_out
    assert "<strong>kalın &lt;svg onload=1&gt;</strong>" in html_out
    assert 'href="https://www.virustotal.com/gui/file/abc"' in html_out


def test_ioc_export_csv_and_stix_dedup_noise_and_safety(tmp_path):
    job = bare_job(tmp_path)
    sha_sample = "a" * 64
    sha_drop = "b" * 64
    job.state["inventory"] = {"original_sha256": sha_sample}
    job.state["static"] = [{
        "rel": "=CMD|' /C calc'!A0",
        "sha256": sha_sample,
        "risk_score": 70,
        "yara_matches": [{"rule": "TestYara"}],
        "interesting_urls": ["https://evil.example/drop.exe", "https://settings.data.microsoft.com/ok"],
    }]
    job.state["vt"] = [{"rel": "sample.exe", "sha256": sha_sample.upper(), "status": "ok",
                        "result": {"stats": {"malicious": 15, "total": 70}, "suggested_threat_label": "stealer"}}]
    job.state["behavior"] = {
        "Files": {"DroppedHashes": [{"Path": "C:\\drop.exe", "SHA256": sha_drop.upper()}]},
        "Network": {
            "Connections": [
                {"Remote": "198.51.100.22", "Port": 443, "Process": "drop.exe", "FromSample": True},
                {"Remote": "192.168.1.10", "Port": 445, "Process": "drop.exe", "FromSample": True},
                {"Remote": "10.0.0.5", "Port": 80, "Process": "svchost.exe", "FromSample": False},
                {"Remote": "127.0.0.1", "Port": 8080, "Process": "drop.exe", "FromSample": True},
            ],
            "DnsCache": [{"Name": "settings-win.data.microsoft.com", "Data": "1.2.3.4"}],
        },
    }
    job.state["network"] = {
        "dns": [{"name": "api.telegram.org", "count": 2, "class": pipeline.CLASS_ABUSED}],
        "sni": [],
        "http": [{"host": "c2.example", "method": "POST", "uri": "/gate'x", "class": pipeline.CLASS_UNKNOWN}],
        "tcp_targets": [{"target": "198.51.100.22:443", "count": 3}],
    }

    iocs = pipeline.collect_iocs(job)
    vals = {(x["type"], x["value"]) for x in iocs}
    assert ("sha256", sha_sample) in vals
    assert ("sha256", sha_drop) in vals
    assert ("domain", "api.telegram.org") in vals
    assert ("domain", "evil.example") in vals
    assert ("ipv4", "198.51.100.22") in vals
    assert ("ipv4", "192.168.1.10") in vals
    assert ("url", "http://c2.example/gate'x") in vals
    # Pure Microsoft noise, non-sample LAN IP, and loopback excluded by default
    assert ("domain", "settings-win.data.microsoft.com") not in vals
    assert ("ipv4", "10.0.0.5") not in vals
    assert ("ipv4", "127.0.0.1") not in vals
    # No duplicate sha_sample from uppercase VT vs lowercase static
    assert sum(1 for x in iocs if x["type"] == "sha256" and x["value"] == sha_sample) == 1

    # With include_noise=True Microsoft noise and non-sample LAN IP appear
    noisy_vals = {(x["type"], x["value"]) for x in pipeline.collect_iocs(job, include_noise=True)}
    assert ("domain", "settings-win.data.microsoft.com") in noisy_vals
    assert ("ipv4", "10.0.0.5") in noisy_vals

    # CSV formula injection neutralized while raw hash remains intact
    csv_txt = pipeline.export_iocs_csv(job)
    assert f"sha256,{sha_sample},true," in csv_txt
    assert "'=CMD|" in csv_txt

    # STIX 2.1 bundle validation
    stix = pipeline.export_iocs_stix(job)
    assert stix["type"] == "bundle"
    inds = [o for o in stix["objects"] if o["type"] == "indicator"]
    assert len(inds) == len(iocs)
    patterns = {o["pattern"] for o in inds}
    assert f"[file:hashes.'SHA-256' = '{sha_sample}']" in patterns
    assert "[domain-name:value = 'api.telegram.org']" in patterns
    assert "[ipv4-addr:value = '198.51.100.22']" in patterns
    assert r"[url:value = 'http://c2.example/gate\'x']" in patterns
