"""The in-sandbox monitor runs under Windows PowerShell 5.1, which reads BOM-less files as the ANSI code page:
any non-ASCII byte can silently corrupt a string or break parsing. Keep it pure ASCII and syntactically valid."""
import json
import subprocess
from pathlib import Path

import pytest

from conftest import ROOT, windows_only

SCRIPTS = [ROOT / "sandbox" / "Inside-Sandbox.ps1"]


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_is_ascii(script):
    data = script.read_bytes()
    bad = [i for i, b in enumerate(data) if b > 127]
    assert not bad, f"non-ASCII bytes at offsets {bad[:10]}"


@windows_only
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_parses(script):
    ps = ("$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
          f"'{script}', [ref]$null, [ref]$e); "
          "ConvertTo-Json -Compress @($e | ForEach-Object { \"$($_.Extent.StartLineNumber): $($_.Message)\" })")
    p = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    errors = json.loads(p.stdout or "[]") or []
    assert errors == [], errors


def test_wsb_config_is_hardened(tmp_path):
    import sandbox_manager as sbm
    xml = sbm.build_wsb(tmp_path / "case & <x>", network=True, memory_mb=8192, input_dir=tmp_path / "in")
    assert "<MemoryInMB>8192</MemoryInMB>" in xml
    assert "case &amp; &lt;x&gt;" in xml                     # paths are XML-escaped
    for off in ("VGpu", "ClipboardRedirection", "PrinterRedirection", "AudioInput", "VideoInput"):
        assert f"<{off}>Disable</{off}>" in xml
    # sample + tools read-only, only output writable
    assert xml.count("<ReadOnly>true</ReadOnly>") == 2 and xml.count("<ReadOnly>false</ReadOnly>") == 1
    assert "<Networking>Disable</Networking>" in sbm.build_wsb(tmp_path, network=False)
    assert "<MemoryInMB>1024</MemoryInMB>" in sbm.build_wsb(tmp_path, network=True, memory_mb=256)
    assert "<MemoryInMB>65536</MemoryInMB>" in sbm.build_wsb(tmp_path, network=True, memory_mb=999999)


def test_script_has_pkt_size_and_dropped_hashes():
    ps = (ROOT / "sandbox" / "Inside-Sandbox.ps1").read_text(encoding="utf-8")
    assert "--pkt-size 4096" in ps   # must keep full TLS ClientHello (SNI)
    assert "DroppedHashes" in ps
    assert "Capture-Screen" in ps
    assert "Invoke-FakeUser" in ps


def test_script_hardening_honeyfiles_audit_and_extended_types():
    ps = (ROOT / "sandbox" / "Inside-Sandbox.ps1").read_text(encoding="utf-8")
    # E10: extended file types & Standard User & DLL exports & CLI args
    for ext in (".dll", ".reg", ".jar", ".vbe", ".jse", ".wsf", ".pif"):
        assert ext in ps
    assert "rundll32.exe" in ps
    assert "RunAsStandardUser" in ps and "0x20000" in ps
    assert "TargetArgs" in ps and "DllExport" in ps

    # E11: gateway is NOT exempted on all ports; DNS restricted to port 53; IPv6 link-local blocked
    assert "SafeBox-BlockDNS-TCP" in ps
    assert "SafeBox-BlockDNS-UDP" in ps
    assert "'1-52'" in ps and "'54-65535'" in ps
    assert "fe80::/10" in ps
    assert "$exempt += $gw" not in ps

    # E12: honeyfiles, 4688 audit, disguised title, WMI/COM/BITS/PSProfile persistence
    assert "Windows Update Service" in ps
    assert "Initialize-Honeyfiles" in ps and "Check-Honeyfiles" in ps
    assert "Import-AuditProcesses" in ps and "4688" in ps
    assert "WmiSubscriptions" in ps and "BitsJobs" in ps and "PsProfiles" in ps
    assert "procmon_summary.json" in ps


def test_e7_wsb_cli_mock(tmp_path, monkeypatch):
    import time
    import sandbox_manager as sbm
    calls = []
    wsb_file = tmp_path / "run.wsb"
    wsb_file.write_text("<Configuration/>", encoding="utf-8")
    gid_1 = "11111111-2222-3333-4444-555555555555"
    gid_2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def fake_run(args, timeout=30):
        calls.append(args)
        if args[1:3] == ["list", "--raw"]:
            return subprocess.CompletedProcess(
                args, 0, stdout=json.dumps({"WindowsSandboxEnvironments": [{"Id": gid_1}]}), stderr=""
            )
        if args[1:3] == ["start", "--config"]:
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps({"Id": gid_2}), stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    started_wsb = []
    monkeypatch.setattr(sbm, "wsb_cli_path", lambda: "wsb.exe")
    monkeypatch.setattr(sbm, "_run", fake_run)
    monkeypatch.setattr(sbm.os, "startfile", lambda p: started_wsb.append(str(p)))
    monkeypatch.setattr(time, "sleep", lambda _s: None)

    assert sbm.wsb_list_ids() == [gid_1]
    assert sbm.launch_sandbox(wsb_file) is None
    assert started_wsb == [str(wsb_file)]

    # Fallback to wsb start --config if os.startfile fails
    monkeypatch.setattr(sbm.os, "startfile", lambda _p: (_ for _ in ()).throw(OSError("no assoc")))
    monkeypatch.setattr(sbm.subprocess, "Popen", lambda *a, **kw: None)
    assert sbm.launch_sandbox(wsb_file) == gid_2
    assert any(c[1:3] == ["start", "--config"] for c in calls)
    sbm.stop_sandbox(gid_2)
    assert any(c == ["wsb.exe", "stop", "--id", gid_2] for c in calls)


def test_f5_sandbox_features_present():
    ps = (ROOT / "sandbox" / "Inside-Sandbox.ps1").read_text(encoding="utf-8")
    # F5: Smarter UIA clicker, Live Process Memory Scan, FakeNet Sinkhole
    for token in (
        "SafeBoxMem",
        "Scan-ProcessMemory",
        "MemoryFindings",
        "Start-FakeNet",
        "Stop-FakeNet",
        "FakeNetRequests",
        "AutoClicks",
        "RadioButton",
        "TogglePattern",
        "LegacyIAccessiblePattern",
        "mouse_event",
    ):
        assert token in ps, f"Missing F5 token in Inside-Sandbox.ps1: {token}"


def test_e8_virtualbox_backend_mock_and_password_never_persisted(tmp_path, monkeypatch):
    import time
    import sandbox_manager as sbm
    import pipeline

    calls = []

    def fake_run(args, timeout=30):
        calls.append(args)
        sub = args[1] if len(args) > 1 else ""
        if sub == "snapshot" and len(args) > 3 and args[3] == "list":
            return subprocess.CompletedProcess(args, 0, stdout='SnapshotName="SafeBox_Temiz_2026"\n', stderr="")
        if sub == "showvminfo":
            return subprocess.CompletedProcess(args, 0, stdout='VMState="poweroff"\n', stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(sbm, "vbox_manage_path", lambda: r"C:\VirtualBox\VBoxManage.exe")
    monkeypatch.setattr(sbm, "_run", fake_run)
    monkeypatch.setattr(time, "sleep", lambda _s: None)

    in_d, tools_d, out_d = tmp_path / "in", tmp_path / "tools", tmp_path / "out"
    for d in (in_d, tools_d, out_d):
        d.mkdir()

    snap = sbm.vbox_start_analysis(
        vm_name="Win10Test", snapshot_name="", input_dir=in_d, tools_dir=tools_d, output_dir=out_d,
        network=False, guest_user="analyst", guest_pass="super-secret-vm-pw",
    )
    assert snap == "SafeBox_Temiz_2026"
    assert any(c[1:4] == ["snapshot", "Win10Test", "restore"] for c in calls)
    assert any(c[1:3] == ["startvm", "Win10Test"] for c in calls)
    assert any("sb_input" in c and "--readonly" in c for c in calls)
    assert any("sb_output" in c and "--readonly" not in c for c in calls)
    assert any("guestcontrol" in c and "Inside-Sandbox.ps1" in " ".join(c) for c in calls)

    calls.clear()
    sbm.vbox_stop_and_restore("Win10Test", snap)
    assert any(c[1:4] == ["controlvm", "Win10Test", "poweroff"] for c in calls)
    assert any(c[1:4] == ["snapshot", "Win10Test", "restore"] for c in calls)

    # Snapshot missing must raise
    monkeypatch.setattr(sbm, "list_vbox_snapshots", lambda _vm: [])
    with pytest.raises(RuntimeError, match="temiz snapshot"):
        sbm.vbox_start_analysis("Win10Test", "", in_d, tools_d, out_d, False, "analyst", "pw")

    # VBox password is kept only in Job memory, NEVER persisted in state.json or snapshot()
    sample = tmp_path / "sample.bat"
    sample.write_text("echo ok\n", encoding="utf-8")
    monkeypatch.setattr(pipeline.threading, "Thread", lambda *a, **kw: type("T", (), {"start": lambda self: None})())
    job = pipeline.create_job(str(sample), {"vbox_user": "analyst", "vbox_password": "secret-vbox-pw-999", "run_sandbox": False})
    assert job.vbox_password == "secret-vbox-pw-999"
    state_disk = (job.case_dir / "state.json").read_text(encoding="utf-8")
    assert "secret-vbox-pw-999" not in state_disk
    assert "vbox_password" not in job.snapshot().get("options", {})


def test_f8_honeyfile_uses_4663_sacl_without_lastaccess_false_positives():
    ps = (ROOT / "sandbox" / "Inside-Sandbox.ps1").read_text(encoding="utf-8")
    assert "disablelastaccess" not in ps
    assert "LastAccessTimeUtc" not in ps
    assert "Set-Acl" not in ps
    assert "SafeBoxPriv" in ps
    assert "SeSecurityPrivilege" in ps
    assert "SetAccessControl" in ps
    assert "0CCE921D-69AE-11D9-BED3-505054503030" in ps
    assert "S-1-1-0" in ps
    assert "FileSystemAuditRule" in ps
    assert "4663" in ps
    assert "Update-HoneyReads" in ps
    assert "ReadFile|CreateFileMapping" in ps
    assert "HoneyBenignReaders" in ps
    assert "HoneyShellDocReaders" in ps

    # Verify Vault vs Desktop/Documents read/copy attribution logic in real Windows PowerShell 5.1
    start = ps.index("$script:Honeyfiles = @()")
    end = ps.index("function Initialize-Honeyfiles")
    snippet = ps[start:end]
    ps_test = (
        "$TreePids = @{ 4242 = 1 }; function Log($m) {}\n"
        + snippet
        + "\n"
        + "$vaultPath = 'C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data'\n"
        + "$docPath = 'C:\\Users\\WDAGUtilityAccount\\Desktop\\wallet_keys.txt'\n"
        + "$script:HoneyMap[$vaultPath.ToLower()] = [pscustomobject]@{ Path = $vaultPath; Vault = $true }\n"
        + "$script:HoneyMap[$docPath.ToLower()] = [pscustomobject]@{ Path = $docPath; Vault = $false }\n"
        + "# 1. Defender scanning vault & explorer thumbnailing Desktop doc -> ignored\n"
        + "Record-HoneyRead $vaultPath 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe' 1100\n"
        + "Record-HoneyRead $docPath 'C:\\Windows\\explorer.exe' 2200\n"
        + "if ($script:HoneyReadAlerts.Count -ne 0) { throw ('unexpected alert: ' + ($script:HoneyReadAlerts -join ';')) }\n"
        + "# 2. Hollowed explorer.exe reading Chrome Login Data (read-only copy, 0 modification) -> CAUGHT!\n"
        + "Record-HoneyRead $vaultPath 'C:\\Windows\\explorer.exe' 2200\n"
        + "# 3. Sample child process copying Desktop wallet_keys.txt (read-only copy, 0 modification) -> CAUGHT!\n"
        + "Record-HoneyRead $docPath 'C:\\Windows\\System32\\xcopy.exe' 4242\n"
        + "Write-Output ('COUNT=' + $script:HoneyReadAlerts.Count)\n"
        + "$script:HoneyReadAlerts | ForEach-Object { Write-Output $_ }\n"
    )
    powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    cp = subprocess.run([powershell, "-NoProfile", "-Command", ps_test], capture_output=True, text=True, timeout=20)
    assert cp.returncode == 0, cp.stderr
    assert "COUNT=2" in cp.stdout
    assert "ACCESSED (infostealer read by explorer.exe pid=2200):" in cp.stdout
    assert "ACCESSED (infostealer read by xcopy.exe pid=4242):" in cp.stdout


def test_win11_idle_sandbox_server_daemon_does_not_block_new_sandbox(monkeypatch):
    import sandbox_manager as sbm

    monkeypatch.setattr(
        sbm,
        "_run",
        lambda args, timeout=30: subprocess.CompletedProcess(
            args,
            0,
            stdout='"WindowsSandboxServer.exe","18712","Console","1","12,000 K"\n"explorer.exe","1234","Console","1","50,000 K"\n',
            stderr="",
        ),
    )
    monkeypatch.setattr(sbm, "wsb_list_ids", lambda: [])
    assert sbm._sandbox_processes() == []
    assert sbm.sandbox_state() is False
    assert sbm.sandbox_running() is False

    # Active client session must still be detected as running
    monkeypatch.setattr(
        sbm,
        "_run",
        lambda args, timeout=30: subprocess.CompletedProcess(
            args,
            0,
            stdout='"WindowsSandboxServer.exe","18712","Console","1","12,000 K"\n"WindowsSandboxClient.exe","9999","Console","1","80,000 K"\n',
            stderr="",
        ),
    )
    assert sbm._sandbox_processes() == ["WindowsSandboxClient.exe"]
    assert sbm.sandbox_running() is True




