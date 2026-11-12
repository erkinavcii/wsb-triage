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
    assert "--pkt-size 512" in ps
    assert "DroppedHashes" in ps
    assert "Capture-Screen" in ps
    assert "Invoke-FakeUser" in ps
