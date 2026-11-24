import base64
import hashlib
import io
import ipaddress
import math
import os
import re
import struct
import subprocess
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

import pefile

import yara_scanner

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".msi", ".scr", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta"
}

SUSPICIOUS_FILENAMES = {
    "amtlib.dll", "patch.exe", "keygen.exe", "crack.exe", "loader.exe",
    "activator.exe", "inject.exe", "hook.dll", "winhttp.dll", "version.dll",
    "uxtheme.dll", "dwmapi.dll", "cryptbase.dll", "profapi.dll", "nsudo.exe"
}

# Imported APIs worth showing, grouped by what they can be used for. Shown for information only: almost every one of
# these also appears in ordinary programs, so the score comes from COMBINATIONS (API_COMBOS below), not single imports.
SUSPICIOUS_APIS = {
    "Process Injection / Bellek Müdahalesi": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "QueueUserAPC", "RtlCreateUserThread", "NtWriteVirtualMemory", "SetThreadContext", "NtCreateThreadEx"
    ],
    "Anti-Debug": ["CheckRemoteDebuggerPresent", "NtSetInformationThread"],
    "Kimlik Bilgisi Erişimi": ["CryptUnprotectData", "CredEnumerate", "VaultEnumerateItems", "LsaRetrievePrivateData"],
    "İndirme & Çalıştırma": ["URLDownloadToFile", "WinExec", "InternetOpenUrl"],
    "Klavye / Ekran İzleme": ["SetWindowsHookEx", "GetAsyncKeyState", "BitBlt"],
    "Servis Kurma": ["CreateService", "ChangeServiceConfig"],
}

# (points, title, required groups): every group must have at least one import present (name prefix match, so
# CreateRemoteThread also matches CreateRemoteThreadEx, WinExec matches WinExec, URLDownloadToFile matches ...A/W).
API_COMBOS = [
    (30, "Süreç enjeksiyonu birleşimi (başka işlemde bellek ayırma + yazma + çalıştırma)",
     [("VirtualAllocEx", "NtAllocateVirtualMemory"), ("WriteProcessMemory", "NtWriteVirtualMemory"),
      ("CreateRemoteThread", "QueueUserAPC", "RtlCreateUserThread", "SetThreadContext", "NtCreateThreadEx")]),
    (25, "Process hollowing birleşimi (işlem belleğini boşaltma + yazma + yeniden başlatma)",
     [("NtUnmapViewOfSection", "ZwUnmapViewOfSection"), ("WriteProcessMemory", "NtWriteVirtualMemory"),
      ("SetThreadContext", "Wow64SetThreadContext", "NtSetContextThread")]),
    (15, "İndir ve çalıştır birleşimi", [("URLDownloadToFile",), ("WinExec", "ShellExecute", "CreateProcess")]),
    (8, "Tuş kaydı birleşimi (klavye kancası + tuş durumu okuma)", [("SetWindowsHookEx",), ("GetAsyncKeyState", "GetKeyboardState")]),
    (10, "Kayıtlı parola kasası okuma", [("CredEnumerate", "VaultEnumerateItems", "LsaRetrievePrivateData")]),
    (8, "Hata ayıklayıcıdan gizlenme", [("NtSetInformationThread",), ("CheckRemoteDebuggerPresent", "NtQueryInformationProcess")]),
]

SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".reg"}
CONFIG_EXTENSIONS = {".pimx", ".iss", ".inf", ".ini"}

# String patterns. A single hit is weak evidence (installers, browser engines and system DLLs contain many of these
# strings legitimately); several DIFFERENT hits in the same category are what matters, so each rule escalates.
# severity: base level; escalate: (distinct matches needed, stronger level).
STRING_SIGNATURES = [
    {
        "category": "Infostealer (Tarayıcı/Cüzdan Hırsızı)",
        "severity": "medium", "escalate": (3, "critical"),
        "patterns": [
            r"Login Data", r"Local State", r"cookies\.sqlite", r"Web Data", r"key4\.db", r"logins\.json",
            r"\\Google\\Chrome\\User Data", r"\\Mozilla\\Firefox\\Profiles", r"\\BraveSoftware\\Brave-Browser",
            r"\\Microsoft\\Edge\\User Data", r"\\Discord\\Local Storage\\leveldb", r"\\Telegram Desktop\\tdata",
            r"MetaMask", r"nkbihfbeogaeaoehlefnkodbefgpgknn", r"Exodus\\exodus\.wallet", r"\\Electrum\\wallets", r"wallet\.dat",
            r"\\Steam\\config", r"FileZilla\\recentservers\.xml"
        ],
        "description": "Tarayıcı şifreleri, çerezler, Discord/Telegram oturumları veya kripto cüzdan dosyalarının yolları. "
                       "Tek bir iz gömülü tarayıcı motorlarında normaldir; birkaç farklı iz bir arada bilgi çalan yazılımlara özgüdür."
    },
    {
        "category": "Anti-VM / Analiz Aracı Tespiti",
        "severity": "medium", "escalate": (3, "high"),
        "patterns": [
            r"SbieDll\.dll", r"VBoxMouse\.sys", r"VBoxGuest\.sys", r"VBoxSF\.sys", r"VBoxService\.exe", r"vmmouse\.sys",
            r"vmhgfs\.sys", r"vmtoolsd\.exe", r"VIRTUALBOX", r"VMWARE", r"QEMU", r"wine_get_unix_file_name", r"cuckoomon",
            r"Wireshark", r"Fiddler", r"procmon64\.exe", r"procexp64\.exe", r"x64dbg", r"ollydbg", r"ProcessHacker"
        ],
        "description": "Sanal makinede ya da analiz araçları altında çalışıp çalışmadığını kontrol ediyor olabilir. "
                       "Sürücüler ve sanallaştırma yazılımları bu adları meşru olarak içerir."
    },
    {
        "category": "Gizli Komut Çalıştırma / Defender Atlatma",
        "severity": "high", "escalate": (2, "critical"),
        "patterns": [
            r"powershell[^\r\n]{0,80}\s-e(nc|ncodedcommand)?\s", r"-WindowStyle\s+Hidden", r"FromBase64String",
            r"DownloadString\(", r"Invoke-Expression|\bIEX\s*\(", r"Add-MpPreference\s+-Exclusion", r"Set-MpPreference\s+-Disable",
            r"certutil[^\r\n]{0,40}-urlcache", r"bitsadmin[^\r\n]{0,40}/transfer", r"mshta\s+https?:", r"regsvr32[^\r\n]{0,40}/i:https?:",
            r"vssadmin[^\r\n]{0,40}delete\s+shadows", r"wevtutil\s+cl\b"
        ],
        "description": "Gizli/şifreli PowerShell, internetten script çalıştırma, Defender istisnası ekleme veya iz silme komutları."
    },
    {
        "category": "Kalıcılık (Başlangıç / Zamanlanmış Görev)",
        "severity": "medium",
        "patterns": [r"schtasks[^\r\n]{0,20}/create", r"CurrentVersion\\Run\b", r"CurrentVersion\\RunOnce", r"\\Start Menu\\Programs\\Startup"],
        "description": "Bilgisayar açılınca otomatik çalışma kaydı veya zamanlanmış görev. Kurulum programlarında da sık görülür."
    },
    {
        "category": "Şüpheli Ağ / Komuta Kontrol (C2) İletişimi",
        "severity": "critical",
        "patterns": [
            r"api\.telegram\.org/bot", r"discord(app)?\.com/api/webhooks", r"pastebin\.com/raw", r"[a-z2-7]{16,56}\.onion\b",
            r"\.ngrok(-free)?\.(io|app)", r"\.trycloudflare\.com"
        ],
        "description": "Çalınan verileri göndermek için sık kullanılan Telegram bot API'si, Discord webhook'u, Pastebin, Tor veya tünel adresi."
    },
    {
        "category": "Şüpheli Dosya Barındırma",
        "severity": "medium",
        "patterns": [r"raw\.githubusercontent\.com", r"cdn\.discordapp\.com/attachments", r"transfer\.sh", r"gofile\.io", r"catbox\.moe"],
        "description": "Ek yük (payload) indirmek için sık kullanılan dosya barındırma adresleri. Güncelleyiciler de kullanabilir."
    }
]

SEVERITY_POINTS = {"critical": 35, "high": 18, "medium": 6}


def calculate_hashes(file_path: str) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    occurences = [0] * 256
    for byte in data:
        occurences[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in occurences:
        if count:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)


def check_authenticode_signatures(file_paths: List[str]) -> Dict[str, Dict[str, Any]]:
    """Checks Windows Authenticode digital signatures in batch using PowerShell."""
    if not file_paths:
        return {}
    results = {}
    try:
        # Use PowerShell to inspect signatures of all target files in one call
        ps_paths = ",".join([f"'{p.replace(chr(39), chr(39)*2)}'" for p in file_paths])
        ps_cmd = (
            f"@({ps_paths}) | ForEach-Object {{ "
            f"$sig = Get-AuthenticodeSignature -FilePath $_ -ErrorAction SilentlyContinue; "
            f"[PSCustomObject]@{{ "
            f"Path = $_; "
            f"Status = if ($sig) {{ $sig.Status.ToString() }} else {{ 'Unknown' }}; "
            f"StatusMessage = if ($sig) {{ $sig.StatusMessage }} else {{ '' }}; "
            f"Signer = if ($sig -and $sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ '' }}; "
            f"Issuer = if ($sig -and $sig.SignerCertificate) {{ $sig.SignerCertificate.Issuer }} else {{ '' }} "
            f"}} }} | ConvertTo-Json -Compress"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=20, encoding="utf-8", errors="replace"
        )
        if proc.returncode == 0 and proc.stdout.strip():
            parsed = json.loads(proc.stdout.strip())
            if isinstance(parsed, dict):
                parsed = [parsed]
            for item in parsed:
                results[item["Path"]] = {
                    "status": item.get("Status", "Unknown"),
                    "message": item.get("StatusMessage", ""),
                    "signer": item.get("Signer", ""),
                    "issuer": item.get("Issuer", "")
                }
    except Exception as e:
        for p in file_paths:
            results[p] = {"status": "Error", "message": str(e), "signer": "", "issuer": ""}
    return results


def extract_printable_strings(data: bytes, min_len: int = 5) -> str:
    # Extract ASCII and UTF-16LE strings
    ascii_strings = [m.group(0).decode("ascii", errors="ignore") for m in re.finditer(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)]
    utf16_strings = [m.group(0).decode("utf-16le", errors="ignore") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}", data)]
    return "\n".join(ascii_strings + utf16_strings)


_IP_PREFIX_SKIP_RX = re.compile(r"(?:version|fileversion|productversion|assemblyversion|assembly|oid|build|\bv)\s*[:=\"']?\s*$", re.I)
_IPV4_PORT_RX = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?![\d.])")


def extract_interesting_ips(extracted_text: str) -> List[str]:
    """Extracts likely C2 IPv4 addresses (optionally with :port), filtering version strings and loopback/bogons."""
    found: List[str] = []
    seen: set = set()
    for m in _IPV4_PORT_RX.finditer(extracted_text):
        ip_str, port_str = m.group(1), m.group(2)
        prefix = extracted_text[max(0, m.start() - 28):m.start()]
        if _IP_PREFIX_SKIP_RX.search(prefix):
            continue
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
        except ValueError:
            continue
        if ip_obj.is_unspecified or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local:
            continue
        if ip_str.startswith("255.") or ip_str.endswith(".0"):
            continue
        port_ok = False
        if port_str:
            try:
                pnum = int(port_str)
                port_ok = 1 <= pnum <= 65535
            except ValueError:
                port_ok = False
        if ip_obj.is_private and not port_ok:
            continue
        if not port_ok and ip_str.startswith(("1.0.", "2.0.", "3.0.", "4.0.", "5.0.", "6.0.")):
            continue
        val = f"{ip_str}:{port_str}" if port_ok else ip_str
        if val not in seen:
            seen.add(val)
            found.append(val)
            if len(found) >= 15:
                break
    return found


_PS_B64_RX = re.compile(
    r"(?i)(?:-e(?:nc(?:odedcommand)?)?\s+|FromBase64String\(\s*['\"])([A-Za-z0-9+/=]{20,})(?:['\"]\s*\))?"
)


def _looks_printable(s: str) -> bool:
    if len(s) < 8:
        return False
    printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\r\n\t")
    return (printable / len(s)) >= 0.75


_CARET_DEOBF_KEEP_RX = re.compile(
    r"(?i)(powershell|https?://|certutil|bitsadmin|mshta|invoke-webrequest|cmd\s*/c|sc\s+(?:stop|delete)|schtasks)"
)


def deobfuscate_script(text: str, allow_caret: bool = True) -> List[Dict[str, str]]:
    """Best-effort decoding of Base64 PowerShell payloads and caret-obfuscated batch lines."""
    snippets: List[Dict[str, str]] = []
    seen: set = set()
    for m in _PS_B64_RX.finditer(text):
        b64 = m.group(1)
        pad = (-len(b64)) % 4
        try:
            raw = base64.b64decode(b64 + ("=" * pad), validate=False)
        except Exception:
            continue
        if not raw:
            continue
        decoded = ""
        # PowerShell -EncodedCommand is UTF-16LE (alternating null bytes for ASCII)
        if len(raw) >= 4 and raw[1::2].count(0) >= max(2, len(raw) // 4):
            try:
                cand = raw.decode("utf-16le", errors="ignore").strip("\x00\r\n ")
                if _looks_printable(cand):
                    decoded = cand
            except Exception:
                pass
        if not decoded:
            try:
                cand = raw.decode("utf-8", errors="ignore").strip("\x00\r\n ")
                if _looks_printable(cand):
                    decoded = cand
            except Exception:
                pass
        if decoded and decoded not in seen:
            seen.add(decoded)
            snippets.append({"kind": "Base64 / PowerShell", "decoded": decoded[:4000]})
            if len(snippets) >= 10:
                break

    if allow_caret:
        for line in text.splitlines():
            if len(line) > 4096 or line.count("^") < 4:
                continue
            if len(re.findall(r"\^[A-Za-z0-9]", line)) < 3:
                continue
            norm = re.sub(r"\^([A-Za-z0-9_.:/\\-])", r"\1", line)
            if norm != line and _CARET_DEOBF_KEEP_RX.search(norm):
                key = norm[:1000]
                if key not in seen:
                    seen.add(key)
                    snippets.append({"kind": "Batch caret temizliği", "decoded": norm[:4000]})
                    if len(snippets) >= 15:
                        break
    return snippets


_DOUBLE_EXT_RX = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|jpg|jpeg|png|gif|mp3|mp4|zip|rar)\.(?:exe|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|com|pif|lnk)$",
    re.I,
)
_DOC_MEDIA_EXT = {
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".mp3", ".mp4", ".wav", ".avi",
}


def detect_spoofing(path_obj: Path, head: bytes) -> List[Dict[str, Any]]:
    flags: List[Dict[str, Any]] = []
    name = path_obj.name
    if any(0x202A <= ord(c) <= 0x202E or 0x2066 <= ord(c) <= 0x2069 for c in name):
        flags.append({
            "type": "rlo",
            "severity": "critical",
            "points": 45,
            "reason": f"KRİTİK: Dosya adında Unicode yön değiştirme karakteri (RLO/BiDi) tespit edildi — uzantı gizleme tekniği: {repr(name)}",
        })
    if _DOUBLE_EXT_RX.search(name):
        flags.append({
            "type": "double_ext",
            "severity": "high",
            "points": 35,
            "reason": f"Çift uzantı kandırmacası tespit edildi ('{name}'): belge/medya gibi görünüp çalıştırılabilir dosya.",
        })
    ext = path_obj.suffix.lower()
    if head[:2] == b"MZ" and ext in _DOC_MEDIA_EXT:
        flags.append({
            "type": "magic_mismatch",
            "severity": "critical",
            "points": 40,
            "reason": f"KRİTİK: Dosya '{ext}' uzantılı ama içeriği çalıştırılabilir Windows programı (MZ başlığı)!",
        })
    return flags


_LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
_LOLBIN_RX = re.compile(r"(?i)\b(powershell|pwsh|cmd(?:\.exe)?|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl|wget)\b")


def parse_lnk(data: bytes) -> Optional[Dict[str, Any]]:
    """Parses MS-SHLLINK (.lnk) header and StringData fields in pure Python."""
    if len(data) < 76:
        return None
    hdr_size = struct.unpack_from("<I", data, 0)[0]
    if hdr_size != 0x4C or data[4:20] != _LNK_CLSID:
        return None
    flags = struct.unpack_from("<I", data, 0x14)[0]
    is_unicode = bool(flags & 0x80)
    pos = 76
    if flags & 0x01:  # HasLinkTargetIDList
        if pos + 2 > len(data):
            return None
        id_sz = struct.unpack_from("<H", data, pos)[0]
        pos += 2 + id_sz
    local_base_path = ""
    if flags & 0x02 and pos + 4 <= len(data):  # HasLinkInfo
        li_sz = struct.unpack_from("<I", data, pos)[0]
        if li_sz >= 28 and pos + li_sz <= len(data):
            li_flags = struct.unpack_from("<I", data, pos + 8)[0]
            if li_flags & 0x01:  # VolumeIDAndLocalBasePath
                lbp_off = struct.unpack_from("<I", data, pos + 16)[0]
                if lbp_off and pos + lbp_off < pos + li_sz:
                    end_nul = data.find(b"\x00", pos + lbp_off, pos + li_sz)
                    if end_nul != -1:
                        local_base_path = data[pos + lbp_off:end_nul].decode("cp1252", errors="ignore")
        pos += li_sz

    out: Dict[str, Any] = {"local_base_path": local_base_path}
    for bit, key in ((0x04, "description"), (0x08, "relative_path"), (0x10, "working_dir"), (0x20, "arguments"), (0x40, "icon_location")):
        if flags & bit and pos + 2 <= len(data):
            cnt = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            byte_len = cnt * 2 if is_unicode else cnt
            if pos + byte_len <= len(data):
                raw_s = data[pos:pos + byte_len]
                out[key] = raw_s.decode("utf-16le" if is_unicode else "cp1252", errors="ignore").strip("\x00")
            pos += byte_len
    return out


def inspect_office_file(file_path: str, ext: str, data: bytes) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if data[:4] == b"PK\x03\x04" and ext in {".docm", ".docx", ".xlsm", ".xlsx", ".pptm", ".pptx"}:
        try:
            with zipfile.ZipFile(io.BytesIO(data) if len(data) < 25 * 1024 * 1024 else file_path, "r") as zf:
                names = zf.namelist()
                vba_files = [n for n in names if n.lower().endswith("vbaproject.bin")]
                if vba_files:
                    vba_raw = zf.read(vba_files[0])[:2 * 1024 * 1024]
                    vba_txt = extract_printable_strings(vba_raw, min_len=4)
                    kw = sorted(set(re.findall(r"(?i)\b(AutoOpen|Auto_Open|Document_Open|Workbook_Open|WScript\.Shell|PowerShell|ShellExecute|URLDownloadToFile|CreateObject)\b", vba_txt)))
                    high_macro = any(k.lower() in {"autoopen", "auto_open", "document_open", "workbook_open"} for k in kw) and any(
                        k.lower() in {"wscript.shell", "powershell", "shellexecute", "urldownloadtofile", "createobject"} for k in kw
                    )
                    findings.append({
                        "category": "Office Makro (VBA)",
                        "severity": "high" if high_macro else "medium",
                        "points": 30 if high_macro else 15,
                        "description": f"Office belgesinde makro projesi (vbaProject.bin) bulundu" + (f": {', '.join(kw[:6])}" if kw else "."),
                    })
                found_external_rel = False
                for n in names:
                    low_n = n.lower()
                    if not found_external_rel and low_n.endswith(".rels"):
                        rel_txt = zf.read(n)[:256 * 1024].decode("utf-8", errors="ignore")
                        if 'TargetMode="External"' in rel_txt and re.search(r'Target="https?://', rel_txt, re.I):
                            findings.append({
                                "category": "Office Harici Şablon / Bağlantı",
                                "severity": "high",
                                "points": 25,
                                "description": f"Office ilişkisinde ({n}) dış HTTP bağlantısı (uzaktan şablon enjeksiyonu riski) var.",
                            })
                            found_external_rel = True
                    if "embeddings/" in low_n and Path(low_n).suffix in {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr"}:
                        findings.append({
                            "category": "Office Gömülü Çalıştırılabilir",
                            "severity": "critical",
                            "points": 35,
                            "description": f"Office paketi içinde çalıştırılabilir gömülü dosya var: {n}",
                        })
        except Exception:
            pass
    elif data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and ext in {".doc", ".xls", ".ppt"}:
        txt = extract_printable_strings(data[:5 * 1024 * 1024], min_len=4)
        has_vba = bool(re.search(r"_VBA_PROJECT_CUR|\bVBA\b", txt))
        kw = sorted(set(re.findall(r"(?i)\b(AutoOpen|Auto_Open|Document_Open|Workbook_Open|WScript\.Shell|PowerShell|ShellExecute|URLDownloadToFile|CreateObject)\b", txt)))
        if has_vba and kw:
            findings.append({
                "category": "Eski Office Makro (OLE2/VBA)",
                "severity": "high",
                "points": 25,
                "description": f"OLE2 Office belgesinde VBA makro izleri: {', '.join(kw[:6])}",
            })
    return findings


def inspect_pdf_file(data: bytes) -> List[Dict[str, Any]]:
    if not data.lstrip().startswith(b"%PDF-"):
        return []
    head = data[:5 * 1024 * 1024]
    tags = sorted(set(m.decode("ascii", errors="ignore") for m in re.findall(rb"/(?:JavaScript|JS|OpenAction|AA|Launch|EmbeddedFile|RichMedia)\b", head)))
    if not tags:
        return []
    tag_set = set(tags)
    has_js = bool(tag_set & {"/JavaScript", "/JS"})
    has_auto = bool(tag_set & {"/OpenAction", "/AA"})
    findings: List[Dict[str, Any]] = []
    if "/Launch" in tag_set or (has_auto and has_js):
        findings.append({
            "category": "Şüpheli PDF Eylemi",
            "severity": "high",
            "points": 25,
            "description": f"PDF belgesinde otomatik tetiklenen komut/JavaScript/Launch eylemi var: {', '.join(tags)}",
        })
    elif has_js or "/EmbeddedFile" in tag_set:
        findings.append({
            "category": "PDF Gömülü Kod / Dosya",
            "severity": "medium",
            "points": 10,
            "description": f"PDF belgesinde gömülü betik veya ek dosya etiketleri: {', '.join(tags)}",
        })
    return findings


_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_MSI_EXEC_RX = re.compile(
    r"(?i)(?:\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|mshta|wscript|cscript|rundll32|regsvr32|Invoke-WebRequest|DownloadString|FromBase64String)\b|(?:^|\s)-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,})"
)
_INSTALLER_TAMPER_RX = re.compile(
    r"(?i)\b(sc(?:\.exe)?\s+(?:stop|delete)|schtasks(?:\.exe)?\s+/delete|AGMService|AGSService|AdobeGCClient|AdobeGCInvoker|SPPExtComObj|Smartversion|amtlib\.dll)\b"
)
_INSTALLER_HIGH_RX = re.compile(r"(?i)\b(sc(?:\.exe)?\s+(?:stop|delete)|schtasks(?:\.exe)?\s+/delete)\b")


def inspect_msi_file(ext: str, data: bytes) -> List[Dict[str, Any]]:
    is_msi = ext == ".msi" or (
        data[:8] == _OLE2_MAGIC
        and (
            b"CustomAction" in data
            or b"InstallExecuteSequence" in data
            or "CustomAction".encode("utf-16le") in data
        )
    )
    if not is_msi:
        return []
    txt = extract_printable_strings(data[:10 * 1024 * 1024], min_len=4)
    hits: List[str] = []
    for m in _MSI_EXEC_RX.finditer(txt):
        tok = m.group(0).strip()[:40]
        if tok and tok.lower() not in {h.lower() for h in hits}:
            hits.append(tok)
            if len(hits) >= 6:
                break
    if not hits:
        return []
    return [{
        "category": "MSI Özel Eylemi (CustomAction)",
        "severity": "high",
        "points": 30,
        "description": f"MSI kurulum paketi içinde şüpheli komut/betik çalıştırma izleri: {', '.join(hits)}",
    }]


def inspect_installer_config(path_obj: Path, ext: str, text: str) -> List[Dict[str, Any]]:
    if ext not in (CONFIG_EXTENSIONS | SCRIPT_EXTENSIONS) and not re.search(r"(?i)(patch.*\.log|runonce.*)", path_obj.name):
        return []
    hits: List[str] = []
    for m in _INSTALLER_TAMPER_RX.finditer(text):
        tok = m.group(0).strip()[:48]
        if tok and tok.lower() not in {h.lower() for h in hits}:
            hits.append(tok)
            if len(hits) >= 6:
                break
    if not hits:
        return []
    is_high = bool(_INSTALLER_HIGH_RX.search(text))
    return [{
        "category": "Kurulum / Lisans Müdahale Betiği",
        "severity": "high" if is_high else "medium",
        "points": 25 if is_high else 15,
        "description": f"Kurulum/yapılandırma dosyasında servis, görev veya lisans bileşeni müdahalesi: {', '.join(hits)}",
    }]


def _analyze_dotnet_strings(extracted_text: str) -> List[Dict[str, Any]]:
    rules = [
        (25, "high", ".NET bellek içi yükleme (Reflection + Base64/İndirme)",
         re.search(r"System\.Reflection", extracted_text) and re.search(r"\bAssembly\b", extracted_text)
         and re.search(r"FromBase64String|DownloadData|DownloadString", extracted_text)),
        (25, "high", ".NET P/Invoke bellek/süreç müdahalesi",
         re.search(r"DllImport|Runtime\.InteropServices", extracted_text)
         and re.search(r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection", extracted_text)),
        (20, "high", ".NET DPAPI tarayıcı/cüzdan veri çözme",
         re.search(r"ProtectedData", extracted_text) and re.search(r"\bUnprotect\b", extracted_text)
         and re.search(r"Login Data|Local State|cookies\.sqlite|logins\.json|wallet\.dat", extracted_text, re.I)),
        (15, "medium", ".NET koruyucu / obfuscator izi",
         re.search(r"ConfuserEx|ConfusedByAttribute|SmartAssembly|Dotfuscator|\.NET Reactor|CryptoObfuscator", extracted_text, re.I)),
    ]
    out: List[Dict[str, Any]] = []
    for pts, sev, desc, cond in rules:
        if cond:
            out.append({"points": pts, "severity": sev, "description": desc})
    return out


def _collect_pe_imports(entries: Any, pe_info: Dict[str, Any]) -> None:
    for entry in entries:
        for imp in entry.imports:
            pe_info["total_imports"] += 1
            if imp.name:
                func_name = imp.name.decode("utf-8", errors="ignore")
                pe_info["_all_imports"].add(func_name)
                for category, api_list in SUSPICIOUS_APIS.items():
                    for target_api in api_list:
                        if func_name.startswith(target_api):
                            pe_info["suspicious_imports"].setdefault(category, [])
                            if func_name not in pe_info["suspicious_imports"][category]:
                                pe_info["suspicious_imports"][category].append(func_name)


_VERSION_FIELDS = {
    "CompanyName", "FileDescription", "OriginalFilename",
    "ProductName", "InternalName", "FileVersion", "LegalCopyright",
}


def analyze_pe_file(file_path: str, raw_data: bytes, file_size: Optional[int] = None) -> Dict[str, Any]:
    pe_info: Dict[str, Any] = {
        "is_pe": False,
        "architecture": "Bilinmiyor",
        "compile_time": None,
        "imphash": "",
        "is_dotnet": False,
        "has_tls_callbacks": False,
        "is_packed": False,
        "packing_reasons": [],
        "anomalies": [],
        "anomaly_points": 0,
        "overlay": None,
        "version_info": {},
        "dotnet_indicators": [],
        "sections": [],
        "suspicious_imports": {},
        "total_imports": 0,
        "_all_imports": set(),   # used for API_COMBOS scoring, removed before the result is returned
    }
    try:
        pe = pefile.PE(data=raw_data, fast_load=False)
        pe_info["is_pe"] = True
        machine = pe.FILE_HEADER.Machine
        pe_info["architecture"] = "64-bit (x64)" if machine == 0x8664 else ("32-bit (x86)" if machine == 0x14c else f"Other ({hex(machine)})")
        try:
            pe_info["imphash"] = pe.get_imphash() or ""
        except Exception:
            pe_info["imphash"] = ""

        for fi_entry in getattr(pe, "FileInfo", None) or []:
            items = fi_entry if isinstance(fi_entry, list) else [fi_entry]
            for fi in items:
                if getattr(fi, "Key", None) == b"StringFileInfo" or hasattr(fi, "StringTable"):
                    for st in getattr(fi, "StringTable", None) or []:
                        for k, v in (getattr(st, "entries", None) or {}).items():
                            k_str = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
                            k_str = k_str.replace("\x00", "").strip()
                            if k_str in _VERSION_FIELDS:
                                v_str = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
                                v_str = v_str.replace("\x00", "").strip()
                                if v_str and k_str not in pe_info["version_info"]:
                                    pe_info["version_info"][k_str] = v_str

        is_repro = False
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            is_repro = any(getattr(getattr(d, "struct", None), "Type", None) == 16 for d in pe.DIRECTORY_ENTRY_DEBUG)

        ts = pe.FILE_HEADER.TimeDateStamp
        if ts:
            try:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                pe_info["compile_time"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                if not is_repro and (dt.year < 1995 or dt.year > datetime.now(timezone.utc).year + 1):
                    pe_info["anomalies"].append(f"Olağandışı derleme zamanı: {pe_info['compile_time']}")
                    pe_info["anomaly_points"] += 6
            except (OverflowError, OSError, ValueError):
                pe_info["compile_time"] = f"Geçersiz ({hex(ts)})"
                pe_info["anomalies"].append("Bozuk PE derleme zaman damgası.")
                pe_info["anomaly_points"] += 6

        data_dirs = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", []) or []
        if len(data_dirs) > 14 and data_dirs[14].VirtualAddress != 0:
            pe_info["is_dotnet"] = True

        # Check actual non-zero TLS callback function pointers (avoid false positives from empty CRT TLS tables)
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and getattr(pe.DIRECTORY_ENTRY_TLS, "struct", None):
            cb_va = getattr(pe.DIRECTORY_ENTRY_TLS.struct, "AddressOfCallBacks", 0)
            if cb_va:
                try:
                    cb_rva = cb_va - pe.OPTIONAL_HEADER.ImageBase
                    ptr_fmt = "<Q" if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else "<I"
                    ptr_sz = 8 if ptr_fmt == "<Q" else 4
                    raw_ptr = pe.get_data(cb_rva, ptr_sz)
                    if len(raw_ptr) == ptr_sz and struct.unpack(ptr_fmt, raw_ptr)[0] != 0:
                        pe_info["has_tls_callbacks"] = True
                        pe_info["anomalies"].append("TLS callback fonksiyonu tanımlı (main öncesi gizli kod çalıştırabilir).")
                        pe_info["anomaly_points"] += 12
                except Exception:
                    pass

        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section = None
        last_sec_name = None
        rwx_hit = False
        vs_ratio_hit = False

        for idx, section in enumerate(pe.sections):
            sec_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            sec_data = section.get_data()
            sec_entropy = calculate_entropy(sec_data)
            raw_size = section.SizeOfRawData
            virtual_size = section.Misc_VirtualSize

            executable = bool(section.Characteristics & 0x20000000)   # IMAGE_SCN_MEM_EXECUTE
            writable = bool(section.Characteristics & 0x80000000)     # IMAGE_SCN_MEM_WRITE
            rwx = executable and writable
            if ep_rva and section.VirtualAddress <= ep_rva < section.VirtualAddress + max(virtual_size, raw_size):
                ep_section = sec_name or "(isimsiz)"
            if idx == len(pe.sections) - 1:
                last_sec_name = sec_name or "(isimsiz)"

            pe_info["sections"].append({
                "name": sec_name or "(isimsiz)",
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "entropy": sec_entropy,
                "executable": executable,
                "writable": writable,
                "rwx": rwx,
                "high_entropy": sec_entropy > 7.2
            })

            if rwx and not rwx_hit:
                rwx_hit = True
                pe_info["anomalies"].append(f"Hem yazılabilir hem çalıştırılabilir (RWX) bölüm tespit edildi: '{sec_name or '(isimsiz)'}'.")
                pe_info["anomaly_points"] += 15

            if executable and virtual_size > 4096 and (raw_size == 0 or virtual_size / max(1, raw_size) >= 5.0) and not vs_ratio_hit:
                vs_ratio_hit = True
                pe_info["anomalies"].append(f"'{sec_name or '(isimsiz)'}' bölümünde VirtualSize ({virtual_size}) >> RawSize ({raw_size}) anomalisi.")
                pe_info["anomaly_points"] += 10

            # Only CODE sections count: resources (.rsrc) and installer payloads are compressed by nature.
            if executable and sec_entropy > 7.2 and raw_size > 1024:
                pe_info["is_packed"] = True
                pe_info["packing_reasons"].append(
                    f"Çalıştırılabilir '{sec_name}' bölümü çok yüksek entropiye ({sec_entropy}/8.0) sahip (şifrelenmiş/paketlenmiş kod ihtimali)."
                )
            if sec_name.lower() in ["upx0", "upx1", ".vmp0", ".vmp1", ".themida", ".enigma1"]:
                pe_info["is_packed"] = True
                pe_info["packing_reasons"].append(
                    f"Bilinen paketleyici/koruyucu bölüm adı tespit edildi: '{sec_name}' (UPX / VMProtect / Themida)."
                )

        if ep_rva and ep_section and ep_section.lower() not in {".text", ".code", "code", "text", ".init", "init"}:
            if ep_section == last_sec_name or ep_section.lower() in {".data", ".rdata", ".rsrc"}:
                pe_info["anomalies"].append(f"Giriş noktası (EntryPoint) standart kod bölümü yerine '{ep_section}' bölümünde.")
                pe_info["anomaly_points"] += 8

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            _collect_pe_imports(pe.DIRECTORY_ENTRY_IMPORT, pe_info)
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            _collect_pe_imports(pe.DIRECTORY_ENTRY_DELAY_IMPORT, pe_info)

        if not pe_info["is_dotnet"] and 0 < pe_info["total_imports"] <= 5:
            imp_lower = {i.lower() for i in pe_info["_all_imports"]}
            if any(x.startswith(("loadlibrary", "getprocaddress")) for x in imp_lower):
                pe_info["anomalies"].append(f"Çok az statik import ({pe_info['total_imports']}) ve dinamik API çözümü (LoadLibrary/GetProcAddress).")
                pe_info["anomaly_points"] += 12

        # PE Overlay inspection (excluding Authenticode security certificate table)
        ov_off = pe.get_overlay_data_start_offset()
        actual_size = file_size if file_size is not None else len(raw_data)
        if ov_off is not None and 0 < ov_off < actual_size:
            ov_size = actual_size - ov_off
            if len(data_dirs) > 4:
                sec_dir = data_dirs[4]
                if sec_dir.VirtualAddress == ov_off and sec_dir.Size >= ov_size:
                    ov_size = 0
                elif sec_dir.VirtualAddress > ov_off and sec_dir.Size > 0:
                    ov_size = max(0, ov_size - sec_dir.Size)
            if ov_size > 0:
                ov_sample = raw_data[ov_off:ov_off + 2 * 1024 * 1024]
                if not ov_sample and file_path and Path(file_path).is_file():
                    try:
                        with open(file_path, "rb") as f:
                            f.seek(ov_off)
                            ov_sample = f.read(2 * 1024 * 1024)
                    except OSError:
                        ov_sample = b""
                ov_ent = calculate_entropy(ov_sample)
                packer_hint = ""
                if b"MEI\x0c\x0b\x0a\x0b\x0e" in ov_sample or b"PyInstaller" in ov_sample:
                    packer_hint = "PyInstaller"
                elif b"Inno Setup" in ov_sample:
                    packer_hint = "Inno Setup"
                pe_info["overlay"] = {
                    "offset": ov_off,
                    "size": ov_size,
                    "ratio": round(ov_size / max(1, actual_size), 3),
                    "entropy": ov_ent,
                    "packer_hint": packer_hint,
                }
                if ov_size > 20 * 1024 * 1024 and ov_ent < 1.5:
                    pe_info["anomalies"].append(f"Binary padding / file pumping şüphesi: {ov_size // (1024 * 1024)} MB düşük entropili ({ov_ent}/8) overlay.")
                    pe_info["anomaly_points"] += 15
                elif ov_size > 65536 and ov_ent > 7.4 and not packer_hint:
                    pe_info["anomalies"].append(f"Yüksek entropili ({ov_ent}/8) büyük PE overlay ({round(ov_size / 1048576, 2)} MB).")
                    pe_info["anomaly_points"] += 8

        pe.close()
    except Exception:
        pass
    return pe_info


_SPOOF_VENDORS_RX = re.compile(
    r"(?i)\b(microsoft\s+corporation|google\s+llc|apple\s+inc|adobe\s+(?:inc|systems)|nvidia\s+corporation|intel\s+corporation|mozilla\s+corporation)\b"
)
_SYSBIN_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
    "explorer.exe", "rundll32.exe", "conhost.exe", "taskhostw.exe",
    "smss.exe", "spoolsv.exe", "ntoskrnl.exe",
}


def analyze_single_file(file_path: str, sig_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    path_obj = Path(file_path)
    file_size = path_obj.stat().st_size
    hashes = calculate_hashes(file_path)

    # Read up to 25 MB from head, plus last 4 MB for oversized padded/pumped binaries
    max_read = 25 * 1024 * 1024
    tail_data = b""
    with open(file_path, "rb") as f:
        sample_data = f.read(max_read)
        if file_size > max_read:
            tail_len = min(4 * 1024 * 1024, file_size - len(sample_data))
            if tail_len > 0:
                f.seek(file_size - tail_len)
                tail_data = f.read(tail_len)

    overall_entropy = calculate_entropy(sample_data)
    if sig_info is None:
        sig_map = check_authenticode_signatures([str(path_obj)])
        sig_info = sig_map.get(str(path_obj), {"status": "Unknown", "message": "", "signer": "", "issuer": ""})

    pe_info = analyze_pe_file(file_path, sample_data, file_size=file_size)
    if pe_info.get("overlay") and not pe_info["overlay"].get("packer_hint") and tail_data:
        if b"MEI\x0c\x0b\x0a\x0b\x0e" in tail_data:
            pe_info["overlay"]["packer_hint"] = "PyInstaller"
        elif b"Inno Setup" in tail_data:
            pe_info["overlay"]["packer_hint"] = "Inno Setup"

    extracted_text = extract_printable_strings(sample_data)
    if tail_data:
        extracted_text += "\n" + extract_printable_strings(tail_data)

    ext = path_obj.suffix.lower()
    lnk_info = parse_lnk(sample_data) if (ext == ".lnk" or sample_data[:4] == b"\x4c\x00\x00\x00") else None
    if lnk_info:
        lnk_parts = [lnk_info.get(k, "") for k in ("local_base_path", "relative_path", "working_dir", "arguments", "description")]
        extracted_text += "\n" + " ".join(p for p in lnk_parts if p)

    deobfuscated_snippets = deobfuscate_script(extracted_text, allow_caret=(not pe_info["is_pe"]))
    if deobfuscated_snippets:
        extracted_text += "\n" + "\n".join(s["decoded"] for s in deobfuscated_snippets)

    if pe_info["is_pe"] and pe_info["is_dotnet"]:
        pe_info["dotnet_indicators"] = _analyze_dotnet_strings(extracted_text)

    sig_status = sig_info.get("status", "Unknown")
    spoof_flags = detect_spoofing(path_obj, sample_data[:64])
    ver_info = pe_info.get("version_info") or {}
    if ver_info:
        comp = (ver_info.get("CompanyName") or "").strip()
        if comp and _SPOOF_VENDORS_RX.search(comp) and sig_status not in ("Valid", "HashMismatch"):
            spoof_flags.append({
                "type": "vendor_impersonation",
                "severity": "high",
                "points": 30,
                "reason": f"Sahte üretici kimliği şüphesi: Dosya meta verisinde '{comp}' yazıyor ancak geçerli dijital imzası yok ({sig_status}).",
            })
        orig_fn = (ver_info.get("OriginalFilename") or "").strip().lower()
        if orig_fn in _SYSBIN_NAMES and path_obj.name.lower() != orig_fn and sig_status != "Valid":
            spoof_flags.append({
                "type": "sysbin_masquerade",
                "severity": "high",
                "points": 25,
                "reason": f"Sistem dosyası kılığına girme: Orijinal adı '{orig_fn}' olan imzasız dosya '{path_obj.name}' adıyla gizlenmiş.",
            })

    format_findings = (
        inspect_office_file(file_path, ext, sample_data)
        + inspect_pdf_file(sample_data)
        + inspect_msi_file(ext, sample_data)
        + inspect_installer_config(path_obj, ext, extracted_text)
    )
    if lnk_info:
        cmd_blob = " ".join(lnk_info.get(k, "") for k in ("local_base_path", "relative_path", "arguments"))
        if _LOLBIN_RX.search(cmd_blob):
            format_findings.append({
                "category": "LNK Kısayol Komutu",
                "severity": "high",
                "points": 30,
                "description": f"LNK kısayolu sistem aracı/komut çalıştırıyor: {cmd_blob.strip()[:160]}",
            })

    string_findings = []
    for rule in STRING_SIGNATURES:
        matched_items = []
        for pat in rule["patterns"]:
            m = re.search(pat, extracted_text, flags=re.IGNORECASE)   # search, not findall: groups would hide the full match
            if m:
                sample_match = m.group(0).strip()[:80]
                if sample_match not in matched_items:
                    matched_items.append(sample_match)
        if matched_items:
            severity = rule["severity"]
            esc = rule.get("escalate")
            extra = 0
            if esc and len(matched_items) >= esc[0]:
                severity = esc[1]
                extra = min(20, 5 * (len(matched_items) - esc[0]))   # each further distinct trait adds weight
            string_findings.append({
                "extra_points": extra,
                "category": rule["category"],
                "severity": severity,
                "description": rule["description"],
                "matches": matched_items[:8],
                "distinct": len(matched_items),
            })

    # Extract URLs and IPv4 addresses of interest
    urls = list(set(re.findall(r"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{8,120}", extracted_text)))
    # Filter out standard certificate authority URLs
    benign_domains = ("digicert.com", "verisign.com", "symantec.com", "microsoft.com", "sectigo.com", "comodoca.com", "globalsign.com", "adobe.com", "w3.org", "xml.org", "schemas.microsoft.com", "ocsp.", "crl.")
    interesting_urls = [u for u in urls if not any(bd in u.lower() for bd in benign_domains)][:15]
    interesting_ips = extract_interesting_ips(extracted_text)

    # Risk Scoring (0 - 100)
    risk_score = 0
    risk_reasons = []

    is_script = ext in SCRIPT_EXTENSIONS
    if sig_status == "HashMismatch":
        risk_score += 45
        risk_reasons.append("KRİTİK: Dosyanın dijital imzası bozulmuş (HashMismatch)! Orijinal dosya sonradan yamalanmış veya içine kod enjekte edilmiş.")
    elif sig_status == "Valid":
        # A valid signature is information, not evidence of safety: stealers are often signed with stolen/bought certificates.
        risk_reasons.append(f"Geçerli dijital imza: {sig_info.get('signer', '')} (imza zararsızlık kanıtı değildir; risk puanını düşürmez)")
    elif is_script:
        risk_reasons.append("Script dosyası: imzasız olması normaldir, puana eklenmedi. İçeriğine bakın.")
    elif pe_info["is_pe"] or ext == ".msi":
        risk_score += 20
        risk_reasons.append(f"Program geçerli bir dijital imzaya sahip değil (Durum: {sig_status}).")

    if path_obj.name.lower() in SUSPICIOUS_FILENAMES and sig_status != "Valid":
        risk_score += 25
        risk_reasons.append(f"'{path_obj.name}' sıkça DLL Hijacking veya yama/crack işlemlerinde değiştirilen kritik bir dosya adıdır ve imzasızdır.")

    if pe_info["is_packed"]:
        risk_score += 20
        risk_reasons.append("Paketlenmiş/şifrelenmiş kod: " + " ".join(pe_info["packing_reasons"][:2]))

    if pe_info["anomalies"]:
        risk_score += min(35, pe_info["anomaly_points"])
        for anom in pe_info["anomalies"][:4]:
            risk_reasons.append(f"PE anomalisi: {anom}")

    if pe_info["dotnet_indicators"]:
        risk_score += min(30, sum(d["points"] for d in pe_info["dotnet_indicators"]))
        for di in pe_info["dotnet_indicators"]:
            risk_reasons.append(f".NET göstergesi ({di['severity']}): {di['description']}")

    for sf in spoof_flags:
        risk_score += sf["points"]
        risk_reasons.append(sf["reason"])

    for ff in format_findings:
        risk_score += ff["points"]
        risk_reasons.append(f"{ff['category']} ({ff['severity']}): {ff['description']}")

    if deobfuscated_snippets:
        risk_reasons.append(f"{len(deobfuscated_snippets)} gizlenmiş/şifreli komut bloğu çözüldü ({deobfuscated_snippets[0]['kind']}).")

    imports = pe_info.pop("_all_imports", set())
    has = lambda names: any(i.startswith(n) for i in imports for n in names)  # noqa: E731
    for points, title, groups in API_COMBOS:
        if imports and all(has(g) for g in groups):
            risk_score += points
            hits = sorted({i for g in groups for i in imports if any(i.startswith(n) for n in g)})
            risk_reasons.append(f"{title}: {', '.join(hits[:6])}")
    if pe_info["suspicious_imports"] and not any(r.startswith(t) for _, t, _ in API_COMBOS for r in risk_reasons):
        cats = ", ".join(pe_info["suspicious_imports"])
        risk_reasons.append(f"Tek başına şüpheli olmayan API'ler var ({cats}); zararlıya özgü bir birleşim yok, puana eklenmedi.")

    for finding in string_findings:
        risk_score += SEVERITY_POINTS.get(finding["severity"], 6) + finding.get("extra_points", 0)
        risk_reasons.append(f"{finding['category']} ({finding['distinct']} farklı iz, {finding['severity']}): {', '.join(finding['matches'][:4])}")

    yara_raw = yara_scanner.scan_bytes(sample_data, path_obj.name)
    if tail_data:
        yara_raw.extend(yara_scanner.scan_bytes(tail_data, path_obj.name))
    if deobfuscated_snippets:
        dec_bytes = "\n".join(s["decoded"] for s in deobfuscated_snippets).encode("utf-8", errors="ignore")
        yara_raw.extend(yara_scanner.scan_bytes(dec_bytes, path_obj.name))
    yara_matches: List[Dict[str, Any]] = []
    seen_yara: set = set()
    for ym in yara_raw:
        if ym["rule"] not in seen_yara:
            seen_yara.add(ym["rule"])
            yara_matches.append(ym)
    if yara_matches:
        risk_score += min(45, sum(m.get("score", 15) for m in yara_matches))
        for ym in yara_matches:
            strs_txt = f" [{', '.join(ym['strings'][:4])}]" if ym.get("strings") else ""
            risk_reasons.append(f"YARA [{ym['rule']}] ({ym['severity']}): {ym['description']}{strs_txt}")

    risk_score = min(100, risk_score)
    if risk_score >= 65:
        risk_level = "YÜKSEK RİSK (Tehlikeli / Şüpheli)"
    elif risk_score >= 35:
        risk_level = "ORTA RİSK (İnceleme & Sandbox Şart)"
    else:
        risk_level = "DÜŞÜK RİSK (statik incelemede belirgin iz yok)"

    return {
        "file_name": path_obj.name,
        "file_path": str(path_obj.resolve()),
        "file_size": file_size,
        "file_size_mb": round(file_size / (1024 * 1024), 2),
        "extension": path_obj.suffix.lower(),
        "hashes": hashes,
        "entropy": overall_entropy,
        "signature": sig_info,
        "pe_info": pe_info,
        "string_findings": string_findings,
        "yara_matches": yara_matches,
        "spoof_flags": spoof_flags,
        "format_findings": format_findings,
        "lnk_info": lnk_info,
        "deobfuscated_snippets": deobfuscated_snippets,
        "interesting_urls": interesting_urls,
        "interesting_ips": interesting_ips,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "external_links": {
            "virustotal": f"https://www.virustotal.com/gui/file/{hashes['sha256']}",
            "hybrid_analysis": f"https://www.hybrid-analysis.com/search?query={hashes['sha256']}",
            "anyrun": f"https://app.any.run/submissions/#filehash:{hashes['sha256']}",
            "triage": f"https://tria.ge/s?q={hashes['sha256']}"
        }
    }


def scan_path(target_path: str, max_files: int = 50) -> Dict[str, Any]:
    """Scans either a single file, a ZIP archive, or a folder containing an installer/crack."""
    path_obj = Path(target_path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Belirtilen dosya veya klasör bulunamadı: {target_path}")

    files_to_scan: List[str] = []

    if path_obj.is_file():
        if path_obj.suffix.lower() == ".zip":
            extract_root = Path(target_path).parent / f"_extracted_{path_obj.stem}"
            extract_root.mkdir(parents=True, exist_ok=True)
            root_resolved = extract_root.resolve()
            with zipfile.ZipFile(path_obj, "r") as zf:
                total_sz = sum(i.file_size for i in zf.infolist())
                if total_sz > 1024 ** 3:
                    raise ValueError("ZIP açılmış boyutu 1 GB sınırını aşıyor.")
                for name in zf.namelist():
                    dest = (root_resolved / name).resolve()
                    if dest != root_resolved and root_resolved not in dest.parents:
                        raise ValueError(f"ZIP içinde güvenli olmayan yol: {name}")
                zf.extractall(extract_root)
            for root, _, files in os.walk(extract_root):
                for f in files:
                    ext = Path(f).suffix.lower()
                    if ext in EXECUTABLE_EXTENSIONS:
                        files_to_scan.append(os.path.join(root, f))
        else:
            files_to_scan.append(str(path_obj.resolve()))
    elif path_obj.is_dir():
        for root, _, files in os.walk(path_obj):
            for f in files:
                ext = Path(f).suffix.lower()
                if ext in EXECUTABLE_EXTENSIONS:
                    files_to_scan.append(os.path.join(root, f))

    # Prioritize suspicious filenames & .exe/.dll/.bat/.ps1 files
    files_to_scan.sort(key=lambda p: (
        0 if Path(p).name.lower() in SUSPICIOUS_FILENAMES else 1,
        0 if Path(p).suffix.lower() in {".exe", ".bat", ".cmd", ".ps1", ".vbs"} else 1
    ))
    files_to_scan = files_to_scan[:max_files]

    sig_map = check_authenticode_signatures(files_to_scan)
    analyzed_files = []
    for fpath in files_to_scan:
        analyzed_files.append(analyze_single_file(fpath, sig_map.get(fpath)))

    # Sort results so highest risk files appear first!
    analyzed_files.sort(key=lambda x: x["risk_score"], reverse=True)

    max_risk = max((f["risk_score"] for f in analyzed_files), default=0)
    unsigned_count = sum(1 for f in analyzed_files if f["signature"].get("status") != "Valid")
    tampered_count = sum(1 for f in analyzed_files if f["signature"].get("status") == "HashMismatch")

    return {
        "target_path": str(path_obj.resolve()),
        "is_directory": path_obj.is_dir(),
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_scanned": len(analyzed_files),
        "max_risk_score": max_risk,
        "unsigned_count": unsigned_count,
        "tampered_count": tampered_count,
        "files": analyzed_files
    }
