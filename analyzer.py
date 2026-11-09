import hashlib
import math
import os
import re
import subprocess
import json
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

import pefile

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".msi", ".scr", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta"
}

SUSPICIOUS_FILENAMES = {
    "amtlib.dll", "patch.exe", "keygen.exe", "crack.exe", "loader.exe",
    "activator.exe", "inject.exe", "hook.dll", "winhttp.dll", "version.dll",
    "uxtheme.dll", "dwmapi.dll", "cryptbase.dll", "profapi.dll", "nsudo.exe"
}

# Suspicious Windows APIs grouped by threat category
SUSPICIOUS_APIS = {
    "Process Injection / Bellek Müdahalesi": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "QueueUserAPC", "SetWindowsHookEx",
        "RtlCreateUserThread", "NtWriteVirtualMemory"
    ],
    "Anti-Debug / Sandbox Atlatma (Anti-VM)": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "GetTickCount64", "QueryPerformanceCounter",
        "NtSetInformationThread"
    ],
    "Şifre & Veri Çalma (Infostealer)": [
        "CryptUnprotectData", "BCryptDecrypt", "VaultEnumerateItems",
        "CredEnumerate", "WlxLoggedOnSAS"
    ],
    "Gizli Komut Çalıştırma / İndirme": [
        "URLDownloadToFile", "WinExec", "ShellExecute", "CreateProcessInternal",
        "InternetOpenUrl", "HttpSendRequest", "WinHttpOpen"
    ],
    "Kayıt Defteri & Servis Kalıcılığı (Persistence)": [
        "RegSetValueEx", "CreateService", "StartService", "ChangeServiceConfig"
    ]
}

# Regex & string patterns for Stealers, RATs, C2, Anti-VM
STRING_SIGNATURES = [
    {
        "category": "Infostealer (Tarayıcı/Cüzdan Hırsızı)",
        "severity": "critical",
        "patterns": [
            r"Login Data", r"Local State", r"cookies\.sqlite", r"Web Data",
            r"\\Google\\Chrome\\User Data", r"\\Mozilla\\Firefox\\Profiles",
            r"\\BraveSoftware\\Brave-Browser", r"\\Discord\\Local Storage\\leveldb",
            r"\\Telegram Desktop\\tdata", r"MetaMask", r"Exodus\\exodus\.wallet",
            r"CryptUnprotectData"
        ],
        "description": "Tarayıcı şifreleri, çerezler (oturumlar), Discord/Telegram veya kripto cüzdan dosyalarına erişim izleri."
    },
    {
        "category": "Anti-VM / Sandbox Tespiti",
        "severity": "high",
        "patterns": [
            r"SbieDll\.dll", r"VBoxMouse\.sys", r"VBoxGuest\.sys", r"VBoxSF\.sys",
            r"vmmouse\.sys", r"vmhgfs\.sys", r"VIRTUALBOX", r"VMWARE", r"QEMU",
            r"wine_get_unix_file_name", r"cuckoomon", r"Wireshark", r"Fiddler",
            r"procmon64\.exe", r"procexp64\.exe"
        ],
        "description": "Dosya sanal makinede (Sandbox/VMware/VirtualBox) veya analiz altında olup olmadığını kontrol ediyor olabilir."
    },
    {
        "category": "Gizli Kalıcılık & Görev Zamanlayıcı (Time-Bomb)",
        "severity": "high",
        "patterns": [
            r"schtasks\s+/create", r"CurrentVersion\\Run", r"CurrentVersion\\RunOnce",
            r"powershell.*-enc", r"powershell.*-WindowStyle\s+Hidden",
            r"powershell.*ExecutionPolicy\s+Bypass", r"cmd\.exe\s+/c",
            r"mshta\.exe", r"regsvr32\s+/s", r"certutil\s+-urlcache",
            r"Add-MpPreference\s+-ExclusionPath"
        ],
        "description": "Windows Defender dışlaması ekleme, gizli PowerShell çalıştırma veya zamanlanmış görev oluşturma komutu."
    },
    {
        "category": "Şüpheli Ağ / Komuta Kontrol (C2) İletişimi",
        "severity": "critical",
        "patterns": [
            r"api\.telegram\.org/bot", r"discord\.com/api/webhooks",
            r"discordapp\.com/api/webhooks", r"pastebin\.com/raw",
            r"\.onion", r"raw\.githubusercontent\.com"
        ],
        "description": "Çalınan verileri dışarı göndermek için sık kullanılan Telegram Bot, Discord Webhook veya Pastebin bağlantısı."
    }
]


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


def analyze_pe_file(file_path: str, raw_data: bytes) -> Dict[str, Any]:
    pe_info = {
        "is_pe": False,
        "architecture": "Bilinmiyor",
        "compile_time": None,
        "is_packed": False,
        "packing_reasons": [],
        "sections": [],
        "suspicious_imports": {},
        "total_imports": 0
    }
    try:
        pe = pefile.PE(data=raw_data, fast_load=False)
        pe_info["is_pe"] = True
        machine = pe.FILE_HEADER.Machine
        pe_info["architecture"] = "64-bit (x64)" if machine == 0x8664 else ("32-bit (x86)" if machine == 0x14c else f"Other ({hex(machine)})")
        
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts:
            pe_info["compile_time"] = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")

        for section in pe.sections:
            sec_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            sec_data = section.get_data()
            sec_entropy = calculate_entropy(sec_data)
            raw_size = section.SizeOfRawData
            virtual_size = section.Misc_VirtualSize

            pe_info["sections"].append({
                "name": sec_name or "(isimsiz)",
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "entropy": sec_entropy,
                "high_entropy": sec_entropy > 7.2
            })

            if sec_entropy > 7.2 and raw_size > 1024:
                pe_info["is_packed"] = True
                pe_info["packing_reasons"].append(
                    f"'{sec_name}' bölümü çok yüksek entropiye ({sec_entropy}/8.0) sahip (Şifrelenmiş/Paketlenmiş kod ihtimali)."
                )
            if sec_name.lower() in ["upx0", "upx1", ".vmp0", ".vmp1", ".themida", ".enigma1"]:
                pe_info["is_packed"] = True
                pe_info["packing_reasons"].append(
                    f"Bilinen paketleyici/koruyucu bölüm adı tespit edildi: '{sec_name}' (UPX / VMProtect / Themida)."
                )

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    pe_info["total_imports"] += 1
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="ignore")
                        for category, api_list in SUSPICIOUS_APIS.items():
                            for target_api in api_list:
                                if func_name.startswith(target_api):
                                    pe_info["suspicious_imports"].setdefault(category, [])
                                    if func_name not in pe_info["suspicious_imports"][category]:
                                        pe_info["suspicious_imports"][category].append(func_name)
        pe.close()
    except Exception:
        pass
    return pe_info


def analyze_single_file(file_path: str, sig_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    path_obj = Path(file_path)
    file_size = path_obj.stat().st_size
    hashes = calculate_hashes(file_path)

    # Read up to 25 MB for string/entropy/PE inspection so huge installers don't freeze memory
    max_read = 25 * 1024 * 1024
    with open(file_path, "rb") as f:
        sample_data = f.read(max_read)

    overall_entropy = calculate_entropy(sample_data)
    if sig_info is None:
        sig_map = check_authenticode_signatures([str(path_obj)])
        sig_info = sig_map.get(str(path_obj), {"status": "Unknown", "message": "", "signer": "", "issuer": ""})

    pe_info = analyze_pe_file(file_path, sample_data)
    extracted_text = extract_printable_strings(sample_data)

    string_findings = []
    for rule in STRING_SIGNATURES:
        matched_items = []
        for pat in rule["patterns"]:
            matches = re.findall(pat, extracted_text, flags=re.IGNORECASE)
            if matches:
                sample_match = matches[0] if isinstance(matches[0], str) else str(matches[0])
                if sample_match not in matched_items:
                    matched_items.append(sample_match)
        if matched_items:
            string_findings.append({
                "category": rule["category"],
                "severity": rule["severity"],
                "description": rule["description"],
                "matches": matched_items[:8]
            })

    # Extract URLs and IPv4 addresses of interest
    urls = list(set(re.findall(r"https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]{8,120}", extracted_text)))
    # Filter out standard certificate authority URLs
    benign_domains = ("digicert.com", "verisign.com", "symantec.com", "microsoft.com", "sectigo.com", "comodoca.com", "globalsign.com", "adobe.com", "w3.org", "xml.org", "schemas.microsoft.com", "ocsp.", "crl.")
    interesting_urls = [u for u in urls if not any(bd in u.lower() for bd in benign_domains)][:15]

    # Risk Scoring (0 - 100)
    risk_score = 0
    risk_reasons = []

    sig_status = sig_info.get("status", "Unknown")
    if sig_status == "HashMismatch":
        risk_score += 45
        risk_reasons.append("KRİTİK: Dosyanın dijital imzası bozulmuş (HashMismatch)! Orijinal dosya sonradan yamalanmış veya içine kod enjekte edilmiş.")
    elif sig_status != "Valid":
        risk_score += 20
        risk_reasons.append(f"Dosya geçerli bir dijital imzaya sahip değil (Durum: {sig_status}).")
    else:
        # A valid signature is information, not evidence of safety: stealers are often signed with stolen/bought certificates.
        risk_reasons.append(f"Geçerli dijital imza: {sig_info.get('signer', '')} (imza zararsızlık kanıtı değildir; risk puanını düşürmez)")

    if path_obj.name.lower() in SUSPICIOUS_FILENAMES and sig_status != "Valid":
        risk_score += 25
        risk_reasons.append(f"'{path_obj.name}' sıkça DLL Hijacking veya yama/crack işlemlerinde değiştirilen kritik bir dosya adıdır ve imzasızdır.")

    if pe_info["is_packed"] or overall_entropy > 7.25:
        risk_score += 20
        risk_reasons.append(f"Yüksek entropi ({overall_entropy}/8.0) veya paketleyici tespit edildi. Zararlı kod analizden gizlenmek için şifrelenmiş olabilir.")

    for cat, apis in pe_info["suspicious_imports"].items():
        if "Injection" in cat or "Infostealer" in cat:
            risk_score += 20
        else:
            risk_score += 10
        risk_reasons.append(f"{cat} API'leri: {', '.join(apis[:5])}")

    for finding in string_findings:
        if finding["severity"] == "critical":
            risk_score += 35
        else:
            risk_score += 18
        risk_reasons.append(f"{finding['category']}: {', '.join(finding['matches'][:4])}")

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
        "interesting_urls": interesting_urls,
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
    temp_extract_dir = None

    if path_obj.is_file():
        if path_obj.suffix.lower() == ".zip":
            extract_root = Path(target_path).parent / f"_extracted_{path_obj.stem}"
            extract_root.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path_obj, "r") as zf:
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
