"""VirusTotal API v3 client: rate-limited lookups, uploads (up to 650 MB) and analysis polling."""
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests

CONFIG_PATH = Path(__file__).parent / "config.json"
VT_BASE_URL = "https://www.virustotal.com/api/v3"
MIN_INTERVAL_SEC = 15.5          # free API: 4 requests / minute
DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024
MAX_UPLOAD = 650 * 1024 * 1024

DANGEROUS_KEYWORDS = ("trojan", "stealer", "lumma", "redline", "vidar", "raccoon", "stealc", "agenttesla", "asyncrat", "njrat",
                      "remcos", "quasar", "cobalt", "ransom", "backdoor", "clipper", "miner", "xmrig", "coinmin", "dropper",
                      "downloader", "spyware", "banker", "infostealer", "rat.")
TOOL_KEYWORDS = ("hacktool", "riskware", "crack", "keygen", "patch", "pua", "pup", "activator", "kms")

_lock = threading.Lock()
_last_call = 0.0


class VtError(Exception):
    pass


# ------------------------------------------------------------------ config / key
def load_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"vt_api_key": ""}


def save_config(cfg: Dict[str, Any]) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def _user_env(name: str) -> str:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
            return str(winreg.QueryValueEx(k, name)[0])
    except Exception:
        return ""


def get_api_key() -> str:
    key = load_config().get("vt_api_key", "").strip()
    return key or os.environ.get("VT_API_KEY", "").strip() or _user_env("VT_API_KEY").strip()


def set_api_key(api_key: str) -> None:
    cfg = load_config()
    cfg["vt_api_key"] = api_key.strip()
    save_config(cfg)


# ------------------------------------------------------------------ low level
def _throttle() -> None:
    global _last_call
    with _lock:
        wait = MIN_INTERVAL_SEC - (time.time() - _last_call)
        if wait > 0:
            time.sleep(wait)
        _last_call = time.time()


def _get(url: str, key: str) -> Optional[Dict[str, Any]]:
    """GET with throttling and 429 retry. Returns None on 404."""
    for _ in range(4):
        _throttle()
        resp = requests.get(url, headers={"x-apikey": key, "Accept": "application/json"}, timeout=30)
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            time.sleep(60)
            continue
        if resp.status_code == 401:
            raise VtError("Geçersiz VirusTotal API anahtarı (HTTP 401).")
        if resp.status_code != 200:
            raise VtError(f"VirusTotal HTTP {resp.status_code}")
        return resp.json()
    raise VtError("VirusTotal kota sınırı aşıldı (429), daha sonra tekrar deneyin.")


def summarize(data: Dict[str, Any], sha256: str) -> Dict[str, Any]:
    attrs = (data or {}).get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    flagged = []
    for engine, ed in results.items():
        if ed.get("category") in ("malicious", "suspicious"):
            flagged.append({"engine": engine, "category": ed.get("category"), "result": ed.get("result") or "Şüpheli"})
    label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", "") or ""
    text = (label + " " + " ".join(e["result"] for e in flagged)).lower()
    sandbox_verdicts = [
        {"sandbox": n, "category": d.get("category", ""), "malware_names": d.get("malware_classification", [])}
        for n, d in (attrs.get("sandbox_verdicts") or {}).items()
    ]
    return {
        "status": "found",
        "sha256": sha256,
        "meaningful_name": attrs.get("meaningful_name", ""),
        "reputation": attrs.get("reputation", 0),
        "stats": {"malicious": malicious, "suspicious": suspicious, "undetected": undetected, "harmless": harmless,
                  "total": malicious + suspicious + undetected + harmless},
        "suggested_threat_label": label or "Belirtilmemiş",
        "has_dangerous_malware_family": any(k in text for k in DANGEROUS_KEYWORDS),
        "looks_like_crack_tool": any(k in text for k in TOOL_KEYWORDS),
        "tags": attrs.get("tags", []),
        "sandbox_verdicts": sandbox_verdicts,
        "flagged_engines": flagged[:20],
        "gui_url": f"https://www.virustotal.com/gui/file/{sha256}/detection",
    }


# ------------------------------------------------------------------ pipeline API
def lookup(sha256: str, key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    key = key or get_api_key()
    data = _get(f"{VT_BASE_URL}/files/{sha256}", key)
    return summarize(data, sha256) if data else None


def upload(file_path: str, key: Optional[str] = None) -> str:
    """Uploads a file and returns the analysis id."""
    key = key or get_api_key()
    size = Path(file_path).stat().st_size
    if size > MAX_UPLOAD:
        raise VtError("Dosya 650 MB'tan büyük, VirusTotal'a yüklenemez.")
    url = f"{VT_BASE_URL}/files"
    if size > DIRECT_UPLOAD_LIMIT:
        u = _get(f"{VT_BASE_URL}/files/upload_url", key)
        if not u or not u.get("data"):
            raise VtError("Büyük dosya yükleme adresi alınamadı.")
        url = u["data"]
    _throttle()
    with open(file_path, "rb") as f:
        resp = requests.post(url, headers={"x-apikey": key}, files={"file": (Path(file_path).name, f)}, timeout=3600)
    if resp.status_code not in (200, 201):
        raise VtError(f"Yükleme hatası HTTP {resp.status_code}: {resp.text[:200]}")
    return resp.json().get("data", {}).get("id", "")


def analysis_done(analysis_id: str, key: Optional[str] = None) -> bool:
    """One (rate-limited) status check of an uploaded file's analysis."""
    data = _get(f"{VT_BASE_URL}/analyses/{analysis_id}", key or get_api_key())
    return bool(data and data.get("data", {}).get("attributes", {}).get("status") == "completed")


def wait_for_analysis(analysis_id: str, key: Optional[str] = None, timeout_sec: int = 480) -> bool:
    key = key or get_api_key()
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        data = _get(f"{VT_BASE_URL}/analyses/{analysis_id}", key)
        if data and data.get("data", {}).get("attributes", {}).get("status") == "completed":
            return True
    return False


# ------------------------------------------------------------------ manual buttons in the panel
def query_virustotal_hash(sha256: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    key = (api_key or get_api_key()).strip()
    if not key:
        return {"status": "no_api_key",
                "message": "VirusTotal API anahtarı girilmemiş. Sağ üstteki 'VirusTotal API Ayarları' butonundan ekleyebilirsiniz."}
    try:
        res = lookup(sha256, key)
        if res is None:
            return {"status": "not_found", "sha256": sha256,
                    "message": "Bu dosya VirusTotal'da hiç taranmamış. 650 MB altındaysa yükleyip taratabilirsiniz."}
        return res
    except VtError as e:
        return {"status": "error", "message": str(e)}
    except Exception as e:
        return {"status": "error", "message": f"Bağlantı hatası: {e}"}


def upload_file_to_virustotal(file_path: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    key = (api_key or get_api_key()).strip()
    if not key:
        return {"status": "no_api_key", "message": "API anahtarı gerekli."}
    if not Path(file_path).exists():
        return {"status": "error", "message": "Dosya bulunamadı."}
    try:
        analysis_id = upload(file_path, key)
        return {"status": "uploaded", "analysis_id": analysis_id,
                "message": "Dosya VirusTotal'a yüklendi. Tarama 1-3 dakika sürer; sonra 'VirusTotal ile Sorgula'ya tekrar basın."}
    except VtError as e:
        return {"status": "error", "message": str(e)}
    except Exception as e:
        return {"status": "error", "message": f"Yükleme sırasında hata: {e}"}
