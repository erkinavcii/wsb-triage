"""Additional threat intelligence clients: MalwareBazaar & Hybrid Analysis (hash lookup only)."""
import os
import re
from typing import Any, Dict, Optional

import requests

import vt_client

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
HA_API_URL = "https://www.hybrid-analysis.com/api/v2"


def get_intel_config() -> Dict[str, Any]:
    cfg = vt_client.load_config()
    mb_key = (cfg.get("mb_api_key") or os.environ.get("MB_API_KEY") or vt_client._user_env("MB_API_KEY") or "").strip()
    ha_key = (cfg.get("ha_api_key") or os.environ.get("HA_API_KEY") or vt_client._user_env("HA_API_KEY") or "").strip()
    mb_enabled = bool(cfg.get("mb_enabled", False) or mb_key)
    return {
        "mb_api_key": mb_key,
        "ha_api_key": ha_key,
        "mb_enabled": mb_enabled,
    }


def set_intel_config(
    mb_api_key: Optional[str] = None,
    ha_api_key: Optional[str] = None,
    mb_enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    cfg = vt_client.load_config()
    if mb_api_key is not None:
        cfg["mb_api_key"] = mb_api_key.strip()
    if ha_api_key is not None:
        cfg["ha_api_key"] = ha_api_key.strip()
    if mb_enabled is not None:
        cfg["mb_enabled"] = bool(mb_enabled)
    vt_client.save_config(cfg)
    return get_intel_config()


def has_configured_sources() -> bool:
    c = get_intel_config()
    return bool(c["mb_enabled"] or c["mb_api_key"] or c["ha_api_key"])


def _clean_sha(sha256: str) -> str:
    s = (sha256 or "").strip().lower()
    if not _SHA256_RE.fullmatch(s):
        raise ValueError("Geçersiz SHA-256 hash.")
    return s


def lookup_malwarebazaar(sha256: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    sha = _clean_sha(sha256)
    gui_url = f"https://bazaar.abuse.ch/sample/{sha}/"
    key = (api_key if api_key is not None else get_intel_config()["mb_api_key"]).strip()
    headers = {"User-Agent": "SafeBox-Analyzer/1.0", "Accept": "application/json"}
    if key:
        headers["Auth-Key"] = key
    try:
        resp = requests.post(MB_API_URL, data={"query": "get_info", "hash": sha}, headers=headers, timeout=20)
    except requests.RequestException as ex:
        return {"source": "MalwareBazaar", "status": "error", "found": False, "verdict": "", "message": f"Bağlantı hatası: {ex}", "gui_url": gui_url}

    if resp.status_code in (401, 403):
        return {"source": "MalwareBazaar", "status": "auth_required", "found": False, "verdict": "",
                "message": "MalwareBazaar Auth-Key gerekiyor (ücretsiz hesapla alınabilir).", "gui_url": gui_url}
    if resp.status_code == 429:
        return {"source": "MalwareBazaar", "status": "rate_limit", "found": False, "verdict": "",
                "message": "MalwareBazaar hız sınırına ulaşıldı.", "gui_url": gui_url}
    if resp.status_code != 200:
        return {"source": "MalwareBazaar", "status": "error", "found": False, "verdict": "",
                "message": f"HTTP {resp.status_code}", "gui_url": gui_url}
    try:
        body = resp.json()
    except Exception:
        return {"source": "MalwareBazaar", "status": "error", "found": False, "verdict": "", "message": "Geçersiz JSON yanıtı", "gui_url": gui_url}

    qst = body.get("query_status")
    if qst == "hash_not_found":
        return {"source": "MalwareBazaar", "status": "not_found", "found": False, "verdict": "not_found",
                "family": "", "tags": [], "gui_url": gui_url}
    if qst == "ok" and isinstance(body.get("data"), list) and body["data"]:
        row = body["data"][0]
        family = str(row.get("signature") or "").strip()
        tags = [str(t) for t in (row.get("tags") or []) if t][:10]
        mime = str(row.get("file_type_mime") or "").strip()
        return {
            "source": "MalwareBazaar",
            "status": "found",
            "found": True,
            "verdict": "malicious",
            "family": family,
            "tags": tags,
            "file_type": mime,
            "gui_url": gui_url,
        }
    return {"source": "MalwareBazaar", "status": "error", "found": False, "verdict": "",
            "message": f"Durum: {qst}", "gui_url": gui_url}


def lookup_hybrid_analysis(sha256: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    sha = _clean_sha(sha256)
    gui_url = f"https://www.hybrid-analysis.com/sample/{sha}"
    key = (api_key if api_key is not None else get_intel_config()["ha_api_key"]).strip()
    if not key:
        return {"source": "Hybrid Analysis", "status": "skipped", "found": False, "verdict": "",
                "message": "Hybrid Analysis API anahtarı girilmemiş.", "gui_url": f"https://www.hybrid-analysis.com/search?query={sha}"}
    headers = {"api-key": key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}
    try:
        resp = requests.get(f"{HA_API_URL}/overview/{sha}", headers=headers, timeout=20)
    except requests.RequestException as ex:
        return {"source": "Hybrid Analysis", "status": "error", "found": False, "verdict": "", "message": f"Bağlantı hatası: {ex}", "gui_url": gui_url}

    if resp.status_code == 404:
        return {"source": "Hybrid Analysis", "status": "not_found", "found": False, "verdict": "not_found",
                "family": "", "score": 0, "tags": [], "gui_url": gui_url}
    if resp.status_code in (401, 403):
        return {"source": "Hybrid Analysis", "status": "error", "found": False, "verdict": "",
                "message": "Hybrid Analysis API anahtarı geçersiz veya yetkisiz.", "gui_url": gui_url}
    if resp.status_code == 429:
        return {"source": "Hybrid Analysis", "status": "rate_limit", "found": False, "verdict": "",
                "message": "Hybrid Analysis hız sınırına ulaşıldı.", "gui_url": gui_url}
    if resp.status_code != 200:
        return {"source": "Hybrid Analysis", "status": "error", "found": False, "verdict": "",
                "message": f"HTTP {resp.status_code}", "gui_url": gui_url}
    try:
        d = resp.json()
    except Exception:
        return {"source": "Hybrid Analysis", "status": "error", "found": False, "verdict": "", "message": "Geçersiz JSON yanıtı", "gui_url": gui_url}

    verdict = str(d.get("verdict") or "unknown").lower()
    score = int(d.get("threat_score") or 0) if str(d.get("threat_score") or "").isdigit() else 0
    av_detect = int(d.get("av_detect") or 0) if str(d.get("av_detect") or "").isdigit() else 0
    family = str(d.get("vx_family") or "").strip()
    tags = [str(t) for t in (d.get("tags") or []) if t][:10]
    return {
        "source": "Hybrid Analysis",
        "status": "found",
        "found": True,
        "verdict": verdict,
        "threat_score": score,
        "av_detect": av_detect,
        "family": family,
        "tags": tags,
        "gui_url": gui_url,
    }


def query_hash_intel(sha256: str, run_mb: bool = True, run_ha: bool = True) -> Dict[str, Any]:
    sha = _clean_sha(sha256)
    mb = lookup_malwarebazaar(sha) if run_mb else None
    ha = lookup_hybrid_analysis(sha) if run_ha else None
    hits = []
    malicious = False
    if mb and mb.get("found"):
        malicious = True
        hits.append(f"MalwareBazaar: {mb.get('family') or 'zararlı kayıtlı'}")
    if ha and ha.get("found"):
        v = ha.get("verdict") or ""
        if v == "malicious" or (ha.get("threat_score") or 0) >= 70:
            malicious = True
        hits.append(f"Hybrid Analysis: {v or 'kayıtlı'}" + (f" ({ha.get('family')})" if ha.get("family") else ""))
    return {
        "sha256": sha,
        "malwarebazaar": mb,
        "hybrid_analysis": ha,
        "any_found": bool((mb and mb.get("found")) or (ha and ha.get("found"))),
        "malicious": malicious,
        "summary": "; ".join(hits),
    }
