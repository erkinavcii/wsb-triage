"""Additional threat intelligence clients: MalwareBazaar, Hybrid Analysis, CIRCL Hashlookup & ThreatFox (hash lookup only)."""
import os
import re
from typing import Any, Dict, Optional

import requests

import vt_client

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
HA_API_URL = "https://www.hybrid-analysis.com/api/v2"
CIRCL_API_URL = "https://hashlookup.circl.lu/lookup/sha256"
TF_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def get_intel_config() -> Dict[str, Any]:
    cfg = vt_client.load_config()
    mb_key = (cfg.get("mb_api_key") or os.environ.get("MB_API_KEY") or vt_client._user_env("MB_API_KEY") or "").strip()
    ha_key = (cfg.get("ha_api_key") or os.environ.get("HA_API_KEY") or vt_client._user_env("HA_API_KEY") or "").strip()
    mb_enabled = bool(cfg.get("mb_enabled", False) or mb_key)
    circl_enabled = bool(cfg.get("circl_enabled", False))
    tf_enabled = bool(cfg.get("tf_enabled", False))
    return {
        "mb_api_key": mb_key,
        "ha_api_key": ha_key,
        "mb_enabled": mb_enabled,
        "circl_enabled": circl_enabled,
        "tf_enabled": tf_enabled,
    }


def set_intel_config(
    mb_api_key: Optional[str] = None,
    ha_api_key: Optional[str] = None,
    mb_enabled: Optional[bool] = None,
    circl_enabled: Optional[bool] = None,
    tf_enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    cfg = vt_client.load_config()
    if mb_api_key is not None:
        cfg["mb_api_key"] = mb_api_key.strip()
    if ha_api_key is not None:
        cfg["ha_api_key"] = ha_api_key.strip()
    if mb_enabled is not None:
        cfg["mb_enabled"] = bool(mb_enabled)
    if circl_enabled is not None:
        cfg["circl_enabled"] = bool(circl_enabled)
    if tf_enabled is not None:
        cfg["tf_enabled"] = bool(tf_enabled)
    vt_client.save_config(cfg)
    return get_intel_config()


def has_configured_sources() -> bool:
    c = get_intel_config()
    return bool(c["mb_enabled"] or c["mb_api_key"] or c["ha_api_key"] or c["circl_enabled"] or c["tf_enabled"])


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


def lookup_circl_hashlookup(sha256: str) -> Dict[str, Any]:
    sha = _clean_sha(sha256)
    gui_url = f"{CIRCL_API_URL}/{sha}"
    headers = {"User-Agent": "SafeBox-Analyzer/1.0", "Accept": "application/json"}
    try:
        resp = requests.get(gui_url, headers=headers, timeout=15)
    except requests.RequestException as ex:
        return {"source": "CIRCL Hashlookup", "status": "error", "found": False, "verdict": "",
                "message": f"Bağlantı hatası: {ex}", "gui_url": gui_url}

    if resp.status_code == 404:
        return {"source": "CIRCL Hashlookup", "status": "not_found", "found": False, "verdict": "not_found",
                "gui_url": gui_url}
    if resp.status_code == 429:
        return {"source": "CIRCL Hashlookup", "status": "error", "found": False, "verdict": "",
                "message": "CIRCL Hashlookup hız sınırına ulaşıldı.", "gui_url": gui_url}
    if resp.status_code != 200:
        return {"source": "CIRCL Hashlookup", "status": "error", "found": False, "verdict": "",
                "message": f"HTTP {resp.status_code}", "gui_url": gui_url}
    try:
        d = resp.json()
        if not isinstance(d, dict):
            raise ValueError("non-dict JSON")
    except Exception:
        return {"source": "CIRCL Hashlookup", "status": "error", "found": False, "verdict": "",
                "message": "Geçersiz JSON yanıtı", "gui_url": gui_url}

    known_mal_raw = d.get("KnownMalicious")
    known_mal = str(known_mal_raw or "").strip()
    verdict = "malicious" if known_mal else "known_good"
    op_sys = d.get("OpSystemCode") if isinstance(d.get("OpSystemCode"), dict) else {}
    mfg = d.get("MfgCode") if isinstance(d.get("MfgCode"), dict) else {}
    return {
        "source": "CIRCL Hashlookup",
        "status": "found",
        "found": True,
        "verdict": verdict,
        "file_name": str(d.get("FileName") or ""),
        "product_name": str(d.get("ProductName") or op_sys.get("OpSystemName") or ""),
        "vendor": str(d.get("VendorName") or mfg.get("MfgName") or ""),
        "known_malicious": str(known_mal_raw or ""),
        "gui_url": gui_url,
    }


def lookup_threatfox(sha256: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    sha = _clean_sha(sha256)
    gui_url = "https://threatfox.abuse.ch/browse/"
    key = (api_key if api_key is not None else get_intel_config()["mb_api_key"]).strip()
    headers = {"User-Agent": "SafeBox-Analyzer/1.0", "Accept": "application/json"}
    if key:
        headers["Auth-Key"] = key
    try:
        resp = requests.post(TF_API_URL, json={"query": "search_hash", "hash": sha}, headers=headers, timeout=15)
    except requests.RequestException as ex:
        return {"source": "ThreatFox", "status": "error", "found": False, "verdict": "",
                "message": f"Bağlantı hatası: {ex}", "gui_url": gui_url}

    if resp.status_code in (401, 403):
        return {"source": "ThreatFox", "status": "auth_required", "found": False, "verdict": "",
                "message": "ThreatFox Auth-Key gerekiyor veya yetkisiz.", "gui_url": gui_url}
    if resp.status_code == 429:
        return {"source": "ThreatFox", "status": "rate_limit", "found": False, "verdict": "",
                "message": "ThreatFox hız sınırına ulaşıldı.", "gui_url": gui_url}
    if resp.status_code != 200:
        return {"source": "ThreatFox", "status": "error", "found": False, "verdict": "",
                "message": f"HTTP {resp.status_code}", "gui_url": gui_url}
    try:
        body = resp.json()
        if not isinstance(body, dict):
            raise ValueError("non-dict JSON")
    except Exception:
        return {"source": "ThreatFox", "status": "error", "found": False, "verdict": "",
                "message": "Geçersiz JSON yanıtı", "gui_url": gui_url}

    qst = body.get("query_status")
    if qst == "no_result":
        return {"source": "ThreatFox", "status": "not_found", "found": False, "verdict": "not_found",
                "gui_url": gui_url}
    if qst == "ok" and isinstance(body.get("data"), list) and body["data"]:
        row = body["data"][0] if isinstance(body["data"][0], dict) else {}
        raw_tags = row.get("tags")
        tags = [str(t) for t in (raw_tags if isinstance(raw_tags, list) else []) if t][:10]
        return {
            "source": "ThreatFox",
            "status": "found",
            "found": True,
            "verdict": "malicious",
            "family": str(row.get("malware_printable") or row.get("malware") or ""),
            "threat_type": str(row.get("threat_type") or ""),
            "tags": tags,
            "gui_url": gui_url,
        }
    return {"source": "ThreatFox", "status": "error", "found": False, "verdict": "",
            "message": f"Durum: {qst}", "gui_url": gui_url}


def query_hash_intel(
    sha256: str,
    run_mb: bool = True,
    run_ha: bool = True,
    run_circl: bool = False,
    run_tf: bool = False,
) -> Dict[str, Any]:
    sha = _clean_sha(sha256)
    mb = lookup_malwarebazaar(sha) if run_mb else None
    ha = lookup_hybrid_analysis(sha) if run_ha else None
    circl = lookup_circl_hashlookup(sha) if run_circl else None
    tf = lookup_threatfox(sha) if run_tf else None
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
    if tf and tf.get("found"):
        malicious = True
        hits.append(f"ThreatFox: {tf.get('family') or 'zararlı IOC'}")
    if circl and circl.get("found"):
        if circl.get("verdict") == "malicious":
            malicious = True
            hits.append(f"CIRCL Hashlookup: {circl.get('known_malicious') or 'zararlı kayıtlı'}")
        else:
            label = circl.get("product_name") or circl.get("file_name") or "bilinen temiz"
            hits.append(f"CIRCL Hashlookup: known_good ({label})")
    known_good = bool(circl and circl.get("found") and circl.get("verdict") == "known_good" and not malicious)
    any_found = bool(
        (mb and mb.get("found"))
        or (ha and ha.get("found"))
        or (circl and circl.get("found"))
        or (tf and tf.get("found"))
    )
    return {
        "sha256": sha,
        "malwarebazaar": mb,
        "hybrid_analysis": ha,
        "circl": circl,
        "threatfox": tf,
        "any_found": any_found,
        "malicious": malicious,
        "known_good": known_good,
        "summary": "; ".join(hits),
    }
