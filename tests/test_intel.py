"""Tests for CIRCL Hashlookup, ThreatFox IOC lookup, config persistence, and query_hash_intel."""
import pytest

import intel_client
import vt_client


class _Resp:
    def __init__(self, code, body=None, json_err=False):
        self.status_code = code
        self._body = body
        self._json_err = json_err
        self.text = ""

    def json(self):
        if self._json_err:
            raise ValueError("bad json")
        return self._body


def test_intel_config_defaults_keep_circl_and_tf_disabled(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.json"
    monkeypatch.setattr(vt_client, "CONFIG_PATH", cfg_file)
    cfg = intel_client.get_intel_config()
    assert cfg["circl_enabled"] is False
    assert cfg["tf_enabled"] is False
    assert cfg["mb_enabled"] is False
    assert intel_client.has_configured_sources() is False


def test_intel_config_persistence_for_circl_and_tf(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.json"
    monkeypatch.setattr(vt_client, "CONFIG_PATH", cfg_file)

    updated = intel_client.set_intel_config(circl_enabled=True, tf_enabled=False)
    assert updated["circl_enabled"] is True
    assert updated["tf_enabled"] is False
    assert intel_client.has_configured_sources() is True

    updated2 = intel_client.set_intel_config(circl_enabled=False, tf_enabled=True)
    assert updated2["circl_enabled"] is False
    assert updated2["tf_enabled"] is True
    assert intel_client.has_configured_sources() is True

    # Reload from disk
    reloaded = intel_client.get_intel_config()
    assert reloaded["circl_enabled"] is False
    assert reloaded["tf_enabled"] is True


def test_circl_known_good_and_known_malicious(monkeypatch):
    sha = "a" * 64
    seen = {}

    def fake_get_good(url, headers=None, timeout=None):
        seen["url"] = url
        seen["timeout"] = timeout
        return _Resp(
            200,
            {
                "FileName": "notepad.exe",
                "OpSystemCode": {"OpSystemName": "Windows 10"},
                "MfgCode": {"MfgName": "Microsoft Corporation"},
                "KnownMalicious": "",
            },
        )

    monkeypatch.setattr(intel_client.requests, "get", fake_get_good)
    res_good = intel_client.lookup_circl_hashlookup(sha)
    assert seen["url"] == f"{intel_client.CIRCL_API_URL}/{sha}"
    assert seen["timeout"] == 15
    assert res_good["source"] == "CIRCL Hashlookup"
    assert res_good["status"] == "found"
    assert res_good["found"] is True
    assert res_good["verdict"] == "known_good"
    assert res_good["file_name"] == "notepad.exe"
    assert res_good["product_name"] == "Windows 10"
    assert res_good["vendor"] == "Microsoft Corporation"

    def fake_get_mal(url, headers=None, timeout=None):
        return _Resp(
            200,
            {
                "FileName": "evil.exe",
                "ProductName": "EvilTool",
                "VendorName": "BadCorp",
                "KnownMalicious": "malshare.com",
            },
        )

    monkeypatch.setattr(intel_client.requests, "get", fake_get_mal)
    res_mal = intel_client.lookup_circl_hashlookup(sha)
    assert res_mal["status"] == "found"
    assert res_mal["found"] is True
    assert res_mal["verdict"] == "malicious"
    assert res_mal["known_malicious"] == "malshare.com"

    monkeypatch.setattr(intel_client.requests, "get", lambda *a, **k: _Resp(404))
    res_404 = intel_client.lookup_circl_hashlookup(sha)
    assert res_404["status"] == "not_found"
    assert res_404["found"] is False
    assert res_404["verdict"] == "not_found"

    monkeypatch.setattr(intel_client.requests, "get", lambda *a, **k: _Resp(429))
    res_429 = intel_client.lookup_circl_hashlookup(sha)
    assert res_429["status"] == "error"
    assert res_429["found"] is False

    monkeypatch.setattr(intel_client.requests, "get", lambda *a, **k: _Resp(200, json_err=True))
    res_bad_json = intel_client.lookup_circl_hashlookup(sha)
    assert res_bad_json["status"] == "error"
    assert res_bad_json["found"] is False


def test_threatfox_malicious_not_found_and_errors(tmp_path, monkeypatch):
    sha = "b" * 64
    monkeypatch.setattr(vt_client, "CONFIG_PATH", tmp_path / "cfg.json")
    intel_client.set_intel_config(mb_api_key="shared-abuse-key")
    seen = {}

    def fake_post_hit(url, json=None, headers=None, timeout=None):
        seen["url"] = url
        seen["json"] = json
        seen["headers"] = headers
        seen["timeout"] = timeout
        return _Resp(
            200,
            {
                "query_status": "ok",
                "data": [
                    {
                        "malware_printable": "Lumma Stealer",
                        "malware": "win.lumma",
                        "threat_type": "payload",
                        "tags": ["stealer", "exe"],
                    }
                ],
            },
        )

    monkeypatch.setattr(intel_client.requests, "post", fake_post_hit)
    hit = intel_client.lookup_threatfox(sha)
    assert seen["url"] == intel_client.TF_API_URL
    assert seen["json"] == {"query": "search_hash", "hash": sha}
    assert seen["headers"].get("Auth-Key") == "shared-abuse-key"
    assert seen["timeout"] == 15
    assert hit["source"] == "ThreatFox"
    assert hit["status"] == "found"
    assert hit["found"] is True
    assert hit["verdict"] == "malicious"
    assert hit["family"] == "Lumma Stealer"
    assert hit["threat_type"] == "payload"
    assert hit["tags"] == ["stealer", "exe"]

    monkeypatch.setattr(
        intel_client.requests,
        "post",
        lambda *a, **k: _Resp(200, {"query_status": "no_result"}),
    )
    miss = intel_client.lookup_threatfox(sha)
    assert miss["status"] == "not_found"
    assert miss["found"] is False
    assert miss["verdict"] == "not_found"

    monkeypatch.setattr(intel_client.requests, "post", lambda *a, **k: _Resp(403))
    auth = intel_client.lookup_threatfox(sha)
    assert auth["status"] == "auth_required"
    assert auth["found"] is False

    monkeypatch.setattr(intel_client.requests, "post", lambda *a, **k: _Resp(429))
    rl = intel_client.lookup_threatfox(sha)
    assert rl["status"] == "rate_limit"
    assert rl["found"] is False


def test_query_hash_intel_circl_and_threatfox_aggregation(monkeypatch):
    sha = "c" * 64

    # Case 1: CIRCL known_good alone -> known_good=True, malicious=False
    monkeypatch.setattr(
        intel_client,
        "lookup_circl_hashlookup",
        lambda s: {
            "source": "CIRCL Hashlookup",
            "status": "found",
            "found": True,
            "verdict": "known_good",
            "file_name": "calc.exe",
            "product_name": "Windows Calculator",
            "vendor": "Microsoft",
            "known_malicious": "",
            "gui_url": f"{intel_client.CIRCL_API_URL}/{s}",
        },
    )
    monkeypatch.setattr(
        intel_client,
        "lookup_threatfox",
        lambda s: {"source": "ThreatFox", "status": "not_found", "found": False, "verdict": "not_found", "gui_url": ""},
    )

    res_clean = intel_client.query_hash_intel(sha, run_mb=False, run_ha=False, run_circl=True, run_tf=True)
    assert res_clean["any_found"] is True
    assert res_clean["malicious"] is False
    assert res_clean["known_good"] is True
    assert res_clean["circl"]["verdict"] == "known_good"
    assert res_clean["threatfox"]["found"] is False
    assert "CIRCL Hashlookup" in res_clean["summary"]

    # Case 2: ThreatFox malicious overrides known_good -> malicious=True, known_good=False
    monkeypatch.setattr(
        intel_client,
        "lookup_threatfox",
        lambda s: {
            "source": "ThreatFox",
            "status": "found",
            "found": True,
            "verdict": "malicious",
            "family": "AgentTesla",
            "threat_type": "payload",
            "tags": ["rat"],
            "gui_url": "https://threatfox.abuse.ch/browse/",
        },
    )
    res_mal = intel_client.query_hash_intel(sha, run_mb=False, run_ha=False, run_circl=True, run_tf=True)
    assert res_mal["any_found"] is True
    assert res_mal["malicious"] is True
    assert res_mal["known_good"] is False
    assert "ThreatFox: AgentTesla" in res_mal["summary"]
