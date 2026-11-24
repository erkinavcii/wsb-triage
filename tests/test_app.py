"""Local panel API: host/origin checks, upload limits, input validation."""
import pytest
from fastapi.testclient import TestClient

import app as app_module
import pipeline

BASE = f"http://127.0.0.1:{app_module.PORT}"


@pytest.fixture
def client():
    # Provide the valid token in cookies / headers by default in test client
    c = TestClient(app_module.app, base_url=BASE)
    c.headers.update({"X-SafeBox-Token": app_module.API_TOKEN})
    return c


def test_index_is_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "<html" in r.text.lower()
    assert "/static/styles.css" in r.text
    assert "/static/app.js" in r.text
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
    assert r.headers.get("Cache-Control") == "no-store"
    assert f'content="{app_module.API_TOKEN}"' in r.text


def test_api_token_protection(client):
    bad_client = TestClient(app_module.app, base_url=BASE, follow_redirects=False)

    # Unauthenticated GET / returns 401 unlock screen and NEVER leaks token or cookie
    r_root = bad_client.get("/")
    assert r_root.status_code == 401
    assert app_module.API_TOKEN not in r_root.text
    assert "safebox_token" not in r_root.cookies

    # Minimal health probe is open for launcher readiness polling
    assert bad_client.get("/api/health").status_code == 200

    # All real API GET and POST endpoints reject unauthenticated callers
    for path in ("/api/jobs", "/api/system-status", "/api/browse-dialog", "/api/jobs/missing/report",
                 f"/api/vt/query/{'0' * 64}"):
        assert bad_client.get(path).status_code == 401, f"{path} was not protected"
    assert bad_client.post("/api/watch", json={"enabled": False}).status_code == 401
    assert bad_client.post("/api/watch", json={"enabled": False}, headers={"X-SafeBox-Token": "wrong-token"}).status_code == 401

    # Query token exchange redirects cleanly and sets HttpOnly cookie
    r_redir = bad_client.get(f"/?token={app_module.API_TOKEN}")
    assert r_redir.status_code == 303
    assert r_redir.cookies.get("safebox_token") == app_module.API_TOKEN
    assert bad_client.get("/").status_code == 200

    # Valid cookie MUST NOT bypass an explicit bad/empty X-SafeBox-Token header
    assert bad_client.post("/api/watch", json={"enabled": False}, headers={"X-SafeBox-Token": ""}).status_code == 401
    assert bad_client.post("/api/watch", json={"enabled": False}, headers={"X-SafeBox-Token": "wrong"}).status_code == 401

    # /api/auth accepts valid JSON token and rejects invalid ones
    assert bad_client.post("/api/auth", json={"token": "nope"}).status_code == 401
    assert bad_client.post("/api/auth", json={"token": app_module.API_TOKEN}).status_code == 200

    # Valid header passes
    assert client.post("/api/watch", json={"enabled": False}).status_code == 200


def test_foreign_host_is_refused(client):
    # DNS rebinding: evil.example resolving to 127.0.0.1
    assert client.get("/api/jobs", headers={"host": "evil.example"}).status_code == 403


@pytest.mark.parametrize("headers", [
    {"origin": "http://evil.example"},
    {"origin": "http://127.0.0.1:9999"},                 # another local port is another site
    {"sec-fetch-site": "cross-site"},
    {"sec-fetch-site": "same-site"},
])
def test_cross_site_requests_are_refused(client, headers):
    r = client.post("/api/watch", json={"enabled": False}, headers=headers)
    assert r.status_code == 403


def test_same_origin_request_passes(client):
    r = client.get("/api/jobs", headers={"origin": BASE, "sec-fetch-site": "same-origin"})
    assert r.status_code == 200
    assert r.json() == []


def test_bad_hash_is_rejected(client):
    assert client.get("/api/vt/query/not-a-hash").status_code == 400


def test_upload_needs_a_length_and_respects_the_limit():
    assert app_module._upload_problem(None)[0] == 411
    assert app_module._upload_problem(str(app_module.MAX_UPLOAD_BYTES + 1))[0] == 413
    assert app_module._upload_problem("10") is None


def test_vt_upload_only_for_sample_files(client, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("x")
    r = client.post("/api/vt/upload", json={"file_path": str(secret)})
    assert r.status_code == 400


def test_unknown_job_is_404(client):
    assert client.get("/api/jobs/does-not-exist").status_code == 404
    assert client.delete("/api/jobs/does-not-exist").status_code == 409


def test_cleanup_needs_at_least_one_day(client):
    assert client.post("/api/jobs-cleanup", json={"days": 0}).status_code == 400


def test_report_formats(client, tmp_path, monkeypatch):
    # Setup a dummy job folder with report.md, report.html, state.json
    case_dir = tmp_path / "cases" / "test-formats"
    case_dir.mkdir(parents=True)
    (case_dir / "report.md").write_text("# Test Report", encoding="utf-8")
    (case_dir / "report.html").write_text("<h1>Test Report</h1>", encoding="utf-8")
    (case_dir / "state.json").write_text('{"id":"test-formats","status":"done"}', encoding="utf-8")
    monkeypatch.setattr(pipeline, "CASES_DIR", tmp_path / "cases")

    # md report
    r_md = client.get("/api/jobs/test-formats/report")
    assert r_md.status_code == 200
    assert "# Test Report" in r_md.text

    # html report
    r_html = client.get("/api/jobs/test-formats/report?format=html")
    assert r_html.status_code == 200
    assert "<h1>Test Report</h1>" in r_html.text
    html_csp = r_html.headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in html_csp
    assert "script-src" not in html_csp

    # json report
    r_json = client.get("/api/jobs/test-formats/report?format=json")
    assert r_json.status_code == 200
    assert r_json.json()["id"] == "test-formats"

    # iocs (csv + stix + invalid format)
    r_csv = client.get("/api/jobs/test-formats/iocs?format=csv")
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.headers["content-type"]
    assert "type,value,malicious,source,classification,context" in r_csv.text

    r_stix = client.get("/api/jobs/test-formats/iocs?format=stix")
    assert r_stix.status_code == 200
    assert r_stix.json()["type"] == "bundle"

    assert client.get("/api/jobs/test-formats/iocs?format=xml").status_code == 400


def test_screenshots_quarantine_and_endpoint(client, tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / "test-shots"
    scr_dir = case_dir / "output" / "screenshots"
    scr_dir.mkdir(parents=True)
    case_dir.mkdir(exist_ok=True)
    (case_dir / "state.json").write_text('{"id":"test-shots","status":"done"}', encoding="utf-8")
    monkeypatch.setattr(pipeline, "CASES_DIR", tmp_path / "cases")

    # Minimal valid PNG header + IHDR bytes
    valid_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 20
    (scr_dir / "scr_001.png").write_bytes(valid_png)
    # Forged non-PNG & executable inside screenshots/ MUST be quarantined
    (scr_dir / "scr_002.png").write_bytes(b"<html><script>alert(1)</script></html>")
    (scr_dir / "dropper.exe").write_bytes(b"MZ" + b"\x00" * 40)

    moved = pipeline.quarantine_output(case_dir / "output")
    assert (scr_dir / "scr_001.png").exists()
    assert not (scr_dir / "scr_002.png").exists()
    assert (scr_dir / "scr_002.png.quarantine").exists()
    assert (scr_dir / "dropper.exe.quarantine").exists()
    assert any("scr_002.png" in m for m in moved)

    st = client.get("/api/jobs/test-shots").json()
    assert st["screenshots"] == ["scr_001.png"]

    r_ok = client.get("/api/jobs/test-shots/screenshots/scr_001.png")
    assert r_ok.status_code == 200
    assert r_ok.headers["content-type"] == "image/png"
    assert r_ok.content == valid_png

    assert client.get("/api/jobs/test-shots/screenshots/scr_002.png").status_code == 404
    assert client.get("/api/jobs/test-shots/screenshots/bad.png").status_code == 404


def test_job_creation_clamps_memory_and_duration(tmp_path, monkeypatch):
    sample = tmp_path / "dummy.bat"
    sample.write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setattr(pipeline, "CASES_DIR", tmp_path / "cases")
    monkeypatch.setattr(pipeline, "run_job", lambda j: None)

    j_low = pipeline.create_job(str(sample), {"memory_mb": 128, "duration_min": -5, "run_sandbox": False})
    assert j_low.opt("memory_mb") == 1024
    assert j_low.opt("duration_min") == 1

    j_high = pipeline.create_job(str(sample), {"memory_mb": 999999, "duration_min": 500, "run_sandbox": False, "simulate_user": True})
    assert j_high.opt("memory_mb") == 65536
    assert j_high.opt("duration_min") == 180
    assert j_high.opt("simulate_user") is True


def test_intel_config_and_query_endpoints(client, tmp_path, monkeypatch):
    import intel_client
    import vt_client
    monkeypatch.setattr(vt_client, "CONFIG_PATH", tmp_path / "cfg.json")
    monkeypatch.setenv("HA_API_KEY", "")

    r_cfg = client.post("/api/intel/config", json={"mb_enabled": True, "mb_api_key": "mb123", "ha_api_key": "ha123"})
    assert r_cfg.status_code == 200
    assert r_cfg.json()["mb_enabled"] is True
    assert r_cfg.json()["mb_configured"] is True
    assert r_cfg.json()["ha_configured"] is True

    assert client.get("/api/intel/query/not-a-sha").status_code == 400
    monkeypatch.setattr(intel_client, "query_hash_intel", lambda sha: {"sha256": sha, "any_found": False, "malicious": False, "summary": ""})
    r_q = client.get("/api/intel/query/" + ("d" * 64))
    assert r_q.status_code == 200
    assert r_q.json()["sha256"] == "d" * 64


def test_compare_endpoint(client, tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "CASES_DIR", tmp_path / "cases")
    for cid in ("case-a", "case-b"):
        d = tmp_path / "cases" / cid
        d.mkdir(parents=True)
        (d / "state.json").write_text(f'{{"id":"{cid}","sample":"{cid}.exe","status":"done","verdict":{{"level":"green"}}}}', encoding="utf-8")
    assert client.get("/api/compare?base=case-a&target=case-a").status_code == 400
    assert client.get("/api/compare?base=case-a&target=missing").status_code == 404
    r = client.get("/api/compare?base=case-a&target=case-b")
    assert r.status_code == 200
    assert r.json()["base"]["id"] == "case-a" and r.json()["target"]["id"] == "case-b"


def test_context_menu_and_enqueue(client, tmp_path, monkeypatch):
    import enqueue
    import sandbox_manager
    import types

    store = {}

    class FakeKey:
        def __init__(self, sub):
            self.sub = sub
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass

    fake_winreg = types.SimpleNamespace(
        HKEY_CURRENT_USER="HKCU",
        REG_SZ=1,
        CreateKey=lambda root, sub: (store.setdefault(sub, {}), FakeKey(sub))[1],
        SetValueEx=lambda k, name, res, typ, val: store[k.sub].__setitem__(name, val),
        OpenKey=lambda root, sub: FakeKey(sub) if sub in store else (_ for _ in ()).throw(FileNotFoundError(sub)),
        DeleteKey=lambda root, sub: store.pop(sub) if sub in store else (_ for _ in ()).throw(FileNotFoundError(sub)),
    )
    monkeypatch.setitem(__import__("sys").modules, "winreg", fake_winreg)
    monkeypatch.setattr(sandbox_manager.os, "name", "nt")

    assert sandbox_manager.context_menu_status() is False
    r_on = client.post("/api/context-menu", json={"enabled": True})
    assert r_on.status_code == 200 and r_on.json()["enabled"] is True
    assert sandbox_manager.context_menu_status() is True
    cmd_val = store[r"Software\Classes\*\shell\SafeBoxAnalyze\command"][""]
    assert "enqueue.py" in cmd_val and '"%1"' in cmd_val

    r_off = client.post("/api/context-menu", json={"enabled": False})
    assert r_off.status_code == 200 and r_off.json()["enabled"] is False
    assert sandbox_manager.context_menu_status() is False

    # Test enqueue helper end-to-end with mocked server & browser opener
    sample = tmp_path / "crack.zip"
    sample.write_bytes(b"PK")
    opened = []
    seen_req = {}

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self): return b'{"id":"job-xyz"}'

    monkeypatch.setattr(enqueue, "_ensure_server", lambda *a, **k: "tok-123")
    def fake_urlopen(req, timeout=10):
        seen_req["url"] = req.full_url
        seen_req["tok"] = req.headers.get("X-safebox-token") or req.headers.get("X-SafeBox-Token")
        seen_req["body"] = __import__("json").loads(req.data.decode("utf-8"))
        return FakeResp()
    monkeypatch.setattr(enqueue.urllib.request, "urlopen", fake_urlopen)

    jid = enqueue.enqueue_path(str(sample), base_url="http://127.0.0.1:8765", opener=opened.append)
    assert jid == "job-xyz"
    assert seen_req["tok"] == "tok-123"
    assert seen_req["body"]["run_sandbox"] is False and seen_req["body"]["vt_upload"] is False
    assert opened == ["http://127.0.0.1:8765/?token=tok-123#job-xyz"]


def test_e6_intel_config_set_and_clear_and_system_status_masks(client, monkeypatch):
    import intel_client
    import vt_client
    monkeypatch.setattr(vt_client, "_user_env", lambda _n: "")
    monkeypatch.setattr(vt_client, "get_api_key", lambda: (vt_client.load_config().get("vt_api_key") or "").strip())
    for env_k in ("VT_API_KEY", "MB_API_KEY", "HA_API_KEY"):
        monkeypatch.delenv(env_k, raising=False)

    r = client.post("/api/intel/config", json={
        "vt_api_key": "vt-secret-1234",
        "mb_api_key": "mb-secret-5678",
        "ha_api_key": "ha-secret-9012",
        "mb_enabled": True,
    })
    assert r.status_code == 200
    d = r.json()
    assert d["vt_configured"] is True and d["mb_configured"] is True and d["ha_configured"] is True

    st = client.get("/api/system-status").json()
    assert st["vt_api_masked"].endswith("1234")
    assert st["mb_api_masked"].endswith("5678")
    assert st["ha_api_masked"].endswith("9012")
    assert "vt-secret" not in st["vt_api_masked"]

    r2 = client.post("/api/intel/config", json={"clear_vt": True, "clear_mb": True, "clear_ha": True, "mb_enabled": False})
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["vt_configured"] is False and d2["mb_configured"] is False and d2["ha_configured"] is False
    assert intel_client.has_configured_sources() is False


def test_e9_and_e15_job_sandbox_overrides_and_safe_file_preview(client, tmp_path, monkeypatch):
    import json
    from conftest import bare_job

    sample = tmp_path / "payload.ps1"
    sample.write_text("Write-Output 'SafeBoxPreviewToken'\nInvoke-WebRequest http://x.test", encoding="utf-8")
    job = bare_job(tmp_path / "case")
    job.input_dir.mkdir(parents=True, exist_ok=True)
    in_sample = job.input_dir / "payload.ps1"
    in_sample.write_bytes(sample.read_bytes())
    (job.input_dir / "helper.exe").write_bytes(b"MZstub")
    job.output_dir.mkdir(parents=True, exist_ok=True)
    (job.output_dir / "procmon_summary.json").write_text(json.dumps({"TotalEvents": 12, "SensitiveEvents": []}), encoding="utf-8")
    job.save()

    monkeypatch.setattr(pipeline, "get_job", lambda cid: job if cid == job.id else None)

    r_get = client.get(f"/api/jobs/{job.id}")
    assert r_get.status_code == 200
    gd = r_get.json()
    assert set(gd["runnable_targets"]) >= {"helper.exe", "payload.ps1"}
    assert gd["procmon_summary"]["TotalEvents"] == 12

    seen_overrides = {}

    def fake_start_later(j, overrides=None):
        seen_overrides["job"] = j.id
        seen_overrides["overrides"] = overrides

    monkeypatch.setattr(pipeline, "start_sandbox_later", fake_start_later)
    r_sb = client.post(f"/api/jobs/{job.id}/sandbox", json={
        "target": "payload.ps1", "network": False, "duration_min": 5, "run_as_standard_user": True,
    })
    assert r_sb.status_code == 200
    assert seen_overrides["job"] == job.id
    assert seen_overrides["overrides"]["target"] == "payload.ps1"
    assert seen_overrides["overrides"]["network"] is False
    assert seen_overrides["overrides"]["run_as_standard_user"] is True

    # E15 preview modes + path traversal rejection
    r_txt = client.get(f"/api/jobs/{job.id}/preview", params={"file_path": str(in_sample), "mode": "text"})
    assert r_txt.status_code == 200 and "SafeBoxPreviewToken" in r_txt.json()["content"]
    r_str = client.get(f"/api/jobs/{job.id}/preview", params={"file_path": str(in_sample), "mode": "strings"})
    assert r_str.status_code == 200 and "SafeBoxPreviewToken" in r_str.json()["content"]
    r_hex = client.get(f"/api/jobs/{job.id}/preview", params={"file_path": str(in_sample), "mode": "hex"})
    assert r_hex.status_code == 200 and "00000000" in r_hex.json()["content"]

    outside = tmp_path / "secret_host.txt"
    outside.write_text("TOP SECRET", encoding="utf-8")
    r_esc = client.get(f"/api/jobs/{job.id}/preview", params={"file_path": str(outside), "mode": "text"})
    assert r_esc.status_code == 400


def test_e17_yara_rules_api_crud(client, tmp_path, monkeypatch):
    import yara_scanner
    rules_tmp = tmp_path / "rules"
    rules_tmp.mkdir()
    orig = (yara_scanner.RULES_DIR / "safebox_builtin.yar").read_text(encoding="utf-8")
    (rules_tmp / "safebox_builtin.yar").write_text(orig, encoding="utf-8")
    monkeypatch.setattr(yara_scanner, "RULES_DIR", rules_tmp)
    monkeypatch.setattr(yara_scanner, "_CACHE_KEY", None)

    r_list = client.get("/api/yara/rules")
    assert r_list.status_code == 200
    assert r_list.json()["status"]["rules_count"] >= 16

    r_builtin = client.get("/api/yara/rules/safebox_builtin.yar")
    assert r_builtin.status_code == 200 and "SafeBox_Crypto_Miner_Indicators" in r_builtin.json()["content"]

    # Bad syntax -> 400
    assert client.post("/api/yara/rules", json={"name": "bad.yar", "content": "not yara"}).status_code == 400
    # Builtin overwrite -> 400
    valid = 'rule Custom_Web_Hit { strings: $x = "API_TEST_HIT" condition: $x }'
    assert client.post("/api/yara/rules", json={"name": "safebox_builtin.yar", "content": valid}).status_code == 400

    # Save & read & delete custom rule
    r_save = client.post("/api/yara/rules", json={"name": "my_custom.yar", "content": valid})
    assert r_save.status_code == 200 and r_save.json()["rules_count"] == 1
    assert client.delete("/api/yara/rules/safebox_builtin.yar").status_code == 400
    assert client.delete("/api/yara/rules/my_custom.yar").status_code == 200
    assert client.get("/api/yara/rules/my_custom.yar").status_code == 404


def test_static_frontend_strict_csp_and_css_completeness():
    import re
    from pathlib import Path
    sdir = Path(__file__).resolve().parent.parent / "static"
    css = (sdir / "styles.css").read_text(encoding="utf-8")
    norm_css = (css.replace("\\/", "/").replace("\\:", ":").replace("\\[", "[")
                   .replace("\\]", "]").replace("\\.", "."))

    html_classes = set()
    for fname in ("index.html", "auth.html", "app.js"):
        txt = (sdir / fname).read_text(encoding="utf-8")
        assert "onclick=" not in txt.lower(), f"inline onclick in {fname}"
        assert not re.search(r"\bstyle\s*=", txt, re.I), f"inline style= in {fname}"
        if fname.endswith(".html"):
            assert "<style" not in txt.lower(), f"inline <style> in {fname}"
            assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", txt, re.I), f"inline <script> in {fname}"
            for m in re.finditer(r'class="([^"]+)"', txt):
                html_classes.update(m.group(1).split())

    for cls in sorted(html_classes):
        if cls == "dark":
            continue
        pat = r"\." + re.escape(cls) + r"(?=[\s,{:\.\>\[])"
        assert re.search(pat, norm_css), f"CSS class missing from static/styles.css: {cls}"


def test_f7_intel_config_circl_tf_and_sandbox_fake_net_api(client, tmp_path, monkeypatch):
    import vt_client
    from conftest import bare_job

    monkeypatch.setattr(vt_client, "CONFIG_PATH", tmp_path / "cfg.json")
    r_cfg = client.post("/api/intel/config", json={"circl_enabled": True, "tf_enabled": True})
    assert r_cfg.status_code == 200
    assert r_cfg.json()["circl_enabled"] is True
    assert r_cfg.json()["tf_enabled"] is True

    st = client.get("/api/system-status").json()
    assert st["circl_enabled"] is True
    assert st["tf_enabled"] is True

    job = bare_job(tmp_path / "sb_fakenet")
    job.save()
    monkeypatch.setattr(pipeline, "get_job", lambda cid: job if cid == job.id else None)
    seen = {}
    monkeypatch.setattr(pipeline, "start_sandbox_later", lambda j, overrides=None: seen.update({"overrides": overrides}))
    r_sb = client.post(f"/api/jobs/{job.id}/sandbox", json={"fake_net": True, "network": False})
    assert r_sb.status_code == 200
    assert seen["overrides"]["fake_net"] is True
    assert seen["overrides"]["network"] is False

    html_txt = (pipeline.BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")
    js_txt = (pipeline.BASE_DIR / "static" / "app.js").read_text(encoding="utf-8")
    for elem_id in ("chkCirclEnabled", "chkTfEnabled", "optFakeNet", "sbModFakeNet"):
        assert elem_id in html_txt and elem_id in js_txt




# ---------------------------------------------------------------- several files / folders dropped together
def test_batch_upload_keeps_structure_and_stays_inside(client, monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "UPLOADS_DIR", tmp_path / "uploads")
    (tmp_path / "uploads").mkdir()
    batch = "a1b2c3d4e5f60718"
    r1 = client.post("/api/upload", files={"file": ("Set-up.exe", b"MZ fake")},
                     data={"batch": batch, "relpath": "Photoshop/Adobe 2026/Set-up.exe"})
    r2 = client.post("/api/upload", files={"file": ("x.md5", b"")},
                     data={"batch": batch, "relpath": "../../../../Windows/evil.md5"})
    assert r1.status_code == 200 and r2.status_code == 200, (r1.text, r2.text)
    root = tmp_path / "uploads" / f"batch_{batch}"
    assert r1.json()["batch_dir"] == str(root.resolve())
    assert (root / "Photoshop" / "Adobe 2026" / "Set-up.exe").read_bytes() == b"MZ fake"
    assert (root / "Windows" / "evil.md5").exists()            # '..' stripped: lands inside the batch folder
    assert not (tmp_path / "Windows").exists()


def test_batch_upload_rejects_bad_batch_id(client):
    r = client.post("/api/upload", files={"file": ("a.txt", b"x")}, data={"batch": "../../x", "relpath": "a.txt"})
    assert r.status_code == 400


def test_batch_total_size_limit(client, monkeypatch, tmp_path):
    monkeypatch.setattr(app_module, "UPLOADS_DIR", tmp_path / "uploads")
    (tmp_path / "uploads").mkdir()
    monkeypatch.setattr(app_module, "MAX_UPLOAD_BYTES", 1000)   # each request (~850 B incl. multipart) passes the header check
    batch = "0011223344556677"
    assert client.post("/api/upload", files={"file": ("a.bin", b"x" * 600)}, data={"batch": batch, "relpath": "a.bin"}).status_code == 200
    r = client.post("/api/upload", files={"file": ("b.bin", b"x" * 600)}, data={"batch": batch, "relpath": "b.bin"})
    assert r.status_code == 413
    assert not (tmp_path / "uploads" / f"batch_{batch}" / "b.bin").exists()


def test_live_screen_endpoint_and_focus(client, tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / "test-live"
    scr_dir = case_dir / "output" / "screenshots"
    scr_dir.mkdir(parents=True)
    (case_dir / "state.json").write_text('{"id":"test-live","status":"running"}', encoding="utf-8")
    monkeypatch.setattr(pipeline, "CASES_DIR", tmp_path / "cases")

    st = client.get("/api/jobs/test-live").json()
    assert st["has_live_screen"] is False
    assert client.get("/api/jobs/test-live/live-screen").status_code == 404

    # a forged live.png is quarantined and never served
    (scr_dir / "live.png").write_bytes(b"<script>alert(1)</script>")
    pipeline.quarantine_output(case_dir / "output")
    assert client.get("/api/jobs/test-live/live-screen").status_code == 404

    valid_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 20
    (scr_dir / "live.png").write_bytes(valid_png)
    pipeline.quarantine_output(case_dir / "output")
    assert (scr_dir / "live.png").exists()
    st = client.get("/api/jobs/test-live").json()
    assert st["has_live_screen"] is True
    assert "live.png" not in st["screenshots"]          # the live frame is not part of the gallery
    r = client.get("/api/jobs/test-live/live-screen")
    assert r.status_code == 200 and r.content == valid_png
    assert r.headers["content-type"] == "image/png"

    import sandbox_manager
    monkeypatch.setattr(sandbox_manager, "find_windows_of", lambda names: [])
    r = client.post("/api/sandbox/focus")
    assert r.status_code == 200
    assert r.json()["status"] == "not_found"
