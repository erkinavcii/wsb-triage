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

    j_high = pipeline.create_job(str(sample), {"memory_mb": 999999, "duration_min": 500, "run_sandbox": False})
    assert j_high.opt("memory_mb") == 65536
    assert j_high.opt("duration_min") == 180
