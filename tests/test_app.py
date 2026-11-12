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
    assert "/static/tailwind.js" in r.text
    assert "Content-Security-Policy" in r.headers
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert app_module.API_TOKEN in r.text


def test_api_token_protection(client):
    # Post without token -> 401
    bad_client = TestClient(app_module.app, base_url=BASE)
    r = bad_client.post("/api/watch", json={"enabled": False})
    assert r.status_code == 401
    assert "API belirteci" in r.text

    # Post with invalid token -> 401
    r = bad_client.post("/api/watch", json={"enabled": False}, headers={"X-SafeBox-Token": "wrong-token"})
    assert r.status_code == 401

    # Post with valid token in header -> passes auth
    r = bad_client.post("/api/watch", json={"enabled": False}, headers={"X-SafeBox-Token": app_module.API_TOKEN})
    assert r.status_code == 200


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

    # json report
    r_json = client.get("/api/jobs/test-formats/report?format=json")
    assert r_json.status_code == 200
    assert r_json.json()["id"] == "test-formats"
