"""Local panel API: host/origin checks, upload limits, input validation."""
import pytest
from fastapi.testclient import TestClient

import app as app_module

BASE = f"http://127.0.0.1:{app_module.PORT}"


@pytest.fixture
def client():
    return TestClient(app_module.app, base_url=BASE)


def test_index_is_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "<html" in r.text.lower()
    assert "/static/tailwind.js" in r.text
    assert "Content-Security-Policy" in r.headers
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


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
