"""mitmproxy addon used INSIDE the sandbox (mitmdump -s https_logger.py, local capture mode).

Writes one JSON line per decrypted HTTP(S) exchange to SAFEBOX_HTTPS_LOG (C:\\Analysis\\output\\https_log.jsonl):
method, URL, status, sizes and a short preview of what was SENT (the part that shows data theft). Response bodies
are not kept. Connections whose TLS could not be intercepted (certificate pinning) are logged as tls_failed.
The host treats this file as untrusted data, like behavior.json.
"""
import json
import os
import time

OUT = os.environ.get("SAFEBOX_HTTPS_LOG") or r"C:\Analysis\output\https_log.jsonl"
MAX_LINES = 5000
MAX_PREVIEW = 1024
_count = 0


def _write(rec):
    global _count
    if _count >= MAX_LINES:
        return
    _count += 1
    try:
        with open(OUT, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _preview(data):
    if not data:
        return ""
    return data[:MAX_PREVIEW].decode("utf-8", "replace")


def _log(flow):
    req, resp = flow.request, flow.response
    try:
        body = req.get_content(strict=False) or b""
    except Exception:  # noqa: BLE001 - unknown encodings: keep the raw bytes
        body = req.raw_content or b""
    _write({
        "t": time.strftime("%H:%M:%S"),
        "method": req.method,
        "url": req.pretty_url[:600],
        "host": req.pretty_host[:200],
        "scheme": req.scheme,
        "status": resp.status_code if resp else None,
        "req_bytes": len(body),
        "req_type": req.headers.get("content-type", "")[:100],
        "req_preview": _preview(body),
        "resp_bytes": len(resp.raw_content or b"") if resp else 0,
        "resp_type": resp.headers.get("content-type", "")[:100] if resp else "",
        "ua": req.headers.get("user-agent", "")[:200],
        "error": str(flow.error)[:200] if flow.error else "",
    })


def response(flow):
    _log(flow)


def error(flow):
    _log(flow)


def tls_failed_client(data):
    try:
        _write({"t": time.strftime("%H:%M:%S"), "tls_failed": True,
                "host": (data.context.client.sni or "")[:200], "error": str(data.conn.error)[:200]})
    except Exception:  # noqa: BLE001
        pass
