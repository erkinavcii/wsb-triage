# SafeBox / wsb-triage

> **Automated Windows Sandbox Malware Analysis & Triage Pipeline**

[Türkçe dökümantasyon için buraya bakın (README.tr.md)](README.tr.md)

SafeBox is a lightweight, local web-based triage and malware analysis workbench for Windows. It provides end-to-end automated and interactive behavioral analysis using disposable Windows Sandbox environments, complete with network packet capture, process/registry tracing, static PE inspection, and VirusTotal enrichment.

![SafeBox Web Interface](static/screenshot.png)

---

## Key Features

- **Isolated One-Click Windows Sandbox Analysis:**
  - Automated `.wsb` provisioning with strictly hardened configurations (vGPU, clipboard, audio, printer, and camera redirections disabled).
  - Samples and tools mapped strictly **Read-Only** (`C:\Analysis\input`, `C:\Analysis\tools`); only output is writable (`C:\Analysis\output`).
  - Configurable sandbox RAM allocation (2 GB up to 16 GB).
  - Automated LAN blocking firewall inside the sandbox: keeps internet access active for C2 observation while protecting local home/office subnets and host endpoints.
- **Deep Live Behavioral Monitoring:**
  - Background network packet capture (`pktmon` / `.pcapng`).
  - Process creation tree (`Win32_ProcessStartTrace`), command-line tracing, and suspicious parameter flags (hidden/encoded PowerShell, bypasses).
  - Persistence inspection (Services, Device Drivers, Scheduled Tasks, Run/RunOnce keys, Startup folder, IFEO).
  - Tamper detection: Windows Defender alterations, `hosts` file modifications, and firewall rule additions.
- **Secondary Dropper & Payload Detection:**
  - Automatically indexes newly dropped executables inside the sandbox, calculates their SHA-256 hashes, and queries VirusTotal without uploading the files outside.
- **Static PE & Heuristic Triage:**
  - Authenticode digital signature validation (valid, broken/mismatched, or unsigned).
  - PE header entropy analysis, section anomalies, and anti-analysis/hollowing API combination heuristics.
  - Infostealer, C2, and token-grabber regex pattern matching.
- **Network Traffic Summaries:**
  - Automated `tshark` dissection: DNS queries, TLS Server Name Indication (SNI), and HTTP endpoints with categorization (Microsoft background noise, Shared Cloud/CDN, Abused infrastructure, or Unknown).
- **Comprehensive Reporting:**
  - Generates structured Markdown (`report.md`), clean standalone HTML (`report.html`), and machine-readable JSON (`state.json`).
- **Download Folder Watcher:**
  - Real-time watcher for browser downloads with baseline diffing, stable-size debouncing, and automated triage.
- **Hardened Local Security:**
  - Bound strictly to `127.0.0.1`, DNS rebinding protection, CSRF prevention (`Sec-Fetch-Site` & `Origin`), strict Content-Security-Policy (`script-src 'self'; style-src 'self'`), and startup secret API token validation (`X-SafeBox-Token` / `HttpOnly` cookie) across all `/api/*` endpoints.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |       SafeBox Host Web UI (8765)      |
                      |    FastAPI + Static CSS + Strict CSP  |
                      +-------------------+-------------------+
                                          |
                        +-----------------+-----------------+
                        |                                   |
              [Static & VT Stage]                [Windows Sandbox Stage]
                        |                                   |
            - 7-Zip safe unpack               - Provision hardened .wsb
            - Authenticode check              - Map input/tools (read-only)
            - Static PE / strings             - In-sandbox monitor script
            - VirusTotal API lookup           - pktmon / pcapng network capture
                        |                     - Live process & persistence diff
                        +-----------------+-----------------+
                                          |
                                [Comprehensive Report]
                           (Markdown, HTML & State JSON)
```

---

## Prerequisites

1. **Windows 10 / 11 Pro, Enterprise, or Education** (with Windows Sandbox enabled).
   - *Can be enabled directly from the UI panel or via PowerShell:*
     ```powershell
     Enable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -All
     ```
2. **Python 3.10+**
3. **7-Zip (25.01+)** installed for archive decompression: [7-zip.org](https://www.7-zip.org)
4. *(Recommended)* **Wireshark / tshark** for network capture dissection: [wireshark.org](https://www.wireshark.org)
5. *(Optional)* **Sysinternals Procmon64.exe** placed in `sandbox/` directory for full event logging.

---

## Installation & Quick Start

1. Clone the repository:
   ```cmd
   git clone https://github.com/erkinavcii/wsb-triage.git
   cd wsb-triage
   ```

2. Install dependencies:
   ```cmd
   pip install -r requirements.txt
   ```

3. Launch SafeBox:
   - Double-click **`Baslat.bat`** (automatically handles the session token and opens the browser), or run:
     ```cmd
     python app.py
     ```
   - Open the printed authenticated URL (`http://127.0.0.1:8765/?token=...`) or paste the session token shown in console (`%LOCALAPPDATA%\SafeBox\session.token`) into the browser prompt.

---

## Running Automated Tests

SafeBox includes a complete test suite covering archive decompression, VirusTotal throttling and streaming, sanitization, domain classification, and job lifecycle:

```cmd
pip install -r requirements-dev.txt
pytest
```

---

## Security Model & Guidelines

- **Untrusted Sandbox Output:** Files generated inside `cases/<case_id>/output/` during execution are treated as untrusted. Non-standard files are quarantined (`.quarantine` with `ZoneId=3`).
- **Privacy First:** Automatic watcher analyses never upload unknown binaries to VirusTotal; only SHA-256 hash lookups are performed.
- **Safety Disclaimer:** SafeBox assists in identifying malicious patterns and behaviors. A clean verdict significantly reduces risk but does not guarantee an executable is completely benign.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
