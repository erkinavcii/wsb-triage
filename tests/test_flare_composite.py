"""capa / FLOSS step (flare_tools) and the combined verdict rules. The real tools are never started here."""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

import flare_tools
import pipeline
from conftest import bare_job, wait_job, windows_only

PY = sys.executable

CAPA_RAW = {
    "meta": {"version": "10.0.0"},
    "rules": {
        "contain loop": {"meta": {"name": "contain loop", "namespace": "", "lib": True, "attack": []}, "matches": [1, 2]},
        "inject thread": {"meta": {"name": "inject thread", "namespace": "host-interaction/process/inject", "lib": False,
                                   "attack": [{"id": "T1055", "technique": "Process Injection", "tactic": "Defense Evasion"}]},
                          "matches": [[1, {}]]},
        "steal chrome login data": {"meta": {"name": "steal chrome login data", "namespace": "collection/browser",
                                             "attack": [{"id": "T1555.003", "technique": "Credentials from Web Browsers"}]}, "matches": {}},
        "execute anti-debugging instructions": {"meta": {"name": "execute anti-debugging instructions",
                                                         "namespace": "anti-analysis/anti-debugging/debugger-detection"}},
        "reference analysis tools strings": {"meta": {"name": "reference analysis tools strings", "namespace": "anti-analysis"}},
        "get geographical location": {"meta": {"name": "get geographical location", "namespace": "collection"}},
        "detect VM via registry": {"meta": {"name": "detect VM via registry", "namespace": "anti-analysis/anti-vm/vm-detection"}},
        "set registry run key": {"meta": {"name": "persist via Run registry key", "namespace": "persistence/registry/run"}},
        "plugx": {"meta": {"name": "(internal) plugx indicator", "namespace": "malware-family/plugx"}},
    },
}


def test_parse_capa_groups_and_library_rules():
    r = flare_tools.parse_capa(CAPA_RAW)
    names = {c["name"] for c in r["capabilities"]}
    assert "contain loop" not in names                       # library rule
    assert r["groups"]["inject"] == ["inject thread"]
    assert r["groups"]["credentials"] == ["steal chrome login data"]
    assert r["groups"]["evasion"] == ["detect VM via registry"]      # anti-debugging / bare anti-analysis are not
    assert r["groups"]["persistence"] == ["set registry run key"]
    assert r["groups"]["family"] == ["plugx"]
    assert "spy" not in r["groups"] and "collection" not in json.dumps(r["groups"])
    assert {a["id"] for a in r["attack"]} == {"T1055", "T1555.003"}


@pytest.mark.parametrize("bad", [None, [], "x", {"rules": "no"}, {"rules": {"a": None, "b": {"meta": "x"}}}])
def test_parse_capa_survives_odd_output(bad):
    assert flare_tools.parse_capa(bad)["capabilities"] == []


def test_parse_floss_dedup_and_short_strings():
    raw = {"strings": {"decoded_strings": [{"string": "https://evil.example/gate.php"}, {"string": "ab"}],
                       "stack_strings": [{"string": "https://evil.example/gate.php"}, {"string": "Login Data"}],
                       "tight_strings": [{"string": 5}, "bad"]}}
    r = flare_tools.parse_floss(raw)
    assert r["decoded"] == ["https://evil.example/gate.php"] and r["stack"] == ["Login Data"] and r["total"] == 2
    assert flare_tools.floss_urls(r) == ["https://evil.example/gate.php"]
    assert flare_tools.url_host("https://Evil.Example:8080/x") == "evil.example"


def test_run_tool_reads_output_and_kills_on_timeout_and_cancel(tmp_path, monkeypatch):
    monkeypatch.setattr(flare_tools, "FLARE_DIR", tmp_path)
    out = tmp_path / "o.json"
    st, err = flare_tools._run_tool([PY, "-c", "print('{\"a\": 1}')"], out, 30, lambda: False)
    assert st == "done" and json.loads(out.read_text()) == {"a": 1}
    st, err = flare_tools._run_tool([PY, "-c", "import sys; sys.stderr.write('x\\nnot a PE file'); sys.exit(2)"], out, 30, lambda: False)
    assert st == "error" and err == "not a PE file"
    t0 = time.monotonic()
    st, _ = flare_tools._run_tool([PY, "-c", "import time; time.sleep(60)"], out, 1, lambda: False)
    assert st == "timeout" and time.monotonic() - t0 < 20
    st, _ = flare_tools._run_tool([PY, "-c", "import time; time.sleep(60)"], out, 60, lambda: True)
    assert st == "cancelled"


@windows_only
def test_timeout_kills_the_child_process_too(tmp_path, monkeypatch):
    """capa / FLOSS are PyInstaller one-file builds whose real work runs in a child process."""
    monkeypatch.setattr(flare_tools, "FLARE_DIR", tmp_path)
    pid_file = tmp_path / "child.pid"
    parent = ("import subprocess, sys, time; c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
              f"open(r'{pid_file}', 'w').write(str(c.pid)); time.sleep(120)")
    st, _ = flare_tools._run_tool([PY, "-c", parent], tmp_path / "o.json", 3, lambda: False)
    assert st == "timeout"
    child = pid_file.read_text().strip()
    time.sleep(0.5)
    out = subprocess.run(["tasklist", "/FI", f"PID eq {child}", "/NH"], capture_output=True, text=True).stdout
    assert child not in out


def test_tools_must_match_pinned_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(flare_tools, "FLARE_DIR", tmp_path)
    (tmp_path / "capa.exe").write_bytes(b"not capa")
    assert flare_tools.capa_available() is False
    assert flare_tools.floss_available() is False                    # missing


def test_analyze_files_budget_and_size_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(flare_tools, "capa_available", lambda: True)
    monkeypatch.setattr(flare_tools, "floss_available", lambda: True)
    calls = []
    monkeypatch.setattr(flare_tools, "run_capa", lambda p, w, t, s, timeout: calls.append(("capa", p)) or {"status": "done", "groups": {}})
    monkeypatch.setattr(flare_tools, "run_floss", lambda p, w, t, s, timeout: calls.append(("floss", p)) or {"status": "done"})
    items = [{"label": "a", "path": "a.exe", "size": 1000},
             {"label": "big", "path": "big.exe", "size": flare_tools.FLOSS_MAX_BYTES + 1}]
    res = flare_tools.analyze_files(items, tmp_path / "w", lambda: False, 60)
    assert res[0]["capa"]["status"] == "done" and res[0]["floss"]["status"] == "done"
    assert res[1]["capa"]["status"] == "done" and res[1]["floss"]["status"] == "skipped"
    assert ("floss", "big.exe") not in calls
    res = flare_tools.analyze_files(items[:1], tmp_path / "w", lambda: False, -1)       # budget already spent
    assert res[0]["capa"]["status"] == "skipped"


# ---------------------------------------------------------------- verdict: capa / FLOSS findings

def _flare(job, files):
    job.state["flare"] = {"status": "done", "files": files}


def test_capa_groups_are_notes_family_is_red(tmp_path):
    job = bare_job(tmp_path)
    _flare(job, [{"label": "x.exe", "capa": {"status": "done", **flare_tools.parse_capa(CAPA_RAW)}}])
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert any(r.startswith("capa zararlı ailesi kuralı: 'x.exe'") for r in v["red"])
    note = next(n for n in v["notes"] if n.startswith("capa yetenekleri: 'x.exe'"))
    assert "Süreç enjeksiyonu" in note and "tek başına" in note.lower()
    assert any(t["id"] == "T1055" for t in v["attack"])


def test_capa_without_family_does_not_turn_red(tmp_path):
    job = bare_job(tmp_path)
    raw = json.loads(json.dumps(CAPA_RAW))
    del raw["rules"]["plugx"]
    _flare(job, [{"label": "x.exe", "capa": {"status": "done", **flare_tools.parse_capa(raw)}}])
    pipeline.compute_verdict(job)
    assert not job.state["verdict"]["red"]


def test_floss_hidden_c2_string_is_red_and_noise_urls_are_dropped(tmp_path):
    job = bare_job(tmp_path)
    floss = {"status": "done", "decoded": ["https://api.telegram.org/bot123:abc/sendMessage", "http://www.microsoft.com/pki"],
             "stack": [], "tight": [], "total": 2}
    pipeline._floss_extras(floss)
    _flare(job, [{"label": "x.exe", "floss": floss}])
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert any(r.startswith("FLOSS: 'x.exe'") and "C2" in r for r in v["red"])
    addr = next(n for n in v["notes"] if "gizlenmiş adresler" in n)
    assert "api.telegram.org" in addr and "microsoft.com" not in addr


def test_tool_timeouts_are_coverage_not_findings(tmp_path):
    job = bare_job(tmp_path)
    _flare(job, [{"label": "x.exe", "capa": {"status": "timeout", "error": ""}, "floss": {"status": "skipped", "error": "süre sınırı"}}])
    job.state["flare"]["too_big"] = ["big.exe"]
    job.state["status"] = "done"
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert not any("capa" in n or "FLOSS" in n for n in v["notes"])            # coverage, not a finding
    assert not any("capa" in r or "FLOSS" in r for r in v["red"])
    pipeline.write_report(job)
    report = (job.case_dir / "report.md").read_text(encoding="utf-8")
    assert "big.exe" in report and "capa: timeout" in report


def test_candidates_leave_out_signed_and_too_large_programs(tmp_path):
    small, big = tmp_path / "a.exe", tmp_path / "b.exe"
    small.write_bytes(b"MZ")
    big.write_bytes(b"MZ")
    st = lambda p, sig, size, risk: {"rel": p.name, "file_path": str(p), "file_size": size, "risk_score": risk,  # noqa: E731
                                     "pe_info": {"is_pe": True}, "signature": {"status": sig}}
    too_big = []
    c = pipeline._flare_candidates([st(big, "NotSigned", flare_tools.CAPA_MAX_BYTES + 1, 90), st(small, "Valid", 10, 80),
                                    st(small, "HashMismatch", 10, 70)], 4, too_big)
    assert [x["label"] for x in c] == ["a.exe"] and too_big == ["b.exe"]


# ---------------------------------------------------------------- combined rules

def _beh(**kw):
    b = {"Target": "x.exe", "Processes": [], "Network": {"Connections": []}, "Files": {"NewCount": 0, "NewExecutables": [],
         "DroppedHashes": []}, "Persistence": {}, "HoneyfileAlerts": []}
    b.update(kw)
    return pipeline.sanitize_sandbox_json(json.loads(json.dumps(b)))


def _composite(job):
    pipeline.compute_verdict(job)
    return {c["id"]: c for c in job.state["verdict"].get("composite") or []}


def _proc(pid, ppid, name, path="", cmd="", tree=True):
    return {"Pid": pid, "Ppid": ppid, "Name": name, "Path": path, "CommandLine": cmd or path, "InTree": tree, "FirstSeen": "10:00:00"}


DROP = r"C:\Users\WDAGUtilityAccount\AppData\Roaming\upd\svc.exe"


def test_credential_theft_needs_access_and_sending(tmp_path):
    job = bare_job(tmp_path)
    job.state["behavior"] = _beh(HoneyfileAlerts=[r"Login Data read by x.exe (Modified)"])
    assert "credential_theft" not in _composite(job)                 # access alone
    job.state["network"] = {"dns": [{"name": "gate.evil.example", "class": pipeline.CLASS_UNKNOWN, "from_sample": True, "count": 1}],
                            "sni": [], "http": []}
    c = _composite(job)
    assert c["credential_theft"]["level"] == "red"
    v = job.state["verdict"]
    assert any(r.startswith("Birleşik kural — Bilgi çalma zinciri") for r in v["red"])
    assert {"T1555", "T1041"} <= {t["id"] for t in v["attack"]}


def test_static_credential_strings_need_strong_sending(tmp_path):
    job = bare_job(tmp_path)
    job.state["static"] = [{"rel": "x.exe", "signature": {"status": "NotSigned"}, "risk_score": 40,
                            "string_findings": [{"category": "Infostealer (Tarayıcı/Cüzdan Hırsızı)", "severity": "critical", "distinct": 4}]}]
    job.state["behavior"] = _beh()
    job.state["network"] = {"dns": [{"name": "update.vendor.example", "class": pipeline.CLASS_UNKNOWN, "from_sample": True}], "sni": [], "http": []}
    assert "credential_theft" not in _composite(job)                 # unknown address is not enough for strings
    job.state["network"]["dns"].append({"name": "api.telegram.org", "class": pipeline.CLASS_ABUSED, "from_sample": True})
    assert _composite(job)["credential_theft"]["level"] == "red"


def test_dropper_rule(tmp_path):
    job = bare_job(tmp_path)
    files = {"NewCount": 3, "NewExecutables": [DROP], "DroppedHashes": [{"Path": DROP, "SigStatus": "NotSigned"}]}
    job.state["behavior"] = _beh(Files=files, Processes=[_proc(10, 1, "x.exe"), _proc(11, 10, "svc.exe", DROP)])
    assert _composite(job)["dropped_exec"]["level"] == "note"        # no network: note only
    job.state["behavior"] = _beh(Files=files, Processes=[_proc(10, 1, "x.exe"), _proc(11, 10, "svc.exe", DROP)],
                                 Network={"Connections": [{"Remote": "203.0.113.5", "Port": 443, "Pid": 10, "FromSample": True}]})
    assert _composite(job)["dropper"]["level"] == "red"
    files["DroppedHashes"][0]["SigStatus"] = "Valid"                 # a signed helper the installer unpacked
    job.state["behavior"] = _beh(Files=files, Processes=[_proc(11, 10, "svc.exe", DROP)],
                                 Network={"Connections": [{"Remote": "203.0.113.5", "Port": 443, "Pid": 10, "FromSample": True}]})
    c = _composite(job)
    assert "dropper" not in c and "dropped_exec" not in c


def test_autostart_of_dropped_program(tmp_path):
    job = bare_job(tmp_path)
    files = {"NewCount": 1, "NewExecutables": [DROP], "DroppedHashes": [{"Path": DROP, "SigStatus": "NotSigned"}]}
    job.state["behavior"] = _beh(Files=files, Persistence={"RunKeys": [rf"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run :: upd = {DROP}"]})
    assert _composite(job)["dropped_persistence"]["level"] == "red"
    job.state["behavior"] = _beh(Files=files, Persistence={"RunKeys": [r"HKLM:\...\Run :: Adobe CCXProcess = C:\Program Files (x86)\Adobe\CCXProcess.exe"]})
    assert "dropped_persistence" not in _composite(job)
    job.state["behavior"] = _beh(Persistence={"Tasks": [r"\Updater | C:\Users\Public\a.vbs"]})
    assert "dropped_persistence" in _composite(job)                  # anything autostarting from Users\Public


def test_dotnet_tool_injection(tmp_path):
    job = bare_job(tmp_path)
    regasm = r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe"
    conns = {"Connections": [{"Remote": "198.51.100.7", "Port": 8080, "Pid": 21, "Process": "RegAsm", "FromSample": True}]}
    job.state["behavior"] = _beh(Processes=[_proc(20, 1, "x.exe"), _proc(21, 20, "RegAsm.exe", regasm, f'"{regasm}"')], Network=conns)
    assert _composite(job)["dotnet_injection"]["level"] == "red"
    job.state["behavior"] = _beh(Processes=[_proc(20, 1, "x.exe"), _proc(21, 20, "RegAsm.exe", regasm, f'"{regasm}" C:\\app\\plugin.dll /codebase')],
                                 Network=conns)
    assert "dotnet_injection" not in _composite(job)                 # installer registering a COM DLL
    job.state["behavior"] = _beh(Processes=[_proc(20, 1, "x.exe"), _proc(21, 20, "RegAsm.exe", regasm, f'"{regasm}"')])
    assert "dotnet_injection" not in _composite(job)                 # started, but no other evidence


def test_quiet_sample_with_evasion_ability(tmp_path):
    job = bare_job(tmp_path)
    _flare(job, [{"label": "x.exe", "capa": {"status": "done", "groups": {"evasion": ["detect VM via registry"]}}}])
    job.state["behavior"] = _beh(Processes=[_proc(30, 1, "x.exe")])
    c = _composite(job)
    assert c["sandbox_evasion"]["level"] == "note"
    assert any(t["id"] == "T1497" for t in job.state["verdict"]["attack"])
    job.state["behavior"] = _beh(Processes=[_proc(30, 1, "x.exe"), _proc(31, 30, "cmd.exe"), _proc(32, 31, "a.exe")])
    assert "sandbox_evasion" not in _composite(job)                  # it did run things


def test_hidden_address_contacted(tmp_path):
    job = bare_job(tmp_path)
    floss = {"status": "done", "decoded": ["http://c2.evil.example/panel/gate.php"], "stack": [], "tight": [], "total": 1}
    pipeline._floss_extras(floss)
    _flare(job, [{"label": "x.exe", "floss": floss}])
    job.state["behavior"] = _beh()
    assert "hidden_address" not in _composite(job)
    job.state["network"] = {"dns": [{"name": "c2.evil.example", "class": pipeline.CLASS_UNKNOWN}], "sni": [], "http": []}
    assert _composite(job)["hidden_address"]["level"] == "red"


def test_ransomware_pattern(tmp_path):
    job = bare_job(tmp_path)
    honey = [r"C:\Users\x\Documents\passwords.docx MODIFIED", r"C:\Users\x\Desktop\wallet.txt DELETED"]
    job.state["behavior"] = _beh(HoneyfileAlerts=honey)
    assert "ransomware" not in _composite(job)
    job.state["behavior"] = _beh(HoneyfileAlerts=honey, Processes=[_proc(40, 1, "vssadmin.exe", cmd="vssadmin delete shadows /all /quiet")])
    assert _composite(job)["ransomware"]["level"] == "red"


def test_composite_rules_survive_hostile_process_fields(tmp_path):
    job = bare_job(tmp_path)
    job.state["behavior"] = _beh(Processes=[{"Pid": [1], "Ppid": {"a": 1}, "Name": ["RegAsm.exe"], "Path": None, "InTree": "yes"},
                                            {"Pid": 5, "Ppid": [1], "Name": "regasm.exe", "InTree": True, "CommandLine": 7}],
                                 Network={"Connections": [{"Pid": [5], "FromSample": True}]})
    pipeline.compute_verdict(job)
    assert job.state["verdict"]["level"] in ("yellow", "red", "green", "pending")
    assert pipeline._proc_tree_lines(job.state["behavior"]["Processes"])


def test_process_tree_lines_nest_children_and_handle_pid_reuse():
    procs = [_proc(1, 0, "setup.exe"), _proc(2, 1, "cmd.exe"), _proc(3, 2, "powershell.exe"), _proc(4, 1, "helper.exe"),
             _proc(2, 99, "later-reuse.exe"), _proc(7, 7, "self-parent.exe")]
    lines = pipeline._proc_tree_lines(procs)
    assert lines[0].startswith("- setup.exe (1)")
    assert "  - cmd.exe (2)" in lines[1] and lines[2].startswith("    - powershell.exe (3)")
    assert any(line.startswith("  - helper.exe (4)") for line in lines)
    assert any(line.startswith("- later-reuse.exe (2)") for line in lines)
    assert any(line.startswith("- self-parent.exe (7)") for line in lines)
    assert len(lines) == len(procs)


# ---------------------------------------------------------------- pipeline integration

@windows_only
def test_job_runs_flare_on_unsigned_programs(tmp_path, monkeypatch, run_job, unsigned_exe):
    monkeypatch.setattr(pipeline, "flare_available", lambda: True)
    seen = []

    def fake(items, work, should_stop, budget, progress=None, workers=2):
        seen.extend(items)
        return [{"label": it["label"], "path": it["path"],
                 "capa": {"status": "done", "capabilities": [], "groups": {"inject": ["inject thread"]}, "attack": []},
                 "floss": {"status": "done", "decoded": ["https://api.telegram.org/bot1:a/sendMessage"], "stack": [], "tight": [], "total": 1}}
                for it in items]
    monkeypatch.setattr(flare_tools, "analyze_files", fake)
    d = tmp_path / "pkg"
    d.mkdir()
    unsigned_exe(d / "tool.exe")
    job = run_job(d)
    assert [Path(x["path"]).name for x in seen] == ["tool.exe"]
    fl = job.state["flare"]
    assert fl["status"] == "done" and fl["files"][0]["floss"]["findings"]
    v = job.state["verdict"]
    assert any(r.startswith("FLOSS: ") for r in v["red"])
    assert any(n.startswith("capa yetenekleri: ") for n in v["notes"])
    report = (job.case_dir / "report.md").read_text(encoding="utf-8")
    assert "## Yetenekler ve gizlenmiş metinler" in report


@windows_only
def test_job_without_flare_tools_says_so(tmp_path, run_job, unsigned_exe):
    d = tmp_path / "pkg"
    d.mkdir()
    unsigned_exe(d / "tool.exe")
    job = run_job(d)
    assert job.state["flare"]["status"] == "unavailable"
