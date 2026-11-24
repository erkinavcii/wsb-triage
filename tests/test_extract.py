"""Archive handling: multi-part detection (A3) and unpack size limits (A8)."""
import shutil
import subprocess
import zipfile

import pytest

import pipeline
import sandbox_manager as sbm
from conftest import SYSTEM32, bare_job, windows_only

VOLUMES = {
    "a.part1.rar": False, "a.part01.rar": False, "a.part001.rar": False, "a.part2.rar": True, "a.part10.rar": True,
    "a.rar": False, "a.r00": True, "a.r12": True, "a.001": False, "a.002": True, "a.010": True,
    "setup.2024": False, "app-1.2.10": False, "photo.7z": False, "x.exe": False, "A.PART02.RAR": True,
}


@pytest.mark.parametrize("name,later", VOLUMES.items())
def test_is_later_volume(name, later):
    assert pipeline.is_later_volume(name) is later


def test_manual_later_volume_is_refused(tmp_path, run_job):
    part = tmp_path / "Program.part2.rar"
    part.write_bytes(b"Rar!")
    job = run_job(part)
    assert job.state["status"] == "error"
    assert "ara parçası" in job.state["stages"]["extract"]["msg"]


def test_archive_set_size_sums_all_volumes(tmp_path):
    for i, size in ((1, 100), (2, 50), (3, 25)):
        (tmp_path / f"big.part{i}.rar").write_bytes(b"x" * size)
    (tmp_path / "other.part1.rar").write_bytes(b"x" * 999)
    assert pipeline._archive_set_size(tmp_path / "big.part1.rar") == 175
    (tmp_path / "s.001").write_bytes(b"x" * 10)
    (tmp_path / "s.002").write_bytes(b"x" * 5)
    assert pipeline._archive_set_size(tmp_path / "s.001") == 15


def test_zip_bomb_ratio_is_refused(tmp_path):
    job = bare_job(tmp_path)
    small = tmp_path / "bomb.zip"
    small.write_bytes(b"x" * 1024 * 1024)                         # 1 MB that claims to unpack to 2 GB
    with pytest.raises(pipeline.PipelineError, match="zip bombası"):
        pipeline._check_unpacked_size(job, 2 * 1024 ** 3, small)


def test_unpack_larger_than_free_space_is_refused(tmp_path, monkeypatch):
    job = bare_job(tmp_path)
    arc = tmp_path / "big.7z"
    arc.write_bytes(b"x" * 4 * 1024 * 1024)                       # 4 MB -> 2 GB is 512x: not a bomb, just big

    class Usage:
        free = 3 * 1024 ** 3
    monkeypatch.setattr(pipeline.shutil, "disk_usage", lambda p: Usage)
    with pytest.raises(pipeline.PipelineError, match="boş alan"):
        pipeline._check_unpacked_size(job, 2 * 1024 ** 3, arc)    # 2 GB + 2 GB reserve > 3 GB free
    pipeline._check_unpacked_size(job, 500 * 1024 ** 2, arc)       # fits


def test_normal_zip_is_extracted(tmp_path, run_job):
    z = tmp_path / "ok.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("readme.txt", "hi")
        zf.writestr("sub/tool.bat", "@echo off")
    job = run_job(z)
    assert job.state["stages"]["extract"]["status"] == "done"
    assert job.state["inventory"]["files"] == 2


def test_zip_without_7zip_rejects_path_escape(tmp_path, run_job, monkeypatch):
    monkeypatch.setattr(sbm, "seven_zip_path", lambda: "")
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("ok.txt", "x")
        zf.writestr("../../escape.txt", "x")
    job = run_job(z)
    assert job.state["status"] == "error"
    assert "klasör dışına" in job.state["stages"]["extract"]["msg"]
    assert not (job.case_dir.parent / "escape.txt").exists()


def test_zip_without_7zip_still_works(tmp_path, run_job, monkeypatch):
    monkeypatch.setattr(sbm, "seven_zip_path", lambda: "")
    z = tmp_path / "plain.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("ok.txt", "x")
    job = run_job(z)
    assert job.state["stages"]["extract"]["status"] == "done"


def test_broad_folder_is_refused(run_job, tmp_path):
    from pathlib import Path
    job = run_job(Path.home())
    assert job.state["status"] == "error"
    assert "çok geniş" in job.state["stages"]["extract"]["msg"]


@pytest.mark.skipif(not sbm.seven_zip_path(), reason="7-Zip not installed")
def test_archive_password_is_never_persisted(tmp_path, run_job):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("x")
    arc = tmp_path / "secret.7z"
    subprocess.run([sbm.seven_zip_path(), "a", "-pGizliSifre99", "-mhe=on", str(arc), str(src / "*")],
                   capture_output=True, check=True)
    job = run_job(arc, password="GizliSifre99")
    assert job.state["stages"]["extract"]["status"] == "done"
    on_disk = (job.case_dir / "state.json").read_text(encoding="utf-8")
    assert "GizliSifre99" not in on_disk
    assert "GizliSifre99" not in str(job.snapshot())
    assert job.state["options"]["has_password"] is True


@pytest.mark.skipif(not sbm.seven_zip_path(), reason="7-Zip not installed")
def test_wrong_archive_password_is_reported(tmp_path, run_job):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("x")
    arc = tmp_path / "secret.7z"
    subprocess.run([sbm.seven_zip_path(), "a", "-pRight", "-mhe=on", str(arc), str(src / "*")], capture_output=True, check=True)
    job = run_job(arc, password="Wrong")
    assert job.state["status"] == "error"
    assert "şifre" in job.state["stages"]["extract"]["msg"].lower()


@windows_only
@pytest.mark.skipif(not sbm.seven_zip_path(), reason="7-Zip not installed")
def test_sfx_installer_is_unpacked_for_static_and_inventory(tmp_path, run_job, unsigned_exe):
    sz = sbm.seven_zip_path()
    # Create an inner suspicious DLL wrapped inside an EXE overlay (simulates SFX / NSIS installer)
    inner_dir = tmp_path / "inner"
    inner_dir.mkdir()
    unsigned_exe(inner_dir / "amtlib.dll")
    payload_zip = tmp_path / "payload.zip"
    subprocess.run([sz, "a", str(payload_zip), str(inner_dir / "amtlib.dll")], capture_output=True, check=True)

    sfx_exe = tmp_path / "setup_sfx.exe"
    sfx_exe.write_bytes((SYSTEM32 / "whoami.exe").read_bytes() + payload_zip.read_bytes())

    job = run_job(sfx_exe)
    assert job.state["stages"]["extract"]["status"] == "done"
    assert "kurulum içi" in job.state["stages"]["extract"]["msg"]
    # Input folder still has only the single setup executable for Sandbox execution
    input_files = [p.name for p in job.input_dir.rglob("*") if p.is_file()]
    assert input_files == ["setup_sfx.exe"]
    # Inventory & static analysis include the unpacked inner DLL
    rels = [r["rel"] for r in job.state["static"]]
    assert any("[paket içi]" in r and r.endswith("amtlib.dll") for r in rels)


@windows_only
@pytest.mark.skipif(not sbm.seven_zip_path(), reason="7-Zip not installed")
def test_plain_pe_is_not_unpacked_as_installer(tmp_path, run_job):
    plain = tmp_path / "plain_tool.exe"
    shutil.copy2(SYSTEM32 / "whoami.exe", plain)
    job = run_job(plain)
    assert job.state["stages"]["extract"]["status"] == "done"
    assert not job.unpacked_dir.exists()
    assert job.state["inventory"]["files"] == 1


def test_unpack_asar_extracts_safe_files_and_blocks_traversal(tmp_path):
    import json
    import struct
    good_bytes = b"console.log('hello electron');"
    evil_bytes = b"evil!"
    manifest = {
        "files": {
            "app": {"files": {"main.js": {"offset": "0", "size": len(good_bytes)}}},
            "..": {"files": {"..": {"files": {"evil.js": {"offset": str(len(good_bytes)), "size": len(evil_bytes)}}}}},
        }
    }
    mbytes = json.dumps(manifest).encode("utf-8")
    hdr = struct.pack("<IIII", 4, 8 + len(mbytes), 4 + len(mbytes), len(mbytes))
    asar = tmp_path / "app.asar"
    asar.write_bytes(hdr + mbytes + good_bytes + evil_bytes)

    dest = tmp_path / "out"
    count = pipeline._unpack_asar(asar, dest)
    assert count == 1
    assert (dest / "app" / "main.js").read_bytes() == good_bytes
    assert not (tmp_path / "evil.js").exists()


def test_analyzer_scan_path_blocks_zip_slip(tmp_path):
    import analyzer
    bad_zip = tmp_path / "slip.zip"
    with zipfile.ZipFile(bad_zip, "w") as zf:
        zf.writestr("../../outside.exe", b"MZ")
    with pytest.raises(ValueError, match="güvenli olmayan yol"):
        analyzer.scan_path(str(bad_zip))


def test_folder_with_small_nested_archive_unpacks_to_unpacked_dir_only(tmp_path, run_job):
    pkg = tmp_path / "InstallFolder"
    pkg.mkdir()
    (pkg / "readme.txt").write_text("info", encoding="utf-8")
    nested = pkg / "AdobeUnlicensedPopupBlocker.zip"
    with zipfile.ZipFile(nested, "w") as zf:
        zf.writestr("blocker/RunOnce.cmd", "@echo off\nsc stop AGMService\n")
        zf.writestr("blocker/install.pimx", "<Installer/>")

    before_names = sorted(p.name for p in pkg.iterdir())
    job = run_job(pkg)
    assert job.state["stages"]["extract"]["status"] == "done"
    # Never write inside the user's source folder
    assert sorted(p.name for p in pkg.iterdir()) == before_names
    assert job.unpacked_dir.is_dir()
    extracted_names = {p.name for p in job.unpacked_dir.rglob("*") if p.is_file()}
    assert "RunOnce.cmd" in extracted_names
    assert "install.pimx" in extracted_names


def test_large_nested_archive_selective_unpack_and_scoring(tmp_path, run_job, unsigned_exe):
    pkg = tmp_path / "PhotoshopFolder"
    pkg.mkdir()
    # Build a > 32 MB ZIP (ZIP_STORED) simulating a large ISO/Core archive with junk assets + high-signal payloads
    big_zip = pkg / "AdobePhotoshop27-Core_x64.zip"
    ps_exe = tmp_path / "Photoshop.exe"
    unsigned_exe(ps_exe)
    with zipfile.ZipFile(big_zip, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("Adobe/CameraRawProfile/CameraRawProfile.dat", b"\x00" * (33 * 1024 * 1024))
        zf.writestr("Adobe/Photoshop.exe", ps_exe.read_bytes())
        zf.writestr("Adobe/RunOnce.cmd", "@echo off\nsc delete AGSService\n")
        zf.writestr("Adobe/Patch_Photoshop.exe_.log", "Patching amtlib.dll")
        zf.writestr("Adobe/setup.pimx", "<pimx/>")
        zf.writestr("Adobe/ui/jquery.min.js", "/*! jQuery */")

    job = run_job(pkg)
    assert job.state["stages"]["extract"]["status"] == "done"
    extracted_names = {p.name for p in job.unpacked_dir.rglob("*") if p.is_file()}
    assert "Photoshop.exe" in extracted_names
    assert "RunOnce.cmd" in extracted_names
    assert "setup.pimx" in extracted_names
    assert "Patch_Photoshop.exe_.log" in extracted_names
    # Large non-executable junk & boilerplate JS are NOT extracted
    assert "CameraRawProfile.dat" not in extracted_names
    assert "jquery.min.js" not in extracted_names

    # Verify inventory config_flag, scoring, and A1 _uploadable privacy guard
    inv = pipeline._load_inventory(job)
    by_name = {pipeline.Path(r["rel"]).name: r for r in inv["files"]}
    assert by_name["setup.pimx"]["config_flag"] is True
    assert by_name["Patch_Photoshop.exe_.log"]["config_flag"] is True
    assert pipeline._candidate_score(by_name["setup.pimx"]) >= 45
    assert pipeline._uploadable(by_name["setup.pimx"], inv) is False
    assert pipeline._uploadable(by_name["Patch_Photoshop.exe_.log"], inv) is False
    assert pipeline._uploadable(by_name["Photoshop.exe"], inv) is True

    # Vendor JS down-ranking vs real EXE/script
    js_rec = {"rel": "ui/jquery.min.js", "size": 1000, "sha256": "a" * 64, "is_pe": False, "is_script": True,
              "is_doc": False, "config_flag": False, "spoof_flag": False, "name_flag": False, "sig": None, "missing": False}
    exe_rec = {"rel": "app/Photoshop.exe", "size": 1000, "sha256": "b" * 64, "is_pe": True, "is_script": False,
               "is_doc": False, "config_flag": False, "spoof_flag": False, "name_flag": False, "sig": None, "missing": False}
    assert pipeline._candidate_score(js_rec) < pipeline._candidate_score(exe_rec)


def test_select_large_archive_entries_caps_and_deprioritizes():
    entries = [{"clean": "assets/CameraRawProfile.zip", "list_path": "assets/CameraRawProfile.zip", "size": 200 * 1024 * 1024},
               {"clean": "products/Core_x64.zip", "list_path": "products/Core_x64.zip", "size": 200 * 1024 * 1024},
               {"clean": "runtime/node.exe", "list_path": "runtime/node.exe", "size": 70 * 1024 * 1024},
               {"clean": "Photoshop.exe", "list_path": "Photoshop.exe", "size": 5 * 1024 * 1024}]
    for i in range(45):
        entries.append({"clean": f"bin/tool_{i}.exe", "list_path": f"bin/tool_{i}.exe", "size": 1024})
    sel = pipeline._select_large_archive_entries(entries, depth=0, max_depth=2, free_bytes=20 * 1024 ** 3)
    names = [s["clean"] for s in sel]
    assert len(sel) == 40
    assert "products/Core_x64.zip" in names
    assert "assets/CameraRawProfile.zip" not in names
    assert "Photoshop.exe" in names
    assert "runtime/node.exe" not in names  # pushed out beyond top 40


def test_select_large_archive_manifests_never_starve_exes_or_large_core_archive():
    entries = [
        {"clean": f"Adobe 2026/packages/ACC64/Pkg{i}/Pkg{i}.pimx", "list_path": f"Adobe 2026/packages/ACC64/Pkg{i}/Pkg{i}.pimx", "size": 4096}
        for i in range(45)
    ] + [
        {"clean": f"Adobe 2026/products/PHSP/AdobePhotoshop27-fr_{i}_x64.zip", "list_path": f"Adobe 2026/products/PHSP/AdobePhotoshop27-fr_{i}_x64.zip", "size": 5 * 1024 * 1024}
        for i in range(25)
    ] + [
        {"clean": "Adobe 2026/products/PHSP/AdobePhotoshop27-en_US_x64.zip", "list_path": "Adobe 2026/products/PHSP/AdobePhotoshop27-en_US_x64.zip", "size": 5 * 1024 * 1024},
        {"clean": "Adobe 2026/products/PHSP/AdobePhotoshop27-SuperCafModels.zip", "list_path": "Adobe 2026/products/PHSP/AdobePhotoshop27-SuperCafModels.zip", "size": 680 * 1024 * 1024},
        {"clean": "Adobe 2026/Set-up.exe", "list_path": "Adobe 2026/Set-up.exe", "size": 7 * 1024 * 1024},
        {"clean": "autoplay.exe", "list_path": "autoplay.exe", "size": 2 * 1024 * 1024},
        {"clean": "Adobe 2026/products/UNPP/AdobeUnlicensedPopupBlocker.zip", "list_path": "Adobe 2026/products/UNPP/AdobeUnlicensedPopupBlocker.zip", "size": 4096},
        {"clean": "Adobe 2026/products/PHSP/AdobePhotoshop27-Core_x64.zip", "list_path": "Adobe 2026/products/PHSP/AdobePhotoshop27-Core_x64.zip", "size": int(2.87 * 1024 ** 3)},
    ]
    sel = pipeline._select_large_archive_entries(entries, depth=0, max_depth=2, free_bytes=20 * 1024 ** 3)
    names = [s["clean"] for s in sel]
    assert "Adobe 2026/Set-up.exe" in names
    assert "autoplay.exe" in names
    assert "Adobe 2026/products/UNPP/AdobeUnlicensedPopupBlocker.zip" in names
    assert "Adobe 2026/products/PHSP/AdobePhotoshop27-Core_x64.zip" in names
    assert "Adobe 2026/products/PHSP/AdobePhotoshop27-SuperCafModels.zip" not in names

    # Non-executable *.LICENSE.txt / .exv / .json matching NAME_RX must not enter tier_scripts or outrank EXEs/scripts
    core_entries = [
        {"clean": f"1/Application/UXP/dist/chunk_{i}.js.LICENSE.txt", "list_path": f"1/Application/UXP/dist/chunk_{i}.js.LICENSE.txt", "size": 2048}
        for i in range(45)
    ] + [
        {"clean": f"1/Application/Required/tools/patchTool-{i}.exv", "list_path": f"1/Application/Required/tools/patchTool-{i}.exv", "size": 1024}
        for i in range(10)
    ] + [
        {"clean": "1/Application/Photoshop.exe", "list_path": "1/Application/Photoshop.exe", "size": 200 * 1024 * 1024},
        {"clean": "1/Application/Patch_Photoshop.exe_.log", "list_path": "1/Application/Patch_Photoshop.exe_.log", "size": 122},
    ]
    core_sel = pipeline._select_large_archive_entries(core_entries, depth=1, max_depth=2, free_bytes=20 * 1024 ** 3)
    core_names = [s["clean"] for s in core_sel]
    assert "1/Application/Photoshop.exe" in core_names
    assert "1/Application/Patch_Photoshop.exe_.log" in core_names
    assert not any(n.endswith((".txt", ".exv")) for n in core_names)

    txt_rec = {"rel": "8530.js.LICENSE.txt", "size": 1000, "sha256": "a" * 64, "is_pe": False, "is_script": False,
               "is_doc": False, "config_flag": False, "spoof_flag": False, "name_flag": True, "sig": None, "missing": False}
    cmd_rec = {"rel": "RunOnce.cmd", "size": 600, "sha256": "b" * 64, "is_pe": False, "is_script": True,
               "is_doc": False, "config_flag": True, "spoof_flag": False, "name_flag": False, "sig": None, "missing": False}
    pe_rec = {"rel": "Set-up.exe", "size": 7000000, "sha256": "c" * 64, "is_pe": True, "is_script": False,
              "is_doc": False, "config_flag": False, "spoof_flag": False, "name_flag": False, "sig": {"status": "NotSigned"}, "missing": False}
    assert pipeline._candidate_score(txt_rec) < pipeline._candidate_score(pe_rec) < pipeline._candidate_score(cmd_rec)



