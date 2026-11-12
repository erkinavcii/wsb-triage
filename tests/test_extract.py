"""Archive handling: multi-part detection (A3) and unpack size limits (A8)."""
import subprocess
import zipfile

import pytest

import pipeline
import sandbox_manager as sbm
from conftest import bare_job

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
