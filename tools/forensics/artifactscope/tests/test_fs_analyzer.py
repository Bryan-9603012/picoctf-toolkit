from pathlib import Path
from types import SimpleNamespace

from artifactscope import fs_analyzer


def test_recover_deleted_files_parses_fls_inode_and_uses_offset(monkeypatch, tmp_path: Path):
    image = tmp_path / "disk.img"
    image.write_bytes(b"dummy")

    calls = []

    def fake_run_fls_deleted(image_path, sector_offset=0):
        return True, "r/r * 15: deleted_flag.txt\n"

    def fake_run_icat(image_path, inode, sector_offset=0, output_path=None):
        calls.append((image_path, inode, sector_offset))
        return True, b"picoCTF{deleted_ok}"

    monkeypatch.setattr(fs_analyzer, "run_fls_deleted", fake_run_fls_deleted)
    monkeypatch.setattr(fs_analyzer, "run_icat", fake_run_icat)

    result = fs_analyzer.recover_deleted_files(image, sector_offset=2048)

    assert calls == [(image, 15, 2048)]
    assert result["deleted_files"] == ["15"]
    assert result["flag_candidates"][0]["matched_pattern"] == "picoCTF{"


def test_analyze_with_sleuthkit_runs_fls_when_available(monkeypatch, tmp_path: Path):
    image = tmp_path / "disk.img"
    image.write_bytes(b"dummy")

    monkeypatch.setattr(fs_analyzer, "check_sleuthkit_available", lambda: {
        "mmls": False,
        "fsstat": False,
        "fls": True,
        "icat": False,
        "tsk_recover": False,
    })
    monkeypatch.setattr(fs_analyzer, "run_fls", lambda image_path, sector_offset=0, recursive=True: (True, "r/r 12: flag.txt\nr/r 13: normal.bin"))

    result = fs_analyzer.analyze_with_sleuthkit(image)

    assert result["file_listings"] == ["r/r 12: flag.txt"]
    assert result["flag_candidates"] == []
    assert result["forensic_leads"] == [{"value": "r/r 12: flag.txt", "source": "sleuthkit fls keyword hit"}]
