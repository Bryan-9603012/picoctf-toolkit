from pathlib import Path

from artifactscope.fs_analyzer import fls_list_files, parse_fls_inode_line


def test_parse_fls_regular_deleted_and_nested():
    regular = parse_fls_inode_line("r/r 2082: flag.txt")
    deleted = parse_fls_inode_line("r/r * 2083(realloc): old_flag.txt")
    nested = parse_fls_inode_line("+ r/r * 2084(realloc): root/secret/flag.txt")

    assert regular["inode"] == "2082"
    assert regular["path"] == "flag.txt"
    assert regular["is_deleted"] is False

    assert deleted["inode"] == "2083"
    assert deleted["is_deleted"] is True

    assert nested["inode"] == "2084"
    assert nested["path"] == "root/secret/flag.txt"
    assert nested["name"] == "flag.txt"


def test_fls_list_files_uses_inode_not_metadata(monkeypatch, tmp_path: Path):
    image = tmp_path / "disk.img"
    image.write_bytes(b"dummy")

    class CP:
        returncode = 0
        stdout = "r/r 15: flag.txt\n+ r/r * 16(realloc): root/secret.txt\n"
        stderr = ""

    monkeypatch.setattr("artifactscope.fs_analyzer.has_command", lambda cmd: True)
    monkeypatch.setattr("artifactscope.fs_analyzer._run", lambda *args, **kwargs: CP())

    files = fls_list_files(image, 2048)
    assert [f["inode"] for f in files] == ["15", "16"]
    assert files[1]["is_deleted"] is True
