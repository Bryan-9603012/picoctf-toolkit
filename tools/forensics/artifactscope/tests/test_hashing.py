import hashlib
from pathlib import Path

from artifactscope.hashing import compute_hashes


def test_compute_hashes(tmp_path: Path):
    sample = tmp_path / "sample.txt"
    sample.write_text("hello", encoding="utf-8")

    hashes = compute_hashes(sample)
    assert hashes["md5"] == hashlib.md5(b"hello").hexdigest()
    assert hashes["sha1"] == hashlib.sha1(b"hello").hexdigest()
    assert hashes["sha256"] == hashlib.sha256(b"hello").hexdigest()
