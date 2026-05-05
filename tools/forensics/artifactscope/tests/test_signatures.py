from pathlib import Path

from artifactscope.signatures import detect_signature


def test_detect_png():
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    result = detect_signature(data, Path("image.png"))
    assert result["detected"] is True
    assert result["type"] == "png"
    assert result["extension_matches"] is True


def test_detect_mismatch():
    data = b"MZ" + b"\x00" * 32
    result = detect_signature(data, Path("note.txt"))
    assert result["detected"] is True
    assert result["type"] == "pe"
    assert result["extension_matches"] is False
