from artifactscope.ctf_handlers import extract_flags_from_bytes, _normalize_possible_flag_bytes
from artifactscope.fs_analyzer import _extract_verified_flags_from_bytes


def test_extracts_utf16le_pico_flag_from_bytes():
    data = "picoCTF{unicode_flag_123}".encode("utf-16le")
    assert extract_flags_from_bytes(data) == ["picoCTF{unicode_flag_123}"]
    assert _normalize_possible_flag_bytes(data) == "picoCTF{unicode_flag_123}"


def test_deleted_recovery_flag_extractor_handles_utf16le_without_bom():
    data = b"noise\x00" + "picoCTF{flag_uni_txt}".encode("utf-16le") + b"\x00tail"
    assert "picoCTF{flag_uni_txt}" in _extract_verified_flags_from_bytes(data)
