from artifactscope.ctf_handlers import decode_encoded_text, extract_flag


def test_extract_flag():
    assert extract_flag("abc picoCTF{ok_123} xyz") == "picoCTF{ok_123}"


def test_decode_encoded_text_normalizes_plain_secret_from_base64():
    decoded = decode_encoded_text("c2VjcmV0MTIz")
    assert decoded["encoding"] == "base64"
    assert decoded["normalized_flag"] == "picoCTF{secret123}"


def test_sleuthkit_inode_parser_handles_deleted_realloc_line():
    from artifactscope.ctf_handlers import _parse_fls_inode_line

    parsed = _parse_fls_inode_line("+ r/r * 2082(realloc): root/flag.txt")

    assert parsed["inode"] == "2082"
    assert parsed["path"] == "root/flag.txt"
    assert parsed["deleted"] is True


def test_normalize_possible_flag_wraps_bare_token():
    from artifactscope.ctf_handlers import _normalize_possible_flag

    assert _normalize_possible_flag("abc_DEF-12345") == "picoCTF{abc_DEF-12345}"
