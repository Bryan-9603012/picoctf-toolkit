from artifactscope.stringscan import analyze_strings, detect_flag_patterns, detect_git_artifacts


def test_analyze_strings_extracts_url_and_email():
    payload = (
        b"Visit https://example.com now\n"
        b"Contact admin@example.com\n"
        b"Use powershell -enc AAAA\n"
    )
    result = analyze_strings(payload)
    assert "https://example.com" in result["urls"]
    assert "admin@example.com" in result["emails"]
    assert any("powershell" in s.lower() for s in result["suspicious_strings"])


def test_detect_flag_patterns_extracts_exact_flag():
    text = "prefix picoCTF{abc_123} suffix"
    flags = detect_flag_patterns([text], text)
    matches = {f["match"] for f in flags}
    assert "picoCTF{abc_123}" in matches
    assert "prefix picoCTF{abc_123} suffix" not in matches


def test_detect_git_artifacts_accepts_windows_paths():
    result = detect_git_artifacts([r".git\config", r"refs\heads\main"], [])
    assert ".git/config" in result["git_files"]
    assert "refs/heads/" in result["git_related_strings"]
    assert result["confidence"] in {"medium", "high", "critical"}
