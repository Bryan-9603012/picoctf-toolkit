from artifactscope.stringscan import detect_flag_patterns, detect_git_artifacts


def test_pico_flag_not_double_counted_as_generic_ctf():
    flags = detect_flag_patterns(["picoCTF{smoke_test}"], "picoCTF{smoke_test}")
    matches = [f["match"] for f in flags]
    assert matches == ["picoCTF{smoke_test}"]


def test_pico_flag_alone_is_not_git_confidence():
    git = detect_git_artifacts(["picoCTF{smoke_test}"], ["picoCTF{smoke_test}"], [])
    assert git["indicator_count"] == 0
    assert git["confidence"] == "none"
