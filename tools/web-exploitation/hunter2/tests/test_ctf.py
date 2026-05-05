# tests/test_ctf.py
import pytest
from core.models import Finding, Evidence
from postprocess.ctf import (
    extract_ctf_clues,
    extract_flags,
    extract_all_ctf_data,
    try_decode,
    is_likely_flag,
)


def test_extract_flags_picoctf():
    evidence = Evidence(
        method="GET",
        url="http://example.com/secret",
        status=200,
        headers={},
        content_length=100,
        snippet="The flag is picoCTF{w3lc0m3_t0_hunter2} good luck!",
    )
    finding = Finding(
        rule_id="test-flag",
        name="Test Flag",
        category="ctf",
        severity="info",
        url="http://example.com/secret",
        evidence=evidence,
    )
    
    flags = extract_flags(finding)
    assert any("picoCTF{" in f["flag"] for f in flags)


def test_extract_flags_generic():
    evidence = Evidence(
        method="GET",
        url="http://example.com/hint",
        status=200,
        headers={},
        content_length=100,
        snippet="Look at the flag{inside_this_string} for answers",
    )
    finding = Finding(
        rule_id="test-generic",
        name="Generic Flag",
        category="ctf",
        severity="info",
        url="http://example.com/hint",
        evidence=evidence,
    )
    
    flags = extract_flags(finding)
    assert any("flag{" in f["flag"] for f in flags)


def test_extract_ctf_clues_hidden_input():
    evidence = Evidence(
        method="GET",
        url="http://example.com/form",
        status=200,
        headers={},
        content_length=500,
        snippet='<form><input type="hidden" name="admin" value="1"></form>',
    )
    finding = Finding(
        rule_id="test-hidden",
        name="Hidden Input",
        category="ctf",
        severity="info",
        url="http://example.com/form",
        evidence=evidence,
    )
    
    clues = extract_ctf_clues(finding)
    assert any("hidden_input" in c for c in clues)


def test_extract_ctf_clues_suspicious_extension():
    evidence = Evidence(
        method="GET",
        url="http://example.com/backup.zip",
        status=200,
        headers={},
        content_length=100,
        snippet="Found backup at /backup.zip",
    )
    finding = Finding(
        rule_id="test-ext",
        name="Suspicious Extension",
        category="ctf",
        severity="info",
        url="http://example.com/backup.zip",
        evidence=evidence,
    )
    
    clues = extract_ctf_clues(finding)
    assert any(".zip" in c for c in clues)


def test_is_likely_flag():
    assert is_likely_flag("picoCTF{w3lc0m3_t0_hunter2}")
    assert is_likely_flag("flag{some_flag}")
    assert not is_likely_flag("hello world")
    assert not is_likely_flag("")


def test_try_decode_base64():
    result = try_decode("SGVsbG8gV29ybGQ=", "base64")
    assert result == "Hello World"


def test_try_decode_hex():
    result = try_decode("48656c6c6f576f726c64", "hex")
    assert result == "HelloWorld"
