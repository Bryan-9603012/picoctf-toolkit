# tests/test_artifact_analyzer.py
import pytest
import os
import tempfile
from postprocess.artifact_analyzer import (
    identify_file_type,
    analyze_text_content,
    analyze_binary_content,
    analyze_artifact,
)


def test_identify_file_type_by_extension():
    assert identify_file_type(b"", "test.zip") == ("zip", "application/zip", "ext:.zip")
    assert identify_file_type(b"", "test.sql") == ("sql", "application/sql", "ext:.sql")
    assert identify_file_type(b"", "test.env") == ("env", "text/plain", "ext:.env")
    assert identify_file_type(b"", "test.heapdump") == ("heapdump", "application/octet-stream", "ext:.heapdump")


def test_identify_file_type_by_magic_bytes():
    png_content = b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d"
    ft, mt, magic = identify_file_type(png_content, "unknown")
    assert ft == "png"
    assert mt == "image/png"

    pdf_content = b"\x25\x50\x44\x46\x2d\x31\x2e\x35"
    ft, mt, magic = identify_file_type(pdf_content, "unknown")
    assert ft == "pdf"
    assert mt == "application/pdf"


def test_analyze_text_content_env():
    content = """
DATABASE_URL=postgresql://localhost:5432/db
API_KEY=sk_test_1234567890abcdef
SECRET_KEY=mysecret123
"""
    result = analyze_text_content(content, "env")
    assert result.file_type == "env"
    assert len(result.secrets) >= 2
    assert any("API_KEY" in s for s in result.secrets)


def test_analyze_text_content_flags():
    content = "The flag is picoCTF{w3lc0m3_t0_hunter2} inside this file"
    result = analyze_text_content(content, "txt")
    assert any("picoCTF{" in s for s in result.secrets)


def test_analyze_text_content_jwt():
    content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = analyze_text_content(content, "txt")
    assert any("Bearer Token" in s for s in result.secrets)


def test_analyze_text_content_urls():
    content = "Check out https://api.example.com/secret and http://internal.corp/admin"
    result = analyze_text_content(content, "txt")
    assert any("url:https://api.example.com" in s for s in result.indicators)


def test_analyze_binary_content():
    content = b"This is binary content with password=secret123 inside"
    result = analyze_binary_content(content, "txt")
    assert len(result.secrets) > 0


def test_analyze_binary_content_heapdump():
    content = b'{"snapshot":{"nodes":[1,2,3],"strings":["password=admin123"]}'
    result = analyze_binary_content(content, "heapdump")
    assert result.file_type == "heapdump"
    assert len(result.secrets) > 0 or "heapdump_content" in result.indicators
