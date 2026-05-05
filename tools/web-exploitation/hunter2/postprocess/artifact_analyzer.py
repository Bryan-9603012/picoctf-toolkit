# postprocess/artifact_analyzer.py
from __future__ import annotations

import io
import json
import os
import re
import shutil
import sqlite3
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


MAGIC_BYTES_SIGNATURES = {
    b"\x50\x4b\x03\x04": ("zip", "application/zip"),
    b"\x50\x4b\x05\x06": ("zip", "application/zip"),
    b"\x50\x4b\x07\x08": ("zip", "application/zip"),
    b"\x1f\x8b": ("gz", "application/gzip"),
    b"\x42\x4d": ("bmp", "image/bmp"),
    b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a": ("png", "image/png"),
    b"\xff\xd8\xff": ("jpg", "image/jpeg"),
    b"\x25\x50\x44\x46": ("pdf", "application/pdf"),
    b"SQLite format 3": ("sqlite", "application/x-sqlite3"),
    b"Rar!\x1a\x07": ("rar", "application/x-rar-compressed"),
    b"\x4d\x5a": ("exe", "application/x-msdownload"),
    b"\xca\xfe\xba\xbe": ("class", "application/x-java-class"),
    b"\x1f\x9d": ("tar", "application/x-tar"),
    b"\x1f\xa0": ("tar", "application/x-tar"),
}


EXTENSION_MIME_MAP = {
    ".zip": ("zip", "application/zip"),
    ".tar": ("tar", "application/x-tar"),
    ".tar.gz": ("tar", "application/x-tar"),
    ".tgz": ("tar", "application/x-tar"),
    ".gz": ("gz", "application/gzip"),
    ".7z": ("7z", "application/x-7z-compressed"),
    ".sql": ("sql", "application/sql"),
    ".db": ("sqlite", "application/x-sqlite3"),
    ".sqlite": ("sqlite", "application/x-sqlite3"),
    ".log": ("log", "text/plain"),
    ".env": ("env", "text/plain"),
    ".json": ("json", "application/json"),
    ".yaml": ("yaml", "application/x-yaml"),
    ".yml": ("yaml", "application/x-yaml"),
    ".xml": ("xml", "application/xml"),
    ".pem": ("pem", "application/x-pem-file"),
    ".key": ("key", "application/x-pem-file"),
    ".crt": ("crt", "application/x-x509-ca-cert"),
    ".cer": ("crt", "application/x-x509-ca-cert"),
    ".heapdump": ("heapdump", "application/octet-stream"),
    ".hprof": ("heapdump", "application/octet-stream"),
    ".jpg": ("jpg", "image/jpeg"),
    ".jpeg": ("jpg", "image/jpeg"),
    ".png": ("png", "image/png"),
    ".gif": ("gif", "image/gif"),
    ".bmp": ("bmp", "image/bmp"),
    ".txt": ("txt", "text/plain"),
    ".html": ("html", "text/html"),
    ".htm": ("html", "text/html"),
    ".js": ("js", "application/javascript"),
    ".css": ("css", "text/css"),
    ".java": ("java", "text/x-java-source"),
    ".class": ("class", "application/x-java-class"),
    ".bak": ("bak", "text/plain"),
    ".backup": ("bak", "text/plain"),
    ".old": ("bak", "text/plain"),
}


SECRET_PATTERNS = {
    "aws_key": (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    "aws_secret": (r"AWS_SECRET_ACCESS_KEY\s*=\s*[A-Za-z0-9/+=]{40}", "AWS Secret"),
    "api_key": (r"api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?", "API Key"),
    "bearer_token": (r"Bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "Bearer Token"),
    "jwt": (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT"),
    "basic_auth": (r"Basic\s+[A-Za-z0-9+/=]{20,}", "Basic Auth"),
    "private_key": (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private Key"),
    "github_token": (r"gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub Token"),
    "slack_token": (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", "Slack Token"),
    "google_api": (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
    "stripe_key": (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Key"),
    "password": (r"password\s*[:=]\s*['\"]?[^\s'\"]{4,}['\"]?", "Password"),
    "secret": (r"secret\s*[:=]\s*['\"]?[^\s'\"]{4,}['\"]?", "Secret"),
    "token": (r"token\s*[:=]\s*['\"]?[A-Za-z0-9_-]{10,}['\"]?", "Token"),
}


URL_PATTERN = re.compile(r"https?://[^\s<>\")']+")
FLAG_PATTERN = re.compile(r"(picoCTF\{[^}]+\}|flag\{[^}]+\}|CTF\{[^}]+\}|[A-Za-z0-9]{31}=)")
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
CREDENTIAL_COMBO = re.compile(r"(username|user|login|email)\s*[:=]\s*['\"]?[^\s'\"]{2,}['\"]?", re.IGNORECASE)


@dataclass
class AnalysisResult:
    file_type: str
    mime_type: str
    magic_bytes: str
    secrets: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    nested_artifacts: List[str] = field(default_factory=list)
    next_actions: List[str] = field(default_factory=list)
    confidence: str = "medium"


def identify_file_type(content: bytes, filename: str = "") -> Tuple[str, str, str]:
    file_type = "unknown"
    mime_type = "application/octet-stream"
    magic_desc = ""
    
    for magic, (ft, mt) in MAGIC_BYTES_SIGNATURES.items():
        if content.startswith(magic):
            file_type = ft
            mime_type = mt
            magic_desc = magic.hex()[:16]
            break
    
    if file_type == "unknown" and filename:
        ext = Path(filename).suffix.lower()
        if ext in EXTENSION_MIME_MAP:
            file_type, mime_type = EXTENSION_MIME_MAP[ext]
            magic_desc = f"ext:{ext}"
    
    return file_type, mime_type, magic_desc


def analyze_text_content(content: str, content_type: str = "text") -> AnalysisResult:
    result = AnalysisResult(
        file_type="txt",
        mime_type="text/plain",
        magic_bytes="text",
    )
    
    if content_type in ["env", "json", "yaml", "xml", "log"]:
        result.file_type = content_type
        result.mime_type = f"text/{content_type}"
    
    for name, (pattern, label) in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            result.secrets.append(f"[{label}] {match[:80]}")
    
    if "env" in content_type or ".env" in str(content_type):
        env_vars = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\n\r#]+)", content)
        for var, val in env_vars[:20]:
            result.indicators.append(f"env:{var}")
            var_l = var.lower()
            clean_val = val.strip()
            if any(tok in var_l for tok in ["secret", "token", "password", "api_key", "apikey", "key"]):
                result.secrets.append(f"[Env Secret] {var}={clean_val[:60]}")
            elif var_l.endswith("_url") and len(clean_val) >= 12:
                result.secrets.append(f"[Connection String] {var}={clean_val[:60]}")
    
    urls = URL_PATTERN.findall(content)
    for url in urls[:10]:
        result.indicators.append(f"url:{url}")
    
    flags = FLAG_PATTERN.findall(content)
    for flag in flags:
        result.secrets.append(f"flag:{flag}")
    
    base64_strings = BASE64_PATTERN.findall(content)
    for bs in base64_strings[:5]:
        result.indicators.append(f"base64_candidate:{bs[:40]}")
    
    creds = CREDENTIAL_COMBO.findall(content)
    for cred in creds[:5]:
        result.indicators.append(f"credential_field:{cred}")
    
    if result.secrets:
        result.confidence = "high"
    elif result.indicators:
        result.confidence = "medium"
    
    return result


def analyze_binary_content(content: bytes, file_type: str) -> AnalysisResult:
    result = AnalysisResult(
        file_type=file_type,
        mime_type="application/octet-stream",
        magic_bytes=content[:16].hex(),
    )
    
    if file_type in ["log", "txt"]:
        try:
            text_result = analyze_text_content(content.decode("utf-8", errors="ignore"), file_type)
            result.secrets = text_result.secrets
            result.indicators = text_result.indicators
            result.confidence = text_result.confidence
        except:
            pass
    
    if file_type == "heapdump":
        result.indicators.append("heapdump_content")
        try:
            text = content.decode("utf-8", errors="ignore")
            secrets = re.findall(r"password\s*[:=]\s*[^\s]{4,}", text, re.IGNORECASE)
            result.secrets.extend([f"heapdump_secret:{s}" for s in secrets[:10]])
            urls = URL_PATTERN.findall(text)
            result.indicators.extend([f"url:{u}" for u in urls[:10]])
        except:
            pass
    
    if result.secrets:
        result.confidence = "high"
    
    return result


def safe_extract_archive(
    archive_path: str,
    output_dir: str,
    max_files: int = 100,
    max_size_bytes: int = 50 * 1024 * 1024,
    max_depth: int = 3,
) -> List[str]:
    extracted = []
    
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            members = zf.namelist()
            if len(members) > max_files:
                members = members[:max_files]
            
            for name in members:
                if name.endswith("/"):
                    continue
                
                safe_path = os.path.normpath(name)
                if safe_path.startswith("..") or safe_path.startswith("/"):
                    continue
                
                info = zf.getinfo(name)
                if info.file_size > max_size_bytes:
                    continue
                
                try:
                    zf.extract(name, output_dir)
                    extracted.append(os.path.join(output_dir, name))
                except:
                    pass
    except:
        pass
    
    try:
        with tarfile.open(archive_path, "r:*") as tf:
            members = tf.getmembers()
            if len(members) > max_files:
                members = members[:max_files]
            
            for member in members:
                if member.isdir():
                    continue
                if member.size > max_size_bytes:
                    continue
                
                try:
                    tf.extract(member, output_dir)
                    extracted.append(os.path.join(output_dir, member.name))
                except:
                    pass
    except:
        pass
    
    return extracted


def analyze_sqlite(db_path: str) -> AnalysisResult:
    result = AnalysisResult(
        file_type="sqlite",
        mime_type="application/x-sqlite3",
        magic_bytes="SQLite",
    )
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        result.indicators.extend([f"table:{t[0]}" for t in tables])
        
        for table in tables[:5]:
            try:
                cursor.execute(f"SELECT * FROM {table[0]} LIMIT 5;")
                rows = cursor.fetchall()
                for row in rows:
                    row_str = str(row)
                    if any(k in row_str.lower() for k in ["password", "token", "secret", "key"]):
                        result.secrets.append(f"db_row:{table[0]}")
                        break
            except:
                pass
        
        conn.close()
        result.confidence = "high"
    except Exception as e:
        result.indicators.append(f"sqlite_error:{str(e)}")
    
    return result


def analyze_artifact(
    artifact_path: str,
    original_url: str = "",
    output_dir: str = "",
) -> AnalysisResult:
    if not os.path.exists(artifact_path):
        return AnalysisResult(
            file_type="missing",
            mime_type="application/octet-stream",
            magic_bytes="",
        )
    
    file_size = os.path.getsize(artifact_path)
    if file_size > 50 * 1024 * 1024:
        result = AnalysisResult(
            file_type="large",
            mime_type="application/octet-stream",
            magic_bytes="too_large",
        )
        result.indicators.append(f"size:{file_size}")
        return result
    
    with open(artifact_path, "rb") as f:
        content = f.read()
    
    file_type, mime_type, magic_desc = identify_file_type(content, artifact_path)
    
    if file_type in ["zip", "tar", "gz"]:
        result = AnalysisResult(
            file_type=file_type,
            mime_type=mime_type,
            magic_bytes=magic_desc,
        )
        
        if output_dir and file_type in ["zip", "tar", "gz"]:
            extract_dir = os.path.join(output_dir, "extracted", os.path.basename(artifact_path))
            os.makedirs(extract_dir, exist_ok=True)
            extracted = safe_extract_archive(artifact_path, extract_dir)
            result.nested_artifacts = extracted
            
            for nested in extracted[:20]:
                if os.path.isfile(nested):
                    nested_result = analyze_artifact(nested, original_url, output_dir)
                    result.secrets.extend(nested_result.secrets)
                    result.indicators.extend(nested_result.indicators)
        
        if result.secrets:
            result.confidence = "high"
        return result
    
    if file_type in ["sqlite", "db"]:
        return analyze_sqlite(artifact_path)
    
    if file_type in ["heapdump", "hprof"]:
        result = analyze_binary_content(content, file_type)
        result.next_actions.append("credential_extraction")
        return result
    
    if file_type in ["log", "txt", "env", "json", "yaml", "xml"]:
        try:
            return analyze_text_content(content.decode("utf-8", errors="ignore"), file_type)
        except:
            pass
    
    return analyze_binary_content(content, file_type)


def collect_artifacts(
    loot_dir: str,
    artifact_outdir: str = "",
    scan_id: str = None,
) -> List[Dict[str, Any]]:
    artifacts = []
    
    if not os.path.exists(loot_dir):
        return artifacts
    
    for fname in os.listdir(loot_dir):
        fpath = os.path.join(loot_dir, fname)
        if not os.path.isfile(fpath):
            continue
        
        result = analyze_artifact(fpath, "", artifact_outdir)
        
        artifact_entry = {
            "path": fpath,
            "filename": fname,
            "file_type": result.file_type,
            "mime_type": result.mime_type,
            "secrets": result.secrets,
            "indicators": result.indicators,
            "nested_artifacts": result.nested_artifacts,
            "confidence": result.confidence,
        }
        
        # Add scan_id if provided
        if scan_id:
            artifact_entry["scan_id"] = scan_id
        
        artifacts.append(artifact_entry)
    
    return artifacts
