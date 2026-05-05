import ast
import base64
import re
import urllib.parse

from src.models import DecodeResult


def _is_base64(text: str) -> bool:
    pattern = r"^[A-Za-z0-9+/]*={0,2}$"
    return bool(re.match(pattern, text)) and len(text) > 0


def decode_base64(text: str) -> DecodeResult:
    if not _is_base64(text):
        return DecodeResult(
            method="BASE64",
            status="skipped",
            reason="input is not valid base64",
        )

    padded = text + "=" * (4 - len(text) % 4) if len(text) % 4 else text
    try:
        decoded = base64.b64decode(padded)
        output = decoded.decode("utf-8")
        return DecodeResult(
            method="BASE64",
            status="success",
            output=output,
        )
    except UnicodeDecodeError:
        return DecodeResult(
            method="BASE64",
            status="skipped",
            reason="decoded base64 output is not readable UTF-8",
        )
    except Exception as e:
        return DecodeResult(
            method="BASE64",
            status="failed",
            error=str(e),
        )


def _is_hex(text: str) -> bool:
    cleaned = text.replace(" ", "").replace("\t", "")
    if not cleaned:
        return False
    if len(cleaned) % 2 != 0:
        return False
    return bool(re.match(r"^[0-9a-fA-F]+$", cleaned))


def _is_readable(text: str) -> bool:
    if not text:
        return False
    import string as _str
    printable = sum(1 for c in text if c in _str.printable)
    return printable / len(text) >= 0.5


def decode_hex(text: str) -> DecodeResult:
    cleaned = text.replace(" ", "").replace("\t", "")
    if not _is_hex(text):
        return DecodeResult(
            method="HEX",
            status="skipped",
            reason="input is not valid hex (length must be even, only 0-9a-fA-F allowed)",
        )

    try:
        decoded = bytes.fromhex(cleaned)
        output = decoded.decode("utf-8")
        if not _is_readable(output):
            return DecodeResult(
                method="HEX",
                status="skipped",
                reason="decoded hex output is not readable",
            )
        return DecodeResult(
            method="HEX",
            status="success",
            output=output,
        )
    except Exception as e:
        return DecodeResult(
            method="HEX",
            status="failed",
            error=str(e),
        )


def _is_binary(text: str) -> bool:
    cleaned = text.replace(" ", "")
    if not cleaned:
        return False
    if not all(c in "01" for c in cleaned):
        return False
    if len(cleaned) % 8 != 0:
        return False
    return True


def decode_binary(text: str) -> DecodeResult:
    if not _is_binary(text):
        return DecodeResult(
            method="BINARY",
            status="skipped",
            reason="input is not valid binary (only 0/1 allowed, length must be multiple of 8)",
        )

    try:
        cleaned = text.replace(" ", "")
        chars = []
        for i in range(0, len(cleaned), 8):
            byte = cleaned[i:i+8]
            chars.append(chr(int(byte, 2)))
        output = "".join(chars)
        return DecodeResult(
            method="BINARY",
            status="success",
            output=output,
        )
    except Exception as e:
        return DecodeResult(
            method="BINARY",
            status="failed",
            error=str(e),
        )


def _is_ascii_decimal(text: str) -> bool:
    parts = text.split()
    if len(parts) < 1:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        val = int(part)
        if val < 0 or val > 255:
            return False
    return True


def decode_ascii_decimal(text: str) -> DecodeResult:
    if not _is_ascii_decimal(text):
        return DecodeResult(
            method="ASCII_DECIMAL",
            status="skipped",
            reason="input is not valid ASCII decimal (space-separated numbers 0-255 expected)",
        )

    try:
        parts = text.split()
        chars = [chr(int(p)) for p in parts]
        output = "".join(chars)
        return DecodeResult(
            method="ASCII_DECIMAL",
            status="success",
            output=output,
        )
    except Exception as e:
        return DecodeResult(
            method="ASCII_DECIMAL",
            status="failed",
            error=str(e),
        )


def decode_a1z26(text: str) -> DecodeResult:
    parts = text.split()
    if not parts:
        return DecodeResult(
            method="A1Z26",
            status="skipped",
            reason="empty input",
        )

    has_numbers = False
    output = ""
    for part in parts:
        if part.isdigit():
            val = int(part)
            if val < 1 or val > 26:
                return DecodeResult(
                    method="A1Z26",
                    status="skipped",
                    reason=f"number {val} is not in A1Z26 range (1-26)",
                )
            output += chr(ord("a") + val - 1)
            has_numbers = True
        elif part in ("{", "}", "_"):
            output += part
        else:
            return DecodeResult(
                method="A1Z26",
                status="skipped",
                reason=f"unsupported token '{part}' in A1Z26 input",
            )

    if not has_numbers:
        return DecodeResult(
            method="A1Z26",
            status="skipped",
            reason="no A1Z26 numbers found in input",
        )

    return DecodeResult(
        method="A1Z26",
        status="success",
        output=output,
    )


def decode_caesar(text: str, shift: int) -> DecodeResult:
    output = ""
    for ch in text:
        if "a" <= ch <= "z":
            output += chr((ord(ch) - ord("a") + shift) % 26 + ord("a"))
        elif "A" <= ch <= "Z":
            output += chr((ord(ch) - ord("A") + shift) % 26 + ord("A"))
        else:
            output += ch

    return DecodeResult(
        method=f"CAESAR_SHIFT_{shift}",
        status="success",
        output=output,
    )


def decode_rot13(text: str) -> DecodeResult:
    output = ""
    for ch in text:
        if "a" <= ch <= "z":
            output += chr((ord(ch) - ord("a") + 13) % 26 + ord("a"))
        elif "A" <= ch <= "Z":
            output += chr((ord(ch) - ord("A") + 13) % 26 + ord("A"))
        else:
            output += ch

    return DecodeResult(
        method="ROT13",
        status="success",
        output=output,
    )


def decode_reverse(text: str) -> DecodeResult:
    return DecodeResult(
        method="REVERSE",
        status="success",
        output=text[::-1],
    )


def decode_url(text: str) -> DecodeResult:
    try:
        decoded = urllib.parse.unquote(text)
        if decoded == text:
            return DecodeResult(
                method="URL_DECODE",
                status="success",
                output=decoded,
                reason="no URL encoding detected",
            )
        return DecodeResult(
            method="URL_DECODE",
            status="success",
            output=decoded,
        )
    except Exception as e:
        return DecodeResult(
            method="URL_DECODE",
            status="failed",
            error=str(e),
        )


def decode_bytes_literal(text: str) -> DecodeResult:
    stripped = text.strip()
    if not (stripped.startswith("b'") or stripped.startswith('b"')):
        return DecodeResult(
            method="BYTES_LITERAL_EXTRACT",
            status="skipped",
            reason="input is not a Python bytes literal",
        )

    try:
        value = ast.literal_eval(stripped)
        if isinstance(value, bytes):
            return DecodeResult(
                method="BYTES_LITERAL_EXTRACT",
                status="success",
                output=value.decode("utf-8"),
            )
        return DecodeResult(
            method="BYTES_LITERAL_EXTRACT",
            status="skipped",
            reason="literal is not bytes type",
        )
    except (ValueError, SyntaxError, MemoryError, RecursionError, TypeError):
        return DecodeResult(
            method="BYTES_LITERAL_EXTRACT",
            status="failed",
            error="unsafe or invalid literal",
        )
    except Exception as e:
        return DecodeResult(
            method="BYTES_LITERAL_EXTRACT",
            status="failed",
            error=str(e),
        )


ALL_DECODERS = [
    decode_base64,
    decode_hex,
    decode_binary,
    decode_ascii_decimal,
    decode_a1z26,
    decode_rot13,
    decode_reverse,
    decode_url,
    decode_bytes_literal,
]
