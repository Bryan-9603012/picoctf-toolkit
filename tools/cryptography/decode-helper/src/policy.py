import re
import string

from dataclasses import dataclass


@dataclass
class ApplicabilityResult:
    decoder_name: str
    applicable: bool
    applicability_score: int
    reason: str


def _base64_score(text: str) -> ApplicabilityResult:
    pattern = r"^[A-Za-z0-9+/]*={0,2}$"
    if not re.match(pattern, text) or len(text) == 0:
        return ApplicabilityResult(
            decoder_name="BASE64",
            applicable=False,
            applicability_score=0,
            reason="character set does not match base64",
        )

    score = 50
    if len(text) % 4 == 0:
        score += 20
    if text.endswith("="):
        score += 10
    if len(text) >= 4:
        score += 10
    if len(text) > 1000:
        score -= 10

    return ApplicabilityResult(
        decoder_name="BASE64",
        applicable=True,
        applicability_score=min(score, 100),
        reason="looks like valid base64",
    )


def _hex_score(text: str) -> ApplicabilityResult:
    cleaned = text.replace(" ", "").replace("\t", "")
    if not cleaned:
        return ApplicabilityResult(
            decoder_name="HEX",
            applicable=False,
            applicability_score=0,
            reason="empty input",
        )
    if not re.match(r"^[0-9a-fA-F]+$", cleaned):
        return ApplicabilityResult(
            decoder_name="HEX",
            applicable=False,
            applicability_score=0,
            reason="contains non-hex characters",
        )
    score = 60
    if len(cleaned) % 2 == 0:
        score += 30
    if len(cleaned) > 4:
        score += 10
    return ApplicabilityResult(
        decoder_name="HEX",
        applicable=True,
        applicability_score=min(score, 100),
        reason="looks like hex string",
    )


def _binary_score(text: str) -> ApplicabilityResult:
    cleaned = text.replace(" ", "")
    if not cleaned:
        return ApplicabilityResult(
            decoder_name="BINARY",
            applicable=False,
            applicability_score=0,
            reason="empty input",
        )
    if not all(c in "01" for c in cleaned):
        return ApplicabilityResult(
            decoder_name="BINARY",
            applicable=False,
            applicability_score=0,
            reason="contains non-binary characters",
        )
    score = 60
    if len(cleaned) % 8 == 0:
        score += 30
    if len(cleaned) >= 8:
        score += 10
    return ApplicabilityResult(
        decoder_name="BINARY",
        applicable=True,
        applicability_score=min(score, 100),
        reason="looks like binary data",
    )


def _ascii_decimal_score(text: str) -> ApplicabilityResult:
    parts = text.split()
    if not parts:
        return ApplicabilityResult(
            decoder_name="ASCII_DECIMAL",
            applicable=False,
            applicability_score=0,
            reason="empty input",
        )
    numeric_parts = [p for p in parts if p.isdigit()]
    if len(numeric_parts) < len(parts) * 0.8:
        return ApplicabilityResult(
            decoder_name="ASCII_DECIMAL",
            applicable=False,
            applicability_score=0,
            reason="most tokens are not numeric",
        )
    valid = sum(1 for p in numeric_parts if 0 <= int(p) <= 255)
    if valid < len(numeric_parts) * 0.8:
        return ApplicabilityResult(
            decoder_name="ASCII_DECIMAL",
            applicable=False,
            applicability_score=0,
            reason="values mostly outside 0-255 range",
        )
    score = 60 + min(30, len(parts) * 2)
    return ApplicabilityResult(
        decoder_name="ASCII_DECIMAL",
        applicable=True,
        applicability_score=min(score, 100),
        reason="looks like space-separated ASCII decimal",
    )


def _a1z26_score(text: str) -> ApplicabilityResult:
    parts = text.split()
    if not parts:
        return ApplicabilityResult(
            decoder_name="A1Z26",
            applicable=False,
            applicability_score=0,
            reason="empty input",
        )
    tokens = [p for p in parts if p.isdigit()]
    if len(tokens) < len(parts) * 0.6:
        return ApplicabilityResult(
            decoder_name="A1Z26",
            applicable=False,
            applicability_score=0,
            reason="most tokens are not numbers",
        )
    in_range = sum(1 for t in tokens if 1 <= int(t) <= 26)
    if in_range < len(tokens) * 0.8:
        return ApplicabilityResult(
            decoder_name="A1Z26",
            applicable=False,
            applicability_score=0,
            reason="most numbers outside 1-26 range",
        )
    score = 60 + min(30, in_range * 3)
    return ApplicabilityResult(
        decoder_name="A1Z26",
        applicable=True,
        applicability_score=min(score, 100),
        reason="looks like A1Z26 encoded numbers",
    )


def _rot13_score(text: str) -> ApplicabilityResult:
    if not text:
        return ApplicabilityResult(
            decoder_name="ROT13",
            applicable=False,
            applicability_score=0,
            reason="empty input",
        )
    if _is_base64_like(text):
        return ApplicabilityResult(
            decoder_name="ROT13",
            applicable=False,
            applicability_score=3,
            reason="input looks like base64, not substitution cipher",
        )
    alpha_ratio = sum(1 for c in text if c in string.ascii_letters) / len(text)
    if alpha_ratio < 0.3:
        return ApplicabilityResult(
            decoder_name="ROT13",
            applicable=False,
            applicability_score=5,
            reason="low alphabetic character ratio",
        )
    score = 30 + int(alpha_ratio * 40)
    return ApplicabilityResult(
        decoder_name="ROT13",
        applicable=True,
        applicability_score=min(score, 100),
        reason="alphabetic text, suitable for rotation cipher",
    )


def _caesar_score(text: str) -> ApplicabilityResult:
    if not text:
        return ApplicabilityResult(
            decoder_name="CAESAR",
            applicable=False,
            applicability_score=0,
            reason="empty input",
        )
    if _is_base64_like(text):
        return ApplicabilityResult(
            decoder_name="CAESAR",
            applicable=False,
            applicability_score=3,
            reason="input looks like base64, not shift cipher",
        )
    alpha_ratio = sum(1 for c in text if c in string.ascii_letters) / len(text)
    if alpha_ratio < 0.3:
        return ApplicabilityResult(
            decoder_name="CAESAR",
            applicable=False,
            applicability_score=5,
            reason="low alphabetic character ratio",
        )
    score = 30 + int(alpha_ratio * 40)
    return ApplicabilityResult(
        decoder_name="CAESAR",
        applicable=True,
        applicability_score=min(score, 100),
        reason="alphabetic text, suitable for shift cipher",
    )


def _reverse_score(text: str) -> ApplicabilityResult:
    if not text:
        return ApplicabilityResult(
            decoder_name="REVERSE",
            applicable=False,
            applicability_score=0,
            reason="empty input",
        )
    base = 10
    if text.startswith("}") or text.endswith("{"):
        base += 50
    return ApplicabilityResult(
        decoder_name="REVERSE",
        applicable=True,
        applicability_score=min(base, 100),
        reason="reversible but low default priority",
    )


def _url_score(text: str) -> ApplicabilityResult:
    if "%20" in text or "%" in text or "+" in text:
        return ApplicabilityResult(
            decoder_name="URL_DECODE",
            applicable=True,
            applicability_score=80,
            reason="contains URL encoding markers",
        )
    return ApplicabilityResult(
        decoder_name="URL_DECODE",
        applicable=False,
        applicability_score=5,
        reason="no URL encoding detected",
    )


def _bytes_literal_score(text: str) -> ApplicabilityResult:
    stripped = text.strip()
    if stripped.startswith("b'") or stripped.startswith('b"'):
        return ApplicabilityResult(
            decoder_name="BYTES_LITERAL_EXTRACT",
            applicable=True,
            applicability_score=95,
            reason="looks like Python bytes literal",
        )
    return ApplicabilityResult(
        decoder_name="BYTES_LITERAL_EXTRACT",
        applicable=False,
        applicability_score=0,
        reason="not a bytes literal",
    )


DECODER_APPLICABILITY = {
    "BASE64": _base64_score,
    "HEX": _hex_score,
    "BINARY": _binary_score,
    "ASCII_DECIMAL": _ascii_decimal_score,
    "A1Z26": _a1z26_score,
    "ROT13": _rot13_score,
    "CAESAR": _caesar_score,
    "REVERSE": _reverse_score,
    "URL_DECODE": _url_score,
    "BYTES_LITERAL_EXTRACT": _bytes_literal_score,
}


def get_applicability(text: str) -> list[ApplicabilityResult]:
    results = []
    for name, scorer in DECODER_APPLICABILITY.items():
        results.append(scorer(text))
    return results


def get_applicable_decoders(text: str, min_score: int = 10) -> list[tuple[str, int, str]]:
    scores = get_applicability(text)
    filtered = [(s.decoder_name, s.applicability_score, s.reason)
                for s in scores if s.applicability_score >= min_score]
    filtered.sort(key=lambda x: x[1], reverse=True)
    return filtered


def _is_bytes_literal(text: str) -> bool:
    stripped = text.strip()
    return stripped.startswith("b'") or stripped.startswith('b"')


def _is_base64_like(text: str) -> bool:
    if not text or len(text) < 4:
        return False
    cleaned = text.strip()
    if not re.match(r"^[A-Za-z0-9+/]*={0,2}$", cleaned):
        return False
    padding_count = cleaned.count("=")
    if padding_count > 2:
        return False
    if padding_count > 0 and not cleaned.endswith("=" * padding_count):
        return False
    upper = sum(1 for c in cleaned if c in string.ascii_uppercase)
    lower = sum(1 for c in cleaned if c in string.ascii_lowercase)
    digits = sum(1 for c in cleaned if c in string.digits)
    other = sum(1 for c in cleaned if c in "+/=")
    total = len(cleaned)
    if total < 4:
        return False
    alpha_ratio = (upper + lower) / total
    if alpha_ratio < 0.3:
        return False
    digit_ratio = digits / total
    if digit_ratio > 0.5:
        return False
    return True


def _is_strong_base64_like(text: str) -> bool:
    """Stronger base64 detection: high alpha+digit ratio, proper padding, looks like real base64."""
    if not _is_base64_like(text):
        return False
    cleaned = text.strip()
    total = len(cleaned)
    if total < 8:
        return False
    upper = sum(1 for c in cleaned if c in string.ascii_uppercase)
    lower = sum(1 for c in cleaned if c in string.ascii_lowercase)
    digits = sum(1 for c in cleaned if c in string.digits)
    alpha_ratio = (upper + lower) / total
    digit_ratio = digits / total
    if alpha_ratio < 0.5:
        return False
    if digit_ratio > 0.3:
        return False
    if not cleaned.endswith("=") and total % 4 != 0:
        return False
    return True


def _is_a1z26_like(text: str) -> bool:
    parts = text.split()
    tokens = [p for p in parts if p.isdigit()]
    if len(tokens) < len(parts) * 0.6:
        return False
    return all(1 <= int(t) <= 26 for t in tokens if t.isdigit())


def _is_hex_like(text: str) -> bool:
    cleaned = text.replace(" ", "").replace("\t", "")
    return bool(re.match(r"^[0-9a-fA-F]+$", cleaned)) and len(cleaned) % 2 == 0


def _is_substitution_cipher_like(text: str) -> bool:
    if not text:
        return False
    if _is_base64_like(text):
        return False
    alpha_ratio = sum(1 for c in text if c in string.ascii_letters) / len(text)
    return alpha_ratio >= 0.6


def _looks_reversible(text: str) -> bool:
    return len(text) > 2 and (text.startswith("}") or text.endswith("{"))


TRANSITION_PRIORITIES = {
    "bytes_literal": ["BYTES_LITERAL_EXTRACT"],
    "base64_like": ["BASE64", "BYTES_LITERAL_EXTRACT"],
    "a1z26_like": ["A1Z26", "ASCII_DECIMAL"],
    "hex_like": ["HEX"],
    "substitution_cipher": ["ROT13", "CAESAR"],
    "reversible": ["REVERSE"],
}


def get_transition_policy(text: str) -> list[tuple[str, int, str]]:
    applicability = get_applicability(text)
    adjusted = []

    base64_boost = _is_base64_like(text)
    strong_base64_boost = _is_strong_base64_like(text)
    bytes_lit_boost = _is_bytes_literal(text)
    a1z26_boost = _is_a1z26_like(text)
    hex_boost = _is_hex_like(text)
    sub_boost = _is_substitution_cipher_like(text)
    rev_boost = _looks_reversible(text)

    for a in applicability:
        score = a.applicability_score

        if a.decoder_name == "BYTES_LITERAL_EXTRACT":
            if bytes_lit_boost:
                score = max(score, 90)
            else:
                score = 0
        elif a.decoder_name == "BASE64":
            if strong_base64_boost:
                score = max(score, 95)
            elif base64_boost:
                score = max(score, 90)
            if bytes_lit_boost:
                score = max(score - 40, 0)
        elif a.decoder_name == "A1Z26":
            if a1z26_boost:
                score = max(score, 85)
        elif a.decoder_name == "ASCII_DECIMAL":
            if a1z26_boost:
                score = max(score - 10, 0)
        elif a.decoder_name == "HEX":
            if hex_boost:
                score = max(score, 80)
        elif a.decoder_name in ("ROT13", "CAESAR"):
            if sub_boost:
                score = max(score, 60)
            if strong_base64_boost:
                score = 0
            elif base64_boost or hex_boost or a1z26_boost:
                score = max(score - 70, 0)
            if bytes_lit_boost:
                score = 0
        elif a.decoder_name == "REVERSE":
            if rev_boost and not (strong_base64_boost or base64_boost or bytes_lit_boost):
                score = max(score, 55)
            if strong_base64_boost:
                score = 0
            elif base64_boost:
                score = min(score, 5)
            if bytes_lit_boost:
                score = min(score, 5)

        adjusted.append((a.decoder_name, score, a.reason))

    adjusted.sort(key=lambda x: x[1], reverse=True)
    return adjusted
