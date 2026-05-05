import re
import string


FLAG_PATTERNS = [
    (r"(?i)picoCTF\{[^}]+\}", 1000),
    (r"(?i)flag\{[^}]+\}", 500),
    (r"(?i)(?<![A-Za-z])CTF\{[^}]+\}", 350),
]

KEYWORDS = [
    "pico", "ctf", "flag", "secret", "password", "key", "token",
    "congratulations", "correct", "well done", "you found",
]


def normalize_flag(flag: str) -> str:
    if re.match(r"(?i)picoCTF\{", flag):
        inner = re.match(r"(?i)picoCTF\{", flag).end()
        return "picoCTF{" + flag[inner:]
    if re.match(r"(?i)flag\{", flag):
        inner = re.match(r"(?i)flag\{", flag).end()
        return "flag{" + flag[inner:]
    if re.match(r"(?i)CTF\{", flag):
        inner = re.match(r"(?i)CTF\{", flag).end()
        return "CTF{" + flag[inner:]
    return flag


def detect_flags(text: str) -> list[str]:
    found = []
    for pattern, _ in FLAG_PATTERNS:
        for match in re.findall(pattern, text):
            normalized = normalize_flag(match)
            if normalized not in found:
                found.append(normalized)
    return found


def flag_score(text: str) -> tuple[int, list[str]]:
    total = 0
    flags = detect_flags(text)
    for pattern, points in FLAG_PATTERNS:
        if re.search(pattern, text):
            total += points
    return total, flags


def keyword_score(text: str) -> int:
    lower = text.lower()
    score = 0
    for kw in KEYWORDS:
        if kw in lower:
            score += 50
            break
    return score


def readability_score(text: str) -> int:
    if not text:
        return -100

    printable = sum(1 for c in text if c in string.printable)
    ratio = printable / len(text)

    alpha_num = sum(1 for c in text if c in string.ascii_letters or c in string.digits or c in " {}_-.:,;!?")
    alpha_ratio = alpha_num / len(text) if len(text) > 0 else 0

    score = 0
    if ratio >= 0.9 and alpha_ratio >= 0.7:
        score += 100
    elif ratio < 0.5:
        score -= 100

    if len(text) < 3:
        score -= 5

    return score


def classify_confidence(output: str, score: int, flags: list[str]) -> str:
    if flags and any("picoCTF" in f for f in flags):
        return "HIGH"
    if flags:
        return "HIGH"
    if score >= 100:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "NOISE"


def compute_score(output: str, previous_input: str = None, chain: list = None) -> tuple[int, list[str], str]:
    if not output:
        return 0, [], "NOISE"

    score = 0
    flags = detect_flags(output)

    f_score, _ = flag_score(output)
    score += f_score

    k_score = keyword_score(output)
    score += k_score

    r_score = readability_score(output)
    score += r_score

    if previous_input is not None and output != previous_input:
        score += 20

    if chain and len(chain) <= 4 and not flags:
        score += 20

    if chain and len(chain) > 4 and not flags:
        score -= 30

    confidence = classify_confidence(output, score, flags)

    return score, flags, confidence
