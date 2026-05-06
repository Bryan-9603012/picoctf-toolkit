from __future__ import annotations

from dataclasses import dataclass, field
import os
import re


@dataclass
class ScriptSignal:
    name: str
    severity: str
    evidence: str
    meaning: str
    recommendation: str


@dataclass
class ScriptReverseResult:
    status: str
    script_type: str = "unknown"
    signals: list[ScriptSignal] = field(default_factory=list)
    suggested_mode: str = "direct-decode"
    reverse_plan: list[str] = field(default_factory=list)
    reason: str = ""


PATTERNS: list[tuple[str, str, str, str, str]] = [
    ("RSA_SMALL_D", r"d\s*=\s*getPrime\s*\(\s*(?:128|160|192|224|256|320)\s*\).*?e\s*=\s*inverse\s*\(\s*d\s*,\s*phi\s*\)", "HIGH", "RSA small private exponent pattern detected.", "Prioritize Wiener Attack in crypto-rsa after extracting n/e/c."),
    ("RSA_POW", r"pow\s*\([^,]+\s*,\s*e\s*,\s*n\s*\)", "HIGH", "RSA modular exponentiation detected.", "Run crypto-rsa after extracting n/e/c/p/q."),
    ("BYTES_TO_LONG", r"bytes_to_long\s*\(", "MEDIUM", "bytes_to_long conversion detected.", "Convert plaintext/ciphertext integers with long_to_bytes when reversing."),
    ("LONG_TO_BYTES", r"long_to_bytes\s*\(", "MEDIUM", "long_to_bytes conversion detected.", "Output is likely an integer-to-bytes conversion."),
    ("GET_PRIME", r"getPrime\s*\(", "MEDIUM", "RSA prime generation detected.", "Look for generated p/q or leaked n/e/c values."),
    ("INVERSE", r"\binverse\s*\(", "MEDIUM", "Modular inverse detected.", "Private exponent or modular arithmetic may be recoverable."),
    ("XOR", r"\^|xor", "MEDIUM", "XOR operation detected.", "Try single-byte XOR or inspect repeating-key logic."),
    ("BASE64", r"base64|b64encode|b64decode", "LOW", "Base64 operation detected.", "Use direct-decode with recursive mode."),
    ("ORD_CHR", r"\bord\s*\(|\bchr\s*\(", "LOW", "ord/chr character transform detected.", "Inspect arithmetic around character mapping."),
    ("RANDOM_SEED", r"random\.seed\s*\(", "MEDIUM", "Deterministic random seed detected.", "Replay the PRNG sequence with the same seed."),
    ("CAESAR_HINT", r"shift|caesar|rot13|rotate", "LOW", "Shift/rotation naming hint detected.", "Try Caesar/ROT13/direct-decode."),
]


def analyze_script_text(text: str) -> ScriptReverseResult:
    signals: list[ScriptSignal] = []
    for name, pattern, severity, meaning, recommendation in PATTERNS:
        m = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if m:
            start = max(0, m.start() - 50)
            end = min(len(text), m.end() + 80)
            evidence = text[start:end].replace("\n", " ").strip()
            signals.append(ScriptSignal(name, severity, evidence, meaning, recommendation))

    result = ScriptReverseResult(status="success" if signals else "no-signal", signals=signals)
    names = {s.name for s in signals}

    if ("RSA_POW" in names and ("BYTES_TO_LONG" in names or "GET_PRIME" in names)) or {"GET_PRIME", "RSA_POW"} <= names:
        result.script_type = "rsa-encryption"
        result.suggested_mode = "crypto-rsa"
        result.reverse_plan = [
            "Extract n, e, c from the challenge text or script output.",
            "If p/q are present, compute phi=(p-1)*(q-1), d=inverse(e, phi), then m=pow(c,d,n).",
        ]
        if "RSA_SMALL_D" in names:
            result.reverse_plan.append("Likely vulnerability: small private exponent. Prioritize Wiener Attack in crypto-rsa.")
        result.reverse_plan += [
            "If multiple ciphertext groups exist, let crypto-rsa inspect common-modulus and broadcast conditions.",
            "If p/q are not present, let crypto-rsa inspect e=3, Fermat, small-n factorization/Pollard Rho, and Wiener conditions.",
            "Convert recovered integer plaintext with long_to_bytes.",
        ]
    elif "XOR" in names:
        result.script_type = "xor-or-byte-transform"
        result.suggested_mode = "direct-decode"
        result.reverse_plan = [
            "Identify whether XOR uses a constant byte, repeating key, or position-dependent key.",
            "For single-byte XOR, brute-force 0..255 and score outputs by flag/readability.",
            "For repeating-key XOR, search for key length or leaked known plaintext such as picoCTF{.",
        ]
    elif "BASE64" in names or "CAESAR_HINT" in names or "ORD_CHR" in names:
        result.script_type = "classical-or-encoding-transform"
        result.suggested_mode = "direct-decode"
        result.reverse_plan = [
            "Run direct-decode with --recursive and a reasonable depth.",
            "Inspect arithmetic around ord/chr if the output is a custom substitution.",
            "Prefer candidate chains that produce picoCTF{...} or readable English.",
        ]
    else:
        result.reason = "No strong crypto/decode pattern was detected. Manual inspection is still recommended."
        result.reverse_plan = ["Search for assignments, loops, byte transforms, and output variables."]
    return result


def analyze_script_file(path: str) -> ScriptReverseResult:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return analyze_script_text(f.read())


def generate_script_reverse_report(result: ScriptReverseResult, output_path: str) -> str:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    lines = [
        "# CTF Decode Helper - Script Reverse Report",
        "",
        "## Summary",
        "",
        f"- **Status:** {result.status}",
        f"- **Detected Type:** {result.script_type}",
        f"- **Suggested Mode:** `{result.suggested_mode}`",
        "",
        "## Signals",
        "",
    ]
    if not result.signals:
        lines.append("No strong pattern detected.")
    else:
        for sig in result.signals:
            lines += [
                f"### {sig.name} ({sig.severity})",
                "",
                f"- **Meaning:** {sig.meaning}",
                f"- **Recommendation:** {sig.recommendation}",
                f"- **Evidence:** `{sig.evidence}`",
                "",
            ]
    lines += ["", "## Reverse Plan", ""]
    for step in result.reverse_plan:
        lines.append(f"- {step}")
    if result.reason:
        lines += ["", "## Notes", "", f"- {result.reason}"]
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return output_path
