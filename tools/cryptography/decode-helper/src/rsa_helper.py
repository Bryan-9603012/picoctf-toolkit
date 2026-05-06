from __future__ import annotations

from dataclasses import dataclass, field
from math import gcd, isqrt
from typing import Optional
import os
import random
import re


@dataclass
class RSAInput:
    n: Optional[int] = None
    e: Optional[int] = None
    c: Optional[int] = None
    p: Optional[int] = None
    q: Optional[int] = None
    phi: Optional[int] = None
    d: Optional[int] = None
    dp: Optional[int] = None
    dq: Optional[int] = None
    qinv: Optional[int] = None
    raw_values: dict[str, int] = field(default_factory=dict)
    groups: list[dict[str, int]] = field(default_factory=list)


@dataclass
class RSAAttackResult:
    status: str
    attack: str
    d: Optional[int] = None
    plaintext_int: Optional[int] = None
    plaintext_bytes: bytes = b""
    plaintext_text: str = ""
    plaintext_hex: str = ""
    plaintext_bytes_repr: str = ""
    found_flag: Optional[str] = None
    reason: str = ""
    notes: list[str] = field(default_factory=list)
    tried_attacks: list[str] = field(default_factory=list)


_FLAG_RE = re.compile(r"(?i)picoCTF\{[^}\n\r]+\}")
# Generic integer assignment parser: n=..., e1=..., c_2=..., etc.
_ASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*([^#\n\r]+)")
_FIXED_FIELDS = {"n", "e", "c", "p", "q", "phi", "d", "dp", "dq", "qinv"}
_INDEXED_FIELD_RE = re.compile(r"^(n|e|c)_?(\d+)$")


def _parse_int(value: str) -> int:
    """Parse decimal/hex Python-style integers, ignoring simple wrappers/spaces."""
    cleaned = value.strip().rstrip(",;")
    cleaned = cleaned.replace(" ", "").replace("_", "")
    m = re.match(r"[-+]?(?:0[xX][0-9a-fA-F]+|\d+)", cleaned)
    if not m:
        raise ValueError(f"not an integer literal: {value!r}")
    return int(m.group(0), 0)


def _build_groups(values: dict[str, int], common_n: Optional[int]) -> list[dict[str, int]]:
    by_index: dict[str, dict[str, int]] = {}
    for key, value in values.items():
        match = _INDEXED_FIELD_RE.match(key)
        if not match:
            continue
        field_name, index = match.groups()
        by_index.setdefault(index, {})[field_name] = value

    groups: list[dict[str, int]] = []
    for index in sorted(by_index, key=lambda x: int(x)):
        group = dict(by_index[index])
        if "n" not in group and common_n is not None:
            group["n"] = common_n
        if {"n", "e", "c"}.issubset(group):
            groups.append(group)
    return groups


def parse_rsa_text(text: str) -> RSAInput:
    values: dict[str, int] = {}
    for match in _ASSIGN_RE.finditer(text):
        key = match.group(1)
        try:
            values[key] = _parse_int(match.group(2))
        except ValueError:
            continue

    rsa_input = RSAInput(raw_values=dict(values))
    for key, value in values.items():
        if key in _FIXED_FIELDS:
            setattr(rsa_input, key, value)

    if rsa_input.n is None and rsa_input.p is not None and rsa_input.q is not None:
        rsa_input.n = rsa_input.p * rsa_input.q
        rsa_input.raw_values["n"] = rsa_input.n

    rsa_input.groups = _build_groups(values, rsa_input.n)

    missing = [name for name in ("n", "e", "c") if getattr(rsa_input, name) is None]
    if missing and not rsa_input.groups:
        raise ValueError(f"Missing RSA fields: {', '.join(missing)}")
    return rsa_input


def _continued_fraction(numerator: int, denominator: int) -> list[int]:
    coeffs: list[int] = []
    while denominator:
        coeffs.append(numerator // denominator)
        numerator, denominator = denominator, numerator % denominator
    return coeffs


def _convergents(coeffs: list[int]):
    if not coeffs:
        return
    n0, d0 = 1, 0
    n1, d1 = coeffs[0], 1
    yield n1, d1
    for a in coeffs[1:]:
        n2 = a * n1 + n0
        d2 = a * d1 + d0
        yield n2, d2
        n0, d0, n1, d1 = n1, d1, n2, d2


def _is_square(value: int) -> bool:
    if value < 0:
        return False
    root = isqrt(value)
    return root * root == value


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return abs(a), 1 if a >= 0 else -1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def invmod(a: int, m: int) -> int:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def _pow_signed(base: int, exponent: int, modulus: int) -> int:
    if exponent >= 0:
        return pow(base, exponent, modulus)
    return pow(invmod(base, modulus), -exponent, modulus)


def long_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


def decode_plaintext(plaintext_int: int) -> tuple[bytes, str, Optional[str]]:
    plaintext_bytes = long_to_bytes(plaintext_int)
    try:
        plaintext_text = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext_text = plaintext_bytes.decode("utf-8", errors="replace")
    match = _FLAG_RE.search(plaintext_text)
    found_flag = match.group(0) if match else None
    if found_flag and found_flag.lower().startswith("picoctf{"):
        found_flag = "picoCTF{" + found_flag[8:]
    return plaintext_bytes, plaintext_text, found_flag


def format_plaintext_bytes(plaintext_bytes: bytes) -> tuple[str, str]:
    """Return hex and repr display strings for decrypted plaintext bytes."""
    return "0x" + plaintext_bytes.hex(), repr(plaintext_bytes)


def _plaintext_result(plaintext_int: int, attack: str, notes: list[str], tried: list[str], reason: str = "") -> RSAAttackResult:
    plaintext_bytes, plaintext_text, found_flag = decode_plaintext(plaintext_int)
    plaintext_hex, plaintext_bytes_repr = format_plaintext_bytes(plaintext_bytes)
    return RSAAttackResult(
        status="success",
        attack=attack,
        plaintext_int=plaintext_int,
        plaintext_bytes=plaintext_bytes,
        plaintext_text=plaintext_text,
        plaintext_hex=plaintext_hex,
        plaintext_bytes_repr=plaintext_bytes_repr,
        found_flag=found_flag,
        reason=reason if reason else ("" if found_flag else "Plaintext recovered, but no picoCTF-style flag pattern was found."),
        notes=notes,
        tried_attacks=tried,
    )


def wiener_attack(n: int, e: int) -> Optional[int]:
    coeffs = _continued_fraction(e, n)
    for k, d in _convergents(coeffs):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        discr = s * s - 4 * n
        if discr < 0 or not _is_square(discr):
            continue
        t = isqrt(discr)
        if (s + t) % 2 != 0:
            continue
        return d
    return None


def fermat_factor(n: int, max_iterations: int = 1_000_000) -> Optional[tuple[int, int]]:
    """Factor n when p and q are close: n = a^2 - b^2."""
    if n <= 0 or n % 2 == 0:
        return None
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iterations + 1):
        b2 = a * a - n
        if _is_square(b2):
            b = isqrt(b2)
            p, q = a - b, a + b
            if p > 1 and q > 1 and p * q == n:
                return min(p, q), max(p, q)
        a += 1
    return None


def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    # Deterministic bases for 64-bit; useful and harmless for larger CTF toy inputs.
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for a in (2, 3, 5, 7, 11, 13, 17):
        if a >= n:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def pollard_rho(n: int, max_rounds: int = 20_000) -> Optional[int]:
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    if n <= 1 or _is_probable_prime(n):
        return None

    rng = random.Random(1337)
    for _attempt in range(16):
        c = rng.randrange(1, n - 1)
        x = rng.randrange(2, n - 1)
        y = x
        d = 1
        for _ in range(max_rounds):
            x = (pow(x, 2, n) + c) % n
            y = (pow(y, 2, n) + c) % n
            y = (pow(y, 2, n) + c) % n
            d = gcd(abs(x - y), n)
            if d == 1:
                continue
            if d == n:
                break
            return d
    return None


def _small_factor(n: int, trial_limit: int = 100_000) -> Optional[tuple[int, int]]:
    if n % 2 == 0:
        return 2, n // 2
    i = 3
    while i <= trial_limit and i * i <= n:
        if n % i == 0:
            return i, n // i
        i += 2
    factor = pollard_rho(n)
    if factor and 1 < factor < n and n % factor == 0:
        return min(factor, n // factor), max(factor, n // factor)
    return None


def _try_decrypt_with_d(n: int, c: int, d: int, attack: str, notes: list[str], tried: list[str]) -> RSAAttackResult:
    result = _plaintext_result(pow(c, d, n), attack, notes, tried)
    result.d = d
    return result


def _decrypt_from_factors(n: int, e: int, c: int, p: int, q: int, attack: str, notes: list[str], tried: list[str]) -> Optional[RSAAttackResult]:
    if p * q != n:
        notes.append(f"{attack} rejected factors: p*q != n")
        return None
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        notes.append(f"{attack} found factors, but gcd(e, phi) != 1")
        return None
    d = invmod(e, phi)
    notes.append(f"{attack} succeeded: p={p}, q={q}")
    return _try_decrypt_with_d(n, c, d, attack, notes, tried)


def _integer_nth_root(value: int, n: int) -> tuple[int, bool]:
    if value < 0:
        raise ValueError("negative root not supported")
    if value in (0, 1):
        return value, True
    lo, hi = 0, 1 << ((value.bit_length() + n - 1) // n)
    while lo <= hi:
        mid = (lo + hi) // 2
        p = mid ** n
        if p == value:
            return mid, True
        if p < value:
            lo = mid + 1
        else:
            hi = mid - 1
    return hi, False


def _crt(congruences: list[tuple[int, int]]) -> Optional[tuple[int, int]]:
    """Return x,N for x = ai mod ni. Requires pairwise-coprime moduli."""
    x = 0
    N = 1
    for _, n_i in congruences:
        N *= n_i
    for a_i, n_i in congruences:
        m_i = N // n_i
        try:
            inv = invmod(m_i, n_i)
        except ValueError:
            return None
        x = (x + a_i * m_i * inv) % N
    return x, N


def common_modulus_attack(groups: list[dict[str, int]], notes: list[str], tried: list[str]) -> Optional[RSAAttackResult]:
    if len(groups) < 2:
        return None
    for i in range(len(groups)):
        for j in range(i + 1, len(groups)):
            g1, g2 = groups[i], groups[j]
            if g1.get("n") != g2.get("n"):
                continue
            n = g1["n"]
            e1, e2 = g1["e"], g2["e"]
            c1, c2 = g1["c"], g2["c"]
            g, a, b = _egcd(e1, e2)
            if g != 1:
                notes.append(f"common modulus skipped pair {i+1}/{j+1}: gcd(e1, e2)={g}")
                continue
            try:
                m = (_pow_signed(c1, a, n) * _pow_signed(c2, b, n)) % n
            except ValueError as ex:
                notes.append(f"common modulus failed pair {i+1}/{j+1}: {ex}")
                continue
            notes.append(f"common modulus succeeded with pair {i+1}/{j+1}: a={a}, b={b}")
            return _plaintext_result(m, "common-modulus", notes, tried)
    return None


def broadcast_attack(groups: list[dict[str, int]], notes: list[str], tried: list[str]) -> Optional[RSAAttackResult]:
    if len(groups) < 2:
        return None
    by_e: dict[int, list[dict[str, int]]] = {}
    for group in groups:
        by_e.setdefault(group["e"], []).append(group)

    for e, e_groups in sorted(by_e.items(), key=lambda item: item[0]):
        if e < 2 or len(e_groups) < e or e > 16:
            continue
        selected = e_groups[:e]
        moduli = [g["n"] for g in selected]
        pairwise_ok = True
        for i in range(len(moduli)):
            for j in range(i + 1, len(moduli)):
                if gcd(moduli[i], moduli[j]) != 1:
                    pairwise_ok = False
                    notes.append(f"broadcast e={e} skipped: n{i+1} and n{j+1} are not coprime")
                    break
            if not pairwise_ok:
                break
        if not pairwise_ok:
            continue
        crt_result = _crt([(g["c"], g["n"]) for g in selected])
        if crt_result is None:
            notes.append(f"broadcast e={e} failed: CRT inverse unavailable")
            continue
        combined, modulus_product = crt_result
        root, exact = _integer_nth_root(combined, e)
        if exact:
            notes.append(f"broadcast attack succeeded with e={e} and {e} ciphertexts")
            return _plaintext_result(root, "broadcast", notes, tried)
        notes.append(f"broadcast e={e} failed: CRT result is not a perfect {e}-th power")
    return None


def analyze_rsa_input(rsa_input: RSAInput) -> list[str]:
    notes: list[str] = []
    n, e, c = rsa_input.n, rsa_input.e, rsa_input.c
    if n is not None:
        notes.append(f"n bit length: {n.bit_length()}")
    if e is not None:
        notes.append(f"e: {e}")
        if e == 3:
            notes.append("e=3 detected: low-exponent checks are applicable.")
        elif e == 65537:
            notes.append("e=65537 detected: common public exponent.")
    if rsa_input.groups:
        notes.append(f"multi-ciphertext groups detected: {len(rsa_input.groups)}")
        shared_n = len({g["n"] for g in rsa_input.groups}) == 1
        shared_e = len({g["e"] for g in rsa_input.groups}) == 1
        if shared_n:
            notes.append("same modulus across groups: common modulus attack may apply.")
        if shared_e:
            notes.append("same exponent across groups: broadcast attack may apply if moduli are different and coprime.")
    if rsa_input.p and rsa_input.q:
        notes.append("p and q are present: direct private-key recovery is available.")
    if rsa_input.d:
        notes.append("d is present: direct RSA decryption is available.")
    if rsa_input.dp and rsa_input.dq:
        notes.append("CRT parameters dp/dq are present: CRT-assisted decryption may be available.")
    if n is not None and c is not None and c < n and e == 3:
        notes.append("c < n with e=3: direct integer cube-root attack will be attempted.")
    return notes


def run_rsa_mode(rsa_input: RSAInput) -> RSAAttackResult:
    notes = analyze_rsa_input(rsa_input)
    tried: list[str] = []
    n, e, c = rsa_input.n, rsa_input.e, rsa_input.c

    if n is not None and e is not None and c is not None:
        if rsa_input.d is not None:
            tried.append("provided-d")
            return _try_decrypt_with_d(n, c, rsa_input.d, "provided-d", notes, tried)

        if rsa_input.p is not None and rsa_input.q is not None:
            tried.append("known-pq")
            phi = rsa_input.phi or (rsa_input.p - 1) * (rsa_input.q - 1)
            try:
                d = invmod(e, phi)
                return _try_decrypt_with_d(n, c, d, "known-pq", notes, tried)
            except ValueError as ex:
                notes.append(f"known-pq failed: {ex}")

    if rsa_input.groups:
        tried.append("common-modulus")
        result = common_modulus_attack(rsa_input.groups, notes, tried)
        if result:
            return result

        tried.append("broadcast")
        result = broadcast_attack(rsa_input.groups, notes, tried)
        if result:
            return result

    if n is None or e is None or c is None:
        return RSAAttackResult(
            status="failed",
            attack="input-validation",
            reason="Single-ciphertext attacks require n/e/c. Multi-ciphertext attacks require indexed n1/e1/c1 style fields.",
            notes=notes,
            tried_attacks=tried,
        )

    if e == 3 and c < n:
        tried.append("low-exponent-e3")
        root, exact = _integer_nth_root(c, 3)
        if exact:
            return _plaintext_result(root, "low-exponent-e3", notes, tried, "Cube-root plaintext recovered, but no flag pattern was found.")
        notes.append("low-exponent-e3 check failed: c is not a perfect cube.")

    if n % 2 == 1:
        tried.append("fermat-factor")
        fermat_limit = 1_000_000 if n.bit_length() <= 512 else 2_000
        factors = fermat_factor(n, max_iterations=fermat_limit)
        if factors:
            result = _decrypt_from_factors(n, e, c, factors[0], factors[1], "fermat-factor", notes, tried)
            if result:
                return result
        notes.append(f"fermat-factor failed or not applicable within iteration limit ({fermat_limit}).")

    if n.bit_length() <= 256:
        tried.append("small-n-factor")
        factors = _small_factor(n)
        if factors:
            result = _decrypt_from_factors(n, e, c, factors[0], factors[1], "small-n-factor", notes, tried)
            if result:
                return result
        notes.append("small-n-factor failed or not applicable.")

    tried.append("Wiener")
    d = wiener_attack(n, e)
    if d is not None:
        return _try_decrypt_with_d(n, c, d, "Wiener", notes, tried)

    return RSAAttackResult(
        status="failed",
        attack="auto-rsa",
        reason="No supported RSA attack recovered plaintext. If the challenge includes encrypt.py, try --mode script-reverse first.",
        notes=notes,
        tried_attacks=tried,
    )


def generate_rsa_report(rsa_input: RSAInput, result: RSAAttackResult, output_path: str) -> str:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    lines = [
        "# CTF Decode Helper - RSA Mode Report",
        "",
        "## Input Fields",
        "",
    ]
    for key in ("n", "e", "c", "p", "q", "phi", "d", "dp", "dq", "qinv"):
        value = getattr(rsa_input, key)
        if value is not None:
            lines.append(f"- {key}: `{value}`")
    if rsa_input.groups:
        lines += ["", "## Multi-Ciphertext Groups", ""]
        for idx, group in enumerate(rsa_input.groups, start=1):
            lines.append(f"- group {idx}: n=`{group['n']}`, e=`{group['e']}`, c=`{group['c']}`")
    lines += [
        "",
        "## Analysis Notes",
        "",
    ]
    if result.notes:
        lines.extend(f"- {note}" for note in result.notes)
    else:
        lines.append("- No additional notes.")
    lines += [
        "",
        "## Attack Results",
        "",
        f"- **Status:** {result.status.upper()}",
        f"- **Selected Attack:** {result.attack}",
        f"- **Tried Attacks:** `{', '.join(result.tried_attacks) if result.tried_attacks else 'none'}`",
    ]
    if result.d is not None:
        lines.append(f"- **Recovered d:** `{result.d}`")
    if result.plaintext_int is not None:
        lines.append(f"- **Plaintext (integer):** `{result.plaintext_int}`")
        lines.append(f"- **Plaintext (hex):** `{result.plaintext_hex}`")
        lines.append(f"- **Plaintext (bytes):** `{result.plaintext_bytes_repr}`")
    lines.append("")
    if result.plaintext_text:
        lines += ["## Plaintext (utf-8 best effort)", "", "```", result.plaintext_text, "```", ""]
    lines += ["## Found Flag", ""]
    if result.found_flag:
        lines.append(f"- `{result.found_flag}`")
    else:
        lines.append("No flag pattern found.")
    lines.append("")
    if result.reason:
        lines += ["## Notes", "", f"- {result.reason}", ""]
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return output_path
