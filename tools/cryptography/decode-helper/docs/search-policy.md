# Search Policy: Applicability and Transition Policy

## Why Applicability?

In earlier versions (v0.4), the recursive decode engine tried all decoders on every layer, then filtered results by confidence. This approach had several problems:

1. **Wasted computation**: Running Caesar shifts on base64 strings produces 25 garbage results
2. **Combinatorial explosion**: At depth 3, trying all 9 decoders + 25 Caesar shifts per layer creates thousands of paths
3. **Noisy results**: Low-quality outputs pollute the result list, burying good candidates
4. **No context awareness**: The engine treated all outputs the same regardless of their characteristics

Applicability scoring solves this by asking each decoder: "Am I the right tool for this input?"

## Applicability Scoring

Each decoder computes an applicability score (0-100) before running:

- **0**: Completely unsuitable (e.g., Base64 on non-base64 text)
- **1-9**: Marginally suitable (e.g., REVERSE on any text — always possible but rarely useful)
- **10-49**: Somewhat suitable (e.g., ROT13 on mixed text with some letters)
- **50-89**: Good candidate (e.g., Base64 on valid base64-like string)
- **90-100**: Strong match (e.g., BYTES_LITERAL_EXTRACT on `b'...'`)

Only decoders with applicability >= 10 are attempted in recursive mode.

## Transition Policy

Applicability scoring alone is not enough. Some decoders are always applicable but rarely useful. The transition policy adjusts scores based on output characteristics:

### Bytes Literal Output
When the output looks like `b'...'`:
- BYTES_LITERAL_EXTRACT: boosted to 90+
- ROT13/Caesar: reduced to avoid wasting cycles on binary-looking text

### Base64-like Output
When the output matches base64 charset:
- BASE64: boosted to 90+ (95+ for strong base64-like with strict alpha/digit ratio)
- BYTES_LITERAL_EXTRACT: moderate (might also be a bytes literal) (85+ if strong base64-like)
- ROT13/CAESAR: suppressed to score=2 for strong base64-like, -50 for regular base64-like
- A1Z26/ASCII decimal: reduced (unlikely to be numeric encoding)
- REVERSE: penalized to score=3 for base64-like inputs

### Strong Base64-like Detection (v0.5.2)
A stronger base64 check (`_is_strong_base64_like`) with stricter criteria:
- Alpha ratio >= 0.5 (vs 0.3 for regular)
- Digit ratio <= 0.3 (vs 0.5 for regular)
- Length >= 8 characters
- Proper padding (ends with `=` or length % 4 == 0)
This prevents ROT13/CAESAR expansion on clearly base64-encoded content.

### Reverse Penalty (v0.5.2)
Chains containing REVERSE decoder are penalized when:
- No flag found
- Output is still base64-like or random-like
- No keywords detected
- No structural improvement
Penalty: -100 score reduction in `_apply_reverse_penalty()`

### Noise Family Suppression (v0.5.2)
Same-family noise results (e.g., BASE64 -> CAESAR_SHIFT_1, 2, 3...) are suppressed:
- Only top 2 results from each noise family kept at original score
- Rest penalized by -80 points
- Implemented in `_suppress_noise_family()` in decoder_engine.py

### A1Z26-like Numbers
When the output is space-separated numbers 1-26:
- A1Z26: boosted to 85+
- ASCII decimal: moderate (valid but less specific)
- Base64: reduced (unlikely to be base64)

### Substitution Cipher Text
When the output is mostly alphabetic:
- ROT13/Caesar: boosted to 60+
- REVERSE: moderate

### Reversible Pattern
When output starts with `}` or ends with `{`:
- REVERSE: boosted to 55+

## Why Not Expand All Decoders?

The `--max-branch N` parameter limits how many decoders are expanded per layer. This prevents combinatorial explosion while still exploring the most promising paths.

For example, on the interencdec challenge:

**Layer 1** (input: base64 string):
- BASE64 (90) → expanded
- ROT13 (35) → expanded
- CAESAR (35) → expanded
- REVERSE (10) → expanded

**Layer 2** (input: `b'...'`):
- BYTES_LITERAL_EXTRACT (95) → expanded
- ROT13 (32) → expanded
- CAESAR (32) → expanded
- REVERSE (10) → expanded

**Layer 3** (input: inner base64):
- BASE64 (90) → expanded
- ROT13 (34) → expanded
- CAESAR (34) → expanded
- REVERSE (10) → expanded

**Layer 4** (input: `wpjvJAM{...}`):
- ROT13 (60) → expanded
- CAESAR (60) → expanded (finds the flag at shift 19)
- REVERSE (10) → expanded

This targeted approach finds the flag with far fewer computations than brute-force expansion.

## Applicability vs Confidence

These are two different concepts:

| Concept | Purpose | When Used | Scale |
|---|---|---|---|
| Applicability | Should we try this decoder? | Before decoding (search expansion) | 0-100 |
| Confidence | Does this result look like an answer? | After decoding (final ranking) | HIGH/MEDIUM/LOW/NOISE |

- **Applicability** is forward-looking: "Will this decoder produce useful output?"
- **Confidence** is backward-looking: "Does this output look like a flag?"

A decoder with high applicability might produce low-confidence output (e.g., BASE64 on valid base64 that decodes to garbage). Conversely, a low-applicability decoder might produce high-confidence output in rare cases (e.g., REVERSE on `}tset{FTCocip`).

The search uses applicability to decide what to try. The ranking uses confidence to decide what to show first.
