# Encoding Cheatsheet

## Supported Encodings (v0.5)

| Encoding / Cipher | Common Pattern | Example | How the tool handles it | Best for |
|---|---|---|---|---|
| Base64 | `[A-Za-z0-9+/]+={0,2}` | `cGljb0NURnt0ZXN0fQ==` → `picoCTF{test}` | Auto-detects charset, pads if needed, decodes | Strings with base64 character set, padding chars |
| Hex | `[0-9a-fA-F]+` (even length) | `7069636f435446` → `picoCTF` | Strips spaces, validates even length, converts | Hex strings, often with `0x` prefix |
| Binary | `[01]{8}` groups | `01110000 01101001` → `pi` | Supports space-separated or continuous, 8-bit groups | Binary data, 7-bit ASCII |
| ASCII Decimal | Space-separated 0-255 | `112 105 99 111` → `pico` | Splits by space, validates range, converts | Space-separated decimal numbers |
| A1Z26 | Space-separated 1-26, with `{` `}` `_` allowed | `16 9 3 15` → `pico` | Validates 1-26 range, preserves symbols, outputs lowercase | Numbers 1-26 with optional `{`, `}`, `_` |
| ROT13 | Mixed letters with `{}` | `cvpbPGS{grfg}` → `picoCTF{test}` | Shifts a-z, A-Z by 13, leaves others | Alphabetic text with flag-like patterns |
| REVERSE | Any string | `}tset{FTCocip` → `picoCTF{test}` | Reverses entire string | Strings starting with `}` or ending with `{` |
| URL Encode | `%XX` sequences | `%70%69%63%6F` → `pico` | Uses `urllib.parse.unquote` | Strings with `%20`, `%XX`, or `+` |
| BYTES_LITERAL_EXTRACT | `b'...'` or `b"..."` | `b'd3BqdkpBT...'` → `d3BqdkpBT...` | Uses `ast.literal_eval` for safe extraction | Python bytes literals from encoding challenges |
| Caesar | Shifted text with known keywords | `qjdpDUH{uftu}` → shift 13 → `picoCTF{test}` | Brute force all 25 shifts, each scored | Alphabetic text, especially with flag patterns |

## Applicability Scoring

Each decoder computes an applicability score (0-100) for the current input:

| Decoder | High Score When | Low Score When |
|---|---|---|
| BASE64 | Valid base64 charset, proper padding | Non-base64 characters, odd length |
| HEX | Only hex chars, even length | Non-hex characters, odd length |
| BINARY | Only 0/1 chars, length multiple of 8 | Mixed characters, wrong length |
| ASCII_DECIMAL | Space-separated numbers in 0-255 | Non-numeric tokens, out-of-range |
| A1Z26 | Space-separated numbers in 1-26 | Numbers outside 1-26 range |
| ROT13 | High alphabetic ratio | Low letters, mostly symbols |
| CAESAR | High alphabetic ratio | Low letters, mostly symbols |
| REVERSE | Starts with `}` or ends with `{` | Normal-looking text |
| URL_DECODE | Contains `%XX` or `+` | No URL encoding markers |
| BYTES_LITERAL_EXTRACT | Starts with `b'` or `b"` | No bytes literal format |

## Transition Policy

The tool uses a transition policy to dynamically prioritize decoders based on output characteristics:

- **Bytes literal output** → prioritize BYTES_LITERAL_EXTRACT, deprioritize ROT13/Caesar
- **Base64-like output** → prioritize BASE64, deprioritize A1Z26/ASCII decimal
- **A1Z26-like numbers** → prioritize A1Z26, then ASCII decimal
- **Hex-like output** → prioritize HEX
- **Substitution cipher text** → prioritize ROT13/Caesar
- **Reversible pattern** → prioritize REVERSE

## Recursive / Multi-Layer Decode

v0.5 introduces heuristic-guided multi-layer decode mode. When `--recursive` is enabled:

1. The tool runs all applicable decoders on the input
2. Each decoder's applicability score determines if it should be tried
3. High-applicability results are fed into the next decode layer
4. Transition policy dynamically adjusts decoder priority per layer
5. This continues up to `--depth N` with `--max-branch K` decoders per layer
6. Each result tracks its full decode chain
7. Results are ranked by confidence score; flag-finding chains appear first

### Expansion Rules

Not all outputs expand to the next layer. Only high-value candidates continue:
- Base64 success with readable output
- BYTES_LITERAL_EXTRACT success
- Hex success with readable output
- URL decode with actual changes
- A1Z26 success with readable output
- ROT13 / REVERSE success with readable output

Excluded from expansion:
- Caesar shifts (too noisy, expanded only when alphabetically appropriate)
- Outputs identical to input
- Very short (< 4) or very long (> 5000) outputs
- Low-confidence / noise results

## Future Work

| Encoding / Cipher | Common Pattern | Example | Planned handling | Notes |
|---|---|---|---|---|
| Morse | `.- ` and `- ` sequences | `.--. .. -.-. ---` → `pico` | Parse dot-dash patterns, convert to letters | Often with spaces between letters |
| Base32 | `[A-Z2-7]+=*` | `OBQXG5DIMUQHC3DF` | Decode with base64.b32decode | Common in picoCTF |
| Base85 | `[!-z]+` with `<~ ~> ` | `<~cV6Eo>` | Decode with base64.b85decode | Less common but appears |
| XOR | Hex string with single-byte key | `37 32 31` with key 0x42 | Brute force all 256 keys, score results | Very common in CTFs |
| Vigenere | Text with keyword hint | `text` + key `secret` | Try known keywords, frequency analysis | Requires keyword or analysis |
