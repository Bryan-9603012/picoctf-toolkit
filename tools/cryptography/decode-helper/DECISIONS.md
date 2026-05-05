# DECISIONS.md - ctf-decode-helper

## ADR-001: v0.1 focuses on keyless decoders only
- **Date:** 2026-05-04
- **Context:** CTF challenges often involve simple encodings that don't require keys.
- **Decision:** First version only supports decoders that don't need user input (Base64, Hex, Binary, ASCII decimal, ROT13, Reverse, URL Decode).
- **Consequence:** Limited to encoding-based challenges; crypto challenges with keys are not supported yet.

## ADR-002: Key-based crypto is postponed to future Crypto Mode
- **Date:** 2026-05-04
- **Context:** AES, RSA, and other key-based attacks require user input and complex logic.
- **Decision:** Postpone all key-based crypto operations to a future "Crypto Mode" feature.
- **Consequence:** Keeps v0.1 focused and simple; users won't expect crypto solver features.

## ADR-003: DecodeResult is the unified result format
- **Date:** 2026-05-04
- **Context:** Multiple decoders produce different outputs; need a consistent format for scoring and display.
- **Decision:** Use a dataclass `DecodeResult` with fields: method, status, output, score, flags, reason, error.
- **Consequence:** All decoders return the same type; engine can sort and display uniformly.

## ADR-004: Python standard library only for v0.1
- **Date:** 2026-05-04
- **Context:** Minimizes setup friction and dependencies.
- **Decision:** No external packages required. All decoders use built-in modules (base64, binascii, urllib.parse, etc.).
- **Consequence:** Easy to run anywhere; may reconsider if advanced features need external libs.

## ADR-005: Defensive decoder design
- **Date:** 2026-05-04
- **Context:** Some inputs will be malformed or not match a decoder's expected format.
- **Decision:** Decoders must never crash. Invalid input returns `skipped` or `failed` with a reason/error message.
- **Consequence:** Tool always produces output even with garbage input; users can see why certain decoders didn't run.

## ADR-006: v0.2 adds file input and Caesar brute force, key-based crypto still postponed
- **Date:** 2026-05-04
- **Context:** Users want to decode from files, and Caesar brute force is a common CTF need.
- **Decision:** Add `--file` input with UTF-8 encoding and clear error handling. Add Caesar brute force (shifts 1-25) as independent scored results. Key-based crypto (AES, RSA, XOR with user-provided key) remains postponed to future Crypto Mode.
- **Consequence:** File input enables batch workflows; Caesar brute force catches common shift ciphers without user guessing; crypto mode stays clean separation for future work.

## ADR-007: v0.2.1 quality fixes for reporter, Base64, and output length
- **Date:** 2026-05-04
- **Context:** Three issues found during acceptance testing: duplicate flags in report, raw Python exception on Base64 UTF-8 failure, and excessive output from 25 Caesar shifts.
- **Decision:** (1) Reporter Found Flags section deduplicates while preserving order. (2) Base64 UnicodeDecodeError returns `skipped` with readable reason instead of raw exception. (3) `--top N` parameter added (default 10, 0 for all) to control displayed results in both terminal and report output. Report Summary includes "Displayed results" count.
- **Consequence:** Cleaner reports, no leaked exceptions, manageable output length for brute-force decoders.

## ADR-008: v0.3 adds A1Z26 decoder and case-insensitive flag detection based on real challenge validation
- **Date:** 2026-05-04
- **Context:** Real picoCTF challenge "The Numbers" uses A1Z26 encoding (1=A, 2=B, ..., 26=Z) with curly braces. The tool previously had no support for this common CTF encoding, and the flag detector was case-sensitive.
- **Decision:** (1) Add A1Z26 decoder that validates 1-26 range, preserves `{`, `}`, `_` symbols, outputs lowercase. (2) Make flag detection case-insensitive using `(?i)` regex flags. (3) Normalize all detected flags to `picoCTF{...}` format in output. Key-based crypto (AES, RSA, XOR) remains postponed.
- **Consequence:** The tool now directly solves "The Numbers" challenge. Case-insensitive detection prevents false negatives on A1Z26 output (which is lowercase). Users see normalized flag format regardless of decoder output case.

## ADR-009: v0.4 introduces bounded confidence-ranked multi-layer decode before key-based crypto
- **Date:** 2026-05-04
- **Context:** Real picoCTF challenge "interencdec" requires 4 decode steps: Base64 → bytes literal extract → Base64 → Caesar shift 19. v0.3 could only solve the first layer; users had to manually extract and re-run the tool.
- **Decision:** (1) Add `--recursive` mode that feeds decoded output back into decoders via bounded BFS up to `--depth N`. (2) Upgrade scoring weights: picoCTF flag = +1000, flag{} = +500, readability = +100, keywords = +50. (3) Add confidence classification: HIGH (flag found), MEDIUM (high readability), LOW (readable), NOISE (garbage). (4) Add `confidence` field to DecodeResult. (5) Add BYTES_LITERAL_EXTRACT decoder using `ast.literal_eval`. (6) Implement selective expansion: only high-value candidates (Base64, Bytes Literal, Hex, URL, A1Z26, ROT13, Reverse) expand to next layer; Caesar shifts excluded to avoid combinatorial noise. (7) Use seen-sets for both output dedup and chain dedup. (8) Add [BEST CANDIDATE] terminal section when a flag is found. (9) Default depth 3; interencdec requires depth 4.
- **Consequence:** interencdec is now fully auto-solved with score 1170, HIGH confidence. Flag-finding chains rank first without needing manual chain boost. Selective expansion prevents explosion at depth 3+. Chain and confidence information displayed in terminal and reports. Key-based crypto (XOR/AES/RSA) remains postponed until more real validation data is collected.

## ADR-010: v0.5 introduces decoder applicability and transition policy to replace naive recursive expansion
- **Date:** 2026-05-04
- **Context:** v0.4's recursive mode expanded all decoders on every layer, producing thousands of results at depth 3+. The approach was computationally wasteful (e.g., running Caesar on base64 strings) and produced noisy results that buried good candidates.
- **Decision:** (1) Add applicability scoring: each decoder computes a 0-100 score indicating how well it fits the current input. (2) Add transition policy: dynamically adjusts applicability scores based on output characteristics (e.g., bytes literal → boost BYTES_LITERAL_EXTRACT, base64-like → boost BASE64). (3) Only decoders with applicability >= 10 are attempted in recursive mode. (4) Add --max-branch N to limit decoders expanded per layer. (5) Add --show-applicability for debugging. (6) Applicability guides search expansion; confidence guides final ranking — these are kept separate.
- **Consequence:** Search is now heuristic-guided rather than blind expansion. interencdec is still auto-solved but with smarter path selection. Combinatorial explosion is better controlled. --show-applicability provides visibility into decoder selection decisions. XOR/AES/RSA still postponed until real validation requires them.

## ADR-011: v0.5.1 suppresses ROT13/CAESAR on base64-like inputs
- **Date:** 2026-05-04
- **Context:** Despite v0.5's applicability scoring, base64-like strings still triggered medium-score ROT13/CAESAR evaluations (alpha ratio high enough to pass threshold), producing meaningless shift variants that cluttered top results.
- **Decision:** (1) Make _is_base64_like stricter: validate padding format, alpha ratio >= 0.3, digit ratio <= 0.5. (2) ROT13 and CAESAR scorers explicitly reject base64-like inputs with score=3. (3) _is_substitution_cipher_like returns False on base64-like input. (4) Recursive engine skips entire Caesar shift loop when input is base64-like. (5) Transition policy suppresses ROT13/CAESAR by -50 on base64/hex/a1z26-like inputs (was -30).
- **Consequence:** Base64-like inputs no longer produce 25 Caesar shift variants at layer 1. interencdec still solved correctly. Top results are cleaner with flag-finding chains ranking first without shift noise.

## ADR-012: v0.5.2 noise cleanup for Top Results
- **Date:** 2026-05-05
- **Context:** After v0.5.1, interencdec Best Candidate is correct, but Top Results still contain too much low-value noise: BASE64->ROT13, BASE64->CAESAR_SHIFT_1..n, REVERSE->CAESAR_SHIFT_17. These results have no flags, no keywords, no structural improvement, but still occupy top positions.
- **Decision:** (1) Add _is_strong_base64_like(): stricter detection (alpha ratio >= 0.5, digit ratio <= 0.3, proper padding, length >= 8). (2) Transition policy: on strong base64-like input, ROT13/CAESAR suppressed to score=2 (was -50). (3) Add reverse penalty: REVERSE decoder penalized by -40 on base64-like inputs (score=3). (4) Add _apply_reverse_penalty(): results with REVERSE in chain but no flag/keywords get -100 score penalty. (5) Add _suppress_noise_family(): BASE64->CAESAR_SHIFT_n same-family results limited to 2 representatives in Top Results, others penalized by -80. (6) Added 9 new tests for regression, reverse penalty, noise family suppression, applicability/transition policy. Total 74 tests pass.
- **Consequence:** Top 5 results are cleaner, base64-like Caesar noise reduced, REVERSE-based noise chains penalized. interencdec best candidate remains correct (BASE64->BYTES_LITERAL_EXTRACT->BASE64->CAESAR_SHIFT_19). No new decoders added.
