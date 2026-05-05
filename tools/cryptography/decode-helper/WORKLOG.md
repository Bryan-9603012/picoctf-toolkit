# WORKLOG.md - ctf-decode-helper

## v0.5.3 (2026-05-05) Display Optimization
- Optimized Best Candidate display: now shows "Flag:" line when flag found, clearer format
- Changed Top Results to summary format: "Score | Confidence", "Output Preview" (truncated at 60 chars)
- Added _preview() helper in utils.py for output truncation
- Simplified Applicability Log: only shows top 5 decoders per layer (score >= 10)
- Added --compact mode: shows Best Candidate + Top 3 summary only
- Updated main.py: new mode display format "[Recursive / Depth 4 / Max-Branch 5]"
- Updated reporter.py: report now uses summary format and Output Preview
- Fixed test_recursive_cli_with_report: updated for new display format
- Added 8 new tests for display optimization:
  - test_output_preview_truncation
  - test_output_preview_length
  - test_top_results_summary_format
  - test_best_candidate_full_output
  - test_applicability_log_summary
  - test_compact_mode_cli
  - test_compact_mode_with_report
- Total 81 tests pass
- Updated README.md: added Display optimization and Compact mode features, updated example output
- Updated reports/v0.5.2-showcase.md: no changes needed
- Updated docs/cli-validation.md: added compact mode examples

## v0.5.2 (2026-05-05) Noise Cleanup for Top Results + Showcase
- Added _is_strong_base64_like(): stricter detection (alpha ratio >= 0.5, digit ratio <= 0.3, proper padding)
- Transition policy now uses strong base64 detection: suppresses ROT13/CAESAR to score=2 (was -50)
- Added reverse penalty: REVERSE on base64-like input reduced to score=3, penalized by -100 in scoring if no flag
- Added noise family suppression: BASE64 -> CAESAR_SHIFT_n same-family results limited to 2 representatives in Top Results
- Added _apply_reverse_penalty() and _suppress_noise_family() in decoder_engine.py
- Updated transition policy: REVERSE decoder penalized on base64-like inputs
- Added 9 new tests: interencdec regression, reverse penalty, noise family suppression, applicability/transition policy
- Total 74 tests pass
- Verified: interencdec best candidate still correct (BASE64->BYTES_LITERAL_EXTRACT->BASE64->CAESAR_SHIFT_19)
- Top 5 now cleaner: base64-like Caesar noise reduced
- Created reports/v0.5.2-showcase.md
- Created docs/cli-validation.md
- Updated README.md, NEXT.md

## v0.5.1 (2026-05-04) Suppress Base64 Shift Noise
- Made _is_base64_like stricter: validates padding format (max 2, trailing), alpha ratio >= 0.3, digit ratio <= 0.5
- ROT13 and CAESAR scorers now explicitly reject base64-like inputs (score=3)
- _is_substitution_cipher_like returns False on base64-like input, preventing substitution boost
- Transition policy suppresses ROT13/CAESAR by -50 on base64/hex/a1z26-like inputs (was -30)
- Recursive engine skips entire Caesar shift loop when current_text is base64-like
- Verified: interencdec still solved correctly (depth 4, score 1170, HIGH confidence)
- Verified: simple base64 input no longer triggers 25 Caesar shift variants at layer 1
- All 65 tests pass

## v0.5.0 (2026-05-04) Heuristic-Guided Multi-Layer Decode
- Created src/policy.py with applicability scoring for all 10 decoder types
- Each decoder computes applicability score (0-100) based on input characteristics
- Added transition policy that dynamically adjusts decoder priority per output type
- Rewrote recursive engine to use heuristic-guided search instead of blind expansion
- Added --show-applicability CLI flag for debugging decoder selection at each layer
- Added --max-branch N CLI flag to limit decoders expanded per layer (default: 5)
- Created docs/search-policy.md explaining applicability vs confidence
- Added 8 new tests (applicability, transition policy, max-branch, show-applicability CLI), total 65 tests all passing
- interencdec still auto-solved: picoCTF{caesar_d3cr9pt3d_78250afc} with score 1170, HIGH confidence
- Search is now guided by input characteristics rather than blind expansion
- Updated README.md, encoding-cheatsheet.md, WORKLOG.md, NEXT.md, DECISIONS.md

## v0.4.0 (2026-05-04) Confidence-Ranked Multi-Layer Decode Mode
- Upgraded scoring weights: picoCTF flag = +1000, flag{} = +500, readability = +100, keywords = +50
- Added confidence classification: HIGH / MEDIUM / LOW / NOISE
- Added `confidence` field to DecodeResult dataclass
- Added BYTES_LITERAL_EXTRACT decoder using `ast.literal_eval` for safe extraction
- Implemented selective recursive expansion: only high-value candidates expand (avoids Caesar noise)
- Bounded BFS with depth limit, seen-set dedup for both outputs and chains
- Output length guards: skip < 4 or > 5000 chars
- [BEST CANDIDATE] section in terminal output when flag found
- Report updated with Best Candidate section, confidence display, chain tracking
- interencdec challenge now auto-solved at depth 4: `picoCTF{caesar_d3cr9pt3d_78250afc}` (score 1170, HIGH confidence)
- Updated 2 existing tests for new flag scores (100 → 1000)
- Added 4 new tests (best candidate ranking, confidence classification), total 57 tests all passing
- Updated README.md, encoding-cheatsheet.md, real-pico-validation-log.md, NEXT.md, DECISIONS.md

## v0.3.2 (2026-05-04) interencdec Validation — Partial Result
- Updated reports/real-pico-validation-log.md with interencdec case (Case 2)
- Result: Partial — v0.3 decoded first Base64 layer but did not auto-detect second Base64 layer inside Python bytes literal
- Full decode chain requires manual extraction: Base64 → strip `b'...'` → Base64 → Caesar shift 19
- Summary updated: 4/4 tested, 3 direct solves, 1 partial assist
- Identified v0.4 candidate features: recursive multi-layer decode, bytes literal auto-strip

## v0.3.1 (2026-05-04) Real Challenge Validation Records
- Updated reports/real-pico-validation-log.md with completed cases:
  - Case 1: 13 — PASS (ROT13 directly solves)
  - Case 3: The Numbers — PASS (A1Z26 directly solves, input manually extracted from image)
  - Case 4: Mod 26 — PASS (ROT13 directly solves)
- Updated Summary: 3/3 real challenges directly solved
- Updated NEXT.md: next priority is interencdec with multi-layer decode evaluation

## v0.3.0 (2026-05-04) A1Z26 + Case-Insensitive Flag Detection
- Added A1Z26 decoder: space-separated 1-26 with {, }, _ symbol support
- Added case-insensitive flag detection: picoCTF{...}, picoctf{...}, PICOCTF{...}
- Added flag normalization: all variants displayed as picoCTF{...}
- Real picoCTF "The Numbers" challenge directly solved: `picoCTF{thenumbersmason}`
- Added 11 new tests (A1Z26 + case-insensitive flags), total 45 tests all passing
- Updated README.md, encoding-cheatsheet.md, real-pico-validation-log.md

## v0.2.4 (2026-05-04) Real Case Workflow Documentation
- Created docs/real-case-workflow.md with step-by-step guide for single challenge validation
- Updated README.md: added Real Case Workflow section linking to docs
- Updated NEXT.md: prioritized running real case 13 first, then interencdec, The Numbers, Mod 26
- Added report naming conventions for real case outputs

## v0.2.3 (2026-05-04) Validation File Organization
- Renamed pico-validation-log.md to internal-validation-log.md with synthetic case disclaimer
- Created real-pico-validation-log.md template with 4 planned real picoCTF challenges
- Updated README.md: added Validation section referencing both log files
- Updated Limitations section (removed outdated file input note, added reversed flag note)
- Updated Future Work (removed completed features, added JSON report and recursive decoding)

## v0.2.2 (2026-05-04) Validation
- Created reports/pico-validation-log.md with 12 real picoCTF-style validation cases
- Validated all supported encoders: Base64, Hex, Binary, ROT13, URL, ASCII Decimal, Caesar
- Confirmed known limitations: reversed flags not auto-detected, no recursive decoding
- All 12 cases documented with input, command, output, and assessment

## v0.2.1 (2026-05-04) Quality Fixes
- Fixed reporter Found Flags section: duplicate flags deduplicated while preserving order
- Fixed Base64 decoder: UTF-8 decode errors now return `skipped` with reason instead of exposing Python codec exception
- Added `--top N` parameter: default 10, 0 shows all results
- Report Summary now shows Total methods, Displayed results, Success, Skipped, Failed
- Added 7 new tests (Base64 UTF-8 fallback, reporter dedup, report top_n, CLI --top), total 34 tests all passing
- Updated README.md with --top usage

## v0.2.0 (2026-05-04) New Features
- Added `--file` input support: reads text from file with UTF-8 encoding, errors="replace"
- Added conflict detection: using both positional text and --file produces clear error
- Added file-not-found error handling with clear message (no traceback)
- Added Caesar brute force decoder: tries all 25 shifts, each as independent DecodeResult
- Caesar results scored and sorted alongside other decoders; high-score results appear first
- Added 7 new tests (Caesar shifts + CLI file input/error handling), total 27 tests all passing
- Updated README.md, encoding-cheatsheet.md, WORKLOG.md, NEXT.md, DECISIONS.md

## v0.1.1 (2026-05-04) Bug Fixes
- Fixed flag detector duplicate detection: `picoCTF{...}` no longer also matches `CTF{...}` (used negative lookbehind `(?<![A-Za-z])CTF\{[^}]+\}`)
- Fixed HEX decoder false positive on binary input: now checks readability of decoded output, returns `skipped` if printable ratio < 50%
- Added 6 new tests (flag detection + hex readability), total 20 tests all passing

## v0.1.0 (2026-05-04)
- Created project structure
- Implemented DecodeResult dataclass (src/models.py)
- Implemented decoders: Base64, Hex, Binary, ASCII decimal, ROT13, Reverse, URL Decode (src/decoders.py)
- Implemented flag detector with regex and scoring (src/detector.py)
- Implemented decoder engine to run all decoders and sort results (src/decoder_engine.py)
- Implemented markdown report generator (src/reporter.py)
- Implemented utility functions (src/utils.py)
- Implemented main.py CLI entry point
- Created sample input files
- Created encoding cheatsheet (docs/encoding-cheatsheet.md)
- Created unit tests (tests/test_decoders.py)
- Created README.md with full documentation
- Created project context files (MEMORY.md, WORKLOG.md, NEXT.md, DECISIONS.md)
