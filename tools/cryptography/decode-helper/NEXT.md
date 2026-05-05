# NEXT.md - ctf-decode-helper

## Completed
- [x] Fix flag detector duplicate detection (v0.1.1)
- [x] Fix HEX decoder false positive on binary input (v0.1.1)
- [x] Add --file input support (v0.2.0)
- [x] Add Caesar brute force decoder (v0.2.0)
- [x] Fix reporter Found Flags duplicate listing (v0.2.1)
- [x] Fix Base64 UTF-8 decode error exposure (v0.2.1)
- [x] Add --top N parameter to control displayed results (v0.2.1)
- [x] Create internal validation log with 12 synthetic cases (v0.2.2)
- [x] Organize validation files: internal vs real challenge logs (v0.2.3)
- [x] Create real case workflow documentation (v0.2.4)
- [x] Add A1Z26 decoder based on "The Numbers" challenge (v0.3.0)
- [x] Add case-insensitive flag detection and normalization (v0.3.0)
- [x] Solve real picoCTF "The Numbers" challenge (v0.3.0)
- [x] Validate real picoCTF "13" and "Mod 26" challenges (v0.3.1)
- [x] Validate real picoCTF "interencdec" challenge (v0.3.2) — Partial result
- [x] Implement bounded confidence-ranked multi-layer decode mode (v0.4.0)
- [x] Add BYTES_LITERAL_EXTRACT decoder (v0.4.0)
- [x] interencdec fully auto-solved with recursive mode (v0.4.0)
- [x] Add confidence classification (HIGH/MEDIUM/LOW/NOISE) (v0.4.0)
- [x] Add [BEST CANDIDATE] terminal section (v0.4.0)
- [x] Upgrade scoring weights (picoCTF=1000, flag=500, readability=100, keywords=50) (v0.4.0)
- [x] Implement decoder applicability scoring (0-100) for all decoders (v0.5.0)
- [x] Implement transition policy for dynamic decoder prioritization (v0.5.0)
- [x] Implement heuristic-guided recursive search (v0.5.0)
- [x] Add --show-applicability and --max-branch CLI flags (v0.5.0)
- [x] Suppress ROT13/CAESAR noise on base64-like inputs (v0.5.1)
- [x] Stronger base64-like suppression with _is_strong_base64_like() (v0.5.2)
- [x] Reverse penalty for noise chains without flags (v0.5.2)
- [x] Noise family suppression for BASE64->CAESAR_SHIFT_n duplicates (v0.5.2)
- [x] Added 9 new tests for v0.5.2 validation (total 74 tests) (v0.5.2)

## Next Steps (Priority Order)

1. Validate v0.5.2 on more real picoCTF cases to confirm noise reduction works
2. Collect more multi-layer picoCTF challenges to stress-test heuristic-guided search
3. Consider result dedup by identical decoded outputs across different chains
4. Consider adding Base32 decoder (appears in many picoCTF challenges)
5. Revisit XOR with key only if a real challenge requires it
