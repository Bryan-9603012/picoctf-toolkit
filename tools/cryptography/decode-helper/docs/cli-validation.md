# CLI Validation Command Reference

This document lists formal CLI validation commands for testing ctf-decode-helper functionality.

---

## 1. Unit Tests

Run all unit tests:
```bash
python3 -m unittest discover -s tests -v
```

Expected output: `Ran 74 tests in ... OK`

---

## 2. Base64 Validation

### Single-pass decode
```bash
python3 main.py "cGljb0NURnt0ZXN0fQ=="
```

Expected:
- Top result: BASE64
- Score: 1120
- Confidence: HIGH
- Flag: `picoCTF{test}`

### File input
```bash
python3 main.py --file samples/base64.txt
```

### Export report
```bash
python3 main.py --report reports/result.md "cGljb0NURnt0ZXN0fQ=="
```

---

## 3. ROT13 / Caesar Validation

### ROT13 decode
```bash
python3 main.py "cvpbPGS{grfg}"
```

Expected:
- Top result: ROT13 or CAESAR_SHIFT_13
- Score: 140
- Output: `picoCTF{test}`

### Caesar brute force (all 25 shifts)
```bash
python3 main.py --top 0 "cvpbPGS{grfg}" | grep -A5 "CAESAR_SHIFT"
```

Expected: CAESAR_SHIFT_13 shows `picoCTF{test}`

### Real challenge: 13
```bash
python3 main.py --report reports/real-case-13.md --top 10 "cvpbPGS{abg_gbj_vqkrs_13}"
```

Expected: ROT13 → `picoCTF{not_too_bad_of_a_problem}`

### Real challenge: Mod 26
```bash
python3 main.py --report reports/real-case-mod-26.md --top 10 "cvpbPGS{abg_gbj_vqkrs_13}"
```

Expected: ROT13 → `picoCTF{next_time_I'll_try_2_rounds_of_rot13_45559abd}`

---

## 4. A1Z26 / The Numbers Validation

### A1Z26 decode
```bash
python3 main.py "16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }"
```

Expected:
- Top result: A1Z26
- Output: `picoctf{thenumbersmason}` (normalized to `picoCTF{thenumbersmason}`)

### Real challenge: The Numbers
```bash
python3 main.py --report reports/real-case-the-numbers.md --top 10 "16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }"
```

Expected: A1Z26 → `picoCTF{thenumbersmason}`

---

## 5. interencdec Recursive Validation

### Recursive mode (depth 4)
```bash
python3 main.py --file samples/interencdec-enc_flag.txt --recursive --depth 4 --max-branch 5 --top 10
```

Expected:
- [BEST CANDIDATE] section appears
- Chain: BASE64 → BYTES_LITERAL_EXTRACT → BASE64 → CAESAR_SHIFT_19
- Flag: `picoCTF{caesar_d3cr9pt3d_78250afc}`
- Score: 1170
- Confidence: HIGH

### Export recursive report
```bash
python3 main.py --file samples/interencdec-enc_flag.txt --recursive --depth 4 --max-branch 5 --top 10 --report reports/interencdec-recursive.md
```

### Depth 3 should NOT find flag
```bash
python3 main.py --file samples/interencdec-enc_flag.txt --recursive --depth 3 --top 10
```

Expected: No `picoCTF{caesar_d3cr9pt3d_78250afc}` in output

---

## 6. interencdec with --show-applicability

### Debug mode (show applicability at each layer)
```bash
python3 main.py --file samples/interencdec-enc_flag.txt --recursive --depth 4 --max-branch 5 --show-applicability --top 10
```

Expected:
- [APPLICABILITY LOG] section appears
- Shows "Applicable decoders:" for each layer
- Still finds best candidate correctly

---

## 7. Error Handling Validation

### File not found
```bash
python3 main.py --file nonexistent_file.txt
```

Expected:
- Exit code: 1
- Stderr: "file not found"

### Text and file conflict
```bash
python3 main.py "some_text" --file samples/base64.txt
```

Expected:
- Exit code: 1
- Stderr: "cannot specify both"

### Empty/invalid inputs
```bash
python3 main.py "not!!valid!!base64"
python3 main.py "xyz123"
python3 main.py "01210000"
```

Expected: Status `skipped` or `failed` with clear reason (no traceback)

---

## 8. Output Control Validation

### --top N (limit displayed results)
```bash
python3 main.py --top 5 "cvpbPGS{grfg}"
```

Expected: Results numbered [1] to [5], no [6]

### --top 0 (show all)
```bash
python3 main.py --top 0 "cvpbPGS{grfg}" | grep "CAESAR_SHIFT_25"
```

Expected: CAESAR_SHIFT_25 appears in output

---

## 9. Noise Suppression Validation (v0.5.2)

### Base64-like input should NOT trigger ROT13/CAESAR expansion
```bash
python3 main.py --top 10 "cGljb0NURnt0ZXN0fQ=="
```

Expected:
- Top results should be BASE64 and BYTES_LITERAL_EXTRACT
- ROT13/CAESAR should have very low scores (≤ 5)

### Check Top 5 is cleaner after v0.5.2
```bash
python3 main.py --file samples/interencdec-enc_flag.txt --recursive --depth 4 --max-branch 5 --top 5
```

Expected:
- BASE64→CAESAR_SHIFT_n noise should NOT dominate top 5
- Best Candidate still correct at position 1

---

## Quick Validation Checklist

- [ ] `python3 -m unittest discover -s tests -v` → 74 tests pass
- [ ] Base64 single-pass → picoCTF{test} found
- [ ] ROT13 → picoCTF{test} found
- [ ] A1Z26 → picoCTF{thenumbersmason} found
- [ ] interencdec recursive → picoCTF{caesar_d3cr9pt3d_78250afc} found
- [ ] interencdec --show-applicability → shows applicability log
- [ ] --top 5 → shows only 5 results
- [ ] File not found → clear error, no traceback
- [ ] Noise suppression working → Top 5 cleaner
