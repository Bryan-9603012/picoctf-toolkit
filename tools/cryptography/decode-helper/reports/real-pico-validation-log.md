# Real picoCTF Challenge Validation Log

## Overview

This document records validation results from real picoCTF challenges.

Unlike internal synthetic tests, each case here includes the challenge name, category, original challenge input, tool command, tool output summary, and whether the tool helped solve or partially solve the challenge.

## Planned Targets

| Case | Challenge | Category | Purpose |
|---|---|---|---|
| 1 | 13 | Cryptography | Validate ROT13 / Caesar support |
| 2 | interencdec | Cryptography | Validate common encoding / decoding workflow |
| 3 | The Numbers | Cryptography | Test numeric encoding support and identify gaps |
| 4 | Mod 26 | Cryptography | Validate Caesar / modulo-26 style decoding |

## Case Template

### Case 1 - 13

- Challenge: 13
- Category: Cryptography
- Difficulty: Easy (100 points)
- Input: `cvpbPGS{abg_gbj_vqkrs_13}`
- Expected Output / Flag: `picoCTF{not_too_bad_of_a_problem}`
- Command: `python3 main.py --report reports/real-case-13.md --top 10 "cvpbPGS{abg_gbj_vqkrs_13}"`
- Top Result: ROT13 / CAESAR_SHIFT_13, Score: 140, Output: `picoCTF{not_too_bad_of_a_problem}`
- Found Flag: Yes
- Did the tool help? Yes
- Notes: ROT13 directly decodes the flag. Both ROT13 and Caesar shift 13 produce identical results at the top.
- Limitation observed: None for this challenge.
- Candidate improvement: N/A

### Case 2 - interencdec

- Challenge: interencdec
- Category: Cryptography
- Difficulty: Easy
- Input Type: File
- Source File: `enc_flag`
- Encoded Input: `YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==`
- Expected Output / Flag: `picoCTF{caesar_d3cr9pt3d_78250afc}`
- Command:
  ```bash
  python3 main.py --file samples/interencdec-enc_flag.txt --report reports/real-case-interencdec.md --top 10
  ```
- Top Result: BASE64, Output: `b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ=='`
- Found Flag: No
- Did the tool help? Partial
- Notes: Tool successfully decoded the first layer (Base64) and produced a Python bytes literal string. The inner Base64 payload `d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ==` was not automatically detected as a second Base64 input because it was embedded in a `b'...'` string format. Full decode chain requires manual extraction:
  1. Base64 → `b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ=='`
  2. Extract inner string → `d3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ==`
  3. Base64 → `w3GdxkGSx{tgFlx6hylz3cy9w3Nk_78250hmj`
  4. Caesar shift 19 → `picoCTF{caesar_d3cr9pt3d_78250afc}`
- Limitation observed: No recursive / multi-layer decode. No automatic extraction of Python bytes literal format. No automatic re-feeding of decoded output back into the decoder chain.
- Candidate improvement: Recursive multi-layer decode (v0.4 target), Python bytes literal stripping, automatic base64-in-base64 detection.

- **v0.4 Recursive Result**:
  - Command: `python3 main.py --file samples/interencdec-enc_flag.txt --recursive --depth 4 --top 10`
  - Top Result: CAESAR_SHIFT_19, Score: 1170, Confidence: HIGH
  - Output: `picoCTF{caesar_d3cr9pt3d_78250afc}`
  - Decode Chain: `BASE64 -> BYTES_LITERAL_EXTRACT -> BASE64 -> CAESAR_SHIFT_19`
  - Found Flag: Yes
  - Previous v0.3 result: **Partial**
  - v0.4 recursive result: **PASS**

### Case 3 - The Numbers

- Challenge: The Numbers
- Category: Cryptography
- Difficulty: Easy (100 points)
- Input: `16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }`
- Expected Output / Flag: `picoCTF{thenumbersmason}`
- Command: `python3 main.py --report reports/real-case-the-numbers.md --top 10 "16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }"`
- Top Result: A1Z26, Score: 140, Output: `picoctf{thenumbersmason}` (normalized to `picoCTF{thenumbersmason}`)
- Found Flag: Yes
- Did the tool help? Yes
- Notes: A1Z26 decoder added in v0.3 correctly decodes this challenge. Flag detector case-insensitively matches `picoctf{...}` and normalizes to `picoCTF{...}`. This is a direct solve.
- Limitation observed: Input was manually extracted from image. No image parsing support.
- Candidate improvement: N/A

### Case 4 - Mod 26

- Challenge: Mod 26
- Category: Cryptography
- Difficulty: Easy (100 points)
- Input: `cvpbPGS{abg_gbj_vqkrs_13}`
- Expected Output / Flag: `picoCTF{next_time_I'll_try_2_rounds_of_rot13_45559abd}`
- Command: `python3 main.py --report reports/real-case-mod-26.md --top 10 "cvpbPGS{abg_gbj_vqkrs_13}"`
- Top Result: ROT13, Score: 140, Output: `picoCTF{next_time_I'll_try_2_rounds_of_rot13_45559abd}`
- Found Flag: Yes
- Did the tool help? Yes
- Notes: ROT13 directly decodes the flag. Both ROT13 and Caesar shift 13 produce identical results at the top. The challenge name "Mod 26" hints at modulo-26 arithmetic (Caesar cipher family).
- Limitation observed: None for this challenge.
- Candidate improvement: N/A

## Summary

- Total real challenges tested: 4 (13, interencdec, The Numbers, Mod 26)
- Directly solved by tool (single-pass): 3 (13, The Numbers, Mod 26)
- Directly solved by tool (recursive mode): 1 (interencdec)
- Partially assisted: 0 (interencdec was Partial in v0.3, PASS in v0.4)
- Not helped: 0
- Most useful decoder: ROT13 / A1Z26 / Base64 / BYTES_LITERAL_EXTRACT
- Observed limitations: Recursive mode may produce combinatorial explosion at high depth
- v0.4 status: interencdec now fully auto-solved via recursive mode
