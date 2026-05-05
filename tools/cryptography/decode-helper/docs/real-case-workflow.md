# Real Case Workflow

## Goal

Use ctf-decode-helper to run all supported decoders against one real picoCTF challenge input and export a Markdown report.

This workflow produces a clean, shareable report per challenge and records the result in the real picoCTF validation log.

## Step 1 - Copy challenge input

From the picoCTF challenge page, copy the encoded string.

The input may be:
- A single encoded string (e.g., `cGljb0NURnt0ZXN0fQ==`)
- A string with spaces (e.g., `01110000 01101001`)
- Multiple lines (extract the suspicious part and test each)

## Step 2 - Run decode helper

Run the tool with `--report` and `--top` to generate a report file:

```bash
python3 main.py --report reports/real-case-<name>.md --top 10 "<input>"
```

### Examples

```bash
# ROT13 challenge
python3 main.py --report reports/real-case-13.md --top 10 "cvpbPGS{grfg}"

# Hex challenge
python3 main.py --report reports/real-case-interencdec.md --top 10 "7069636f4354467b..."

# If the input contains spaces (binary, ASCII decimal)
python3 main.py --report reports/real-case-the-numbers.md --top 10 "112 105 99 111 67 84 70"
```

## Step 3 - Review top results

Open the generated report or review terminal output. Check:

- **Found Flags**: Does the tool detect any `picoCTF{...}`, `flag{...}`, or `CTF{...}` patterns?
- **Top Result**: Which decoder has the highest score?
- **Decoder method**: Which encoding was detected (Base64, Hex, ROT13, Caesar, etc.)?
- **Whether the result directly solves the challenge**: Does the decoded output match the expected flag format and content?

### What to look for

| Scenario | Interpretation |
|---|---|
| Flag found in top result | Tool directly solved it |
| Flag found but inner text is garbled | Multi-layer encoding; need another tool/step |
| No flag found, but readable output | Input may not be a flag container |
| No flag found, all results noise | Unsupported encoding (XOR, Base32, custom cipher) |

## Step 4 - Record validation result

Open `reports/real-pico-validation-log.md` and fill in the case template:

- **Challenge**: Challenge name
- **Category**: Cryptography / Forensics / etc.
- **Difficulty**: Point value or difficulty rating
- **Input**: The encoded string tested
- **Expected Output / Flag**: The actual flag (if known)
- **Command**: The exact command used
- **Top Result**: The highest-scoring decoded output
- **Found Flag**: Did the tool detect a flag pattern? (Yes/No)
- **Did the tool help?**: Yes / Partial / No
- **Notes**: Observations about how the tool performed
- **Limitation observed**: What the tool could not do
- **Candidate improvement**: Feature suggestion for future versions

## Suggested report naming

- `reports/real-case-13.md`
- `reports/real-case-interencdec.md`
- `reports/real-case-the-numbers.md`
- `reports/real-case-mod-26.md`

## Tips

1. **Use `--top 0`** if you want to see all 32 results (7 base decoders + 25 Caesar shifts).
2. **Use `--file`** if the challenge input is in a text file:
   ```bash
   python3 main.py --file challenge-input.txt --report reports/real-case-<name>.md --top 10
   ```
3. **Multi-layer encodings**: If the tool decodes one layer but the inner text is still encoded, copy the decoded output and run the tool again:
   ```bash
   python3 main.py --report reports/real-case-<name>-layer2.md --top 10 "<decoded-from-layer-1>"
   ```
4. **Caesar brute force**: If ROT13 does not match but the challenge hints at a shift cipher, check the top-scoring Caesar shifts in the report.
