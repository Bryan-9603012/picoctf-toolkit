# CTF Decode Helper Report

## Mode: Recursive

## Input

```
7069636f4354467b746573747d
```

## Summary

- Total methods explored: 9
- Displayed results: 9
- Success: 5
- Skipped: 3
- Failed: 1
- Recursive: yes
- Max depth used: 3

## Found Flags

- `picoCTF{test}`

## Best Candidate

- **Flag:** `picoCTF{test}`
- **Score:** 1170
- **Confidence:** HIGH
- **Chain:** `HEX`

```
picoCTF{test}
```

## Results (Summary)

### 1. HEX

- **Score:** 1170 | **Confidence:** HIGH
- **Chain:** `HEX`
- **Flags:**
  - `picoCTF{test}`

**Output Preview:**
`picoCTF{test}`

### 2. HEX

- **Score:** 1170 | **Confidence:** HIGH
- **Chain:** `REVERSE -> REVERSE -> HEX`
- **Flags:**
  - `picoCTF{test}`

**Output Preview:**
`picoCTF{test}`

### 3. REVERSE

- **Score:** 140 | **Confidence:** MEDIUM
- **Chain:** `REVERSE`

**Output Preview:**
`d747375647b7644534f6369607`

### 4. REVERSE

- **Score:** 140 | **Confidence:** MEDIUM
- **Chain:** `REVERSE -> REVERSE`

**Output Preview:**
`7069636f4354467b746573747d`

### 5. BASE64

- **Score:** 0 | **Confidence:** NOISE
- **Reason:** decoded base64 output is not readable UTF-8

### 6. HEX

- **Score:** 0 | **Confidence:** NOISE
- **Error:** 'utf-8' codec can't decode byte 0xd7 in position 0: invalid continuation byte

### 7. BASE64

- **Score:** 0 | **Confidence:** NOISE
- **Reason:** decoded base64 output is not readable UTF-8

### 8. BASE64

- **Score:** 0 | **Confidence:** NOISE
- **Reason:** decoded base64 output is not readable UTF-8

### 9. REVERSE

- **Score:** 0 | **Confidence:** NOISE

**Output Preview:**
`d747375647b7644534f6369607`

## Skipped / Failed Details

- **BASE64** (skipped): decoded base64 output is not readable UTF-8
- **HEX** (failed): 'utf-8' codec can't decode byte 0xd7 in position 0: invalid continuation byte
- **BASE64** (skipped): decoded base64 output is not readable UTF-8
- **BASE64** (skipped): decoded base64 output is not readable UTF-8
