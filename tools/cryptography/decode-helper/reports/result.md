# CTF Decode Helper Report

## Input

```
cGljb0NURnt0ZXN0fQ==
```

## Summary

- Total methods: 7
- Success: 4
- Skipped: 3
- Failed: 0

## Found Flags

- `picoCTF{test}`
- `CTF{test}`

## Results

### 1. BASE64

- **Status:** success
- **Score:** 210
- **Flags:**
  - `picoCTF{test}`
  - `CTF{test}`

```
picoCTF{test}
```

### 2. ROT13

- **Status:** success
- **Score:** 20

```
pTywo0AHEag0MKA0sD==
```

### 3. REVERSE

- **Status:** success
- **Score:** 20

```
==Qf0NXZ0tnRUN0bjlGc
```

### 4. URL_DECODE

- **Status:** success
- **Score:** 20
- **Reason:** no URL encoding detected

```
cGljb0NURnt0ZXN0fQ==
```

### 5. HEX

- **Status:** skipped
- **Score:** 0
- **Reason:** input is not valid hex (length must be even, only 0-9a-fA-F allowed)

### 6. BINARY

- **Status:** skipped
- **Score:** 0
- **Reason:** input is not valid binary (only 0/1 allowed, length must be multiple of 8)

### 7. ASCII_DECIMAL

- **Status:** skipped
- **Score:** 0
- **Reason:** input is not valid ASCII decimal (space-separated numbers 0-255 expected)

## Skipped / Failed Details

- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
