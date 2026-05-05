# CTF Decode Helper Report

## Input

```
16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
```

## Summary

- Total methods: 33
- Displayed results: 10
- Success: 29
- Skipped: 4
- Failed: 0

## Found Flags

- `picoCTF{thenumbersmason}`

## Results

### 1. A1Z26

- **Status:** success
- **Score:** 140
- **Flags:**
  - `picoCTF{thenumbersmason}`

```
picoctf{thenumbersmason}
```

### 2. ROT13

- **Status:** success
- **Score:** 20

```
16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
```

### 3. REVERSE

- **Status:** success
- **Score:** 20

```
} 41 51 91 1 31 91 81 5 2 31 12 41 5 8 02 { 6 02 3 51 3 9 61
```

### 4. URL_DECODE

- **Status:** success
- **Score:** 20
- **Reason:** no URL encoding detected

```
16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
```

### 5. CAESAR_SHIFT_1

- **Status:** success
- **Score:** 20

```
16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
```

### 6. CAESAR_SHIFT_2

- **Status:** success
- **Score:** 20

```
16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
```

### 7. CAESAR_SHIFT_3

- **Status:** success
- **Score:** 20

```
16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
```

### 8. CAESAR_SHIFT_4

- **Status:** success
- **Score:** 20

```
16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
```

### 9. CAESAR_SHIFT_5

- **Status:** success
- **Score:** 20

```
16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
```

### 10. CAESAR_SHIFT_6

- **Status:** success
- **Score:** 20

```
16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
```

## Skipped / Failed Details

- **BASE64** (skipped): input is not valid base64
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
