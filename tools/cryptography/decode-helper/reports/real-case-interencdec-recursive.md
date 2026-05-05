# CTF Decode Helper Report

## Mode: Recursive

## Input

```
YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==
```

## Summary

- Total methods explored: 442
- Displayed results: 10
- Success: 368
- Skipped: 74
- Failed: 0
- Recursive: yes
- Max depth used: 4

## Found Flags

- `picoCTF{caesar_d3cr9pt3d_78250afc}`

## Best Candidate

- **Method:** CAESAR_SHIFT_19
- **Score:** 1170
- **Confidence:** HIGH
- **Chain:** `BASE64 -> BYTES_LITERAL_EXTRACT -> BASE64 -> CAESAR_SHIFT_19`
- **Flags:**
  - `picoCTF{caesar_d3cr9pt3d_78250afc}`

```
picoCTF{caesar_d3cr9pt3d_78250afc}
```

## Results

### 1. CAESAR_SHIFT_19

- **Status:** success
- **Score:** 1170
- **Confidence:** HIGH
- **Chain:**
  - `BASE64 -> BYTES_LITERAL_EXTRACT -> BASE64 -> CAESAR_SHIFT_19`
- **Flags:**
  - `picoCTF{caesar_d3cr9pt3d_78250afc}`

```
picoCTF{caesar_d3cr9pt3d_78250afc}
```

### 2. CAESAR_SHIFT_17

- **Status:** success
- **Score:** 190
- **Confidence:** MEDIUM
- **Chain:**
  - `REVERSE -> CAESAR_SHIFT_17`

```
==xTe0KGIQNtotLP3McrEIqP6yctFIMNqnXMcWeK6WdQjyLP2x3IyWYuPIcHnkXQoA0DbuzP
```

### 3. CAESAR_SHIFT_4

- **Status:** success
- **Score:** 190
- **Confidence:** MEDIUM
- **Chain:**
  - `ROT13 -> REVERSE -> CAESAR_SHIFT_4`

```
==xTe0KGIQNtotLP3McrEIqP6yctFIMNqnXMcWeK6WdQjyLP2x3IyWYuPIcHnkXQoA0DbuzP
```

### 4. BASE64

- **Status:** success
- **Score:** 140
- **Confidence:** MEDIUM
- **Chain:**
  - `BASE64`

```
b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ=='

```

### 5. ROT13

- **Status:** success
- **Score:** 140
- **Confidence:** MEDIUM
- **Chain:**
  - `ROT13`

```
LvqxZ0WkMTgjDyELqUSuE3t2LHufMzS6GaSyITjmJIEBpyu6LmEAnyI3LHpkpJMECG0aPt==
```

### 6. REVERSE

- **Status:** success
- **Score:** 140
- **Confidence:** MEDIUM
- **Chain:**
  - `REVERSE`

```
==gCn0TPRZWcxcUY3VlaNRzY6hlcORVWzwGVlFnT6FmZshUY2g3RhFHdYRlQwtGZxJ0MkdiY
```

### 7. CAESAR_SHIFT_1

- **Status:** success
- **Score:** 140
- **Confidence:** MEDIUM
- **Chain:**
  - `CAESAR_SHIFT_1`

```
ZjelN0KyAHuxRmSZeIGiS3h2ZVitAnG6UoGmWHxaXWSPdmi6ZaSObmW3ZVdydXASQU0oDh==
```

### 8. CAESAR_SHIFT_2

- **Status:** success
- **Score:** 140
- **Confidence:** MEDIUM
- **Chain:**
  - `CAESAR_SHIFT_2`

```
AkfmO0LzBIvySnTAfJHjT3i2AWjuBoH6VpHnXIybYXTQenj6AbTPcnX3AWezeYBTRV0pEi==
```

### 9. CAESAR_SHIFT_3

- **Status:** success
- **Score:** 140
- **Confidence:** MEDIUM
- **Chain:**
  - `CAESAR_SHIFT_3`

```
BlgnP0MaCJwzToUBgKIkU3j2BXkvCpI6WqIoYJzcZYURfok6BcUQdoY3BXfafZCUSW0qFj==
```

### 10. CAESAR_SHIFT_4

- **Status:** success
- **Score:** 140
- **Confidence:** MEDIUM
- **Chain:**
  - `CAESAR_SHIFT_4`

```
CmhoQ0NbDKxaUpVChLJlV3k2CYlwDqJ6XrJpZKadAZVSgpl6CdVRepZ3CYgbgADVTX0rGk==
```

## Skipped / Failed Details

- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token 'YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **BASE64** (skipped): input is not valid base64
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token 'b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ=='' in A1Z26 input
- **BASE64** (skipped): decoded base64 output is not readable UTF-8
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token 'LvqxZ0WkMTgjDyELqUSuE3t2LHufMzS6GaSyITjmJIEBpyu6LmEAnyI3LHpkpJMECG0aPt==' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **BASE64** (skipped): input is not valid base64
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token '==gCn0TPRZWcxcUY3VlaNRzY6hlcORVWzwGVlFnT6FmZshUY2g3RhFHdYRlQwtGZxJ0MkdiY' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **BASE64** (skipped): input is not valid base64
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token 'o'q3OdqxcOGKgdnTk6nUysnmAdrGy3LGAeKmp4ZwHjnT1dsD=='' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **BASE64** (skipped): input is not valid base64
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token ''==Qfq1GawUjM4czXrNTY3lTeqNzaflHa6xGaqtXTBpkdqB3d'b' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token 'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ==' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token 'YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **BASE64** (skipped): input is not valid base64
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token '==tPa0GCEMJpkpHL3IynAEmL6uypBEIJmjTIySaG6SzMfuHL2t3EuSUqLEyDjgTMkW0ZxqvL' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **BASE64** (skipped): input is not valid base64
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token ''==Dsd1TnjHwZ4pmKeAGL3yGrdAmnsyUn6kTndgKGOcxqdO3q'o' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **BASE64** (skipped): input is not valid base64
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token 'wpjvJAM{jhlzhy_k3jy9wa3k_78250hmj}' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **BASE64** (skipped): decoded base64 output is not readable UTF-8
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token 'q3OdqxcOGKgdnTk6nUysnmAdrGy3LGAeKmp4ZwHjnT1dsD==' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
- **BASE64** (skipped): input is not valid base64
- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token '==Qfq1GawUjM4czXrNTY3lTeqNzaflHa6xGaqtXTBpkdqB3d' in A1Z26 input
- **BYTES_LITERAL_EXTRACT** (skipped): input is not a Python bytes literal
