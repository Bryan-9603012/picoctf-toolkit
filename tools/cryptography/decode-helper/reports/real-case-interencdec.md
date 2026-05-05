# CTF Decode Helper Report

## Input

```
YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==
```

## Summary

- Total methods: 33
- Displayed results: 10
- Success: 29
- Skipped: 4
- Failed: 0

## Results

### 1. BASE64

- **Status:** success
- **Score:** 20

```
b'd3BqdkpBTXtqaGx6aHlfazNqeTl3YTNrXzc4MjUwaG1qfQ=='

```

### 2. ROT13

- **Status:** success
- **Score:** 20

```
LvqxZ0WkMTgjDyELqUSuE3t2LHufMzS6GaSyITjmJIEBpyu6LmEAnyI3LHpkpJMECG0aPt==
```

### 3. REVERSE

- **Status:** success
- **Score:** 20

```
==gCn0TPRZWcxcUY3VlaNRzY6hlcORVWzwGVlFnT6FmZshUY2g3RhFHdYRlQwtGZxJ0MkdiY
```

### 4. URL_DECODE

- **Status:** success
- **Score:** 20
- **Reason:** no URL encoding detected

```
YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==
```

### 5. CAESAR_SHIFT_1

- **Status:** success
- **Score:** 20

```
ZjelN0KyAHuxRmSZeIGiS3h2ZVitAnG6UoGmWHxaXWSPdmi6ZaSObmW3ZVdydXASQU0oDh==
```

### 6. CAESAR_SHIFT_2

- **Status:** success
- **Score:** 20

```
AkfmO0LzBIvySnTAfJHjT3i2AWjuBoH6VpHnXIybYXTQenj6AbTPcnX3AWezeYBTRV0pEi==
```

### 7. CAESAR_SHIFT_3

- **Status:** success
- **Score:** 20

```
BlgnP0MaCJwzToUBgKIkU3j2BXkvCpI6WqIoYJzcZYURfok6BcUQdoY3BXfafZCUSW0qFj==
```

### 8. CAESAR_SHIFT_4

- **Status:** success
- **Score:** 20

```
CmhoQ0NbDKxaUpVChLJlV3k2CYlwDqJ6XrJpZKadAZVSgpl6CdVRepZ3CYgbgADVTX0rGk==
```

### 9. CAESAR_SHIFT_5

- **Status:** success
- **Score:** 20

```
DnipR0OcELybVqWDiMKmW3l2DZmxErK6YsKqALbeBAWThqm6DeWSfqA3DZhchBEWUY0sHl==
```

### 10. CAESAR_SHIFT_6

- **Status:** success
- **Score:** 20

```
EojqS0PdFMzcWrXEjNLnX3m2EAnyFsL6ZtLrBMcfCBXUirn6EfXTgrB3EAidiCFXVZ0tIm==
```

## Skipped / Failed Details

- **HEX** (skipped): input is not valid hex (length must be even, only 0-9a-fA-F allowed)
- **BINARY** (skipped): input is not valid binary (only 0/1 allowed, length must be multiple of 8)
- **ASCII_DECIMAL** (skipped): input is not valid ASCII decimal (space-separated numbers 0-255 expected)
- **A1Z26** (skipped): unsupported token 'YidkM0JxZGtwQlRYdHFhR3g2YUhsZmF6TnFlVGwzWVROclh6YzRNalV3YUcxcWZRPT0nCg==' in A1Z26 input
