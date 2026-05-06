# CTF Decode Helper - Script Reverse Report

## Summary

- **Status:** success
- **Detected Type:** rsa-encryption
- **Suggested Mode:** `crypto-rsa`

## Signals

### RSA_POW (HIGH)

- **Meaning:** RSA modular exponentiation detected.
- **Recommendation:** Run crypto-rsa after extracting n/e/c/p/q.
- **Evidence:** `) n = p * q e = 65537 m = bytes_to_long(flag) c = pow(m, e, n) print(n, e, c)`

### BYTES_TO_LONG (MEDIUM)

- **Meaning:** bytes_to_long conversion detected.
- **Recommendation:** Convert plaintext/ciphertext integers with long_to_bytes when reversing.
- **Evidence:** `me(512) q = getPrime(512) n = p * q e = 65537 m = bytes_to_long(flag) c = pow(m, e, n) print(n, e, c)`

### GET_PRIME (MEDIUM)

- **Meaning:** RSA prime generation detected.
- **Recommendation:** Look for generated p/q or leaked n/e/c values.
- **Evidence:** `es_to_long, getPrime  flag = b"picoCTF{demo}" p = getPrime(512) q = getPrime(512) n = p * q e = 65537 m = bytes_to_long(flag) c = pow(m, e,`


## Reverse Plan

- Extract n, e, c from the challenge text or script output.
- If p/q are present, compute phi=(p-1)*(q-1), d=inverse(e, phi), then m=pow(c,d,n).
- If p/q are not present, let crypto-rsa inspect e=3, small-n factorization, and Wiener conditions.
- Convert recovered integer plaintext with long_to_bytes.