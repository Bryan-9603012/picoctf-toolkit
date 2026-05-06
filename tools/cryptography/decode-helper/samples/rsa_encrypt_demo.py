from Crypto.Util.number import bytes_to_long, getPrime

flag = b"picoCTF{demo}"
p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537
m = bytes_to_long(flag)
c = pow(m, e, n)
print(n, e, c)
