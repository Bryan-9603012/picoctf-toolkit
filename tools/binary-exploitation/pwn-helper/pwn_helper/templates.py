
from pathlib import Path

def build_template(binary, host, port):
    return f'''from pwn import *

context.binary = "{binary}"
context.arch = "amd64"

HOST = "{host}"
PORT = {port}

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(context.binary)

io = start()

# TODO:
# 1. recv 初始輸出 / leak
# 2. send 第一段 payload
# 3. send 第二段 payload
# 4. 根據題型改成 recvall() 或 interactive()

io.interactive()
'''

def save_template(path, content):
    Path(path).write_text(content, encoding="utf-8")
