# pwn-helper v0.3

半自動 Pwn 題分析與求解工具。

## 支援題型
- `printf(buf)` / format string leak
- `strcpy/gets/read` 類 stack overflow
- 可執行 stack / RWX shellcode injection
- `win` 類 ret2win
- `signal(SIGSEGV, handler)` 類 crash-trigger handler
- `NX enabled + printf + strcpy + libc provided` 類 one_gadget / ret2libc

## 指令
- `analyze`
- `suggest`
- `strategy`
- `offset`
- `template`
- `fmt-scan`
- `landing-scan`
- `solve`
- `report`

## v0.3 新增
- `fmt-scan` 會輸出 `rank` 與 `reason`
- `strategy` 新增 `fmt-one-gadget`
- `suggest` 新增 `strcpy` 對 ROP chain 的 NUL 截斷提醒
- `solve` 新增 `fmt-one-gadget`

## 安裝
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 範例

### 分析
```bash
python3 main.py analyze ./gauntlet
python3 main.py suggest ./gauntlet
python3 main.py strategy ./gauntlet
```

### fmt 掃描
```bash
python3 main.py fmt-scan ./gauntlet --host wily-courier.picoctf.net --port 62738 --count 30
```

### one_gadget 類
```bash
python3 main.py solve ./gauntlet \
  --host wily-courier.picoctf.net --port 62738 \
  --mode fmt-one-gadget \
  --leak-slot 23 \
  --libc ./libc-2.27.so \
  --ret-delta 0xe7 \
  --one-gadget 0x4f2c5 \
  --offset 120
```
