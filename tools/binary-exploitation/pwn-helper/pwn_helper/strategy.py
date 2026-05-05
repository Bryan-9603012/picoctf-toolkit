
from __future__ import annotations

def choose_strategy(res):
    pats = set(res.patterns)
    if "signal_handler_path" in pats:
        return {"mode": "handler-crash", "reason": "偵測到 signal/handler 類路徑，適合直接 crash 觸發。"}
    if "ret2win_candidate" in pats:
        return {"mode": "ret2win", "reason": "偵測到 win 符號，優先嘗試 ret2win。"}
    if "fmt_ret2libc_candidate" in pats and "strcpy_copy_path" in pats:
        return {"mode": "fmt-one-gadget", "reason": "NX 啟用且存在 printf+strcpy，one_gadget 通常比長 ROP chain 穩定。"}
    if "fmt_ret2libc_candidate" in pats:
        return {"mode": "fmt-ret2libc", "reason": "偵測到 printf+strcpy 且 NX 啟用，適合 leak libc 後 ret2libc。"}
    if "format_string_plus_stack_overflow" in pats and "shellcode_injection_candidate" in pats:
        return {"mode": "fmt-shellcode", "reason": "偵測到 printf+strcpy 且 stack 可執行，適合 leak + shellcode。"}
    return {"mode": "manual", "reason": "沒有找到足夠明確的自動策略，建議手動分析。"}
