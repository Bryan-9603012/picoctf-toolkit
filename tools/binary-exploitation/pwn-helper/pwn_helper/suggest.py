
from __future__ import annotations

def build_suggestions(res):
    out = []
    pats = set(res.patterns)
    danger = set(res.dangerous_functions)
    pie = (res.checksec.get("pie") or "").lower()
    nx = (res.checksec.get("nx") or "").lower()
    rwx = (res.checksec.get("rwx_segments") or "").lower()

    if "ret2win_candidate" in pats:
        out.append("優先檢查是否可直接覆蓋 RIP 到 win。")
    if "format_string_plus_stack_overflow" in pats:
        out.append("先用 format string 掃 `%1$p ~ %30$p`，分類 stack / code / libc 類位址。")
    if "shellcode_injection_candidate" in pats:
        out.append("若 stack 可執行，優先考慮 leak 後做 shellcode landing。")
    if "fmt_ret2libc_candidate" in pats:
        out.append("NX 啟用時，優先考慮 ret2libc / one_gadget，而非 stack shellcode。")
    if "strcpy_copy_path" in pats:
        out.append("注意：payload 經 strcpy 複製時，長 ROP chain 可能因 NUL byte 被提早截斷。")
        out.append("若 leak 到 libc，one_gadget 常比長 ret2libc 鏈更穩。")
    if "signal_handler_path" in pats:
        out.append("檢查是否存在 crash-trigger 路線，例如 SIGSEGV handler 直接印 flag。")
    if "printf" in danger and "strcpy" in danger and ("exec" in nx or "has rwx" in rwx):
        out.append("這很像 Binary Gauntlet 1/2 類題型：format string leak -> overflow -> shellcode。")
    if "no pie" in pie:
        out.append("PIE 關閉，binary base 固定；若有 win/system/plt 可考慮直接覆蓋。")
    if not out:
        out.append("暫時沒有明確 heuristics，建議先檢查 main、危險函式與可疑輸出。")
    return out
