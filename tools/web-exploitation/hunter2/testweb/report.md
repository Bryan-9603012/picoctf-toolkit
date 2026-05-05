# Hunter-2 安全掃描報告

**目標：** http://saturn.picoctf.net:60627

**產生時間：** 2026-04-16T06:00:47.671062 UTC

**輸出資料夾：** `loot`

**總發現數：** 1

## 摘要

- **敏感資訊外洩**：1 項

### 風險等級統計

- **重大**：0
- **高**：1
- **中**：0
- **低**：0
- **資訊**：0
- **未知**：0

### 驗證狀態統計

- **已觀察 (observed)**：0
- **可疑 (suspected)**：1
- **已驗證 (verified)**：0
- **已利用 (exploited)**：0

### 檔案分析統計

- **已分析檔案數**：0
- **已輸出修補檔數**：0
- **驗證成功次數**：0
- **驗證失敗次數**：0

---

# 敏感資訊外洩

## 1. passive-secrets

**風險等級：** 高

**驗證狀態：** 可疑

**信心水準：** medium

**網址：** `http://saturn.picoctf.net:60627/`

**證據：**

- `picoctf_flag:picoCTF{1n5p3t0r_0f_h7ml_fd5d57bd}`

**修補建議：** Remove secrets from client-facing responses; rotate exposed keys/tokens.

---

