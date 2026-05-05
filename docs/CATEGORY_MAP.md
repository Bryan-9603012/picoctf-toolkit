# picoCTF Category Mapping

| picoCTF Category | Toolkit command | Included tool | Purpose |
|---|---:|---|---|
| Web Exploitation | `web` | Hunter-2 | 掃描 picoCTF Web 題目、被動找 flag、規則掃描、產生 report。 |
| Cryptography | `crypto` | CTF Decode Helper | 處理 Base64、Hex、Binary、URL、ROT、ASCII、多層 keyless decode。 |
| Forensics | `forensics` | ArtifactScope | 分析 `.img`、檔案、字串、carving、Git/檔案系統 forensic 線索。 |
| Binary Exploitation | `binary` | Pwn Helper | ELF 保護分析、exploit 方向建議、pwntools template、format string/offset 輔助。 |
| Reverse Engineering | reserved | Not included yet | 之後可放 static/dynamic analysis helper。 |
| General Skills | reserved | Not included yet | 之後可放 Linux、grep、hash、archive、misc helper。 |

## Design decision

這個版本採用「單一入口 + 類別模組」：外層 `ctf.py` 負責分派，四個原工具仍保留各自資料夾與執行環境。這比把所有 Python 檔案混在同一層更穩，因為原工具存在不同 import 結構，例如 `src.*`、`hunter.*`、`artifactscope.*`、`pwn_helper.*`。
