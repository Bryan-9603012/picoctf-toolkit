# Windows 啟動說明

建議優先雙擊：

```bat
ctf.bat
```

如果雙擊後仍然閃退，請改用 CMD / PowerShell 進入資料夾後執行：

```bat
ctf.bat
```

本版會在根目錄產生：

```text
ctf-last-run.log
```

若出錯，請把畫面或這個 log 貼給我。

## 依賴安裝

如果 Web 模式缺少 `PyYAML` 或 `requests`，可以先雙擊：

```bat
install_deps.bat
```

或手動執行：

```bat
py -3 -m pip install PyYAML requests
```

## 不建議

不建議用 MSYS2 的 Python 直接跑，因為它常見問題是沒有 pip：

```text
C:\msys64\ucrt64\bin\python.exe: No module named pip
```

建議安裝 Windows 官方 Python，或用 `py -3 ctf.py` 啟動。
