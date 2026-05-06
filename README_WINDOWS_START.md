# Windows 啟動說明

目前最穩定的方式是：**在 Windows 雙擊 `ctf.bat`，由它自動轉進 WSL 執行 `run_wsl.sh`。**

## 建議流程

1. 先安裝並設定好 WSL Ubuntu
2. 雙擊 `ctf.bat`
3. 它會自動：
   - 取得目前資料夾對應的 WSL 路徑
   - 進入 WSL
   - 執行 `./run_wsl.sh`

## install_deps.bat

如果要先安裝依賴，可以雙擊：

```bat
install_deps.bat
```

它會優先呼叫：

```bash
./install_deps_wsl.sh
```

## 後備模式

若電腦沒有 WSL，`ctf.bat` 才會退回 Windows Python 模式。

## Log

若執行失敗，根目錄會保留：

```text
ctf-last-run.log
```

把畫面或這個 log 貼出來即可。
