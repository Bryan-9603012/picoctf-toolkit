# WSL / Ubuntu 使用方式

## 一鍵啟動互動式選單

```bash
cd /mnt/c/Users/10801/Downloads/picoctf-modular-toolkit-interactive-v5/picoctf-modular-toolkit
./run_wsl.sh
```

第一次執行會自動建立 `.venv`，並安裝 Web/Hunter-2 需要的 `PyYAML`、`requests`。

## Web 題 Hunter-2 流程

1. 執行 `./run_wsl.sh`
2. 選 `1. Web Exploitation`
3. 貼上 picoCTF 題目 URL
4. 選 `1. CTF 完整模式`

等同於呼叫：

```bash
python -m hunter.cli <URL> medium --mode ctf --report report
```

## 手動安裝依賴

```bash
./install_deps_wsl.sh
```

## 不用選單，直接跑 Web

```bash
./run_wsl.sh web http://example.picoctf.net:12345/ --mode ctf --report report
```
