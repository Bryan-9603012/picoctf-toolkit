# PicoCTF Modular Toolkit - Run Notes

## Recommended on Windows

Double-click:

```bat
ctf.bat
```

The launcher prefers the official Windows Python launcher `py -3` when available. This avoids MSYS2 Python builds that may not include `pip`.

## If you see `No module named pip`

You are probably running MSYS2/UCRT64 Python:

```text
C:\msys64\ucrt64\bin\python.exe
```

Recommended fixes:

```bat
py -3 ctf.py
```

or install pip in MSYS2 UCRT64:

```bash
pacman -S mingw-w64-ucrt-x86_64-python-pip
```

Then install the Web dependencies:

```bat
py -3 -m pip install PyYAML requests
```
