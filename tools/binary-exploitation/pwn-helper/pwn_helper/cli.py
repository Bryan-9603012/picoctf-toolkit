
from __future__ import annotations
import argparse
import json
from pwn_helper.analyze import analyze_binary, pretty_print_result, result_to_dict
from pwn_helper.suggest import build_suggestions
from pwn_helper.strategy import choose_strategy
from pwn_helper.templates import build_template, save_template
from pwn_helper.fmt_scan import scan_fmt
from pwn_helper.landing_scan import scan_landing
from pwn_helper.offset import find_offset
from pwn_helper.solve import solve_handler_crash, solve_ret2win, solve_fmt_shellcode, solve_fmt_one_gadget
from pwn_helper.utils import save_json, parse_num_list

def _parse_int(s):
    return int(s, 0)

def cmd_analyze(args):
    res = analyze_binary(args.binary)
    if args.json:
        print(json.dumps(result_to_dict(res), indent=2, ensure_ascii=False))
    else:
        print(pretty_print_result(res))

def cmd_suggest(args):
    res = analyze_binary(args.binary)
    print(pretty_print_result(res))
    print("\n[+] Suggestions:")
    for s in build_suggestions(res):
        print(f"    - {s}")

def cmd_strategy(args):
    res = analyze_binary(args.binary)
    strat = choose_strategy(res)
    print(pretty_print_result(res))
    print("\n[+] Strategy:")
    print(json.dumps(strat, indent=2, ensure_ascii=False))

def cmd_template(args):
    content = build_template(args.binary, args.host, args.port)
    if args.output:
        save_template(args.output, content)
        print(f"[+] Template saved to {args.output}")
    else:
        print(content)

def cmd_fmt_scan(args):
    rows = scan_fmt(args.host, args.port, args.count)
    for row in rows:
        print(f"%{row['slot']}$p -> {row['value']} [{row['class']}] rank={row['rank']} reason={row['reason']}")
    if args.json_out:
        save_json(args.json_out, {"results": rows})
        print(f"[+] JSON saved to {args.json_out}")

def cmd_landing_scan(args):
    res = scan_landing(
        host=args.host,
        port=args.port,
        leak_slot=args.leak_slot,
        base_adjust=_parse_int(args.base_adjust),
        window=_parse_int(args.window),
        step=_parse_int(args.step),
        offset=args.offset,
        mode=args.mode,
        delay=args.delay,
        prefix_nops=args.prefix_nops,
    )
    if res is None:
        print("[-] No hit found in current scan window.")
        return
    print("[+] Hit found")
    print(json.dumps(res, indent=2, ensure_ascii=False))

def cmd_offset(args):
    print(json.dumps(find_offset(args.binary, args.length), indent=2, ensure_ascii=False))

def cmd_solve(args):
    if args.mode == "handler-crash":
        res = solve_handler_crash(args.host, args.port, line1=args.line1, lengths=parse_num_list(args.lengths))
    elif args.mode == "ret2win":
        res = solve_ret2win(args.host, args.port, target=_parse_int(args.target), offset=args.offset, line1=args.line1)
    elif args.mode == "fmt-shellcode":
        res = solve_fmt_shellcode(
            args.host, args.port, leak_slot=args.leak_slot, base_adjust=_parse_int(args.base_adjust),
            offset=args.offset, payload=args.payload, prefix_nops=args.prefix_nops, line_after=args.line_after,
        )
    elif args.mode == "fmt-one-gadget":
        res = solve_fmt_one_gadget(
            args.host, args.port, leak_slot=args.leak_slot, libc_path=args.libc,
            ret_delta=_parse_int(args.ret_delta), one_gadget=_parse_int(args.one_gadget), offset=args.offset,
        )
    else:
        raise ValueError("unknown mode")
    print(json.dumps(res, indent=2, ensure_ascii=False))

def cmd_report(args):
    res = analyze_binary(args.binary)
    data = result_to_dict(res)
    data["suggestions"] = build_suggestions(res)
    data["strategy"] = choose_strategy(res)
    save_json(args.output, data)
    print(f"[+] Report saved to {args.output}")

def build_parser():
    p = argparse.ArgumentParser(prog="pwn-helper", description="Semi-automatic pwn helper")
    sub = p.add_subparsers(dest="command", required=True)

    p1 = sub.add_parser("analyze", help="Analyze ELF and protections")
    p1.add_argument("binary")
    p1.add_argument("--json", action="store_true")
    p1.set_defaults(func=cmd_analyze)

    p2 = sub.add_parser("suggest", help="Suggest exploit paths")
    p2.add_argument("binary")
    p2.set_defaults(func=cmd_suggest)

    p3 = sub.add_parser("strategy", help="Choose likely exploit strategy")
    p3.add_argument("binary")
    p3.set_defaults(func=cmd_strategy)

    p4 = sub.add_parser("template", help="Generate pwntools template")
    p4.add_argument("binary")
    p4.add_argument("--host", required=True)
    p4.add_argument("--port", type=int, required=True)
    p4.add_argument("-o", "--output")
    p4.set_defaults(func=cmd_template)

    p5 = sub.add_parser("fmt-scan", help="Scan format string slots")
    p5.add_argument("binary")
    p5.add_argument("--host", required=True)
    p5.add_argument("--port", type=int, required=True)
    p5.add_argument("--count", type=int, default=30)
    p5.add_argument("--json-out")
    p5.set_defaults(func=cmd_fmt_scan)

    p6 = sub.add_parser("landing-scan", help="Scan shellcode landing around a base adjustment")
    p6.add_argument("binary")
    p6.add_argument("--host", required=True)
    p6.add_argument("--port", type=int, required=True)
    p6.add_argument("--leak-slot", type=int, required=True)
    p6.add_argument("--base-adjust", required=True)
    p6.add_argument("--window", default="0x40")
    p6.add_argument("--step", default="0x8")
    p6.add_argument("--offset", type=int, default=120)
    p6.add_argument("--mode", choices=["ok", "cat"], default="ok")
    p6.add_argument("--delay", type=float, default=0.8)
    p6.add_argument("--prefix-nops", type=int, default=48)
    p6.set_defaults(func=cmd_landing_scan)

    p7 = sub.add_parser("offset", help="Find RIP offset (currently entry/helper)")
    p7.add_argument("binary")
    p7.add_argument("--length", type=int, default=400)
    p7.set_defaults(func=cmd_offset)

    p8 = sub.add_parser("solve", help="Semi-automatic solver")
    p8.add_argument("binary")
    p8.add_argument("--host", required=True)
    p8.add_argument("--port", type=int, required=True)
    p8.add_argument("--mode", required=True, choices=["handler-crash", "ret2win", "fmt-shellcode", "fmt-one-gadget"])
    p8.add_argument("--line1", default="test")
    p8.add_argument("--lengths", default="200,300,400,600")
    p8.add_argument("--target")
    p8.add_argument("--offset", type=int, default=120)
    p8.add_argument("--leak-slot", type=int)
    p8.add_argument("--base-adjust")
    p8.add_argument("--payload", choices=["cat", "sh", "ok"], default="cat")
    p8.add_argument("--prefix-nops", type=int, default=48)
    p8.add_argument("--line-after")
    p8.add_argument("--libc")
    p8.add_argument("--ret-delta")
    p8.add_argument("--one-gadget")
    p8.set_defaults(func=cmd_solve)

    p9 = sub.add_parser("report", help="Export analysis report as JSON")
    p9.add_argument("binary")
    p9.add_argument("-o", "--output", required=True)
    p9.set_defaults(func=cmd_report)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
