import argparse
import os
import sys

sys.path.insert(0, ".")

from src.decoder_engine import run_all_decoders, run_recursive_decoders
from src.reporter import generate_report, generate_json_report
from src.utils import (
    print_header,
    print_input,
    print_best_candidate,
    print_results,
    print_report_saved,
    print_applicability,
)
from src.rsa_helper import parse_rsa_text, run_rsa_mode, generate_rsa_report
from src.script_reverse import analyze_script_file, generate_script_reverse_report


def _read_text_file(path: str) -> str:
    if not os.path.exists(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as ex:
        print(f"Error: failed to read file {path}: {ex}", file=sys.stderr)
        sys.exit(1)


def _print_rsa_result(result) -> None:
    print("## Attack Results")
    print()
    print(f"**Status:** {result.status.upper()}")
    print(f"**Selected attack:** {result.attack}")
    if result.tried_attacks:
        print(f"**Tried attacks:** {', '.join(result.tried_attacks)}")
    if result.notes:
        print()
        print("### Analysis Notes")
        for note in result.notes:
            print(f"- {note}")
    if result.d is not None:
        print()
        print("### Recovered d")
        d_str = str(result.d)
        print(f"`{d_str[:80]}{'...' if len(d_str) > 80 else ''}`")
    if result.plaintext_int is not None:
        print()
        print("### Plaintext (integer)")
        p_str = str(result.plaintext_int)
        print(f"`{p_str[:100]}{'...' if len(p_str) > 100 else ''}`")
        print()
        print("### Plaintext (hex)")
        print(f"`{result.plaintext_hex}`")
        print()
        print("### Plaintext (bytes)")
        print(f"`{result.plaintext_bytes_repr}`")
    if result.plaintext_text:
        print()
        print("### Plaintext (utf-8 best effort)")
        print(result.plaintext_text)
    if result.found_flag:
        print()
        print("**Flag found:**", f"`{result.found_flag}`")
    else:
        print()
        print("**Flag found:** None")
        if result.reason:
            print(result.reason)


def run_direct_decode(args) -> None:
    if args.input_text and args.file:
        print("Error: cannot specify both positional text and --file. Use one or the other.", file=sys.stderr)
        sys.exit(1)

    if args.file:
        text = _read_text_file(args.file).strip()
        if not text:
            print("No input found in file. Exiting.", file=sys.stderr)
            sys.exit(0)
    elif args.input_text:
        text = args.input_text
    else:
        print_header("CTF Decode Helper")
        text = input("Enter text to decode: ").strip()
        if not text:
            print("No input provided. Exiting.")
            sys.exit(0)

    if args.recursive:
        applicability_log = [] if args.show_applicability else None
        results = run_recursive_decoders(
            text,
            max_depth=args.depth,
            max_branch=args.max_branch,
            show_applicability=args.show_applicability,
            applicability_log=applicability_log,
        )
        if applicability_log:
            print()
            print_applicability(applicability_log)
            print()
    else:
        results = run_all_decoders(text)

    if args.compact:
        display_results = results[:3]
        show_top = 3
    elif args.top > 0:
        display_results = results[: args.top]
        show_top = args.top
    else:
        display_results = results
        show_top = len(results)

    mode_parts = []
    if args.recursive:
        mode_parts += ["Recursive", "direct-decode", f"Depth {args.depth}", f"Max-Branch {args.max_branch}"]
    else:
        mode_parts += ["Single-pass", "direct-decode"]
    if args.compact:
        mode_parts.append("Compact")

    print_header("CTF Decode Helper")
    print(f"[{' / '.join(mode_parts)}]")
    print_input(text)

    if args.recursive and display_results:
        best = display_results[0]
        if best.status == "success" and best.output and best.flags:
            print_best_candidate(best)

    print_results(display_results)

    report_top = 3 if args.compact else args.top
    if args.report:
        path = generate_report(text, results, args.report, report_top, recursive=args.recursive)
        print_report_saved(path)
    if args.report_md:
        path = generate_report(text, results, args.report_md, report_top, recursive=args.recursive)
        print_report_saved(path)
    if args.report_json:
        path = generate_json_report(text, results, args.report_json, report_top, recursive=args.recursive)
        print_report_saved(path)


def run_crypto_rsa(args) -> None:
    if args.input_text:
        print("Error: positional input is not used in RSA mode. Use --file or --n/--e/--c.", file=sys.stderr)
        sys.exit(1)
    if args.file and any([args.n, args.e, args.c]):
        print("Error: cannot combine --file with --n/--e/--c in RSA mode.", file=sys.stderr)
        sys.exit(1)
    if args.file:
        rsa_text = _read_text_file(args.file)
        try:
            rsa_input = parse_rsa_text(rsa_text)
        except ValueError as ex:
            print(f"Error: {ex}", file=sys.stderr)
            sys.exit(1)
    elif args.n and args.e and args.c:
        try:
            rsa_input = parse_rsa_text(f"n = {args.n}\ne = {args.e}\nc = {args.c}\n")
        except ValueError as ex:
            print(f"Error: {ex}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: RSA mode requires --file or all of --n --e --c.", file=sys.stderr)
        sys.exit(1)

    print_header("CTF Decode Helper - Crypto RSA Mode")
    if rsa_input.n is not None or rsa_input.e is not None or rsa_input.c is not None:
        print(f"n = {rsa_input.n}")
        print(f"e = {rsa_input.e}")
        print(f"c = {rsa_input.c}")
    if rsa_input.groups:
        print("groups:")
        for idx, group in enumerate(rsa_input.groups, start=1):
            print(f"  [{idx}] n = {group['n']}")
            print(f"      e = {group['e']}")
            print(f"      c = {group['c']}")
    for key in ("p", "q", "phi", "d", "dp", "dq", "qinv"):
        value = getattr(rsa_input, key)
        if value is not None:
            print(f"{key} = {value}")
    print()
    result = run_rsa_mode(rsa_input)
    _print_rsa_result(result)

    out_path = args.report or args.report_md
    if out_path:
        path = generate_rsa_report(rsa_input, result, out_path)
        print()
        print_report_saved(path)


def run_script_reverse(args) -> None:
    if not args.file:
        print("Error: script-reverse mode requires --file encrypt.py", file=sys.stderr)
        sys.exit(1)
    try:
        result = analyze_script_file(args.file)
    except FileNotFoundError:
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    print_header("CTF Decode Helper - Script Reverse Mode")
    print(f"Status: {result.status}")
    print(f"Detected type: {result.script_type}")
    print(f"Suggested next mode: {result.suggested_mode}")
    print()
    print("## Signals")
    if not result.signals:
        print("- No strong crypto/decode signal detected.")
    else:
        for sig in result.signals:
            print(f"- [{sig.severity}] {sig.name}: {sig.meaning}")
            print(f"  Evidence: {sig.evidence[:160]}")
            print(f"  Next: {sig.recommendation}")
    print()
    print("## Reverse Plan")
    for step in result.reverse_plan:
        print(f"- {step}")

    out_path = args.report or args.report_md
    if out_path:
        path = generate_script_reverse_report(result, out_path)
        print()
        print_report_saved(path)


def main():
    parser = argparse.ArgumentParser(
        description="CTF Decode Helper: direct decode + RSA helper + script reverse scanner."
    )
    parser.add_argument(
        "--mode",
        choices=["direct-decode", "decode", "crypto-rsa", "rsa", "script-reverse"],
        default="direct-decode",
        help="Tool mode. Aliases: decode=direct-decode, rsa=crypto-rsa.",
    )
    parser.add_argument("input_text", nargs="?", default=None, help="Text to decode for direct-decode mode")
    parser.add_argument("--file", type=str, default=None, help="Input file path")
    parser.add_argument("--n", type=str, default=None, help="RSA modulus n for crypto-rsa mode")
    parser.add_argument("--e", type=str, default=None, help="RSA public exponent e for crypto-rsa mode")
    parser.add_argument("--c", type=str, default=None, help="RSA ciphertext c for crypto-rsa mode")
    parser.add_argument("--report", type=str, default=None, help="Backward-compatible markdown report path")
    parser.add_argument("--report-md", type=str, default=None, help="Path to save markdown report")
    parser.add_argument("--report-json", type=str, default=None, help="Path to save JSON report for direct-decode mode")
    parser.add_argument("--top", type=int, default=10, help="Number of top results to display (default: 10, 0 for all)")
    parser.add_argument("--recursive", action="store_true", default=False, help="Enable confidence-ranked multi-layer decode mode")
    parser.add_argument("--depth", type=int, default=3, help="Maximum recursion depth for --recursive mode")
    parser.add_argument("--show-applicability", action="store_true", default=False, help="Show decoder applicability scores")
    parser.add_argument("--max-branch", type=int, default=5, help="Maximum decoders to expand per layer")
    parser.add_argument("--compact", action="store_true", default=False, help="Show Best Candidate + Top 3 only")

    args = parser.parse_args()
    mode = {"decode": "direct-decode", "rsa": "crypto-rsa"}.get(args.mode, args.mode)
    if mode == "direct-decode":
        run_direct_decode(args)
    elif mode == "crypto-rsa":
        run_crypto_rsa(args)
    elif mode == "script-reverse":
        run_script_reverse(args)
    else:
        print(f"Error: unknown mode: {args.mode}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
