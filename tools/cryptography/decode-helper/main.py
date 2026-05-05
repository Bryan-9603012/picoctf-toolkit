import argparse
import sys
import os

sys.path.insert(0, ".")

from src.decoder_engine import run_all_decoders, run_recursive_decoders
from src.reporter import generate_report
from src.utils import (
    print_header, print_input, print_best_candidate,
    print_results, print_report_saved, print_applicability,
)


def main():
    parser = argparse.ArgumentParser(
        description="CTF Decode Helper: try multiple keyless decoders and detect flags."
    )
    parser.add_argument(
        "input_text",
        nargs="?",
        default=None,
        help="Text to decode (if omitted, interactive mode)",
    )
    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Path to input file containing text to decode",
    )
    parser.add_argument(
        "--report",
        type=str,
        default=None,
        help="Path to save markdown report (e.g., reports/result.md)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top results to display (default: 10, 0 for all)",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        default=False,
        help="Enable confidence-ranked multi-layer decode mode",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=3,
        help="Maximum recursion depth for --recursive mode (default: 3)",
    )
    parser.add_argument(
        "--show-applicability",
        action="store_true",
        default=False,
        help="Show decoder applicability scores at each layer (for debugging)",
    )
    parser.add_argument(
        "--max-branch",
        type=int,
        default=5,
        help="Maximum number of decoders to expand per layer in --recursive mode (default: 5)",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        default=False,
        help="Compact mode: show Best Candidate + Top 3 summary only",
    )

    args = parser.parse_args()

    if args.input_text and args.file:
        print("Error: cannot specify both positional text and --file. Use one or the other.", file=sys.stderr)
        sys.exit(1)

    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                text = f.read().strip()
        except Exception as e:
            print(f"Error: failed to read file {args.file}: {e}", file=sys.stderr)
            sys.exit(1)
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
        display_results = results[:args.top]
        show_top = args.top
    else:
        display_results = results
        show_top = len(results)

    mode_parts = []
    if args.recursive:
        mode_parts.append("Recursive")
        mode_parts.append(f"Depth {args.depth}")
        mode_parts.append(f"Max-Branch {args.max_branch}")
    else:
        mode_parts.append("Single-pass")
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

    if args.report:
        report_top = 3 if args.compact else args.top
        path = generate_report(text, results, args.report, report_top, recursive=args.recursive)
        print_report_saved(path)


if __name__ == "__main__":
    main()
