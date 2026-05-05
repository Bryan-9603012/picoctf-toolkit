from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

from .analyzer import analyze_file
from .reporter import render_terminal_summary, write_json_report, write_markdown_report
from .utils import ensure_dir, iter_files


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ArtifactScope",
        description="Security-oriented file triage and artifact analysis tool.",
    )
    parser.add_argument("target", help="Target file or directory to analyze.")
    parser.add_argument("--recursive", action="store_true", help="Recursively analyze files in a directory.")
    parser.add_argument("--strings", action="store_true", help="Enable string extraction and IOC-like pattern scan.")
    parser.add_argument("--carve", action="store_true", help="Enable embedded file carving.")
    parser.add_argument("--mount", "--mount-git", dest="mount", action="store_true", help="Enable deep forensic recovery (mount/fallback/Git recovery).")
    parser.add_argument("--git", action="store_true", help="Prefer deep Git forensic recovery when Git artifacts are detected.")
    parser.add_argument("--full-recover", action="store_true", help="Allow full partition recovery with tsk_recover as a last resort.")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout in seconds for external forensic tools.")
    parser.add_argument("--report", action="store_true", help="Write both JSON and Markdown reports to output/.")
    parser.add_argument("--report-json", action="store_true", help="Write a JSON report to output/." )
    parser.add_argument("--report-md", action="store_true", help="Write a Markdown report to output/." )
    parser.add_argument("--output-dir", default="output", help="Directory for reports and analysis artifacts.")
    parser.add_argument("--rules", default="rules/default_rules.yaml", help="Path to YAML rules file.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        parser.error(f"Target not found: {target}")

    rules_path = Path(args.rules)
    if not rules_path.exists():
        parser.error(f"Rules file not found: {rules_path}")

    output_dir = ensure_dir(Path(args.output_dir))
    carve_dir = ensure_dir(output_dir / "carved") if args.carve else None

    results: List[dict] = []
    for file_path in iter_files(target, recursive=args.recursive):
        per_file_output = ensure_dir(output_dir / file_path.stem)
        try:
            result = analyze_file(
                file_path,
                rules_path=rules_path,
                scan_strings=args.strings,
                carve=args.carve,
                carve_dir=carve_dir,
                mount_git=args.mount,
                output_dir=per_file_output,
                full_recover=args.full_recover,
                timeout=args.timeout,
                git_mode=args.git,
            )
            results.append(result)
        except Exception as exc:
            results.append({
                "file_info": {
                    "name": file_path.name,
                    "path": str(file_path.resolve()),
                    "extension": file_path.suffix.lower(),
                    "size": 0,
                    "created": "N/A",
                    "modified": "N/A",
                },
                "error": str(exc),
                "hashes": {},
                "signature": {
                    "name": "Error",
                    "type": "error",
                    "extension_matches": False,
                    "expected_extensions": [],
                },
                "entropy": {"score": 0.0, "classification": "unknown"},
                "embedded": [],
                "carved": [],
                "risk": {"findings": [], "risk_score": 0, "risk_level": "Unknown"},
                "verified_flags": [],
                "flag_candidates": [],
                "forensic_leads": [],
                "access_trace": [],
            })

    print(render_terminal_summary(results))

    if args.report:
        args.report_json = True
        args.report_md = True

    if args.report_json:
        json_path = output_dir / "artifactscope_report.json"
        write_json_report(results, json_path)
        print(f"[+] JSON report written to: {json_path}")

    if args.report_md:
        md_path = output_dir / "artifactscope_report.md"
        write_markdown_report(results, md_path)
        print(f"[+] Markdown report written to: {md_path}")

    return 0
