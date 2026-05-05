# hunter.py
from __future__ import annotations

import argparse
import os

from config.config import Config
from config.defaults import default_config
from config.yaml_config import find_config_file, load_yaml_config, merge_yaml_to_args
from fingerprint.fingerprint import fingerprint_target
from fingerprint.loader import load_fingerprint_dbs
from rules.loader import load_rules, list_packs, list_rules_in_pack
from core.models import severity_rank

from enumeration.enumerator import enumerate_targets
from scanning.rule_engine.runner import run_rules
from scanning.passive.passive_scan import run_passive_scan
from scanning.fuzz.runner import run_fuzz

from postprocess.dedupe import dedupe_findings_prefer_chain
from postprocess.baseline import (
    load_baseline,
    compare_with_baseline,
    write_delta_report,
    print_delta_summary,
    filter_new_only_by_severity,
    BaselineReport,
)
from postprocess.suppression import (
    apply_suppressions,
    SuppressionStore,
)
from postprocess.risk import score_findings
from postprocess.artifact_analyzer import collect_artifacts
from postprocess.ctf import extract_all_ctf_data
from reports.markdown import write_markdown
from reports.json_report import write_json
from reports.html import write_html


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Hunter v2 - Enterprise-grade rule-based web security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s http://example.com                           # Basic scan
  %(prog)s http://example.com --policy balanced         # With policy
  %(prog)s http://example.com --baseline scan.json     # With baseline
  %(prog)s http://target --fail-on high                 # CI integration
  %(prog)s http://target --metrics                      # Show metrics

See docs/samples/CLI_USAGE.md for more examples.
        """
    )
    
    ap.add_argument("--version", action="version", version="%(prog)s 1.0.0")
    
    ap.add_argument("base", help="Base URL, e.g. http://host:port")
    ap.add_argument(
        "speed",
        nargs="?",
        default="medium",
        choices=["fast", "medium", "slow"],
        help="Scan speed profile: fast | medium | slow (default: medium)",
    )

    ap.add_argument(
        "--mode",
        default="",
        choices=["", "ctf", "web", "stealth"],
        help="Preset mode: ctf | web | stealth",
    )

    ap.add_argument(
        "--policy",
        default="balanced",
        choices=["safe", "balanced", "aggressive"],
        help="Scan policy: safe (no impact) | balanced | aggressive (full testing) (default: balanced)",
    )

    ap.add_argument(
        "--env",
        default="unknown",
        choices=["dev", "staging", "prod", "unknown"],
        help="Target environment: dev | staging | prod | unknown (default: unknown)",
    )

    ap.add_argument("--pack", default="auto", help="Rule pack(s): auto | ctf | spring | web-misconfig | comma-separated")
    ap.add_argument("--rules-dir", default="rules", help="Rules directory (default: rules)")
    ap.add_argument("--outdir", default="loot", help="Artifact output directory (default: loot)")
    ap.add_argument("--report", default="report", help="Report basename (default: report => report.md/.json/.html)")

    ap.add_argument("--qps", type=float, default=2.0, help="Global request rate limit QPS (default: 2.0)")
    ap.add_argument("--timeout", type=float, default=12.0, help="Request timeout seconds (default: 12)")
    ap.add_argument("--retries", type=int, default=1, help="Retries on network errors (default: 1)")
    ap.add_argument("--threads", type=int, default=5, help="Concurrency threads (default: 5)")
    ap.add_argument("--max-requests", type=int, default=0, help="Hard cap total HTTP requests (0=unlimited)")

    ap.add_argument("--allow-host", action="append", default=[], help="Exact allowed host (repeatable)")
    ap.add_argument("--allow-suffix", action="append", default=[], help="Allowed host suffix like picoctf.net (repeatable)")
    ap.add_argument("--exclude", action="append", default=[], help="Exclude URL pattern (repeatable)")
    ap.add_argument("--deny-private", action="store_true", help="Deny localhost/private/reserved IP targets (safety)")

    ap.add_argument("--no-redirects", action="store_true", help="Disable redirects globally")
    ap.add_argument("--print-matches", action="store_true", help="Print regex matches to console when found")
    ap.add_argument("--verbose", action="store_true", help="Verbose output")
    ap.add_argument("--proxy", default="", help="Proxy URL, e.g. http://127.0.0.1:8080 (Burp)")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification (useful with Burp)")
    ap.add_argument("--header", action="append", default=[], help='Extra header "K: V" (repeatable)')
    ap.add_argument("--cookie", default="", help='Cookie header value, e.g. "a=b; c=d"')
    ap.add_argument("--bearer", default="", help="Authorization Bearer token")

    ap.add_argument("--discover", action="store_true", help="Enable common path discovery (robots/sitemap/swagger etc)")
    ap.add_argument("--crawl", action="store_true", help="Enable same-origin crawl (HTML/JS endpoint discovery)")
    ap.add_argument("--crawl-depth", type=int, default=2)
    ap.add_argument("--crawl-max-pages", type=int, default=60)
    ap.add_argument("--seed", action="append", default=[], help="Seed path, repeatable (e.g. /login)")
    ap.add_argument("--seeds-file", default="", help="File with seed paths, one per line")

    ap.add_argument("--passive", action="store_true", help="Enable passive secrets scan (HTML/JS/JSON)")
    ap.add_argument("--fuzz", action="append", default=[], help="Enable fuzz payload set, repeatable: lfi/sqli/xss/ssrf")
    ap.add_argument("--fuzz-target", action="append", default=[], help="Template path with FUZZ, repeatable")
    ap.add_argument("--payload-dir", default="payloads", help="Payload directory (default: payloads)")

    ap.add_argument("--artifact-analysis", action="store_true", help="Enable artifact analysis (files from loot/)")
    ap.add_argument("--save-artifacts", action="store_true", help="Save downloaded artifacts")
    ap.add_argument("--max-artifact-mb", type=int, default=10, help="Max artifact size in MB (default: 10)")

    ap.add_argument(
        "--fail-on",
        default="",
        choices=["", "critical", "high", "medium", "low"],
        help="Exit with error code if findings at or above severity found (CI integration)",
    )
    ap.add_argument("--fail-verified-only", action="store_true", help="Only fail on verified/exploited findings")
    ap.add_argument("--fail-exploited-only", action="store_true", help="Only fail on exploited findings")
    ap.add_argument(
        "--fail-on-new",
        default="",
        choices=["", "critical", "high", "medium", "low"],
        help="Only fail on NEW findings (requires --baseline)",
    )
    ap.add_argument(
        "--fail-on-changed",
        default="",
        choices=["", "critical", "high", "medium", "low"],
        help="Only fail on findings with changed severity (requires --baseline)",
    )
    ap.add_argument(
        "--fail-on-delta-only",
        action="store_true",
        help="Only fail on findings that differ from baseline (new/changed/resolved)",
    )
    ap.add_argument(
        "--ignore-expired-suppressions",
        action="store_true",
        help="Ignore expired suppressions (default: false - expired suppressions are not applied)",
    )

    ap.add_argument(
        "--baseline",
        default="",
        help="Baseline report.json to compare against (for delta reporting)",
    )
    ap.add_argument(
        "--new-only",
        action="store_true",
        help="Only show new findings compared to baseline (CI friendly)",
    )

    ap.add_argument(
        "--suppressions",
        default="",
        help="Suppressions file (JSON)",
    )
    ap.add_argument(
        "--hide-suppressed",
        action="store_true",
        help="Hide suppressed findings from output",
    )

    ap.add_argument("--html", action="store_true", help="Generate HTML report")
    ap.add_argument(
        "--metrics",
        action="store_true",
        help="Print metrics summary after scan",
    )
    ap.add_argument("--dry-run", action="store_true", help="Preview mode: show what would be done without executing")
    ap.add_argument("--stop-on-high-confidence", action="store_true", help="Stop scan when high confidence finding (CTF mode)")

    ap.add_argument("--list-packs", action="store_true", help="List available packs and exit")
    ap.add_argument("--list-rules", metavar="PACK", help="List rules in pack and exit")
    ap.add_argument("--init-config", action="store_true", help="Create example hunter.yaml config file and exit")

    return ap.parse_args()


def apply_speed_profile(args: argparse.Namespace) -> None:
    speed = (args.speed or "medium").lower().strip()
    policy = (args.policy or "balanced").lower().strip()

    if speed == "fast":
        args.discover = True if args.discover is False else args.discover
        args.passive = True if args.passive is False else args.passive
        args.qps = 4.0 if args.qps == 2.0 else args.qps
        args.threads = 6 if args.threads == 5 else args.threads
        args.max_requests = 100 if args.max_requests == 0 else args.max_requests
        args.artifact_analysis = False
        args.save_artifacts = False
    elif speed == "slow":
        args.discover = True if args.discover is False else args.discover
        args.crawl = True if args.crawl is False else args.crawl
        args.passive = True if args.passive is False else args.passive
        args.qps = 0.8 if args.qps == 2.0 else args.qps
        args.threads = 2 if args.threads == 5 else args.threads
        args.retries = 3 if args.retries == 1 else args.retries
        args.timeout = 18.0 if args.timeout == 12.0 else args.timeout
        args.max_requests = 220 if args.max_requests == 0 else args.max_requests
        args.artifact_analysis = True
        args.save_artifacts = True
    else:
        args.discover = True if args.discover is False else args.discover
        args.crawl = True if args.crawl is False else args.crawl
        args.passive = True if args.passive is False else args.passive
        args.qps = 2.0 if args.qps == 2.0 else args.qps
        args.threads = 4 if args.threads == 5 else args.threads
        args.max_requests = 150 if args.max_requests == 0 else args.max_requests
        args.artifact_analysis = True
        args.save_artifacts = True

    if policy == "safe":
        args.qps = min(args.qps, 1.0)
        args.timeout = max(args.timeout, 15.0)
        args.retries = max(args.retries, 2)
    elif policy == "aggressive":
        args.qps = args.qps * 1.5
        args.threads = args.threads + 2
        args.max_requests = 0


def apply_mode_defaults(args: argparse.Namespace) -> None:
    mode = (args.mode or "").lower().strip()
    if not mode:
        return

    def set_if_false(attr: str, value: bool = True):
        if getattr(args, attr) is False:
            setattr(args, attr, value)

    def set_if_default(attr: str, default_value, new_value):
        if getattr(args, attr) == default_value:
            setattr(args, attr, new_value)

    if mode == "ctf":
        args.pack = "ctf"
        args.discover = True
        args.passive = True
        args.verbose = True
        args.print_matches = True
        args.qps = 0.5
        args.threads = 1
        args.retries = 5
        args.timeout = 20.0
        args.max_requests = 40
        args.artifact_analysis = True
        args.save_artifacts = True
        args.html = True

    elif mode == "web":
        set_if_default("pack", "auto", "web-misconfig")
        set_if_false("discover", True)
        set_if_false("crawl", True)
        set_if_false("passive", True)
        set_if_false("verbose", True)
        set_if_default("crawl_depth", 2, 2)
        set_if_default("crawl_max_pages", 60, 80)
        set_if_default("qps", 2.0, 2.0)
        set_if_default("threads", 5, 6)

    elif mode == "stealth":
        set_if_default("pack", "auto", "web-misconfig")
        set_if_default("qps", 2.0, 0.5)
        set_if_default("threads", 5, 2)
        set_if_default("timeout", 12.0, 15.0)
        set_if_default("retries", 1, 1)
        set_if_default("max_requests", 0, 200)


def main() -> int:
    args = parse_args()
    
    yaml_config_path = find_config_file()
    if yaml_config_path:
        print(f"[+] Loading config from: {yaml_config_path}")
        yaml_config = load_yaml_config(yaml_config_path)
        merge_yaml_to_args(yaml_config, args)
    
    apply_speed_profile(args)
    apply_mode_defaults(args)
    cfg = default_config(args)
    os.makedirs(cfg.outdir, exist_ok=True)

    if args.list_packs:
        for x in list_packs(args.rules_dir):
            print(x)
        return 0
    if args.list_rules:
        for x in list_rules_in_pack(args.rules_dir, args.list_rules):
            print(x)
        return 0
    if args.init_config:
        from config.yaml_config import write_example_config
        write_example_config()
        print("[+] Created example hunter.yaml")
        return 0

    if args.dry_run:
        print(f"[DRY RUN] Would scan: {cfg.base}")
        print(f"[DRY RUN] Pack: {cfg.pack}")
        print(f"[DRY RUN] Mode: {args.mode or 'default'}")
        print(f"[DRY RUN] Options:")
        print(f"  - discover: {cfg.discover}")
        print(f"  - crawl: {cfg.crawl}")
        print(f"  - passive: {cfg.passive}")
        print(f"  - fuzz: {cfg.fuzz_sets}")
        print(f"  - artifact_analysis: {cfg.artifact_analysis}")
        print(f"[DRY RUN] Would execute rules and generate reports.")
        return 0

    tech_db, waf_db = load_fingerprint_dbs(cfg.fingerprints_dir)
    fp = fingerprint_target(
        tech_db=tech_db,
        waf_db=waf_db,
        base=cfg.base,
        cfg=cfg,
    )

    rules = load_rules(cfg.rules_dir, pack=cfg.pack, tech=fp.tech, waf=fp.waf)
    targets = enumerate_targets(cfg)

    print(f"[+] Scan ID: {cfg.scan_id}")
    print(f"[+] Policy: {cfg.policy}, Environment: {cfg.environment}")

    findings = []
    findings.extend(run_rules(cfg, rules, scan_id=cfg.scan_id))
    if cfg.passive:
        findings.extend(run_passive_scan(cfg, targets, scan_id=cfg.scan_id))
    if cfg.fuzz_sets and cfg.fuzz_targets:
        findings.extend(run_fuzz(cfg))

    # P2: Apply verification state transitions
    from postprocess.verifier import FindingVerifier
    verifier = FindingVerifier(scan_id=cfg.scan_id)
    transition_logs = []
    for finding in findings:
        try:
            # Rule engine sets initial state
            finding.verification_state = verifier.set_initial_state(
                finding.id or finding.rule_id,
                actor_name="rule_engine"
            )
            
            # Auto-upgrade based on evidence
            if cfg.verification_depth in ["medium", "high"]:
                evidence_dict = {}
                if finding.evidence:
                    ev = finding.evidence
                    evidence_dict = {
                        "status": ev.status,
                        "headers": ev.headers,
                        "matched_pattern": ev.matched_pattern,
                        "snippet": ev.snippet,
                        "extracted_data": finding.extracted_data,
                    }
                
                # Try to upgrade to suspected
                try:
                    finding.verification_state = verifier.transition_to_suspected(
                        finding.id or finding.rule_id,
                        finding.verification_state,
                        actor_name="verifier_auto",
                        reason="Auto-detected context indicators",
                    )
                except:
                    pass
                
                # Try to upgrade to verified if depth is high
                if cfg.verification_depth == "high":
                    try:
                        finding.verification_state = verifier.transition_to_verified(
                            finding.id or finding.rule_id,
                            finding.verification_state,
                            actor_name="verifier_auto", 
                            reason="Deep verification - sensitive data analysis",
                        )
                    except:
                        pass
                        
        except Exception as e:
            if cfg.verbose:
                print(f"[!] Verification error for {finding.rule_id}: {e}")
    
    transition_logs = verifier.get_transition_log_as_dicts()
    if cfg.verbose and transition_logs:
        print(f"[+] State transitions: {len(transition_logs)}")
        for log in transition_logs[:3]:
            print(f"    {log['from_state']} -> {log['to_state']} by {log['actor_type']}")

    score_findings(findings)
    findings = dedupe_findings_prefer_chain(findings)

    artifacts = []
    if cfg.artifact_analysis:
        artifacts = collect_artifacts(cfg.outdir, cfg.outdir, scan_id=cfg.scan_id)

    flags = []
    clues = []
    mode = (args.mode or "").lower()
    if mode == "ctf" or cfg.passive:
        flags, clues = extract_all_ctf_data(findings)

    # --- Baseline Comparison ---
    delta_report = None
    if args.baseline:
        from postprocess.baseline import (
            load_baseline, 
            compare_with_baseline, 
            write_delta_report,
            print_delta_summary,
        )
        
        baseline = load_baseline(args.baseline)
        if baseline:
            baseline_scan_id = list(baseline.values())[0].scan_id if baseline else "unknown"
            delta_report = compare_with_baseline(
                findings, 
                baseline, 
                cfg.scan_id, 
                baseline_scan_id
            )
            
            # Filter to new only if requested
            if args.new_only:
                new_only_severity = filter_new_only_by_severity(delta_report, "medium")
                findings = new_only_severity
            
            # Print delta summary
            print_delta_summary(delta_report)
            
            # Write delta report
            delta_path = f"{cfg.report}-delta.json"
            write_delta_report(delta_path, delta_report, cfg.base)
            print(f"[+] Delta report: {delta_path}")
    
    # --- Suppression Filter ---
    if args.hide_suppressed or args.suppressions:
        from postprocess.suppression import apply_suppressions, SuppressionResult
        
        suppression_file = args.suppressions if args.suppressions else "suppressions.json"
        result = apply_suppressions(findings, suppression_file)
        
        if args.hide_suppressed and result.suppressed:
            print(f"[+] Suppressed: {len(result.suppressed)}, Remaining: {len(result.remaining)}")
            findings = result.remaining

    md_path = f"{cfg.report}.md"
    js_path = f"{cfg.report}.json"
    html_path = ""
    write_markdown(md_path, cfg.base, cfg.outdir, findings)
    write_json(js_path, cfg.base, cfg.outdir, findings, cfg)
    
    suppressed_count = 0
    if args.hide_suppressed or args.suppressions:
        from postprocess.suppression import apply_suppressions
        suppression_file = args.suppressions if args.suppressions else "suppressions.json"
        result = apply_suppressions(findings, suppression_file)
        suppressed_count = len(result.suppressed)
    
    if args.html:
        html_path = f"{cfg.report}.html"
        scan_meta = {
            "scan_id": cfg.scan_id,
            "policy": cfg.policy,
            "environment": cfg.environment,
        }
        write_html(html_path, cfg.base, cfg.outdir, findings, delta_report=delta_report, suppressed_count=suppressed_count, scan_metadata=scan_meta)

    if flags:
        print("\n[FLAG FOUND]")
        for flag in flags:
            print(flag)

    if clues and args.verbose:
        print("\n[CTF CLUES]")
        for clue in clues[:20]:
            print(f"  - {clue}")

    # --- CI Integration: Exit code based on findings ---
    exit_code = 0
    
    # Use delta_report from earlier baseline comparison
    delta_result = delta_report
    
    # Determine which findings to evaluate based on triage policy
    eval_findings = findings
    eval_description = "all findings"
    
    if args.hide_suppressed and args.suppressions:
        store = SuppressionStore(args.suppressions)
        if not args.ignore_expired_suppressions:
            store.clean_expired()
        result = apply_suppressions(findings, args.suppressions)
        eval_findings = result.remaining
        eval_description = f"non-suppressed findings (suppressed: {len(result.suppressed)})"
    
    if delta_result and args.new_only:
        eval_findings = delta_result.new_findings
        eval_description = f"new findings only (total: {len(delta_result.new_findings)})"
    
    # Fail-on: Original behavior (fail on severity threshold)
    if cfg.fail_on_severity:
        sev_rank = severity_rank(cfg.fail_on_severity)
        for f in eval_findings:
            f_rank = severity_rank(f.severity)
            meets_criteria = False
            if cfg.fail_exploited_only:
                meets_criteria = getattr(f, 'verification_state', 'observed') == "exploited"
            elif cfg.fail_verified_only:
                meets_criteria = getattr(f, 'verification_state', 'observed') in ["verified", "exploited"]
            else:
                meets_criteria = f_rank >= sev_rank
            
            if meets_criteria:
                exit_code = 2
                print(f"\n[!] FAIL ({eval_description}): Found {f.severity} {f.title} (verification: {getattr(f, 'verification_state', 'observed')})")
                break
    
    # Fail-on-new: Only fail on NEW findings (requires baseline)
    if exit_code == 0 and args.fail_on_new and delta_result:
        sev_rank = severity_rank(args.fail_on_new)
        for df in delta_result.new_findings:
            f_rank = severity_rank(df.finding.severity)
            if f_rank >= sev_rank:
                exit_code = 2
                print(f"\n[!] FAIL (new findings): Found {df.finding.severity} {df.finding.title} (NEW)")
                break
    
    # Fail-on-changed: Only fail on severity CHANGED findings (requires baseline)
    if exit_code == 0 and args.fail_on_changed and delta_result:
        sev_rank = severity_rank(args.fail_on_changed)
        for df in delta_result.changed_findings:
            f_rank = severity_rank(df.finding.severity)
            if f_rank >= sev_rank:
                exit_code = 2
                print(f"\n[!] FAIL (changed findings): Found {df.finding.severity} {df.finding.title} (was {df.previous_severity})")
                break
    
    # Fail-on-delta-only: Fail if any delta exists (new/changed/resolved)
    if exit_code == 0 and args.fail_on_delta_only and delta_result:
        has_delta = (
            len(delta_result.new_findings) > 0 or
            len(delta_result.changed_findings) > 0 or
            len(delta_result.resolved_findings) > 0
        )
        if has_delta:
            exit_code = 2
            summary = []
            if delta_result.new_findings:
                summary.append(f"new: {len(delta_result.new_findings)}")
            if delta_result.changed_findings:
                summary.append(f"changed: {len(delta_result.changed_findings)}")
            if delta_result.resolved_findings:
                summary.append(f"resolved: {len(delta_result.resolved_findings)}")
            print(f"\n[!] FAIL (delta): Baseline differs - {', '.join(summary)}")

    print(f"[+] Done. Findings={len(findings)}")
    print(f"[+] Reports: {md_path}, {js_path}" + (f", {html_path}" if args.html else ""))
    if artifacts:
        print(f"[+] Artifacts analyzed: {len(artifacts)}")
    if cfg.policy:
        print(f"[+] Policy: {cfg.policy}")
    if cfg.environment != "unknown":
        print(f"[+] Environment: {cfg.environment}")
    
    if args.metrics:
        from postprocess.metrics import generate_metrics_report, print_metrics_summary
        
        baseline_findings = None
        baseline_scan_id = None
        if args.baseline:
            from postprocess.baseline import load_baseline
            baseline = load_baseline(args.baseline)
            if baseline:
                baseline_findings = []
                for key, bf in baseline.items():
                    from core.models import Finding
                    f = Finding(
                        id=bf.rule_id,
                        rule_id=bf.rule_id,
                        url=bf.url,
                        severity=bf.severity,
                    )
                    f.verification_state = bf.verification_state
                    baseline_findings.append(f)
                baseline_scan_id = baseline.values()[0].scan_id if baseline else None
        
        report = generate_metrics_report(
            findings,
            cfg.scan_id,
            cfg.base,
            baseline_findings,
            baseline_scan_id,
        )
        print_metrics_summary(report)
    
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
