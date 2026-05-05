from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .utils import human_size


PRIORITY_LEAD_SCORE = {
    "partition": 60,
    "ZIP archive": 50,
    "Git repository": 45,
    "Git indicators": 40,
    "PE executable": 30,
    "ELF executable": 25,
    "PNG image": 10,
    "JPEG image": 10,
    "PDF document": 20,
    "Suspicious string": 15,
    "SleuthKit": 55,
}


def _build_priority_leads(result: Dict[str, object]) -> List[dict]:
    leads = []

    is_forensic = result.get("is_forensic_image", False)

    partition_access = result.get("partition_access", [])
    if partition_access:
        for pa in partition_access:
            status = pa.get("access_status", "failed")
            part = pa.get("partition", "?")
            fs_type = pa.get("fs_type", "")
            error = pa.get("error", "")

            if status == "mounted":
                leads.append({
                    "text": f"Mounted {part} ({fs_type})",
                    "reason": pa.get("mount_path", ""),
                    "priority": "high",
                    "confidence": "high",
                    "score": 65,
                    "type": "partition_access",
                })
            elif status == "recovered_by_tsk":
                leads.append({
                    "text": f"TSK Recovered {part} ({fs_type})",
                    "reason": pa.get("tsk_recover_output", ""),
                    "priority": "high",
                    "confidence": "high",
                    "score": 60,
                    "type": "partition_access",
                })
            elif status == "extracted_by_icat":
                leads.append({
                    "text": f"ICAT Extracted {part} ({fs_type})",
                    "reason": pa.get("icat_output", ""),
                    "priority": "high",
                    "confidence": "medium",
                    "score": 55,
                    "type": "partition_access",
                })
            elif error:
                leads.append({
                    "text": f"Failed {part} ({fs_type})",
                    "reason": error[:60],
                    "priority": "low",
                    "confidence": "low",
                    "score": 10,
                    "type": "partition_access",
                })

    mounted = result.get("mounted_partitions", [])
    if mounted:
        for m in mounted:
            leads.append({
                "text": f"Mounted {m['partition']} @ {m['mount_path']}",
                "reason": "Partition mounted successfully",
                "priority": "high",
                "confidence": "high",
                "score": 65,
                "type": "mounted",
            })

    git_repos = result.get("git_repos", [])
    for repo in git_repos:
        leads.append({
            "text": f"Git repo: {repo['repo_path']}",
            "reason": f"Branch: {repo.get('branch', 'unknown')}",
            "priority": "high",
            "confidence": "high",
            "score": 70,
            "type": "git_confirmed",
        })

    sleuthkit_files = result.get("sleuthkit_file_listings", [])
    if sleuthkit_files:
        leads.append({
            "text": f"SleuthKit file listings: {len(sleuthkit_files)} matches",
            "reason": "File listing from fls",
            "priority": "high",
            "confidence": "high",
            "score": PRIORITY_LEAD_SCORE.get("SleuthKit", 55),
            "type": "sleuthkit",
        })

    partitions = result.get("partitions", [])
    for p in partitions:
        if p.get("fs_type") in ("Linux",):
            marker = " *" if p.get("active") else ""
            leads.append({
                "text": f"Partition p{p['partition']}{marker}: {p['fs_type']} ({p['size_mb']}MB)",
                "reason": "Linux filesystem - may contain .git",
                "priority": "high",
                "confidence": "high",
                "score": 60,
                "type": "partition",
            })

    embedded = result.get("embedded", [])
    for item in embedded:
        name = item.get("name", "")
        offset = item.get("offset", 0)
        score = PRIORITY_LEAD_SCORE.get(name, 0)

        if is_forensic:
            score = max(0, score - 20)

        reason = ""
        priority = "low"
        confidence = "low"

        if name == "ZIP archive":
            status = item.get("zip_parse_status")
            if status == "success":
                reason = "extractable archive"
                priority = "high"
                confidence = "high"
            elif status == "partial":
                reason = "partial archive, may extract"
                priority = "medium"
                confidence = "medium"
            else:
                reason = item.get("zip_parse_reason", "truncated")
                priority = "low"
                confidence = "low"

        if name in ("PE executable", "ELF executable"):
            priority = "medium"
            confidence = "medium"

        if score > 0:
            leads.append({
                "text": f"{name} @ {offset}",
                "reason": reason,
                "priority": priority,
                "confidence": confidence,
                "score": score,
                "type": "embedded",
            })

    git = result.get("git_artifacts", {})
    indicator_count = git.get("indicator_count", 0)
    if indicator_count > 0:
        conf = git.get("confidence", "none")
        if conf == "critical":
            priority = "high"
            score = 80
        elif conf == "high":
            priority = "high"
            score = 50
        elif conf == "medium":
            priority = "medium"
            score = 35
        elif conf == "low":
            priority = "low"
            score = 20
        else:
            priority = "low"
            score = 10

        reason = f"{indicator_count} git indicators ({conf})"
        leads.append({
            "text": f"Git indicators: {indicator_count}",
            "reason": reason,
            "priority": priority,
            "confidence": conf,
            "score": score,
            "type": "git",
        })

    git_raw = result.get("git_in_raw_data", [])
    if git_raw:
        unique_markers = {}
        for g in git_raw:
            m = g.get("marker", "")
            if m not in unique_markers:
                unique_markers[m] = True
        if unique_markers and not git_repos:
            leads.append({
                "text": f"Git in raw data: {len(unique_markers)} markers",
                "reason": "Found .git files in raw data (not confirmed)",
                "priority": "low",
                "confidence": "low",
                "score": 25,
                "type": "git_raw",
            })

    flag_raw = result.get("flag_in_raw_data", [])
    if flag_raw:
        leads.append({
            "text": f"Flag candidates: {len(flag_raw)}",
            "reason": "Flag patterns found in raw data",
            "priority": "medium",
            "confidence": "low",
            "score": 20,
            "type": "flag",
        })

    strings = result.get("strings", {})
    if is_forensic:
        suspicious_details = strings.get("suspicious_details", [])
        for sd in suspicious_details[:10]:
            leads.append({
                "text": f"Suspicious string: {sd.get('string', '')[:40]}",
                "reason": f"{sd.get('pattern', '')} @ {sd.get('likely_partition', 'raw')}",
                "priority": "medium",
                "confidence": "medium",
                "score": 15,
                "type": "string",
            })
    else:
        for s in strings.get("suspicious_strings", [])[:5]:
            leads.append({
                "text": f"Suspicious string: {s}",
                "reason": "encoding/crypto hint",
                "priority": "medium",
                "confidence": "medium",
                "score": PRIORITY_LEAD_SCORE.get("Suspicious string", 0),
                "type": "string",
            })

    leads.sort(key=lambda x: (x["score"], x["confidence"] == "high"), reverse=True)
    return leads[:10]


def _build_next_actions(result: Dict[str, object]) -> List[str]:
    actions = []
    carved = result.get("carved", [])

    zips = [c for c in carved if c.get("extension") == ".zip"]
    for z in zips:
        offset = z["offset"]
        status = z.get("zip_parse_status")
        path = z.get("output_path", "")

        if status == "success":
            actions.append(f"Inspect extracted ZIP: {path}")
        elif status == "partial":
            attempts = z.get("archive_indicators", {}).get("count", 0)
            if attempts > 0:
                actions.append(f"Check partial ZIP @ {offset} (has {attempts} indicators)")
            else:
                actions.append(f"Skip ZIP @ {offset} unless using loose recovery mode")
        else:
            actions.append(f"Skip ZIP @ {offset} (not extractable)")

    git = result.get("git_artifacts", {})
    if git.get("indicator_count", 0) > 0:
        conf = git.get("confidence", "none")
        if conf in ("high", "medium"):
            actions.append(f"Search for .git artifacts in strings (confidence: {conf})")

    strings = result.get("strings", {})
    suspicious = strings.get("suspicious_strings", [])
    if any("base64" in s.lower() for s in suspicious):
        actions.append("Check suspicious strings for encoded content")

    return actions[:10]


def render_terminal_summary(results: List[Dict[str, object]]) -> str:
    lines = []
    for result in results:
        file_info = result["file_info"]
        if "error" in result:
            lines.append("=" * 70)
            lines.append(f"File:         {file_info['path']}")
            lines.append(f"Error:        {result['error']}")
            continue

        sig = result["signature"]
        entropy = result["entropy"]
        risk = result["risk"]

        lines.append("=" * 70)
        lines.append(f"File:         {file_info['path']}")
        lines.append(f"Size:         {human_size(file_info['size'])} ({file_info['size']} bytes)")
        lines.append(f"SHA256:       {result['hashes']['sha256']}")
        lines.append(f"Detected:     {sig['name']} ({sig['type']})")
        lines.append(f"Ext Match:    {'Yes' if sig['extension_matches'] else 'No'}")
        lines.append(f"Entropy:      {entropy['score']:.3f} ({entropy['classification']})")
        lines.append(f"Risk:         {risk['risk_level']} ({risk['risk_score']}/100)")
        lines.append(f"Findings:     {len(risk['findings'])}")

        if result.get("embedded"):
            lines.append(f"Embedded:     {len(result['embedded'])} candidate(s)")

        if result.get("strings"):
            lines.append(
                f"Strings:      urls={len(result['strings']['urls'])}, "
                f"emails={len(result['strings']['emails'])}, "
                f"ips={len(result['strings']['ips'])}, "
                f"suspicious={len(result['strings']['suspicious_strings'])}"
            )

        verified_flags = result.get("verified_flags", []) or []
        flag_candidates = result.get("flag_candidates", []) or []
        if verified_flags:
            first_flag = verified_flags[0]
            if isinstance(first_flag, dict):
                first_flag = first_flag.get("value") or first_flag.get("flag") or str(first_flag)
            lines.append(f"Solved:       YES ({len(verified_flags)} flag(s))")
            lines.append(f"Flag:         {str(first_flag)[:120]}")
        elif flag_candidates:
            lines.append(f"Solved:       NO (candidates={len(flag_candidates)})")

        answers = result.get("answers", []) or []
        if answers:
            first_answer = answers[0]
            if isinstance(first_answer, dict):
                val = first_answer.get("value") or str(first_answer)
                kind = first_answer.get("kind", "answer")
                lines.append(f"Answer:       {kind} = {val}")
            else:
                lines.append(f"Answer:       {first_answer}")

        artifacts = result.get("verified_artifacts", []) or []
        if artifacts:
            lines.append(f"Artifacts:    {len(artifacts)} verified artifact(s)")

        leads = _build_priority_leads(result)
        if leads:
            lines.append("")
            lines.append("### Top Leads (Priority Order)")
            for i, lead in enumerate(leads, 1):
                reason = lead.get("reason", "")
                reason_str = f" [{reason}]" if reason else ""
                lines.append(f"{i}. {lead['text']}{reason_str}")

        carved = result.get("carved", [])
        zips = [c for c in carved if c.get("extension") == ".zip"]
        if zips:
            lines.append("")
            lines.append("### ZIP Status")
            for z in zips[:10]:
                offset = z["offset"]
                status = z.get("zip_parse_status_detail", z.get("zip_parse_status", "unknown"))
                path = z.get("output_path", "N/A").split("/")[-1]
                size = z.get("size", 0)

                if status == "valid":
                    lines.append(f"  {offset}  validated     {size:>6}  {path}")
                elif status == "corrupted-but-structured":
                    lines.append(f"  {offset}  corrupted    {size:>6}  {path}")
                elif status == "signature-only":
                    lines.append(f"  {offset}  signature-onl {size:>6}  {path}")
                else:
                    lines.append(f"  {offset}  {status:>15} {size:>6}  {path}")

        indicators = _build_next_actions(result)
        if indicators:
            lines.append("")
            lines.append("### Next Actions")
            for action in indicators:
                lines.append(f"  - {action}")

    if lines:
        lines.append("=" * 70)
    return "\n".join(lines)


def write_json_report(results: List[Dict[str, object]], out_path: Path) -> Path:
    out_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def write_markdown_report(results: List[Dict[str, object]], out_path: Path) -> Path:
    lines = ["# ArtifactScope Report", ""]
    for result in results:
        file_info = result["file_info"]
        if "error" in result:
            lines.extend([
                f"## {file_info['name']}",
                "",
                f"- **Path:** `{file_info['path']}`",
                f"- **Error:** {result['error']}",
                "",
                "---",
                "",
            ])
            continue

        sig = result["signature"]
        entropy = result["entropy"]
        risk = result["risk"]

        lines.extend([
            f"## {file_info['name']}",
            "",
            f"- **Path:** `{file_info['path']}`",
            f"- **Size:** {human_size(file_info['size'])} ({file_info['size']} bytes)",
            f"- **Extension:** `{file_info['extension'] or '(none)'}`",
            f"- **Created:** {file_info['created']}",
            f"- **Modified:** {file_info['modified']}",
        ])

        verified_flags = result.get("verified_flags", []) or []
        flag_candidates_summary = result.get("flag_candidates", []) or []
        forensic_leads_summary = result.get("forensic_leads", []) or []
        access_trace = result.get("access_trace", []) or []

        lines.extend([
            "",
            "### Final Result",
            "",
            f"- **Solved:** {'Yes' if verified_flags else 'No'}",
            f"- **Verified Flag Count:** {len(verified_flags)}",
            f"- **Flag Candidate Count:** {len(flag_candidates_summary)}",
            f"- **Forensic Lead Count:** {len(forensic_leads_summary)}",
            f"- **Answer Count:** {len(result.get('answers', []) or [])}",
            f"- **Verified Artifact Count:** {len(result.get('verified_artifacts', []) or [])}",
        ])

        if verified_flags:
            lines.extend([
                "",
                "### Verified Flags",
                "",
            ])
            for vf in verified_flags[:10]:
                if isinstance(vf, dict):
                    value = vf.get("value") or vf.get("flag") or str(vf)
                    source = vf.get("source", "unknown")
                    lines.append(f"- **{value}**")
                    lines.append(f"  - Source: {source}")
                else:
                    lines.append(f"- **{vf}**")

        elif flag_candidates_summary:
            lines.extend([
                "",
                "### Flag Candidates",
                "",
            ])
            for fc in flag_candidates_summary[:10]:
                if isinstance(fc, dict):
                    value = fc.get("value") or fc.get("flag") or str(fc)
                    source = fc.get("source", "unknown")
                    lines.append(f"- `{value}`")
                    lines.append(f"  - Source: {source}")
                else:
                    lines.append(f"- `{fc}`")

        answers = result.get("answers", []) or []
        if answers:
            lines.extend(["", "### Extracted Answers", ""])
            for ans in answers[:20]:
                if isinstance(ans, dict):
                    lines.append(f"- **{ans.get('kind', 'answer')}:** `{ans.get('value')}`")
                    lines.append(f"  - Source: {ans.get('source', 'unknown')}")
                else:
                    lines.append(f"- `{ans}`")

        verified_artifacts = result.get("verified_artifacts", []) or []
        if verified_artifacts:
            lines.extend(["", "### Verified Artifacts", ""])
            for va in verified_artifacts[:20]:
                if isinstance(va, dict):
                    lines.append(f"- {va.get('value', str(va))}")
                    lines.append(f"  - Source: {va.get('source', 'unknown')}")
                else:
                    lines.append(f"- {va}")

        if forensic_leads_summary and not verified_flags:
            lines.extend([
                "",
                "### Forensic Leads",
                "",
            ])
            for fl in forensic_leads_summary[:10]:
                if isinstance(fl, dict):
                    value = fl.get("value") or str(fl)
                    source = fl.get("source", "unknown")
                    lines.append(f"- {value}")
                    lines.append(f"  - Source: {source}")
                else:
                    lines.append(f"- {fl}")

        if access_trace:
            lines.extend([
                "",
                "### Access Trace",
                "",
            ])
            for at in access_trace:
                lines.append(f"- **{at.get('partition', '?')}:** {at.get('access_status', 'unknown')}")
                for key in ("mount_result", "fls_result", "icat_result", "tsk_result"):
                    value = at.get(key)
                    if value:
                        lines.append(f"  - {key}: {value}")
                for key in ("mount_path", "icat_output", "tsk_recover_output"):
                    value = at.get(key)
                    if value:
                        lines.append(f"  - {key}: `{value}`")

        leads = _build_priority_leads(result)
        if leads:
            lines.extend([
                "",
                "### Top Leads (Priority Order)",
                "",
            ])
            for i, lead in enumerate(leads, 1):
                reason = lead.get("reason", "")
                text = lead.get("text", "")
                priority = lead.get("priority", "")
                confidence = lead.get("confidence", "")
                reason_str = f" [{reason}]" if reason else ""
                if priority and confidence:
                    pri_str = f" [{priority}/{confidence}]"
                elif priority:
                    pri_str = f" [{priority}]"
                else:
                    pri_str = ""
                lines.append(f"{i}. {text}{reason_str}{pri_str}")

        partitions = result.get("partitions", [])
        if partitions:
            lines.extend([
                "",
                "### Partition Table",
                "",
            ])
            for p in partitions:
                marker = " *" if p.get("active") else ""
                lines.append(
                    f"- **p{p['partition']}{marker}:** offset={p['offset_bytes']}, "
                    f"size={p['size_mb']}MB, fs={p['fs_type']}"
                )

        ctf_subresults = result.get("ctf_subresults", []) or []
        if ctf_subresults:
            lines.extend(["", "### CTF Handler Results", ""])
            for sr in ctf_subresults:
                lines.append(f"- **{sr.get('tool', 'ctf_handler')}**: {sr.get('status', 'unknown')}")
                if sr.get('candidate_inodes'):
                    for ci in sr.get('candidate_inodes', [])[:10]:
                        lines.append(f"  - inode {ci.get('inode')}: `{ci.get('path', '')}`")
                if sr.get('candidates'):
                    for ci in sr.get('candidates', [])[:10]:
                        lines.append(f"  - inode {ci.get('inode')}: `{ci.get('path', '')}` @ sector {ci.get('offset')}" )
                if sr.get('raw_hits'):
                    lines.append(f"  - residual grep hits: {len(sr.get('raw_hits', []))}")
                if sr.get('icat_attempts'):
                    lines.append(f"  - icat attempts: {len(sr.get('icat_attempts', []))}")
                    for at in sr.get('icat_attempts', [])[:8]:
                        preview = str(at.get('preview', '')).replace('`', "'").replace('\n', ' / ')[:180]
                        rc = at.get('returncode')
                        lines.append(
                            f"  - inode {at.get('inode')} @ sector {at.get('offset')} rc={rc}: `{at.get('path', '')}` preview=`{preview}`"
                        )

        partition_access = result.get("partition_access", [])
        if partition_access:
            lines.extend([
                "",
                "### Filesystem Access",
                "",
            ])
            for pa in partition_access:
                part = pa.get("partition", "?")
                fs_type = pa.get("fs_type", "")
                status = pa.get("access_status", "failed")
                error = pa.get("error", "")

                if status == "mounted":
                    lines.append(f"- **p{part}:** mounted @ {pa.get('mount_path', 'N/A')}")
                elif status == "recovered_by_tsk":
                    lines.append(f"- **p{part}:** TSK recovered ({pa.get('tsk_recover_output', 'N/A')})")
                elif status == "extracted_by_icat":
                    lines.append(f"- **p{part}:** ICAT extracted ({pa.get('icat_output', 'N/A')})")
                elif error:
                    lines.append(f"- **p{part}:** FAILED - {error[:50]}")

        sleuthkit_files = result.get("sleuthkit_file_listings", [])
        if sleuthkit_files:
            lines.extend([
                "",
                "### SleuthKit File Listings",
                "",
            ])
            for fl in sleuthkit_files[:20]:
                lines.append(f"- {fl}")
            if len(sleuthkit_files) > 20:
                lines.append(f"... and {len(sleuthkit_files) - 20} more")

        sleuthkit_suggested = result.get("sleuthkit_suggested_commands", [])
        if sleuthkit_suggested:
            lines.extend([
                "",
                "### Suggested SleuthKit Commands",
                "",
            ])
            for cmd in sleuthkit_suggested:
                lines.append(f"- {cmd}")

        mounted = result.get("mounted_partitions", [])
        if mounted:
            lines.extend([
                "",
                "### Mounted Findings",
                "",
            ])
            for m in mounted:
                lines.append(f"- **{m['partition']}** mounted at `{m['mount_path']}`")

        git_repos = result.get("git_repos", [])
        if git_repos:
            lines.extend([
                "",
                "### Git Repositories (Confirmed)",
                "",
            ])
            for repo in git_repos:
                branch = repo.get("branch", "unknown")
                lines.append(f"- `{repo['repo_path']}` (branch: {branch})")

        git_history = result.get("git_history", [])
        if git_history:
            lines.extend([
                "",
                "### Git History Analysis",
                "",
            ])

            for hist in git_history:
                repo_path = hist.get("repo_path", "unknown")
                source = hist.get("source", "unknown")

                if source in ("deleted_content_recovery", "full_git_recovery", "working_tree_recovery"):
                    lines.append("")
                    lines.append("### Recovered Evidence")
                    lines.append("")
                    lines.append(f"- **Repo:** {repo_path}")

                    access_method = hist.get("access_method", "unknown")
                    if access_method and access_method != "unknown":
                        lines.append(f"- **Access:** {access_method}")

                    last_msg = hist.get("last_commit_message", "")
                    if last_msg:
                        lines.append(f"- **Last Commit:** {last_msg}")

                    commits = hist.get("commits", [])
                    if commits:
                        lines.append("- **Commit History:**")
                        for c in commits[:5]:
                            hash_key = (
                                c.get("hash")
                                or c.get("new_hash")
                                or c.get("old_hash")
                                or ""
                            )[:7]
                            action = c.get("action", "commit")
                            msg = c.get("message", "")[:80]
                            lines.append(f"  - {hash_key} ({action}): {msg}")

                    deleted = hist.get("deleted_files", [])
                    if deleted:
                        lines.append(f"- **Deleted Files:** {', '.join(deleted[:5])}")

                    recovered = hist.get("recovered_content", [])
                    if recovered:
                        lines.append("")
                        lines.append("### Recovered Content")
                        for rc in recovered[:3]:
                            lines.append(f"- **{rc.get('file', 'unknown')}:**")
                            lines.append("  ```")
                            lines.append(f"  {rc.get('content', '')}")
                            lines.append("  ```")

                    flag_cands = hist.get("flag_candidates", [])
                    if flag_cands:
                        lines.append("")
                        lines.append("### Flag Candidates")
                        lines.append("")
                        for fc in flag_cands[:10]:
                            lines.append(f"- `{fc[:100]}`")

                    verified = hist.get("verified_flags", [])
                    if verified:
                        lines.append("")
                        lines.append("### Verified Flags")
                        lines.append("")
                        for vf in verified[:10]:
                            lines.append(f"- **{vf[:100]}**")

                    forensic = hist.get("forensic_leads", [])
                    if forensic:
                        lines.append("")
                        lines.append("### Forensic Leads")
                        lines.append("")
                        for fl in forensic[:10]:
                            lines.append(f"- {fl}")

                    hint_cands = hist.get("hint_candidates", [])
                    if hint_cands:
                        lines.append("")
                        lines.append("### Hint Candidates")
                        lines.append("")
                        for hc in hint_cands[:10]:
                            lines.append(f"- `{hc}`")

                    continue

                lines.append(f"**Repo:** {repo_path}")

                commits = hist.get("commits", [])
                if commits:
                    lines.append(f"- **Commits ({len(commits)}):**")
                    for c in commits[:5]:
                        hash_key = c.get("hash") or c.get("new_hash") or c.get("old_hash", "")
                        msg_key = c.get("message", c.get("action", ""))
                        lines.append(f"  - {hash_key[:7]}: {msg_key[:60]}")

                flags = hist.get("verified_flags", [])
                if flags:
                    lines.append("- **Verified Flags:**")
                    for fl in flags[:10]:
                        lines.append(f"  - **{fl[:100]}**")

                cand_flags = hist.get("flag_candidates", [])
                if cand_flags:
                    lines.append("- **Flag Candidates:**")
                    for fl in cand_flags[:10]:
                        lines.append(f"  - {fl[:100]}")

                lead_flags = hist.get("forensic_leads", [])
                if lead_flags:
                    lines.append("- **Forensic Leads:**")
                    for fl in lead_flags[:10]:
                        lines.append(f"  - {fl}")

                hints = hist.get("hint_candidates", [])
                if hints:
                    lines.append("- **Hint Candidates:**")
                    for hc in hints[:10]:
                        lines.append(f"  - {hc}")

        git_raw = result.get("git_in_raw_data", [])
        if git_raw:
            lines.extend([
                "",
                "### Git Indicators (Raw Data)",
                "",
            ])
            for g in git_raw[:5]:
                part = g.get("likely_partition", "unknown")
                lines.append(f"- {g.get('marker', 'unknown')} @ offset {g.get('offset')} [{part}]")

        flag_raw = result.get("flag_in_raw_data", [])
        if flag_raw:
            lines.extend([
                "",
                "### Flag Candidates (Raw Data)",
                "",
            ])
            for f in flag_raw[:10]:
                part = f.get("likely_partition", "unknown")
                lines.append(f"- **{f.get('pattern')}**: `{f.get('match')}` @ {f.get('offset')} [{part}]")

        flag_cands = result.get("flag_candidates", [])
        partition_flag_cands = [fc for fc in flag_cands if isinstance(fc, dict) and (fc.get("flag") or fc.get("offset") is not None or fc.get("partition") is not None)]
        if partition_flag_cands:
            lines.extend([
                "",
                "### Recovered Flags / Candidates",
                "",
            ])
            for fc in partition_flag_cands[:10]:
                flag_str = fc.get("flag") or fc.get("value") or fc.get("content_preview") or str(fc)
                offset = fc.get("offset", "?")
                partition = fc.get("partition", "?")
                source = fc.get("source", "unknown")
                lines.append(f"- **{flag_str}** @ p{partition} offset {offset} ({source})")

        deleted_recovery = result.get("deleted_recovery", [])
        if deleted_recovery:
            lines.extend([
                "",
                "### Deleted File Recovery",
                "",
            ])
            for dr in deleted_recovery:
                part = dr.get("partition", "unknown")
                deleted_inodes = dr.get("deleted_inodes", [])
                flag_cands = dr.get("flag_candidates", [])

                lines.append(f"**Partition {part}:**")
                if deleted_inodes:
                    lines.append(f"- Deleted inodes: {', '.join(deleted_inodes[:10])}")

                recovered = dr.get("recovered_content", [])
                if recovered:
                    lines.append("- Recovered content:")
                    for rc in recovered[:3]:
                        inode = rc.get("inode", "?")
                        content = rc.get("content", "")[:150]
                        lines.append(f"  - inode {inode}: {content}")

                if flag_cands:
                    lines.append("- **Flag candidates:**")
                    for fc in flag_cands[:5]:
                        pattern = fc.get("matched_pattern", "")
                        preview = fc.get("content_preview", "")[:80]
                        lines.append(f"  - {pattern}: {preview}")

        timeline_analysis = result.get("timeline_analysis", {})
        if timeline_analysis:
            lines.extend([
                "",
                "### Timeline Analysis",
                "",
            ])

            bodyfile = timeline_analysis.get("bodyfile")
            if bodyfile:
                lines.append(f"- **Bodyfile:** `{bodyfile}`")

            csv_output = timeline_analysis.get("csv_output")
            if csv_output:
                lines.append(f"- **Timeline CSV:** `{csv_output}`")

            recent_mods = timeline_analysis.get("recent_modifications", [])
            if recent_mods:
                lines.append("- **Recent Modifications:**")
                for mod in recent_mods[:10]:
                    lines.append(f"  - {mod[:100]}")

            recent_dels = timeline_analysis.get("recent_deletions", [])
            if recent_dels:
                lines.append("- **Recent Deletions:**")
                for dele in recent_dels[:10]:
                    lines.append(f"  - {dele[:100]}")

            suspicious = timeline_analysis.get("suspicious_filenames", [])
            if suspicious:
                lines.append("- **Suspicious Filenames:**")
                for susp in suspicious[:10]:
                    lines.append(f"  - {susp[:100]}")

        extracted_scan = result.get("extracted_content_scan", [])
        if extracted_scan:
            lines.extend([
                "",
                "### Extracted Content Scan",
                "",
            ])
            for esc in extracted_scan[:20]:
                src = esc.get("source_file", "")
                part = esc.get("partition", "unknown")
                pattern = esc.get("matched_pattern", "")
                ctx = esc.get("context", "")[:80]
                lines.append(f"- **{pattern}** in {src} [{part}]")
                if ctx:
                    lines.append(f"  - Context: {ctx}")

        lines.extend([
            "",
            "### Hashes",
            "",
            f"- **MD5:** `{result['hashes']['md5']}`",
            f"- **SHA1:** `{result['hashes']['sha1']}`",
            f"- **SHA256:** `{result['hashes']['sha256']}`",
            "",
            "### Type Detection",
            "",
            f"- **Detected Type:** {sig['name']} (`{sig['type']}`)",
            f"- **Extension Match:** {'Yes' if sig['extension_matches'] else 'No'}",
            f"- **Expected Extensions:** {', '.join(sig['expected_extensions']) if sig['expected_extensions'] else '(unknown)'}",
            "",
            "### Entropy",
            "",
            f"- **Score:** {entropy['score']:.3f}",
            f"- **Classification:** {entropy['classification']}",
            "",
            "### Risk",
            "",
            f"- **Risk Level:** {risk['risk_level']}",
            f"- **Risk Score:** {risk['risk_score']}/100",
            "",
            "### Findings",
            "",
        ])

        if risk["findings"]:
            for finding in risk["findings"]:
                lines.extend([
                    f"- **{finding['name']}** [{finding['severity'].upper()} | +{finding['score']}]",
                    f"  - {finding['description']}",
                    f"  - Evidence: {finding['evidence']}",
                ])
        else:
            lines.append("- No rule-based findings.")

        if result.get("strings"):
            s = result["strings"]
            lines.extend([
                "",
                "### String Scan Summary",
                "",
                f"- URLs: {len(s['urls'])}",
                f"- Emails: {len(s['emails'])}",
                f"- IPs: {len(s['ips'])}",
                f"- Base64-like strings: {len(s['base64_like'])}",
                f"- Suspicious strings: {len(s['suspicious_strings'])}",
            ])

            if s.get("suspicious_details"):
                lines.extend([
                    "",
                    "### Suspicious String Details",
                    "",
                ])
                total = len(s["suspicious_details"])
                for sd in s["suspicious_details"][:20]:
                    lines.append(
                        f"- **{sd.get('pattern', '')}**: {sd.get('string', '')[:50]} @ {sd.get('offset')} [{sd.get('likely_partition', 'raw')}]"
                    )
                if total > 20:
                    lines.append(f"... and {total - 20} more (not shown)")

        if result.get("git_artifacts"):
            ga = result["git_artifacts"]
            lines.extend([
                "",
                "### Git Artifacts",
                "",
                f"- **Indicator Count:** {ga.get('indicator_count', 0)}",
                f"- **Confidence:** {ga.get('confidence', 'none').upper()}",
            ])
            if ga.get("git_files"):
                lines.append("- **Direct .git paths:**")
                for f in ga["git_files"]:
                    lines.append(f"  - {f}")
            if ga.get("git_related_strings"):
                lines.append("- **Git-related strings:**")
                for s in ga["git_related_strings"]:
                    lines.append(f"  - {s}")
            if ga.get("git_refs"):
                lines.append("- **Git refs:**")
                for r in ga["git_refs"][:10]:
                    lines.append(f"  - {r}")
            if ga.get("commit_hashes"):
                lines.append("- **Commit hashes:**")
                for h in ga["commit_hashes"][:10]:
                    lines.append(f"  - {h}")

        if result.get("flag_patterns"):
            fp = result["flag_patterns"]
            lines.extend([
                "",
                "### FLAG PATTERNS",
                "",
            ])
            for f in fp[:20]:
                lines.append(f"- **{f['pattern']}**")
                lines.append(f"  - {f['match']}")

        if result.get("git_analysis"):
            ga = result["git_analysis"]
            lines.extend([
                "",
                "### Git Repository Analysis",
                "",
                f"- **Is Git Repo:** {ga.get('is_git_repo', False)}",
                f"- **Current Branch:** {ga.get('current_branch', 'N/A')}",
            ])
            branches = ga.get("branches", [])
            if branches:
                lines.append(f"- **Branches ({len(branches)}):**")
                for b in branches[:10]:
                    lines.append(f"  - {b}")
            tags = ga.get("tags", [])
            if tags:
                lines.append("- **Tags:**")
                for t in tags[:10]:
                    lines.append(f"  - {t}")
            commits = ga.get("commits", [])
            if commits:
                lines.append("- **Recent Commits:**")
                for c in commits[:10]:
                    lines.append(f"  - {c['hash'][:8]}: {c['message']}")
            flag_search = ga.get("flag_search", [])
            if flag_search:
                lines.append("- **FLAG Search Results:**")
                for f in flag_search[:10]:
                    lines.append(f"  - {f['file']}:{f['line']} - {f['content'][:50]}")

        if result.get("embedded"):
            lines.extend([
                "",
                "### Embedded Artifact Candidates",
                "",
            ])
            for item in result["embedded"]:
                line = f"- {item['name']} at offset `{item['offset']}`"
                if item.get("zip_parse_status") == "success":
                    line += " [validated]"
                elif item.get("zip_end"):
                    line += f" [estimated end: {item['zip_end']}]"
                if item.get("zip_parse_status"):
                    line += f" [{item['zip_parse_status']}]"
                    if item.get("zip_parse_reason"):
                        line += f" - {item['zip_parse_reason']}"
                lines.append(line)

        if result.get("carved"):
            carved = result["carved"]
            high_priority = []
            readable = []
            archives = []

            for item in carved:
                ext = item.get("extension", "")
                name = item.get("name", "")
                size = item.get("size", 0)
                zip_status = item.get("zip_parse_status")

                if zip_status == "success":
                    item["carve_label"] = "validated"
                    high_priority.append(item)
                elif name in ("ZIP archive",):
                    item["carve_label"] = "candidate"
                    high_priority.append(item)
                elif ext in (".zip", ".tar", ".gz", ".7z", ".rar"):
                    item["carve_label"] = "signature-only"
                    archives.append(item)
                elif ext in (".md", ".txt", ".json", ".yaml", ".yml", ".xml", ".py", ".js", ".sh", ".c", ".cpp", ".java", ".db", ".sqlite") and size < 1024 * 1024:
                    readable.append(item)
                elif size < 100 * 1024:
                    readable.append(item)

            lines.extend([
                "",
                "### Carved Files",
                "",
            ])

            shown = 0
            for item in high_priority[:5]:
                reid = item.get("reidentified", {})
                reid_name = reid.get("name", item["name"]) if reid else item["name"]
                fname = item.get("output_path", "").split("/")[-1]
                carve_label = item.get("carve_label", "")
                lines.append(f"- `{fname}` ({item['size']} bytes)")
                if carve_label == "validated":
                    lines.append(f"  - [validated {reid_name}]")
                elif carve_label == "candidate":
                    lines.append(f"  - [weak {reid_name}]")
                else:
                    lines.append(f"  - {reid_name}")

                zc = item.get("zip_contents", {})
                if len(zc.get("files", [])) > 0:
                    all_files = zc.get("files", [])
                    high_files = []
                    text_files = []

                    for f in all_files:
                        path = f.get("path", "").lower()
                        if ".git" in path or "head" in path or "config" in path or "refs" in path:
                            high_files.append(f)
                        elif "flag" in path or "secret" in path:
                            high_files.append(f)
                        elif path.endswith((".md", ".txt", ".json", ".py", ".sh")):
                            text_files.append(f)

                    lines.append(f"  - Contents ({zc['count']} files):")

                    for hf in high_files[:5]:
                        fp = hf.get("path", "")[:45]
                        lines.append(f"    [!] {fp}")
                    for tf in text_files[:5]:
                        fp = tf.get("path", "")[:45]
                        lines.append(f"    [txt] {fp}")

                    remaining = len(all_files) - len(high_files[:5]) - len(text_files[:5])
                    if remaining > 0:
                        lines.append(f"    ... ({remaining} more files)")

                indicators = item.get("archive_indicators", {}).get("indicators", [])
                if indicators:
                    lines.append("  - HIGH PRIORITY:")
                    for ind in indicators[:3]:
                        itype = ind.get("type", "")
                        ipath = ind.get("path", "")[:40]
                        lines.append(f"    [{itype}] {ipath}")

                shown += 1

            for item in readable[:20]:
                if shown >= 30:
                    break
                reid = item.get("reidentified", {})
                reid_name = reid.get("name", item["name"]) if reid else item["name"]
                lines.append(f"- `{item['output_path'].split('/')[-1]}` ({item['size']} bytes)")
                lines.append(f"  - {reid_name}")
                shown += 1

            if shown < len(carved):
                lines.append(f"... and {len(carved) - shown} more files (not shown)")

        lines.extend(["", "---", ""])

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path
