import os
from src.models import DecodeResult

PREVIEW_LENGTH = 60


def _preview(text: str, length: int = PREVIEW_LENGTH) -> str:
    if len(text) <= length:
        return text
    return text[:length] + "..."


def generate_report(input_text: str, results: list[DecodeResult], output_path: str, top_n: int = 0, recursive: bool = False) -> str:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    lines = []
    lines.append("# CTF Decode Helper Report")
    lines.append("")
    mode = "Recursive" if recursive else "Single-pass"
    lines.append(f"## Mode: {mode}")
    lines.append("")
    lines.append("## Input")
    lines.append("")
    lines.append(f"```")
    lines.append(input_text)
    lines.append(f"```")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    success = sum(1 for r in results if r.status == "success")
    skipped = sum(1 for r in results if r.status == "skipped")
    failed = sum(1 for r in results if r.status == "failed")
    displayed = results[:top_n] if top_n > 0 else results
    displayed_count = len(displayed)
    lines.append(f"- Total methods explored: {len(results)}")
    lines.append(f"- Displayed results: {displayed_count}")
    lines.append(f"- Success: {success}")
    lines.append(f"- Skipped: {skipped}")
    lines.append(f"- Failed: {failed}")
    if recursive:
        depth = max((len(r.chain) for r in results if r.chain), default=0)
        lines.append(f"- Recursive: yes")
        lines.append(f"- Max depth used: {depth}")
    lines.append("")

    all_flags = []
    for r in results:
        for f in r.flags:
            if f not in all_flags:
                all_flags.append(f)
    if all_flags:
        lines.append("## Found Flags")
        lines.append("")
        for f in all_flags:
            lines.append(f"- `{f}`")
        lines.append("")

    best = results[0] if results and results[0].status == "success" and results[0].flags else None
    if best:
        lines.append("## Best Candidate")
        lines.append("")
        if best.flags:
            lines.append(f"- **Flag:** `{best.flags[0]}`")
        lines.append(f"- **Score:** {best.score}")
        lines.append(f"- **Confidence:** {best.confidence}")
        if best.chain:
            lines.append(f"- **Chain:** `{' -> '.join(best.chain)}`")
        lines.append("")
        if best.output:
            lines.append(f"```")
            lines.append(best.output)
            lines.append(f"```")
            lines.append("")

    lines.append("## Results (Summary)")
    lines.append("")
    for i, r in enumerate(displayed, 1):
        lines.append(f"### {i}. {r.method}")
        lines.append("")
        lines.append(f"- **Score:** {r.score} | **Confidence:** {r.confidence}")
        
        if r.chain:
            lines.append(f"- **Chain:** `{' -> '.join(r.chain)}`")
        
        if r.flags:
            lines.append(f"- **Flags:**")
            for f in r.flags:
                lines.append(f"  - `{f}`")
        
        if r.reason and r.status == "skipped":
            lines.append(f"- **Reason:** {r.reason}")
        if r.error and r.status == "failed":
            lines.append(f"- **Error:** {r.error}")
        
        lines.append("")
        if r.output:
            lines.append(f"**Output Preview:**")
            lines.append(f"`{_preview(r.output)}`")
            lines.append("")

    lines.append("## Skipped / Failed Details")
    lines.append("")
    skipped_or_failed = [r for r in results if r.status in ("skipped", "failed")]
    if not skipped_or_failed:
        lines.append("None. All methods succeeded.")
    else:
        for r in skipped_or_failed:
            reason = r.reason or r.error or "unknown"
            lines.append(f"- **{r.method}** ({r.status}): {reason}")
    lines.append("")

    content = "\n".join(lines)
    with open(output_path, "w") as f:
        f.write(content)

    return output_path
