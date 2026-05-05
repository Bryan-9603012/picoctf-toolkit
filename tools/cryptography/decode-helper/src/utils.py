import sys

SEPARATOR = "=" * 50
SUB_SEPARATOR = "-" * 50
PREVIEW_LENGTH = 60


def _preview(text: str, length: int = PREVIEW_LENGTH) -> str:
    if len(text) <= length:
        return text
    return text[:length] + "..."


def print_header(title: str):
    print()
    print(SEPARATOR)
    print(f" {title}")
    print(SEPARATOR)
    print()


def print_input(text: str):
    print("[INPUT]")
    print(text)
    print()


def print_best_candidate(result):
    print("[BEST CANDIDATE]")
    print()
    if result.flags:
        print(f"Flag: {result.flags[0]}")
    print(f"Score: {result.score}")
    print(f"Confidence: {result.confidence}")
    if result.chain:
        print(f"Chain: {' -> '.join(result.chain)}")
    if result.output:
        print()
        print("[OUTPUT]")
        print(result.output)
    print()


def print_results(results):
    print("[TOP RESULTS]")
    print()
    for i, r in enumerate(results, 1):
        print(SUB_SEPARATOR)
        print(f"[{i}] {r.method}")
        print(f"Score: {r.score} | Confidence: {r.confidence}")
        if r.chain:
            print(f"Chain: {' -> '.join(r.chain)}")
        if r.flags:
            print("Flags:")
            for f in r.flags:
                print(f"  - {f}")
        if r.reason and r.status == "skipped":
            print(f"Reason: {r.reason}")
        if r.error and r.status == "failed":
            print(f"Error: {r.error}")
        if r.output:
            print("Output Preview:")
            print(_preview(r.output))
        print()


def print_applicability(log: list[dict]):
    print("[APPLICABILITY LOG]")
    print()
    for entry in log:
        print(SUB_SEPARATOR)
        print(f"Layer {entry['layer']} candidate: {_preview(entry['input'], 40)}")
        print()
        print("Expanded decoders:")
        top_policies = [(n, s, r) for n, s, r in entry["policy"] if s >= 10]
        top_policies.sort(key=lambda x: x[1], reverse=True)
        for name, score, reason in top_policies[:3]:
            print(f"  - {name}: {score} ({reason})")
        print()


def print_report_saved(path: str):
    print()
    print("[REPORT]")
    print(f"Saved to {path}")
    print()
