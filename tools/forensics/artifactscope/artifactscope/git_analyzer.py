from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple


VERIFIED_FLAG_REGEXES = [
    r"picoCTF\{[^}\r\n]{1,300}\}",
    r"flag\{[^}\r\n]{1,300}\}",
    r"ctf\{[^}\r\n]{1,300}\}",
]

FLAG_PATTERNS = [
    "picoCTF{",
    "flag{",
    "CTF{",
    "actf{",
    "dctf{",
]

SUSPICIOUS_KEYWORDS = [
    "flag",
    "secret",
    "password",
    "key",
    "ctf",
    "pico",
    "token",
    "api_key",
    "private_key",
]

HINT_PATTERNS = [
    r"g17_[A-Za-z0-9_]+",
    r"Wrap this phrase in the flag format:\s*([A-Za-z0-9_]+)",
]

FORENSIC_LEAD_KEYWORDS = [
    "remove flag",
    "add random",
    "delete flag",
    "secret file",
    "chat log",
]

FLAG_LIKE_PREFIXES = ["secret", "password", "key", "token", "flag", "ctf", "api_", "api_key", "private"]


def _classify_flag_content(content: str, source: str = "unknown") -> Tuple[List[str], List[str], List[str]]:
    verified_flags = []
    flag_candidates = []
    forensic_leads = []

    for pattern in VERIFIED_FLAG_REGEXES:
        for match in re.finditer(pattern, content, flags=re.IGNORECASE):
            verified_flags.append(match.group(0))

    content_lower = content.lower()
    for keyword in FORENSIC_LEAD_KEYWORDS:
        if keyword in content_lower:
            idx = content_lower.find(keyword)
            snippet = content[idx : idx + len(keyword) + 30]
            forensic_leads.append(f"[{keyword.upper()}] {snippet[:60]}")

    lines = content.split("\n")
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        if raw_line.startswith(("-", "+")):
            if len(line) > 1:
                line = line[1:].strip()
                if not line:
                    continue

        line_lower = line.lower()

        if any(line.startswith(kw) for kw in FLAG_LIKE_PREFIXES):
            if len(line) > 5 and len(line) < 200 and "{" not in line:
                if "remove" not in line_lower and "add" not in line_lower and "delete" not in line_lower:
                    if line not in verified_flags:
                        flag_candidates.append(f"[SUSPICIOUS_LINE] {line[:80]}")

        if any(kw in line_lower for kw in ["flag", "secret", "password", "token"]):
            if "remove" not in line_lower and "delete" not in line_lower and "add" not in line_lower:
                if len(line) > 5 and len(line) < 150 and line not in verified_flags:
                    if not any(line.startswith(kw) for kw in ["diff", "---", "+++", "commit", "Author", "Date"]):
                        flag_candidates.append(f"[FLAG_LIKE] {line[:80]}")

    file_path_pattern = re.compile(
        r"(?:^|[\s/])(flag|secret|password|key|token|ctf)[^\s]*",
        re.IGNORECASE,
    )
    for match in file_path_pattern.finditer(content):
        path_snippet = match.group(0).strip()
        if path_snippet not in forensic_leads and len(path_snippet) < 100:
            forensic_leads.append(f"[FILENAME] {path_snippet}")

    return verified_flags, flag_candidates, forensic_leads


def _run_git(repo_path: Path, args: List[str], timeout: int = 90) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def is_git_repo(path: Path) -> bool:
    head = path / ".git" / "HEAD"
    if not head.exists():
        return False
    try:
        content = head.read_text(errors="replace").strip()
    except Exception:
        return False

    if content.startswith("ref: refs/"):
        return True

    if re.fullmatch(r"[0-9a-fA-F]{40}", content):
        return True

    return False


def get_current_branch(repo_path: Path) -> Optional[str]:
    try:
        result = _run_git(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"], timeout=15)
        if result.returncode == 0:
            out = result.stdout.strip()
            if out and out != "HEAD":
                return out
    except Exception:
        pass

    try:
        head = (repo_path / ".git" / "HEAD").read_text(errors="replace").strip()
        if head.startswith("ref: refs/heads/"):
            return head.rsplit("/", 1)[-1]
    except Exception:
        pass

    return None


def get_branches(repo_path: Path) -> List[str]:
    try:
        result = _run_git(repo_path, ["branch", "-a"], timeout=15)
        if result.returncode == 0:
            return [b.strip().replace("* ", "") for b in result.stdout.splitlines() if b.strip()][:50]
    except Exception:
        pass
    return []


def get_tags(repo_path: Path) -> List[str]:
    try:
        result = _run_git(repo_path, ["tag"], timeout=15)
        if result.returncode == 0:
            return [t.strip() for t in result.stdout.splitlines() if t.strip()]
    except Exception:
        pass
    return []


def get_recent_commits(repo_path: Path, limit: int = 20) -> List[Dict[str, str]]:
    commits: List[Dict[str, str]] = []
    try:
        result = _run_git(repo_path, ["log", "--oneline", f"-{limit}", "--all"], timeout=60)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                commits.append(
                    {
                        "hash": parts[0][:40],
                        "message": parts[1] if len(parts) > 1 else "",
                    }
                )
    except Exception:
        pass
    return commits


def search_in_git(repo_path: Path, pattern: str) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []

    for args in (
        ["grep", "-n", pattern],
        ["grep", "-n", pattern, "--", "*"],
    ):
        try:
            result = _run_git(repo_path, args, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines()[:50]:
                    parts = line.split(":", 2)
                    if len(parts) >= 2:
                        results.append(
                            {
                                "file": parts[0],
                                "line": parts[1],
                                "content": parts[2] if len(parts) > 2 else "",
                            }
                        )
        except Exception:
            pass

    try:
        revs = _run_git(repo_path, ["rev-list", "--all"], timeout=60)
        if revs.returncode == 0:
            for commit in [c.strip() for c in revs.stdout.splitlines() if c.strip()][:100]:
                show = _run_git(repo_path, ["show", "--format=fuller", "--stat", commit], timeout=60)
                if show.returncode != 0:
                    continue
                text = show.stdout
                if pattern.lower() in text.lower():
                    results.append(
                        {
                            "file": f"<commit:{commit[:7]}>",
                            "line": "N/A",
                            "content": text[:200],
                        }
                    )
    except Exception:
        pass

    dedup = []
    seen = set()
    for item in results:
        key = (item["file"], item["line"], item["content"])
        if key not in seen:
            seen.add(key)
            dedup.append(item)
    return dedup[:50]


def find_deleted_files(repo_path: Path) -> List[Dict[str, str]]:
    deleted: List[Dict[str, str]] = []
    try:
        result = _run_git(repo_path, ["log", "--all", "--name-status", "--diff-filter=D"], timeout=60)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split("\t", 1)
                if len(parts) == 2 and parts[0].startswith("D"):
                    deleted.append({"path": parts[1].strip()})
    except Exception:
        pass

    uniq = []
    seen = set()
    for item in deleted:
        p = item.get("path", "")
        if p and p not in seen:
            seen.add(p)
            uniq.append(item)
    return uniq[:20]


def analyze_git_repo(repo_path: Path) -> Dict[str, object]:
    result = {
        "is_git_repo": False,
        "commits": [],
        "branches": [],
        "tags": [],
        "flag_search": [],
        "deleted_files": [],
        "current_branch": None,
    }

    if not is_git_repo(repo_path):
        return result

    result["is_git_repo"] = True
    result["current_branch"] = get_current_branch(repo_path)
    result["branches"] = get_branches(repo_path)
    result["tags"] = get_tags(repo_path)
    result["commits"] = get_recent_commits(repo_path)

    result["flag_search"] = search_in_git(repo_path, "picoCTF")
    result["flag_search"] += search_in_git(repo_path, "flag{")
    result["flag_search"] += search_in_git(repo_path, "CTF{")
    result["flag_search"] += search_in_git(repo_path, "g17_")

    result["deleted_files"] = find_deleted_files(repo_path)
    return result


def find_git_repos(root: Path) -> List[Dict[str, str]]:
    repos: List[Dict[str, str]] = []

    try:
        for git_dir in root.rglob(".git"):
            repo_root = git_dir.parent
            branch = get_current_branch(repo_root) or "unknown"

            try:
                rel_path = str(repo_root.relative_to(root))
            except ValueError:
                rel_path = str(repo_root)

            score = 0
            low = rel_path.lower()
            for kw in ["secret", "flag", "chat", "app", "killer", "ctf"]:
                if kw in low:
                    score += 1

            repos.append(
                {
                    "path": rel_path,
                    "branch": branch,
                    "score": score,
                }
            )
    except Exception:
        pass

    repos.sort(key=lambda x: x.get("score", 0), reverse=True)
    return repos[:20]


def _extract_flags_from_text(text: str) -> List[str]:
    verified_flags, flag_candidates, forensic_leads = _classify_flag_content(text, "git_text")
    return verified_flags + flag_candidates


def _extract_hints_from_text(text: str) -> List[str]:
    hints = []
    for pat in HINT_PATTERNS:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            if m.groups():
                hints.append(m.group(1))
            else:
                hints.append(m.group(0))
    return hints


def analyze_git_history(repo_path: Path) -> Dict[str, object]:
    result: Dict[str, object] = {
        "repo_path": str(repo_path),
        "commits": [],
        "deleted_files": [],
        "verified_flags": [],
        "flag_candidates": [],
        "forensic_leads": [],
        "hint_candidates": [],
        "recovered_content": [],
        "last_commit_message": "",
        "source": "git_history",
    }

    if not is_git_repo(repo_path):
        return result

    proc_log = _run_git(repo_path, ["log", "--oneline", "--all"], timeout=60)
    if proc_log.returncode == 0:
        for line in proc_log.stdout.splitlines()[:100]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            msg = parts[1] if len(parts) > 1 else ""
            for lead_kw in FORENSIC_LEAD_KEYWORDS:
                if lead_kw in msg.lower():
                    result["forensic_leads"].append(f"[COMMIT_MSG] {msg[:80]}")
                    break

            result["commits"].append(
                {
                    "hash": parts[0],
                    "message": msg,
                }
            )

    if result["commits"]:
        result["last_commit_message"] = result["commits"][0]["message"]

    result["deleted_files"] = [d["path"] for d in find_deleted_files(repo_path) if d.get("path")]

    for deleted_file in result["deleted_files"]:
        fn_lower = deleted_file.lower()
        if any(kw in fn_lower for kw in ["flag", "secret", "password", "token", "key"]):
            result["forensic_leads"].append(f"[DELETED_FILE] {deleted_file}")

    proc_patch = _run_git(repo_path, ["log", "-p", "--all"], timeout=120)
    if proc_patch.returncode == 0 and proc_patch.stdout.strip():
        patch_text = proc_patch.stdout

        verified, candidates, leads = _classify_flag_content(patch_text, "git_patch")
        result["verified_flags"].extend(verified)
        result["flag_candidates"].extend(candidates)
        result["forensic_leads"].extend(leads)

        result["hint_candidates"].extend(_extract_hints_from_text(patch_text))

        current_file = None
        deleted_lines: List[str] = []

        for line in patch_text.splitlines():
            if line.startswith("diff --git "):
                if current_file and deleted_lines:
                    result["recovered_content"].append(
                        {
                            "file": current_file,
                            "content": "\n".join(deleted_lines[:20]),
                        }
                    )
                current_file = None
                deleted_lines = []
                continue

            if line.startswith("--- a/"):
                current_file = line[6:].strip()
                continue

            if line.startswith("-") and not line.startswith("---"):
                deleted_lines.append(line[1:])

        if current_file and deleted_lines:
            result["recovered_content"].append(
                {
                    "file": current_file,
                    "content": "\n".join(deleted_lines[:20]),
                }
            )

    no_commit_repo = len(result["commits"]) == 0

    if no_commit_repo:
        result["source"] = "working_tree_recovery"

        proc_status = _run_git(repo_path, ["status", "--short"], timeout=30)
        if proc_status.returncode == 0 and proc_status.stdout.strip():
            result["recovered_content"].append(
                {
                    "file": "<git-status>",
                    "content": proc_status.stdout[:2000],
                }
            )
            result["hint_candidates"].extend(_extract_hints_from_text(proc_status.stdout))
            result["flag_candidates"].extend(_extract_flags_from_text(proc_status.stdout))

        proc_cached = _run_git(repo_path, ["diff", "--cached"], timeout=60)
        if proc_cached.returncode == 0 and proc_cached.stdout.strip():
            text = proc_cached.stdout
            result["recovered_content"].append(
                {
                    "file": "<git-diff-cached>",
                    "content": text[:4000],
                }
            )
            result["hint_candidates"].extend(_extract_hints_from_text(text))
            result["flag_candidates"].extend(_extract_flags_from_text(text))

        for path in repo_path.rglob("*"):
            if not path.is_file():
                continue
            if ".git" in path.parts:
                continue

            try:
                data = path.read_text(errors="replace")
            except Exception:
                continue

            if not data.strip():
                continue

            if (
                "flag" in path.name.lower()
                or "log" in path.name.lower()
                or "chat" in path.name.lower()
                or "secret" in path.name.lower()
                or "g17_" in data
                or "picoCTF" in data
                or "flag{" in data.lower()
            ):
                result["recovered_content"].append(
                    {
                        "file": str(path.relative_to(repo_path)),
                        "content": data[:2000],
                    }
                )

            result["hint_candidates"].extend(_extract_hints_from_text(data))
            result["flag_candidates"].extend(_extract_flags_from_text(data))

    else:
        proc_rev = _run_git(repo_path, ["rev-list", "--all"], timeout=60)
        if proc_rev.returncode == 0:
            commit_ids = [c.strip() for c in proc_rev.stdout.splitlines() if c.strip()]

            for commit in commit_ids[:150]:
                show = _run_git(repo_path, ["show", "--format=fuller", "--stat", commit], timeout=60)
                if show.returncode == 0:
                    text = show.stdout
                    result["flag_candidates"].extend(_extract_flags_from_text(text))
                    result["hint_candidates"].extend(_extract_hints_from_text(text))

                for deleted_file in result["deleted_files"][:20]:
                    blob = _run_git(repo_path, ["show", f"{commit}:{deleted_file}"], timeout=30)
                    if blob.returncode == 0 and blob.stdout:
                        content = blob.stdout
                        result["recovered_content"].append(
                            {
                                "file": deleted_file,
                                "content": content[:2000],
                            }
                        )
                        result["flag_candidates"].extend(_extract_flags_from_text(content))
                        result["hint_candidates"].extend(_extract_hints_from_text(content))

    for rc in result["recovered_content"]:
        content = rc.get("content", "")
        if content:
            verified, candidates, leads = _classify_flag_content(content, "recovered_content")
            result["verified_flags"].extend(verified)
            result["flag_candidates"].extend(candidates)
            result["forensic_leads"].extend(leads)
            result["hint_candidates"].extend(_extract_hints_from_text(content))

    for hint in list(result["hint_candidates"]):
        if hint.startswith("g17_"):
            wrapped = f"picoCTF{{{hint}}}"
            result["verified_flags"].append(wrapped)

    result["verified_flags"] = list(dict.fromkeys([x for x in result["verified_flags"] if x]))[:20]
    result["flag_candidates"] = list(dict.fromkeys([x for x in result["flag_candidates"] if x]))[:20]
    result["forensic_leads"] = list(dict.fromkeys([x for x in result["forensic_leads"] if x]))[:20]
    result["hint_candidates"] = list(dict.fromkeys([x for x in result["hint_candidates"] if x]))[:20]

    if (
        result["verified_flags"]
        or result["flag_candidates"]
        or result["deleted_files"]
        or result["recovered_content"]
        or result["hint_candidates"]
    ):
        if result["source"] == "git_history":
            result["source"] = "deleted_content_recovery"

    return result


def extract_git_repo_from_file(
    source_data: bytes,
    output_dir: Path,
    source_name: str,
) -> Optional[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    git_marker = b".git"
    pos = source_data.find(git_marker)
    if pos == -1:
        return None

    test_dir = output_dir / f"{source_name}_git"
    test_dir.mkdir(exist_ok=True)

    git_dir = test_dir / ".git"
    git_dir.mkdir(exist_ok=True)

    return None


def full_git_recovery(part_img: Path) -> Dict[str, object]:
    result = {
        "repo_path": "",
        "commits": [],
        "deleted_files": [],
        "verified_flags": [],
        "flag_candidates": [],
        "forensic_leads": [],
        "hint_candidates": [],
        "recovered_content": [],
        "source": "full_git_recovery",
        "git_objects": [],
        "git_logs": [],
        "lost_found": [],
    }

    if not part_img or not part_img.exists():
        return result

    git_dir = part_img / ".git"
    if not git_dir.exists():
        return result

    result["repo_path"] = str(part_img)

    if is_git_repo(part_img):
        result.update(analyze_git_history(part_img))
        result["source"] = "full_git_recovery"
        return result

    import zlib as zlib_module
    git_objects = git_dir / "objects"
    if git_objects.exists() and git_objects.is_dir():
        try:
            for obj in git_objects.rglob("*"):
                if obj.is_file() and obj.stat().st_size > 0:
                    try:
                        raw = obj.read_bytes()
                        try:
                            decompressed = zlib_module.decompress(raw)
                            text = decompressed.decode("utf-8", errors="ignore")
                            verified, candidates, leads = _classify_flag_content(text, "git_object")
                            result["verified_flags"].extend(verified)
                            result["flag_candidates"].extend(candidates)
                            result["forensic_leads"].extend(leads)
                        except zlib_module.error:
                            text = raw.decode("utf-8", errors="replace")
                            verified, candidates, leads = _classify_flag_content(text, "git_object")
                            result["verified_flags"].extend(verified)
                            result["flag_candidates"].extend(candidates)
                            result["forensic_leads"].extend(leads)
                    except Exception:
                        pass
        except Exception:
            pass

    git_logs = git_dir / "logs" / "HEAD"
    if git_logs.exists():
        try:
            logs_text = git_logs.read_text(errors="replace")
            result["git_logs"].append(logs_text[:2000])
            verified, candidates, leads = _classify_flag_content(logs_text, "git_log")
            result["verified_flags"].extend(verified)
            result["flag_candidates"].extend(candidates)
            result["forensic_leads"].extend(leads)
        except Exception:
            pass

    lost_found_dir = git_dir / "lost-found"
    if lost_found_dir.exists():
        try:
            for lost_file in lost_found_dir.rglob("*"):
                if lost_file.is_file():
                    try:
                        content = lost_file.read_text(errors="replace")
                        result["lost_found"].append({
                            "file": str(lost_file),
                            "content": content[:500],
                        })
                        verified, candidates, leads = _classify_flag_content(content, "lost_found")
                        result["verified_flags"].extend(verified)
                        result["flag_candidates"].extend(candidates)
                        result["forensic_leads"].extend(leads)
                    except Exception:
                        pass
        except Exception:
            pass

    return result


def git_deep_scan(git_dir_path: Path) -> Dict[str, object]:
    result = {
        "is_git_repo": False,
        "commits": [],
        "flag_search": [],
        "deleted_files": [],
        "log_name_status": [],
        "show_all": [],
        "fsck_lost_found": [],
        "git_objects": [],
        "git_logs": [],
        "lost_found": [],
        "verified_flags": [],
        "flag_candidates": [],
        "forensic_leads": [],
    }

    if not git_dir_path.exists():
        return result

    git_path = git_dir_path
    if git_dir_path.name != ".git":
        git_path = git_dir_path / ".git"

    if not git_path.exists():
        return result

    git_dir = git_path
    if not is_git_repo(git_dir_path):
        result["source_type"] = "git_dir_only"
        git_objects_dir = git_dir / "objects"
        if git_objects_dir.exists():
            try:
                for obj in git_objects_dir.rglob("*"):
                    if obj.is_file() and obj.stat().st_size > 0:
                        result["git_objects"].append(str(obj.relative_to(git_dir)))
            except Exception:
                pass

        git_logs = git_dir / "logs" / "HEAD"
        if git_logs.exists():
            try:
                result["git_logs"].append(git_logs.read_text(errors="replace")[:3000])
            except Exception:
                pass

        lost_found = git_dir / "lost-found"
        if lost_found.exists():
            try:
                for lf in lost_found.rglob("*"):
                    if lf.is_file():
                        content = lf.read_text(errors="replace")[:500]
                        result["lost_found"].append({
                            "path": str(lf.relative_to(git_dir)),
                            "content": content,
                        })
            except Exception:
                pass
        return result

    result["is_git_repo"] = True

    try:
        rev_list = _run_git(git_dir_path, ["rev-list", "--all"], timeout=60)
        if rev_list.returncode == 0:
            commits = [c.strip() for c in rev_list.stdout.splitlines() if c.strip()]
            result["commits"] = commits[:100]
    except Exception:
        pass

    try:
        for pattern in SUSPICIOUS_KEYWORDS:
            grep_result = _run_git(git_dir_path, ["grep", "-n", pattern, "--all"], timeout=60)
            if grep_result.returncode == 0 and grep_result.stdout.strip():
                for line in grep_result.stdout.splitlines()[:20]:
                    result["flag_search"].append(f"[{pattern}] {line}")

        grep_pico = _run_git(git_dir_path, ["grep", "-n", "picoCTF\\|flag", "--all"], timeout=60)
        if grep_pico.returncode == 0 and grep_pico.stdout.strip():
            for line in grep_pico.stdout.splitlines()[:50]:
                result["flag_search"].append(line)
    except Exception:
        pass

    try:
        log_status = _run_git(git_dir_path, ["log", "--all", "--name-status"], timeout=60)
        if log_status.returncode == 0 and log_status.stdout.strip():
            result["log_name_status"].append(log_status.stdout[:5000])
    except Exception:
        pass

    try:
        show_all = _run_git(git_dir_path, ["show", "--all"], timeout=120)
        if show_all.returncode == 0 and show_all.stdout.strip():
            result["show_all"].append(show_all.stdout[:10000])
            verified, candidates, leads = _classify_flag_content(show_all.stdout, "git_show")
            result["verified_flags"].extend(verified)
            result["flag_candidates"].extend(candidates)
            result["forensic_leads"].extend(leads)
    except Exception:
        pass

    try:
        fsck1 = _run_git(git_dir_path, ["fsck", "--lost-found"], timeout=60)
        if fsck1.returncode == 0 and fsck1.stdout.strip():
            result["fsck_lost_found"].append(fsck1.stdout[:2000])
    except Exception:
        pass

    try:
        fsck2 = _run_git(git_dir_path, ["fsck", "--no-reflogs", "--lost-found"], timeout=60)
        if fsck2.returncode == 0 and fsck2.stdout.strip():
            result["fsck_lost_found"].append(fsck2.stdout[:2000])
    except Exception:
        pass

    git_logs = git_dir / "logs" / "HEAD"
    if git_logs.exists():
        try:
            result["git_logs"].append(git_logs.read_text(errors="replace")[:3000])
        except Exception:
            pass

    lost_found = git_dir / "lost-found"
    if lost_found.exists():
        try:
            for lf in lost_found.rglob("*"):
                if lf.is_file():
                    content = lf.read_text(errors="replace")[:500]
                    result["lost_found"].append({
                        "path": str(lf.relative_to(git_dir)),
                        "content": content,
                    })
                    verified, candidates, leads = _classify_flag_content(content, "lost_found")
                    result["verified_flags"].extend(verified)
                    result["flag_candidates"].extend(candidates)
                    result["forensic_leads"].extend(leads)
        except Exception:
            pass

    result["verified_flags"] = list(dict.fromkeys([x for x in result["verified_flags"] if x]))[:20]
    result["flag_candidates"] = list(dict.fromkeys([x for x in result["flag_candidates"] if x]))[:20]
    result["forensic_leads"] = list(dict.fromkeys([x for x in result["forensic_leads"] if x]))[:20]

    return result


def recover_dangling_commits(git_dir_path: Path) -> Dict[str, object]:
    result = {
        "dangling_commits": [],
        "recovered_content": [],
        "verified_flags": [],
        "flag_candidates": [],
        "forensic_leads": [],
    }

    if not git_dir_path.exists():
        return result

    git_path = git_dir_path
    if git_dir_path.name != ".git":
        git_path = git_dir_path / ".git"

    if not git_path.exists():
        return result

    if not is_git_repo(git_dir_path):
        import zlib as zlib_module

        objects_dir = git_path / "objects"
        if not objects_dir.exists():
            return result

        for obj_dir in objects_dir.iterdir():
            if not obj_dir.is_dir() or len(obj_dir.name) != 2:
                continue
            try:
                for obj_file in obj_dir.iterdir():
                    if not obj_file.is_file():
                        continue
                    try:
                        raw = obj_file.read_bytes()
                        try:
                            decompressed = zlib_module.decompress(raw)
                            content = decompressed.decode("utf-8", errors="ignore")
                            verified, candidates, leads = _classify_flag_content(
                                content, "dangling_object"
                            )
                            result["verified_flags"].extend(verified)
                            result["flag_candidates"].extend(candidates)
                            result["forensic_leads"].extend(leads)
                        except Exception:
                            pass
                    except Exception:
                        pass
            except Exception:
                pass
        return result

    try:
        fsck_proc = _run_git(git_dir_path, ["fsck", "--no-reflogs", "--lost-found"], timeout=60)
        if fsck_proc.returncode == 0 and fsck_proc.stdout.strip():
            output = fsck_proc.stdout
            verified, candidates, leads = _classify_flag_content(output, "fsck_output")
            result["verified_flags"].extend(verified)
            result["flag_candidates"].extend(candidates)
            result["forensic_leads"].extend(leads)
    except Exception:
        pass

    if not result.get("verified_flags") and not result.get("flag_candidates"):
        import zlib as zlib_module
        objects_dir = (git_path / "objects")
        if objects_dir.exists():
            for obj_dir in objects_dir.iterdir():
                if not obj_dir.is_dir() or len(obj_dir.name) != 2:
                    continue
                try:
                    for obj_file in obj_dir.iterdir():
                        if not obj_file.is_file():
                            continue
                        try:
                            raw = obj_file.read_bytes()
                            try:
                                decompressed = zlib_module.decompress(raw)
                                content = decompressed.decode("utf-8", errors="ignore")
                                verified, candidates, leads = _classify_flag_content(
                                    content, "dangling_object"
                                )
                                result["verified_flags"].extend(verified)
                                result["flag_candidates"].extend(candidates)
                                result["forensic_leads"].extend(leads)
                            except Exception:
                                pass
                        except Exception:
                            pass
                except Exception:
                    pass

    try:
        reflog = _run_git(git_dir_path, ["reflog", "show", "--all"], timeout=30)
        if reflog.returncode == 0:
            result["dangling_commits"].append(reflog.stdout[:2000])
    except Exception:
        pass

    return result


# --- Compatibility wrapper for analyzer.py imports ---

def git_deep_recovery_chain(file_path: str, partitions, output_root: str):
    """
    Compatibility wrapper used by analyzer.py.
    Runs the available git recovery routines and merges their outputs.
    """
    result = {"mode": "git_deep_recovery_chain", "forensic_leads": [], "flag_candidates": [], "verified_flags": []}
    for fn in (full_git_recovery, analyze_git_history, recover_dangling_commits):
        try:
            out = fn(file_path) if fn is not recover_dangling_commits else fn(file_path)
        except TypeError:
            # Some versions expect repo path and may not apply here.
            continue
        except Exception:
            continue
        if not isinstance(out, dict):
            continue
        for k in ("forensic_leads", "flag_candidates", "verified_flags"):
            for item in out.get(k, []):
                if item not in result[k]:
                    result[k].append(item)
    return result
