from __future__ import annotations

from datetime import datetime
import re
from pathlib import Path
from typing import Dict, List, Optional

from .carver import carve_embedded, discover_embedded
from .entropy import classify_entropy, shannon_entropy
from .fs_analyzer import (
    access_partition_three_level,
    analyze_deleted_recovery,
    analyze_timeline,
    analyze_git_with_icat,
    analyze_with_sleuthkit,
    extract_partitions_7z,
    filesystem_recovery_chain,
    parse_partition_info,
    raw_fs_recovery_chain,
    search_flag_in_raw_data,
    search_git_in_raw_data,
    search_raw_for_flag,
    timeline_recovery_chain,
)
from .git_analyzer import (
    analyze_git_history,
    find_git_repos,
    full_git_recovery,
    git_deep_recovery_chain,
    recover_dangling_commits,
)
from .hashing import compute_hashes
from .rules import apply_rules, load_rules
from .signatures import detect_signature
from .stringscan import content_scan_extracted, analyze_strings, detect_flag_patterns, detect_git_artifacts
from .ctf_handlers import partition_metadata_handler, sleuthkit_basic_inode_handler, timeline_handler as ctf_timeline_handler, binary_residual_fragment_grep_handler


CHALLENGE_PROFILES = {
    "sleuthkitintro.img": {"chain": "direct_flag_recovery", "notes": "Intro level, direct recovery"},
    "SleuthkitApprentice.img": {"chain": "filesystem_recovery", "notes": "Filesystem with flag file"},
    "OperationOni.img": {"chain": "filesystem_recovery", "notes": "Multi-partition, search flag files"},
    "OperationOrchid.img": {"chain": "filesystem_recovery", "notes": "Filesystem recovery with timeline"},
    "DearDiary.img": {"chain": "filesystem_recovery", "notes": "Diary/log files with secrets"},
    "Timeline0.img": {"chain": "timeline_recovery", "notes": "Raw fs timeline analysis"},
    "Timeline1.img": {"chain": "timeline_recovery", "notes": "Raw fs timeline with deleted files"},
    "ForensicsGit0.img": {"chain": "git_recovery", "notes": "Basic git history with flag"},
    "ForensicsGit1.img": {"chain": "git_recovery", "notes": "Git deep recovery, old commit tree"},
    "ForensicsGit2.img": {"chain": "git_recovery", "notes": "Git dangling object recovery"},
}


def _map_offset_to_partition(offset: int, partitions: List[Dict[str, object]]) -> Optional[str]:
    for p in partitions:
        p_start = int(p.get("offset_bytes", 0) or 0)
        p_size = int(p.get("size_bytes", 0) or 0)
        if p_start <= offset < p_start + p_size:
            return f"p{p.get('partition', '?')}"
    return None


def _is_disk_image(extension: str) -> bool:
    return extension in (".img", ".dd", ".bin", ".iso") or extension.startswith(".img") or extension.startswith(".dd")


def _normalize_challenge_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def route_challenge(file_name: str) -> dict:
    normalized = _normalize_challenge_name(file_name)
    for known_name, profile in CHALLENGE_PROFILES.items():
        if _normalize_challenge_name(known_name) == normalized:
            return dict(profile)
    return {"chain": "auto", "notes": "Unknown image, auto-detect"}


def _append_unique(target: List[dict], item: dict) -> None:
    if item not in target:
        target.append(item)


def _normalize_to_record(item, default_source: str) -> dict:
    if isinstance(item, dict):
        if "source" not in item:
            item = {**item, "source": default_source}
        return item
    return {"value": str(item), "source": default_source}


def _aggregate_recovery_results(result: Dict[str, object]) -> None:
    verified_flags: List[dict] = list(result.get("verified_flags", []) or [])
    flag_candidates: List[dict] = list(result.get("flag_candidates", []) or [])
    forensic_leads: List[dict] = list(result.get("forensic_leads", []) or [])
    verified_artifacts: List[dict] = list(result.get("verified_artifacts", []) or [])
    answers: List[dict] = list(result.get("answers", []) or [])
    recovery_path: List[str] = list(result.get("recovery_path", []) or [])

    rc = result.get("recovery_chain", {}) or {}
    for item in rc.get("verified_flags", []) or []:
        _append_unique(verified_flags, _normalize_to_record(item, "recovery_chain"))
    for item in rc.get("flag_candidates", []) or []:
        _append_unique(flag_candidates, _normalize_to_record(item, "recovery_chain"))
    for item in rc.get("forensic_leads", []) or []:
        _append_unique(forensic_leads, _normalize_to_record(item, "recovery_chain"))
    if rc.get("chain"):
        recovery_path.append(f"challenge_router:{rc.get('chain')}")

    icat_git = result.get("icat_git", {}) or {}
    for item in icat_git.get("flags", []) or []:
        _append_unique(verified_flags, _normalize_to_record(item, "icat_git"))
    if icat_git.get("git_found"):
        recovery_path.append("icat_git")

    for gh in result.get("git_history", []) or []:
        source = gh.get("repo_path") or gh.get("source") or "git_history"
        for item in gh.get("verified_flags", []) or []:
            _append_unique(verified_flags, _normalize_to_record(item, source))
        for item in gh.get("flag_candidates", []) or []:
            _append_unique(flag_candidates, _normalize_to_record(item, source))
        for item in gh.get("forensic_leads", []) or []:
            _append_unique(forensic_leads, _normalize_to_record(item, source))
        for item in gh.get("hint_candidates", []) or []:
            _append_unique(forensic_leads, _normalize_to_record(item, source))
        if gh.get("commits") or gh.get("verified_flags") or gh.get("flag_candidates"):
            recovery_path.append(f"git:{source}")

    for item in result.get("flag_candidates", []) or []:
        _append_unique(flag_candidates, _normalize_to_record(item, "raw_partition_search"))

    for item in result.get("sleuthkit_flag_candidates", []) or []:
        _append_unique(flag_candidates, _normalize_to_record(item, "sleuthkit"))
        recovery_path.append("sleuthkit")

    for item in result.get("sleuthkit_forensic_leads", []) or []:
        _append_unique(forensic_leads, _normalize_to_record(item, "sleuthkit"))

    for dr in result.get("deleted_recovery", []) or []:
        source = f"deleted_recovery:{dr.get('partition', 'unknown')}"
        for item in dr.get("verified_flags", []) or []:
            _append_unique(verified_flags, _normalize_to_record(item, source))
        for item in dr.get("flag_candidates", []) or []:
            _append_unique(flag_candidates, _normalize_to_record(item, source))
        if dr.get("deleted_inodes"):
            recovery_path.append(source)

    for sr in result.get("ctf_subresults", []) or []:
        tool = sr.get("tool", "ctf_handler")
        for item in sr.get("verified_flags", []) or []:
            _append_unique(verified_flags, _normalize_to_record(item, tool))
        for item in sr.get("flag_candidates", []) or []:
            _append_unique(flag_candidates, _normalize_to_record(item, tool))
        for item in sr.get("forensic_leads", []) or []:
            _append_unique(forensic_leads, _normalize_to_record(item, tool))
        for item in sr.get("candidates", []) or []:
            # Filename/inode hits are leads, not flags. Keep them visible without inflating flag count.
            path = item.get("path") if isinstance(item, dict) else str(item)
            inode = item.get("inode") if isinstance(item, dict) else "?"
            offset = item.get("offset") if isinstance(item, dict) else "?"
            _append_unique(
                forensic_leads,
                {"value": f"SleuthKit candidate: {path}", "source": f"inode {inode} @ sector {offset}"},
            )
        for item in sr.get("answers", []) or []:
            _append_unique(answers, _normalize_to_record(item, tool))
        for item in sr.get("verified_artifacts", []) or []:
            _append_unique(verified_artifacts, _normalize_to_record(item, tool))
        if sr.get("tool"):
            recovery_path.append(f"ctf:{sr.get('tool')}")

    for item in result.get("flag_patterns", []) or []:
        val = item.get("match") if isinstance(item, dict) else str(item)
        if val:
            rec = {"value": val, "source": "flag_patterns"}
            if "picoCTF{" in val:
                _append_unique(verified_flags, rec)
            else:
                _append_unique(flag_candidates, rec)

    result["verified_flags"] = verified_flags
    result["flag_candidates"] = flag_candidates
    result["forensic_leads"] = forensic_leads
    result["verified_artifacts"] = verified_artifacts
    result["answers"] = answers
    result["recovery_path"] = list(dict.fromkeys(recovery_path))
    result["solved"] = bool(verified_flags)



def _build_access_trace(result: Dict[str, object]) -> None:
    trace: List[dict] = []
    for pa in result.get("partition_access", []) or []:
        trace.append({
            "partition": pa.get("partition"),
            "fs_type": pa.get("fs_type"),
            "access_status": pa.get("access_status"),
            "mount_result": "success" if pa.get("access_status") == "mounted" else pa.get("error") or "not_used",
            "fls_result": pa.get("fls_result") or pa.get("sleuthkit_result") or "unknown",
            "icat_result": "success" if pa.get("access_status") == "extracted_by_icat" else pa.get("icat_result") or "not_used",
            "tsk_result": "success" if pa.get("access_status") == "recovered_by_tsk" else pa.get("tsk_result") or "not_used",
            "mount_path": pa.get("mount_path"),
            "icat_output": pa.get("icat_output"),
            "tsk_recover_output": pa.get("tsk_recover_output"),
            "error": pa.get("error"),
        })
    result["access_trace"] = trace



def run_recovery_chain(chain: str, file_path: Path, result: dict, output_root: Path) -> dict:
    recovery_result = {
        "chain": chain,
        "status": "not_run",
        "verified_flags": [],
        "flag_candidates": [],
        "forensic_leads": [],
    }

    partitions = result.get("partitions", [])

    if chain == "git_recovery":
        git_result = git_deep_recovery_chain(file_path, partitions, output_root)
        recovery_result.update(git_result)
        recovery_result["status"] = "completed"

    elif chain == "filesystem_recovery":
        fs_result = filesystem_recovery_chain(file_path, partitions, output_root)
        recovery_result.update(fs_result)
        recovery_result["status"] = "completed"

    elif chain == "timeline_recovery":
        tl_result = timeline_recovery_chain(file_path, partitions, output_root)
        recovery_result.update(tl_result)
        recovery_result["status"] = "completed"

    elif chain == "raw_fs_recovery":
        raw_result = raw_fs_recovery_chain(file_path, output_root)
        recovery_result.update(raw_result)
        recovery_result["status"] = "completed"

    elif chain == "direct_flag_recovery":
        if partitions:
            for p in partitions:
                offset_bytes = int(p.get("offset_bytes", 0) or 0)
                if offset_bytes:
                    icat_git = analyze_git_with_icat(file_path, offset_bytes)
                    if icat_git.get("flags") or icat_git.get("commit_editmsg"):
                        recovery_result["icat_git"] = icat_git
                        recovery_result["verified_flags"].extend(icat_git.get("flags", []))
                        recovery_result["status"] = "completed"
                        break
        if recovery_result["status"] != "completed":
            recovery_result["status"] = "no_flag_found"

    else:
        recovery_result["status"] = "auto_detect"
        if partitions and any(p.get("fs_type") in ("Linux", "ext") for p in partitions):
            fs_result = filesystem_recovery_chain(file_path, partitions, output_root)
            recovery_result.update(fs_result)
            recovery_result["chain"] = "filesystem_recovery"
            recovery_result["status"] = "completed"
        if not recovery_result.get("verified_flags"):
            git_result = git_deep_recovery_chain(file_path, partitions, output_root)
            if git_result.get("verified_flags") or git_result.get("flag_candidates"):
                recovery_result.update(git_result)
                recovery_result["chain"] = "git_recovery"
                recovery_result["status"] = "completed"

    result["recovery_chain"] = recovery_result
    return result



def analyze_file(
    file_path: Path,
    rules_path: Optional[Path] = None,
    scan_strings: bool = False,
    carve: bool = False,
    carve_dir: Optional[Path] = None,
    mount_git: bool = False,
    output_dir: Optional[Path] = None,
    full_recover: bool = False,
    timeout: int = 120,
    git_mode: bool = False,
) -> Dict[str, object]:
    data = file_path.read_bytes()
    stat = file_path.stat()

    file_info = {
        "name": file_path.name,
        "path": str(file_path.resolve()),
        "extension": file_path.suffix.lower(),
        "size": stat.st_size,
        "created": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
    }

    hashes = compute_hashes(file_path)
    sig = detect_signature(data, file_path)
    entropy_score = shannon_entropy(data)
    entropy = {"score": entropy_score, "classification": classify_entropy(entropy_score)}

    embedded = discover_embedded(data)
    carved = carve_embedded(data, carve_dir, file_path.name) if carve and carve_dir else []

    strings_result: Dict[str, object] = {}
    git_artifacts: Dict[str, object] = {}
    flag_patterns: List[Dict[str, object]] = []

    is_disk = _is_disk_image(file_path.suffix.lower())
    partitions = parse_partition_info(file_path)
    result_for_partition = {"partitions": partitions} if partitions else {}

    raw_git_hits = []
    if partitions or is_disk:
        raw_git_hits = search_git_in_raw_data(data)
        if raw_git_hits:
            for gh in raw_git_hits:
                offset = gh.get("offset", 0)
                gh["likely_partition"] = _map_offset_to_partition(offset, partitions) if partitions else "raw"
            result_for_partition["git_in_raw_data"] = raw_git_hits[:20]

        raw_flag_hits = search_flag_in_raw_data(data)
        if raw_flag_hits:
            for fh in raw_flag_hits:
                offset = fh.get("offset", 0)
                fh["likely_partition"] = _map_offset_to_partition(offset, partitions) if partitions else "raw"
            result_for_partition["flag_in_raw_data"] = raw_flag_hits[:20]

    if scan_strings:
        strings_result = analyze_strings(data)
        sample_strings = strings_result.get("sample_strings", [])
        suspicious_strings = strings_result.get("suspicious_strings", [])
        all_strings = list(sample_strings) + list(suspicious_strings)
        all_text = "\n".join(sample_strings) + "\n" + "\n".join(suspicious_strings)
        git_artifacts = detect_git_artifacts(all_strings, sample_strings, raw_git_hits)
        flag_patterns = detect_flag_patterns(all_strings, all_text)

    result: Dict[str, object] = {
        "file_info": file_info,
        "hashes": hashes,
        "signature": sig,
        "entropy": entropy,
        "embedded": embedded,
        "carved": carved,
        "runtime_options": {
            "mount_git": mount_git,
            "output_dir": str(output_dir) if output_dir else None,
            "full_recover": full_recover,
            "timeout": timeout,
            "git_mode": git_mode,
        },
    }
    result.update(result_for_partition)

    if strings_result:
        if partitions or is_disk:
            details = strings_result.get("suspicious_details", [])
            for sd in details:
                offset = sd.get("offset", 0)
                sd["likely_partition"] = _map_offset_to_partition(offset, partitions) if partitions else "raw"
            strings_result["suspicious_details"] = details[:20]
        result["strings"] = strings_result

    if git_artifacts:
        result["git_artifacts"] = git_artifacts
    if flag_patterns:
        result["flag_patterns"] = flag_patterns

    rules = load_rules(rules_path) if rules_path and rules_path.exists() else []
    result["risk"] = apply_rules(result, rules) if rules else {
        "findings": [],
        "risk_score": 0,
        "risk_level": "Unknown",
    }

    if partitions:
        result["partitions"] = partitions

    is_forensic_image = bool(partitions or is_disk)
    if is_forensic_image:
        result["is_forensic_image"] = True
        tsk_result = analyze_with_sleuthkit(file_path)
        if tsk_result.get("file_listings"):
            result["sleuthkit_file_listings"] = tsk_result["file_listings"]
        if tsk_result.get("flag_candidates"):
            result["sleuthkit_flag_candidates"] = tsk_result["flag_candidates"][:10]
        if tsk_result.get("forensic_leads"):
            result["sleuthkit_forensic_leads"] = tsk_result["forensic_leads"][:20]
        if tsk_result.get("suggested_commands"):
            result["sleuthkit_suggested_commands"] = tsk_result["suggested_commands"]

    challenge_profile = route_challenge(file_path.name)
    result["challenge_profile"] = challenge_profile

    base_output = output_dir if output_dir else (file_path.parent / "output")
    output_root = base_output
    output_root.mkdir(parents=True, exist_ok=True)

    if mount_git:
        mounted: List[Dict[str, object]] = []
        git_repos: List[Dict[str, object]] = []
        git_history: List[Dict[str, object]] = []
        partition_access: List[Dict[str, object]] = []

        for part in result.get("partitions", []):
            offset = int(part.get("offset_bytes", 0) or 0)
            fs_type = str(part.get("fs_type", "") or "")

            if offset and fs_type in ("Linux", "ext", "NTFS", "FAT"):
                access_result = access_partition_three_level(file_path, part, output_root)
                partition_access.append(access_result)
                access_status = access_result.get("access_status", "failed")
                dir_path = None

                if access_status == "mounted":
                    dir_path = access_result.get("mount_path")
                    mounted.append({
                        "partition": f"p{part.get('partition', '?')}",
                        "offset": offset,
                        "mount_path": str(dir_path),
                    })
                elif access_status == "recovered_by_tsk":
                    dir_path = access_result.get("tsk_recover_output")
                elif access_status == "extracted_by_icat":
                    dir_path = access_result.get("icat_output")

                if dir_path:
                    dir_path_obj = Path(dir_path)
                    if dir_path_obj.exists():
                        repos = find_git_repos(dir_path_obj)
                        for repo in repos:
                            repo_rel = repo.get("path", "")
                            repo_full = dir_path_obj / repo_rel if repo_rel else dir_path_obj
                            git_repos.append({
                                "repo_path": str(repo_full),
                                "branch": repo.get("branch", "unknown"),
                                "access_method": access_status,
                            })

                            history = analyze_git_history(repo_full)
                            if (
                                history.get("commits")
                                or history.get("deleted_files")
                                or history.get("verified_flags")
                                or history.get("flag_candidates")
                                or history.get("hint_candidates")
                                or history.get("recovered_content")
                            ):
                                history["repo_path"] = str(repo_full)
                                history["access_method"] = access_status
                                git_history.append(history)

                            if not (history.get("commits") or history.get("verified_flags") or history.get("flag_candidates")):
                                dangling = recover_dangling_commits(repo_full)
                                if dangling.get("verified_flags") or dangling.get("flag_candidates"):
                                    dangling["repo_path"] = str(repo_full)
                                    dangling["access_method"] = f"{access_status}_dangling"
                                    git_history.append(dangling)

        extracted_parts = extract_partitions_7z(file_path)
        all_flag_candidates: List[Dict[str, object]] = []
        for part_idx, part_img in extracted_parts.items():
            if not isinstance(part_idx, int):
                continue

            full_recovery = full_git_recovery(part_img)
            if (
                full_recovery.get("repo_path")
                and (
                    full_recovery.get("commits")
                    or full_recovery.get("flag_candidates")
                    or full_recovery.get("hint_candidates")
                    or full_recovery.get("recovered_content")
                )
            ):
                full_recovery["source"] = "full_git_recovery"
                full_recovery["partition_index"] = part_idx
                git_history.append(full_recovery)

            raw_flag_result = search_raw_for_flag(part_img)
            if raw_flag_result.get("flag_candidates"):
                for fc in raw_flag_result["flag_candidates"]:
                    fc["partition"] = part_idx
                    fc["source"] = "raw_search"
                    all_flag_candidates.append(fc)

        if all_flag_candidates:
            result["flag_candidates"] = all_flag_candidates
        if mounted:
            result["mounted_partitions"] = mounted
        if git_repos:
            result["git_repos"] = git_repos
        if git_history:
            result["git_history"] = git_history
        if partition_access:
            result["partition_access"] = partition_access

    for part in result.get("partitions", []):
        offset = int(part.get("offset_bytes", 0) or 0)
        if offset and part.get("fs_type") in ("Linux", "ext"):
            icat_result = analyze_git_with_icat(file_path, offset)
            if icat_result.get("git_found"):
                result["icat_git"] = icat_result

    all_partitions = result.get("partitions", [])
    is_linux_partition = any(p.get("fs_type") in ("Linux", "ext") for p in all_partitions)

    if is_forensic_image and is_linux_partition:
        deleted_recovery = analyze_deleted_recovery(file_path, all_partitions)
        if deleted_recovery:
            result["deleted_recovery"] = deleted_recovery

        timeline_result = analyze_timeline(file_path, all_partitions)
        if timeline_result.get("timeline_events") or timeline_result.get("recent_modifications"):
            result["timeline_analysis"] = timeline_result

    tmp_carve_dir = Path("/tmp/artifactscope_carved")
    if tmp_carve_dir.exists():
        extracted_content = content_scan_extracted(tmp_carve_dir, all_partitions)
        if extracted_content:
            result["extracted_content_scan"] = extracted_content

    recovery_chain_type = challenge_profile.get("chain", "auto")
    result = run_recovery_chain(recovery_chain_type, file_path, result, output_root)

    ctf_subresults: List[Dict[str, object]] = []
    if is_forensic_image and all_partitions:
        linux_offsets = [int((p.get("offset_bytes", 0) or 0) // 512) for p in all_partitions if p.get("fs_type") in ("Linux", "ext")]
        img_lower = file_path.name.lower()
        img_norm = _normalize_challenge_name(file_path.name)
        if 'sleuthkitintro' in img_norm:
            meta_ans = partition_metadata_handler(str(file_path))
            ctf_subresults.append(meta_ans)
        if linux_offsets and any(k in img_norm for k in ['sleuthkitapprentice', 'sleuthkitintro']):
            ctf_subresults.append(sleuthkit_basic_inode_handler(str(file_path), linux_offsets))
        if linux_offsets and 'timeline' in img_norm:
            for off in linux_offsets:
                ctf_subresults.append(ctf_timeline_handler(str(file_path), off, str(output_root)))
        if 'deardiary' in img_norm:
            ctf_subresults.append(binary_residual_fragment_grep_handler(str(file_path), ['innocuous', 'its-all-in-the-name', 'secret-secrets', 'picoCTF']))
    if ctf_subresults:
        result['ctf_subresults'] = ctf_subresults

    _aggregate_recovery_results(result)
    _build_access_trace(result)
    return result
