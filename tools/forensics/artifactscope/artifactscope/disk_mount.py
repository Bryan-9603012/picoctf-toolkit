from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def _run(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def has_command(cmd: str) -> bool:
    return shutil.which(cmd) is not None


class PartitionScanner:
    def __init__(self, image_path: Path):
        self.image_path = image_path
        self.partitions: List[Dict] = []

    def scan_mmls(self) -> List[Dict]:
        if not has_command("mmls"):
            return []
        
        result = _run(["mmls", "-o", str(self.image_path)], timeout=30)
        if result.returncode != 0:
            return []
        
        parts = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("geom") or line.startswith("-"):
                continue
            
            parts_m = re.match(r"(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)", line)
            if parts_m:
                slot, start, end, size, desc = parts_m.groups()
                parts.append({
                    "slot": int(slot),
                    "start": int(start),
                    "end": int(end),
                    "size": int(size),
                    "description": desc,
                })
        
        return parts

    def scan_fdisk(self) -> List[Dict]:
        result = _run(["fdisk", "-l", str(self.image_path)], timeout=20)
        if result.returncode != 0:
            return []
        
        parts = []
        for line in result.stdout.splitlines():
            if self.image_path.name not in line:
                continue
            
            m = re.match(
                r"(\S+)\s+\*?\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$",
                line.strip()
            )
            if m:
                dev, start, end, sectors, size, part_id, ptype = m.groups()
                fs_type = "Unknown"
                if "Linux swap" in ptype:
                    fs_type = "Linux swap"
                elif "Linux" in ptype:
                    fs_type = "Linux"
                elif "NTFS" in ptype:
                    fs_type = "NTFS"
                elif "FAT" in ptype:
                    fs_type = "FAT"
                
                parts.append({
                    "slot": int(part_id),
                    "start": int(start),
                    "sectors": int(sectors),
                    "size_bytes": int(sectors) * 512,
                    "fs_type": fs_type,
                    "description": ptype.strip(),
                })
        
        return parts

    def scan(self) -> List[Dict]:
        parts = self.scan_mmls()
        if not parts:
            parts = self.scan_fdisk()
        
        for p in parts:
            p["offset_bytes"] = p.get("start", 0) * 512
            p["size_mb"] = round(p.get("size_bytes", 0) / (1024 * 1024))
        
        self.partitions = parts
        return parts

    def to_json(self) -> Dict:
        return {
            "image": str(self.image_path),
            "partitions": self.partitions,
        }


class DiskMounter:
    def __init__(self, image_path: Path, mount_base: Optional[Path] = None):
        self.image_path = image_path
        self.mount_base = mount_base or Path("/tmp/artifactscope_mount")
        self.mounted_partitions: Dict[str, Path] = {}

    def _get_partition_offset(self, part_info: Dict) -> int:
        return part_info.get("offset_bytes", part_info.get("start", 0) * 512)

    def mount_partition(self, part_info: Dict, partition_id: str) -> Optional[Path]:
        offset = self._get_partition_offset(part_info)
        mount_point = self.mount_base / f"{self.image_path.name}_{partition_id}"
        
        mount_point.mkdir(parents=True, exist_ok=True)
        
        if has_command("mount"):
            result = _run([
                "mount",
                "-o", f"ro,loop,offset={offset}",
                str(self.image_path),
                str(mount_point),
            ], timeout=15)
            
            if result.returncode == 0:
                self.mounted_partitions[partition_id] = mount_point
                return mount_point
        
        if has_command("debugfs"):
            result = _run(["debugfs", "-R", f"stats {offset}", str(self.image_path)], timeout=10)
            if result.returncode == 0:
                self.mounted_partitions[partition_id] = mount_point
                return mount_point

        if has_command("icat"):
            return mount_point

        return None

    def mount_all(self, partitions: List[Dict]) -> Dict[str, Path]:
        for p in partitions:
            pid = f"p{p.get('slot', p.get('partition', 0))}"
            self.mount_partition(p, pid)
        
        return self.mounted_partitions

    def unmount_all(self):
        if has_command("umount"):
            for mp in self.mounted_partitions.values():
                _run(["umount", str(mp)], timeout=10)
        
        import shutil
        if shutil.which("fusermount"):
            for mp in self.mounted_partitions.values():
                _run(["fusermount", "-u", str(mp)], timeout=10)
        
        self.mounted_partitions = {}


class FileEnumerator:
    def __init__(self, mount_point: Path):
        self.mount_point = mount_point
        self.files: List[Dict] = []
        self.candidates: List[Dict] = []

    def enumerate(self, max_files: int = 1000) -> List[Dict]:
        if not self.mount_point.exists():
            return []
        
        FLAG_RE = re.compile(r"picoCTF\{[^}\r\n]{1,300}\}", re.IGNORECASE)
        
        for path in self.mount_point.rglob("*"):
            if not path.is_file():
                continue
            
            try:
                stat = path.stat()
                rel_path = str(path.relative_to(self.mount_point))
            except (PermissionError, OSError):
                continue
            
            entry = {
                "path": rel_path,
                "size": stat.st_size,
            }
            
            if stat.st_size < 1024 * 1024:
                try:
                    content = path.read_text(errors="ignore")
                    for m in FLAG_RE.finditer(content):
                        self.candidates.append({
                            "file": rel_path,
                            "match": m.group()[:100],
                        })
                except Exception:
                    pass
            
            self.files.append(entry)
            
            if len(self.files) >= max_files:
                break
        
        return self.files[:max_files]

    def grep_pattern(self, pattern: str, max_results: int = 50) -> List[Dict]:
        if not self.mount_point.exists():
            return []
        
        results = []
        
        if has_command("grep"):
            result = _run([
                "grep", "-r", "-l", pattern,
                str(self.mount_point),
                "--include=*.txt",
                "--include=*.md",
                "--include=*.log",
            ], timeout=30)
            
            if result.returncode == 0:
                for f in result.stdout.splitlines()[:20]:
                    results.append({"file": f, "pattern": pattern})
        
        return results[:max_results]

    def to_json(self) -> Dict:
        return {
            "mount_point": str(self.mount_point),
            "files": self.files[:500],
            "candidates": self.candidates[:50],
        }


class GitRecovery:
    def __init__(self, git_root: Path):
        self.git_root = git_root

    def is_valid_repo(self) -> bool:
        head = self.git_root / ".git" / "HEAD"
        if not head.exists():
            return False
        try:
            content = head.read_text(errors="replace").strip()
            return "ref: refs/" in content or len(content) == 40
        except Exception:
            return False

    def get_reflog(self, limit: int = 50) -> List[Dict]:
        if not self.is_valid_repo():
            return []
        
        result = _run(
            ["git", "log", "--all", "--walk=reflogs", "--format=%h %g%d %s"],
            cwd=self.git_root,
            timeout=30
        )
        
        if result.returncode != 0:
            return []
        
        entries = []
        for line in result.stdout.splitlines()[:limit]:
            parts = line.split(None, 2)
            if len(parts) >= 2:
                entries.append({
                    "hash": parts[0],
                    "ref": parts[1],
                    "message": parts[2] if len(parts) > 2 else "",
                })
        
        return entries

    def get_unreachable_commits(self) -> List[Dict]:
        if not self.is_valid_repo():
            return []
        
        result = _run(
            ["git", "fsck", "--unreachable", "--no-progress"],
            cwd=self.git_root,
            timeout=30
        )
        
        if result.returncode != 0:
            return []
        
        commits = []
        for line in result.stdout.splitlines():
            if "commit" in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    commits.append({"object": parts[-1][:40]})
        
        return commits

    def show_commit(self, commit_hash: str) -> Optional[Dict]:
        result = _run(
            ["git", "show", "--format=fuller", commit_hash],
            cwd=self.git_root,
            timeout=30
        )
        
        if result.returncode != 0:
            return None
        
        text = result.stdout
        flags = re.findall(r"(picoCTF\{[^}]+\}|flag\{[^}]+\})", text, re.IGNORECASE)
        
        return {
            "hash": commit_hash[:7],
            "content": text[:2000],
            "flags": flags[:10],
        }

    def scan_dangling_blobs(self) -> List[Dict]:
        if not self.is_valid_repo():
            return []
        
        git_dir = self.git_root / ".git"
        objects_dir = git_dir / "objects"
        
        if not objects_dir.exists():
            return []
        
        dangling = []
        
        for subdir in objects_dir.iterdir():
            if not subdir.is_dir() or len(subdir.name) != 2:
                continue
            
            for obj in subdir.iterdir():
                if not obj.is_file():
                    continue
                
                blob_hash = subdir.name + obj.name
                
                result = _run(
                    ["git", "cat-file", "-p", blob_hash],
                    cwd=self.git_root,
                    timeout=10
                )
                
                if result.returncode == 0:
                    content = result.stdout[:500]
                    if any(p in content.lower() for p in ["picoctf", "flag", "password", "secret"]):
                        dangling.append({
                            "blob": blob_hash,
                            "preview": content[:200],
                        })
        
        return dangling[:20]

    def full_recovery(self) -> Dict:
        result = {
            "is_valid_repo": self.is_valid_repo(),
            "reflog": [],
            "unreachable": [],
            "commits": [],
            "dangling_blobs": [],
            "flags_found": [],
        }
        
        if not self.is_valid_repo():
            return result
        
        result["reflog"] = self.get_reflog()
        result["unreachable"] = self.get_unreachable_commits()
        
        result_log = _run(
            ["git", "log", "--all", "--oneline", "-50"],
            cwd=self.git_root,
            timeout=30
        )
        
        if result_log.returncode == 0:
            for line in result_log.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if not parts:
                    continue
                
                commit_hash = parts[0]
                show = self.show_commit(commit_hash)
                
                if show:
                    result["commits"].append(show)
                    result["flags_found"].extend(show.get("flags", []))
        
        result["dangling_blobs"] = self.scan_dangling_blobs()
        
        for blob in result["dangling_blobs"]:
            if "flag" in blob.get("preview", "").lower():
                result["flags_found"].append(blob["preview"])
        
        result["flags_found"] = list(set(result["flags_found"]))[:20]
        
        return result


def analyze_disk_image(
    image_path: Path,
    output_dir: Optional[Path] = None,
) -> Dict:
    output_dir = output_dir or Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    result = {
        "image": str(image_path),
        "partitions": [],
        "mounted": {},
        "files": [],
        "git_repos": [],
    }
    
    scanner = PartitionScanner(image_path)
    partitions = scanner.scan()
    result["partitions"] = partitions
    
    partitions_file = output_dir / f"{image_path.stem}_partitions.json"
    partitions_file.write_text(json.dumps(scanner.to_json(), indent=2))
    
    mounter = DiskMounter(image_path, output_dir / "mounts")
    mounted = mounter.mount_all(partitions)
    result["mounted"] = {k: str(v) for k, v in mounted.items()}
    
    for part_id, mount_point in mounted.items():
        if not mount_point.exists():
            continue
        
        enumerator = FileEnumerator(mount_point)
        files = enumerator.enumerate()
        result["files"].extend(files)
        
        for f in enumerator.candidates:
            result["git_repos"].append(f)
        
        git_root = mount_point
        if git_root.is_dir():
            for git_dir in git_root.rglob(".git"):
                recovery = GitRecovery(git_dir.parent)
                git_result = recovery.full_recovery()
                
                if git_result.get("flags_found"):
                    result["git_repos"].append({
                        "path": str(git_dir.parent.relative_to(mount_point)),
                        "flags": git_result["flags_found"],
                        "reflog": len(git_result["reflog"]),
                        "unreachable": len(git_result["unreachable"]),
                    })
    
    mounter.unmount_all()
    
    files_index = output_dir / f"{image_path.stem}_file_index.json"
    files_index.write_text(json.dumps(result, indent=2, default=str))
    
    return result