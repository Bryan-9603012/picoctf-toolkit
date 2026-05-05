# ArtifactScope Roadmap

## Current Status (v0.1)
- Raw disk image scanner
- Entropy, signatures, embedded file detection
- Strings scan with IOC patterns
- Git indicator detection (raw)

## Target Architecture

```
disk.img → [Partition Scanner] → partitions.json
               ↓
         [Mount + Enumerate] → file_index.json
               ↓
            [Git Recovery] → git_history.json
               ↓
           [LLM Report] → summary.md / report.json / candidates.json
```

## v0.2: Partition-Aware Scanner

- [ ] Auto-run `mmls` (The Sleuth Kit)
- [ ] Detect Linux / FAT / NTFS / ext4 / XFS partitions
- [ ] Calculate: offset = start_sector * sector_size
- [ ] Output: `partitions.json`
  ```json
  {
    "disk": "image.img",
    "partitions": [
      {"id": "p1", "type": "Linux", "start_sector": 2048, "sectors": 614400, "offset": 1048576, "size_mb": 300}
    ]
  }
  ```

## v0.3: Mount + File Enumeration

- [ ] Read-only mount each partition (requires root/elevated)
- [ ] `find` to enumerate all filenames
- [ ] `grep` for patterns: picoCTF, flag, password, key, ssh, private
- [ ] Export: `file_index.json`
  ```json
  {
    "partition": "p1",
    "files": [
      {"path": "/home/user/secret.txt", "size": 45, "modified": "..."}
    ],
    "candidates": [
      {"file": "/home/user/.bashrc", "match": "flag{...", "line": 15}
    ]
  }
  ```

## v0.4: Git Recovery

- [ ] Locate `.git` directories in mounted partitions
- [ ] `git log --all --oneline`
- [ ] `git reflog`
- [ ] `git show` each commit
- [ ] Scan `.git/objects/` for dangling blobs
- [ ] Recover deleted files with `git fsck --unreachable`

## v0.5: LLM-Ready Report

- [ ] `summary.md` - Executive summary (executive-friendly)
- [ ] `report.json` - Full structured data
- [ ] `candidates.json` - Flag/password candidates with confidence scores
- [ ] `recommended_next_steps.json` - Suggested commands/actions

## Design Principles

1. **No LLM on raw disk image** - Tool first, LLM second
2. **Structure extraction** → LLM analysis
3. **Offline-first** - Work without network
4. **Minimal dependencies** - Use standard forensics tools (mmls, git, mount, find, grep)
5. **Composable** - Each stage output feeds next stage

## Technical Notes

- Partition detection uses MBR/GPT parsing
- Mount requires: root or FUSE (libguestfs)
- Git recovery can work without mounting (direct .git access)
- String search on disk images finds hidden/deleted data

---

*Last updated: 2026-04-27*