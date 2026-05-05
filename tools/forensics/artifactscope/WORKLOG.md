# WORKLOG

## 2026-05-03 v0.1.1 Bugfix Pass

### Changes Made

1. **Flag extraction correctness**
   - Fixed `detect_flag_patterns()` regex branch using the wrong variable name.
   - Prevented broad line-level matches from being reported as verified flags when an exact `picoCTF{...}` match exists.

2. **Git artifact detection correctness**
   - Fixed Windows-style `.git\config` / `refs\heads` matching logic.

3. **SleuthKit / deleted recovery fixes**
   - Restored unreachable `analyze_with_sleuthkit()` logic so `mmls`, `fsstat`, and `fls` can actually populate results.
   - Fixed deleted inode parsing from `fls -rd` output.
   - Fixed `icat` deleted-file recovery to pass the partition sector offset.
   - Fixed compatibility wrappers to pass `partitions` correctly.

4. **Project hygiene**
   - Added missing `requirements.txt`.
   - Added `.gitignore`.
   - Added regression tests for flag extraction, Git path detection, CTF handlers, SleuthKit listing, and deleted recovery.

### Validation

- `python3 -m compileall -q artifactscope main.py` passed.
- `python3 -m pytest -q` passed: 12 tests.

## 2026-04-27 v0.5 Maintenance - Extracted Content Scanner, Git Deep Scanner, Deleted Recovery, Timeline Mode

### Changes Made

1. **Extracted Content Scanner (stringscan.py)**
   - Added `content_scan_extracted()` function
   - Scans all files in extracted directories (carved, tsk_recover, icat)
   - Searches for: picoCTF{, pico, flag{, secret, password, key, ssh, id_rsa
   - For binary files, runs `strings` before scanning
   - Returns source file path, partition, inode, matched pattern, context

2. **Git Deep Scanner (git_analyzer.py)**
   - Added `git_deep_scan()` for full git repo analysis:
     - git rev-list --all
     - git grep -n "picoCTF\|flag" $(git rev-list --all)
     - git log --all --name-status
     - git show --all
     - git fsck --lost-found
     - git fsck --no-reflogs --lost-found
   - Added `recover_dangling_commits()` for ForensicsGit1/2
   - Supports git --git-dir=<path> mode for bare repos
   - Scans .git/objects, .git/logs/HEAD, .git/lost-found
   - Updated `full_git_recovery()` to scan git artifacts

3. **Deleted File Recovery (fs_analyzer.py)**
   - Added `run_fls_deleted()` using `fls -rd`
   - Added `recover_deleted_files()` using icat on deleted inodes
   - Added `analyze_deleted_recovery()` for partition-level recovery
   - New section in report: "Deleted File Recovery"

4. **Timeline Mode (fs_analyzer.py)**
   - Added `run_fls_timeline()` using `fls -r -m /`
   - Generates bodyfile for timeline analysis
   - Adds `mactime` support for CSV output
   - New section in report: "Timeline Analysis"

5. **Reporter Updates (reporter.py)**
   - Added "Deleted File Recovery" section
   - Added "Timeline Analysis" section
   - Added "Extracted Content Scan" section
   - Reports bodyfile path and CSV output

## 2026-04-27 - Scan All .img Files + Roadmap Planning

### Changes Made

1. **Scanned All .img Files**
   - Ran ArtifactScope on 10 disk images: sleuthkitintro.img, Timeline0/1, DearDiary, ForensicsGit0-2, OperationOrchid, OperationOni, SleuthkitApprentice
   - Generated report to output/artifactscope_report.md
   - Result: No picoCTF flags found in raw disk data

2. **Roadmap Added**
   - Created MEMORY.md with v0.2-v0.5 feature roadmap
   - v0.2: Partition-aware scanner (mmls, offset calculation)
   - v0.3: Mount + file enumeration
   - v0.4: Git recovery
   - v0.5: LLM-ready report

3. **Key Insight**
   - Current tool scans raw disk image, finds embedded artifacts
   - Next version should: partition → mount → enumerate → extract files → LLM
   - LLM receives structured data, not raw disk image

## 2025-04-27 - Maintenance Phase
   - Updated `stringscan.py`: Added `raw_git_indicators` parameter to `detect_git_artifacts()`
   - Fixed confidence rules: config + branch_ref >= 3 → MEDIUM, .git/logs or .git/objects → HIGH, picoCTF in git → CRITICAL
   - indicator_count now equals raw + string indicators

2. **Offset-to-Partition Mapping**
   - Added `_map_offset_to_partition()` in analyzer.py
   - Maps raw git indicators, flag candidates, suspicious strings to partitions
   - Added `likely_partition` field to all indicators

3. **SleuthKit Integration MVP**
   - Added `analyze_with_sleuthkit()` in fs_analyzer.py
   - Checks for mmls, fsstat, fls, icat availability
   - Runs fls -r on partitions for file listings
   - Suggested commands if tools not available

4. **Suspicious String Details**
   - Added `suspicious_details` in stringscan.py with pattern, offset, context
   - Shows top 20 in report.md/report.json

5. **Embedded Artifact Noise Reduction**
   - Added `is_forensic_image` detection
   - Reduces embedded artifact priority for disk images
   - Shows first 20 embedded, rest as count

6. **Reporter Updates**
   - Updated `_build_priority_leads()` for new priorities
   - Added SleuthKit, suspicious_details sections
   - Added confidence/critical handling in Top Leads
## 2026-05-03 Follow-up Fix: SleuthKit Apprentice Accuracy

- Fixed misleading SleuthKit filename hits being counted as flag candidates.
- Added robust parsing for `fls` deleted/realloc inode lines such as `r/r * 2082(realloc): flag.txt`.
- Improved `sleuthkit_basic_inode_handler` to run both `fls -r` and `fls -rd` and then `icat` candidate inodes.
- Added candidate content preview handling and aggregation from CTF handlers.
- Added tests for deleted/realloc inode parsing and bare-token flag normalization.
- Verified with `python3 -m compileall -q artifactscope main.py` and `python3 -m pytest -q`.

## 2026-05-03 - v3 SleuthKit Apprentice Recovery Patch

- Added binary-safe `icat` handling for SleuthKit CTF handlers.
- Added fallback `icat -r` for deleted/reallocated ext filesystem entries.
- Expanded SleuthKit filename keywords for Apprentice-style clues such as `innocuous`, `its-all-in-the-name`, and `force-wait`.
- Added `icat_attempts` debug evidence into JSON/Markdown reports so failed inode recovery can be inspected directly.
- Preserved test suite status: `14 passed`.

## 2026-05-03 CLI compatibility fix v4
- Added `--report` as a convenience alias that enables both `--report-json` and `--report-md`.
- Added `--mount-git` as a backward-compatible alias for `--mount`.
- Verified argparse no longer treats `--report` as ambiguous between `--report-json` and `--report-md`.

## 2026-05-03 v5 hotfix

### Fixed
- Prevented privileged mount attempts from aborting the whole scan when `sudo mount` hangs or times out in WSL/Windows environments.
- Changed internal sudo-based filesystem commands to use `sudo -n` where applicable, so the tool fails fast instead of waiting for an interactive password prompt.
- Hardened `fs_analyzer._run()` so timeouts, missing commands, and OS errors return a structured `CompletedProcess` result instead of raising and stopping analysis.
- Added regression tests for mount timeout handling and safe fallback behavior.

### Validation
- `python3 -m compileall -q artifactscope main.py`
- `python3 -m pytest -q` → 16 passed

## 2026-05-03 v6 hardening pass

- Fixed `fls` inode parsing for regular, deleted, realloc, and nested SleuthKit entries.
- Fixed targeted `icat` extraction so it uses the numeric inode instead of the `r/r` metadata field.
- Changed `icat` reads/writes to binary-safe mode.
- Deleted-file recovery now tries both normal `icat` and `icat -r`.
- Deleted-file recovery now promotes exact `picoCTF{...}` matches to verified flags.
- Challenge routing is now case/space/punctuation-insensitive.
- Fixed `picoCTF{...}` being double-counted as generic `CTF{...}`.
- Fixed Git confidence so a standalone flag string does not imply Git artifacts.
- Hardened Markdown output for mixed candidate schemas.
- Added regression tests for CLI aliases, FLS parsing, and flag de-duplication.
- Verification: `python3 -m compileall -q artifactscope main.py` and `python3 -m pytest -q` => 21 passed.

## 2026-05-03 v7 Unicode flag recovery hardening

- Fixed Sleuthkit Apprentice false negative for `flag.uni.txt` style Unicode files.
- Added raw byte flag extraction for UTF-8, Latin-1, UTF-16, UTF-16LE, UTF-16BE, and NUL-stripped ASCII.
- Updated SleuthKit inode handler to treat `uni`, `unicode`, and `my_folder` as high-priority filename hints.
- Updated deleted-file recovery to extract flags from raw bytes instead of UTF-8 text only.
- Added regression tests for UTF-16LE picoCTF flags.
- Validation: `python3 -m compileall -q artifactscope main.py` and `python3 -m pytest -q` pass with 23 tests.
