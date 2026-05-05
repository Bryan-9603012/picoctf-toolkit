# NEXT

## v0.6 (Next Sprint Recommendations)

1. **YARA Integration**
   - Add YARA rule scanning for malware signatures
   - Support custom YARA rule files
   - Scan extracted files and carved artifacts

2. **Bulk Processing**
   - Process multiple disk images in parallel
   - Add job queue for large-scale triage
   - Export aggregated reports

3. **Enhanced Git Recovery**
   - Automate full git repo extraction from disk images
   - Handle more edge cases (corrupt objects)
   - Integrate with git_deep_scan in main analyzer

4. **Report Improvements**
   - Add visual timeline charts
   - Include IOC summary tables
   - Export to CSV/JSON for SIEM integration

## v0.5 Completed

1. **Extracted Content Scanner**
   - Content scanning for carved/extracted files
   - Patterns: picoCTF{, pico, flag{, secret, password, key, ssh, id_rsa
   - Binary files scanned via strings utility

2. **Git Deep Scanner**
   - Full git rev-list, grep, log, show, fsck analysis
   - Dangling commit recovery
   - Bare repo support with --git-dir

3. **Deleted File Recovery**
   - fls -rd for deleted inode enumeration
   - icat for content recovery
   - Pattern scanning on recovered content

4. **Timeline Mode**
   - fls -r -m / for bodyfile generation
   - mactime for CSV timeline export
   - Recent modifications/deletions tracking

## v0.4 Completed
- Full git history analysis
- Deleted file recovery
- Hint extraction from git logs