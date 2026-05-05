# DECISIONS

## v0.5 Design Decisions

### Content Scan Patterns
- Primary: picoCTF{, flag{, ctf{, actf{, dctf{
- Secondary: pico, secret, password, key, ssh, id_rsa
- Context window: 30 bytes before/after match

### Git Deep Scan Commands
1. git rev-list --all (commit enumeration)
2. git grep -n "picoCTF\|flag" $(git rev-list --all)
3. git log --all --name-status
4. git show --all
5. git fsck --lost-found
6. git fsck --no-reflogs --lost-found

### Deleted Recovery Flow
1. fls -rd <offset> (list deleted inodes)
2. icat <image> <inode> (recover content)
3. Scan recovered content for patterns

### Timeline Generation
1. fls -r -m / <offset> (generate bodyfile)
2. mactime -b <bodyfile> -d (CSV output)
3. Track M (modified), D (deleted), C (created)

### Reporter Priority Order
1. Mounted partitions > Git repos > SleuthKit
2. Partitions > Deleted recovery > Timeline
3. Extracted content > Git artifacts > Strings

## Legacy Design Decisions

### Git Confidence Rules
- config + branch_ref >= 3 → MEDIUM
- .git/logs OR .git/objects found → HIGH
- picoCTF/flag in git history → CRITICAL

### Partition Mapping
- Range = offset_start ~ offset_start + size
- Raw indicators show likely_partition (p1, p2, etc.)

### Forensic Image Handling
- Disk images (.img, .dd) get lower embedded artifact priority
- SleuthKit/file listings take priority over embedded
- Top leads: mounted > Git repo > SleuthKit > partitions > embedded

### String Details
- First 20 shown in report, rest as count
- Includes pattern, offset, likely_partition