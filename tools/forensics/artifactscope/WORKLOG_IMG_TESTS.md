# WORKLOG_IMG_TESTS

## Regression Tests v0.5

Run these commands to test the forensics analysis pipeline:

### ForensicsGit Images (Git Recovery Focus)
```bash
# ForensicsGit0.img - Git repo
python3 -c "
import sys; sys.argv = ['cli', 'ForensicsGit0.img', '--strings', '--mount', '--report-md']
from artifactscope.cli import main
main()
"

# ForensicsGit1.img - Dangling commits (run with mount, takes longer)
python3 -c "
import sys; sys.argv = ['cli', 'ForensicsGit1.img', '--strings', '--mount', '--report-md']
from artifactscope.cli import main
main()
"

# ForensicsGit2.img - Deleted files
python3 -c "
import sys; sys.argv = ['cli', 'ForensicsGit2.img', '--strings', '--mount', '--report-md']
from artifactscope.cli import main
main()
"
```

### Timeline Images (Timeline Mode)
```bash
# Timeline0.img - Timeline analysis
python3 -c "
import sys; sys.argv = ['cli', 'Timeline0.img', '--strings', '--report-md']
from artifactscope.cli import main
main()
"

# Timeline1.img - Timeline analysis
python3 -c "
import sys; sys.argv = ['cli', 'Timeline1.img', '--strings', '--report-md']
from artifactscope.cli import main
main()
"
```

### Other Disk Images (Full Pipeline)
```bash
# disko-1.dd
python3 -c "
import sys; sys.argv = ['cli', 'disko-1.dd', '--strings', '--report-md']
from artifactscope.cli import main
main()
"

# DearDiary.img
python3 -c "
import sys; sys.argv = ['cli', 'DearDiary.img', '--strings', '--report-md']
from artifactscope.cli import main
main()
"

# OperationOni.img
python3 -c "
import sys; sys.argv = ['cli', 'OperationOni.img', '--strings', '--report-md']
from artifactscope.cli import main
main()
"

# OperationOrchid.img
python3 -c "
import sys; sys.argv = ['cli', 'OperationOrchid.img', '--strings', '--report-md']
from artifactscope.cli import main
main()
"
```

### Quick Validation Commands
```bash
# Test with strings only (fastest)
python3 -c "
import sys; sys.argv = ['cli', 'Timeline0.img', '--strings']
from artifactscope.cli import main
main()
"

# Test all forensics images in directory
for img in ForensicsGit0.img ForensicsGit1.img ForensicsGit2.img disko-1.dd Timeline0.img Timeline1.img; do
  echo "=== Testing $img ==="
  python3 -c "
import sys; sys.argv = ['cli', '$img', '--strings', '--report-md']
from artifactscope.cli import main
main()
"
done
```

### Expected Results After v0.5

1. **ForensicsGit0/1/2**
   - Git Artifacts: Indicator Count > 0
   - Confidence: MEDIUM/HIGH/CRITICAL
   - Deleted Recovery section available
   - Timeline section available (if Linux partitions)

2. **Timeline0/1**
   - Bodyfile generated in /tmp/artifactscope_timeline/
   - Recent modifications listed
   - Recent deletions listed
   - Suspicious filenames highlighted

3. **All Disk Images**
   - Suspicious string details with offset/partition
   - SleuthKit file listings or suggested commands
   - Extracted Content Scan section
   - Top leads show partition/git/string clues