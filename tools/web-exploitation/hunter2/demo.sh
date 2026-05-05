#!/bin/bash
# Demo workflow for Hunter-2
# Run this to see a complete scan workflow

set -e

echo "=========================================="
echo "Hunter-2 Demo Workflow"
echo "=========================================="
echo ""

TARGET="${1:-http://example.com}"
REPORT_PREFIX="demo-${2:-scan}"

echo "Target: $TARGET"
echo "Report prefix: $REPORT_PREFIX"
echo ""

# Step 1: Initial baseline scan
echo "=== Step 1: Create Baseline Scan ==="
hunter "$TARGET" \
    --policy balanced \
    --report "${REPORT_PREFIX}-baseline" \
    --html

echo ""
echo "Baseline scan complete: ${REPORT_PREFIX}-baseline.json"
echo ""

# Step 2: Simulated rescan (using same target for demo)
echo "=== Step 2: Compare with Baseline ==="
hunter "$TARGET" \
    --policy balanced \
    --baseline "${REPORT_PREFIX}-baseline.json" \
    --new-only \
    --report "${REPORT_PREFIX}-delta"

echo ""
echo "Delta scan complete: ${REPORT_PREFIX}-delta.json"
echo ""

# Step 3: Full governance scan
echo "=== Step 3: Full Governance Scan ==="
hunter "$TARGET" \
    --policy balanced \
    --env staging \
    --baseline "${REPORT_PREFIX}-baseline.json" \
    --fail-on-new high \
    --report "${REPORT_PREFIX}-full" \
    --html

echo ""
echo "Full governance scan complete"
echo ""

echo "=========================================="
echo "Demo Complete"
echo "=========================================="
echo ""
echo "Generated files:"
ls -la ${REPORT_PREFIX}-*.json ${REPORT_PREFIX}-*.md ${REPORT_PREFIX}-*.html 2>/dev/null || true