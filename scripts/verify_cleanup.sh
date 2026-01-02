#!/bin/bash
# Verify secrets have been removed

set -e

GITLEAKS="$HOME/.local/bin/gitleaks"
cd /home/t4riq/Desktop/Rust/wolf_prowler

echo "========================================="
echo "  SECRET PURGE VERIFICATION"
echo "========================================="
echo ""

# 1. Re-run gitleaks
echo "1. Re-scanning for secrets with gitleaks..."
echo ""

"$GITLEAKS" detect --source . --verbose 2>&1 | tee verification-scan.log

SCAN_RESULT=$?

echo ""

if [ $SCAN_RESULT -eq 0 ]; then
    echo "✅ No secrets detected!"
else
    echo "⚠️  Secrets still found - review verification-scan.log"
    echo ""
    echo "Remaining secrets:"
    "$GITLEAKS" detect --source . --report-format json --report-path verification-report.json --no-color || true
fi

echo ""

# 2. Check Git integrity
echo "2. Checking Git repository integrity..."
git fsck --full

echo ""

# 3. Show recent commit history
echo "3. Recent commit history (verify hashes changed):"
git log --oneline -10

echo ""

# 4. Manual pattern check for the specific leaked secrets
echo "4. Manual verification - checking for specific leaked secrets..."
echo ""

# Check for the real API keys
echo "   Checking for VT_API_KEY (71e549...):"
if git log --all --source --full-history -S "71e5490276da557423521b43683227ef79ab068634399afc07a10598e682c4e6" | grep -q "commit"; then
    echo "   ❌ STILL FOUND in history!"
else
    echo "   ✅ Not found - successfully removed"
fi

echo ""
echo "   Checking for API_KEY UUID (a15435f6...):"
if git log --all --source --full-history -S "a15435f6-9d44-471b-9e1f-c06dd48819f5" | grep -q "commit"; then
    echo "   ❌ STILL FOUND in history!"
else
    echo "   ✅ Not found - successfully removed"
fi

echo ""
echo "   Checking for ORG_KEY (WOLF-ABCD...):"
if git log --all --source --full-history -S "WOLF-ABCD-1234-XYZ" | grep -q "commit"; then
    echo "   ❌ STILL FOUND in history!"
else
    echo "   ✅ Not found - successfully removed"
fi

echo ""
echo "========================================="
echo "  VERIFICATION COMPLETE"
echo "========================================="
echo ""

if [ $SCAN_RESULT -eq 0 ]; then
    echo "✅ All secrets successfully purged!"
    echo ""
    echo "📋 Final steps:"
    echo "  1. Rotate all exposed secrets"
    echo "  2. Force push to remote: git push origin --force --all"
    echo "  3. Notify collaborators to re-clone"
else
    echo "⚠️  Some secrets may still be present."
    echo "Review the verification-scan.log file for details."
fi
