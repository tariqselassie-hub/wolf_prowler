#!/bin/bash
# Purge secrets from Git history using BFG

set -e

GITLEAKS="$HOME/.local/bin/gitleaks"
BFG="$HOME/.local/bin/bfg"
REPO_DIR="/home/t4riq/Desktop/Rust/wolf_prowler"
MIRROR_DIR="/tmp/wolf_prowler_mirror.git"
SECRETS_FILE="$REPO_DIR/secrets-to-purge.txt"

# Verify secrets file exists
if [ ! -f "$SECRETS_FILE" ]; then
    echo "❌ Error: secrets-to-purge.txt not found!"
    echo "Please create this file with secrets to purge."
    exit 1
fi

# Verify BFG is installed
if [ ! -f "$BFG" ]; then
    echo "❌ Error: BFG not installed!"
    echo "Run: ./scripts/install_bfg.sh"
    exit 1
fi

echo "========================================="
echo "  SECRET PURGE - Git History Rewrite"
echo "========================================="
echo ""
echo "⚠️  WARNING: This will rewrite Git history!"
echo ""
read -p "Have you created a backup? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Please run: ./scripts/backup_repo.sh first"
    exit 1
fi

echo ""
echo "Step 1: Creating mirror clone..."
rm -rf "$MIRROR_DIR"
cd "$REPO_DIR"
git clone --mirror . "$MIRROR_DIR"

echo ""
echo "Step 2: Purging secrets with BFG..."
"$BFG" --replace-text "$SECRETS_FILE" "$MIRROR_DIR"

echo ""
echo "Step 3: Cleaning up Git references..."
cd "$MIRROR_DIR"
git reflog expire --expire=now --all
git gc --prune=now --aggressive

echo ""
echo "Step 4: Updating original repository..."
cd "$REPO_DIR"

# Push cleaned history from mirror back to working repo
git remote remove mirror 2>/dev/null || true
git remote add mirror "$MIRROR_DIR"
git fetch mirror

# Get current branch name
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

# Reset to cleaned history
git reset --hard "mirror/$CURRENT_BRANCH"

# Clean up
git remote remove mirror

echo ""
echo "========================================="
echo "  ✅ Secret purge complete!"
echo "========================================="
echo ""
echo "📋 IMPORTANT NEXT STEPS:"
echo ""
echo "1. Verify secrets are gone:"
echo "   ./scripts/scan_secrets.sh"
echo ""
echo "2. ⚠️  ROTATE ALL EXPOSED SECRETS IMMEDIATELY"
echo "   Check the scan reports for details"
echo ""
echo "3. Review recent commits:"
echo "   git log --oneline -20"
echo ""
echo "4. Force push to remote (if applicable):"
echo "   git push origin --force --all"
echo "   git push origin --force --tags"
echo ""
echo "5. Notify collaborators to re-clone the repository"
echo ""
