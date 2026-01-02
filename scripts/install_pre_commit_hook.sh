#!/bin/bash
# Install pre-commit hook for secret detection

set -e

HOOK_SOURCE="/home/t4riq/Desktop/Rust/wolf_prowler/scripts/pre-commit-hook.sh"
HOOK_TARGET="/home/t4riq/Desktop/Rust/wolf_prowler/.git/hooks/pre-commit"

echo "Installing pre-commit hook..."

# Create hooks directory if it doesn't exist
mkdir -p "$(dirname "$HOOK_TARGET")"

# Copy the hook
cp "$HOOK_SOURCE" "$HOOK_TARGET"
chmod +x "$HOOK_TARGET"

echo "✅ Pre-commit hook installed!"
echo ""
echo "The hook will automatically scan for secrets before each commit."
echo "To bypass (not recommended): git commit --no-verify"
