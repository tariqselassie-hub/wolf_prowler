#!/bin/bash
# Pre-commit hook to prevent secret commits

GITLEAKS="$HOME/.local/bin/gitleaks"

if [ ! -f "$GITLEAKS" ]; then
    echo "⚠️  Warning: gitleaks not installed - skipping secret scan"
    exit 0
fi

echo "Running gitleaks pre-commit scan..."
"$GITLEAKS" protect --staged --verbose

if [ $? -ne 0 ]; then
    echo ""
    echo "⛔ COMMIT REJECTED: Secrets detected!"
    echo "Remove secrets before committing."
    exit 1
fi

echo "✅ No secrets detected - proceeding with commit"
exit 0
