#!/bin/bash
# Scan entire Git history for secrets

GITLEAKS="$HOME/.local/bin/gitleaks"
cd /home/t4riq/Desktop/Rust/wolf_prowler

echo "Scanning Git history for secrets..."
"$GITLEAKS" detect \
  --source . \
  --report-format json \
  --report-path gitleaks-report.json \
  --verbose

echo ""
echo "Generating human-readable report..."
"$GITLEAKS" detect \
  --source . \
  --report-format sarif \
  --report-path gitleaks-report.sarif \
  --verbose

echo ""
echo "Reports generated:"
echo "  - gitleaks-report.json (machine-readable)"
echo "  - gitleaks-report.sarif (SARIF format)"
echo ""
echo "Review the reports to identify secrets that need purging."
