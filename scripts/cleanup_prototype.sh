#!/bin/bash
# Cleanup script to remove obsolete wolf_prowler_prototype code

echo "Removing obsolete prototype crypto implementation..."
rm -v wolf-prowler/src/wolf_prowler_prototype/crypto.rs

echo "Removing obsolete implementation plan..."
rm -v implementation_plan.md

echo "Cleanup complete. Please update wolf-prowler/src/lib.rs to remove the module declaration if necessary."