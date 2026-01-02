#!/bin/bash
# Cleanup script to remove rogue wolfpack files from wolf_den and the shim in wolfsec

rm -v wolf_den/src/hierarchy.rs
rm -v wolf_den/src/territory.rs
rm -v wolfsec/src/wolf_pack.rs
echo "Removed rogue files. Please check wolf_den/src/lib.rs and wolfsec/src/lib.rs for module updates."