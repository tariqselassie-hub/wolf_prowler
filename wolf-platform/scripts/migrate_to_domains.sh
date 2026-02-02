#!/bin/bash

# Wolf Prowler Poly-Repo migration script
# This script splits the monorepo into domain-specific repositories.
# Each domain becomes a standalone Rust workspace or crate.

set -euo pipefail

# Configuration
ORIGINAL_DIR="$(pwd)"
OUTPUT_DIR="${ORIGINAL_DIR}_polyrepo"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}Starting Poly-Repo Migration for Wolf Prowler...${NC}"

# 1. Define Domains and their Sub-items
declare -A DOMAINS
DOMAINS=(
    ["wolf-platform"]="src scripts config.toml settings.toml features.toml AGENTS.md README.md LICENSE-MIT Makefile"
    ["wolf-security"]="wolfsec wolfsec-core wolfsec-network wolfsec-siem wolfsec-threat-detection crates/tercespot crates/lock_prowler secrets"
    ["wolf-networking"]="wolf_net wolf_web"
    ["wolf-observability"]="crates/wolf_log src/observability"
    ["wolf-storage"]="crates/WolfDb src/persistence migrations"
    ["wolf-integrations"]="wolf_control wolf_server wolf_fuzz wolf_den examples"
)

# 2. Preparation
echo -e "${YELLOW}Preparing output directory: $OUTPUT_DIR${NC}"
mkdir -p "$OUTPUT_DIR"

# 3. Migration Logic
for domain in "${!DOMAINS[@]}"; do
    echo -e "${GREEN}Processing domain: $domain...${NC}"
    DOMAIN_DIR="$OUTPUT_DIR/$domain"
    mkdir -p "$DOMAIN_DIR"
    
    # Initialize Git
    cd "$DOMAIN_DIR"
    git init -q
    cd "$ORIGINAL_DIR"
    
    # Move items
    for item in ${DOMAINS[$domain]}; do
        if [ -e "$item" ]; then
            echo "  -> Including $item"
            # Maintain structure relative to root for most things, 
            # but we might want to flatten them later.
            # For now, let's keep the subfolder names.
            dest_path="$DOMAIN_DIR/$item"
            mkdir -p "$(dirname "$dest_path")"
            cp -r "$item" "$dest_path"
        fi
    done
    
    # Create domain-specific Cargo.toml if it's a new workspace
    # We will detect sub-crates that have Cargo.toml files
    SUB_CRATES=""
    while IFS= read -r cargo_file; do
        crate_dir=$(dirname "$cargo_file")
        rel_dir=${crate_dir#"$DOMAIN_DIR/"}
        if [ "$rel_dir" != "." ]; then
            SUB_CRATES="$SUB_CRATES\"$rel_dir\", "
        fi
    done < <(find "$DOMAIN_DIR" -maxdepth 3 -name "Cargo.toml")

    cat > "$DOMAIN_DIR/Cargo.toml" << EOF
[workspace]
resolver = "2"
members = [
    $SUB_CRATES
]

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["Wolf Prowler Team"]
license = "MIT"

[workspace.dependencies]
# Shared dependencies for the $domain domain
tokio = { version = "1.35", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"
thiserror = "1.0"
tracing = "0.1"
EOF

    # Commit initial state
    cd "$DOMAIN_DIR"
    git add .
    git commit -m "chore: initial migration for $domain domain" -q
    cd "$ORIGINAL_DIR"
done

# Helper function to get relative paths for Cargo members
# We'll just manually fix the Cargo.toml for each domain after copying to make it cleaner.

# 4. Refine Cargo.toml for each domain
echo -e "${YELLOW}Refining Cargo configurations...${NC}"

# Platform should be the main entry point
PLATFORM_CARGO="$OUTPUT_DIR/wolf-platform/Cargo.toml"
cat > "$PLATFORM_CARGO" << EOF
[package]
name = "wolf-prowler-platform"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "wolf_prowler"
path = "src/main.rs"

[dependencies]
# Local Domain Dependencies (using relative paths for local development)
wolf-security = { path = "../wolf-security/wolfsec" }
wolf-networking = { path = "../wolf-networking/wolf_net" }
wolf-observability = { path = "../wolf-observability/crates/wolf_log" }
wolf-storage = { path = "../wolf-storage/crates/WolfDb" }

# External dependencies
tokio = { version = "1.35", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
anyhow = "1.0"
tracing = "0.1"
EOF

echo -e "${GREEN}Migration complete!${NC}"
echo -e "Files are located in: ${BLUE}$OUTPUT_DIR${NC}"
echo -e "You can now push each directory in $OUTPUT_DIR to its own separate repository."