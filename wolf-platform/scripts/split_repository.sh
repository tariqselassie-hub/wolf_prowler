#!/bin/bash

# Wolf Prowler Repository Splitting Script
# Domain-based approach for logical organization

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ORIGINAL_REPO="$(pwd)"
SPLIT_BASE="${ORIGINAL_REPO}_split"
DOMAINS=(
    "wolf-prowler-platform"
    "wolf-security" 
    "wolf-networking"
    "wolf-observability"
    "wolf-storage"
    "wolf-integrations"
)

echo -e "${BLUE}🐺 Wolf Prowler Repository Splitting${NC}"
echo -e "${YELLOW}Domain-based approach for logical organization${NC}"
echo

# Create base directory for split repos
mkdir -p "$SPLIT_BASE"
cd "$SPLIT_BASE"

echo -e "${GREEN}📁 Creating domain repositories...${NC}"

# Function to create a new repository for a domain
create_domain_repo() {
    local domain=$1
    local description=$2
    
    echo -e "${BLUE}Creating ${domain} repository...${NC}"
    
    mkdir -p "$domain"
    cd "$domain"
    
    # Initialize Git repository
    git init
    
    # Create basic structure
    mkdir -p src tests docs examples
    
    # Create README
    cat > README.md << EOF
# $domain

$description

## Overview

This repository contains the $domain components of the Wolf Prowler security platform.

## Structure

- \`src/\` - Main source code
- \`tests/\` - Integration and unit tests  
- \`docs/\` - Documentation
- \`examples/\` - Usage examples

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

*Part of the Wolf Prowler Security Platform* 🐺
EOF

    # Create basic Cargo.toml
    cat > Cargo.toml << EOF
[package]
name = "$domain"
version = "0.1.0"
edition = "2021"
description = "$description"
license = "MIT"
repository = "https://github.com/your-org/wolf-prowler"
keywords = ["security", "p2p", "rust", "wolf-prowler"]
categories = ["security", "network-programming"]

[dependencies]
# Will be populated during migration

[workspace]
members = [
    ".",
    # Sub-crates will be added here
]
EOF

    # Create lib.rs
    cat > src/lib.rs << EOF
//! $domain
//!
//! $description

#![warn(missing_docs)]
#![warn(unused_imports)]

pub mod prelude;

/// Domain-specific functionality will be migrated here
pub fn domain_info() -> &'static str {
    "$domain - Wolf Prowler Security Platform"
}
EOF

    # Create prelude module
    cat > src/prelude.rs << EOF
//! Prelude for $domain
//!
//! Common imports and re-exports for convenience.

pub use crate::domain_info;
EOF

    cd ..
    echo -e "${GREEN}✓ Created ${domain}${NC}"
}

# Create all domain repositories
create_domain_repo "wolf-prowler-platform" "Core platform, CLI, and main application"
create_domain_repo "wolf-security" "Security engine, authentication, threat detection, and compliance"
create_domain_repo "wolf-networking" "P2P networking, swarm management, and communication protocols"
create_domain_repo "wolf-observability" "Logging, metrics, audit trails, and monitoring"
create_domain_repo "wolf-storage" "Database layer, persistence, and data management"
create_domain_repo "wolf-integrations" "Third-party integrations, adapters, and external services"

echo
echo -e "${GREEN}🎯 Domain repositories created successfully!${NC}"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review the created repositories in: $SPLIT_BASE"
echo "2. Run the migration script to move code"
echo "3. Update dependencies and workspace configurations"
echo "4. Set up CI/CD for each repository"
echo
echo -e "${BLUE}📋 Migration Plan:${NC}"
echo "Run './migrate_to_domains.sh' to begin code migration"