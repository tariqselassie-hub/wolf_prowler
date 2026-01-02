# Wolf Prowler Project Cleanup Plan

## 🎯 **Current State Analysis**

### **Issues Identified:**
- **28+ binaries** in Cargo.toml (many broken/duplicates)
- **30+ markdown files** scattered in root
- **5 different Cargo.toml** variants
- **Multiple backup directories** with old code
- **3,769 build artifacts** in target directory
- **Redundant P2P modules** (p2p_basic.rs, p2p_simple.rs, p2p_minimal.rs, etc.)

## 🚀 **Proposed Clean Structure**

```
wolf-prowler/
├── Cargo.toml                    # Clean, minimal configuration
├── README.md                     # Main documentation
├── src/
│   ├── main.rs                   # Main application entry point
│   ├── main_simple.rs            # Simple version
│   ├── main_cli.rs               # CLI interface
│   ├── lib.rs                    # Library entry point
│   ├── core/                     # Core functionality
│   │   ├── mod.rs
│   │   ├── config.rs
│   │   ├── state.rs
│   │   └── logging.rs
│   ├── p2p/                      # P2P networking (consolidated)
│   │   ├── mod.rs
│   │   ├── simple.rs             # Basic P2P
│   │   ├── enhanced.rs           # Advanced P2P
│   │   └── discovery.rs          # Peer discovery
│   ├── crypto/                   # Cryptographic operations
│   │   ├── mod.rs
│   │   ├── engine.rs
│   │   └── protocols.rs
│   ├── security/                 # Security features
│   │   ├── mod.rs
│   │   ├── authentication.rs
│   │   └── encryption.rs
│   ├── web/                      # Web interface
│   │   ├── mod.rs
│   │   ├── dashboard.rs
│   │   └── api.rs
│   └── bin/                      # Essential binaries only
│       ├── wolf_prowler.rs       # Main binary
│       ├── wolf_prowler_simple.rs # Simple version
│       └── wolf_prowler_enhanced.rs # Enhanced version
├── wolf_den/                     # Cryptographic library
│   ├── full/
│   └── basic/
├── full/                         # Standalone full version
│   ├── Cargo.toml
│   └── src/main.rs
├── docs/                         # Organized documentation
│   ├── README.md
│   ├── API.md
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   └── legacy/                   # Old documentation
│       ├── *_SUMMARY.md
│       ├── *_GUIDE.md
│       └── *_REPORT.md
├── tests/                        # Test files
├── examples/                     # Example code
├── config/                       # Configuration files
└── target/                       # Build artifacts (generated)
```

## 📋 **Cleanup Actions**

### **Phase 1: Safe Backup**
1. Create timestamped backup directory
2. Move all files to be deleted to backup first

### **Phase 2: Binary Cleanup**
**Keep only these essential binaries:**
- `wolf_prowler` (main application)
- `wolf_prowler_simple` (lightweight version)
- `wolf_prowler_enhanced` (full-featured version)

**Remove these redundant binaries:**
- All prototype variants
- All test binaries
- All backup binaries
- Duplicate versions

### **Phase 3: Module Consolidation**
**P2P modules to keep:**
- `p2p_simple.rs` → `src/p2p/simple.rs`
- `p2p_enhanced.rs` → `src/p2p/enhanced.rs`

**P2P modules to remove:**
- `p2p_basic.rs`, `p2p_minimal.rs`, `p2p_test_bin.rs`
- `prototype_p2p_backup.rs`, `p2p_basic.rs`

### **Phase 4: Documentation Organization**
**Move to docs/:**
- All *.md files except README.md
- Create subdirectories: `api/`, `guides/`, `legacy/`

**Keep in root:**
- README.md (main documentation)

### **Phase 5: Configuration Cleanup**
**Keep:**
- `Cargo.toml` (clean version)
- `wolf_prowler.toml` (app config)

**Remove:**
- `Cargo_*.toml` variants
- `development.toml`, `production.toml`

### **Phase 6: Build Artifact Cleanup**
**Remove:**
- `target/` directory (3,769 items)
- All `.pdb` files
- All `.exe` test files

## 🎯 **Expected Results**

### **Before Cleanup:**
- 28+ binaries (many broken)
- 30+ markdown files in root
- 5 Cargo.toml variants
- Multiple backup directories
- 3,769 build artifacts

### **After Cleanup:**
- 3 essential binaries (all working)
- Clean docs/ structure
- 1 Cargo.toml
- No backup directories
- Clean build directory

## 🚨 **Safety Measures**

1. **Backup First**: All deletions go to backup directory
2. **Incremental**: Clean one category at a time
3. **Test After Each Phase**: Ensure compilation still works
4. **Rollback Ready**: Can restore from backup if needed

## 📝 **Implementation Commands**

```powershell
# Run the cleanup script
.\cleanup_project.ps1

# Test compilation after cleanup
cargo check

# Build the cleaned project
cargo build

# Test essential binaries
cargo run --bin wolf_prowler
cargo run --bin wolf_prowler_simple
```

## 🔄 **Maintenance**

To prevent future accumulation:
1. Regular cleanup scripts
2. Clear naming conventions
3. Proper module organization
4. Documentation standards
5. Build artifact management
