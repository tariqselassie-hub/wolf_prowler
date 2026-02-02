# Wolf Prowler Automation

.PHONY: all build test clean run backup restore patch monitor help

all: build

build:
	cargo build --release

test:
	cargo test --workspace

clean:
	cargo clean

run:
	cargo run --bin wolf_prowler

# --- Admin Tasks ---

backup:
	@echo "Creating system backup..."
	@./scripts/backup_system.sh

restore:
	@echo "Restoring system from backup..."
	@if [ -z "$(FILE)" ]; then echo "Error: Specify backup file with FILE=path/to/backup.tar.gz"; exit 1; fi
	@./scripts/restore_system.sh $(FILE)

patch:
	@echo "Checking for dependency updates..."
	@cargo update
	@echo "Dependencies updated. Run 'make test' to verify."

monitor:
	@echo "Running system health checks..."
	@cargo test --test dashboard_comprehensive_test
	@cargo test -p wolf_net --test discovery_integration

user-add:
	@echo "Running user management tool..."
	@cargo run --example manage_users

help:
	@echo "Wolf Prowler Make Commands:"
	@echo "  build       - Build release binary"
	@echo "  test        - Run all tests"
	@echo "  run         - Run the main application"
	@echo "  backup      - Archive data and config"
	@echo "  restore     - Restore from backup (FILE=...)"
	@echo "  patch       - Update Rust dependencies"
	@echo "  monitor     - Run health and network checks"
	@echo "  user-add    - Add a new system user"
