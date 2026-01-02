#!/bin/bash
# Wolf Prowler Database Management Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Database connection details
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-wolf_prowler}"
DB_USER="${DB_USER:-wolf_admin}"
DB_PASSWORD="${DB_PASSWORD:-wolf_secure_pass_2024}"

# Functions
print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check if PostgreSQL is running
check_postgres() {
    print_header "Checking PostgreSQL Connection"
    
    if PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d postgres -c '\q' 2>/dev/null; then
        print_success "PostgreSQL is running and accessible"
        return 0
    else
        print_error "Cannot connect to PostgreSQL"
        return 1
    fi
}

# Create database
create_database() {
    print_header "Creating Database"
    
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d postgres <<EOF
CREATE DATABASE $DB_NAME;
EOF
    
    if [ $? -eq 0 ]; then
        print_success "Database '$DB_NAME' created successfully"
    else
        print_warning "Database may already exist"
    fi
}

# Run migrations
run_migrations() {
    print_header "Running Migrations"
    
    if [ ! -d "migrations" ]; then
        print_error "Migrations directory not found"
        exit 1
    fi
    
    for migration in migrations/*.sql; do
        if [ -f "$migration" ]; then
            echo "Running migration: $(basename $migration)"
            PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -f "$migration"
            
            if [ $? -eq 0 ]; then
                print_success "Migration $(basename $migration) completed"
            else
                print_error "Migration $(basename $migration) failed"
                exit 1
            fi
        fi
    done
    
    print_success "All migrations completed successfully"
}

# Backup database
backup_database() {
    print_header "Backing Up Database"
    
    BACKUP_DIR="backups"
    mkdir -p $BACKUP_DIR
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="$BACKUP_DIR/wolf_prowler_backup_$TIMESTAMP.sql"
    
    PGPASSWORD=$DB_PASSWORD pg_dump -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME > $BACKUP_FILE
    
    if [ $? -eq 0 ]; then
        print_success "Database backed up to: $BACKUP_FILE"
        
        # Compress backup
        gzip $BACKUP_FILE
        print_success "Backup compressed: ${BACKUP_FILE}.gz"
    else
        print_error "Backup failed"
        exit 1
    fi
}

# Restore database
restore_database() {
    if [ -z "$1" ]; then
        print_error "Please provide backup file path"
        echo "Usage: $0 restore <backup_file>"
        exit 1
    fi
    
    BACKUP_FILE=$1
    
    if [ ! -f "$BACKUP_FILE" ]; then
        print_error "Backup file not found: $BACKUP_FILE"
        exit 1
    fi
    
    print_header "Restoring Database"
    print_warning "This will drop and recreate the database. Continue? (y/N)"
    read -r response
    
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Restore cancelled"
        exit 0
    fi
    
    # Drop and recreate database
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d postgres <<EOF
DROP DATABASE IF EXISTS $DB_NAME;
CREATE DATABASE $DB_NAME;
EOF
    
    # Restore from backup
    if [[ $BACKUP_FILE == *.gz ]]; then
        gunzip -c $BACKUP_FILE | PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME
    else
        PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME < $BACKUP_FILE
    fi
    
    if [ $? -eq 0 ]; then
        print_success "Database restored successfully"
    else
        print_error "Restore failed"
        exit 1
    fi
}

# Show database stats
show_stats() {
    print_header "Database Statistics"
    
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME <<EOF
-- Table sizes
SELECT 
    schemaname as schema,
    tablename as table,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
    pg_total_relation_size(schemaname||'.'||tablename) as bytes
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY bytes DESC;

-- Row counts
SELECT 
    'peers' as table, COUNT(*) as rows FROM peers
UNION ALL
SELECT 'security_events', COUNT(*) FROM security_events
UNION ALL
SELECT 'alerts', COUNT(*) FROM alerts
UNION ALL
SELECT 'users', COUNT(*) FROM users
UNION ALL
SELECT 'roles', COUNT(*) FROM roles
UNION ALL
SELECT 'threats', COUNT(*) FROM threats
UNION ALL
SELECT 'audit_logs', COUNT(*) FROM audit_logs
UNION ALL
SELECT 'pack_members', COUNT(*) FROM pack_members
UNION ALL
SELECT 'system_logs', COUNT(*) FROM system_logs;
EOF
}

# Clean old data
clean_old_data() {
    print_header "Cleaning Old Data"
    print_warning "This will delete old records. Continue? (y/N)"
    read -r response
    
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Cleanup cancelled"
        exit 0
    fi
    
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME <<EOF
-- Clean old peer metrics (keep last 30 days)
DELETE FROM peer_metrics WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '30 days';

-- Clean resolved security events (keep last 90 days)
DELETE FROM security_events WHERE resolved = true AND timestamp < CURRENT_TIMESTAMP - INTERVAL '90 days';

-- Clean old alerts (keep last 90 days)
DELETE FROM alerts WHERE (status = 'resolved' OR status = 'suppressed') AND timestamp < CURRENT_TIMESTAMP - INTERVAL '90 days';

-- Clean old system logs (keep last 7 days)
DELETE FROM system_logs WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '7 days';

-- Vacuum to reclaim space
VACUUM ANALYZE;
EOF
    
    print_success "Old data cleaned successfully"
}

# Main menu
show_menu() {
    echo ""
    print_header "Wolf Prowler Database Manager"
    echo "1. Check PostgreSQL connection"
    echo "2. Create database"
    echo "3. Run migrations"
    echo "4. Backup database"
    echo "5. Restore database"
    echo "6. Show database statistics"
    echo "7. Clean old data"
    echo "8. Full setup (create + migrate)"
    echo "9. Exit"
    echo ""
    echo -n "Select option: "
}

# Main script
case "${1:-menu}" in
    check)
        check_postgres
        ;;
    create)
        create_database
        ;;
    migrate)
        run_migrations
        ;;
    backup)
        backup_database
        ;;
    restore)
        restore_database "$2"
        ;;
    stats)
        show_stats
        ;;
    clean)
        clean_old_data
        ;;
    setup)
        check_postgres && create_database && run_migrations
        ;;
    menu)
        while true; do
            show_menu
            read -r choice
            case $choice in
                1) check_postgres ;;
                2) create_database ;;
                3) run_migrations ;;
                4) backup_database ;;
                5) 
                    echo -n "Enter backup file path: "
                    read -r backup_file
                    restore_database "$backup_file"
                    ;;
                6) show_stats ;;
                7) clean_old_data ;;
                8) check_postgres && create_database && run_migrations ;;
                9) exit 0 ;;
                *) print_error "Invalid option" ;;
            esac
            echo ""
            echo "Press Enter to continue..."
            read
        done
        ;;
    *)
        echo "Usage: $0 {check|create|migrate|backup|restore|stats|clean|setup|menu}"
        echo ""
        echo "Commands:"
        echo "  check    - Check PostgreSQL connection"
        echo "  create   - Create database"
        echo "  migrate  - Run migrations"
        echo "  backup   - Backup database"
        echo "  restore  - Restore database from backup"
        echo "  stats    - Show database statistics"
        echo "  clean    - Clean old data"
        echo "  setup    - Full setup (create + migrate)"
        echo "  menu     - Interactive menu (default)"
        exit 1
        ;;
esac
