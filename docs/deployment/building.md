# Wolf Prowler Build Guide

## Quick Start

Use the provided build script to automatically handle environment variables:

```bash
./build.sh                    # Standard debug build
./build.sh --release          # Release build
./build.sh --check            # Quick syntax check
./build.sh --test             # Run tests
./build.sh --run              # Build and run
```

## Why Use the Build Script?

The Wolf Prowler project uses `sqlx` macros that verify SQL queries at compile time. This requires:
1. A running PostgreSQL database
2. The `DATABASE_URL` environment variable set

The `build.sh` script automatically:
- ✅ Loads environment variables from `.env`
- ✅ Verifies database connectivity
- ✅ Runs the appropriate cargo command
- ✅ Provides helpful error messages

## Manual Building

If you prefer to build manually, ensure you export the DATABASE_URL first:

```bash
export DATABASE_URL=postgresql://wolf_admin:wolf_secure_pass_2024@localhost:5432/wolf_prowler
cargo build
```

## Database Setup

The PostgreSQL database runs in a Docker container. Ensure it's running:

```bash
docker ps | grep wolf_postgres
```

If not running, start it with:

```bash
docker start wolf_postgres
```

## Troubleshooting

### "Connection refused" during build
- Check if the database container is running: `docker ps`
- Verify the DATABASE_URL in `.env` uses `localhost:5432`
- Test connection: `psql $DATABASE_URL -c "SELECT 1;"`

### Database IP changed
The `.env` file now uses `localhost:5432` which is stable across container restarts. If you need to use the Docker internal IP, update it with:

```bash
docker inspect wolf_postgres | grep IPAddress
```

### SQLx offline mode (for CI/CD)
To build without database access:

```bash
cargo sqlx prepare  # Generate query metadata (run once with DB)
cargo build --offline  # Build using cached metadata
```
