#!/bin/bash
# Wolf Prowler Build Script
# Automatically loads environment variables from .env and builds the project

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}🐺 Wolf Prowler Build Script${NC}"
echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${RED}Error: .env file not found!${NC}"
    echo "Please create a .env file with DATABASE_URL and other required variables."
    exit 1
fi

# Load environment variables from .env
echo -e "${YELLOW}Loading environment variables from .env...${NC}"
export $(grep -v '^#' .env | xargs)

# Verify DATABASE_URL is set
if [ -z "$DATABASE_URL" ]; then
    echo -e "${RED}Error: DATABASE_URL not found in .env file!${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Environment variables loaded${NC}"
echo -e "${YELLOW}Database: ${DATABASE_URL#*@}${NC}"  # Show only the host part
echo ""

# Check if database is accessible
echo -e "${YELLOW}Checking database connection...${NC}"
if psql "$DATABASE_URL" -c "SELECT 1;" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Database connection successful${NC}"
else
    echo -e "${RED}Warning: Cannot connect to database${NC}"
    echo -e "${YELLOW}Build may fail if sqlx macros need to verify queries${NC}"
fi
echo ""

# Parse command line arguments
BUILD_TYPE="build"
EXTRA_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --release)
            EXTRA_ARGS="$EXTRA_ARGS --release"
            shift
            ;;
        --test)
            BUILD_TYPE="test"
            shift
            ;;
        --check)
            BUILD_TYPE="check"
            shift
            ;;
        --run)
            BUILD_TYPE="run"
            shift
            ;;
        *)
            EXTRA_ARGS="$EXTRA_ARGS $1"
            shift
            ;;
    esac
done

# Execute cargo command
echo -e "${GREEN}Running: cargo $BUILD_TYPE $EXTRA_ARGS${NC}"
echo ""

cargo $BUILD_TYPE $EXTRA_ARGS

# Check exit code
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Build completed successfully!${NC}"
else
    echo ""
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
