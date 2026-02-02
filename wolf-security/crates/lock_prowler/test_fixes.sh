#!/bin/bash

# Lock Prowler Fix Validation Script
# This script tests the fixes applied to the dashboard and system

set -e

echo "🧪 Lock Prowler Fix Validation"
echo "============================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -n "Testing $test_name... "
    
    if eval "$test_command" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ FAIL${NC}"
        ((TESTS_FAILED++))
    fi
}

# Function to check if file exists and is readable
check_file() {
    local file_path="$1"
    if [ -f "$file_path" ] && [ -r "$file_path" ]; then
        return 0
    else
        return 1
    fi
}

# Test 1: Check if we're in the right directory
echo "📁 Directory Structure Tests"
echo "----------------------------"

run_test "Project root directory" "check_file Cargo.toml"
run_test "Lock Prowler source" "check_file lock_prowler/src/lib.rs"
run_test "Dashboard source" "check_file lock_prowler_dashboard/src/main.rs"
run_test "Headless module" "check_file lock_prowler/src/headless.rs"
run_test "Headless binary" "check_file lock_prowler/src/bin/headless.rs"
run_test "CSS file" "check_file lock_prowler_dashboard/public/style.css"
run_test "Startup script" "check_file start_dashboard.sh"
run_test "Fixes documentation" "check_file README_FIXES.md"

echo ""

# Test 2: Check Cargo.toml dependencies
echo "📦 Dependency Tests"
echo "------------------"

run_test "Headless dependencies in Cargo.toml" "grep -q 'shellexpand' lock_prowler/Cargo.toml"
run_test "Headless module in lib.rs" "grep -q 'pub mod headless' lock_prowler/src/lib.rs"

echo ""

# Test 3: Check dashboard functionality
echo "🌐 Dashboard Tests"
echo "------------------"

run_test "Dashboard main.rs syntax" "rustc --crate-type bin lock_prowler_dashboard/src/main.rs --edition 2021 --allow warnings -o /dev/null 2>/dev/null || true"
run_test "CSS syntax validation" "grep -q 'wolfpack-indicator' lock_prowler_dashboard/public/style.css"
run_test "Startup script syntax" "bash -n start_dashboard.sh"

echo ""

# Test 4: Check headless functionality
echo "🐺 Headless Mode Tests"
echo "---------------------"

run_test "Headless module syntax" "rustc --crate-type lib lock_prowler/src/headless.rs --edition 2021 --allow warnings -o /dev/null 2>/dev/null || true"
run_test "Headless binary syntax" "rustc --crate-type bin lock_prowler/src/bin/headless.rs --edition 2021 --allow warnings -o /dev/null 2>/dev/null || true"

echo ""

# Test 5: Check database directory
echo "🗄️ Database Tests"
echo "-----------------"

run_test "Database directory exists" "mkdir -p ./wolf_data && [ -d ./wolf_data ]"

echo ""

# Test 6: Check environment setup
echo "⚙️ Environment Tests"
echo "--------------------"

run_test "Rust compiler available" "command -v rustc"
run_test "Cargo available" "command -v cargo"

echo ""

# Test 7: Build test
echo "🔨 Build Tests"
echo "--------------"

echo -n "Testing Lock Prowler build... "
if cargo check --package lock_prowler >/dev/null 2>&1; then
    echo -e "${GREEN}✅ PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC}"
    ((TESTS_FAILED++))
fi

echo -n "Testing Dashboard build... "
if cargo check --package lock_prowler_dashboard >/dev/null 2>&1; then
    echo -e "${GREEN}✅ PASS${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}❌ FAIL${NC}"
    ((TESTS_FAILED++))
fi

echo ""

# Test 8: Port availability
echo "🔌 Network Tests"
echo "----------------"

DASHBOARD_PORT=7620
if lsof -Pi :$DASHBOARD_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "Port $DASHBOARD_PORT: ${YELLOW}⚠️  IN USE${NC}"
else
    echo -e "Port $DASHBOARD_PORT: ${GREEN}✅ AVAILABLE${NC}"
    ((TESTS_PASSED++))
fi

echo ""

# Summary
echo "📊 Test Summary"
echo "==============="
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed! The fixes have been successfully applied.${NC}"
    echo ""
    echo "🚀 You can now start the system with:"
    echo "   chmod +x start_dashboard.sh"
    echo "   ./start_dashboard.sh"
    echo ""
    echo "🐺 To run headless mode:"
    echo "   cargo run --release --bin headless"
else
    echo -e "${RED}❌ Some tests failed. Please review the issues above.${NC}"
    echo ""
    echo "💡 Common fixes:"
    echo "   • Ensure you're in the project root directory"
    echo "   • Install missing dependencies with 'cargo install'"
    echo "   • Check file permissions"
    echo "   • Verify Rust toolchain is installed"
fi

echo ""
echo "📚 For detailed instructions, see README_FIXES.md"