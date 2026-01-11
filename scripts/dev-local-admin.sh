#!/bin/bash

# n8n Development Server Startup Script with Local Admin Mode
# This script implements all prerequisites from START.md and starts n8n in dev mode
# with N8N_LOCAL=true to enable all enterprise features without a license

set -e  # Exit on error

# ============================================
# Configuration
# ============================================
readonly BACKEND_PORT=5888
readonly FRONTEND_PORT=8080
readonly MAX_WAIT=120
readonly LOG_FILE="/tmp/n8n-dev-$(date +%Y%m%d-%H%M%S).log"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global variables
SCRIPT_DIR=""
PROJECT_ROOT=""
DEV_PID=""

# ============================================
# Output Functions
# ============================================
printStatus() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

printSuccess() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

printWarning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

printError() {
    echo -e "${RED}[ERROR]${NC} $1"
}

printHeader() {
    echo "======================================"
    echo "  n8n Development Server Setup"
    echo "  Local Admin Mode Enabled"
    echo "======================================"
    echo ""
}

# ============================================
# Prerequisite Check Functions
# ============================================
checkNodeVersion() {
    printStatus "Checking Node.js version..."
    local node_version
    node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)

    if [ "$node_version" -lt 20 ] || [ "$node_version" -gt 24 ]; then
        printError "Node.js version $node_version is not compatible"
        printError "Required: >=20.19 <= 24.x"
        return 1
    fi

    printSuccess "Node.js version $(node --version) is compatible"
    return 0
}

checkPnpmVersion() {
    printStatus "Checking pnpm installation..."

    if ! command -v pnpm &> /dev/null; then
        printError "pnpm is not installed"
        printError "Install with: npm install -g pnpm@10.22.0"
        return 1
    fi

    local pnpm_version
    pnpm_version=$(pnpm --version)
    printSuccess "pnpm version $pnpm_version found"
    return 0
}

checkDependencies() {
    printStatus "Checking if dependencies are installed..."

    if [ ! -d "node_modules" ]; then
        printWarning "node_modules not found. Installing dependencies..."
        pnpm install
    else
        printSuccess "Dependencies are installed"
    fi
    return 0
}

checkNodemon() {
    printStatus "Verifying nodemon installation in CLI package..."

    cd "$PROJECT_ROOT/packages/cli" || return 1

    if ! pnpm list nodemon 2>/dev/null | grep -q "nodemon"; then
        printWarning "nodemon not found. Installing..."
        pnpm add -D nodemon
        printSuccess "nodemon installed"
    else
        printSuccess "nodemon is installed"
    fi

    cd "$PROJECT_ROOT" || return 1
    return 0
}

checkPackagesBuild() {
    printStatus "Checking if packages are built..."

    if [ ! -d "packages/cli/dist" ] || [ ! -d "packages/core/dist" ]; then
        printWarning "Some packages are not built. This may cause issues."
        printWarning "Run 'pnpm build' if you encounter problems."
    fi
    return 0
}

updateFrontendPort() {
    printStatus "Updating frontend API URL to use port ${BACKEND_PORT}..."

    local package_json="$PROJECT_ROOT/packages/frontend/editor-ui/package.json"

    if grep -q "VUE_APP_URL_BASE_API=http://localhost:${BACKEND_PORT}/" "$package_json"; then
        printSuccess "Frontend already configured for port ${BACKEND_PORT}"
    else
        printWarning "Updating frontend package.json to use port ${BACKEND_PORT}"
        # Use sed to update the port in the serve script
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' "s|VUE_APP_URL_BASE_API=http://localhost:[0-9]\+/|VUE_APP_URL_BASE_API=http://localhost:${BACKEND_PORT}/|g" "$package_json"
        else
            # Linux
            sed -i "s|VUE_APP_URL_BASE_API=http://localhost:[0-9]\+/|VUE_APP_URL_BASE_API=http://localhost:${BACKEND_PORT}/|g" "$package_json"
        fi
        printSuccess "Frontend configured for port ${BACKEND_PORT}"
    fi
    return 0
}

# ============================================
# Port Management Functions
# ============================================
killExistingProcesses() {
    printStatus "Checking for existing processes on ports ${BACKEND_PORT}, ${FRONTEND_PORT}, and 5999 (Task Broker)..."

    local pids_backend
    local pids_frontend
    local pids_broker
    pids_backend=$(lsof -ti ":${BACKEND_PORT}" 2>/dev/null || true)
    pids_frontend=$(lsof -ti ":${FRONTEND_PORT}" 2>/dev/null || true)
    pids_broker=$(lsof -ti ":5999" 2>/dev/null || true)

    if [ -n "$pids_backend" ]; then
        printWarning "Killing processes on port ${BACKEND_PORT}: $pids_backend"
        echo "$pids_backend" | xargs kill -9 2>/dev/null || true
        sleep 1
    fi

    if [ -n "$pids_frontend" ]; then
        printWarning "Killing processes on port ${FRONTEND_PORT}: $pids_frontend"
        echo "$pids_frontend" | xargs kill -9 2>/dev/null || true
        sleep 1
    fi

    if [ -n "$pids_broker" ]; then
        printWarning "Killing processes on port 5999 (Task Broker): $pids_broker"
        echo "$pids_broker" | xargs kill -9 2>/dev/null || true
        sleep 1
    fi

    printSuccess "Ports ${BACKEND_PORT}, ${FRONTEND_PORT}, and 5999 are now available"
    return 0
}

# ============================================
# Environment Setup Functions
# ============================================
setupEnvironment() {
    printStatus "Setting environment variables..."

    export N8N_PORT="${BACKEND_PORT}"
    export N8N_LOCAL=true
    export N8N_LOCAL_ADMIN="admin@n8n.local"

    printSuccess "Environment configured:"
    echo "  - N8N_PORT=${BACKEND_PORT} (backend)"
    echo "  - N8N_LOCAL=true (all enterprise features enabled)"
    echo "  - N8N_LOCAL_ADMIN=$N8N_LOCAL_ADMIN"
    echo ""
    return 0
}

# ============================================
# Service Startup Functions
# ============================================
startDevServer() {
    printStatus "Logs will be written to: $LOG_FILE"
    echo ""

    printStatus "Starting development server..."
    printStatus "This may take 60-90 seconds for first compilation..."
    echo ""

    # Start the dev server and capture output
    pnpm run dev > "$LOG_FILE" 2>&1 &
    DEV_PID=$!

    return 0
}

waitForServices() {
    printStatus "Waiting for services to start (timeout: ${MAX_WAIT}s)..."

    local backend_ready=false
    local frontend_ready=false
    local wait_count=0
    local last_progress=""

    while [ $wait_count -lt $MAX_WAIT ]; do
        sleep 2
        wait_count=$((wait_count + 2))

        # Check if backend is ready
        if ! $backend_ready && grep -q "n8n ready on" "$LOG_FILE" 2>/dev/null; then
            backend_ready=true
            echo ""  # New line after dots
            printSuccess "Backend is ready on port ${BACKEND_PORT}"
        fi

        # Check if frontend is ready
        if ! $frontend_ready && grep -q "Local:.*${FRONTEND_PORT}" "$LOG_FILE" 2>/dev/null; then
            frontend_ready=true
            echo ""  # New line after dots
            printSuccess "Frontend is ready on port ${FRONTEND_PORT}"
        fi

        # Both ready, exit loop
        if $backend_ready && $frontend_ready; then
            echo ""
            return 0
        fi

        # Show progress with more context
        if [ $((wait_count % 10)) -eq 0 ]; then
            # Get last non-empty line from log that's not a warning
            local current_line
            current_line=$(tail -5 "$LOG_FILE" 2>/dev/null | grep -v "WARN" | grep -v "^$" | tail -1 | cut -c1-80)
            if [ -n "$current_line" ] && [ "$current_line" != "$last_progress" ]; then
                echo ""
                printStatus "Progress: ${current_line}..."
                last_progress="$current_line"
            fi
        fi

        # Show dot
        echo -n "."
    done

    echo ""
    echo ""
    return 1
}

verifyHealthCheck() {
    printStatus "Testing backend health..."

    if curl -sf "http://localhost:${BACKEND_PORT}/healthz" > /dev/null 2>&1; then
        local health
        health=$(curl -s "http://localhost:${BACKEND_PORT}/healthz")
        printSuccess "Backend health check: $health"
        return 0
    else
        printWarning "Backend health check failed, but service may still be starting"
        return 1
    fi
}

displaySuccessMessage() {
    printSuccess "All services started successfully!"
    echo ""

    echo "======================================"
    echo "  🎉 n8n Development Server Running"
    echo "======================================"
    echo ""
    echo "Access Points:"
    echo "  🌐 Frontend:     http://localhost:${FRONTEND_PORT}"
    echo "  🔧 Backend API:  http://localhost:${BACKEND_PORT}"
    echo "  ❤️  Health Check: http://localhost:${BACKEND_PORT}/healthz"
    echo ""
    echo "Local Admin Mode:"
    echo "  👤 Email: $N8N_LOCAL_ADMIN"
    echo "  🔓 All enterprise features enabled"
    echo ""
    echo "Logs:"
    echo "  📄 Tail logs: tail -f $LOG_FILE"
    echo "  📊 View full: cat $LOG_FILE"
    echo ""
    echo "To stop:"
    echo "  🛑 Press Ctrl+C or run: pkill -9 -f 'pnpm.*dev'"
    echo ""
    echo "======================================"
    echo ""
}

tailLogs() {
    printStatus "Tailing logs (Ctrl+C to stop)..."
    echo ""
    tail -f "$LOG_FILE"
}

watchLogs() {
    local log_to_watch="$LOG_FILE"

    # Find the most recent log file if LOG_FILE is not set or doesn't exist
    if [ -z "$log_to_watch" ] || [ ! -f "$log_to_watch" ]; then
        log_to_watch=$(ls -t /tmp/n8n-dev-*.log 2>/dev/null | head -1)
        if [ -z "$log_to_watch" ]; then
            printError "No log files found in /tmp/n8n-dev-*.log"
            return 1
        fi
        printStatus "Watching most recent log file: $log_to_watch"
    else
        printStatus "Watching log file: $log_to_watch"
    fi

    echo ""
    printStatus "Press Ctrl+C to stop watching..."
    echo ""

    tail -f "$log_to_watch"
}

status() {
    printHeader

    # Check backend status
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Backend Status (Port ${BACKEND_PORT})"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local backend_pid
    backend_pid=$(lsof -ti ":${BACKEND_PORT}" 2>/dev/null || true)

    if [ -n "$backend_pid" ]; then
        printSuccess "Backend is RUNNING"
        echo "  PID: $backend_pid"
        echo "  Port: ${BACKEND_PORT}"
        echo "  URL: http://localhost:${BACKEND_PORT}"

        # Try health check
        if curl -s -f "http://localhost:${BACKEND_PORT}/healthz" > /dev/null 2>&1; then
            printSuccess "  Health Check: OK"
        else
            printWarning "  Health Check: Failed or not ready"
        fi
    else
        printError "Backend is NOT RUNNING"
    fi

    echo ""

    # Check frontend status
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Frontend Status (Port ${FRONTEND_PORT})"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local frontend_pid
    frontend_pid=$(lsof -ti ":${FRONTEND_PORT}" 2>/dev/null || true)

    if [ -n "$frontend_pid" ]; then
        printSuccess "Frontend is RUNNING"
        echo "  PID: $frontend_pid"
        echo "  Port: ${FRONTEND_PORT}"
        echo "  URL: http://localhost:${FRONTEND_PORT}"
    else
        printError "Frontend is NOT RUNNING"
    fi

    echo ""

    # Check log files
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Log Files"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local recent_logs
    recent_logs=$(ls -t /tmp/n8n-dev-*.log 2>/dev/null | head -3)

    if [ -n "$recent_logs" ]; then
        echo "Recent log files:"
        echo "$recent_logs" | while read -r log; do
            local log_size
            log_size=$(du -h "$log" | cut -f1)
            echo "  - $log ($log_size)"
        done
    else
        printWarning "No log files found"
    fi

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Overall status summary
    if [ -n "$backend_pid" ] && [ -n "$frontend_pid" ]; then
        echo ""
        printSuccess "✓ All services are running"
        echo ""
        echo "Access your n8n instance at: http://localhost:${FRONTEND_PORT}"
    elif [ -n "$backend_pid" ] || [ -n "$frontend_pid" ]; then
        echo ""
        printWarning "⚠ Some services are running"
    else
        echo ""
        printError "✗ No services are running"
        echo ""
        echo "Start services with: $0"
    fi
}

handleFailure() {
    printError "Services did not start within ${MAX_WAIT} seconds"
    printError "Check logs at: $LOG_FILE"
    echo ""
    printStatus "Last 50 lines of log:"
    tail -50 "$LOG_FILE"
    return 1
}

# ============================================
# Cleanup Function
# ============================================
cleanup() {
    echo ''
    printStatus 'Shutting down...'
    kill "$DEV_PID" 2>/dev/null || true
    exit 0
}

# ============================================
# Help Function
# ============================================
showHelp() {
    echo "n8n Development Server Script - Local Admin Mode"
    echo ""
    echo "Usage:"
    echo "  $0                    # Run full startup sequence"
    echo "  $0 <function>         # Run a specific function"
    echo ""
    echo "Available Functions:"
    echo "  checkNodeVersion      - Check Node.js version compatibility"
    echo "  checkPnpmVersion      - Check pnpm installation"
    echo "  checkDependencies     - Check and install dependencies"
    echo "  checkNodemon          - Check nodemon in CLI package"
    echo "  checkPackagesBuild    - Check if packages are built"
    echo "  updateFrontendPort    - Update frontend to use port ${BACKEND_PORT}"
    echo "  killExistingProcesses - Kill processes on ports ${BACKEND_PORT} and ${FRONTEND_PORT}"
    echo "  setupEnvironment      - Setup environment variables"
    echo "  startDevServer        - Start the dev server"
    echo "  waitForServices       - Wait for services to start"
    echo "  verifyHealthCheck     - Check backend health endpoint"
    echo "  watchLogs             - Watch the most recent log file"
    echo "  status                - Check status of running services"
    echo "  displaySuccessMessage - Show success message with URLs"
    echo ""
    echo "Configuration:"
    echo "  Backend Port:  ${BACKEND_PORT}"
    echo "  Frontend Port: ${FRONTEND_PORT}"
    echo "  Max Wait:      ${MAX_WAIT}s"
    echo ""
    echo "Examples:"
    echo "  $0 status                 # Check status of running services"
    echo "  $0 watchLogs              # Watch logs from previous run"
    echo "  $0 checkNodeVersion       # Just check Node version"
    echo "  $0 verifyHealthCheck      # Check if backend is healthy"
    echo "  $0 killExistingProcesses  # Kill existing dev processes"
    echo ""

}

# ============================================
# Cleanup Function
# ============================================
# ============================================
# Cleanup Function
# ============================================
cleanup() {
    echo ''
    printStatus 'Shutting down...'
    kill "$DEV_PID" 2>/dev/null || true
    exit 0
}

# ============================================
# Function Dispatcher
# ============================================
runFunction() {
    local func_name="$1"
    shift  # Remove function name from arguments

    # Setup script paths for individual function calls
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
    cd "$PROJECT_ROOT" || exit 1

    # Check if function exists
    if declare -f "$func_name" > /dev/null; then
        # Special handling for functions that need setup
        case "$func_name" in
            setupEnvironment|startDevServer|waitForServices|verifyHealthCheck|displaySuccessMessage)
                # These functions need environment setup
                setupEnvironment > /dev/null 2>&1 || true
                ;;
        esac

        # Execute the function
        "$func_name" "$@"
        exit $?
    else
        printError "Function '$func_name' not found"
        echo ""
        showHelp
        exit 1
    fi
}

# ============================================
# Main Function
# ============================================
main() {
    # Setup script paths
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

    cd "$PROJECT_ROOT" || exit 1

    # Setup cleanup trap
    trap cleanup INT TERM

    # Display header
    printHeader

    # Execute prerequisite checks in sequence
    checkNodeVersion || exit 1
    checkPnpmVersion || exit 1
    checkDependencies || exit 1
    checkNodemon || exit 1
    checkPackagesBuild || exit 1
    updateFrontendPort || exit 1

    # Kill existing processes
    killExistingProcesses || exit 1

    # Setup environment
    setupEnvironment || exit 1

    # Start dev server
    startDevServer || exit 1

    # Wait for services to be ready
    if waitForServices; then
        # Verify health check
        verifyHealthCheck

        # Display success message
        displaySuccessMessage

        # Tail logs
        tailLogs
    else
        handleFailure
        exit 1
    fi
}

# ============================================
# Script Entry Point
# ============================================
if [ $# -eq 0 ]; then
    # No arguments - run full sequence
    main
elif [ "$1" = "help" ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    # Show help
    showHelp
else
    # Run specific function
    runFunction "$@"
fi
