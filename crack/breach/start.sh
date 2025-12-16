#!/bin/bash

# B.R.E.A.C.H. Launcher
# Box Reconnaissance, Exploitation & Attack Command Hub
#
# Usage:
#   ./start.sh              # Normal mode
#   ./start.sh --debug      # Debug mode (all logs)
#   ./start.sh debug        # Same as --debug
#   ./start.sh --verbose    # Maximum verbosity
#   ./start.sh verbose      # Same as --verbose

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Handle --help
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo ""
    echo "B.R.E.A.C.H. - Box Reconnaissance, Exploitation & Attack Command Hub"
    echo ""
    echo "Usage:"
    echo "  crack-breach              Launch GUI (normal mode)"
    echo "  crack-breach --debug      Launch with debug logging (INFO level)"
    echo "  crack-breach --verbose    Launch with verbose logging (TRACE level)"
    echo "  crack-breach --help       Show this help"
    echo ""
    echo "Features:"
    echo "  • Terminal multiplexer (xterm.js + node-pty)"
    echo "  • Engagement tracking (Neo4j)"
    echo "  • Credential vault"
    echo "  • Loot tracking"
    echo "  • Target sidebar"
    echo ""
    echo "Debug Modes:"
    echo "  normal    No debug output (production)"
    echo "  --debug   INFO level + all categories"
    echo "  --verbose TRACE level + all categories (very noisy)"
    echo ""
    echo "Log Levels (from highest to lowest priority):"
    echo "  ERROR     Critical failures - always shown"
    echo "  WARN      Recoverable issues, potential problems"
    echo "  INFO      General operational info (--debug default)"
    echo "  DEBUG     Detailed debugging information"
    echo "  TRACE     Very verbose, function-level tracing (--verbose)"
    echo ""
    echo "Log Categories:"
    echo "  Main Process:"
    echo "    STARTUP      App initialization, window creation"
    echo "    NEO4J        Database connections, pool status"
    echo "    QUERY        Neo4j query execution details"
    echo "    IPC          IPC handler invocations"
    echo "    PTY          Terminal PTY I/O, spawn/kill"
    echo "    SESSION      Session lifecycle, linking"
    echo "    ELECTRON     Electron framework events"
    echo ""
    echo "  Renderer Process:"
    echo "    UI           Panel state, tab switches, collapse"
    echo "    ACTION       User-initiated actions"
    echo "    DATA         Async data fetching"
    echo "    VALIDATION   Input validation results"
    echo "    LIFECYCLE    Component mount/unmount"
    echo "    RENDER       Re-render triggers (verbose)"
    echo "    FOCUS        Focus/blur events"
    echo "    CLIPBOARD    Copy/paste operations"
    echo "    TERMINAL_IO  Terminal input/output tracking"
    echo ""
    echo "  Shared:"
    echo "    ERROR        All error logging"
    echo "    PERFORMANCE  Timing measurements"
    echo ""
    echo "Runtime Configuration (DevTools Console):"
    echo "  // Enable debug in browser"
    echo "  localStorage.setItem('breach_debug', JSON.stringify({"
    echo "    enabled: true,"
    echo "    level: 3,  // 0=ERROR, 1=WARN, 2=INFO, 3=DEBUG, 4=TRACE"
    echo "    categories: ['IPC', 'TERMINAL_IO', 'PTY']"
    echo "  }));"
    echo ""
    echo "  // Then refresh the page (Ctrl+R)"
    echo ""
    echo "Requirements:"
    echo "  • Neo4j 5.x running on bolt://localhost:7687"
    echo "  • Node.js 18+"
    echo ""
    exit 0
fi

echo "🔓 Starting B.R.E.A.C.H. (Box Reconnaissance, Exploitation & Attack Command Hub)"

# Check if Neo4j is running
if ! pgrep -f "org.neo4j.server" > /dev/null; then
    echo "📊 Starting Neo4j..."

    # Try systemd first
    if systemctl list-unit-files neo4j.service &> /dev/null; then
        sudo systemctl start neo4j
    # Fall back to direct neo4j command
    elif command -v neo4j &> /dev/null; then
        sudo neo4j start
    else
        echo "❌ Neo4j not found. Please install Neo4j."
        echo "   B.R.E.A.C.H. requires Neo4j for engagement tracking."
        exit 1
    fi

    # Wait for Neo4j to be ready
    echo "⏳ Waiting for Neo4j to start..."
    for i in {1..10}; do
        if pgrep -f "org.neo4j.server" > /dev/null; then
            echo "✅ Neo4j is running"
            break
        fi
        sleep 1
    done

    if ! pgrep -f "org.neo4j.server" > /dev/null; then
        echo "⚠️  Neo4j may not have started properly"
    fi
else
    echo "✅ Neo4j is already running"
fi

# Check node_modules
if [ ! -d "$SCRIPT_DIR/node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

# Determine which mode to run
MODE=${1:-normal}

# Handle --flag style arguments
case "$MODE" in
    --debug)
        MODE="debug"
        ;;
    --verbose)
        MODE="verbose"
        ;;
    -d)
        MODE="debug"
        ;;
    -v)
        MODE="verbose"
        ;;
esac

case "$MODE" in
    debug)
        echo "🔧 Launching B.R.E.A.C.H. in DEBUG mode..."
        npm run dev:debug
        ;;
    verbose)
        echo "🔧 Launching B.R.E.A.C.H. in VERBOSE mode..."
        npm run dev:verbose
        ;;
    *)
        echo "🔧 Launching B.R.E.A.C.H. (normal mode)..."
        npm run dev
        ;;
esac
