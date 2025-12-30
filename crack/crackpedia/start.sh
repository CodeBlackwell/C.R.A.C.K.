#!/bin/bash

# Crackpedia Launcher
# Ensures Neo4j is running and launches the app
#
# Usage:
#   ./start.sh          # Normal mode
#   ./start.sh debug    # Debug mode (all logs)
#   ./start.sh neo4j    # Debug Neo4j only
#   ./start.sh ipc      # Debug IPC only
#   ./start.sh verbose  # Maximum verbosity

echo "🚀 Starting Crackpedia..."

# Function to wait for bolt port to be ready
wait_for_bolt() {
    echo "⏳ Waiting for Neo4j bolt port (7687)..."
    for i in {1..30}; do
        if nc -z 127.0.0.1 7687 2>/dev/null; then
            echo "✅ Neo4j bolt port is ready"
            return 0
        fi
        sleep 1
    done
    echo "⚠️  Neo4j bolt port may not be ready"
    return 1
}

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
        exit 1
    fi

    # Wait for Neo4j process to appear
    echo "⏳ Waiting for Neo4j process..."
    for i in {1..10}; do
        if pgrep -f "org.neo4j.server" > /dev/null; then
            echo "✅ Neo4j process started"
            break
        fi
        sleep 1
    done

    if ! pgrep -f "org.neo4j.server" > /dev/null; then
        echo "⚠️  Neo4j may not have started properly"
    fi

    # Wait for bolt port
    wait_for_bolt
else
    echo "✅ Neo4j process is running"
    # Still verify bolt port is ready (might have just started)
    if ! nc -z 127.0.0.1 7687 2>/dev/null; then
        wait_for_bolt
    else
        echo "✅ Neo4j bolt port is ready"
    fi
fi

# Determine which mode to run
MODE=${1:-normal}

case "$MODE" in
    debug)
        echo "🔧 Launching with DEBUG mode..."
        npm run dev:debug
        ;;
    verbose)
        echo "🔧 Launching with VERBOSE debug mode..."
        npm run dev:verbose
        ;;
    neo4j)
        echo "🔧 Launching with Neo4j debug logs..."
        npm run dev:neo4j
        ;;
    ipc)
        echo "🔧 Launching with IPC debug logs..."
        npm run dev:ipc
        ;;
    *)
        echo "🔧 Launching Crackpedia (normal mode)..."
        npm run dev
        ;;
esac
