#!/bin/bash

# CRACK Electron Launcher
# Ensures Neo4j is running and launches the app
#
# Usage:
#   ./start.sh          # Normal mode
#   ./start.sh debug    # Debug mode (all logs)
#   ./start.sh neo4j    # Debug Neo4j only
#   ./start.sh ipc      # Debug IPC only
#   ./start.sh verbose  # Maximum verbosity

echo "🚀 Starting CRACK Electron..."

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
        echo "🔧 Launching Electron app (normal mode)..."
        npm run dev
        ;;
esac
