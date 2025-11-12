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
if ! sudo systemctl is-active --quiet neo4j; then
    echo "📊 Starting Neo4j..."
    sudo systemctl start neo4j
    sleep 5
fi

echo "✅ Neo4j is running"

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
