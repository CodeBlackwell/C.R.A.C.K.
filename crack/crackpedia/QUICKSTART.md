# CRACK Electron - Quick Start Guide

## What Was Built

A working Electron desktop application that visualizes your CRACK Neo4j database with:

### ✅ Features Implemented

1. **Command Search** (`src/renderer/src/components/CommandSearch.tsx`)
   - Full-text search across 734 commands
   - Filter by OSCP relevance
   - Real-time debounced search
   - Results table with tags and categories

2. **Command Details** (`src/renderer/src/components/CommandDetails.tsx`)
   - Complete command information
   - Flags with descriptions
   - Variables and examples
   - Output indicators (success/failure patterns)
   - Tags and metadata

3. **Interactive Graph** (`src/renderer/src/components/GraphView.tsx`)
   - Cytoscape.js visualization
   - Color-coded relationships:
     - 🟡 Yellow = Alternative commands
     - 🔴 Red = Prerequisites
     - 🟢 Green = Next steps
   - Click nodes to navigate
   - Auto-layout with cose-bilkent algorithm
   - Zoom and pan controls

4. **Neo4j Integration** (`src/main/neo4j.ts`)
   - Direct Bolt connection
   - IPC handlers for all queries
   - Connection health checking
   - Error handling

## How to Run

### Method 1: Quick Start
```bash
cd /home/kali/Desktop/OSCP/crack-electron
./start.sh
```

### Method 2: Manual
```bash
# 1. Ensure Neo4j is running
sudo systemctl start neo4j

# 2. Run the app
cd /home/kali/Desktop/OSCP/crack-electron
npm run dev
```

## Usage

1. **Launch the app** - It will connect to Neo4j automatically
2. **Search for commands** - Type in the search box (try "nmap", "gobuster", etc.)
3. **Select a command** - Click any row in the results table
4. **View details** - Left panel shows full command info
5. **Explore the graph** - Right panel shows related commands
6. **Navigate** - Click nodes in the graph to jump to related commands

## Keyboard Shortcuts

- **Type** anywhere to focus search
- **Click** nodes to navigate
- **Scroll** to zoom in graph
- **Drag** to pan the graph

## Connection Status

Look for the badge in the top-right corner:
- 🟢 **Green** "Connected" = Good to go
- 🔴 **Red** "Disconnected" = Neo4j not running

## Troubleshooting

### App won't start
```bash
# Check Neo4j is running
sudo systemctl status neo4j

# Start it if needed
sudo systemctl start neo4j
```

### Can't connect to database
```bash
# Verify credentials
echo $NEO4J_PASSWORD  # Should be: Neo4j123

# Test connection manually
cypher-shell -u neo4j -p Neo4j123
```

### Search returns no results
- Wait 10 seconds for Neo4j to fully start
- Refresh the app (Ctrl+R in Electron)
- Check database has data: `MATCH (c:Command) RETURN count(c)`

## Build for Distribution

```bash
# Build production version
npm run build

# Output: ./release/crack-*.AppImage
```

## Project Structure

```
crack-electron/
├── src/
│   ├── main/
│   │   ├── index.ts       # Electron main process
│   │   └── neo4j.ts       # Database connection + IPC
│   ├── preload/
│   │   └── index.ts       # Secure IPC bridge
│   └── renderer/
│       └── src/
│           ├── App.tsx              # Main app
│           ├── components/
│           │   ├── CommandSearch    # Search + results
│           │   ├── CommandDetails   # Info panel
│           │   └── GraphView        # Cytoscape graph
│           └── types/
│               └── command.ts       # TypeScript types
├── package.json
├── vite.config.ts
└── README.md
```

## Next Steps (Not in MVP)

Future enhancements could include:
- Target profile tracking
- Task tree management
- Attack chain visualization
- Command execution
- Export to markdown
- Favorites/bookmarks
- Search history
- Graph filters

## Tech Stack Summary

- **Electron 28** - Desktop framework
- **React 18 + TypeScript** - UI
- **Mantine 7** - Component library (dark theme)
- **Cytoscape.js 3.28** - Graph visualization
- **Neo4j Driver 5.15** - Database connection
- **Vite 5** - Build tool

---

**Total Development Time**: ~2.5 hours ✅

Built with the CRACK philosophy: Fast, minimal, functional.
