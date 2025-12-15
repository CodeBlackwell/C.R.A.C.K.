# Crackpedia - CRACK Command Encyclopedia

Electron-based GUI for visualizing and exploring the CRACK penetration testing toolkit's Neo4j command database.

## Features

- **Command Search**: Full-text search across 734 pentesting commands
- **Graph Visualization**: Interactive relationship graph showing:
  - Alternative commands (when tools fail)
  - Prerequisites (required setup)
  - Next steps (workflow progression)
- **Detailed View**: Complete command information including:
  - Flags and their explanations
  - Variables and placeholders
  - Output indicators (success/failure patterns)
  - OSCP relevance tags

## Tech Stack

- **Electron** - Desktop application framework
- **React + TypeScript** - UI components
- **Mantine** - UI component library (dark theme)
- **Cytoscape.js** - Graph visualization
- **Neo4j Driver** - Direct database connection

## Prerequisites

1. **Neo4j** must be running:
   ```bash
   # Start Neo4j
   sudo systemctl start neo4j

   # Or via Docker
   docker run -p 7687:7687 -p 7474:7474 neo4j
   ```

2. **CRACK database** must be populated with commands

## Quick Start

```bash
# Launch Crackpedia (ensures Neo4j is running)
crackpedia

# Or run directly
cd /path/to/crack/crackpedia
./start.sh
```

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev
```

## Environment Variables

```bash
# Optional: Override default Neo4j connection
export NEO4J_URI=bolt://127.0.0.1:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=Neo4j123
```

## Build

```bash
# Build for production
npm run build

# Output will be in ./release/ directory
```

## Usage

1. Launch the application
2. Search for commands using the search bar
3. Click a command to view details
4. The graph shows related commands:
   - **Yellow edges** = Alternative commands
   - **Red edges** = Prerequisites
   - **Green edges** = Next steps
5. Click nodes in the graph to navigate between commands

## Project Structure

```
crackpedia/
├── src/
│   ├── main/              # Electron main process
│   │   ├── index.ts       # App entry
│   │   └── neo4j.ts       # Neo4j IPC handlers
│   ├── preload/           # IPC bridge
│   │   └── index.ts
│   └── renderer/          # React UI
│       ├── src/
│       │   ├── App.tsx
│       │   ├── main.tsx
│       │   ├── components/
│       │   │   ├── CommandSearch.tsx
│       │   │   ├── CommandDetails.tsx
│       │   │   └── GraphView.tsx
│       │   └── types/
│       │       └── command.ts
└── package.json
```

## License

Part of the CRACK penetration testing toolkit.
