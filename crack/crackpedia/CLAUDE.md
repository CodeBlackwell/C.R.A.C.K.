# CLAUDE.md - Crackpedia Development Guide

## Project Overview
Desktop application for visualizing CRACK command database using Electron + React + Neo4j.

**Stack:** Electron 28, React 18, TypeScript, Neo4j Driver, Cytoscape.js, Mantine UI

## Architecture

### Three-Process Model
1. **Main Process** (`src/main/`) - Node.js, Neo4j connection, IPC handlers
2. **Preload Script** (`src/preload/`) - Secure IPC bridge
3. **Renderer Process** (`src/renderer/`) - React UI, browser context

### Data Flow
```
User Action → Renderer → IPC → Main → Neo4j → Main → IPC → Renderer → UI Update
```

### Key Design Patterns
- **Centralized Query Handler** - All Neo4j queries flow through `runQuery()` in `src/main/neo4j.ts`
- **IPC Handlers** - All database operations exposed via `ipcMain.handle()`
- **Type Safety** - TypeScript interfaces for Command, GraphData, SearchFilters
- **Debug Logging** - Structured logging system in `src/main/debug.ts`

## File Structure
```
crackpedia/
├── src/
│   ├── main/
│   │   ├── index.ts          # Electron main process, window management
│   │   ├── neo4j.ts           # Database connection, IPC handlers
│   │   └── debug.ts           # Logging system
│   ├── preload/
│   │   └── index.ts           # Secure API bridge (contextBridge)
│   └── renderer/
│       └── src/
│           ├── App.tsx        # Main layout (3-column)
│           ├── components/
│           │   ├── CommandSearch.tsx   # Search + keyboard nav
│           │   ├── GraphView.tsx       # Cytoscape visualization
│           │   └── CommandDetails.tsx  # Command info display
│           ├── types/         # TypeScript interfaces
│           └── utils/         # Console bridge, helpers
├── package.json
├── tsconfig.json
├── vite.config.ts
└── start.sh                   # Development launch script
```

## Development Workflow

### Start Dev Server
```bash
cd /home/kali/Desktop/KaliBackup/OSCP/crack/crackpedia
npm run dev

# Or use the launcher
crackpedia
```

### Debug Process
1. **Check logs** - All processes log to terminal with prefixes: `[MAIN]`, `[RENDERER]`, `[NEO4J]`, `[IPC]`
2. **Enable debug mode** - `DEBUG=true npm run dev` for verbose logging
3. **Check Neo4j** - Connection status shown in app header badge
4. **Inspect renderer** - Chromium DevTools available in Electron window

### Common Issues
- **"Service no longer running"** - HMR crash, restart dev server
- **Neo4j connection fails** - Check `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` in `src/main/neo4j.ts`
- **IPC handler not found** - Verify handler registered in `neo4j.ts` and exposed in `preload/index.ts`

## UI Layout (3-Column)
```
┌─────────────┬──────────────────────┬─────────────────┐
│   Search    │        Graph         │    Details      │
│   (350px)   │      (flexible)      │    (450px)      │
│             │                      │                 │
│ • List      │ • Cytoscape canvas   │ • Command info  │
│ • Filter    │ • Relationships      │ • Flags         │
│ • Keyboard  │ • Node interactions  │ • Variables     │
│   nav ↑↓    │ • Legend             │ • Indicators    │
└─────────────┴──────────────────────┴─────────────────┘
```

## Key Features

### Keyboard Navigation
- **Arrow Up/Down** - Navigate command list
- **Auto-load** - Selected command details + graph load automatically
- **Auto-scroll** - Selected row stays visible

### Graph Visualization
- **Node Types:** Center (selected) = cyan, Related = gray
- **Edge Types:** Alternative = yellow, Prerequisite = red, Next Step = green
- **Interactions:** Click nodes to load new command
- **Layout:** Auto-layout with cose-bilkent algorithm

## Code Style

### React Components
- Functional components with hooks
- TypeScript for all props
- Debug logging with component name prefix: `console.log('[ComponentName] message', data)`
- useEffect for side effects, properly cleanup event listeners

### IPC Handlers
- Always use `ipcMain.handle()` for async operations
- Return empty arrays/objects on error (never throw to renderer)
- Log all operations: `logIPC('handler-name called', params)`

### Database Queries
- Use `runQuery<T>()` helper for all Cypher queries
- Parameterized queries (never string concatenation)
- Return plain objects (IDs preserved from database properties)

### Error Handling
- Try-catch in all async operations
- Log errors with context: `logError('operation failed', error)`
- Graceful degradation (show empty state, not crash)

## Neo4j Query Patterns

### Search Commands
```cypher
MATCH (c:Command)
WHERE toLower(c.name) CONTAINS toLower($searchQuery)
RETURN c.id, c.name, c.category, c.description, c.tags, c.oscp_relevance
ORDER BY c.name LIMIT 100
```

### Get Command Details
```cypher
MATCH (c:Command {id: $commandId})
OPTIONAL MATCH (c)-[:HAS_FLAG]->(f:Flag)
OPTIONAL MATCH (c)-[:USES_VARIABLE]->(v:Variable)
RETURN c, collect(f), collect(v)
```

### Get Relationship Graph
```cypher
MATCH (c:Command {id: $commandId})
OPTIONAL MATCH (c)-[r:ALTERNATIVE|PREREQUISITE|NEXT_STEP]->(related:Command)
RETURN c, collect({type: type(r), command: related})
```

## Adding New Features

### New IPC Handler
1. Add handler in `src/main/neo4j.ts`: `ipcMain.handle('handler-name', async (_, params) => {...})`
2. Expose in `src/preload/index.ts`: `handlerName: (params) => ipcRenderer.invoke('handler-name', params)`
3. Add type in TypeScript: `window.electronAPI.handlerName()`
4. Call from React: `await window.electronAPI.handlerName(params)`

### New React Component
1. Create in `src/renderer/src/components/`
2. Add TypeScript props interface
3. Import and use in `App.tsx` or other components
4. Add debug logging for key interactions

### New Neo4j Query
1. Use centralized `runQuery()` helper
2. Parameterize all inputs
3. Handle Neo4j types (node properties, integers)
4. Return plain JavaScript objects

## Testing Checklist
- [ ] Neo4j connection established (header badge = Connected)
- [ ] Search returns results
- [ ] Keyboard navigation (↑↓) works
- [ ] Command details load on selection
- [ ] Graph visualization renders relationships
- [ ] Node clicks update selected command
- [ ] Console logs show data flow
- [ ] No errors in terminal or DevTools

## Environment Variables
```bash
# Default values (override in src/main/neo4j.ts or system env)
NEO4J_URI=bolt://127.0.0.1:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=Neo4j123
```

## Building for Production
```bash
npm run build        # Build renderer + main
npm run preview      # Test production build
# Package with electron-builder (add to package.json scripts)
```

## Git Workflow
- Commit message format: `feat:` / `fix:` / `refactor:` prefix
- Small, focused commits
- Test before committing
- Include Claude co-author footer

## Performance Considerations
- Neo4j connection pool: 50 connections, 2s timeout
- Query limit: 100 results for searches
- Graph layout: Debounced on command changes
- HMR: Fast refresh for React components

## Security Notes
- Preload script uses `contextBridge` (no node integration in renderer)
- Database credentials in main process only
- IPC handlers validate inputs
- No eval() or dynamic code execution

## Documentation
- `README.md` - User guide, setup instructions
- `QUICKSTART.md` - Fast setup for developers
- `DEBUG.md` - Troubleshooting common issues
- `CLAUDE.md` - This file (development guide)

---

**Philosophy:** Clean architecture, type safety, centralized data flow, comprehensive logging, graceful error handling.
