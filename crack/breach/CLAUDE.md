# B.R.E.A.C.H. - Box Reconnaissance, Exploitation & Attack Command Hub

## Overview

Electron-based pentesting workspace for OSCP preparation. Combines terminal multiplexing with Neo4j-backed engagement tracking.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           RENDERER (React)                          │
├─────────────┬───────────────────────────────────┬───────────────────┤
│ TargetSidebar│         TerminalTabs             │   ContextPanel    │
│             │    ┌─────────────────────┐        │  ┌─────────────┐  │
│  Targets    │    │   xterm.js PTY      │        │  │ Credentials │  │
│  by status  │    │   sessions          │        │  │ Loot        │  │
│             │    └─────────────────────┘        │  └─────────────┘  │
├─────────────┴───────────────────────────────────┴───────────────────┤
│                      EngagementSelector (Header)                    │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                          contextBridge (IPC)
                                  │
┌─────────────────────────────────────────────────────────────────────┐
│                            MAIN (Electron)                          │
├─────────────────────────────────────────────────────────────────────┤
│  IPC Handlers          │  PTY Manager        │  Neo4j Connection    │
│  - engagements.ts      │  - node-pty         │  - bolt://localhost  │
│  - credentials.ts      │  - session mgmt     │  - query.ts          │
│  - loot.ts             │  - output buffer    │                      │
│  - targets.ts          │                     │                      │
│  - sessions.ts         │                     │                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Model

```
(:Engagement)─[:TARGETS]→(:Target)─[:HAS_SERVICE]→(:Service)
      │
      ├─[:HAS_CREDENTIAL]→(:Credential)─[:GRANTS_ACCESS]→(:Service)
      │
      └─[:HAS_LOOT]→(:Loot)
```

**Simplified model**: No Client/organization layer. Each Engagement is a standalone workspace (OSCP lab, HTB box, etc.).

## Directory Structure

```
breach/
├── src/
│   ├── main/                    # Electron main process
│   │   ├── index.ts             # App entry, window creation
│   │   ├── ipc/                  # IPC handlers
│   │   │   ├── engagements.ts   # Engagement CRUD
│   │   │   ├── credentials.ts   # Credential management
│   │   │   ├── loot.ts          # File/loot tracking
│   │   │   ├── targets.ts       # Target management
│   │   │   ├── sessions.ts      # Terminal session IPC
│   │   │   └── neo4j.ts         # Health check, connection
│   │   └── pty/
│   │       └── manager.ts       # PTY session manager
│   │
│   ├── preload/
│   │   └── index.ts             # Context bridge (electronAPI)
│   │
│   └── renderer/src/
│       ├── App.tsx              # Main layout
│       ├── components/
│       │   ├── header/          # EngagementSelector
│       │   ├── layout/          # TargetSidebar, SessionDock
│       │   ├── terminal/        # TerminalTabs, TerminalPane
│       │   ├── context/         # ContextPanel, CredentialVault, LootPanel
│       │   ├── modals/          # EngagementManager
│       │   ├── topology/        # (planned) Session graph
│       │   └── findings/        # (planned) Finding tracker
│       ├── hooks/               # Custom React hooks
│       ├── stores/              # Zustand state management
│       └── types/               # Renderer-specific types
│
├── package.json
├── vite.config.ts
├── tsconfig.json
└── start.sh                     # Dev launcher with Neo4j check
```

## Shared Types (../shared/types/)

| File | Purpose |
|------|---------|
| `engagement.ts` | Engagement, EngagementStatus, EngagementStats |
| `credential.ts` | Credential with access tracking, validation |
| `loot.ts` | Loot with pattern detection (flags, SSH keys, configs) |
| `session.ts` | TerminalSession, CreateSessionOptions |
| `graph.ts` | Cytoscape graph types for topology view |

## Key Components

### EngagementSelector
Header dropdown for switching workspaces. Shows flat list of engagements with status badges.

### EngagementManager
Modal for CRUD operations: create, edit, archive, delete engagements.

### ContextPanel
Collapsible right panel with tabs:
- **Credentials**: Discovered creds with "Use" action (spawn session)
- **Loot**: Tracked files with pattern detection

### TerminalTabs
xterm.js-based terminal multiplexer with:
- Multiple PTY sessions
- Output buffering for background tasks
- Session linking (parent/child relationships)

### TargetSidebar
Left panel showing engagement targets grouped by status (active, compromised, etc.).

## IPC API

All IPC calls go through `window.electronAPI`:

```typescript
// Engagements
electronAPI.engagementList()
electronAPI.engagementCreate(data)
electronAPI.engagementActivate(id)
electronAPI.engagementDelete(id)

// Credentials
electronAPI.credentialList(engagementId)
electronAPI.credentialAdd(credential)
electronAPI.credentialValidateAccess(credId, serviceId, accessType)

// Loot
electronAPI.lootList(engagementId)
electronAPI.lootAdd(lootData)
electronAPI.lootByPattern(engagementId, pattern)  // 'flag', 'ssh_key', etc.

// Sessions
electronAPI.sessionCreate(command, args, options)
electronAPI.sessionWrite(sessionId, data)
electronAPI.sessionKill(sessionId)
```

## Development

```bash
# Start (checks Neo4j, rebuilds node-pty if needed)
./start.sh

# Or manually
npm run dev           # Normal mode
npm run dev:debug     # With debug logging
npm run dev:verbose   # All debug categories

# Build
npm run build
npm run electron:build
```

## Requirements

- Node.js 18+
- Neo4j 5.x running on bolt://localhost:7687
- node-pty native module (auto-rebuilt by start.sh)

## Environment

```bash
export NEO4J_URI='bolt://localhost:7687'
export NEO4J_USER='neo4j'
export NEO4J_PASSWORD='your_password'
```

## Planned Features

1. **Topology View**: Cytoscape graph showing session relationships
2. **Finding Tracker**: Vulnerability/finding management with severity
3. **PRISM Integration**: Auto-parse credentials from terminal output
4. **Attack Timeline**: Reconstruct attack sequence from session history
5. **Report Export**: Generate markdown/PDF engagement reports

## Design Principles

- **Engagement-centric**: All data scoped to active engagement
- **Terminal-first**: PTY sessions are primary interaction
- **Neo4j-backed**: Graph database for relationship queries
- **Minimal UI**: Focus on terminal, context panels collapse
