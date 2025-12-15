/**
 * CRACK Shared Module
 *
 * Common utilities and types shared across CRACK Electron applications.
 *
 * Usage:
 *   import { debug, runQuery, TerminalSession } from '@crack/shared';
 */

// Electron utilities
export {
  DebugLogger,
  DebugCategory,
  createDebugLogger,
  debug,
  logNeo4j,
  logIPC,
  logElectron,
  logQuery,
  logError,
  logStartup,
  logPerformance,
  logPty,
  logSession,
} from './electron/debug';

// Neo4j utilities
export {
  neo4jDriver,
  createNeo4jDriver,
} from './neo4j/driver';

export type { Neo4jConfig } from './neo4j/driver';

export {
  runQuery,
  runQuerySingle,
  runQuerySafe,
  runWrite,
} from './neo4j/query';

// Graph types
export type {
  CytoscapeNode,
  CytoscapeEdge,
  GraphData,
  LayoutType,
  LayoutOrientation,
  LayoutConfig,
  NodeClickEvent,
  EdgeClickEvent,
} from './types/graph';

// Session types
export type {
  SessionType,
  SessionStatus,
  TerminalSession,
  SessionProgress,
  SessionLinkType,
  SessionLink,
  SessionTemplate,
  TemplateVariable,
  CreateSessionOptions,
  SessionFilter,
} from './types/session';
