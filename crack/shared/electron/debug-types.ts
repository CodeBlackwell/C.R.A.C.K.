/**
 * Debug Logging Type Definitions
 *
 * Shared types for the comprehensive logging system used by both
 * main process (Node.js) and renderer process (browser).
 */

/**
 * Log Levels - severity from highest to lowest priority
 * Filter logs by setting minimum level (e.g., DEBUG shows DEBUG, INFO, WARN, ERROR)
 */
export enum LogLevel {
  ERROR = 0,   // Critical failures - always shown
  WARN = 1,    // Recoverable issues, potential problems
  INFO = 2,    // General operational info (default level)
  DEBUG = 3,   // Detailed debugging information
  TRACE = 4,   // Very verbose, function-level tracing
}

/**
 * Log Categories - functional areas of the application
 * Filter logs by enabling specific categories
 */
export enum LogCategory {
  // === Main Process Categories ===
  STARTUP = 'STARTUP',         // App initialization, window creation
  NEO4J = 'NEO4J',             // Database connections, pool status
  QUERY = 'QUERY',             // Neo4j query execution details
  IPC = 'IPC',                 // IPC handler invocations
  PTY = 'PTY',                 // Terminal PTY I/O, spawn/kill
  SESSION = 'SESSION',         // Session lifecycle, linking
  ELECTRON = 'ELECTRON',       // Electron framework events
  PERFORMANCE = 'PERFORMANCE', // Timing measurements

  // === Renderer Process Categories ===
  UI = 'UI',                   // Panel state, tab switches, collapse
  ACTION = 'ACTION',           // User-initiated actions
  DATA = 'DATA',               // Async data fetching
  VALIDATION = 'VALIDATION',   // Input validation results
  LIFECYCLE = 'LIFECYCLE',     // Component mount/unmount
  RENDER = 'RENDER',           // Re-render triggers (verbose)
  FOCUS = 'FOCUS',             // Focus/blur events
  CLIPBOARD = 'CLIPBOARD',     // Copy/paste operations

  // === Shared Categories (Both Processes) ===
  ERROR = 'ERROR',             // All error logging
}

/**
 * Log level names for display and parsing
 */
export const LOG_LEVEL_NAMES: Record<LogLevel, string> = {
  [LogLevel.ERROR]: 'ERROR',
  [LogLevel.WARN]: 'WARN',
  [LogLevel.INFO]: 'INFO',
  [LogLevel.DEBUG]: 'DEBUG',
  [LogLevel.TRACE]: 'TRACE',
};

/**
 * Parse log level from string (case-insensitive)
 */
export function parseLogLevel(str: string): LogLevel {
  const upper = str.toUpperCase();
  switch (upper) {
    case 'ERROR': return LogLevel.ERROR;
    case 'WARN': return LogLevel.WARN;
    case 'INFO': return LogLevel.INFO;
    case 'DEBUG': return LogLevel.DEBUG;
    case 'TRACE': return LogLevel.TRACE;
    default: return LogLevel.INFO;
  }
}

/**
 * Structured log entry
 */
export interface LogEntry {
  timestamp: string;           // ISO 8601 format
  elapsed: number;             // Milliseconds since logger start
  level: LogLevel;
  category: LogCategory | string;
  message: string;
  data?: unknown;
  correlationId?: string;      // For tracing IPC calls across processes
  source: 'main' | 'renderer';
}

/**
 * Logger configuration
 */
export interface LoggerConfig {
  enabled: boolean;
  minLevel: LogLevel;
  categories: Set<string>;
  correlationEnabled: boolean;
  appName: string;
}

/**
 * Renderer-specific logger configuration (stored in localStorage)
 */
export interface RendererLoggerConfig {
  enabled: boolean;
  level: LogLevel;
  categories: string[];
  bridgeToMain: boolean;
}

/**
 * Performance measurement result
 */
export interface MeasureResult<T> {
  result: T;
  duration: number;
  correlationId?: string;
}

/**
 * All category names for iteration
 */
export const ALL_CATEGORIES = Object.values(LogCategory);

/**
 * Main process categories only
 */
export const MAIN_CATEGORIES: LogCategory[] = [
  LogCategory.STARTUP,
  LogCategory.NEO4J,
  LogCategory.QUERY,
  LogCategory.IPC,
  LogCategory.PTY,
  LogCategory.SESSION,
  LogCategory.ELECTRON,
  LogCategory.PERFORMANCE,
  LogCategory.ERROR,
];

/**
 * Renderer process categories only
 */
export const RENDERER_CATEGORIES: LogCategory[] = [
  LogCategory.UI,
  LogCategory.ACTION,
  LogCategory.DATA,
  LogCategory.VALIDATION,
  LogCategory.LIFECYCLE,
  LogCategory.RENDER,
  LogCategory.FOCUS,
  LogCategory.CLIPBOARD,
  LogCategory.IPC,
  LogCategory.PERFORMANCE,
  LogCategory.ERROR,
];
