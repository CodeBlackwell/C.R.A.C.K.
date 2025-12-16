/**
 * Shared Debug Logging System for CRACK Electron Applications
 *
 * Provides categorized logging with timestamps, color coding, and log levels.
 * Extensible for different applications (crackpedia, B.R.E.A.C.H., etc.)
 *
 * Usage:
 *   import { createDebugLogger, DebugCategory, LogLevel } from '@crack/shared/electron/debug';
 *   const debug = createDebugLogger({ appName: 'breach' });
 *
 * Environment Variables:
 *   DEBUG=true                    Enable debug logging
 *   DEBUG_LEVEL=DEBUG             Minimum log level (ERROR, WARN, INFO, DEBUG, TRACE)
 *   DEBUG_CATEGORIES=IPC,ERROR    Comma-separated categories to show
 */

import {
  LogLevel,
  LogCategory,
  LogEntry,
  parseLogLevel,
  LOG_LEVEL_NAMES,
  ALL_CATEGORIES,
} from './debug-types';

// Re-export types for convenience
export { LogLevel, LogCategory } from './debug-types';
export type { LogEntry } from './debug-types';

/** Legacy category enum - use LogCategory instead */
export enum DebugCategory {
  NEO4J = 'NEO4J',
  IPC = 'IPC',
  ELECTRON = 'ELECTRON',
  QUERY = 'QUERY',
  ERROR = 'ERROR',
  STARTUP = 'STARTUP',
  PERFORMANCE = 'PERFORMANCE',
  PTY = 'PTY',
  SESSION = 'SESSION',
  PRISM = 'PRISM',
}

/** Color codes for terminal output by category */
const CATEGORY_COLORS: Record<string, string> = {
  // Main process categories
  NEO4J: '\x1b[36m',       // Cyan
  IPC: '\x1b[35m',         // Magenta
  ELECTRON: '\x1b[34m',    // Blue
  QUERY: '\x1b[33m',       // Yellow
  ERROR: '\x1b[31m',       // Red
  STARTUP: '\x1b[32m',     // Green
  PERFORMANCE: '\x1b[90m', // Gray
  PTY: '\x1b[95m',         // Light Magenta
  SESSION: '\x1b[96m',     // Light Cyan
  PRISM: '\x1b[38;5;208m', // Orange (256-color)
  // Renderer categories (for bridged logs)
  UI: '\x1b[34m',          // Blue
  ACTION: '\x1b[91m',      // Light Red
  DATA: '\x1b[92m',        // Light Green
  VALIDATION: '\x1b[93m',  // Light Yellow
  LIFECYCLE: '\x1b[94m',   // Light Blue
  RENDER: '\x1b[90m',      // Gray
  FOCUS: '\x1b[37m',       // White
  CLIPBOARD: '\x1b[97m',   // Bright White
};

/** Color codes for log levels */
const LEVEL_COLORS: Record<LogLevel, string> = {
  [LogLevel.ERROR]: '\x1b[31m',   // Red
  [LogLevel.WARN]: '\x1b[33m',    // Yellow
  [LogLevel.INFO]: '\x1b[32m',    // Green
  [LogLevel.DEBUG]: '\x1b[36m',   // Cyan
  [LogLevel.TRACE]: '\x1b[90m',   // Gray
};

/** Emoji icons for categories */
const CATEGORY_EMOJIS: Record<string, string> = {
  // Main process
  NEO4J: '🔷',
  IPC: '📡',
  ELECTRON: '⚡',
  QUERY: '🔍',
  ERROR: '❌',
  STARTUP: '🚀',
  PERFORMANCE: '⏱️',
  PTY: '💻',
  SESSION: '🔗',
  PRISM: '🔬',
  // Renderer
  UI: '🖥️',
  ACTION: '🎯',
  DATA: '📦',
  VALIDATION: '✅',
  LIFECYCLE: '🔄',
  RENDER: '🎨',
  FOCUS: '👁️',
  CLIPBOARD: '📋',
};

/** Level emojis */
const LEVEL_EMOJIS: Record<LogLevel, string> = {
  [LogLevel.ERROR]: '❌',
  [LogLevel.WARN]: '⚠️',
  [LogLevel.INFO]: '📌',
  [LogLevel.DEBUG]: '🔧',
  [LogLevel.TRACE]: '🔬',
};

interface DebugLoggerOptions {
  appName?: string;
  enabledByDefault?: boolean;
  defaultLevel?: LogLevel;
}

export class DebugLogger {
  private enabled: boolean;
  private categories: Set<string>;
  private startTime: number;
  private appName: string;
  private minLevel: LogLevel;
  private logBuffer: LogEntry[] = [];
  private maxBufferSize = 1000;
  private correlationEnabled = true;

  constructor(options: DebugLoggerOptions = {}) {
    this.appName = options.appName || 'crack';

    // Enable debug if DEBUG env var is set
    const debugEnv = process.env.DEBUG || '';
    this.enabled = options.enabledByDefault ??
      (debugEnv.toLowerCase() === 'true' || debugEnv === '1' || debugEnv === '*');

    // Parse log level from DEBUG_LEVEL (default: INFO)
    const levelEnv = process.env.DEBUG_LEVEL || '';
    this.minLevel = options.defaultLevel ?? (levelEnv ? parseLogLevel(levelEnv) : LogLevel.INFO);

    // Parse categories from DEBUG_CATEGORIES (comma-separated)
    const categoriesEnv = process.env.DEBUG_CATEGORIES || '';
    if (categoriesEnv === '*' || !categoriesEnv) {
      this.categories = new Set([...Object.values(DebugCategory), ...ALL_CATEGORIES]);
    } else {
      this.categories = new Set(
        categoriesEnv.split(',').map(c => c.trim().toUpperCase())
      );
    }

    this.startTime = Date.now();

    if (this.enabled) {
      console.log(`\n🔧 [${this.appName.toUpperCase()}] DEBUG MODE ENABLED`);
      console.log('📋 Categories:', Array.from(this.categories).join(', '));
      console.log('📊 Min Level:', LOG_LEVEL_NAMES[this.minLevel]);
      console.log('⏱️  Start time:', new Date().toISOString());
      console.log('━'.repeat(80) + '\n');
    }
  }

  /** Enable/disable debug logging at runtime */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  /** Check if debug is enabled */
  isEnabled(): boolean {
    return this.enabled;
  }

  /** Set minimum log level */
  setLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  /** Get current minimum log level */
  getLevel(): LogLevel {
    return this.minLevel;
  }

  /** Enable specific categories */
  enableCategories(...categories: string[]): void {
    categories.forEach(c => this.categories.add(c.toUpperCase()));
  }

  /** Disable specific categories */
  disableCategories(...categories: string[]): void {
    categories.forEach(c => this.categories.delete(c.toUpperCase()));
  }

  /** Generate a unique correlation ID */
  generateCorrelationId(): string {
    return `m-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  }

  /** Get elapsed time since logger creation */
  private getElapsedTime(): string {
    const elapsed = Date.now() - this.startTime;
    const seconds = Math.floor(elapsed / 1000);
    const ms = elapsed % 1000;
    return `+${seconds}.${ms.toString().padStart(3, '0')}s`;
  }

  /** Get color code for category */
  private getCategoryColor(category: string): string {
    return CATEGORY_COLORS[category.toUpperCase()] || '\x1b[37m';
  }

  /** Get emoji for category */
  private getCategoryEmoji(category: string): string {
    return CATEGORY_EMOJIS[category.toUpperCase()] || '📌';
  }

  /** Buffer a log entry for crash dumps */
  private bufferEntry(entry: LogEntry): void {
    this.logBuffer.push(entry);
    if (this.logBuffer.length > this.maxBufferSize) {
      this.logBuffer.shift();
    }
  }

  /** Main logging function with level support */
  logWithLevel(
    level: LogLevel,
    category: string,
    message: string,
    data?: unknown,
    correlationId?: string
  ): void {
    const upperCategory = category.toUpperCase();

    // Check enabled, level, and category filters
    if (!this.enabled) return;
    if (level > this.minLevel) return;
    if (!this.categories.has(upperCategory)) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      elapsed: Date.now() - this.startTime,
      level,
      category: upperCategory,
      message,
      data,
      correlationId,
      source: 'main',
    };

    // Buffer for crash dumps
    this.bufferEntry(entry);

    // Output to console
    this.outputEntry(entry);
  }

  /** Output a log entry to console */
  private outputEntry(entry: LogEntry): void {
    const levelColor = LEVEL_COLORS[entry.level];
    const categoryColor = this.getCategoryColor(entry.category);
    const emoji = this.getCategoryEmoji(entry.category);
    const reset = '\x1b[0m';
    const timestamp = entry.timestamp.split('T')[1].slice(0, 12);
    const elapsed = `+${(entry.elapsed / 1000).toFixed(3)}s`;
    const levelName = LOG_LEVEL_NAMES[entry.level].padEnd(5);

    const prefix = `${levelColor}${levelName}${reset} ${categoryColor}${emoji} [${entry.category.padEnd(11)}]${reset} ${timestamp} ${elapsed}`;

    if (entry.correlationId) {
      console.log(`${prefix} ${entry.message} [${entry.correlationId}]`);
    } else {
      console.log(`${prefix} ${entry.message}`);
    }

    if (entry.data !== undefined) {
      console.log(`${categoryColor}   └─${reset}`, entry.data);
    }
  }

  /** Legacy log function (backward compatible - uses INFO level) */
  log(category: string, message: string, data?: unknown): void {
    this.logWithLevel(LogLevel.INFO, category, message, data);
  }

  /** Log at ERROR level */
  logError(category: string, message: string, data?: unknown, correlationId?: string): void {
    this.logWithLevel(LogLevel.ERROR, category, message, data, correlationId);
  }

  /** Log at WARN level */
  logWarn(category: string, message: string, data?: unknown, correlationId?: string): void {
    this.logWithLevel(LogLevel.WARN, category, message, data, correlationId);
  }

  /** Log at INFO level */
  logInfo(category: string, message: string, data?: unknown, correlationId?: string): void {
    this.logWithLevel(LogLevel.INFO, category, message, data, correlationId);
  }

  /** Log at DEBUG level */
  logDebug(category: string, message: string, data?: unknown, correlationId?: string): void {
    this.logWithLevel(LogLevel.DEBUG, category, message, data, correlationId);
  }

  /** Log at TRACE level */
  logTrace(category: string, message: string, data?: unknown, correlationId?: string): void {
    this.logWithLevel(LogLevel.TRACE, category, message, data, correlationId);
  }

  /** Convenience methods for common categories */
  neo4j(message: string, data?: unknown): void {
    this.log(DebugCategory.NEO4J, message, data);
  }

  ipc(message: string, data?: unknown): void {
    this.log(DebugCategory.IPC, message, data);
  }

  electron(message: string, data?: unknown): void {
    this.log(DebugCategory.ELECTRON, message, data);
  }

  query(message: string, data?: unknown): void {
    this.log(DebugCategory.QUERY, message, data);
  }

  error(message: string, error?: unknown): void {
    this.log(DebugCategory.ERROR, message, error);
  }

  startup(message: string, data?: unknown): void {
    this.log(DebugCategory.STARTUP, message, data);
  }

  performance(message: string, data?: unknown): void {
    this.log(DebugCategory.PERFORMANCE, message, data);
  }

  pty(message: string, data?: unknown): void {
    this.log(DebugCategory.PTY, message, data);
  }

  session(message: string, data?: unknown): void {
    this.log(DebugCategory.SESSION, message, data);
  }

  prism(message: string, data?: unknown): void {
    this.log(DebugCategory.PRISM, message, data);
  }

  /** Measure execution time of async function */
  async measure<T>(
    category: string,
    label: string,
    fn: () => Promise<T>
  ): Promise<T> {
    const start = Date.now();
    this.log(category, `${label} - START`);

    try {
      const result = await fn();
      const duration = Date.now() - start;
      this.performance(`${label} - COMPLETE`, { duration_ms: duration });
      return result;
    } catch (error) {
      const duration = Date.now() - start;
      this.error(`${label} - FAILED`, { duration_ms: duration, error });
      throw error;
    }
  }

  /** Measure with correlation ID for tracing */
  async measureWithCorrelation<T>(
    category: string,
    label: string,
    fn: () => Promise<T>,
    correlationId?: string
  ): Promise<{ result: T; duration: number; correlationId: string }> {
    const cid = correlationId || this.generateCorrelationId();
    const start = Date.now();

    this.logDebug(category, `${label} - START`, undefined, cid);

    try {
      const result = await fn();
      const duration = Date.now() - start;
      this.logInfo(LogCategory.PERFORMANCE, `${label} - COMPLETE`, { duration_ms: duration }, cid);
      return { result, duration, correlationId: cid };
    } catch (error) {
      const duration = Date.now() - start;
      this.logError(category, `${label} - FAILED`, { duration_ms: duration, error }, cid);
      throw error;
    }
  }

  /** Get buffered log entries */
  getLogBuffer(): LogEntry[] {
    return [...this.logBuffer];
  }

  /** Clear the log buffer */
  clearLogBuffer(): void {
    this.logBuffer = [];
  }

  /** Dump logs to file for post-mortem debugging */
  dumpLogs(reason?: string): string {
    // This is for Node.js environments - check if fs is available
    try {
      // Dynamic import to avoid issues in renderer
      const fs = require('fs');
      const path = require('path');
      const os = require('os');

      const logDir = path.join(os.homedir(), '.breach', 'logs');
      fs.mkdirSync(logDir, { recursive: true });

      const filename = `breach-${new Date().toISOString().replace(/[:.]/g, '-')}.log`;
      const filepath = path.join(logDir, filename);

      const content = [
        `=== B.R.E.A.C.H. Log Dump ===`,
        `App: ${this.appName}`,
        `Reason: ${reason || 'Manual dump'}`,
        `Time: ${new Date().toISOString()}`,
        `Entries: ${this.logBuffer.length}`,
        `Min Level: ${LOG_LEVEL_NAMES[this.minLevel]}`,
        `Categories: ${Array.from(this.categories).join(', ')}`,
        `---`,
        ...this.logBuffer.map(e => JSON.stringify(e)),
      ].join('\n');

      fs.writeFileSync(filepath, content);
      console.log(`📁 Logs dumped to: ${filepath}`);
      return filepath;
    } catch (err) {
      console.error('Failed to dump logs:', err);
      return '';
    }
  }

  /** Create a section separator */
  section(title: string): void {
    if (!this.enabled) return;
    console.log(`\n${'═'.repeat(80)}`);
    console.log(`  ${title.toUpperCase()}`);
    console.log(`${'═'.repeat(80)}\n`);
  }

  /** Create a subsection */
  subsection(title: string): void {
    if (!this.enabled) return;
    console.log(`\n${'─'.repeat(40)}`);
    console.log(`  ${title}`);
    console.log(`${'─'.repeat(40)}`);
  }
}

/** Factory function to create app-specific logger */
export function createDebugLogger(options: DebugLoggerOptions = {}): DebugLogger {
  return new DebugLogger(options);
}

/** Default singleton for backward compatibility */
export const debug = new DebugLogger();

/** Convenience exports for quick logging */
export const logNeo4j = (msg: string, data?: unknown): void => debug.neo4j(msg, data);
export const logIPC = (msg: string, data?: unknown): void => debug.ipc(msg, data);
export const logElectron = (msg: string, data?: unknown): void => debug.electron(msg, data);
export const logQuery = (msg: string, data?: unknown): void => debug.query(msg, data);
export const logError = (msg: string, error?: unknown): void => debug.error(msg, error);
export const logStartup = (msg: string, data?: unknown): void => debug.startup(msg, data);
export const logPerformance = (msg: string, data?: unknown): void => debug.performance(msg, data);
export const logPty = (msg: string, data?: unknown): void => debug.pty(msg, data);
export const logSession = (msg: string, data?: unknown): void => debug.session(msg, data);
export const logPrism = (msg: string, data?: unknown): void => debug.prism(msg, data);
