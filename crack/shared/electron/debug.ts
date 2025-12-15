/**
 * Shared Debug Logging System for CRACK Electron Applications
 *
 * Provides categorized logging with timestamps and color coding.
 * Extensible for different applications (crackpedia, B.R.E.A.C.H., etc.)
 *
 * Usage:
 *   import { createDebugLogger, DebugCategory } from '@crack/shared/electron/debug';
 *   const debug = createDebugLogger({ appName: 'breach' });
 */

/** Base debug categories - extend in consuming applications */
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
}

/** Color codes for terminal output */
const CATEGORY_COLORS: Record<string, string> = {
  NEO4J: '\x1b[36m',       // Cyan
  IPC: '\x1b[35m',         // Magenta
  ELECTRON: '\x1b[34m',    // Blue
  QUERY: '\x1b[33m',       // Yellow
  ERROR: '\x1b[31m',       // Red
  STARTUP: '\x1b[32m',     // Green
  PERFORMANCE: '\x1b[90m', // Gray
  PTY: '\x1b[95m',         // Light Magenta
  SESSION: '\x1b[96m',     // Light Cyan
};

/** Emoji icons for categories */
const CATEGORY_EMOJIS: Record<string, string> = {
  NEO4J: '🔷',
  IPC: '📡',
  ELECTRON: '⚡',
  QUERY: '🔍',
  ERROR: '❌',
  STARTUP: '🚀',
  PERFORMANCE: '⏱️',
  PTY: '💻',
  SESSION: '🔗',
};

interface DebugLoggerOptions {
  appName?: string;
  enabledByDefault?: boolean;
}

export class DebugLogger {
  private enabled: boolean;
  private categories: Set<string>;
  private startTime: number;
  private appName: string;

  constructor(options: DebugLoggerOptions = {}) {
    this.appName = options.appName || 'crack';

    // Enable debug if DEBUG env var is set
    const debugEnv = process.env.DEBUG || '';
    this.enabled = options.enabledByDefault ??
      (debugEnv.toLowerCase() === 'true' || debugEnv === '1' || debugEnv === '*');

    // Parse categories from DEBUG_CATEGORIES (comma-separated)
    const categoriesEnv = process.env.DEBUG_CATEGORIES || '';
    if (categoriesEnv === '*' || !categoriesEnv) {
      this.categories = new Set(Object.values(DebugCategory));
    } else {
      this.categories = new Set(
        categoriesEnv.split(',').map(c => c.trim().toUpperCase())
      );
    }

    this.startTime = Date.now();

    if (this.enabled) {
      console.log(`\n🔧 [${this.appName.toUpperCase()}] DEBUG MODE ENABLED`);
      console.log('📋 Categories:', Array.from(this.categories).join(', '));
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

  /** Enable specific categories */
  enableCategories(...categories: string[]): void {
    categories.forEach(c => this.categories.add(c.toUpperCase()));
  }

  /** Disable specific categories */
  disableCategories(...categories: string[]): void {
    categories.forEach(c => this.categories.delete(c.toUpperCase()));
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

  /** Main logging function */
  log(category: string, message: string, data?: unknown): void {
    const upperCategory = category.toUpperCase();
    if (!this.enabled || !this.categories.has(upperCategory)) {
      return;
    }

    const color = this.getCategoryColor(upperCategory);
    const emoji = this.getCategoryEmoji(upperCategory);
    const reset = '\x1b[0m';
    const timestamp = new Date().toISOString().split('T')[1].slice(0, 12);
    const elapsed = this.getElapsedTime();

    const prefix = `${color}${emoji} [${upperCategory.padEnd(11)}]${reset} ${timestamp} ${elapsed}`;

    if (data === undefined) {
      console.log(`${prefix} ${message}`);
    } else {
      console.log(`${prefix} ${message}`);
      console.log(`${color}   └─${reset}`, data);
    }
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
