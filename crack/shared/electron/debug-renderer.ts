/**
 * B.R.E.A.C.H. Renderer Debug Logger
 *
 * Browser-compatible logging with CSS styling for DevTools console.
 * Supports localStorage configuration for runtime debugging.
 *
 * Usage:
 *   import { log, LogCategory } from '@shared/electron/debug-renderer';
 *   log.ui('Panel collapsed', { panel: 'context' });
 *   log.action('Credential used', { credentialId });
 *
 * Configuration (DevTools console):
 *   localStorage.setItem('breach_debug', JSON.stringify({
 *     enabled: true,
 *     level: 3,  // DEBUG
 *     categories: ['IPC', 'UI', 'ACTION']
 *   }));
 */

import {
  LogLevel,
  LogCategory,
  LogEntry,
  RendererLoggerConfig,
  LOG_LEVEL_NAMES,
  RENDERER_CATEGORIES,
} from './debug-types';

// Re-export for convenience
export { LogLevel, LogCategory } from './debug-types';

// Declare globals that Vite will inject at build time
declare global {
  const __DEBUG__: boolean | undefined;
  const __DEBUG_CATEGORIES__: string | undefined;
  const __DEBUG_LEVEL__: string | undefined;
}

/** CSS styles for log levels */
const LEVEL_STYLES: Record<LogLevel, string> = {
  [LogLevel.ERROR]: 'color: #ff6b6b; font-weight: bold;',
  [LogLevel.WARN]: 'color: #ffd93d; font-weight: bold;',
  [LogLevel.INFO]: 'color: #69db7c;',
  [LogLevel.DEBUG]: 'color: #748ffc;',
  [LogLevel.TRACE]: 'color: #868e96;',
};

/** CSS styles for category badges */
const CATEGORY_STYLES: Record<string, string> = {
  // Renderer categories
  UI: 'background: #228be6; color: white; padding: 1px 4px; border-radius: 2px;',
  ACTION: 'background: #fa5252; color: white; padding: 1px 4px; border-radius: 2px;',
  DATA: 'background: #40c057; color: white; padding: 1px 4px; border-radius: 2px;',
  VALIDATION: 'background: #fab005; color: black; padding: 1px 4px; border-radius: 2px;',
  LIFECYCLE: 'background: #7950f2; color: white; padding: 1px 4px; border-radius: 2px;',
  RENDER: 'background: #495057; color: white; padding: 1px 4px; border-radius: 2px;',
  FOCUS: 'background: #20c997; color: white; padding: 1px 4px; border-radius: 2px;',
  CLIPBOARD: 'background: #15aabf; color: white; padding: 1px 4px; border-radius: 2px;',
  TERMINAL_IO: 'background: #f06595; color: white; padding: 1px 4px; border-radius: 2px; font-weight: bold;',
  // Shared categories
  IPC: 'background: #be4bdb; color: white; padding: 1px 4px; border-radius: 2px;',
  ERROR: 'background: #ff6b6b; color: white; padding: 1px 4px; border-radius: 2px;',
  PERFORMANCE: 'background: #868e96; color: white; padding: 1px 4px; border-radius: 2px;',
};

const STORAGE_KEY = 'breach_debug';

/**
 * Renderer Debug Logger
 *
 * Browser-compatible logger with CSS styling and localStorage persistence.
 */
export class RendererLogger {
  private enabled: boolean;
  private minLevel: LogLevel;
  private categories: Set<string>;
  private startTime: number;
  private bridgeToMain: boolean;

  constructor() {
    this.startTime = Date.now();

    // Check for build-time flags (injected by Vite)
    const buildEnabled = typeof __DEBUG__ !== 'undefined' ? __DEBUG__ : false;
    const buildCategories = typeof __DEBUG_CATEGORIES__ !== 'undefined' ? __DEBUG_CATEGORIES__ : '*';
    const buildLevel = typeof __DEBUG_LEVEL__ !== 'undefined' ? __DEBUG_LEVEL__ : 'INFO';

    // Allow runtime override via localStorage
    const storageConfig = this.loadStorageConfig();

    this.enabled = storageConfig?.enabled ?? buildEnabled;
    this.minLevel = storageConfig?.level ?? this.parseLevel(buildLevel);
    this.bridgeToMain = storageConfig?.bridgeToMain ?? true;

    // Parse categories
    if (storageConfig?.categories && storageConfig.categories.length > 0) {
      this.categories = new Set(storageConfig.categories.map(c => c.toUpperCase()));
    } else if (buildCategories === '*') {
      this.categories = new Set(RENDERER_CATEGORIES);
    } else {
      this.categories = new Set(buildCategories.split(',').map(c => c.trim().toUpperCase()));
    }

    if (this.enabled) {
      this.logBanner();
    }
  }

  private parseLevel(str: string): LogLevel {
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

  private loadStorageConfig(): RendererLoggerConfig | null {
    try {
      if (typeof localStorage === 'undefined') return null;
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  }

  private logBanner(): void {
    console.log(
      '%c B.R.E.A.C.H. %c DEBUG MODE %c',
      'background: linear-gradient(45deg, #ff6b6b, #ffd93d); color: black; font-weight: bold; padding: 4px 8px;',
      'background: #25262b; color: #69db7c; padding: 4px 8px;',
      ''
    );
    console.log('%cCategories: %c' + Array.from(this.categories).join(', '),
      'color: #868e96;', 'color: #69db7c;');
    console.log('%cMin Level: %c' + LOG_LEVEL_NAMES[this.minLevel],
      'color: #868e96;', 'color: #748ffc;');
    console.log('%cBridge to Main: %c' + (this.bridgeToMain ? 'Yes' : 'No'),
      'color: #868e96;', 'color: #ffd93d;');
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
      source: 'renderer',
    };

    this.outputToConsole(entry);

    // Bridge errors and warnings to main process
    if (this.bridgeToMain && level <= LogLevel.WARN) {
      this.bridgeEntry(entry);
    }
  }

  private outputToConsole(entry: LogEntry): void {
    const levelStyle = LEVEL_STYLES[entry.level];
    const categoryStyle = CATEGORY_STYLES[entry.category] || 'background: #868e96; color: white; padding: 1px 4px; border-radius: 2px;';
    const levelName = LOG_LEVEL_NAMES[entry.level].padEnd(5);
    const elapsed = `+${(entry.elapsed / 1000).toFixed(3)}s`;

    // Build format string and styles array
    const format = `%c${levelName}%c %c${entry.category}%c ${elapsed} ${entry.message}`;
    const styles = [levelStyle, '', categoryStyle, ''];

    if (entry.data !== undefined || entry.correlationId) {
      // Use grouped output for data
      console.groupCollapsed(format, ...styles);
      if (entry.correlationId) {
        console.log('%cCorrelation ID:%c ' + entry.correlationId, 'color: #868e96;', 'color: #748ffc;');
      }
      if (entry.data !== undefined) {
        console.log('Data:', entry.data);
      }
      console.groupEnd();
    } else {
      console.log(format, ...styles);
    }
  }

  private bridgeEntry(entry: LogEntry): void {
    // Bridge to main process if electronAPI is available
    if (typeof window !== 'undefined' && (window as any).electronAPI?.logFromRenderer) {
      (window as any).electronAPI.logFromRenderer(entry);
    }
  }

  // ===== Level-specific methods =====

  /** Log at ERROR level */
  error(category: string, message: string, data?: unknown, correlationId?: string): void {
    this.logWithLevel(LogLevel.ERROR, category, message, data, correlationId);
  }

  /** Log at WARN level */
  warn(category: string, message: string, data?: unknown, correlationId?: string): void {
    this.logWithLevel(LogLevel.WARN, category, message, data, correlationId);
  }

  /** Log at INFO level */
  info(category: string, message: string, data?: unknown, correlationId?: string): void {
    this.logWithLevel(LogLevel.INFO, category, message, data, correlationId);
  }

  /** Log at DEBUG level */
  debug(category: string, message: string, data?: unknown, correlationId?: string): void {
    this.logWithLevel(LogLevel.DEBUG, category, message, data, correlationId);
  }

  /** Log at TRACE level */
  trace(category: string, message: string, data?: unknown, correlationId?: string): void {
    this.logWithLevel(LogLevel.TRACE, category, message, data, correlationId);
  }

  // ===== Category convenience methods =====

  /** Log UI state changes */
  ui(message: string, data?: unknown): void {
    this.info(LogCategory.UI, message, data);
  }

  /** Log user actions */
  action(message: string, data?: unknown): void {
    this.info(LogCategory.ACTION, message, data);
  }

  /** Log data loading operations */
  data(message: string, data?: unknown): void {
    this.debug(LogCategory.DATA, message, data);
  }

  /** Log validation results */
  validation(message: string, data?: unknown): void {
    this.warn(LogCategory.VALIDATION, message, data);
  }

  /** Log component lifecycle events */
  lifecycle(message: string, data?: unknown): void {
    this.trace(LogCategory.LIFECYCLE, message, data);
  }

  /** Log render events */
  render(message: string, data?: unknown): void {
    this.trace(LogCategory.RENDER, message, data);
  }

  /** Log focus events */
  focus(message: string, data?: unknown): void {
    this.debug(LogCategory.FOCUS, message, data);
  }

  /** Log clipboard operations */
  clipboard(message: string, data?: unknown): void {
    this.info(LogCategory.CLIPBOARD, message, data);
  }

  /** Log terminal I/O - input and output tracking */
  terminalIO(message: string, data?: unknown): void {
    this.info(LogCategory.TERMINAL_IO, message, data);
  }

  /** Log IPC calls */
  ipc(message: string, data?: unknown, correlationId?: string): void {
    this.debug(LogCategory.IPC, message, data, correlationId);
  }

  /** Log performance measurements */
  perf(message: string, data?: unknown): void {
    this.info(LogCategory.PERFORMANCE, message, data);
  }

  // ===== Utility methods =====

  /** Generate a unique correlation ID */
  generateCorrelationId(): string {
    return `r-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
  }

  /** Wrap an IPC call with automatic logging */
  async ipcCall<T>(
    channel: string,
    fn: () => Promise<T>,
    requestData?: unknown
  ): Promise<T> {
    const correlationId = this.generateCorrelationId();
    const start = Date.now();

    this.debug(LogCategory.IPC, `CALL: ${channel}`, { ...requestData as object, correlationId }, correlationId);

    try {
      const result = await fn();
      const duration = Date.now() - start;
      this.debug(LogCategory.IPC, `RESPONSE: ${channel}`, { duration_ms: duration }, correlationId);
      return result;
    } catch (error) {
      const duration = Date.now() - start;
      this.error(LogCategory.IPC, `ERROR: ${channel}`, { duration_ms: duration, error }, correlationId);
      throw error;
    }
  }

  /** Measure async operation performance */
  async measure<T>(
    category: string,
    label: string,
    fn: () => Promise<T>
  ): Promise<T> {
    const start = Date.now();
    this.debug(category, `${label} - START`);

    try {
      const result = await fn();
      const duration = Date.now() - start;
      this.info(LogCategory.PERFORMANCE, `${label} - COMPLETE`, { duration_ms: duration });
      return result;
    } catch (error) {
      const duration = Date.now() - start;
      this.error(category, `${label} - FAILED`, { duration_ms: duration, error });
      throw error;
    }
  }

  // ===== Runtime configuration =====

  /** Enable debug logging */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
    this.saveStorageConfig();
    if (enabled && !this.enabled) {
      this.logBanner();
    }
  }

  /** Check if debug is enabled */
  isEnabled(): boolean {
    return this.enabled;
  }

  /** Set minimum log level */
  setLevel(level: LogLevel): void {
    this.minLevel = level;
    this.saveStorageConfig();
  }

  /** Get current minimum log level */
  getLevel(): LogLevel {
    return this.minLevel;
  }

  /** Enable specific categories */
  enableCategories(...categories: string[]): void {
    categories.forEach(c => this.categories.add(c.toUpperCase()));
    this.saveStorageConfig();
  }

  /** Disable specific categories */
  disableCategories(...categories: string[]): void {
    categories.forEach(c => this.categories.delete(c.toUpperCase()));
    this.saveStorageConfig();
  }

  /** Enable all categories */
  enableAllCategories(): void {
    RENDERER_CATEGORIES.forEach(c => this.categories.add(c));
    this.saveStorageConfig();
  }

  /** Set bridge to main process */
  setBridgeToMain(bridge: boolean): void {
    this.bridgeToMain = bridge;
    this.saveStorageConfig();
  }

  private saveStorageConfig(): void {
    try {
      if (typeof localStorage === 'undefined') return;
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        enabled: this.enabled,
        level: this.minLevel,
        categories: Array.from(this.categories),
        bridgeToMain: this.bridgeToMain,
      }));
    } catch {
      // Ignore storage errors
    }
  }

  /** Reset to build-time defaults */
  resetConfig(): void {
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.removeItem(STORAGE_KEY);
      }
    } catch {
      // Ignore
    }
    // Reinitialize
    const buildEnabled = typeof __DEBUG__ !== 'undefined' ? __DEBUG__ : false;
    const buildCategories = typeof __DEBUG_CATEGORIES__ !== 'undefined' ? __DEBUG_CATEGORIES__ : '*';
    const buildLevel = typeof __DEBUG_LEVEL__ !== 'undefined' ? __DEBUG_LEVEL__ : 'INFO';

    this.enabled = buildEnabled;
    this.minLevel = this.parseLevel(buildLevel);
    this.bridgeToMain = true;

    if (buildCategories === '*') {
      this.categories = new Set(RENDERER_CATEGORIES);
    } else {
      this.categories = new Set(buildCategories.split(',').map(c => c.trim().toUpperCase()));
    }
  }
}

// ===== Singleton export =====

/** Singleton logger instance */
export const log = new RendererLogger();

// ===== Convenience re-exports =====

export const rendererLogger = log;
