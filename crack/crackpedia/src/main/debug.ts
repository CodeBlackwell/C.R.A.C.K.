/**
 * Debug logging system for CRACK Electron
 *
 * Provides categorized logging with timestamps and color coding
 * Toggle via DEBUG environment variable or programmatically
 */

export enum DebugCategory {
  NEO4J = 'NEO4J',
  IPC = 'IPC',
  ELECTRON = 'ELECTRON',
  QUERY = 'QUERY',
  ERROR = 'ERROR',
  STARTUP = 'STARTUP',
  PERFORMANCE = 'PERFORMANCE',
}

class DebugLogger {
  private enabled: boolean;
  private categories: Set<DebugCategory>;
  private startTime: number;

  constructor() {
    // Enable debug if DEBUG env var is set
    const debugEnv = process.env.DEBUG || '';
    this.enabled = debugEnv.toLowerCase() === 'true' || debugEnv === '1' || debugEnv === '*';

    // Parse categories from DEBUG_CATEGORIES (comma-separated)
    const categoriesEnv = process.env.DEBUG_CATEGORIES || '';
    if (categoriesEnv === '*' || !categoriesEnv) {
      this.categories = new Set(Object.values(DebugCategory));
    } else {
      this.categories = new Set(
        categoriesEnv.split(',').map(c => c.trim().toUpperCase() as DebugCategory)
      );
    }

    this.startTime = Date.now();

    if (this.enabled) {
      console.log('\n🔧 DEBUG MODE ENABLED');
      console.log('📋 Categories:', Array.from(this.categories).join(', '));
      console.log('⏱️  Start time:', new Date().toISOString());
      console.log('━'.repeat(80) + '\n');
    }
  }

  /**
   * Enable/disable debug logging at runtime
   */
  setEnabled(enabled: boolean) {
    this.enabled = enabled;
  }

  /**
   * Enable specific categories
   */
  enableCategories(...categories: DebugCategory[]) {
    categories.forEach(c => this.categories.add(c));
  }

  /**
   * Disable specific categories
   */
  disableCategories(...categories: DebugCategory[]) {
    categories.forEach(c => this.categories.delete(c));
  }

  /**
   * Get elapsed time since logger creation
   */
  private getElapsedTime(): string {
    const elapsed = Date.now() - this.startTime;
    const seconds = Math.floor(elapsed / 1000);
    const ms = elapsed % 1000;
    return `+${seconds}.${ms.toString().padStart(3, '0')}s`;
  }

  /**
   * Get color code for category
   */
  private getCategoryColor(category: DebugCategory): string {
    const colors: Record<DebugCategory, string> = {
      [DebugCategory.NEO4J]: '\x1b[36m',      // Cyan
      [DebugCategory.IPC]: '\x1b[35m',         // Magenta
      [DebugCategory.ELECTRON]: '\x1b[34m',    // Blue
      [DebugCategory.QUERY]: '\x1b[33m',       // Yellow
      [DebugCategory.ERROR]: '\x1b[31m',       // Red
      [DebugCategory.STARTUP]: '\x1b[32m',     // Green
      [DebugCategory.PERFORMANCE]: '\x1b[90m', // Gray
    };
    return colors[category] || '\x1b[37m'; // White default
  }

  /**
   * Get emoji for category
   */
  private getCategoryEmoji(category: DebugCategory): string {
    const emojis: Record<DebugCategory, string> = {
      [DebugCategory.NEO4J]: '🔷',
      [DebugCategory.IPC]: '📡',
      [DebugCategory.ELECTRON]: '⚡',
      [DebugCategory.QUERY]: '🔍',
      [DebugCategory.ERROR]: '❌',
      [DebugCategory.STARTUP]: '🚀',
      [DebugCategory.PERFORMANCE]: '⏱️',
    };
    return emojis[category] || '📌';
  }

  /**
   * Main logging function
   */
  log(category: DebugCategory, message: string, data?: any) {
    if (!this.enabled || !this.categories.has(category)) {
      return;
    }

    const color = this.getCategoryColor(category);
    const emoji = this.getCategoryEmoji(category);
    const reset = '\x1b[0m';
    const timestamp = new Date().toISOString().split('T')[1].slice(0, 12); // HH:MM:SS.mmm
    const elapsed = this.getElapsedTime();

    const prefix = `${color}${emoji} [${category.padEnd(11)}]${reset} ${timestamp} ${elapsed}`;

    if (data === undefined) {
      console.log(`${prefix} ${message}`);
    } else {
      console.log(`${prefix} ${message}`);
      console.log(`${color}   └─${reset}`, data);
    }
  }

  /**
   * Log Neo4j operations
   */
  neo4j(message: string, data?: any) {
    this.log(DebugCategory.NEO4J, message, data);
  }

  /**
   * Log IPC calls
   */
  ipc(message: string, data?: any) {
    this.log(DebugCategory.IPC, message, data);
  }

  /**
   * Log Electron events
   */
  electron(message: string, data?: any) {
    this.log(DebugCategory.ELECTRON, message, data);
  }

  /**
   * Log database queries
   */
  query(message: string, data?: any) {
    this.log(DebugCategory.QUERY, message, data);
  }

  /**
   * Log errors (always shown if debug enabled)
   */
  error(message: string, error?: any) {
    this.log(DebugCategory.ERROR, message, error);
  }

  /**
   * Log startup sequence
   */
  startup(message: string, data?: any) {
    this.log(DebugCategory.STARTUP, message, data);
  }

  /**
   * Log performance metrics
   */
  performance(message: string, data?: any) {
    this.log(DebugCategory.PERFORMANCE, message, data);
  }

  /**
   * Measure execution time of async function
   */
  async measure<T>(
    category: DebugCategory,
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

  /**
   * Create a section separator
   */
  section(title: string) {
    if (!this.enabled) return;
    console.log(`\n${'═'.repeat(80)}`);
    console.log(`  ${title.toUpperCase()}`);
    console.log(`${'═'.repeat(80)}\n`);
  }

  /**
   * Create a subsection
   */
  subsection(title: string) {
    if (!this.enabled) return;
    console.log(`\n${'─'.repeat(40)}`);
    console.log(`  ${title}`);
    console.log(`${'─'.repeat(40)}`);
  }
}

// Singleton instance
export const debug = new DebugLogger();

// Convenience exports
export const logNeo4j = (msg: string, data?: any) => debug.neo4j(msg, data);
export const logIPC = (msg: string, data?: any) => debug.ipc(msg, data);
export const logElectron = (msg: string, data?: any) => debug.electron(msg, data);
export const logQuery = (msg: string, data?: any) => debug.query(msg, data);
export const logError = (msg: string, error?: any) => debug.error(msg, error);
export const logStartup = (msg: string, data?: any) => debug.startup(msg, data);
export const logPerformance = (msg: string, data?: any) => debug.performance(msg, data);
