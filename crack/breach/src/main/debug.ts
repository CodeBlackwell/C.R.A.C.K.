/**
 * Main Process Debug Logger Singleton
 *
 * All main process modules should import from here to avoid
 * multiple logger instances and duplicate banners.
 */

import { createDebugLogger } from '@shared/electron/debug';

// Single logger instance for the entire main process
export const debug = createDebugLogger({ appName: 'breach' });

// Re-export for convenience
export { DebugCategory } from '@shared/electron/debug';
