/**
 * Console bridge - sends renderer console logs to main process (terminal)
 * Logs appear in BOTH DevTools and terminal
 */

// Store original console methods
const originalConsole = {
  log: console.log.bind(console),
  warn: console.warn.bind(console),
  error: console.error.bind(console),
  info: console.info.bind(console),
};

// Helper to format arguments
function formatArgs(args: any[]): string {
  return args
    .map(arg => {
      if (typeof arg === 'object') {
        try {
          return JSON.stringify(arg, null, 2);
        } catch {
          return String(arg);
        }
      }
      return String(arg);
    })
    .join(' ');
}

// Override console methods to bridge to main process
function setupConsoleBridge() {
  if (!window.electronAPI) {
    console.warn('[Console Bridge] electronAPI not available - terminal logs disabled');
    return;
  }

  // Check if bridge handler exists
  if (typeof (window.electronAPI as any).logToTerminal !== 'function') {
    console.warn('[Console Bridge] logToTerminal IPC handler not found - terminal logs disabled');
    return;
  }

  const bridge = (window.electronAPI as any).logToTerminal;

  // Override console.log
  console.log = (...args: any[]) => {
    originalConsole.log(...args);
    bridge('log', formatArgs(args));
  };

  // Override console.warn
  console.warn = (...args: any[]) => {
    originalConsole.warn(...args);
    bridge('warn', formatArgs(args));
  };

  // Override console.error
  console.error = (...args: any[]) => {
    originalConsole.error(...args);
    bridge('error', formatArgs(args));
  };

  // Override console.info
  console.info = (...args: any[]) => {
    originalConsole.info(...args);
    bridge('info', formatArgs(args));
  };

  console.log('[Console Bridge] Renderer logs will appear in terminal');
}

export { setupConsoleBridge, originalConsole };
