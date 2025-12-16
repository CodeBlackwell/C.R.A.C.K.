/**
 * TerminalPane - xterm.js Terminal Wrapper
 *
 * Renders a terminal instance connected to a PTY session via IPC.
 * Uses fetch-then-listen pattern: fetch buffered output first, then register for live updates.
 */

import { useEffect, useRef, useCallback } from 'react';
import { Terminal, IDisposable } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import { log, LogCategory } from '@shared/electron/debug-renderer';
import 'xterm/css/xterm.css';

interface TerminalPaneProps {
  sessionId: string;
  active: boolean;
}

/** Terminal theme matching B.R.E.A.C.H. dark UI */
const TERMINAL_THEME = {
  background: '#1a1b1e',
  foreground: '#c9d1d9',
  cursor: '#58a6ff',
  cursorAccent: '#1a1b1e',
  selectionBackground: '#264f78',
  black: '#0d1117',
  red: '#ff7b72',
  green: '#7ee787',
  yellow: '#d29922',
  blue: '#58a6ff',
  magenta: '#bc8cff',
  cyan: '#39c5cf',
  white: '#b1bac4',
  brightBlack: '#6e7681',
  brightRed: '#ffa198',
  brightGreen: '#56d364',
  brightYellow: '#e3b341',
  brightBlue: '#79c0ff',
  brightMagenta: '#d2a8ff',
  brightCyan: '#56d4dd',
  brightWhite: '#f0f6fc',
};

// Track terminal instances globally to prevent StrictMode double-creation
// Use window to survive HMR (Hot Module Replacement) reloads
interface TerminalInstance {
  terminal: Terminal;
  fitAddon: FitAddon;
  disposed: boolean;
  onDataDisposable: IDisposable | null;
  outputCleanup: (() => void) | null;
  container: HTMLDivElement | null; // Track which container the terminal is attached to
}

const TERMINAL_INSTANCES_KEY = '__BREACH_TERMINAL_INSTANCES__';
const terminalInstances: Map<string, TerminalInstance> =
  (window as any)[TERMINAL_INSTANCES_KEY] ||
  ((window as any)[TERMINAL_INSTANCES_KEY] = new Map());

export function TerminalPane({ sessionId, active }: TerminalPaneProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  // Initialize terminal - fetch-then-listen pattern
  useEffect(() => {
    if (!containerRef.current) return;

    log.lifecycle('TerminalPane mount', { sessionId });

    // Check if we already have an instance for this session (StrictMode reclaim)
    const existing = terminalInstances.get(sessionId);
    log.data('Terminal instance check', {
      sessionId,
      hasExisting: !!existing,
      disposed: existing?.disposed,
      hasOutputCleanup: !!existing?.outputCleanup
    });

    if (existing) {
      // Reclaim existing terminal - cancel any pending disposal from StrictMode unmount
      log.lifecycle('Reclaiming existing terminal', { sessionId });
      existing.disposed = false; // Cancel deferred disposal
      terminalRef.current = existing.terminal;
      fitAddonRef.current = existing.fitAddon;

      // Move terminal's DOM element to new container if needed
      // This happens in StrictMode where React creates a new DOM element on remount
      // IMPORTANT: Use appendChild to MOVE the element, NOT terminal.open() which creates duplicates
      if (existing.terminal.element && existing.terminal.element.parentElement !== containerRef.current) {
        log.lifecycle('Moving terminal DOM to new container', { sessionId });
        // appendChild moves (not copies) the element to the new container
        containerRef.current.appendChild(existing.terminal.element);
        existing.container = containerRef.current;
        // Refit after move
        setTimeout(() => {
          try {
            existing.fitAddon.fit();
          } catch {
            // Ignore fit errors
          }
        }, 10);
      }
      return; // Reclaimed - output listener already registered
    }

    // Create new terminal
    const terminal = new Terminal({
      theme: TERMINAL_THEME,
      fontFamily: 'JetBrains Mono, Monaco, Courier, monospace',
      fontSize: 13,
      lineHeight: 1.2,
      cursorBlink: true,
      cursorStyle: 'block',
      allowProposedApi: true,
      scrollback: 10000,
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    terminal.loadAddon(fitAddon);
    terminal.loadAddon(webLinksAddon);
    terminal.open(containerRef.current);

    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;

    // Handle keyboard shortcuts (CTRL+SHIFT+C for copy, CTRL+SHIFT+V for paste)
    terminal.attachCustomKeyEventHandler((event) => {
      // CTRL+SHIFT+C - Copy selection to clipboard
      if (event.ctrlKey && event.shiftKey && event.code === 'KeyC') {
        const selection = terminal.getSelection();
        if (selection) {
          navigator.clipboard.writeText(selection).then(() => {
            log.action('Copied to clipboard', { length: selection.length });
          }).catch((err) => {
            log.error(LogCategory.UI, 'Failed to copy', err);
          });
        }
        return false; // Prevent default handling
      }

      // CTRL+SHIFT+V - Paste from clipboard
      if (event.ctrlKey && event.shiftKey && event.code === 'KeyV') {
        navigator.clipboard.readText().then((text) => {
          if (text) {
            window.electronAPI.sessionWrite(sessionId, text);
            log.action('Pasted from clipboard', { length: text.length });
          }
        }).catch((err) => {
          log.error(LogCategory.UI, 'Failed to paste', err);
        });
        return false; // Prevent default handling
      }

      return true; // Allow default handling for other keys
    });

    // Track onData for cleanup (prevents duplicate input)
    const onDataDisposable = terminal.onData((data) => {
      log.terminalIO('INPUT', {
        sessionId,
        data: data.length <= 10 ? data : `${data.substring(0, 10)}...`,
        charCodes: data.split('').map(c => c.charCodeAt(0)).slice(0, 5)
      });
      window.electronAPI.sessionWrite(sessionId, data);
    });

    // Handle resize
    terminal.onResize(({ cols, rows }) => {
      window.electronAPI.sessionResize(sessionId, cols, rows);
    });

    // Output handler for live updates
    const handleOutput = (_: unknown, data: { sessionId: string; data: string }) => {
      if (data.sessionId === sessionId) {
        log.terminalIO('OUTPUT', {
          sessionId,
          dataLength: data.data.length,
          preview: data.data.length <= 20 ? data.data : `${data.data.substring(0, 20)}...`
        });
        terminal.write(data.data);
      }
    };

    // Store instance
    const instance: TerminalInstance = {
      terminal,
      fitAddon,
      disposed: false,
      onDataDisposable,
      outputCleanup: null,
      container: containerRef.current,
    };
    terminalInstances.set(sessionId, instance);

    // FETCH existing output FIRST, THEN register for live updates
    log.ipc('Fetching session output buffer', { sessionId });
    window.electronAPI.sessionGetOutput(sessionId).then((existingOutput) => {
      if (instance.disposed) {
        log.lifecycle('Terminal disposed during fetch, skipping', { sessionId });
        return;
      }

      log.data('Session output buffer received', {
        sessionId,
        bufferLength: existingOutput?.length || 0,
        hasContent: existingOutput && existingOutput.length > 0
      });

      // Write buffered output
      if (existingOutput && existingOutput.length > 0) {
        terminal.write(existingOutput.join(''));
      }

      // NOW register for live output (after buffer is written)
      log.lifecycle('Registering output listener', { sessionId });
      window.electronAPI.onSessionOutput(handleOutput);
      instance.outputCleanup = () => {
        window.electronAPI.removeSessionOutputListener(handleOutput);
      };
    });

    // Defer fit() to ensure terminal is fully initialized
    setTimeout(() => {
      if (fitAddonRef.current && containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          try {
            fitAddonRef.current.fit();
          } catch {
            // Ignore fit errors during initialization
          }
        }
      }
    }, 50);

    return () => {
      const inst = terminalInstances.get(sessionId);
      if (inst) {
        inst.disposed = true;
      }

      // Defer disposal for StrictMode reclaim
      setTimeout(() => {
        const inst = terminalInstances.get(sessionId);
        if (inst?.disposed) {
          inst.onDataDisposable?.dispose();
          inst.outputCleanup?.();
          inst.terminal.dispose();
          terminalInstances.delete(sessionId);
        }
      }, 0);

      terminalRef.current = null;
      fitAddonRef.current = null;
    };
  }, [sessionId]);

  // Safe fit function
  const safeFit = useCallback(() => {
    if (!fitAddonRef.current || !terminalRef.current || !containerRef.current) {
      return;
    }
    const rect = containerRef.current.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      try {
        fitAddonRef.current.fit();
      } catch {
        // Ignore fit errors
      }
    }
  }, []);

  // Handle window resize
  useEffect(() => {
    if (!active) return;
    const handleWindowResize = () => safeFit();
    window.addEventListener('resize', handleWindowResize);
    return () => window.removeEventListener('resize', handleWindowResize);
  }, [active, safeFit]);

  // Handle pane becoming active
  useEffect(() => {
    if (active && terminalRef.current) {
      const timer = setTimeout(safeFit, 10);
      return () => clearTimeout(timer);
    }
  }, [active, safeFit]);

  // Focus terminal when active
  useEffect(() => {
    if (active && terminalRef.current) {
      terminalRef.current.focus();
    }
  }, [active]);

  return (
    <div
      ref={containerRef}
      style={{
        width: '100%',
        height: '100%',
        display: active ? 'block' : 'none',
        background: TERMINAL_THEME.background,
      }}
    />
  );
}
