/**
 * TerminalPane - xterm.js Terminal Wrapper
 *
 * Renders a terminal instance connected to a PTY session via IPC.
 */

import { useEffect, useRef, useCallback } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
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

export function TerminalPane({ sessionId, active }: TerminalPaneProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  // Track the session ID we initialized for to handle StrictMode properly
  const initializedForSessionRef = useRef<string | null>(null);
  // Store output handler ref for proper cleanup
  const outputHandlerRef = useRef<((event: unknown, data: { sessionId: string; data: string }) => void) | null>(null);

  // Initialize terminal
  useEffect(() => {
    // Only initialize if not already initialized for this session
    if (!containerRef.current || initializedForSessionRef.current === sessionId) return;

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
    initializedForSessionRef.current = sessionId;

    // Defer fit() with setTimeout to ensure terminal is fully initialized
    // Use multiple frames to give xterm time to set up internal renderer
    setTimeout(() => {
      if (fitAddonRef.current && containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect();
        // Only fit if container has actual dimensions
        if (rect.width > 0 && rect.height > 0) {
          try {
            fitAddonRef.current.fit();
          } catch {
            // Ignore fit errors during initialization
          }
        }
      }
    }, 50);

    // Forward terminal input to PTY
    terminal.onData((data) => {
      window.electronAPI.sessionWrite(sessionId, data);
    });

    // Handle resize
    terminal.onResize(({ cols, rows }) => {
      window.electronAPI.sessionResize(sessionId, cols, rows);
    });

    // Load existing output
    window.electronAPI.sessionGetOutput(sessionId).then((output) => {
      if (output) {
        terminal.write(output);
      }
    });

    return () => {
      terminal.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
      // Don't reset initializedForSessionRef - let it persist to prevent re-init in StrictMode
    };
  }, [sessionId]);

  // Listen for session output - use stable ref for proper cleanup
  useEffect(() => {
    // Remove any existing listener first (handles StrictMode double-mount)
    if (outputHandlerRef.current) {
      window.electronAPI.removeSessionOutputListener(outputHandlerRef.current as any);
    }

    const handleOutput = (_: unknown, data: { sessionId: string; data: string }) => {
      if (data.sessionId === sessionId && terminalRef.current) {
        terminalRef.current.write(data.data);
      }
    };

    outputHandlerRef.current = handleOutput;
    window.electronAPI.onSessionOutput(handleOutput as any);

    return () => {
      if (outputHandlerRef.current) {
        window.electronAPI.removeSessionOutputListener(outputHandlerRef.current as any);
        outputHandlerRef.current = null;
      }
    };
  }, [sessionId]);

  // Safe fit function that checks terminal readiness
  const safeFit = useCallback(() => {
    if (!fitAddonRef.current || !terminalRef.current || !containerRef.current) {
      return;
    }
    const rect = containerRef.current.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      try {
        fitAddonRef.current.fit();
      } catch {
        // Ignore fit errors - terminal may not be ready
      }
    }
  }, []);

  // Handle window resize events
  useEffect(() => {
    if (!active) return;

    const handleWindowResize = () => {
      safeFit();
    };

    window.addEventListener('resize', handleWindowResize);
    return () => window.removeEventListener('resize', handleWindowResize);
  }, [active, safeFit]);

  // Handle pane becoming active - delay fit to ensure DOM is updated
  useEffect(() => {
    if (active && initializedForSessionRef.current) {
      // Small delay to ensure display:block has taken effect
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
