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
  const initializedRef = useRef(false);

  // Initialize terminal
  useEffect(() => {
    if (!containerRef.current || initializedRef.current) return;

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

    // Defer fit() to allow terminal to fully render in DOM
    requestAnimationFrame(() => {
      try {
        fitAddon.fit();
      } catch {
        // Ignore fit errors during initialization
      }
    });

    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;
    initializedRef.current = true;

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
      initializedRef.current = false;
    };
  }, [sessionId]);

  // Listen for session output
  useEffect(() => {
    const handleOutput = (_: unknown, data: { sessionId: string; data: string }) => {
      if (data.sessionId === sessionId && terminalRef.current) {
        terminalRef.current.write(data.data);
      }
    };

    window.electronAPI.onSessionOutput(handleOutput as any);

    return () => {
      window.electronAPI.removeSessionOutputListener(handleOutput as any);
    };
  }, [sessionId]);

  // Handle resize when pane becomes active or window resizes
  const handleResize = useCallback(() => {
    if (fitAddonRef.current && terminalRef.current && active) {
      try {
        fitAddonRef.current.fit();
      } catch {
        // Ignore fit errors during resize
      }
    }
  }, [active]);

  useEffect(() => {
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [handleResize]);

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
