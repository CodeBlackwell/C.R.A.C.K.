/**
 * PTY Manager - Terminal Session Lifecycle Management
 *
 * Handles spawning, communication, and cleanup of terminal sessions
 * using node-pty for real PTY emulation.
 */

import * as pty from 'node-pty';
import { BrowserWindow } from 'electron';
import { debug } from '../debug';
import { getCredentialParser } from '../parser';
import { getNetworkParser } from '../parser/network-parser';
import { sessionPersistence } from './persistence';
import type {
  TerminalSession,
  SessionType,
  CreateSessionOptions,
} from '@shared/types/session';
import type { CommandProvenance } from '@shared/types/signal';
import type { PersistedSession, RestoreSessionInfo } from '@shared/types/persistence';

/**
 * Capture the launch directory at module load time.
 * This is the directory from which BREACH was launched.
 * All new terminal sessions will default to this directory.
 */
const LAUNCH_DIRECTORY = process.cwd();
debug.pty('Launch directory captured', { launchDir: LAUNCH_DIRECTORY });

/** Internal PTY process wrapper */
interface PtyProcess {
  pty: pty.IPty;
  session: TerminalSession;
  outputBuffer: string[];
  inputBuffer: string;           // Buffer for tracking user input
  lastCommand: CommandProvenance | null;  // Last command entered
}

/** Generate unique session ID */
function generateSessionId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 9);
  return `sess-${timestamp}-${random}`;
}

/**
 * PTY Manager Singleton
 *
 * Manages all terminal sessions in the application.
 */
class PtyManager {
  private processes: Map<string, PtyProcess> = new Map();
  private mainWindow: BrowserWindow | null = null;
  private maxOutputBuffer = 10000;

  /** Set the main window for IPC communication */
  setMainWindow(window: BrowserWindow): void {
    this.mainWindow = window;
    debug.pty('Main window set for PTY communication');
  }

  /**
   * Create a new terminal session
   */
  async createSession(
    command: string,
    args: string[] = [],
    options: CreateSessionOptions = {}
  ): Promise<TerminalSession> {
    const sessionId = generateSessionId();

    debug.pty('Creating session', { sessionId, command, args });

    const session: TerminalSession = {
      id: sessionId,
      type: options.type || 'custom',
      status: 'starting',
      command,
      args,
      workingDir: options.workingDir || LAUNCH_DIRECTORY,
      env: options.env,
      targetId: options.targetId,
      engagementId: options.engagementId,
      linkedSessions: options.linkedSessions || [],
      parentSessionId: options.parentSessionId,
      label: options.label || command,
      persistent: options.persistent ?? false,
      interactive: options.interactive ?? true,
      startedAt: new Date().toISOString(),
    };

    try {
      const ptyProcess = pty.spawn(command, args, {
        name: 'xterm-256color',
        cols: 120,
        rows: 30,
        cwd: session.workingDir,
        env: {
          ...process.env,
          TERM: 'xterm-256color',
          ...options.env,
        } as Record<string, string>,
      });

      session.pid = ptyProcess.pid;
      session.status = 'running';

      const processWrapper: PtyProcess = {
        pty: ptyProcess,
        session,
        outputBuffer: [],
        inputBuffer: '',
        lastCommand: null,
      };

      // Handle output
      ptyProcess.onData((data: string) => {
        this.handleOutput(sessionId, data);
      });

      // Handle exit
      ptyProcess.onExit(({ exitCode, signal }) => {
        debug.pty('PTY exited', { sessionId, exitCode, signal });
        this.handleExit(sessionId, exitCode);
      });

      this.processes.set(sessionId, processWrapper);

      debug.pty('Session created successfully', {
        sessionId,
        pid: session.pid,
        type: session.type,
      });

      // Notify renderer
      this.sendToRenderer('session-created', session);

      return session;
    } catch (error) {
      debug.error('Failed to create PTY session', error);
      session.status = 'error';
      throw error;
    }
  }

  /**
   * Write data to a session's stdin
   */
  write(sessionId: string, data: string): boolean {
    const proc = this.processes.get(sessionId);
    if (!proc) {
      debug.error('Session not found for write', { sessionId });
      return false;
    }

    try {
      // Track input for command provenance
      this.trackInput(proc, data);

      proc.pty.write(data);
      return true;
    } catch (error) {
      debug.error('Failed to write to PTY', { sessionId, error });
      return false;
    }
  }

  /**
   * Track user input for command provenance
   * Captures the command when Enter is pressed
   */
  private trackInput(proc: PtyProcess, data: string): void {
    // Check for Enter key (carriage return or newline)
    if (data.includes('\r') || data.includes('\n')) {
      // Capture the command before clearing the buffer
      const command = proc.inputBuffer.trim();
      if (command) {
        proc.lastCommand = {
          sessionId: proc.session.id,
          command,
          workingDirectory: proc.session.workingDir,
          timestamp: new Date().toISOString(),
        };
        debug.pty('Command captured', {
          sessionId: proc.session.id,
          command: command.substring(0, 50),
        });
      }
      // Clear buffer for next command
      proc.inputBuffer = '';
    } else if (data === '\x7f' || data === '\b') {
      // Backspace - remove last character
      proc.inputBuffer = proc.inputBuffer.slice(0, -1);
    } else if (data === '\x03') {
      // Ctrl+C - clear buffer
      proc.inputBuffer = '';
    } else if (data === '\x15') {
      // Ctrl+U - clear line
      proc.inputBuffer = '';
    } else if (data.length === 1 && data.charCodeAt(0) >= 32) {
      // Regular printable character
      proc.inputBuffer += data;
    } else if (data.length > 1 && !data.startsWith('\x1b')) {
      // Pasted text (multiple chars, not escape sequence)
      proc.inputBuffer += data;
    }
    // Ignore escape sequences (arrow keys, etc.)
  }

  /**
   * Get the last command entered in a session
   */
  getLastCommand(sessionId: string): CommandProvenance | null {
    const proc = this.processes.get(sessionId);
    return proc?.lastCommand || null;
  }

  /**
   * Resize a session's terminal
   */
  resize(sessionId: string, cols: number, rows: number): boolean {
    const proc = this.processes.get(sessionId);
    if (!proc) {
      return false;
    }

    try {
      proc.pty.resize(cols, rows);
      debug.pty('Session resized', { sessionId, cols, rows });
      return true;
    } catch (error) {
      debug.error('Failed to resize PTY', { sessionId, error });
      return false;
    }
  }

  /**
   * Kill a session
   */
  kill(sessionId: string, signal: string = 'SIGTERM'): boolean {
    const proc = this.processes.get(sessionId);
    if (!proc) {
      return false;
    }

    debug.pty('Killing session', { sessionId, signal });

    try {
      proc.pty.kill(signal);
      proc.session.status = 'stopped';
      proc.session.stoppedAt = new Date().toISOString();
      this.sendToRenderer('session-status', {
        sessionId,
        status: 'stopped',
      });
      return true;
    } catch (error) {
      debug.error('Failed to kill PTY', { sessionId, error });
      return false;
    }
  }

  /**
   * Background a session (mark as backgrounded but keep running)
   */
  background(sessionId: string): boolean {
    const proc = this.processes.get(sessionId);
    if (!proc) {
      return false;
    }

    proc.session.status = 'backgrounded';
    this.sendToRenderer('session-status', {
      sessionId,
      status: 'backgrounded',
    });
    debug.pty('Session backgrounded', { sessionId });
    return true;
  }

  /**
   * Foreground a backgrounded session
   */
  foreground(sessionId: string): boolean {
    const proc = this.processes.get(sessionId);
    if (!proc || proc.session.status !== 'backgrounded') {
      return false;
    }

    proc.session.status = 'running';
    this.sendToRenderer('session-status', {
      sessionId,
      status: 'running',
    });
    debug.pty('Session foregrounded', { sessionId });
    return true;
  }

  /**
   * Get a session by ID
   */
  getSession(sessionId: string): TerminalSession | null {
    return this.processes.get(sessionId)?.session || null;
  }

  /**
   * Get all active sessions
   */
  getAllSessions(): TerminalSession[] {
    return Array.from(this.processes.values()).map((p) => p.session);
  }

  /**
   * Get sessions by type
   */
  getSessionsByType(type: SessionType): TerminalSession[] {
    return this.getAllSessions().filter((s) => s.type === type);
  }

  /**
   * Get sessions by target
   */
  getSessionsByTarget(targetId: string): TerminalSession[] {
    return this.getAllSessions().filter((s) => s.targetId === targetId);
  }

  /**
   * Get output buffer for a session
   */
  getOutputBuffer(sessionId: string): string[] {
    return this.processes.get(sessionId)?.outputBuffer || [];
  }

  /**
   * Link two sessions (e.g., chisel client → server)
   */
  linkSessions(sourceId: string, targetId: string): boolean {
    const source = this.processes.get(sourceId);
    const target = this.processes.get(targetId);

    if (!source || !target) {
      return false;
    }

    if (!source.session.linkedSessions.includes(targetId)) {
      source.session.linkedSessions.push(targetId);
    }
    if (!target.session.linkedSessions.includes(sourceId)) {
      target.session.linkedSessions.push(sourceId);
    }

    debug.session('Sessions linked', { sourceId, targetId });
    return true;
  }

  /**
   * Update session label
   */
  setSessionLabel(sessionId: string, label: string): boolean {
    const proc = this.processes.get(sessionId);
    if (!proc) {
      return false;
    }

    proc.session.label = label;
    this.sendToRenderer('session-updated', proc.session);
    return true;
  }

  /**
   * Cleanup all sessions on shutdown
   */
  async cleanup(): Promise<void> {
    debug.pty('Cleaning up all sessions');

    for (const [sessionId, proc] of this.processes) {
      try {
        proc.pty.kill();
        proc.session.status = 'stopped';
        proc.session.stoppedAt = new Date().toISOString();
      } catch (error) {
        debug.error('Error killing session during cleanup', { sessionId, error });
      }
    }

    this.processes.clear();
    debug.pty('All sessions cleaned up');
  }

  /**
   * Persist all sessions to disk before app quit
   */
  async persistAll(): Promise<void> {
    debug.pty('Persisting all sessions', { count: this.processes.size });

    if (this.processes.size === 0) {
      debug.pty('No sessions to persist');
      return;
    }

    await sessionPersistence.saveAll(this.processes);
  }

  /**
   * Get restore info for UI (lightweight, no output buffers)
   */
  async getRestoreInfo(engagementId: string): Promise<RestoreSessionInfo[]> {
    return sessionPersistence.getRestoreInfo(engagementId);
  }

  /**
   * Restore sessions from disk
   * Creates new shell sessions with historical output as scroll-back
   */
  async restoreSessions(sessionIds: string[], engagementId: string): Promise<TerminalSession[]> {
    debug.pty('Restoring sessions', { count: sessionIds.length, engagementId });

    const restored: TerminalSession[] = [];

    for (const sessionId of sessionIds) {
      try {
        const persisted = await sessionPersistence.loadSession(engagementId, sessionId);
        if (!persisted) {
          debug.error('Could not load persisted session', { sessionId });
          continue;
        }

        // Create a new shell session in the same working directory
        const session = await this.createSession('bash', [], {
          type: persisted.type,
          label: persisted.label ? `${persisted.label} (restored)` : 'restored',
          workingDir: persisted.workingDir,
          engagementId: persisted.engagementId,
          targetId: persisted.targetId,
          interactive: true,
        });

        // Prepend historical output to the new session's buffer
        const proc = this.processes.get(session.id);
        if (proc && persisted.outputBuffer.length > 0) {
          // Add a separator and then the historical output
          const separator = '\r\n\x1b[90m--- Restored session history ---\x1b[0m\r\n';
          const historicalOutput = persisted.outputBuffer.join('\n');

          // Write to the terminal (renderer will receive this)
          this.sendToRenderer('session-output', {
            sessionId: session.id,
            data: separator + historicalOutput + '\r\n\x1b[90m--- End of history ---\x1b[0m\r\n\r\n',
          });

          // Also add to buffer
          proc.outputBuffer.push(...persisted.outputBuffer);
        }

        restored.push(session);

        // Delete the persisted session file after successful restore
        await sessionPersistence.deleteSession(engagementId, sessionId);

        debug.pty('Restored session', {
          originalId: sessionId,
          newId: session.id,
          outputLines: persisted.outputBuffer.length,
        });
      } catch (error) {
        debug.error('Failed to restore session', { sessionId, error });
      }
    }

    return restored;
  }

  // Private methods

  private handleOutput(sessionId: string, data: string): void {
    const proc = this.processes.get(sessionId);
    if (!proc) return;

    // Update activity timestamp
    proc.session.lastActivityAt = new Date().toISOString();

    // Buffer output (ring buffer)
    const lines = data.split('\n');
    proc.outputBuffer.push(...lines);
    if (proc.outputBuffer.length > this.maxOutputBuffer) {
      proc.outputBuffer = proc.outputBuffer.slice(-this.maxOutputBuffer);
    }

    // Common context for parsers
    const parserContext = {
      engagementId: proc.session.engagementId,
      targetId: proc.session.targetId,
    };

    // Feed to PRISM credential parser for credential/finding detection
    getCredentialParser().ingestOutput(sessionId, data, parserContext);

    // Feed to network parser for network signal detection
    // Extract target IP from the session if available
    const targetIp = this.extractTargetIp(proc.session);
    getNetworkParser().parseText(
      data,
      sessionId,
      { ...parserContext, targetIp },
      proc.lastCommand || undefined
    );

    // Send to renderer
    this.sendToRenderer('session-output', { sessionId, data });
  }

  /**
   * Extract target IP from session context
   */
  private extractTargetIp(session: TerminalSession): string | undefined {
    // Try to extract IP from various session properties
    // 1. From command args (e.g., nmap 192.168.1.10)
    if (session.args && session.args.length > 0) {
      const ipPattern = /\d+\.\d+\.\d+\.\d+/;
      for (const arg of session.args) {
        const match = arg.match(ipPattern);
        if (match) return match[0];
      }
    }

    // 2. From session label
    if (session.label) {
      const ipPattern = /\d+\.\d+\.\d+\.\d+/;
      const match = session.label.match(ipPattern);
      if (match) return match[0];
    }

    return undefined;
  }

  private handleExit(sessionId: string, exitCode: number): void {
    const proc = this.processes.get(sessionId);
    if (!proc) return;

    proc.session.exitCode = exitCode;
    proc.session.status = exitCode === 0 ? 'completed' : 'error';
    proc.session.stoppedAt = new Date().toISOString();

    // Flush any remaining buffered output to parser
    getCredentialParser().flushSession(sessionId, {
      engagementId: proc.session.engagementId,
      targetId: proc.session.targetId,
    });

    // Clear network parser session cache
    getNetworkParser().clearSession(sessionId);

    this.sendToRenderer('session-status', {
      sessionId,
      status: proc.session.status,
      exitCode,
    });

    // Remove from active processes (keep in map for history)
    // Optionally remove after delay or based on persistent flag
    if (!proc.session.persistent) {
      setTimeout(() => {
        this.processes.delete(sessionId);
      }, 60000); // Keep for 1 minute after exit
    }
  }

  private sendToRenderer(channel: string, data: unknown): void {
    if (this.mainWindow && !this.mainWindow.isDestroyed()) {
      this.mainWindow.webContents.send(channel, data);
    }
  }
}

/** Singleton instance */
export const ptyManager = new PtyManager();

/** Set main window (called from main process) */
export function setPtyMainWindow(window: BrowserWindow): void {
  ptyManager.setMainWindow(window);
}
