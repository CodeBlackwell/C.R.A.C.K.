/**
 * PTY Manager - Terminal Session Lifecycle Management
 *
 * Handles spawning, communication, and cleanup of terminal sessions
 * using node-pty for real PTY emulation.
 */

import * as pty from 'node-pty';
import { BrowserWindow } from 'electron';
import { createDebugLogger } from '@shared/electron/debug';
import type {
  TerminalSession,
  SessionType,
  CreateSessionOptions,
} from '@shared/types/session';

const debug = createDebugLogger({ appName: 'breach' });

/** Internal PTY process wrapper */
interface PtyProcess {
  pty: pty.IPty;
  session: TerminalSession;
  outputBuffer: string[];
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
      workingDir: options.workingDir || process.env.HOME || '/tmp',
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
      proc.pty.write(data);
      return true;
    } catch (error) {
      debug.error('Failed to write to PTY', { sessionId, error });
      return false;
    }
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

    // Send to renderer
    this.sendToRenderer('session-output', { sessionId, data });
  }

  private handleExit(sessionId: string, exitCode: number): void {
    const proc = this.processes.get(sessionId);
    if (!proc) return;

    proc.session.exitCode = exitCode;
    proc.session.status = exitCode === 0 ? 'completed' : 'error';
    proc.session.stoppedAt = new Date().toISOString();

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
