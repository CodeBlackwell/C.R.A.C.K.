/**
 * Tmux Backend for Persistent Sessions
 *
 * Provides tmux integration for sessions that should survive app restarts.
 * Listeners, tunnels, and long-running scans can continue running in tmux
 * and be reattached when the app restarts.
 */

import { spawn, execSync } from 'child_process';
import * as pty from 'node-pty';
import { debug } from '../debug';

/** Tmux session info */
export interface TmuxSessionInfo {
  name: string;
  created: Date;
  attached: boolean;
  windows: number;
}

/** Prefix for B.R.E.A.C.H. managed tmux sessions */
const TMUX_PREFIX = 'breach';

/**
 * Tmux Backend - manages persistent terminal sessions via tmux
 */
class TmuxBackend {
  private available: boolean | null = null;

  /**
   * Check if tmux is installed and available
   */
  async isAvailable(): Promise<boolean> {
    if (this.available !== null) {
      return this.available;
    }

    try {
      execSync('which tmux', { stdio: 'pipe' });
      // Also verify tmux can actually run
      execSync('tmux -V', { stdio: 'pipe' });
      this.available = true;
      debug.pty('Tmux is available');
    } catch {
      this.available = false;
      debug.pty('Tmux is not available');
    }

    return this.available;
  }

  /**
   * Generate a unique tmux session name for B.R.E.A.C.H.
   */
  generateSessionName(sessionId: string): string {
    return `${TMUX_PREFIX}-${sessionId}`;
  }

  /**
   * Parse a tmux session name to get the B.R.E.A.C.H. session ID
   */
  parseSessionName(tmuxName: string): string | null {
    if (tmuxName.startsWith(`${TMUX_PREFIX}-`)) {
      return tmuxName.slice(TMUX_PREFIX.length + 1);
    }
    return null;
  }

  /**
   * Create a new tmux session and return a PTY attached to it
   *
   * @param sessionId - B.R.E.A.C.H. session ID
   * @param command - Command to run in the session
   * @param args - Command arguments
   * @param options - PTY spawn options
   */
  async createSession(
    sessionId: string,
    command: string,
    args: string[],
    options: {
      cwd?: string;
      env?: Record<string, string>;
      cols?: number;
      rows?: number;
    } = {}
  ): Promise<{ pty: pty.IPty; tmuxSession: string }> {
    const tmuxSession = this.generateSessionName(sessionId);

    // Build the full command to run inside tmux
    const fullCommand = args.length > 0 ? `${command} ${args.join(' ')}` : command;

    // Create tmux session in detached mode first
    try {
      const createCmd = [
        'tmux', 'new-session',
        '-d',                      // Detached
        '-s', tmuxSession,         // Session name
        '-x', String(options.cols || 120),  // Width
        '-y', String(options.rows || 30),   // Height
        fullCommand                // Command to run
      ];

      debug.pty('Creating tmux session', { tmuxSession, command: fullCommand });

      execSync(createCmd.join(' '), {
        cwd: options.cwd,
        env: { ...process.env, ...options.env },
        stdio: 'pipe',
      });
    } catch (error) {
      debug.error('Failed to create tmux session', { tmuxSession, error });
      throw error;
    }

    // Now attach to the session via PTY
    const ptyProcess = pty.spawn('tmux', ['attach-session', '-t', tmuxSession], {
      name: 'xterm-256color',
      cols: options.cols || 120,
      rows: options.rows || 30,
      cwd: options.cwd,
      env: {
        ...process.env,
        TERM: 'xterm-256color',
        ...options.env,
      } as Record<string, string>,
    });

    debug.pty('Attached to tmux session', { tmuxSession, pid: ptyProcess.pid });

    return { pty: ptyProcess, tmuxSession };
  }

  /**
   * Attach to an existing tmux session
   *
   * @param tmuxSession - Tmux session name
   * @param options - PTY options
   */
  async attachSession(
    tmuxSession: string,
    options: {
      cols?: number;
      rows?: number;
    } = {}
  ): Promise<pty.IPty | null> {
    // Check if session exists
    if (!await this.sessionExists(tmuxSession)) {
      debug.pty('Tmux session does not exist', { tmuxSession });
      return null;
    }

    try {
      const ptyProcess = pty.spawn('tmux', ['attach-session', '-t', tmuxSession], {
        name: 'xterm-256color',
        cols: options.cols || 120,
        rows: options.rows || 30,
        env: {
          ...process.env,
          TERM: 'xterm-256color',
        } as Record<string, string>,
      });

      debug.pty('Reattached to tmux session', { tmuxSession, pid: ptyProcess.pid });
      return ptyProcess;
    } catch (error) {
      debug.error('Failed to attach to tmux session', { tmuxSession, error });
      return null;
    }
  }

  /**
   * Check if a tmux session exists
   */
  async sessionExists(tmuxSession: string): Promise<boolean> {
    try {
      execSync(`tmux has-session -t ${tmuxSession}`, { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * List all B.R.E.A.C.H. managed tmux sessions
   */
  async listSessions(): Promise<TmuxSessionInfo[]> {
    if (!await this.isAvailable()) {
      return [];
    }

    try {
      const output = execSync(
        'tmux list-sessions -F "#{session_name}|#{session_created}|#{session_attached}|#{session_windows}"',
        { stdio: 'pipe', encoding: 'utf-8' }
      );

      const sessions: TmuxSessionInfo[] = [];

      for (const line of output.trim().split('\n')) {
        if (!line) continue;

        const [name, created, attached, windows] = line.split('|');

        // Only include B.R.E.A.C.H. managed sessions
        if (name.startsWith(`${TMUX_PREFIX}-`)) {
          sessions.push({
            name,
            created: new Date(parseInt(created) * 1000),
            attached: attached === '1',
            windows: parseInt(windows),
          });
        }
      }

      debug.pty('Listed tmux sessions', { count: sessions.length });
      return sessions;
    } catch {
      // No sessions or tmux not running
      return [];
    }
  }

  /**
   * Kill a tmux session
   */
  async killSession(tmuxSession: string): Promise<boolean> {
    try {
      execSync(`tmux kill-session -t ${tmuxSession}`, { stdio: 'pipe' });
      debug.pty('Killed tmux session', { tmuxSession });
      return true;
    } catch (error) {
      debug.error('Failed to kill tmux session', { tmuxSession, error });
      return false;
    }
  }

  /**
   * Kill all B.R.E.A.C.H. managed tmux sessions
   */
  async killAllSessions(): Promise<number> {
    const sessions = await this.listSessions();
    let killed = 0;

    for (const session of sessions) {
      if (await this.killSession(session.name)) {
        killed++;
      }
    }

    debug.pty('Killed all B.R.E.A.C.H. tmux sessions', { count: killed });
    return killed;
  }

  /**
   * Send keys to a tmux session (for automation)
   */
  async sendKeys(tmuxSession: string, keys: string): Promise<boolean> {
    try {
      // Escape special characters for tmux
      const escaped = keys.replace(/'/g, "'\\''");
      execSync(`tmux send-keys -t ${tmuxSession} '${escaped}'`, { stdio: 'pipe' });
      return true;
    } catch (error) {
      debug.error('Failed to send keys to tmux session', { tmuxSession, error });
      return false;
    }
  }

  /**
   * Capture pane content from a tmux session
   */
  async capturePane(tmuxSession: string, lines: number = 1000): Promise<string[]> {
    try {
      const output = execSync(
        `tmux capture-pane -t ${tmuxSession} -p -S -${lines}`,
        { stdio: 'pipe', encoding: 'utf-8' }
      );
      return output.split('\n');
    } catch (error) {
      debug.error('Failed to capture tmux pane', { tmuxSession, error });
      return [];
    }
  }
}

/** Singleton instance */
export const tmuxBackend = new TmuxBackend();

/** Export for testing */
export { TmuxBackend };
