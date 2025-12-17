/**
 * Session Persistence
 *
 * Handles saving and restoring terminal sessions across app restarts.
 * Stores session metadata and output buffers to ~/.crack/breach/sessions/
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import * as zlib from 'zlib';
import { promisify } from 'util';
import { debug } from '../debug';

/** Promisified gzip functions */
const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);
import type {
  SessionManifest,
  PersistedSession,
  RestoreSessionInfo,
} from '@shared/types/persistence';
import { PERSISTENCE_VERSION } from '@shared/types/persistence';
import type { TerminalSession } from '@shared/types/session';

/** Base path for session storage */
const SESSIONS_BASE_PATH = path.join(os.homedir(), '.crack', 'breach', 'sessions');

/** Manifest filename */
const MANIFEST_FILE = 'manifest.json';

/**
 * Sanitize terminal output for persistence
 *
 * Raw terminal output contains ANSI escape sequences for cursor positioning,
 * carriage returns for spinners/progress bars, and other control sequences
 * that don't make sense when replayed. This function:
 *
 * 1. Processes carriage returns (\r) - keeps only final content per line
 * 2. Strips cursor movement sequences (CSI H, CSI A/B/C/D, etc.)
 * 3. Strips screen clearing sequences (CSI 2J, CSI K, etc.)
 * 4. Preserves color/style sequences (CSI ...m)
 * 5. Collapses duplicate spinner lines
 */
function sanitizeTerminalOutput(rawChunks: string[]): string[] {
  // Join all chunks to process as one stream
  // NOTE: Raw chunks from PTY should be concatenated directly (no separator)
  // The newlines are already embedded in the data itself
  const raw = rawChunks.join('');

  // Process carriage returns: split by \r, process each segment
  // A \r means "return to beginning of line", so we simulate this
  const lines: string[] = [];
  let currentLine = '';

  for (let i = 0; i < raw.length; i++) {
    const char = raw[i];

    if (char === '\r') {
      // Carriage return - check if followed by \n
      if (raw[i + 1] === '\n') {
        // \r\n is a normal line ending
        lines.push(currentLine);
        currentLine = '';
        i++; // Skip the \n
      } else {
        // Standalone \r - go back to beginning of line (overwrite mode)
        // Keep the line content but prepare to overwrite
        // Only push if next chars will create new content
        currentLine = ''; // Reset to simulate cursor returning to start
      }
    } else if (char === '\n') {
      // Newline - end current line
      lines.push(currentLine);
      currentLine = '';
    } else {
      currentLine += char;
    }
  }

  // Don't forget the last line if no trailing newline
  if (currentLine) {
    lines.push(currentLine);
  }

  // Now strip cursor movement escape sequences but keep colors
  // CSI sequences: \x1b[ followed by parameters and a letter
  const cleanedLines = lines.map((line) => {
    // Strip cursor movement and screen control sequences
    // Keep: \x1b[...m (SGR - colors/styles)
    // Strip: \x1b[...H (cursor position), \x1b[...A/B/C/D (cursor movement)
    //        \x1b[...J (erase display), \x1b[...K (erase line)
    //        \x1b[?...h/l (private modes like cursor, mouse, bracketed paste)
    //        \x1b[...r (scroll region)
    // Note: \?? makes the ? optional - sequences like \x1b[?25h have ? AFTER [
    return line.replace(
      /\x1b\[\??[\d;]*[HABCDEFGJKSTfnsuhl]/g,
      ''
    );
  });

  // Remove empty lines that were just cursor control sequences
  // and collapse consecutive duplicate lines (spinner effect)
  const deduped: string[] = [];
  let lastLine = '';

  for (const line of cleanedLines) {
    // Skip if line is just whitespace or identical to previous (spinner)
    const trimmed = line.replace(/\x1b\[[\d;]*m/g, '').trim();
    if (!trimmed) continue;

    // Check for spinner patterns: lines differing only in spinner char
    const spinnerPattern = /^\s*[\[\(]?[\|\/\-\\][\]\)]?\s*/;
    const lastTrimmed = lastLine.replace(/\x1b\[[\d;]*m/g, '').trim();

    if (spinnerPattern.test(trimmed) && spinnerPattern.test(lastTrimmed)) {
      const lastWithoutSpinner = lastTrimmed.replace(spinnerPattern, '');
      const currentWithoutSpinner = trimmed.replace(spinnerPattern, '');
      if (lastWithoutSpinner === currentWithoutSpinner) {
        // Same line with different spinner char - skip
        continue;
      }
    }

    deduped.push(line);
    lastLine = line;
  }

  return deduped;
}

/**
 * Session Persistence Manager
 *
 * Saves and loads session state to/from disk.
 */
export class SessionPersistence {
  private basePath: string;

  constructor(basePath: string = SESSIONS_BASE_PATH) {
    this.basePath = basePath;
  }

  /**
   * Ensure the sessions directory exists
   */
  async ensureDir(engagementId?: string): Promise<void> {
    const dirPath = engagementId
      ? path.join(this.basePath, engagementId)
      : this.basePath;

    try {
      await fs.mkdir(dirPath, { recursive: true });
    } catch (error) {
      debug.error('Failed to create sessions directory', { dirPath, error });
      throw error;
    }
  }

  /**
   * Get path to manifest file
   */
  private getManifestPath(): string {
    return path.join(this.basePath, MANIFEST_FILE);
  }

  /**
   * Get path to session metadata file
   */
  private getSessionPath(engagementId: string, sessionId: string): string {
    return path.join(this.basePath, engagementId, `${sessionId}.json`);
  }

  /**
   * Get path to compressed output buffer file
   */
  private getOutputPath(engagementId: string, sessionId: string): string {
    return path.join(this.basePath, engagementId, `${sessionId}.output.gz`);
  }

  /**
   * Compress and save output buffer to file
   * Sanitizes terminal output before saving to remove cursor control sequences
   * Returns the output file path and sanitized line count
   */
  private async saveCompressedOutput(
    engagementId: string,
    sessionId: string,
    outputBuffer: string[]
  ): Promise<{ outputFile: string; lineCount: number }> {
    const outputPath = this.getOutputPath(engagementId, sessionId);

    // Sanitize the output to remove cursor control sequences and process \r
    const sanitized = sanitizeTerminalOutput(outputBuffer);
    const text = sanitized.join('\n');

    const compressed = await gzip(Buffer.from(text, 'utf-8'));
    await fs.writeFile(outputPath, compressed);

    debug.pty('Saved compressed output', {
      sessionId,
      rawLines: outputBuffer.length,
      sanitizedLines: sanitized.length,
    });

    // Return relative path and sanitized line count
    return {
      outputFile: `${sessionId}.output.gz`,
      lineCount: sanitized.length,
    };
  }

  /**
   * Load and decompress output buffer from file
   */
  private async loadCompressedOutput(
    engagementId: string,
    outputFile: string
  ): Promise<string[]> {
    try {
      const outputPath = path.join(this.basePath, engagementId, outputFile);
      const compressed = await fs.readFile(outputPath);
      const decompressed = await gunzip(compressed);
      // Return as single chunk to preserve newlines - buffer format matches live sessions
      // (raw chunks that may contain \n characters)
      return [decompressed.toString('utf-8')];
    } catch (error) {
      debug.error('Failed to load compressed output', { outputFile, error });
      return [];
    }
  }

  /**
   * Load the session manifest
   */
  async loadManifest(): Promise<SessionManifest | null> {
    try {
      const manifestPath = this.getManifestPath();
      const data = await fs.readFile(manifestPath, 'utf-8');
      const manifest = JSON.parse(data) as SessionManifest;
      debug.pty('Loaded session manifest', {
        version: manifest.version,
        engagementCount: Object.keys(manifest.engagements).length,
      });
      return manifest;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        debug.pty('No session manifest found');
        return null;
      }
      debug.error('Failed to load session manifest', error);
      return null;
    }
  }

  /**
   * Save the session manifest
   */
  async saveManifest(manifest: SessionManifest): Promise<void> {
    try {
      await this.ensureDir();
      const manifestPath = this.getManifestPath();
      await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
      debug.pty('Saved session manifest', {
        engagementCount: Object.keys(manifest.engagements).length,
      });
    } catch (error) {
      debug.error('Failed to save session manifest', error);
      throw error;
    }
  }

  /**
   * Save all sessions from the given processes map
   */
  async saveAll(
    processes: Map<string, { session: TerminalSession; outputBuffer: string[]; tmuxSession?: string }>
  ): Promise<void> {
    if (processes.size === 0) {
      debug.pty('No sessions to persist');
      return;
    }

    debug.pty('Persisting sessions', { count: processes.size });

    const manifest: SessionManifest = {
      version: PERSISTENCE_VERSION,
      lastSaved: new Date().toISOString(),
      engagements: {},
    };

    // Group sessions by engagement
    const byEngagement = new Map<string, PersistedSession[]>();

    for (const [, proc] of processes) {
      const { session, outputBuffer, tmuxSession } = proc;
      const engagementId = session.engagementId || 'no-engagement';

      const persisted: PersistedSession = {
        id: session.id,
        type: session.type,
        status: session.status,
        command: session.command,
        args: session.args,
        workingDir: session.workingDir,
        env: session.env,
        targetId: session.targetId,
        engagementId: session.engagementId,
        linkedSessions: session.linkedSessions,
        parentSessionId: session.parentSessionId,
        label: session.label,
        icon: session.icon,
        persistent: session.persistent,
        interactive: session.interactive,
        startedAt: session.startedAt,
        stoppedAt: session.stoppedAt,
        lastActivityAt: session.lastActivityAt,
        savedAt: new Date().toISOString(),
        outputBuffer: outputBuffer,
        tmuxSession: tmuxSession, // Phase 3: save tmux session name
      };

      if (!byEngagement.has(engagementId)) {
        byEngagement.set(engagementId, []);
      }
      byEngagement.get(engagementId)!.push(persisted);
    }

    // Save each engagement's sessions
    for (const [engagementId, sessions] of byEngagement) {
      await this.ensureDir(engagementId);

      const activeIds: string[] = [];

      for (const session of sessions) {
        try {
          // Save compressed output buffer to separate file (also sanitizes)
          const { outputFile, lineCount } = await this.saveCompressedOutput(
            engagementId,
            session.id,
            session.outputBuffer
          );

          // Create metadata without inline output buffer (use compressed file)
          const metadata: PersistedSession = {
            ...session,
            outputBuffer: [], // Don't store inline - use compressed file
            outputBufferFile: outputFile,
            outputLineCount: lineCount, // Use sanitized line count
          };

          const sessionPath = this.getSessionPath(engagementId, session.id);
          await fs.writeFile(sessionPath, JSON.stringify(metadata, null, 2));
          activeIds.push(session.id);
          debug.pty('Persisted session (compressed)', {
            sessionId: session.id,
            engagementId,
            outputLines: lineCount,
            outputFile,
          });
        } catch (error) {
          debug.error('Failed to persist session', { sessionId: session.id, error });
        }
      }

      // Update manifest for this engagement
      manifest.engagements[engagementId] = {
        sessionCount: sessions.length,
        lastActivity: sessions
          .map((s) => s.lastActivityAt || s.startedAt)
          .sort()
          .pop() || new Date().toISOString(),
        activeSessionIds: activeIds,
      };
    }

    // Save manifest
    await this.saveManifest(manifest);

    debug.pty('Session persistence complete', {
      totalSessions: processes.size,
      engagements: byEngagement.size,
    });
  }

  /**
   * Save a single session to disk (called when session is killed)
   */
  async saveSession(
    engagementId: string,
    session: TerminalSession,
    outputBuffer: string[],
    tmuxSession?: string
  ): Promise<void> {
    await this.ensureDir(engagementId);

    // Save compressed output
    const { outputFile, lineCount } = await this.saveCompressedOutput(
      engagementId,
      session.id,
      outputBuffer
    );

    // Save metadata
    const metadata: PersistedSession = {
      id: session.id,
      type: session.type,
      status: session.status,
      command: session.command,
      args: session.args,
      workingDir: session.workingDir,
      env: session.env,
      targetId: session.targetId,
      engagementId: session.engagementId,
      linkedSessions: session.linkedSessions,
      parentSessionId: session.parentSessionId,
      label: session.label,
      icon: session.icon,
      persistent: session.persistent,
      interactive: session.interactive,
      startedAt: session.startedAt,
      stoppedAt: session.stoppedAt,
      lastActivityAt: session.lastActivityAt,
      savedAt: new Date().toISOString(),
      outputBuffer: [],
      outputBufferFile: outputFile,
      outputLineCount: lineCount,
      tmuxSession,
    };

    const sessionPath = this.getSessionPath(engagementId, session.id);
    await fs.writeFile(sessionPath, JSON.stringify(metadata, null, 2));

    // Update manifest
    await this.updateManifestForSession(engagementId, session.id);

    debug.pty('Saved session', { sessionId: session.id, outputLines: lineCount });
  }

  /**
   * Update manifest when a single session is saved
   */
  private async updateManifestForSession(engagementId: string, sessionId: string): Promise<void> {
    let manifest = await this.loadManifest();

    if (!manifest) {
      manifest = {
        version: PERSISTENCE_VERSION,
        lastSaved: new Date().toISOString(),
        engagements: {},
      };
    }

    if (!manifest.engagements[engagementId]) {
      manifest.engagements[engagementId] = {
        sessionCount: 0,
        lastActivity: new Date().toISOString(),
        activeSessionIds: [],
      };
    }

    const engagement = manifest.engagements[engagementId];

    // Add session if not already tracked
    if (!engagement.activeSessionIds.includes(sessionId)) {
      engagement.activeSessionIds.push(sessionId);
      engagement.sessionCount = engagement.activeSessionIds.length;
    }

    engagement.lastActivity = new Date().toISOString();
    manifest.lastSaved = new Date().toISOString();

    await this.saveManifest(manifest);
  }

  /**
   * Get persisted sessions for an engagement
   */
  async getPersistedSessions(engagementId: string): Promise<PersistedSession[]> {
    const sessions: PersistedSession[] = [];
    const engagementDir = path.join(this.basePath, engagementId);

    try {
      const files = await fs.readdir(engagementDir);
      const jsonFiles = files.filter((f) => f.endsWith('.json'));

      for (const file of jsonFiles) {
        try {
          const filePath = path.join(engagementDir, file);
          const data = await fs.readFile(filePath, 'utf-8');
          const session = JSON.parse(data) as PersistedSession;
          sessions.push(session);
        } catch (error) {
          debug.error('Failed to load persisted session', { file, error });
        }
      }

      debug.pty('Loaded persisted sessions', {
        engagementId,
        count: sessions.length,
      });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        debug.error('Failed to read engagement directory', { engagementId, error });
      }
    }

    return sessions;
  }

  /**
   * Get restore info for UI display (without full output buffer)
   */
  async getRestoreInfo(engagementId: string): Promise<RestoreSessionInfo[]> {
    const sessions = await this.getPersistedSessions(engagementId);

    return sessions.map((s) => ({
      id: s.id,
      type: s.type,
      label: s.label,
      command: s.command,
      workingDir: s.workingDir,
      lastActivityAt: s.lastActivityAt,
      // Phase 2+: use stored count, Phase 1 fallback: inline buffer length
      outputLineCount: s.outputLineCount ?? s.outputBuffer.length,
      canReconnect: !!s.tmuxSession, // Phase 3: true if tmux session exists
    }));
  }

  /**
   * Load a single persisted session with its output buffer
   * Decompresses output from .gz file if using Phase 2+ format
   */
  async loadSession(
    engagementId: string,
    sessionId: string
  ): Promise<PersistedSession | null> {
    try {
      const sessionPath = this.getSessionPath(engagementId, sessionId);
      const data = await fs.readFile(sessionPath, 'utf-8');
      const session = JSON.parse(data) as PersistedSession;

      // Phase 2+: Load compressed output from separate file
      if (session.outputBufferFile) {
        session.outputBuffer = await this.loadCompressedOutput(
          engagementId,
          session.outputBufferFile
        );
        debug.pty('Loaded compressed output', {
          sessionId,
          lines: session.outputBuffer.length,
        });
      }

      return session;
    } catch (error) {
      debug.error('Failed to load session', { sessionId, error });
      return null;
    }
  }

  /**
   * Clear persisted sessions for an engagement
   */
  async clearPersisted(engagementId: string): Promise<void> {
    const engagementDir = path.join(this.basePath, engagementId);

    try {
      await fs.rm(engagementDir, { recursive: true, force: true });
      debug.pty('Cleared persisted sessions', { engagementId });

      // Update manifest
      const manifest = await this.loadManifest();
      if (manifest) {
        delete manifest.engagements[engagementId];
        await this.saveManifest(manifest);
      }
    } catch (error) {
      debug.error('Failed to clear persisted sessions', { engagementId, error });
    }
  }

  /**
   * Clear all persisted sessions
   */
  async clearAll(): Promise<void> {
    try {
      await fs.rm(this.basePath, { recursive: true, force: true });
      debug.pty('Cleared all persisted sessions');
    } catch (error) {
      debug.error('Failed to clear all persisted sessions', error);
    }
  }

  /**
   * Delete a single persisted session
   */
  async deleteSession(engagementId: string, sessionId: string): Promise<void> {
    try {
      const sessionPath = this.getSessionPath(engagementId, sessionId);
      await fs.unlink(sessionPath);
      debug.pty('Deleted persisted session', { sessionId, engagementId });

      // Update manifest
      const manifest = await this.loadManifest();
      if (manifest && manifest.engagements[engagementId]) {
        manifest.engagements[engagementId].activeSessionIds =
          manifest.engagements[engagementId].activeSessionIds.filter(
            (id) => id !== sessionId
          );
        manifest.engagements[engagementId].sessionCount--;

        if (manifest.engagements[engagementId].sessionCount === 0) {
          delete manifest.engagements[engagementId];
        }

        await this.saveManifest(manifest);
      }
    } catch (error) {
      debug.error('Failed to delete session', { sessionId, error });
    }
  }
}

/** Singleton instance */
export const sessionPersistence = new SessionPersistence();
