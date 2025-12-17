/**
 * Session Persistence
 *
 * Handles saving and restoring terminal sessions across app restarts.
 * Stores session metadata and output buffers to ~/.crack/breach/sessions/
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { debug } from '../debug';
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
   * Get path to session file
   */
  private getSessionPath(engagementId: string, sessionId: string): string {
    return path.join(this.basePath, engagementId, `${sessionId}.json`);
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
    processes: Map<string, { session: TerminalSession; outputBuffer: string[] }>
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
      const { session, outputBuffer } = proc;
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
          const sessionPath = this.getSessionPath(engagementId, session.id);
          await fs.writeFile(sessionPath, JSON.stringify(session, null, 2));
          activeIds.push(session.id);
          debug.pty('Persisted session', {
            sessionId: session.id,
            engagementId,
            outputLines: session.outputBuffer.length,
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
      outputLineCount: s.outputBuffer.length,
      canReconnect: false, // Phase 3: will check tmux
    }));
  }

  /**
   * Load a single persisted session with its output buffer
   */
  async loadSession(
    engagementId: string,
    sessionId: string
  ): Promise<PersistedSession | null> {
    try {
      const sessionPath = this.getSessionPath(engagementId, sessionId);
      const data = await fs.readFile(sessionPath, 'utf-8');
      return JSON.parse(data) as PersistedSession;
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
