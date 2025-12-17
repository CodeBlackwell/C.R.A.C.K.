/**
 * Session Persistence Types
 *
 * Types for saving and restoring terminal sessions across app restarts.
 */

import type { SessionType, SessionStatus } from './session';

/** Version for schema migrations */
export const PERSISTENCE_VERSION = 2;

/** Session manifest - index of all persisted sessions */
export interface SessionManifest {
  version: number;
  lastSaved: string;
  engagements: Record<
    string,
    {
      sessionCount: number;
      lastActivity: string;
      activeSessionIds: string[];
    }
  >;
}

/** Persisted session data */
export interface PersistedSession {
  id: string;
  type: SessionType;
  status: SessionStatus;

  /** Command execution */
  command: string;
  args: string[];
  workingDir: string;
  env?: Record<string, string>;

  /** Relationships */
  targetId?: string;
  engagementId?: string;
  linkedSessions: string[];
  parentSessionId?: string;

  /** Metadata */
  label?: string;
  icon?: string;
  persistent: boolean;
  interactive: boolean;

  /** Timestamps */
  startedAt: string;
  stoppedAt?: string;
  lastActivityAt?: string;
  savedAt: string;

  /** Output buffer - Phase 1 stored inline, Phase 2+ uses compressed file */
  outputBuffer: string[];

  /** Path to compressed output buffer file (Phase 2+) */
  outputBufferFile?: string;

  /** Number of lines in output buffer (for UI display without decompressing) */
  outputLineCount?: number;

  /** Tmux session name for live reconnection (Phase 3) */
  tmuxSession?: string;
}

/** Restore options for UI */
export interface RestoreSessionInfo {
  id: string;
  type: SessionType;
  label?: string;
  command: string;
  workingDir: string;
  lastActivityAt?: string;
  outputLineCount: number;
  canReconnect: boolean; // True if tmux session exists (Phase 3)
}

/** Restore request from renderer */
export interface RestoreRequest {
  sessionIds: string[];
  engagementId: string;
}

/** Restore result */
export interface RestoreResult {
  restored: string[];
  failed: Array<{ id: string; error: string }>;
}
