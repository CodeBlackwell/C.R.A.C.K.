/**
 * Session Persistence Types
 *
 * Types for saving and restoring terminal sessions across app restarts.
 */

import type { SessionType, SessionStatus } from './session';

/** Version for schema migrations */
export const PERSISTENCE_VERSION = 1;

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

  /** Output buffer (stored directly for Phase 1, compressed in Phase 2) */
  outputBuffer: string[];
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
