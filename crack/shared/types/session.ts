/**
 * Shared Terminal Session Types
 *
 * Common type definitions for terminal session management.
 * Used by B.R.E.A.C.H. GUI and engagement tracking system.
 */

/** Session type categories */
export type SessionType =
  | 'shell'      // Reverse/bind shell
  | 'listener'   // NC, multi/handler
  | 'tunnel'     // Chisel, SSH tunnel
  | 'proxy'      // SOCKS, HTTP proxy
  | 'scan'       // nmap, ffuf, gobuster
  | 'server'     // HTTP server, SMB share
  | 'custom';    // User-defined

/** Session lifecycle status */
export type SessionStatus =
  | 'starting'      // Process spawning
  | 'running'       // Active and connected
  | 'backgrounded'  // Running but not focused
  | 'stopped'       // Gracefully terminated
  | 'error'         // Failed or crashed
  | 'completed'     // Finished (for scans)
  | 'disconnected'; // Lost connection (for reconnect)

/** Terminal session data model */
export interface TerminalSession {
  id: string;
  type: SessionType;
  status: SessionStatus;

  /** Command execution */
  command: string;
  args: string[];
  workingDir: string;
  env?: Record<string, string>;

  /** Process info */
  pid?: number;
  exitCode?: number;

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

  /** Progress (for scans) */
  progress?: SessionProgress;
}

/** Session progress tracking */
export interface SessionProgress {
  current: number;
  total: number;
  percentage: number;
  message?: string;
}

/** Session link types for topology graph */
export type SessionLinkType =
  | 'tunnels_through'   // Chisel client → server
  | 'provides_access'   // Shell → target
  | 'spawned_from'      // Command ran in shell
  | 'proxies_via';      // Proxychains → SOCKS

/** Session relationship */
export interface SessionLink {
  id: string;
  sourceSessionId: string;
  targetSessionId: string;
  linkType: SessionLinkType;
  createdAt: string;
}

/** Session template for quick start */
export interface SessionTemplate {
  id: string;
  name: string;
  type: SessionType;
  command: string;
  args: string[];
  variables: TemplateVariable[];
  persistent: boolean;
  description: string;
  icon?: string;
}

/** Template variable placeholder */
export interface TemplateVariable {
  name: string;
  placeholder: string;
  default?: string;
  description?: string;
}

/** Session creation options */
export interface CreateSessionOptions {
  type?: SessionType;
  targetId?: string;
  engagementId?: string;
  label?: string;
  workingDir?: string;
  env?: Record<string, string>;
  persistent?: boolean;
  interactive?: boolean;
  linkedSessions?: string[];
  parentSessionId?: string;
}

/** Session filter criteria */
export interface SessionFilter {
  type?: SessionType | SessionType[];
  status?: SessionStatus | SessionStatus[];
  targetId?: string;
  engagementId?: string;
  persistent?: boolean;
}
