/**
 * B.R.E.A.C.H. Preload Script
 *
 * Secure context bridge exposing IPC handlers to renderer process.
 */

import { contextBridge, ipcRenderer, IpcRendererEvent } from 'electron';
import type { TerminalSession, CreateSessionOptions } from '@shared/types/session';
import type { Credential } from '@shared/types/credential';
import type { Loot, PatternType } from '@shared/types/loot';
import type { Finding, CreateFindingData, FindingSummary } from '@shared/types/finding';
import type {
  Engagement,
  CreateEngagementData,
  EngagementStats,
  EngagementStatus,
} from '@shared/types/engagement';
import type { Target, CreateTargetData } from '@shared/types/target';
import type {
  ModuleMetadata,
  CommandModule,
} from '@shared/types/module-preferences';
import type {
  Signal,
  SignalType,
  SignalSummary,
  HostReachabilitySignal,
  PortStatusSignal,
  DnsResolutionSignal,
  OsDetectionSignal,
  UserEnumerationSignal,
  CrackedHashSignal,
} from '@shared/types/signal';
import type {
  SessionManifest,
  RestoreSessionInfo,
} from '@shared/types/persistence';

/** Callback type for session events */
type SessionOutputCallback = (event: IpcRendererEvent, data: { sessionId: string; data: string }) => void;
type SessionStatusCallback = (event: IpcRendererEvent, data: { sessionId: string; status: string; exitCode?: number }) => void;
type SessionCreatedCallback = (event: IpcRendererEvent, session: TerminalSession) => void;
type SessionUpdatedCallback = (event: IpcRendererEvent, session: TerminalSession) => void;

/** Callback types for discovery events */
type CredentialDiscoveredCallback = (event: IpcRendererEvent, data: { credential: Credential; sessionId: string; isHighValue: boolean }) => void;
type FindingDiscoveredCallback = (event: IpcRendererEvent, data: { finding: Finding; sessionId: string; isHighValue: boolean }) => void;

/** Callback types for signal events */
type SignalCallback<T extends Signal> = (event: IpcRendererEvent, data: { signal: T; sessionId: string; isHighValue: boolean }) => void;
type HostReachabilityCallback = SignalCallback<HostReachabilitySignal>;
type PortDiscoveredCallback = SignalCallback<PortStatusSignal>;
type DnsResolvedCallback = SignalCallback<DnsResolutionSignal>;
type OsDetectedCallback = SignalCallback<OsDetectionSignal>;
type UserEnumeratedCallback = SignalCallback<UserEnumerationSignal>;
type HashCrackedCallback = SignalCallback<CrackedHashSignal>;

/** API exposed to renderer */
const electronAPI = {
  // Neo4j
  healthCheck: () => ipcRenderer.invoke('neo4j-health-check'),
  getActiveEngagement: () => ipcRenderer.invoke('get-active-engagement'),
  getEngagement: (id: string) => ipcRenderer.invoke('get-engagement', id),

  // Sessions
  sessionCreate: (command: string, args: string[], options: CreateSessionOptions) =>
    ipcRenderer.invoke('session-create', command, args, options),
  sessionWrite: (sessionId: string, data: string) =>
    ipcRenderer.invoke('session-write', sessionId, data),
  sessionResize: (sessionId: string, cols: number, rows: number) =>
    ipcRenderer.invoke('session-resize', sessionId, cols, rows),
  sessionKill: (sessionId: string, signal?: string) =>
    ipcRenderer.invoke('session-kill', sessionId, signal),
  sessionBackground: (sessionId: string) =>
    ipcRenderer.invoke('session-background', sessionId),
  sessionForeground: (sessionId: string) =>
    ipcRenderer.invoke('session-foreground', sessionId),
  sessionGet: (sessionId: string) =>
    ipcRenderer.invoke('session-get', sessionId),
  sessionList: () =>
    ipcRenderer.invoke('session-list'),
  sessionListByType: (type: string) =>
    ipcRenderer.invoke('session-list-by-type', type),
  sessionListByTarget: (targetId: string) =>
    ipcRenderer.invoke('session-list-by-target', targetId),
  sessionGetOutput: (sessionId: string) =>
    ipcRenderer.invoke('session-get-output', sessionId),
  sessionLink: (sourceId: string, targetId: string) =>
    ipcRenderer.invoke('session-link', sourceId, targetId),
  sessionSetLabel: (sessionId: string, label: string) =>
    ipcRenderer.invoke('session-set-label', sessionId, label),
  sessionPrismScan: (sessionId: string, engagementId: string, targetId?: string): Promise<{
    credentials: Credential[];
    findings: Finding[];
  }> =>
    ipcRenderer.invoke('session-prism-scan', sessionId, engagementId, targetId),

  /** PRISM scan arbitrary text (from terminal selection) */
  prismScanText: (text: string, engagementId: string, targetId?: string, sessionId?: string): Promise<{
    credentials: Credential[];
    findings: Finding[];
  }> =>
    ipcRenderer.invoke('prism-scan-text', text, engagementId, targetId, sessionId),

  /** Set PRISM autoscan enabled state */
  prismSetAutoscan: (enabled: boolean): Promise<boolean> =>
    ipcRenderer.invoke('prism-set-autoscan', enabled),

  /** Get PRISM autoscan enabled state */
  prismGetAutoscan: (): Promise<boolean> =>
    ipcRenderer.invoke('prism-get-autoscan'),

  /** Get PRISM parser statistics */
  prismGetStats: (): Promise<{ enabled: boolean; sessions: number; dedup: { credentials: number; findings: number } }> =>
    ipcRenderer.invoke('prism-get-stats'),

  // =========================================================================
  // TMUX BACKEND (Phase 3)
  // =========================================================================

  /** Check if tmux is available on the system */
  tmuxIsAvailable: (): Promise<boolean> =>
    ipcRenderer.invoke('tmux-is-available'),

  /** List B.R.E.A.C.H. managed tmux sessions */
  tmuxListSessions: (): Promise<Array<{ name: string; created: Date; attached: boolean; windows: number }>> =>
    ipcRenderer.invoke('tmux-list-sessions'),

  /** Kill a specific tmux session */
  tmuxKillSession: (tmuxSession: string): Promise<boolean> =>
    ipcRenderer.invoke('tmux-kill-session', tmuxSession),

  /** Kill all B.R.E.A.C.H. tmux sessions */
  tmuxKillAll: (): Promise<number> =>
    ipcRenderer.invoke('tmux-kill-all'),

  // =========================================================================
  // SESSION PERSISTENCE / RESTORE
  // =========================================================================

  /** Get session manifest (list of engagements with persisted sessions) */
  sessionGetManifest: (): Promise<SessionManifest | null> =>
    ipcRenderer.invoke('session-get-manifest'),

  /** Get restore info for an engagement (lightweight, no output buffers) */
  sessionGetRestoreInfo: (engagementId: string): Promise<RestoreSessionInfo[]> =>
    ipcRenderer.invoke('session-get-restore-info', engagementId),

  /** Restore specific sessions */
  sessionRestore: (sessionIds: string[], engagementId: string): Promise<TerminalSession[]> =>
    ipcRenderer.invoke('session-restore', sessionIds, engagementId),

  /** Clear persisted sessions for an engagement */
  sessionClearPersisted: (engagementId: string): Promise<boolean> =>
    ipcRenderer.invoke('session-clear-persisted', engagementId),

  // Session event listeners
  onSessionOutput: (callback: SessionOutputCallback) => {
    ipcRenderer.on('session-output', callback);
  },
  removeSessionOutputListener: (callback: SessionOutputCallback) => {
    ipcRenderer.removeListener('session-output', callback);
  },
  onSessionStatus: (callback: SessionStatusCallback) => {
    ipcRenderer.on('session-status', callback);
  },
  removeSessionStatusListener: (callback: SessionStatusCallback) => {
    ipcRenderer.removeListener('session-status', callback);
  },
  onSessionCreated: (callback: SessionCreatedCallback) => {
    ipcRenderer.on('session-created', callback);
  },
  removeSessionCreatedListener: (callback: SessionCreatedCallback) => {
    ipcRenderer.removeListener('session-created', callback);
  },
  onSessionUpdated: (callback: SessionUpdatedCallback) => {
    ipcRenderer.on('session-updated', callback);
  },
  removeSessionUpdatedListener: (callback: SessionUpdatedCallback) => {
    ipcRenderer.removeListener('session-updated', callback);
  },

  // Targets
  targetList: (engagementId: string) =>
    ipcRenderer.invoke('target-list', engagementId),
  targetAdd: (engagementId: string, data: CreateTargetData): Promise<Target | { error: string } | null> =>
    ipcRenderer.invoke('target-add', engagementId, data),
  targetGet: (targetId: string) =>
    ipcRenderer.invoke('target-get', targetId),
  targetServices: (targetId: string) =>
    ipcRenderer.invoke('target-services', targetId),
  targetFindings: (targetId: string) =>
    ipcRenderer.invoke('target-findings', targetId),
  targetUpdateStatus: (targetId: string, status: string) =>
    ipcRenderer.invoke('target-update-status', targetId, status),

  // Credentials
  credentialList: (engagementId: string): Promise<Credential[]> =>
    ipcRenderer.invoke('credential-list', engagementId),
  credentialAdd: (credential: Omit<Credential, 'id' | 'createdAt'>): Promise<Credential> =>
    ipcRenderer.invoke('credential-add', credential),
  credentialUpdate: (id: string, updates: Partial<Credential>): Promise<boolean> =>
    ipcRenderer.invoke('credential-update', id, updates),
  credentialDelete: (id: string): Promise<boolean> =>
    ipcRenderer.invoke('credential-delete', id),
  credentialValidateAccess: (credentialId: string, serviceId: string, accessType: string): Promise<boolean> =>
    ipcRenderer.invoke('credential-validate-access', credentialId, serviceId, accessType),
  credentialByTarget: (targetId: string): Promise<Credential[]> =>
    ipcRenderer.invoke('credential-by-target', targetId),
  credentialGetAdmin: (engagementId: string): Promise<Credential[]> =>
    ipcRenderer.invoke('credential-get-admin', engagementId),

  // Loot
  lootList: (engagementId: string): Promise<Loot[]> =>
    ipcRenderer.invoke('loot-list', engagementId),
  lootAdd: (lootData: {
    name: string;
    path: string;
    sourcePath?: string;
    sourceSessionId: string;
    targetId: string;
    engagementId: string;
    content?: string;
    notes?: string;
  }): Promise<Loot> =>
    ipcRenderer.invoke('loot-add', lootData),
  lootGetContent: (id: string): Promise<{ content?: string; error?: string; truncated?: boolean; size?: number }> =>
    ipcRenderer.invoke('loot-get-content', id),
  lootDelete: (id: string, deleteFile?: boolean): Promise<boolean> =>
    ipcRenderer.invoke('loot-delete', id, deleteFile),
  lootByPattern: (engagementId: string, pattern: PatternType): Promise<Loot[]> =>
    ipcRenderer.invoke('loot-by-pattern', engagementId, pattern),
  lootGetFlags: (engagementId: string): Promise<Loot[]> =>
    ipcRenderer.invoke('loot-get-flags', engagementId),
  lootUpdateNotes: (id: string, notes: string): Promise<boolean> =>
    ipcRenderer.invoke('loot-update-notes', id, notes),

  // =========================================================================
  // FINDINGS
  // =========================================================================

  /** List all findings for an engagement */
  findingList: (engagementId: string): Promise<Finding[]> =>
    ipcRenderer.invoke('finding-list', engagementId),

  /** Add a new finding */
  findingAdd: (engagementId: string, findingData: CreateFindingData): Promise<Finding> =>
    ipcRenderer.invoke('finding-add', engagementId, findingData),

  /** Update a finding */
  findingUpdate: (id: string, updates: Partial<Finding>): Promise<boolean> =>
    ipcRenderer.invoke('finding-update', id, updates),

  /** Delete a finding */
  findingDelete: (id: string): Promise<boolean> =>
    ipcRenderer.invoke('finding-delete', id),

  /** Get findings by target */
  findingByTarget: (targetId: string): Promise<Finding[]> =>
    ipcRenderer.invoke('finding-by-target', targetId),

  /** Get findings summary (counts by severity) */
  findingSummary: (engagementId: string): Promise<FindingSummary> =>
    ipcRenderer.invoke('finding-summary', engagementId),

  // =========================================================================
  // DISCOVERY EVENT LISTENERS (from parser)
  // =========================================================================

  /** Listen for credential discoveries from terminal output parsing */
  onCredentialDiscovered: (callback: CredentialDiscoveredCallback) => {
    ipcRenderer.on('credential-discovered', callback);
  },
  removeCredentialDiscoveredListener: (callback: CredentialDiscoveredCallback) => {
    ipcRenderer.removeListener('credential-discovered', callback);
  },

  /** Listen for finding discoveries from terminal output parsing */
  onFindingDiscovered: (callback: FindingDiscoveredCallback) => {
    ipcRenderer.on('finding-discovered', callback);
  },
  removeFindingDiscoveredListener: (callback: FindingDiscoveredCallback) => {
    ipcRenderer.removeListener('finding-discovered', callback);
  },

  // Console bridge (renderer → terminal)
  logToTerminal: (level: string, message: string) =>
    ipcRenderer.send('log-to-terminal', level, message),

  // =========================================================================
  // ENGAGEMENTS
  // =========================================================================

  /** List all engagements */
  engagementList: (): Promise<Engagement[]> =>
    ipcRenderer.invoke('engagement-list'),

  /** Get engagement by ID */
  engagementGet: (id: string): Promise<Engagement | null> =>
    ipcRenderer.invoke('engagement-get', id),

  /** Create a new engagement */
  engagementCreate: (data: CreateEngagementData): Promise<Engagement | null> =>
    ipcRenderer.invoke('engagement-create', data),

  /** Activate an engagement (deactivates others) */
  engagementActivate: (id: string): Promise<Engagement | null> =>
    ipcRenderer.invoke('engagement-activate', id),

  /** Deactivate all engagements */
  engagementDeactivate: (): Promise<boolean> =>
    ipcRenderer.invoke('engagement-deactivate'),

  /** Update engagement status */
  engagementUpdateStatus: (id: string, status: EngagementStatus): Promise<boolean> =>
    ipcRenderer.invoke('engagement-update-status', id, status),

  /** Update engagement details */
  engagementUpdate: (id: string, updates: Partial<Engagement>): Promise<boolean> =>
    ipcRenderer.invoke('engagement-update', id, updates),

  /** Delete an engagement */
  engagementDelete: (id: string): Promise<{ success: boolean; error?: string }> =>
    ipcRenderer.invoke('engagement-delete', id),

  /** Get engagement statistics */
  engagementStats: (id: string): Promise<EngagementStats | null> =>
    ipcRenderer.invoke('engagement-stats', id),

  // =========================================================================
  // ACTIONS (Command database queries)
  // =========================================================================

  /** Get enriched category data from Neo4j command database */
  actionsGetCategory: (categoryId: string): Promise<{
    id: string;
    tools: Array<{
      id: string;
      name: string;
      variants: Array<{
        id: string;
        label: string;
        command: string;
        description?: string;
        oscpRelevance?: string;
      }>;
    }>;
  } | null> =>
    ipcRenderer.invoke('actions-get-category', categoryId),

  /** Search commands by query string */
  actionsSearch: (query: string): Promise<Array<{
    id: string;
    name: string;
    command: string;
    description?: string;
    category?: string;
    oscpRelevance?: string;
  }>> =>
    ipcRenderer.invoke('actions-search', query),

  /** Get detailed command information */
  actionsGetCommand: (commandId: string): Promise<{
    id: string;
    name: string;
    command: string;
    description?: string;
    flags?: Array<{ flag: string; explanation: string }>;
    variables?: Array<{ name: string; description: string; example?: string }>;
  } | null> =>
    ipcRenderer.invoke('actions-get-command', commandId),

  // =========================================================================
  // MODULES (Dynamic command modules from Neo4j)
  // =========================================================================

  /** List available modules with command counts */
  modulesList: (): Promise<ModuleMetadata[]> =>
    ipcRenderer.invoke('modules-list'),

  /** Load a single module's commands (lazy load) */
  modulesLoad: (moduleId: string): Promise<CommandModule | null> =>
    ipcRenderer.invoke('modules-load', moduleId),

  /** Batch load multiple modules */
  modulesLoadBatch: (moduleIds: string[]): Promise<Record<string, CommandModule>> =>
    ipcRenderer.invoke('modules-load-batch', moduleIds),

  /** Global search across all commands in Neo4j */
  commandsSearchGlobal: (options: {
    query: string;
    filters: {
      name: boolean;
      command: boolean;
      description: boolean;
      tags: boolean;
      oscpHigh: boolean;
    };
    filterLogic: 'AND' | 'OR';
    limit?: number;
  }): Promise<
    Array<{
      id: string;
      name: string;
      command: string;
      description?: string;
      category?: string;
      subcategory?: string;
      oscpRelevance?: string;
    }>
  > => ipcRenderer.invoke('commands-search-global', options),

  // =========================================================================
  // SIGNALS (Network recon, enumeration, hash cracking)
  // =========================================================================

  /** List signals by engagement, optionally filtered by type */
  signalList: (engagementId: string, type?: SignalType): Promise<Signal[]> =>
    ipcRenderer.invoke('signals:list', engagementId, type),

  /** Get host reachability signals (ping results) */
  signalReachability: (engagementId: string): Promise<HostReachabilitySignal[]> =>
    ipcRenderer.invoke('signals:reachability', engagementId),

  /** Get port status signals */
  signalPorts: (engagementId: string, targetIp?: string): Promise<PortStatusSignal[]> =>
    ipcRenderer.invoke('signals:ports', engagementId, targetIp),

  /** Get open ports only */
  signalOpenPorts: (engagementId: string, targetIp?: string): Promise<PortStatusSignal[]> =>
    ipcRenderer.invoke('signals:open-ports', engagementId, targetIp),

  /** Get DNS resolution signals */
  signalDns: (engagementId: string): Promise<DnsResolutionSignal[]> =>
    ipcRenderer.invoke('signals:dns', engagementId),

  /** Get OS detection signals */
  signalOs: (engagementId: string, targetIp?: string): Promise<OsDetectionSignal[]> =>
    ipcRenderer.invoke('signals:os', engagementId, targetIp),

  /** Get user enumeration signals */
  signalUsers: (engagementId: string): Promise<UserEnumerationSignal[]> =>
    ipcRenderer.invoke('signals:users', engagementId),

  /** Get cracked hash signals */
  signalCrackedHashes: (engagementId: string): Promise<CrackedHashSignal[]> =>
    ipcRenderer.invoke('signals:cracked-hashes', engagementId),

  /** Get signal summary (counts) */
  signalSummary: (engagementId: string): Promise<SignalSummary> =>
    ipcRenderer.invoke('signals:summary', engagementId),

  /** Get signals by target */
  signalByTarget: (engagementId: string, targetId: string): Promise<Signal[]> =>
    ipcRenderer.invoke('signals:by-target', engagementId, targetId),

  /** Get parser statistics */
  signalParserStats: (): Promise<{
    networkParser: { enabled: boolean; sessions: number; signalCounts: Record<string, number> };
    potfileWatcher: { enabled: boolean; watchedFiles: string[]; seenHashesCount: number };
  }> =>
    ipcRenderer.invoke('signals:parser-stats'),

  /** Start potfile watcher */
  signalStartPotfileWatcher: (engagementId: string): Promise<{ success: boolean; error?: string }> =>
    ipcRenderer.invoke('signals:start-potfile-watcher', engagementId),

  /** Stop potfile watcher */
  signalStopPotfileWatcher: (): Promise<{ success: boolean; error?: string }> =>
    ipcRenderer.invoke('signals:stop-potfile-watcher'),

  /** Add custom potfile to watch */
  signalAddPotfile: (path: string, type: 'hashcat' | 'john'): Promise<{ success: boolean; error?: string }> =>
    ipcRenderer.invoke('signals:add-potfile', path, type),

  // =========================================================================
  // SIGNAL EVENT LISTENERS
  // =========================================================================

  /** Listen for host reachability discoveries */
  onHostReachability: (callback: HostReachabilityCallback) => {
    ipcRenderer.on('host-reachability', callback);
  },
  removeHostReachabilityListener: (callback: HostReachabilityCallback) => {
    ipcRenderer.removeListener('host-reachability', callback);
  },

  /** Listen for port discoveries */
  onPortDiscovered: (callback: PortDiscoveredCallback) => {
    ipcRenderer.on('port-discovered', callback);
  },
  removePortDiscoveredListener: (callback: PortDiscoveredCallback) => {
    ipcRenderer.removeListener('port-discovered', callback);
  },

  /** Listen for DNS resolution discoveries */
  onDnsResolved: (callback: DnsResolvedCallback) => {
    ipcRenderer.on('dns-resolved', callback);
  },
  removeDnsResolvedListener: (callback: DnsResolvedCallback) => {
    ipcRenderer.removeListener('dns-resolved', callback);
  },

  /** Listen for OS detection discoveries */
  onOsDetected: (callback: OsDetectedCallback) => {
    ipcRenderer.on('os-detected', callback);
  },
  removeOsDetectedListener: (callback: OsDetectedCallback) => {
    ipcRenderer.removeListener('os-detected', callback);
  },

  /** Listen for user enumeration discoveries */
  onUserEnumerated: (callback: UserEnumeratedCallback) => {
    ipcRenderer.on('user-enumerated', callback);
  },
  removeUserEnumeratedListener: (callback: UserEnumeratedCallback) => {
    ipcRenderer.removeListener('user-enumerated', callback);
  },

  /** Listen for cracked hash discoveries */
  onHashCracked: (callback: HashCrackedCallback) => {
    ipcRenderer.on('hash-cracked', callback);
  },
  removeHashCrackedListener: (callback: HashCrackedCallback) => {
    ipcRenderer.removeListener('hash-cracked', callback);
  },

  /** Listen for host identity discoveries */
  onHostIdentity: (callback: SignalCallback<Signal>) => {
    ipcRenderer.on('host-identity', callback);
  },
  removeHostIdentityListener: (callback: SignalCallback<Signal>) => {
    ipcRenderer.removeListener('host-identity', callback);
  },
};

// Expose to renderer
contextBridge.exposeInMainWorld('electronAPI', electronAPI);

// TypeScript type definitions
export type ElectronAPI = typeof electronAPI;

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
