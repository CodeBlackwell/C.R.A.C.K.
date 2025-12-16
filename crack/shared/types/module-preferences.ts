/**
 * Module Preferences Types
 *
 * Defines user preferences for which action modules to display in ActionsPanel.
 * Modules can be enabled/disabled and pinned to always show regardless of service detection.
 */

/** Service match display mode */
export type ServiceMatchMode = 'relevant' | 'all_enabled';

/** Module category identifiers matching ACTION_CATEGORIES */
export type ModuleId =
  | 'port-scan'
  | 'smb'
  | 'http'
  | 'ldap'
  | 'ssh'
  | 'ftp'
  | 'mssql'
  | 'mysql'
  | 'rdp'
  | 'winrm'
  | 'dns'
  | 'snmp'
  | 'nfs'
  | 'kerberos'
  | 'active-directory';

/** Module preference entry */
export interface ModulePreference {
  id: ModuleId;
  enabled: boolean;
  pinned: boolean; // Always show regardless of service detection
}

/** User's module preferences */
export interface ModulePreferences {
  modules: ModulePreference[];
  lastUpdated: string; // ISO timestamp
  serviceMatchMode: ServiceMatchMode; // 'relevant' = show only service-matched, 'all_enabled' = show all enabled
}

/** All available module IDs */
export const ALL_MODULE_IDS: ModuleId[] = [
  'port-scan',
  'smb',
  'http',
  'ldap',
  'ssh',
  'ftp',
  'mssql',
  'mysql',
  'rdp',
  'winrm',
  'dns',
  'snmp',
  'nfs',
  'kerberos',
  'active-directory',
];

/** Default preferences - all modules enabled, only port-scan pinned */
export const DEFAULT_MODULE_PREFERENCES: ModulePreferences = {
  modules: [
    { id: 'port-scan', enabled: true, pinned: true },
    { id: 'active-directory', enabled: true, pinned: false },
    { id: 'smb', enabled: true, pinned: false },
    { id: 'http', enabled: true, pinned: false },
    { id: 'ldap', enabled: true, pinned: false },
    { id: 'ssh', enabled: true, pinned: false },
    { id: 'ftp', enabled: true, pinned: false },
    { id: 'mssql', enabled: true, pinned: false },
    { id: 'mysql', enabled: true, pinned: false },
    { id: 'rdp', enabled: true, pinned: false },
    { id: 'winrm', enabled: true, pinned: false },
    { id: 'dns', enabled: true, pinned: false },
    { id: 'snmp', enabled: true, pinned: false },
    { id: 'nfs', enabled: true, pinned: false },
    { id: 'kerberos', enabled: true, pinned: false },
  ],
  lastUpdated: new Date().toISOString(),
  serviceMatchMode: 'relevant',
};

/** Module groupings for UI organization */
export const MODULE_GROUPS: Record<string, ModuleId[]> = {
  'Always Available': ['port-scan'],
  'Directory Services': ['ldap', 'kerberos', 'active-directory'],
  'Network Services': ['smb', 'ssh', 'ftp', 'rdp', 'winrm', 'nfs'],
  Web: ['http'],
  Databases: ['mssql', 'mysql'],
  Other: ['dns', 'snmp'],
};

/** Module metadata from Neo4j (lightweight, for listing) */
export interface ModuleMetadata {
  id: string;
  name: string;
  commandCount: number;
}

/** Command variant for action execution */
export interface CommandVariant {
  id: string;
  label: string;
  command: string;
  description?: string;
  oscpRelevance?: 'high' | 'medium' | 'low';
  flagExplanations?: Record<string, string>;
}

/** Tool grouping within a module */
export interface CommandTool {
  id: string;
  name: string;
  variants: CommandVariant[];
}

/** Full module with loaded commands */
export interface CommandModule {
  id: string;
  name: string;
  commandCount: number;
  tools: CommandTool[];
}
