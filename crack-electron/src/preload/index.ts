import { contextBridge, ipcRenderer } from 'electron';

// Expose protected methods that allow the renderer process to use ipcRenderer
contextBridge.exposeInMainWorld('electronAPI', {
  searchCommands: (query: string, filters?: any) =>
    ipcRenderer.invoke('search-commands', query, filters),

  getCommand: (commandId: string) =>
    ipcRenderer.invoke('get-command', commandId),

  getGraph: (commandId: string) =>
    ipcRenderer.invoke('get-graph', commandId),

  getCategoryHierarchy: () =>
    ipcRenderer.invoke('get-category-hierarchy'),

  healthCheck: () =>
    ipcRenderer.invoke('neo4j-health-check'),

  searchCheatsheets: (query: string, filters?: any) =>
    ipcRenderer.invoke('search-cheatsheets', query, filters),

  getCheatsheet: (cheatsheetId: string) =>
    ipcRenderer.invoke('get-cheatsheet', cheatsheetId),

  // Console bridge - send renderer logs to terminal
  logToTerminal: (level: string, message: string) =>
    ipcRenderer.send('log-to-terminal', level, message),
});

// Type definitions for TypeScript
export interface ElectronAPI {
  searchCommands: (query: string, filters?: {
    category?: string;
    subcategory?: string;
    tags?: string[];
    oscp_only?: boolean;
  }) => Promise<any[]>;
  getCommand: (commandId: string) => Promise<any>;
  getGraph: (commandId: string) => Promise<any>;
  getCategoryHierarchy: () => Promise<any[]>;
  healthCheck: () => Promise<{ connected: boolean; uri?: string; error?: string }>;
  searchCheatsheets: (query: string, filters?: {
    tags?: string[];
  }) => Promise<any[]>;
  getCheatsheet: (cheatsheetId: string) => Promise<any>;
  logToTerminal: (level: string, message: string) => void;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
