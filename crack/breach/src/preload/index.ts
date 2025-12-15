/**
 * B.R.E.A.C.H. Preload Script
 *
 * Secure context bridge exposing IPC handlers to renderer process.
 */

import { contextBridge, ipcRenderer, IpcRendererEvent } from 'electron';
import type { TerminalSession, CreateSessionOptions } from '@shared/types/session';

/** Callback type for session events */
type SessionOutputCallback = (event: IpcRendererEvent, data: { sessionId: string; data: string }) => void;
type SessionStatusCallback = (event: IpcRendererEvent, data: { sessionId: string; status: string; exitCode?: number }) => void;
type SessionCreatedCallback = (event: IpcRendererEvent, session: TerminalSession) => void;
type SessionUpdatedCallback = (event: IpcRendererEvent, session: TerminalSession) => void;

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
  targetGet: (targetId: string) =>
    ipcRenderer.invoke('target-get', targetId),
  targetServices: (targetId: string) =>
    ipcRenderer.invoke('target-services', targetId),
  targetFindings: (targetId: string) =>
    ipcRenderer.invoke('target-findings', targetId),
  targetUpdateStatus: (targetId: string, status: string) =>
    ipcRenderer.invoke('target-update-status', targetId, status),

  // Console bridge (renderer → terminal)
  logToTerminal: (level: string, message: string) =>
    ipcRenderer.send('log-to-terminal', level, message),
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
