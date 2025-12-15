/**
 * Session IPC Handlers
 *
 * IPC handlers for terminal session management.
 */

import { ipcMain } from 'electron';
import { ptyManager, setPtyMainWindow as setPtyWindow } from '../pty/manager';
import { debug } from '../debug';
import type { CreateSessionOptions } from '@shared/types/session';

/** Export setPtyMainWindow for main process */
export { setPtyWindow as setPtyMainWindow };

/** Register all session-related IPC handlers */
export function registerSessionHandlers(): void {
  debug.ipc('Registering session IPC handlers');

  // Create a new session
  ipcMain.handle(
    'session-create',
    async (_, command: string, args: string[], options: CreateSessionOptions) => {
      debug.ipc('session-create called', { command, args, options });
      try {
        const session = await ptyManager.createSession(command, args, options);
        debug.ipc('session-create completed', { sessionId: session.id });
        return session;
      } catch (error) {
        debug.error('session-create failed', error);
        throw error;
      }
    }
  );

  // Write to session stdin
  ipcMain.handle('session-write', (_, sessionId: string, data: string) => {
    return ptyManager.write(sessionId, data);
  });

  // Resize session terminal
  ipcMain.handle('session-resize', (_, sessionId: string, cols: number, rows: number) => {
    return ptyManager.resize(sessionId, cols, rows);
  });

  // Kill a session
  ipcMain.handle('session-kill', (_, sessionId: string, signal?: string) => {
    debug.ipc('session-kill called', { sessionId, signal });
    return ptyManager.kill(sessionId, signal);
  });

  // Background a session
  ipcMain.handle('session-background', (_, sessionId: string) => {
    return ptyManager.background(sessionId);
  });

  // Foreground a session
  ipcMain.handle('session-foreground', (_, sessionId: string) => {
    return ptyManager.foreground(sessionId);
  });

  // Get single session
  ipcMain.handle('session-get', (_, sessionId: string) => {
    return ptyManager.getSession(sessionId);
  });

  // List all sessions
  ipcMain.handle('session-list', () => {
    return ptyManager.getAllSessions();
  });

  // Get sessions by type
  ipcMain.handle('session-list-by-type', (_, type: string) => {
    return ptyManager.getSessionsByType(type as any);
  });

  // Get sessions by target
  ipcMain.handle('session-list-by-target', (_, targetId: string) => {
    return ptyManager.getSessionsByTarget(targetId);
  });

  // Get session output buffer
  ipcMain.handle('session-get-output', (_, sessionId: string) => {
    return ptyManager.getOutputBuffer(sessionId);
  });

  // Link sessions
  ipcMain.handle('session-link', (_, sourceId: string, targetId: string) => {
    return ptyManager.linkSessions(sourceId, targetId);
  });

  // Set session label
  ipcMain.handle('session-set-label', (_, sessionId: string, label: string) => {
    return ptyManager.setSessionLabel(sessionId, label);
  });

  debug.ipc('Session IPC handlers registered');
}
