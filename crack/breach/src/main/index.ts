/**
 * B.R.E.A.C.H. - Electron Main Process
 *
 * Box Reconnaissance, Exploitation & Attack Command Hub
 */

import { app, BrowserWindow, dialog } from 'electron';
import path from 'path';
import { debug } from './debug';
import { registerSessionHandlers, setPtyMainWindow } from './ipc/sessions';
import { registerTargetHandlers } from './ipc/targets';
import { registerNeo4jHandlers } from './ipc/neo4j';
import { registerCredentialHandlers } from './ipc/credentials';
import { registerLootHandlers } from './ipc/loot';
import { registerEngagementHandlers } from './ipc/engagements';
import { registerActionsHandlers } from './ipc/actions';
import { registerFindingHandlers } from './ipc/findings';
import { registerSignalHandlers } from './ipc/signals';
import { registerModulesHandlers } from './ipc/modules';
import { getPotfileWatcher } from './parser';
import { ptyManager } from './pty/manager';
import { tmuxBackend } from './pty/tmux-backend';

debug.section('B.R.E.A.C.H. STARTUP');

// Vite dev server URL
const VITE_DEV_SERVER_URL = process.env['VITE_DEV_SERVER_URL'];

let mainWindow: BrowserWindow | null = null;

async function createWindow(): Promise<void> {
  debug.startup('Creating main window');

  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 800,
    title: 'B.R.E.A.C.H.',
    backgroundColor: '#1a1b1e',
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: false, // Allow file:// URLs for local resources
    },
  });

  // Set window reference for PTY manager
  setPtyMainWindow(mainWindow);

  // Load the app
  if (VITE_DEV_SERVER_URL) {
    debug.startup('Loading dev server', { url: VITE_DEV_SERVER_URL });
    await mainWindow.loadURL(VITE_DEV_SERVER_URL);
    // Open DevTools docked to avoid separate window
    mainWindow.webContents.openDevTools({ mode: 'bottom' });
  } else {
    debug.startup('Loading production build');
    await mainWindow.loadFile(path.join(__dirname, '../../dist/index.html'));
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  debug.startup('Main window created successfully');
}

// App lifecycle
app.whenReady().then(async () => {
  debug.startup('Electron app ready');

  // Register IPC handlers
  debug.subsection('Registering IPC Handlers');
  registerNeo4jHandlers();
  registerSessionHandlers();
  registerTargetHandlers();
  registerCredentialHandlers();
  registerLootHandlers();
  registerEngagementHandlers();
  registerActionsHandlers();
  registerFindingHandlers();
  registerSignalHandlers();
  registerModulesHandlers();

  // Create main window
  await createWindow();

  app.on('activate', async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      await createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  debug.startup('All windows closed');
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Track if we're already quitting (to prevent double-save)
let isQuitting = false;

app.on('before-quit', async (event) => {
  if (isQuitting) return;

  // Prevent default to show dialog
  event.preventDefault();

  const sessions = ptyManager.getAllSessions();
  const tmuxSessions = await tmuxBackend.listSessions();
  const hasActiveSessions = sessions.length > 0 || tmuxSessions.length > 0;

  // If no active sessions, just quit
  if (!hasActiveSessions) {
    isQuitting = true;
    app.exit();
    return;
  }

  // Build message with session counts
  let message = 'You have active sessions:\n';
  if (sessions.length > 0) {
    message += `• ${sessions.length} terminal session${sessions.length > 1 ? 's' : ''}\n`;
  }
  if (tmuxSessions.length > 0) {
    message += `• ${tmuxSessions.length} persistent tmux session${tmuxSessions.length > 1 ? 's' : ''}\n`;
  }
  message += '\nWhat would you like to do?';

  debug.startup('Showing quit confirmation dialog', {
    sessions: sessions.length,
    tmuxSessions: tmuxSessions.length,
  });

  const { response } = await dialog.showMessageBox(mainWindow!, {
    type: 'question',
    buttons: ['Keep Running', 'Kill All', 'Cancel'],
    defaultId: 0,
    cancelId: 2,
    title: 'Exit B.R.E.A.C.H.',
    message: 'Exit Application?',
    detail: message,
  });

  if (response === 2) {
    // Cancel - abort quit
    debug.startup('Quit cancelled by user');
    return;
  }

  isQuitting = true;

  debug.startup('Application quitting - persisting sessions...');

  try {
    // Persist all active sessions before quitting
    await ptyManager.persistAll();
    debug.startup('Sessions persisted successfully');
  } catch (error) {
    debug.error('Failed to persist sessions', error);
  }

  if (response === 1) {
    // Kill All - terminate all processes including tmux
    debug.startup('Killing all sessions including tmux');
    await tmuxBackend.killAllSessions();
    await ptyManager.cleanup();
  } else {
    // Keep Running - just detach PTY but leave tmux running
    debug.startup('Keeping tmux sessions alive');
    await ptyManager.cleanup();
  }

  // Now actually quit
  app.exit();
});

debug.startup('Main process initialized');
