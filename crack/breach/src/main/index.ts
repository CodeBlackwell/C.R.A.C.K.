/**
 * B.R.E.A.C.H. - Electron Main Process
 *
 * Box Reconnaissance, Exploitation & Attack Command Hub
 */

import { app, BrowserWindow } from 'electron';
import path from 'path';
import { debug } from './debug';
import { registerSessionHandlers, setPtyMainWindow } from './ipc/sessions';
import { registerTargetHandlers } from './ipc/targets';
import { registerNeo4jHandlers } from './ipc/neo4j';
import { registerCredentialHandlers } from './ipc/credentials';
import { registerLootHandlers } from './ipc/loot';
import { registerEngagementHandlers } from './ipc/engagements';
import { registerActionsHandlers } from './ipc/actions';

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

app.on('before-quit', () => {
  debug.startup('Application quitting');
  // Cleanup will be handled by PtyManager
});

debug.startup('Main process initialized');
