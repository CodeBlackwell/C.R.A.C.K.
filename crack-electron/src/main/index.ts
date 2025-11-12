import { app, BrowserWindow } from 'electron';
import path from 'node:path';
import { debug, logElectron, logStartup } from './debug';
import './neo4j'; // Initialize Neo4j IPC handlers

logStartup('Electron main process initializing');

process.env.DIST = path.join(__dirname, '../..');
process.env.VITE_PUBLIC = app.isPackaged
  ? process.env.DIST
  : path.join(process.env.DIST, '../public');

logStartup('Environment configured', {
  DIST: process.env.DIST,
  VITE_PUBLIC: process.env.VITE_PUBLIC,
  packaged: app.isPackaged,
});

let win: BrowserWindow | null;

const VITE_DEV_SERVER_URL = process.env['VITE_DEV_SERVER_URL'];

function createWindow() {
  logElectron('Creating browser window', {
    width: 1400,
    height: 900,
    devServer: VITE_DEV_SERVER_URL,
  });

  win = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
    backgroundColor: '#1a1b1e', // Mantine dark theme background
    title: 'CRACK - Command Graph Visualizer',
  });

  logElectron('Browser window created successfully');

  // Test active push message to Renderer-process.
  win.webContents.on('did-finish-load', () => {
    logElectron('Renderer finished loading');
    win?.webContents.send('main-process-message', new Date().toLocaleString());
  });

  win.webContents.on('crashed', () => {
    logElectron('Renderer process crashed!');
  });

  win.on('unresponsive', () => {
    logElectron('Window became unresponsive');
  });

  win.on('responsive', () => {
    logElectron('Window became responsive again');
  });

  if (VITE_DEV_SERVER_URL) {
    logElectron('Loading dev server URL', { url: VITE_DEV_SERVER_URL });
    win.loadURL(VITE_DEV_SERVER_URL);
    win.webContents.openDevTools();
    logElectron('DevTools opened');
  } else {
    const htmlPath = path.join(process.env.DIST!, 'index.html');
    logElectron('Loading production HTML', { path: htmlPath });
    win.loadFile(htmlPath);
  }
}

app.whenReady().then(() => {
  debug.section('ELECTRON APP READY');
  logStartup('Electron app ready - creating window');
  createWindow();
});

app.on('window-all-closed', () => {
  logElectron('All windows closed', { platform: process.platform });
  if (process.platform !== 'darwin') {
    logElectron('Quitting application (non-macOS)');
    app.quit();
  }
});

app.on('activate', () => {
  logElectron('App activated');
  if (BrowserWindow.getAllWindows().length === 0) {
    logElectron('No windows open - creating new window');
    createWindow();
  }
});

process.on('uncaughtException', (error) => {
  logElectron('UNCAUGHT EXCEPTION', error);
  console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason) => {
  logElectron('UNHANDLED REJECTION', reason);
  console.error('Unhandled Rejection:', reason);
});
