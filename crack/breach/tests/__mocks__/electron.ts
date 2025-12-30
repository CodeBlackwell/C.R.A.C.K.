/**
 * Electron Mock for Vitest
 *
 * Provides mock implementations for Electron APIs used in IPC handlers.
 * Enables testing main process code without actual Electron runtime.
 */

import { vi } from 'vitest';

/**
 * Captured IPC handlers for test assertions
 */
export const capturedHandlers = new Map<string, Function>();

/**
 * Mock ipcMain module
 */
export const ipcMain = {
  /**
   * Capture registered handlers for testing
   */
  handle: vi.fn((channel: string, handler: Function) => {
    capturedHandlers.set(channel, handler);
  }),

  /**
   * Event listener registration
   */
  on: vi.fn(),

  /**
   * Remove a handler
   */
  removeHandler: vi.fn((channel: string) => {
    capturedHandlers.delete(channel);
  }),

  /**
   * Remove all handlers
   */
  removeAllListeners: vi.fn(() => {
    capturedHandlers.clear();
  }),
};

/**
 * Mock BrowserWindow for event emission
 */
const mockWebContents = {
  send: vi.fn(),
  isDestroyed: vi.fn(() => false),
};

const mockWindow = {
  webContents: mockWebContents,
  isDestroyed: vi.fn(() => false),
  id: 1,
};

export const BrowserWindow = {
  getAllWindows: vi.fn(() => [mockWindow]),
  fromWebContents: vi.fn(() => mockWindow),
  fromId: vi.fn(() => mockWindow),
};

/**
 * Mock app module
 */
export const app = {
  getPath: vi.fn((name: string) => `/tmp/breach-test/${name}`),
  getName: vi.fn(() => 'breach-test'),
  getVersion: vi.fn(() => '0.1.0-test'),
  isPackaged: false,
  quit: vi.fn(),
  exit: vi.fn(),
  on: vi.fn(),
  whenReady: vi.fn(() => Promise.resolve()),
};

/**
 * Mock dialog module
 */
export const dialog = {
  showOpenDialog: vi.fn(() => Promise.resolve({ filePaths: [], canceled: true })),
  showSaveDialog: vi.fn(() => Promise.resolve({ filePath: undefined, canceled: true })),
  showMessageBox: vi.fn(() => Promise.resolve({ response: 0 })),
};

/**
 * Mock shell module
 */
export const shell = {
  openExternal: vi.fn(() => Promise.resolve()),
  openPath: vi.fn(() => Promise.resolve('')),
  showItemInFolder: vi.fn(),
};

/**
 * Helper to get a registered handler for testing
 */
export function getHandler(channel: string): Function | undefined {
  return capturedHandlers.get(channel);
}

/**
 * Helper to invoke a registered handler with test data
 */
export async function invokeHandler<T>(
  channel: string,
  ...args: unknown[]
): Promise<T> {
  const handler = capturedHandlers.get(channel);
  if (!handler) {
    throw new Error(`No handler registered for channel: ${channel}`);
  }
  // First arg is IpcMainInvokeEvent (mocked as empty object)
  return handler({}, ...args) as Promise<T>;
}

/**
 * Reset all captured handlers and mocks
 */
export function resetElectronMocks(): void {
  capturedHandlers.clear();
  ipcMain.handle.mockClear();
  ipcMain.on.mockClear();
  ipcMain.removeHandler.mockClear();
  BrowserWindow.getAllWindows.mockClear();
  mockWebContents.send.mockClear();
}

/**
 * Get the mock webContents for asserting events
 */
export function getMockWebContents() {
  return mockWebContents;
}

export default {
  ipcMain,
  BrowserWindow,
  app,
  dialog,
  shell,
};
