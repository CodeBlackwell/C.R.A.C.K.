/**
 * Mock for electron module
 *
 * Business Value Focus:
 * - Enables testing IPC handlers in isolation
 * - Tracks handler registration and invocations
 * - Simulates Electron's IPC mechanism
 */

import { vi } from 'vitest';

type IpcHandler = (event: any, ...args: any[]) => Promise<any> | any;
type IpcListener = (event: any, ...args: any[]) => void;

/**
 * Registry for IPC handlers
 */
class IpcHandlerRegistry {
  private handlers: Map<string, IpcHandler> = new Map();
  private listeners: Map<string, IpcListener[]> = new Map();

  /**
   * Register a handler for an IPC channel
   */
  handle(channel: string, handler: IpcHandler): void {
    this.handlers.set(channel, handler);
  }

  /**
   * Remove handler for an IPC channel
   */
  removeHandler(channel: string): void {
    this.handlers.delete(channel);
  }

  /**
   * Register a listener for one-way IPC messages
   */
  on(channel: string, listener: IpcListener): void {
    const existing = this.listeners.get(channel) || [];
    existing.push(listener);
    this.listeners.set(channel, existing);
  }

  /**
   * Invoke a registered handler
   */
  async invoke(channel: string, ...args: any[]): Promise<any> {
    const handler = this.handlers.get(channel);
    if (!handler) {
      throw new Error(`No handler registered for channel: ${channel}`);
    }
    return handler({}, ...args);
  }

  /**
   * Send a one-way message to listeners
   */
  send(channel: string, ...args: any[]): void {
    const listeners = this.listeners.get(channel) || [];
    listeners.forEach(listener => listener({}, ...args));
  }

  /**
   * Get all registered handler channels
   */
  getRegisteredChannels(): string[] {
    return Array.from(this.handlers.keys());
  }

  /**
   * Check if a handler is registered
   */
  hasHandler(channel: string): boolean {
    return this.handlers.has(channel);
  }

  /**
   * Clear all handlers and listeners
   */
  clear(): void {
    this.handlers.clear();
    this.listeners.clear();
  }

  /**
   * Get handler for a channel (for testing)
   */
  getHandler(channel: string): IpcHandler | undefined {
    return this.handlers.get(channel);
  }
}

// Singleton registry instance
const registry = new IpcHandlerRegistry();

/**
 * Mock ipcMain object
 */
export const ipcMain = {
  handle: vi.fn((channel: string, handler: IpcHandler) => {
    registry.handle(channel, handler);
  }),
  removeHandler: vi.fn((channel: string) => {
    registry.removeHandler(channel);
  }),
  on: vi.fn((channel: string, listener: IpcListener) => {
    registry.on(channel, listener);
  }),
};

/**
 * Mock ipcRenderer object
 */
export const ipcRenderer = {
  invoke: vi.fn(async (channel: string, ...args: any[]) => {
    return registry.invoke(channel, ...args);
  }),
  send: vi.fn((channel: string, ...args: any[]) => {
    registry.send(channel, ...args);
  }),
  on: vi.fn(),
  once: vi.fn(),
  removeListener: vi.fn(),
  removeAllListeners: vi.fn(),
};

/**
 * Mock contextBridge object
 */
export const contextBridge = {
  exposeInMainWorld: vi.fn(),
};

/**
 * Mock app object
 */
export const app = {
  getPath: vi.fn((name: string) => `/mock/path/${name}`),
  quit: vi.fn(),
  on: vi.fn(),
  whenReady: vi.fn().mockResolvedValue(undefined),
};

/**
 * Mock BrowserWindow class
 */
export const BrowserWindow = vi.fn().mockImplementation(() => ({
  loadURL: vi.fn(),
  loadFile: vi.fn(),
  on: vi.fn(),
  webContents: {
    send: vi.fn(),
    on: vi.fn(),
    openDevTools: vi.fn(),
  },
  show: vi.fn(),
  close: vi.fn(),
}));

/**
 * Helper to get the registry for test assertions
 */
export function getIpcRegistry(): IpcHandlerRegistry {
  return registry;
}

/**
 * Helper to clear all registrations between tests
 */
export function clearIpcRegistry(): void {
  registry.clear();
}

/**
 * Helper to invoke a handler directly for testing
 */
export async function invokeHandler(channel: string, ...args: any[]): Promise<any> {
  return registry.invoke(channel, ...args);
}

/**
 * Default export for module mocking
 */
export default {
  ipcMain,
  ipcRenderer,
  contextBridge,
  app,
  BrowserWindow,
};
