/**
 * Vitest Setup File
 *
 * Initializes mocks and test utilities before each test run.
 * Ensures isolated, deterministic test execution.
 */

import { vi, beforeEach, afterEach } from 'vitest';

// Mock electron module globally
vi.mock('electron', () => ({
  ipcMain: {
    handle: vi.fn(),
    on: vi.fn(),
    removeHandler: vi.fn(),
  },
  BrowserWindow: {
    getAllWindows: vi.fn(() => []),
    fromWebContents: vi.fn(),
  },
  app: {
    getPath: vi.fn((name: string) => `/tmp/breach-test/${name}`),
    getName: vi.fn(() => 'breach-test'),
    getVersion: vi.fn(() => '0.1.0-test'),
  },
}));

// Mock Neo4j query module
vi.mock('@shared/neo4j/query', () => ({
  runQuery: vi.fn(),
  runWrite: vi.fn(),
  runQuerySingle: vi.fn(),
  runQuerySafe: vi.fn(),
  neo4jDriver: {
    getSession: vi.fn(),
    close: vi.fn(),
  },
}));

// Mock node-pty
vi.mock('node-pty', () => ({
  spawn: vi.fn(() => ({
    pid: 12345,
    onData: vi.fn(),
    onExit: vi.fn(),
    write: vi.fn(),
    resize: vi.fn(),
    kill: vi.fn(),
  })),
}));

// Mock fs module for loot tests
vi.mock('fs', async () => {
  const actual = await vi.importActual('fs');
  return {
    ...actual,
    existsSync: vi.fn(() => true),
    readFileSync: vi.fn(() => 'mock file content'),
    statSync: vi.fn(() => ({ size: 100 })),
    unlinkSync: vi.fn(),
  };
});

// Reset mocks between tests
beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

// Console spy helpers for debug output validation
export const consoleSpy = {
  log: vi.spyOn(console, 'log').mockImplementation(() => {}),
  error: vi.spyOn(console, 'error').mockImplementation(() => {}),
  warn: vi.spyOn(console, 'warn').mockImplementation(() => {}),
};
