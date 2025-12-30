/**
 * PTY Mock for Vitest
 *
 * Provides mock implementations for node-pty and PTY manager.
 * Enables testing session handlers without actual terminal spawning.
 */

import { vi } from 'vitest';
import type { TerminalSession, SessionStatus, CreateSessionOptions } from '@shared/types/session';

/**
 * Mock PTY process
 */
interface MockPtyProcess {
  pid: number;
  cols: number;
  rows: number;
  process: string;
  handleFlowControl: boolean;
  onData: ReturnType<typeof vi.fn>;
  onExit: ReturnType<typeof vi.fn>;
  write: ReturnType<typeof vi.fn>;
  resize: ReturnType<typeof vi.fn>;
  kill: ReturnType<typeof vi.fn>;
  pause: ReturnType<typeof vi.fn>;
  resume: ReturnType<typeof vi.fn>;
}

/**
 * Create a mock PTY process
 */
export function createMockPtyProcess(pid: number = 12345): MockPtyProcess {
  return {
    pid,
    cols: 80,
    rows: 24,
    process: '/bin/bash',
    handleFlowControl: false,
    onData: vi.fn((callback: (data: string) => void) => {
      // Store callback for triggering in tests
      return { dispose: vi.fn() };
    }),
    onExit: vi.fn((callback: (exitInfo: { exitCode: number; signal?: number }) => void) => {
      return { dispose: vi.fn() };
    }),
    write: vi.fn(),
    resize: vi.fn(),
    kill: vi.fn(),
    pause: vi.fn(),
    resume: vi.fn(),
  };
}

/**
 * Store of mock sessions
 */
const mockSessions = new Map<string, TerminalSession>();
const mockOutputBuffers = new Map<string, string[]>();

/**
 * Counter for generating session IDs
 */
let sessionCounter = 0;

/**
 * Mock PTY Manager
 */
export const ptyManager = {
  createSession: vi.fn(async (
    command: string,
    args: string[],
    options: CreateSessionOptions
  ): Promise<TerminalSession> => {
    const id = `session-${++sessionCounter}`;
    const session: TerminalSession = {
      id,
      type: options.type || 'shell',
      status: 'running',
      command,
      args,
      workingDir: options.workingDir || '/home/kali',
      env: options.env,
      pid: 12345 + sessionCounter,
      targetId: options.targetId,
      engagementId: options.engagementId,
      linkedSessions: options.linkedSessions || [],
      parentSessionId: options.parentSessionId,
      label: options.label,
      persistent: options.persistent ?? true,
      interactive: options.interactive ?? true,
      startedAt: new Date().toISOString(),
    };

    mockSessions.set(id, session);
    mockOutputBuffers.set(id, []);

    return session;
  }),

  write: vi.fn((sessionId: string, data: string): boolean => {
    if (!mockSessions.has(sessionId)) {
      return false;
    }
    return true;
  }),

  resize: vi.fn((sessionId: string, cols: number, rows: number): boolean => {
    if (!mockSessions.has(sessionId)) {
      return false;
    }
    return true;
  }),

  kill: vi.fn((sessionId: string, signal?: string): boolean => {
    const session = mockSessions.get(sessionId);
    if (!session) {
      return false;
    }
    session.status = 'stopped';
    session.stoppedAt = new Date().toISOString();
    return true;
  }),

  background: vi.fn((sessionId: string): boolean => {
    const session = mockSessions.get(sessionId);
    if (!session) {
      return false;
    }
    session.status = 'backgrounded';
    return true;
  }),

  foreground: vi.fn((sessionId: string): boolean => {
    const session = mockSessions.get(sessionId);
    if (!session) {
      return false;
    }
    session.status = 'running';
    return true;
  }),

  getSession: vi.fn((sessionId: string): TerminalSession | undefined => {
    return mockSessions.get(sessionId);
  }),

  getAllSessions: vi.fn((): TerminalSession[] => {
    return Array.from(mockSessions.values());
  }),

  getSessionsByType: vi.fn((type: string): TerminalSession[] => {
    return Array.from(mockSessions.values()).filter(s => s.type === type);
  }),

  getSessionsByTarget: vi.fn((targetId: string): TerminalSession[] => {
    return Array.from(mockSessions.values()).filter(s => s.targetId === targetId);
  }),

  getOutputBuffer: vi.fn((sessionId: string): string[] => {
    return mockOutputBuffers.get(sessionId) || [];
  }),

  linkSessions: vi.fn((sourceId: string, targetId: string): boolean => {
    const source = mockSessions.get(sourceId);
    const target = mockSessions.get(targetId);
    if (!source || !target) {
      return false;
    }
    source.linkedSessions.push(targetId);
    return true;
  }),

  setSessionLabel: vi.fn((sessionId: string, label: string): boolean => {
    const session = mockSessions.get(sessionId);
    if (!session) {
      return false;
    }
    session.label = label;
    return true;
  }),

  getRestoreInfo: vi.fn((engagementId: string): unknown => {
    return { sessions: [], manifest: null };
  }),

  restoreSessions: vi.fn((sessionIds: string[], engagementId: string): unknown => {
    return { restored: [], failed: [] };
  }),
};

/**
 * Mock tmux backend
 */
export const tmuxBackend = {
  isAvailable: vi.fn(async (): Promise<boolean> => true),
  listSessions: vi.fn(async (): Promise<string[]> => []),
  killSession: vi.fn(async (name: string): Promise<boolean> => true),
  killAllSessions: vi.fn(async (): Promise<number> => 0),
};

/**
 * Mock session persistence
 */
export const sessionPersistence = {
  loadManifest: vi.fn(async (): Promise<unknown> => ({
    engagements: {},
    version: 1,
  })),
  saveSession: vi.fn(async (): Promise<void> => {}),
  clearPersisted: vi.fn(async (): Promise<void> => {}),
};

// ============================================================================
// Test Helpers
// ============================================================================

/**
 * Add mock output to a session buffer
 */
export function addMockOutput(sessionId: string, output: string): void {
  const buffer = mockOutputBuffers.get(sessionId);
  if (buffer) {
    buffer.push(output);
  }
}

/**
 * Create a pre-existing mock session
 */
export function createMockSession(overrides: Partial<TerminalSession> = {}): TerminalSession {
  const id = overrides.id || `session-${++sessionCounter}`;
  const session: TerminalSession = {
    id,
    type: 'shell',
    status: 'running',
    command: '/bin/bash',
    args: [],
    workingDir: '/home/kali',
    linkedSessions: [],
    persistent: true,
    interactive: true,
    startedAt: new Date().toISOString(),
    ...overrides,
  };

  mockSessions.set(id, session);
  mockOutputBuffers.set(id, []);

  return session;
}

/**
 * Reset all PTY mocks
 */
export function resetPtyMocks(): void {
  mockSessions.clear();
  mockOutputBuffers.clear();
  sessionCounter = 0;

  ptyManager.createSession.mockClear();
  ptyManager.write.mockClear();
  ptyManager.resize.mockClear();
  ptyManager.kill.mockClear();
  ptyManager.background.mockClear();
  ptyManager.foreground.mockClear();
  ptyManager.getSession.mockClear();
  ptyManager.getAllSessions.mockClear();
  ptyManager.getSessionsByType.mockClear();
  ptyManager.getSessionsByTarget.mockClear();
  ptyManager.getOutputBuffer.mockClear();
  ptyManager.linkSessions.mockClear();
  ptyManager.setSessionLabel.mockClear();

  tmuxBackend.isAvailable.mockClear();
  tmuxBackend.listSessions.mockClear();
  tmuxBackend.killSession.mockClear();
  tmuxBackend.killAllSessions.mockClear();

  sessionPersistence.loadManifest.mockClear();
  sessionPersistence.saveSession.mockClear();
  sessionPersistence.clearPersisted.mockClear();
}

/**
 * Get all mock sessions
 */
export function getMockSessions(): TerminalSession[] {
  return Array.from(mockSessions.values());
}

/**
 * Get mock session by ID
 */
export function getMockSession(id: string): TerminalSession | undefined {
  return mockSessions.get(id);
}

export default {
  spawn: vi.fn(() => createMockPtyProcess()),
};
