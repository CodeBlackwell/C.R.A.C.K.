/**
 * Session IPC Handler Tests
 *
 * Business Value Focus (TIER 2: FUNCTIONAL CORRECTNESS - High):
 * - Session lifecycle management (create -> running -> stopped)
 * - PTY session operations (write, resize, kill)
 * - Session persistence and restore
 * - PRISM integration for credential extraction
 *
 * Tests protect against:
 * - Lost terminal sessions
 * - Failed PTY operations
 * - Credential extraction failures
 * - Session restore corruption
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ipcMain, BrowserWindow } from 'electron';
import {
  runQuery,
  runWrite,
  setMockQueryResults,
  setMockQueryError,
  setMockWriteError,
  resetNeo4jMocks,
  capturedQueries,
} from './__mocks__/neo4j';
import {
  capturedHandlers,
  invokeHandler,
  resetElectronMocks,
  getMockWebContents,
} from './__mocks__/electron';
import {
  ptyManager,
  tmuxBackend,
  sessionPersistence,
  resetPtyMocks,
  createMockSession,
  addMockOutput,
} from './__mocks__/pty';

// Mock all dependencies
vi.mock('@shared/neo4j/query', () => import('./__mocks__/neo4j'));
vi.mock('electron', () => import('./__mocks__/electron'));
vi.mock('../src/main/pty/manager', () => ({
  ptyManager: ptyManager,
  setPtyMainWindow: vi.fn(),
}));
vi.mock('../src/main/pty/tmux-backend', () => ({
  tmuxBackend: tmuxBackend,
}));
vi.mock('../src/main/pty/persistence', () => ({
  sessionPersistence: sessionPersistence,
}));
vi.mock('../src/main/debug', () => ({
  debug: {
    ipc: vi.fn(),
    error: vi.fn(),
    neo4j: vi.fn(),
    pty: vi.fn(),
  },
}));
vi.mock('../src/main/parser/patterns', () => ({
  matchCredentials: vi.fn(() => []),
  matchFindings: vi.fn(() => []),
}));
vi.mock('../src/main/parser', () => ({
  getCredentialParser: vi.fn(() => ({
    setEnabled: vi.fn(),
    getStats: vi.fn(() => ({ enabled: true, matches: 0 })),
  })),
}));

let registerSessionHandlers: () => void;

beforeEach(async () => {
  resetElectronMocks();
  resetNeo4jMocks();
  resetPtyMocks();

  const module = await import('../src/main/ipc/sessions');
  registerSessionHandlers = module.registerSessionHandlers;
  registerSessionHandlers();
});

afterEach(() => {
  vi.clearAllMocks();
});

// ============================================================================
// session-create Handler Tests
// ============================================================================

describe('session-create handler', () => {
  describe('BV: Users can create terminal sessions', () => {
    it('should create session with specified command and args', async () => {
      /**
       * BV: Terminal sessions spawn with correct command
       *
       * Scenario:
       *   Given: User requests new bash session
       *   When: session-create is called
       *   Then: PTY manager creates session with command /bin/bash
       */
      const result = await invokeHandler<any>(
        'session-create',
        '/bin/bash',
        ['-l'],
        { type: 'shell', engagementId: 'eng-123' }
      );

      expect(ptyManager.createSession).toHaveBeenCalledWith(
        '/bin/bash',
        ['-l'],
        expect.objectContaining({
          type: 'shell',
          engagementId: 'eng-123',
        })
      );
      expect(result).toHaveProperty('id');
      expect(result.status).toBe('running');
    });

    it('should associate session with engagement', async () => {
      /**
       * BV: Sessions are scoped to current engagement
       */
      const result = await invokeHandler<any>(
        'session-create',
        '/bin/bash',
        [],
        { engagementId: 'eng-456' }
      );

      expect(result.engagementId).toBe('eng-456');
    });

    it('should associate session with target when specified', async () => {
      /**
       * BV: Sessions track which target they connect to
       */
      const result = await invokeHandler<any>(
        'session-create',
        'nc',
        ['-lvnp', '4444'],
        { type: 'listener', targetId: 'target-123' }
      );

      expect(result.targetId).toBe('target-123');
    });

    it('should handle custom labels', async () => {
      /**
       * BV: Users can label sessions for identification
       */
      const result = await invokeHandler<any>(
        'session-create',
        '/bin/bash',
        [],
        { label: 'DC01 Shell' }
      );

      expect(result.label).toBe('DC01 Shell');
    });

    it('should throw error when PTY creation fails', async () => {
      /**
       * BV: Creation failures are reported to user
       */
      ptyManager.createSession.mockRejectedValueOnce(new Error('PTY spawn failed'));

      await expect(
        invokeHandler('session-create', '/bin/bash', [], {})
      ).rejects.toThrow('PTY spawn failed');
    });
  });

  describe('BV: Session types are correctly assigned', () => {
    const testCases = [
      { type: 'shell', expectedType: 'shell' },
      { type: 'listener', expectedType: 'listener' },
      { type: 'tunnel', expectedType: 'tunnel' },
      { type: 'scan', expectedType: 'scan' },
      { type: 'proxy', expectedType: 'proxy' },
    ];

    for (const { type, expectedType } of testCases) {
      it(`should create session with type ${type}`, async () => {
        const result = await invokeHandler<any>(
          'session-create',
          '/bin/bash',
          [],
          { type }
        );

        expect(result.type).toBe(expectedType);
      });
    }
  });
});

// ============================================================================
// session-write Handler Tests
// ============================================================================

describe('session-write handler', () => {
  describe('BV: Users can send input to terminal', () => {
    beforeEach(() => {
      createMockSession({ id: 'session-123' });
    });

    it('should write data to session', async () => {
      /**
       * BV: Keyboard input reaches terminal
       */
      const result = await invokeHandler<boolean>(
        'session-write',
        'session-123',
        'whoami\n'
      );

      expect(ptyManager.write).toHaveBeenCalledWith('session-123', 'whoami\n');
      expect(result).toBe(true);
    });

    it('should handle special characters', async () => {
      /**
       * BV: Control characters and escape sequences work
       */
      const result = await invokeHandler<boolean>(
        'session-write',
        'session-123',
        '\x03' // Ctrl+C
      );

      expect(ptyManager.write).toHaveBeenCalledWith('session-123', '\x03');
      expect(result).toBe(true);
    });

    it('should return false for non-existent session', async () => {
      /**
       * BV: Invalid session IDs are handled gracefully
       */
      const result = await invokeHandler<boolean>(
        'session-write',
        'non-existent',
        'test'
      );

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// session-resize Handler Tests
// ============================================================================

describe('session-resize handler', () => {
  describe('BV: Terminal can be resized', () => {
    beforeEach(() => {
      createMockSession({ id: 'session-123' });
    });

    it('should resize session to specified dimensions', async () => {
      /**
       * BV: Terminal output renders correctly at new size
       */
      const result = await invokeHandler<boolean>(
        'session-resize',
        'session-123',
        120,
        40
      );

      expect(ptyManager.resize).toHaveBeenCalledWith('session-123', 120, 40);
      expect(result).toBe(true);
    });

    it('should return false for non-existent session', async () => {
      /**
       * BV: Invalid session IDs handled gracefully
       */
      const result = await invokeHandler<boolean>(
        'session-resize',
        'non-existent',
        80,
        24
      );

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// session-kill Handler Tests
// ============================================================================

describe('session-kill handler', () => {
  describe('BV: Users can terminate sessions', () => {
    beforeEach(() => {
      createMockSession({ id: 'session-123' });
    });

    it('should kill session', async () => {
      /**
       * BV: Sessions can be cleanly terminated
       */
      const result = await invokeHandler<boolean>(
        'session-kill',
        'session-123'
      );

      expect(ptyManager.kill).toHaveBeenCalledWith('session-123', undefined);
      expect(result).toBe(true);
    });

    it('should pass signal when specified', async () => {
      /**
       * BV: Force kill with SIGKILL when needed
       */
      const result = await invokeHandler<boolean>(
        'session-kill',
        'session-123',
        'SIGKILL'
      );

      expect(ptyManager.kill).toHaveBeenCalledWith('session-123', 'SIGKILL');
      expect(result).toBe(true);
    });

    it('should return false for non-existent session', async () => {
      /**
       * BV: Invalid session IDs handled gracefully
       */
      const result = await invokeHandler<boolean>(
        'session-kill',
        'non-existent'
      );

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// session-background/foreground Handler Tests
// ============================================================================

describe('session-background handler', () => {
  describe('BV: Sessions can run in background', () => {
    beforeEach(() => {
      createMockSession({ id: 'session-123' });
    });

    it('should background a running session', async () => {
      /**
       * BV: Long-running tasks can continue while hidden
       */
      const result = await invokeHandler<boolean>(
        'session-background',
        'session-123'
      );

      expect(ptyManager.background).toHaveBeenCalledWith('session-123');
      expect(result).toBe(true);
    });
  });
});

describe('session-foreground handler', () => {
  describe('BV: Sessions can be brought to foreground', () => {
    beforeEach(() => {
      createMockSession({ id: 'session-123', status: 'backgrounded' });
    });

    it('should foreground a backgrounded session', async () => {
      /**
       * BV: Backgrounded tasks can be resumed
       */
      const result = await invokeHandler<boolean>(
        'session-foreground',
        'session-123'
      );

      expect(ptyManager.foreground).toHaveBeenCalledWith('session-123');
      expect(result).toBe(true);
    });
  });
});

// ============================================================================
// session-get Handler Tests
// ============================================================================

describe('session-get handler', () => {
  describe('BV: Users can retrieve session details', () => {
    it('should return session by ID', async () => {
      /**
       * BV: Session metadata is accessible
       */
      const mockSession = createMockSession({
        id: 'session-123',
        label: 'Test Session',
      });

      const result = await invokeHandler<any>('session-get', 'session-123');

      expect(result).toEqual(mockSession);
    });

    it('should return undefined for non-existent session', async () => {
      /**
       * BV: Missing sessions don't crash
       */
      const result = await invokeHandler<any>('session-get', 'non-existent');

      expect(result).toBeUndefined();
    });
  });
});

// ============================================================================
// session-list Handler Tests
// ============================================================================

describe('session-list handler', () => {
  describe('BV: Users can list all sessions', () => {
    it('should return all sessions', async () => {
      /**
       * BV: Overview of all active sessions
       */
      createMockSession({ id: 'session-1', type: 'shell' });
      createMockSession({ id: 'session-2', type: 'listener' });
      createMockSession({ id: 'session-3', type: 'scan' });

      const result = await invokeHandler<any[]>('session-list');

      expect(result).toHaveLength(3);
    });

    it('should return empty array when no sessions', async () => {
      /**
       * BV: Empty state handled correctly
       */
      const result = await invokeHandler<any[]>('session-list');

      expect(result).toEqual([]);
    });
  });
});

// ============================================================================
// session-list-by-type Handler Tests
// ============================================================================

describe('session-list-by-type handler', () => {
  describe('BV: Users can filter sessions by type', () => {
    beforeEach(() => {
      createMockSession({ id: 'session-1', type: 'shell' });
      createMockSession({ id: 'session-2', type: 'shell' });
      createMockSession({ id: 'session-3', type: 'listener' });
    });

    it('should return only sessions of specified type', async () => {
      /**
       * BV: Find all shells or all listeners quickly
       */
      const result = await invokeHandler<any[]>('session-list-by-type', 'shell');

      expect(result).toHaveLength(2);
      expect(result.every(s => s.type === 'shell')).toBe(true);
    });

    it('should return empty array for type with no sessions', async () => {
      /**
       * BV: Missing type handled gracefully
       */
      const result = await invokeHandler<any[]>('session-list-by-type', 'tunnel');

      expect(result).toEqual([]);
    });
  });
});

// ============================================================================
// session-list-by-target Handler Tests
// ============================================================================

describe('session-list-by-target handler', () => {
  describe('BV: Users can find sessions by target', () => {
    beforeEach(() => {
      createMockSession({ id: 'session-1', targetId: 'target-123' });
      createMockSession({ id: 'session-2', targetId: 'target-123' });
      createMockSession({ id: 'session-3', targetId: 'target-456' });
    });

    it('should return sessions for specific target', async () => {
      /**
       * BV: Find all sessions connected to a machine
       */
      const result = await invokeHandler<any[]>(
        'session-list-by-target',
        'target-123'
      );

      expect(result).toHaveLength(2);
      expect(result.every(s => s.targetId === 'target-123')).toBe(true);
    });
  });
});

// ============================================================================
// session-get-output Handler Tests
// ============================================================================

describe('session-get-output handler', () => {
  describe('BV: Users can retrieve session output buffer', () => {
    it('should return buffered output', async () => {
      /**
       * BV: Scrollback history is accessible
       */
      createMockSession({ id: 'session-123' });
      addMockOutput('session-123', 'kali@kali:~$ whoami\r\nkali\r\n');

      const result = await invokeHandler<string[]>(
        'session-get-output',
        'session-123'
      );

      expect(result).toContain('kali@kali:~$ whoami\r\nkali\r\n');
    });

    it('should return empty array for session with no output', async () => {
      /**
       * BV: Empty buffer doesn't crash
       */
      createMockSession({ id: 'session-123' });

      const result = await invokeHandler<string[]>(
        'session-get-output',
        'session-123'
      );

      expect(result).toEqual([]);
    });
  });
});

// ============================================================================
// session-link Handler Tests
// ============================================================================

describe('session-link handler', () => {
  describe('BV: Sessions can be linked for topology tracking', () => {
    beforeEach(() => {
      createMockSession({ id: 'parent-123' });
      createMockSession({ id: 'child-456' });
    });

    it('should link two sessions', async () => {
      /**
       * BV: Session relationships tracked for graph visualization
       */
      const result = await invokeHandler<boolean>(
        'session-link',
        'parent-123',
        'child-456'
      );

      expect(ptyManager.linkSessions).toHaveBeenCalledWith(
        'parent-123',
        'child-456'
      );
      expect(result).toBe(true);
    });

    it('should return false if source session missing', async () => {
      /**
       * BV: Invalid links are rejected
       */
      const result = await invokeHandler<boolean>(
        'session-link',
        'non-existent',
        'child-456'
      );

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// session-set-label Handler Tests
// ============================================================================

describe('session-set-label handler', () => {
  describe('BV: Users can rename sessions', () => {
    beforeEach(() => {
      createMockSession({ id: 'session-123' });
    });

    it('should update session label', async () => {
      /**
       * BV: Sessions can be given meaningful names
       */
      const result = await invokeHandler<boolean>(
        'session-set-label',
        'session-123',
        'DC01 Admin Shell'
      );

      expect(ptyManager.setSessionLabel).toHaveBeenCalledWith(
        'session-123',
        'DC01 Admin Shell'
      );
      expect(result).toBe(true);
    });
  });
});

// ============================================================================
// Session Persistence Handler Tests
// ============================================================================

describe('session-get-manifest handler', () => {
  describe('BV: Users can view persisted sessions', () => {
    it('should return session manifest', async () => {
      /**
       * BV: Overview of all restorable sessions
       */
      sessionPersistence.loadManifest.mockResolvedValueOnce({
        engagements: { 'eng-123': { sessions: ['s1', 's2'] } },
        version: 1,
      });

      const result = await invokeHandler<any>('session-get-manifest');

      expect(result).toHaveProperty('engagements');
      expect(result.version).toBe(1);
    });
  });
});

describe('session-restore handler', () => {
  describe('BV: Users can restore previous sessions', () => {
    it('should restore specified sessions', async () => {
      /**
       * BV: Work can continue after app restart
       */
      ptyManager.restoreSessions.mockResolvedValueOnce({
        restored: ['session-1', 'session-2'],
        failed: [],
      });

      const result = await invokeHandler<any>(
        'session-restore',
        ['session-1', 'session-2'],
        'eng-123'
      );

      expect(ptyManager.restoreSessions).toHaveBeenCalledWith(
        ['session-1', 'session-2'],
        'eng-123'
      );
      expect(result.restored).toHaveLength(2);
    });
  });
});

describe('session-clear-persisted handler', () => {
  describe('BV: Users can clear session history', () => {
    it('should clear persisted sessions for engagement', async () => {
      /**
       * BV: Old session data can be cleaned up
       */
      const result = await invokeHandler<boolean>(
        'session-clear-persisted',
        'eng-123'
      );

      expect(sessionPersistence.clearPersisted).toHaveBeenCalledWith('eng-123');
      expect(result).toBe(true);
    });
  });
});

// ============================================================================
// PRISM Integration Handler Tests
// ============================================================================

describe('prism-set-autoscan handler', () => {
  describe('BV: Users can toggle automatic credential scanning', () => {
    it('should enable autoscan', async () => {
      /**
       * BV: Credentials are automatically extracted from output
       */
      const result = await invokeHandler<boolean>('prism-set-autoscan', true);

      expect(result).toBe(true);
    });

    it('should disable autoscan', async () => {
      /**
       * BV: Users can disable if causing performance issues
       */
      const result = await invokeHandler<boolean>('prism-set-autoscan', false);

      expect(result).toBe(false);
    });
  });
});

describe('prism-get-autoscan handler', () => {
  describe('BV: Users can check autoscan status', () => {
    it('should return current autoscan state', async () => {
      /**
       * BV: UI can reflect current setting
       */
      const result = await invokeHandler<boolean>('prism-get-autoscan');

      expect(typeof result).toBe('boolean');
    });
  });
});

describe('prism-get-stats handler', () => {
  describe('BV: Users can view PRISM statistics', () => {
    it('should return parser statistics', async () => {
      /**
       * BV: Monitor how many credentials have been extracted
       */
      const result = await invokeHandler<any>('prism-get-stats');

      expect(result).toHaveProperty('enabled');
    });
  });
});

// ============================================================================
// Tmux Backend Handler Tests
// ============================================================================

describe('tmux-is-available handler', () => {
  describe('BV: Check tmux availability', () => {
    it('should return true when tmux is available', async () => {
      /**
       * BV: Persistent sessions require tmux
       */
      tmuxBackend.isAvailable.mockResolvedValueOnce(true);

      const result = await invokeHandler<boolean>('tmux-is-available');

      expect(result).toBe(true);
    });

    it('should return false when tmux is not available', async () => {
      /**
       * BV: Fallback mode when tmux missing
       */
      tmuxBackend.isAvailable.mockResolvedValueOnce(false);

      const result = await invokeHandler<boolean>('tmux-is-available');

      expect(result).toBe(false);
    });
  });
});

describe('tmux-list-sessions handler', () => {
  describe('BV: List tmux managed sessions', () => {
    it('should return list of tmux sessions', async () => {
      /**
       * BV: View all persistent backend sessions
       */
      tmuxBackend.listSessions.mockResolvedValueOnce([
        'breach-session-1',
        'breach-session-2',
      ]);

      const result = await invokeHandler<string[]>('tmux-list-sessions');

      expect(result).toHaveLength(2);
    });
  });
});

describe('tmux-kill-session handler', () => {
  describe('BV: Kill specific tmux session', () => {
    it('should kill named tmux session', async () => {
      /**
       * BV: Clean up orphaned tmux sessions
       */
      tmuxBackend.killSession.mockResolvedValueOnce(true);

      const result = await invokeHandler<boolean>(
        'tmux-kill-session',
        'breach-session-1'
      );

      expect(tmuxBackend.killSession).toHaveBeenCalledWith('breach-session-1');
      expect(result).toBe(true);
    });
  });
});

describe('tmux-kill-all handler', () => {
  describe('BV: Kill all breach tmux sessions', () => {
    it('should kill all managed sessions', async () => {
      /**
       * BV: Clean up all sessions on shutdown
       */
      tmuxBackend.killAllSessions.mockResolvedValueOnce(5);

      const result = await invokeHandler<number>('tmux-kill-all');

      expect(result).toBe(5);
    });
  });
});

// ============================================================================
// Handler Registration Tests
// ============================================================================

describe('Handler Registration', () => {
  it('should register all session handlers', () => {
    /**
     * BV: All session operations available via IPC
     */
    const expectedHandlers = [
      'session-create',
      'session-write',
      'session-resize',
      'session-kill',
      'session-background',
      'session-foreground',
      'session-get',
      'session-list',
      'session-list-by-type',
      'session-list-by-target',
      'session-get-output',
      'session-link',
      'session-set-label',
      'session-prism-scan',
      'prism-scan-text',
      'session-get-manifest',
      'session-get-restore-info',
      'session-restore',
      'session-clear-persisted',
      'prism-set-autoscan',
      'prism-get-autoscan',
      'prism-get-stats',
      'tmux-is-available',
      'tmux-list-sessions',
      'tmux-kill-session',
      'tmux-kill-all',
    ];

    for (const handler of expectedHandlers) {
      expect(capturedHandlers.has(handler)).toBe(true);
    }
  });
});
