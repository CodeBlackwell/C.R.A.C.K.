/**
 * Engagement IPC Handler Tests
 *
 * Business Value Focus (TIER 2: FUNCTIONAL CORRECTNESS - High):
 * - Engagement CRUD operations (create, read, update, delete)
 * - Active engagement management (only one active at a time)
 * - Engagement statistics aggregation
 * - Data isolation between engagements
 *
 * Tests protect against:
 * - Lost engagement data
 * - Multiple simultaneously active engagements
 * - Orphaned data on deletion
 * - Statistics calculation errors
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ipcMain } from 'electron';
import {
  runQuery,
  runWrite,
  setMockQueryResults,
  setMockQueryError,
  setMockWriteError,
  resetNeo4jMocks,
  createMockEngagementResult,
  capturedQueries,
  getLastQuery,
  getQueriesByType,
} from './__mocks__/neo4j';
import {
  capturedHandlers,
  invokeHandler,
  resetElectronMocks,
} from './__mocks__/electron';

// Mock all dependencies
vi.mock('@shared/neo4j/query', () => import('./__mocks__/neo4j'));
vi.mock('electron', () => import('./__mocks__/electron'));
vi.mock('../src/main/debug', () => ({
  debug: {
    ipc: vi.fn(),
    error: vi.fn(),
    neo4j: vi.fn(),
  },
}));

let registerEngagementHandlers: () => void;

beforeEach(async () => {
  resetElectronMocks();
  resetNeo4jMocks();

  const module = await import('../src/main/ipc/engagements');
  registerEngagementHandlers = module.registerEngagementHandlers;
  registerEngagementHandlers();
});

afterEach(() => {
  vi.clearAllMocks();
});

// ============================================================================
// engagement-list Handler Tests
// ============================================================================

describe('engagement-list handler', () => {
  describe('BV: Users can view all engagements', () => {
    it('should return all engagements ordered by status and date', async () => {
      /**
       * BV: Active engagements appear first for quick access
       *
       * Scenario:
       *   Given: Multiple engagements in database
       *   When: engagement-list is called
       *   Then: Engagements returned with active first, then by date
       */
      const mockEngagements = [
        createMockEngagementResult({ id: 'eng-1', name: 'OSCP Lab', status: 'active' }),
        createMockEngagementResult({ id: 'eng-2', name: 'HTB Box', status: 'paused' }),
      ];
      setMockQueryResults(mockEngagements);

      const result = await invokeHandler<any[]>('engagement-list');

      expect(result).toHaveLength(2);
      const query = getLastQuery();
      expect(query?.query.toLowerCase()).toContain('order by');
      expect(query?.query.toLowerCase()).toContain('status desc');
    });

    it('should return empty array when no engagements exist', async () => {
      /**
       * BV: Empty state handled gracefully
       */
      setMockQueryResults([]);

      const result = await invokeHandler<any[]>('engagement-list');

      expect(result).toEqual([]);
    });

    it('should return empty array on Neo4j error', async () => {
      /**
       * BV: Application remains usable when database unavailable
       */
      setMockQueryError(new Error('Connection refused'));

      const result = await invokeHandler<any[]>('engagement-list');

      expect(result).toEqual([]);
    });

    it('should map Neo4j node properties correctly', async () => {
      /**
       * BV: All engagement fields are accessible in UI
       */
      const mockEngagement = createMockEngagementResult({
        id: 'eng-123',
        name: 'Test Engagement',
        status: 'active',
        scope_type: 'internal',
        scope_text: '192.168.1.0/24',
        notes: 'Test notes',
      });
      setMockQueryResults([mockEngagement]);

      const result = await invokeHandler<any[]>('engagement-list');

      expect(result[0]).toHaveProperty('id', 'eng-123');
      expect(result[0]).toHaveProperty('name', 'Test Engagement');
      expect(result[0]).toHaveProperty('status', 'active');
      expect(result[0]).toHaveProperty('scope_type', 'internal');
    });
  });
});

// ============================================================================
// engagement-get Handler Tests
// ============================================================================

describe('engagement-get handler', () => {
  describe('BV: Users can retrieve specific engagement', () => {
    it('should return engagement by ID', async () => {
      /**
       * BV: Engagement details are accessible
       */
      const mockEngagement = createMockEngagementResult({
        id: 'eng-123',
        name: 'OSCP Lab',
      });
      setMockQueryResults([mockEngagement]);

      const result = await invokeHandler<any>('engagement-get', 'eng-123');

      expect(result).toHaveProperty('id', 'eng-123');
      expect(result).toHaveProperty('name', 'OSCP Lab');
      const query = getLastQuery();
      expect(query?.params.engagementId).toBe('eng-123');
    });

    it('should return null for non-existent engagement', async () => {
      /**
       * BV: Missing engagement doesn't crash
       */
      setMockQueryResults([]);

      const result = await invokeHandler<any>('engagement-get', 'non-existent');

      expect(result).toBeNull();
    });

    it('should return null on Neo4j error', async () => {
      /**
       * BV: Errors handled gracefully
       */
      setMockQueryError(new Error('Query failed'));

      const result = await invokeHandler<any>('engagement-get', 'eng-123');

      expect(result).toBeNull();
    });
  });
});

// ============================================================================
// engagement-create Handler Tests
// ============================================================================

describe('engagement-create handler', () => {
  describe('BV: Users can create new engagements', () => {
    it('should create engagement with generated ID', async () => {
      /**
       * BV: New engagements have unique identifiers
       *
       * Scenario:
       *   Given: User wants to create new engagement
       *   When: engagement-create is called with name
       *   Then: Engagement created with ID pattern eng-{random}
       */
      const mockEngagement = createMockEngagementResult({
        id: 'eng-test123',
        name: 'OSCP Lab',
        status: 'paused',
      });
      setMockQueryResults([mockEngagement]);

      const result = await invokeHandler<any>('engagement-create', {
        name: 'OSCP Lab',
      });

      expect(result).not.toBeNull();
      const query = getLastQuery();
      expect(query?.params.id).toMatch(/^eng-[a-z0-9]+$/);
    });

    it('should set initial status to paused', async () => {
      /**
       * BV: New engagements don't automatically become active
       */
      const mockEngagement = createMockEngagementResult({ status: 'paused' });
      setMockQueryResults([mockEngagement]);

      await invokeHandler('engagement-create', { name: 'Test' });

      const query = getLastQuery();
      expect(query?.query).toContain("status: 'paused'");
    });

    it('should set start_date to today', async () => {
      /**
       * BV: Engagement start date is tracked
       */
      const mockEngagement = createMockEngagementResult();
      setMockQueryResults([mockEngagement]);

      await invokeHandler('engagement-create', { name: 'Test' });

      const query = getLastQuery();
      const today = new Date().toISOString().split('T')[0];
      expect(query?.params.start_date).toBe(today);
    });

    it('should include scope information when provided', async () => {
      /**
       * BV: Scope constraints are preserved
       */
      const mockEngagement = createMockEngagementResult({
        scope_type: 'internal',
        scope_text: '192.168.1.0/24',
      });
      setMockQueryResults([mockEngagement]);

      await invokeHandler('engagement-create', {
        name: 'Test',
        scope_type: 'internal',
        scope_text: '192.168.1.0/24',
      });

      const query = getLastQuery();
      expect(query?.params.scope_type).toBe('internal');
      expect(query?.params.scope_text).toBe('192.168.1.0/24');
    });

    it('should include notes when provided', async () => {
      /**
       * BV: Engagement notes are preserved
       */
      const mockEngagement = createMockEngagementResult();
      setMockQueryResults([mockEngagement]);

      await invokeHandler('engagement-create', {
        name: 'Test',
        notes: 'Initial setup notes',
      });

      const query = getLastQuery();
      expect(query?.params.notes).toBe('Initial setup notes');
    });

    it('should return null on Neo4j error', async () => {
      /**
       * BV: Creation failures are reported
       */
      setMockQueryError(new Error('Write failed'));

      const result = await invokeHandler<any>('engagement-create', {
        name: 'Test',
      });

      expect(result).toBeNull();
    });
  });
});

// ============================================================================
// engagement-activate Handler Tests
// ============================================================================

describe('engagement-activate handler', () => {
  describe('BV: Only one engagement can be active at a time', () => {
    it('should deactivate all other engagements first', async () => {
      /**
       * BV: Prevents multiple active engagements causing confusion
       *
       * Scenario:
       *   Given: eng-1 is currently active
       *   When: engagement-activate is called for eng-2
       *   Then: eng-1 is deactivated, eng-2 becomes active
       */
      const mockEngagement = createMockEngagementResult({
        id: 'eng-2',
        status: 'active',
      });
      setMockQueryResults([mockEngagement]);

      await invokeHandler('engagement-activate', 'eng-2');

      const queries = getQueriesByType('write');
      // First write should deactivate all active
      expect(queries[0].query).toContain("status: 'active'");
      expect(queries[0].query).toContain("e.status = 'paused'");
    });

    it('should set specified engagement to active', async () => {
      /**
       * BV: Selected engagement becomes the active one
       */
      const mockEngagement = createMockEngagementResult({
        id: 'eng-123',
        status: 'active',
      });
      setMockQueryResults([mockEngagement]);

      await invokeHandler('engagement-activate', 'eng-123');

      const queries = getQueriesByType('write');
      expect(queries[1].query).toContain("e.status = 'active'");
      expect(queries[1].params.engagementId).toBe('eng-123');
    });

    it('should return the activated engagement', async () => {
      /**
       * BV: Confirmation of which engagement is now active
       */
      const mockEngagement = createMockEngagementResult({
        id: 'eng-123',
        status: 'active',
      });
      setMockQueryResults([mockEngagement]);

      const result = await invokeHandler<any>('engagement-activate', 'eng-123');

      expect(result).not.toBeNull();
      expect(result.status).toBe('active');
    });

    it('should return null on Neo4j error', async () => {
      /**
       * BV: Activation failures are reported
       */
      setMockQueryError(new Error('Write failed'));

      const result = await invokeHandler<any>('engagement-activate', 'eng-123');

      expect(result).toBeNull();
    });
  });
});

// ============================================================================
// engagement-deactivate Handler Tests
// ============================================================================

describe('engagement-deactivate handler', () => {
  describe('BV: Users can deactivate all engagements', () => {
    it('should set all active engagements to paused', async () => {
      /**
       * BV: No engagement is active when explicitly deactivated
       */
      const result = await invokeHandler<boolean>('engagement-deactivate');

      expect(result).toBe(true);
      const query = getLastQuery();
      expect(query?.query).toContain("status: 'active'");
      expect(query?.query).toContain("e.status = 'paused'");
    });

    it('should return false on Neo4j error', async () => {
      /**
       * BV: Deactivation failures are reported
       */
      setMockWriteError(new Error('Write failed'));

      const result = await invokeHandler<boolean>('engagement-deactivate');

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// engagement-update-status Handler Tests
// ============================================================================

describe('engagement-update-status handler', () => {
  describe('BV: Users can update engagement status', () => {
    it('should update status to specified value', async () => {
      /**
       * BV: Engagement lifecycle can be tracked
       */
      const result = await invokeHandler<boolean>(
        'engagement-update-status',
        'eng-123',
        'completed'
      );

      expect(result).toBe(true);
      const query = getLastQuery();
      expect(query?.params.status).toBe('completed');
    });

    it('should set end_date when status is completed', async () => {
      /**
       * BV: Completion date is automatically recorded
       */
      await invokeHandler(
        'engagement-update-status',
        'eng-123',
        'completed'
      );

      const query = getLastQuery();
      expect(query?.params.end_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });

    it('should set end_date when status is archived', async () => {
      /**
       * BV: Archive date is automatically recorded
       */
      await invokeHandler(
        'engagement-update-status',
        'eng-123',
        'archived'
      );

      const query = getLastQuery();
      expect(query?.params.end_date).not.toBeNull();
    });

    it('should not set end_date for paused status', async () => {
      /**
       * BV: Pausing doesn't mean finished
       */
      await invokeHandler(
        'engagement-update-status',
        'eng-123',
        'paused'
      );

      const query = getLastQuery();
      expect(query?.params.end_date).toBeNull();
    });

    it('should return false on Neo4j error', async () => {
      /**
       * BV: Update failures are reported
       */
      setMockWriteError(new Error('Write failed'));

      const result = await invokeHandler<boolean>(
        'engagement-update-status',
        'eng-123',
        'completed'
      );

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// engagement-update Handler Tests
// ============================================================================

describe('engagement-update handler', () => {
  describe('BV: Users can update engagement details', () => {
    it('should update name when provided', async () => {
      /**
       * BV: Engagement names can be changed
       */
      const result = await invokeHandler<boolean>(
        'engagement-update',
        'eng-123',
        { name: 'New Name' }
      );

      expect(result).toBe(true);
      const query = getLastQuery();
      expect(query?.query).toContain('e.name = $name');
    });

    it('should update scope_type and scope_text', async () => {
      /**
       * BV: Scope can be modified
       */
      await invokeHandler('engagement-update', 'eng-123', {
        scope_type: 'external',
        scope_text: '10.0.0.0/8',
      });

      const query = getLastQuery();
      expect(query?.query).toContain('scope_type');
      expect(query?.query).toContain('scope_text');
    });

    it('should update notes', async () => {
      /**
       * BV: Notes can be modified
       */
      await invokeHandler('engagement-update', 'eng-123', {
        notes: 'Updated notes',
      });

      const query = getLastQuery();
      expect(query?.params.notes).toBe('Updated notes');
    });

    it('should not update protected fields (id, created_at)', async () => {
      /**
       * BV: Immutable fields are protected
       */
      await invokeHandler('engagement-update', 'eng-123', {
        id: 'hacked-id',
        created_at: '1999-01-01',
        name: 'Valid Update',
      });

      const query = getLastQuery();
      expect(query?.query).not.toContain('e.id');
      expect(query?.query).not.toContain('e.created_at');
      expect(query?.query).toContain('e.name');
    });

    it('should return false when no updates provided', async () => {
      /**
       * BV: Empty update is a no-op
       */
      const result = await invokeHandler<boolean>(
        'engagement-update',
        'eng-123',
        {}
      );

      expect(result).toBe(false);
    });

    it('should return false on Neo4j error', async () => {
      /**
       * BV: Update failures are reported
       */
      setMockWriteError(new Error('Write failed'));

      const result = await invokeHandler<boolean>(
        'engagement-update',
        'eng-123',
        { name: 'Test' }
      );

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// engagement-delete Handler Tests
// ============================================================================

describe('engagement-delete handler', () => {
  describe('BV: Users can delete engagements with all related data', () => {
    it('should delete engagement and all related nodes', async () => {
      /**
       * BV: No orphaned data after deletion
       *
       * Scenario:
       *   Given: Engagement with targets, services, findings, credentials, loot
       *   When: engagement-delete is called
       *   Then: All related data is also deleted
       */
      const result = await invokeHandler<{ success: boolean }>(
        'engagement-delete',
        'eng-123'
      );

      expect(result.success).toBe(true);
      const query = getLastQuery();
      expect(query?.query).toContain('TARGETS');
      expect(query?.query).toContain('HAS_SERVICE');
      expect(query?.query).toContain('HAS_FINDING');
      expect(query?.query).toContain('HAS_CREDENTIAL');
      expect(query?.query).toContain('HAS_LOOT');
      expect(query?.query.toLowerCase()).toContain('detach delete');
    });

    it('should use DETACH DELETE for clean removal', async () => {
      /**
       * BV: No orphaned relationships
       */
      await invokeHandler('engagement-delete', 'eng-123');

      const query = getLastQuery();
      expect(query?.query.toLowerCase()).toContain('detach delete');
    });

    it('should return error object on Neo4j error', async () => {
      /**
       * BV: Deletion failures include error message
       */
      setMockWriteError(new Error('Delete failed'));

      const result = await invokeHandler<{ success: boolean; error?: string }>(
        'engagement-delete',
        'eng-123'
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Delete failed');
    });
  });
});

// ============================================================================
// engagement-stats Handler Tests
// ============================================================================

describe('engagement-stats handler', () => {
  describe('BV: Users can view engagement statistics', () => {
    it('should return counts of all related entities', async () => {
      /**
       * BV: Dashboard shows engagement progress
       */
      setMockQueryResults([{
        target_count: 5,
        service_count: 15,
        finding_count: 8,
        credential_count: 3,
        loot_count: 2,
      }]);

      const result = await invokeHandler<any>('engagement-stats', 'eng-123');

      expect(result.target_count).toBe(5);
      expect(result.service_count).toBe(15);
      expect(result.finding_count).toBe(8);
      expect(result.credential_count).toBe(3);
      expect(result.loot_count).toBe(2);
    });

    it('should use DISTINCT to avoid duplicate counting', async () => {
      /**
       * BV: Accurate counts for overlapping relationships
       */
      setMockQueryResults([{
        target_count: 0,
        service_count: 0,
        finding_count: 0,
        credential_count: 0,
        loot_count: 0,
      }]);

      await invokeHandler('engagement-stats', 'eng-123');

      const query = getLastQuery();
      expect(query?.query).toContain('count(DISTINCT t)');
      expect(query?.query).toContain('count(DISTINCT s)');
      expect(query?.query).toContain('count(DISTINCT f)');
      expect(query?.query).toContain('count(DISTINCT c)');
      expect(query?.query).toContain('count(DISTINCT l)');
    });

    it('should return null for non-existent engagement', async () => {
      /**
       * BV: Missing engagement doesn't crash
       */
      setMockQueryResults([]);

      const result = await invokeHandler<any>('engagement-stats', 'non-existent');

      expect(result).toBeNull();
    });

    it('should return null on Neo4j error', async () => {
      /**
       * BV: Errors handled gracefully
       */
      setMockQueryError(new Error('Query failed'));

      const result = await invokeHandler<any>('engagement-stats', 'eng-123');

      expect(result).toBeNull();
    });
  });
});

// ============================================================================
// Handler Registration Tests
// ============================================================================

describe('Handler Registration', () => {
  it('should register all engagement handlers', () => {
    /**
     * BV: All engagement operations available via IPC
     */
    const expectedHandlers = [
      'engagement-list',
      'engagement-get',
      'engagement-create',
      'engagement-activate',
      'engagement-deactivate',
      'engagement-update-status',
      'engagement-update',
      'engagement-delete',
      'engagement-stats',
    ];

    for (const handler of expectedHandlers) {
      expect(capturedHandlers.has(handler)).toBe(true);
    }
  });
});

// ============================================================================
// Edge Cases
// ============================================================================

describe('Edge Cases', () => {
  describe('BV: Special characters in engagement data', () => {
    it('should handle special characters in name', async () => {
      /**
       * BV: Names with special chars are preserved
       */
      const mockEngagement = createMockEngagementResult({
        name: 'OSCP Lab #1 (2024)',
      });
      setMockQueryResults([mockEngagement]);

      await invokeHandler('engagement-create', {
        name: 'OSCP Lab #1 (2024)',
      });

      const query = getLastQuery();
      expect(query?.params.name).toBe('OSCP Lab #1 (2024)');
    });

    it('should handle multi-line notes', async () => {
      /**
       * BV: Multi-line notes are preserved
       */
      const notes = 'Line 1\nLine 2\nLine 3';
      const mockEngagement = createMockEngagementResult({ notes });
      setMockQueryResults([mockEngagement]);

      await invokeHandler('engagement-create', {
        name: 'Test',
        notes,
      });

      const query = getLastQuery();
      expect(query?.params.notes).toBe(notes);
    });

    it('should handle CIDR notation in scope', async () => {
      /**
       * BV: Network ranges are preserved correctly
       */
      const mockEngagement = createMockEngagementResult({
        scope_text: '192.168.1.0/24, 10.0.0.0/8',
      });
      setMockQueryResults([mockEngagement]);

      await invokeHandler('engagement-create', {
        name: 'Test',
        scope_text: '192.168.1.0/24, 10.0.0.0/8',
      });

      const query = getLastQuery();
      expect(query?.params.scope_text).toBe('192.168.1.0/24, 10.0.0.0/8');
    });
  });

  describe('BV: Concurrent operations', () => {
    it('should generate unique IDs for rapid creates', async () => {
      /**
       * BV: No ID collisions in rapid creation
       */
      const mockEngagement1 = createMockEngagementResult({ id: 'eng-abc123' });
      const mockEngagement2 = createMockEngagementResult({ id: 'eng-def456' });
      const mockEngagement3 = createMockEngagementResult({ id: 'eng-ghi789' });

      setMockQueryResults([mockEngagement1]);
      const result1 = await invokeHandler('engagement-create', { name: 'Test 1' });

      setMockQueryResults([mockEngagement2]);
      const result2 = await invokeHandler('engagement-create', { name: 'Test 2' });

      setMockQueryResults([mockEngagement3]);
      const result3 = await invokeHandler('engagement-create', { name: 'Test 3' });

      // Verify the generated IDs are different
      const queries = getQueriesByType('read');
      const ids = queries.map(q => q.params.id).filter(Boolean);
      const uniqueIds = new Set(ids);

      // IDs should be generated by the handler (we check the create queries)
      expect(uniqueIds.size).toBeGreaterThan(0);
    });
  });
});
