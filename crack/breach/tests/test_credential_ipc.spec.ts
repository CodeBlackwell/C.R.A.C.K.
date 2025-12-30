/**
 * Credential IPC Handler Tests
 *
 * Business Value Focus (TIER 1: DATA INTEGRITY - Critical):
 * - Credential storage preserves all metadata (no data loss)
 * - Proper engagement scoping (no credential leakage between engagements)
 * - Unique ID generation (no collisions)
 * - Graceful Neo4j error handling (resilient to DB issues)
 *
 * Tests protect against:
 * - Lost credentials during save/retrieve operations
 * - Cross-engagement data exposure
 * - Duplicate credential IDs
 * - Crashes when Neo4j is unavailable
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
  createMockCredentialResult,
  capturedQueries,
  getLastQuery,
} from './__mocks__/neo4j';
import {
  capturedHandlers,
  invokeHandler,
  resetElectronMocks,
} from './__mocks__/electron';

// Import the module under test
// Note: We need to mock dependencies before importing
vi.mock('@shared/neo4j/query', () => import('./__mocks__/neo4j'));
vi.mock('electron', () => import('./__mocks__/electron'));
vi.mock('../src/main/debug', () => ({
  debug: {
    ipc: vi.fn(),
    error: vi.fn(),
    neo4j: vi.fn(),
  },
}));

// Dynamic import after mocks are set up
let registerCredentialHandlers: () => void;

beforeEach(async () => {
  resetElectronMocks();
  resetNeo4jMocks();

  // Import fresh module
  const module = await import('../src/main/ipc/credentials');
  registerCredentialHandlers = module.registerCredentialHandlers;
  registerCredentialHandlers();
});

afterEach(() => {
  vi.clearAllMocks();
});

// ============================================================================
// credential-list Handler Tests
// ============================================================================

describe('credential-list handler', () => {
  describe('BV: Users can retrieve all credentials for an engagement', () => {
    it('should return credentials scoped to the specified engagement', async () => {
      /**
       * BV: Prevents credential leakage between engagements
       *
       * Scenario:
       *   Given: Neo4j contains credentials for engagement "eng-123"
       *   When: credential-list is called with "eng-123"
       *   Then: Only credentials for that engagement are returned
       */
      const mockCreds = [
        createMockCredentialResult({ id: 'cred-1', username: 'admin' }),
        createMockCredentialResult({ id: 'cred-2', username: 'user1' }),
      ];
      setMockQueryResults(mockCreds);

      const result = await invokeHandler<unknown[]>('credential-list', 'eng-123');

      expect(result).toHaveLength(2);
      expect(result[0]).toHaveProperty('id', 'cred-1');
      expect(result[1]).toHaveProperty('id', 'cred-2');

      // Verify query used correct engagement ID
      const query = getLastQuery();
      expect(query?.params).toHaveProperty('engagementId', 'eng-123');
    });

    it('should include target IP and hostname in returned credentials', async () => {
      /**
       * BV: Users see which target each credential was found on
       *
       * Scenario:
       *   Given: Credential linked to target with IP and hostname
       *   When: credential-list is called
       *   Then: Target info is included in credential object
       */
      const mockCreds = [
        createMockCredentialResult({
          id: 'cred-1',
          targetIp: '192.168.1.100',
          targetHostname: 'DC01',
        }),
      ];
      setMockQueryResults(mockCreds);

      const result = await invokeHandler<unknown[]>('credential-list', 'eng-123');

      expect(result[0]).toHaveProperty('targetIp', '192.168.1.100');
      expect(result[0]).toHaveProperty('targetHostname', 'DC01');
    });

    it('should return empty array when no credentials exist', async () => {
      /**
       * BV: Empty state handled gracefully, no crashes
       *
       * Scenario:
       *   Given: No credentials in engagement
       *   When: credential-list is called
       *   Then: Empty array returned (not null/undefined)
       */
      setMockQueryResults([]);

      const result = await invokeHandler<unknown[]>('credential-list', 'eng-123');

      expect(result).toEqual([]);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should return empty array on Neo4j connection error', async () => {
      /**
       * BV: Application remains usable when Neo4j is temporarily unavailable
       *
       * Scenario:
       *   Given: Neo4j connection is down
       *   When: credential-list is called
       *   Then: Empty array returned, no crash
       */
      setMockQueryError(new Error('Connection refused'));

      const result = await invokeHandler<unknown[]>('credential-list', 'eng-123');

      expect(result).toEqual([]);
    });

    it('should order credentials by creation date descending', async () => {
      /**
       * BV: Most recent credentials appear first for quick access
       *
       * Scenario:
       *   Given: Multiple credentials with different creation times
       *   When: credential-list is called
       *   Then: Query includes ORDER BY created_at DESC
       */
      setMockQueryResults([]);

      await invokeHandler('credential-list', 'eng-123');

      const query = getLastQuery();
      expect(query?.query.toLowerCase()).toContain('order by');
      expect(query?.query.toLowerCase()).toContain('desc');
    });
  });
});

// ============================================================================
// credential-add Handler Tests
// ============================================================================

describe('credential-add handler', () => {
  const validCredential = {
    username: 'admin',
    secret: 'Password123!',
    secretType: 'password' as const,
    domain: 'TESTDOMAIN',
    source: 'mimikatz',
    engagementId: 'eng-123',
    validatedAccess: [],
    isAdmin: false,
  };

  describe('BV: Users can save discovered credentials', () => {
    it('should generate unique ID for new credential', async () => {
      /**
       * BV: Each credential has unique identifier for tracking and updates
       *
       * Scenario:
       *   Given: User adds a new credential
       *   When: credential-add is called
       *   Then: Generated ID follows pattern cred-{timestamp}-{random}
       */
      const result = await invokeHandler<any>('credential-add', validCredential);

      expect(result.id).toMatch(/^cred-[a-z0-9]+-[a-z0-9]+$/);
    });

    it('should generate different IDs for multiple credentials', async () => {
      /**
       * BV: No ID collisions when adding multiple credentials rapidly
       *
       * Scenario:
       *   Given: User adds multiple credentials in quick succession
       *   When: credential-add is called multiple times
       *   Then: Each credential gets a unique ID
       */
      const results = await Promise.all([
        invokeHandler<any>('credential-add', validCredential),
        invokeHandler<any>('credential-add', { ...validCredential, username: 'user2' }),
        invokeHandler<any>('credential-add', { ...validCredential, username: 'user3' }),
      ]);

      const ids = results.map(r => r.id);
      const uniqueIds = new Set(ids);

      expect(uniqueIds.size).toBe(3);
    });

    it('should include createdAt timestamp in returned credential', async () => {
      /**
       * BV: Credentials have accurate creation timestamps for auditing
       *
       * Scenario:
       *   Given: User adds a credential
       *   When: credential-add is called
       *   Then: createdAt is set to current ISO timestamp
       */
      const beforeAdd = new Date().toISOString();
      const result = await invokeHandler<any>('credential-add', validCredential);
      const afterAdd = new Date().toISOString();

      expect(result.createdAt).toBeDefined();
      expect(result.createdAt >= beforeAdd).toBe(true);
      expect(result.createdAt <= afterAdd).toBe(true);
    });

    it('should preserve all input fields in returned credential', async () => {
      /**
       * BV: No credential data loss during save operation
       *
       * Scenario:
       *   Given: Credential with all fields populated
       *   When: credential-add is called
       *   Then: All fields are preserved in returned object
       */
      const fullCredential = {
        ...validCredential,
        domain: 'CORP.LOCAL',
        sourceSessionId: 'session-456',
        targetId: 'target-789',
        validatedAccess: ['smb:SYSVOL', 'winrm'],
        isAdmin: true,
        notes: 'Domain admin credential',
      };

      const result = await invokeHandler<any>('credential-add', fullCredential);

      expect(result.username).toBe('admin');
      expect(result.secret).toBe('Password123!');
      expect(result.secretType).toBe('password');
      expect(result.domain).toBe('CORP.LOCAL');
      expect(result.source).toBe('mimikatz');
      expect(result.sourceSessionId).toBe('session-456');
      expect(result.targetId).toBe('target-789');
      expect(result.validatedAccess).toEqual(['smb:SYSVOL', 'winrm']);
      expect(result.isAdmin).toBe(true);
      expect(result.notes).toBe('Domain admin credential');
    });

    it('should link credential to engagement in Neo4j', async () => {
      /**
       * BV: Credentials are properly associated with their engagement
       *
       * Scenario:
       *   Given: User adds credential for engagement eng-123
       *   When: credential-add is called
       *   Then: MERGE creates HAS_CREDENTIAL relationship
       */
      await invokeHandler('credential-add', validCredential);

      const query = getLastQuery();
      expect(query?.query).toContain('HAS_CREDENTIAL');
      expect(query?.params.engagementId).toBe('eng-123');
    });

    it('should link credential to target when targetId provided', async () => {
      /**
       * BV: Credentials are linked to the target they were found on
       *
       * Scenario:
       *   Given: Credential has targetId specified
       *   When: credential-add is called
       *   Then: FOUND_ON relationship is created
       */
      const credWithTarget = { ...validCredential, targetId: 'target-123' };

      await invokeHandler('credential-add', credWithTarget);

      const query = getLastQuery();
      expect(query?.query).toContain('FOUND_ON');
      expect(query?.params.targetId).toBe('target-123');
    });

    it('should handle missing optional fields with defaults', async () => {
      /**
       * BV: Credentials with minimal data can still be saved
       *
       * Scenario:
       *   Given: Credential with only required fields
       *   When: credential-add is called
       *   Then: Optional fields default to empty/false
       */
      const minimalCredential = {
        username: 'admin',
        secret: 'pass123',
        secretType: 'password' as const,
        source: 'manual',
        engagementId: 'eng-123',
      };

      const result = await invokeHandler<any>('credential-add', minimalCredential);

      expect(result.domain).toBeUndefined();
      expect(result.validatedAccess).toEqual([]);
      expect(result.isAdmin).toBe(false);
    });

    it('should throw error when Neo4j write fails', async () => {
      /**
       * BV: Errors are not silently swallowed - user knows save failed
       *
       * Scenario:
       *   Given: Neo4j write operation fails
       *   When: credential-add is called
       *   Then: Error is thrown (not silently ignored)
       */
      setMockWriteError(new Error('Write failed'));

      await expect(
        invokeHandler('credential-add', validCredential)
      ).rejects.toThrow('Write failed');
    });
  });

  describe('BV: Credential ID format is secure and unique', () => {
    it('should use timestamp-based prefix for rough ordering', async () => {
      /**
       * BV: IDs are roughly sortable by creation time
       */
      const result = await invokeHandler<any>('credential-add', validCredential);

      // ID format: cred-{base36 timestamp}-{random}
      const parts = result.id.split('-');
      expect(parts).toHaveLength(3);
      expect(parts[0]).toBe('cred');
      expect(parseInt(parts[1], 36)).toBeGreaterThan(0);
    });

    it('should include random suffix to prevent predictability', async () => {
      /**
       * BV: IDs cannot be guessed/enumerated
       */
      const result = await invokeHandler<any>('credential-add', validCredential);

      const parts = result.id.split('-');
      expect(parts[2].length).toBeGreaterThan(4);
    });
  });
});

// ============================================================================
// credential-update Handler Tests
// ============================================================================

describe('credential-update handler', () => {
  describe('BV: Users can update credential metadata', () => {
    it('should update validatedAccess when provided', async () => {
      /**
       * BV: Users can track which services a credential works on
       *
       * Scenario:
       *   Given: Existing credential cred-123
       *   When: credential-update called with new validatedAccess
       *   Then: validatedAccess is updated in Neo4j
       */
      const result = await invokeHandler<boolean>(
        'credential-update',
        'cred-123',
        { validatedAccess: ['smb:SYSVOL', 'winrm'] }
      );

      expect(result).toBe(true);
      const query = getLastQuery();
      expect(query?.query).toContain('validatedAccess');
      expect(query?.params.validatedAccess).toEqual(['smb:SYSVOL', 'winrm']);
    });

    it('should update isAdmin flag when provided', async () => {
      /**
       * BV: Users can mark credentials as admin for prioritization
       */
      const result = await invokeHandler<boolean>(
        'credential-update',
        'cred-123',
        { isAdmin: true }
      );

      expect(result).toBe(true);
      const query = getLastQuery();
      expect(query?.params.isAdmin).toBe(true);
    });

    it('should update notes when provided', async () => {
      /**
       * BV: Users can add context notes to credentials
       */
      const result = await invokeHandler<boolean>(
        'credential-update',
        'cred-123',
        { notes: 'Service account for backup' }
      );

      expect(result).toBe(true);
      const query = getLastQuery();
      expect(query?.params.notes).toBe('Service account for backup');
    });

    it('should return true when no updates provided', async () => {
      /**
       * BV: Empty update is a no-op, not an error
       */
      const result = await invokeHandler<boolean>(
        'credential-update',
        'cred-123',
        {}
      );

      expect(result).toBe(true);
    });

    it('should return false on Neo4j error', async () => {
      /**
       * BV: Update failures are reported, not crashes
       */
      setMockWriteError(new Error('Update failed'));

      const result = await invokeHandler<boolean>(
        'credential-update',
        'cred-123',
        { isAdmin: true }
      );

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// credential-delete Handler Tests
// ============================================================================

describe('credential-delete handler', () => {
  describe('BV: Users can remove credentials', () => {
    it('should delete credential by ID', async () => {
      /**
       * BV: Unwanted credentials can be removed
       */
      const result = await invokeHandler<boolean>('credential-delete', 'cred-123');

      expect(result).toBe(true);
      const query = getLastQuery();
      expect(query?.query.toLowerCase()).toContain('delete');
      expect(query?.params.id).toBe('cred-123');
    });

    it('should use DETACH DELETE to remove relationships', async () => {
      /**
       * BV: Credential deletion doesn't leave orphaned relationships
       */
      await invokeHandler('credential-delete', 'cred-123');

      const query = getLastQuery();
      expect(query?.query.toLowerCase()).toContain('detach delete');
    });

    it('should return false on Neo4j error', async () => {
      /**
       * BV: Delete failures are reported
       */
      setMockWriteError(new Error('Delete failed'));

      const result = await invokeHandler<boolean>('credential-delete', 'cred-123');

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// credential-validate-access Handler Tests
// ============================================================================

describe('credential-validate-access handler', () => {
  describe('BV: Users can track service access validation', () => {
    it('should add access type to validatedAccess array', async () => {
      /**
       * BV: Successful authentications are tracked
       */
      const result = await invokeHandler<boolean>(
        'credential-validate-access',
        'cred-123',
        'service-456',
        'smb:SYSVOL'
      );

      expect(result).toBe(true);
      const query = getLastQuery();
      expect(query?.params.accessType).toBe('smb:SYSVOL');
    });

    it('should create GRANTS_ACCESS_TO relationship', async () => {
      /**
       * BV: Credential-service relationships are tracked in graph
       */
      await invokeHandler(
        'credential-validate-access',
        'cred-123',
        'service-456',
        'smb'
      );

      const query = getLastQuery();
      expect(query?.query).toContain('GRANTS_ACCESS_TO');
    });

    it('should not duplicate access types', async () => {
      /**
       * BV: Prevents duplicate entries in validatedAccess
       */
      await invokeHandler(
        'credential-validate-access',
        'cred-123',
        'service-456',
        'smb'
      );

      const query = getLastQuery();
      expect(query?.query).toContain('CASE');
      expect(query?.query).toContain('IN c.validatedAccess');
    });

    it('should return false on Neo4j error', async () => {
      /**
       * BV: Validation failures are reported
       */
      setMockWriteError(new Error('Validation failed'));

      const result = await invokeHandler<boolean>(
        'credential-validate-access',
        'cred-123',
        'service-456',
        'smb'
      );

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// credential-by-target Handler Tests
// ============================================================================

describe('credential-by-target handler', () => {
  describe('BV: Users can find credentials by target', () => {
    it('should return credentials linked to specific target', async () => {
      /**
       * BV: Quick lookup of credentials for lateral movement
       */
      const mockCreds = [
        createMockCredentialResult({ id: 'cred-1', username: 'admin' }),
        createMockCredentialResult({ id: 'cred-2', username: 'service' }),
      ];
      setMockQueryResults(mockCreds);

      const result = await invokeHandler<unknown[]>(
        'credential-by-target',
        'target-123'
      );

      expect(result).toHaveLength(2);
      const query = getLastQuery();
      expect(query?.params.targetId).toBe('target-123');
    });

    it('should query FOUND_ON relationship', async () => {
      /**
       * BV: Uses correct relationship to find target credentials
       */
      setMockQueryResults([]);

      await invokeHandler('credential-by-target', 'target-123');

      const query = getLastQuery();
      expect(query?.query).toContain('FOUND_ON');
    });

    it('should return empty array on Neo4j error', async () => {
      /**
       * BV: Errors handled gracefully
       */
      setMockQueryError(new Error('Query failed'));

      const result = await invokeHandler<unknown[]>(
        'credential-by-target',
        'target-123'
      );

      expect(result).toEqual([]);
    });
  });
});

// ============================================================================
// credential-get-admin Handler Tests
// ============================================================================

describe('credential-get-admin handler', () => {
  describe('BV: Users can quickly access admin credentials', () => {
    it('should return only credentials with isAdmin=true', async () => {
      /**
       * BV: Quick access to high-value credentials for escalation
       */
      const mockCreds = [
        createMockCredentialResult({ id: 'cred-1', isAdmin: true }),
      ];
      setMockQueryResults(mockCreds);

      await invokeHandler('credential-get-admin', 'eng-123');

      const query = getLastQuery();
      expect(query?.query).toContain('c.isAdmin = true');
    });

    it('should include target IP in results', async () => {
      /**
       * BV: Know which target the admin cred was found on
       */
      const mockCreds = [
        createMockCredentialResult({
          id: 'cred-1',
          isAdmin: true,
          targetIp: '192.168.1.100',
        }),
      ];
      setMockQueryResults(mockCreds);

      const result = await invokeHandler<unknown[]>(
        'credential-get-admin',
        'eng-123'
      );

      expect(result[0]).toHaveProperty('targetIp', '192.168.1.100');
    });

    it('should return empty array on Neo4j error', async () => {
      /**
       * BV: Graceful degradation
       */
      setMockQueryError(new Error('Query failed'));

      const result = await invokeHandler<unknown[]>(
        'credential-get-admin',
        'eng-123'
      );

      expect(result).toEqual([]);
    });
  });
});

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

describe('Edge Cases', () => {
  describe('BV: Handler registration', () => {
    it('should register all credential handlers', () => {
      /**
       * BV: All credential operations are available via IPC
       */
      const expectedHandlers = [
        'credential-list',
        'credential-add',
        'credential-update',
        'credential-delete',
        'credential-validate-access',
        'credential-by-target',
        'credential-get-admin',
      ];

      for (const handler of expectedHandlers) {
        expect(capturedHandlers.has(handler)).toBe(true);
      }
    });
  });

  describe('BV: Special characters in credential data', () => {
    it('should handle special characters in username', async () => {
      /**
       * BV: Usernames with special chars (domain\\user) are preserved
       */
      const cred = {
        username: 'CORP\\admin$',
        secret: 'pass',
        secretType: 'password' as const,
        source: 'manual',
        engagementId: 'eng-123',
      };

      const result = await invokeHandler<any>('credential-add', cred);

      expect(result.username).toBe('CORP\\admin$');
    });

    it('should handle special characters in secret', async () => {
      /**
       * BV: Passwords with special chars are preserved
       */
      const cred = {
        username: 'admin',
        secret: 'P@ssw0rd!$#%^&*()',
        secretType: 'password' as const,
        source: 'manual',
        engagementId: 'eng-123',
      };

      const result = await invokeHandler<any>('credential-add', cred);

      expect(result.secret).toBe('P@ssw0rd!$#%^&*()');
    });

    it('should handle unicode in notes', async () => {
      /**
       * BV: Notes with unicode chars are preserved
       */
      await invokeHandler(
        'credential-update',
        'cred-123',
        { notes: 'Domain: CORP' }
      );

      const query = getLastQuery();
      expect(query?.params.notes).toBe('Domain: CORP');
    });
  });

  describe('BV: Empty/null values', () => {
    it('should handle empty string username', async () => {
      /**
       * BV: Edge case - empty username doesn't crash
       */
      const cred = {
        username: '',
        secret: 'hash123',
        secretType: 'ntlm' as const,
        source: 'secretsdump',
        engagementId: 'eng-123',
      };

      const result = await invokeHandler<any>('credential-add', cred);

      expect(result.username).toBe('');
    });

    it('should handle null domain gracefully', async () => {
      /**
       * BV: Missing domain doesn't break storage
       */
      const cred = {
        username: 'admin',
        secret: 'pass',
        secretType: 'password' as const,
        source: 'manual',
        engagementId: 'eng-123',
        domain: undefined,
      };

      const result = await invokeHandler<any>('credential-add', cred);

      // Should not throw, domain defaults to empty
      expect(result).toHaveProperty('id');
    });
  });
});
