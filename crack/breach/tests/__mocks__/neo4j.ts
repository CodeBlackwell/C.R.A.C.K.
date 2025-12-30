/**
 * Neo4j Mock for Vitest
 *
 * Provides configurable mock implementations for Neo4j query functions.
 * Supports testing various query scenarios: success, failure, empty results.
 */

import { vi } from 'vitest';

/**
 * Mock query results store
 */
let mockQueryResults: unknown[] = [];
let mockWriteStats = {
  nodesCreated: 0,
  nodesDeleted: 0,
  relationshipsCreated: 0,
  relationshipsDeleted: 0,
  propertiesSet: 0,
};
let mockQueryError: Error | null = null;
let mockWriteError: Error | null = null;

/**
 * Captured queries for assertions
 */
export const capturedQueries: Array<{
  query: string;
  params: Record<string, unknown>;
  type: 'read' | 'write';
}> = [];

/**
 * Mock runQuery implementation
 */
export const runQuery = vi.fn(async (
  query: string,
  params: Record<string, unknown> = {}
): Promise<unknown[]> => {
  capturedQueries.push({ query, params, type: 'read' });

  if (mockQueryError) {
    throw mockQueryError;
  }

  return mockQueryResults;
});

/**
 * Mock runWrite implementation
 */
export const runWrite = vi.fn(async (
  query: string,
  params: Record<string, unknown> = {}
): Promise<typeof mockWriteStats> => {
  capturedQueries.push({ query, params, type: 'write' });

  if (mockWriteError) {
    throw mockWriteError;
  }

  return mockWriteStats;
});

/**
 * Mock runQuerySingle implementation
 */
export const runQuerySingle = vi.fn(async (
  query: string,
  params: Record<string, unknown> = {}
): Promise<unknown | null> => {
  capturedQueries.push({ query, params, type: 'read' });

  if (mockQueryError) {
    throw mockQueryError;
  }

  return mockQueryResults.length > 0 ? mockQueryResults[0] : null;
});

/**
 * Mock runQuerySafe implementation (never throws)
 */
export const runQuerySafe = vi.fn(async (
  query: string,
  params: Record<string, unknown> = {}
): Promise<unknown[]> => {
  capturedQueries.push({ query, params, type: 'read' });

  if (mockQueryError) {
    return [];
  }

  return mockQueryResults;
});

/**
 * Mock neo4jDriver
 */
export const neo4jDriver = {
  getSession: vi.fn(() => ({
    run: vi.fn(),
    close: vi.fn(),
  })),
  close: vi.fn(),
  verifyConnectivity: vi.fn(() => Promise.resolve()),
};

// ============================================================================
// Test Helpers
// ============================================================================

/**
 * Set mock query results for the next query call
 */
export function setMockQueryResults(results: unknown[]): void {
  mockQueryResults = results;
}

/**
 * Set mock write statistics for the next write call
 */
export function setMockWriteStats(stats: Partial<typeof mockWriteStats>): void {
  mockWriteStats = { ...mockWriteStats, ...stats };
}

/**
 * Set mock query error (will be thrown on next query)
 */
export function setMockQueryError(error: Error | null): void {
  mockQueryError = error;
}

/**
 * Set mock write error (will be thrown on next write)
 */
export function setMockWriteError(error: Error | null): void {
  mockWriteError = error;
}

/**
 * Reset all Neo4j mocks to default state
 */
export function resetNeo4jMocks(): void {
  mockQueryResults = [];
  mockWriteStats = {
    nodesCreated: 0,
    nodesDeleted: 0,
    relationshipsCreated: 0,
    relationshipsDeleted: 0,
    propertiesSet: 0,
  };
  mockQueryError = null;
  mockWriteError = null;
  capturedQueries.length = 0;

  runQuery.mockClear();
  runWrite.mockClear();
  runQuerySingle.mockClear();
  runQuerySafe.mockClear();
}

/**
 * Get the last captured query
 */
export function getLastQuery(): typeof capturedQueries[0] | undefined {
  return capturedQueries[capturedQueries.length - 1];
}

/**
 * Get all captured queries of a specific type
 */
export function getQueriesByType(type: 'read' | 'write'): typeof capturedQueries {
  return capturedQueries.filter(q => q.type === type);
}

/**
 * Assert that a query was called with specific patterns
 */
export function assertQueryContains(pattern: string): void {
  const found = capturedQueries.some(q =>
    q.query.toLowerCase().includes(pattern.toLowerCase())
  );
  if (!found) {
    throw new Error(
      `Expected query containing "${pattern}" but got:\n${
        capturedQueries.map(q => q.query).join('\n')
      }`
    );
  }
}

// ============================================================================
// Factory Helpers for Test Data
// ============================================================================

/**
 * Create mock credential result
 */
export function createMockCredentialResult(overrides: Record<string, unknown> = {}): unknown {
  return {
    c: {
      properties: {
        id: 'cred-test-123',
        username: 'testuser',
        secret: 'TestPass123!',
        secretType: 'password',
        domain: 'TESTDOMAIN',
        source: 'mimikatz',
        engagementId: 'eng-test-123',
        validatedAccess: [],
        isAdmin: false,
        createdAt: '2024-01-15T12:00:00.000Z',
        notes: '',
        ...overrides,
      },
    },
    targetIp: '192.168.1.100',
    targetHostname: 'DC01',
  };
}

/**
 * Create mock engagement result
 */
export function createMockEngagementResult(overrides: Record<string, unknown> = {}): unknown {
  return {
    e: {
      id: 'eng-test-123',
      name: 'Test Engagement',
      status: 'active',
      start_date: '2024-01-15',
      end_date: null,
      scope_type: 'internal',
      scope_text: '192.168.1.0/24',
      notes: 'Test notes',
      created_at: '2024-01-15T12:00:00.000Z',
      ...overrides,
    },
  };
}

/**
 * Create mock loot result
 */
export function createMockLootResult(overrides: Record<string, unknown> = {}): unknown {
  return {
    l: {
      properties: {
        id: 'loot-test-123',
        type: 'file',
        name: 'test.txt',
        path: '/tmp/loot/test.txt',
        sourcePath: '/home/user/test.txt',
        sourceSessionId: 'session-123',
        targetId: 'target-123',
        engagementId: 'eng-test-123',
        contentPreview: 'File content preview...',
        size: 1024,
        detectedPatterns: [],
        extractedData: '{}',
        createdAt: '2024-01-15T12:00:00.000Z',
        notes: '',
        ...overrides,
      },
    },
    targetIp: '192.168.1.100',
    targetHostname: 'DC01',
  };
}

/**
 * Create mock session result
 */
export function createMockSessionResult(overrides: Record<string, unknown> = {}): unknown {
  return {
    s: {
      properties: {
        id: 'session-test-123',
        type: 'shell',
        status: 'running',
        command: '/bin/bash',
        args: [],
        workingDir: '/home/kali',
        pid: 12345,
        targetId: 'target-123',
        engagementId: 'eng-test-123',
        linkedSessions: [],
        label: 'Test Session',
        persistent: true,
        interactive: true,
        startedAt: '2024-01-15T12:00:00.000Z',
        ...overrides,
      },
    },
  };
}

export default {
  runQuery,
  runWrite,
  runQuerySingle,
  runQuerySafe,
  neo4jDriver,
};
