/**
 * Test Setup for Crackpedia
 *
 * Initializes mocks and test utilities before each test file.
 * Ensures isolation between tests and consistent mock behavior.
 */

import { vi, beforeEach, afterEach } from 'vitest';
import { clearIpcRegistry } from './__mocks__/electron';
import { setMockDriver } from './__mocks__/neo4j-driver';

// Mock electron module
vi.mock('electron', () => import('./__mocks__/electron'));

// Mock neo4j-driver module
vi.mock('neo4j-driver', () => import('./__mocks__/neo4j-driver'));

// Mock fs module (for file operations)
vi.mock('fs', () => ({
  existsSync: vi.fn(() => true),
  readdirSync: vi.fn(() => []),
  readFileSync: vi.fn(() => ''),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
}));

// Mock path module (for consistent cross-platform paths)
vi.mock('path', async () => {
  const actual = await vi.importActual('path');
  return {
    ...actual,
    resolve: vi.fn((...args: string[]) => args.join('/')),
  };
});

/**
 * Reset all mocks before each test
 */
beforeEach(() => {
  vi.clearAllMocks();
  clearIpcRegistry();
  setMockDriver(null);
});

/**
 * Clean up after each test
 */
afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * Global test utilities
 */
export const testUtils = {
  /**
   * Create a mock command for testing
   */
  createMockCommand(overrides: Partial<{
    id: string;
    name: string;
    description: string;
    command: string;
    category: string;
    subcategory: string;
    tags: string[];
    oscp_relevance: boolean;
    flags: any[];
    variables: any[];
    indicators: any[];
  }> = {}): Record<string, any> {
    return {
      id: overrides.id || 'test-command-1',
      name: overrides.name || 'Test Command',
      description: overrides.description || 'A test command for unit tests',
      command: overrides.command || 'test --flag <VAR>',
      category: overrides.category || 'test',
      subcategory: overrides.subcategory || '',
      tags: overrides.tags || ['test', 'OSCP:HIGH'],
      oscp_relevance: overrides.oscp_relevance ?? true,
      flags: overrides.flags || [],
      variables: overrides.variables || [],
      indicators: overrides.indicators || [],
    };
  },

  /**
   * Create a mock cheatsheet for testing
   */
  createMockCheatsheet(overrides: Partial<{
    id: string;
    name: string;
    description: string;
    tags: string | string[];
    sections: any[];
  }> = {}): Record<string, any> {
    return {
      id: overrides.id || 'test-cheatsheet-1',
      name: overrides.name || 'Test Cheatsheet',
      description: overrides.description || 'A test cheatsheet',
      tags: overrides.tags || 'test|reference',
      sections: overrides.sections || [],
    };
  },

  /**
   * Create a mock attack chain for testing
   */
  createMockChain(overrides: Partial<{
    id: string;
    name: string;
    description: string;
    category: string;
    platform: string;
    difficulty: string;
    steps: any[];
  }> = {}): Record<string, any> {
    return {
      id: overrides.id || 'test-chain-1',
      name: overrides.name || 'Test Attack Chain',
      description: overrides.description || 'A test attack chain',
      category: overrides.category || 'test',
      platform: overrides.platform || 'Windows',
      difficulty: overrides.difficulty || 'Medium',
      steps: overrides.steps || [],
    };
  },

  /**
   * Create a mock Neo4j integer
   */
  createMockInteger(value: number): { low: number; high: number; toNumber: () => number } {
    return {
      low: value,
      high: 0,
      toNumber: () => value,
    };
  },

  /**
   * Create a mock Neo4j node
   */
  createMockNode(properties: Record<string, any>): { properties: Record<string, any> } {
    return {
      properties,
    };
  },

  /**
   * Simulate a delay (for testing async behavior)
   */
  delay: (ms: number) => new Promise(resolve => setTimeout(resolve, ms)),
};
