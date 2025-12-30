/**
 * Mock for neo4j-driver module
 *
 * Business Value Focus:
 * - Enables testing IPC handlers without Neo4j connection
 * - Configurable responses for different test scenarios
 * - Tracks query execution for assertions
 */

import { vi } from 'vitest';

/**
 * Mock Neo4j Record with properties unpacking
 */
export class MockRecord {
  private data: Map<string, any>;
  public keys: string[];

  constructor(data: Record<string, any>) {
    this.data = new Map(Object.entries(data));
    this.keys = Object.keys(data);
  }

  get(key: string): any {
    return this.data.get(key);
  }
}

/**
 * Mock Neo4j Result
 */
export class MockResult {
  public records: MockRecord[];

  constructor(records: Record<string, any>[]) {
    this.records = records.map(r => new MockRecord(r));
  }
}

/**
 * Mock Neo4j Session
 */
export class MockSession {
  public queries: Array<{ query: string; params: Record<string, any> }> = [];
  private mockResults: MockResult;
  private shouldFail: boolean;
  private errorMessage: string;

  constructor(options: {
    records?: Record<string, any>[];
    shouldFail?: boolean;
    errorMessage?: string;
  } = {}) {
    this.mockResults = new MockResult(options.records || []);
    this.shouldFail = options.shouldFail || false;
    this.errorMessage = options.errorMessage || 'Mock Neo4j error';
  }

  async run(query: string, params: Record<string, any> = {}): Promise<MockResult> {
    this.queries.push({ query, params });

    if (this.shouldFail) {
      throw new Error(this.errorMessage);
    }

    return this.mockResults;
  }

  async close(): Promise<void> {
    // No-op for mock
  }
}

/**
 * Mock Neo4j Driver
 */
export class MockDriver {
  private sessionOptions: {
    records?: Record<string, any>[];
    shouldFail?: boolean;
    errorMessage?: string;
  };
  private verifyFails: boolean;
  private verifyErrorMessage: string;
  public sessions: MockSession[] = [];

  constructor(options: {
    records?: Record<string, any>[];
    shouldFail?: boolean;
    errorMessage?: string;
    verifyFails?: boolean;
    verifyErrorMessage?: string;
  } = {}) {
    this.sessionOptions = {
      records: options.records || [],
      shouldFail: options.shouldFail || false,
      errorMessage: options.errorMessage,
    };
    this.verifyFails = options.verifyFails || false;
    this.verifyErrorMessage = options.verifyErrorMessage || 'Connection refused';
  }

  session(options?: { database?: string }): MockSession {
    const session = new MockSession(this.sessionOptions);
    this.sessions.push(session);
    return session;
  }

  async verifyConnectivity(): Promise<void> {
    if (this.verifyFails) {
      throw new Error(this.verifyErrorMessage);
    }
  }

  async close(): Promise<void> {
    // No-op for mock
  }
}

/**
 * Factory to create mock driver instances
 */
export function createMockDriver(options: {
  records?: Record<string, any>[];
  shouldFail?: boolean;
  errorMessage?: string;
  verifyFails?: boolean;
  verifyErrorMessage?: string;
} = {}): MockDriver {
  return new MockDriver(options);
}

/**
 * Mock Neo4j Integer type
 * Neo4j integers come as { low: number, high: number } objects
 */
export class MockInteger {
  low: number;
  high: number;

  constructor(value: number) {
    this.low = value;
    this.high = 0;
  }

  toNumber(): number {
    return this.low;
  }

  toString(): string {
    return String(this.low);
  }
}

/**
 * Mock Neo4j Node type with properties
 */
export class MockNode {
  identity: MockInteger;
  labels: string[];
  properties: Record<string, any>;

  constructor(id: number, labels: string[], properties: Record<string, any>) {
    this.identity = new MockInteger(id);
    this.labels = labels;
    this.properties = properties;
  }
}

/**
 * Factory function to create mock nodes for testing
 */
export function createMockNode(
  id: number,
  labels: string[],
  properties: Record<string, any>
): MockNode {
  return new MockNode(id, labels, properties);
}

/**
 * Default mock implementation for neo4j-driver module
 */
let currentMockDriver: MockDriver | null = null;

export function setMockDriver(driver: MockDriver | null): void {
  currentMockDriver = driver;
}

export function getMockDriver(): MockDriver | null {
  return currentMockDriver;
}

const neo4jDriverMock = {
  driver: vi.fn((uri: string, auth: any, config?: any) => {
    if (currentMockDriver) {
      return currentMockDriver;
    }
    return new MockDriver();
  }),
  auth: {
    basic: vi.fn((username: string, password: string) => ({
      scheme: 'basic',
      principal: username,
      credentials: password,
    })),
  },
  int: vi.fn((value: number) => new MockInteger(value)),
  isInt: vi.fn((value: any) => value instanceof MockInteger),
};

export default neo4jDriverMock;

// Named exports for types
export type { Driver, Session, Record, Result } from 'neo4j-driver';
