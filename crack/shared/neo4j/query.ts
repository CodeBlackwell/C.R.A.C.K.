/**
 * Shared Neo4j Query Helper
 *
 * Provides centralized query execution with:
 * - Automatic Neo4j type conversion (Integer, Node properties)
 * - Performance logging
 * - Error handling with graceful fallbacks
 * - Parameterized query support
 */

import { Session, Record as Neo4jRecord } from 'neo4j-driver';
import { neo4jDriver } from './driver';

interface QueryOptions {
  /** Custom session (uses default if not provided) */
  session?: Session;
  /** Log query execution (default: false) */
  logQuery?: boolean;
  /** Logger function (uses console.log if not provided) */
  logger?: (category: string, message: string, data?: unknown) => void;
}

/**
 * Convert Neo4j types to plain JavaScript types
 * Handles: Integer, Node properties, null values
 */
function convertNeo4jValue(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  // Neo4j Integer (has low/high properties)
  if (typeof value === 'object' && value !== null && 'low' in value && 'high' in value) {
    const neo4jInt = value as { low: number; high: number; toNumber: () => number };
    if (typeof neo4jInt.toNumber === 'function') {
      return neo4jInt.toNumber();
    }
    return neo4jInt.low;
  }

  // Neo4j Node (has properties)
  if (typeof value === 'object' && value !== null && 'properties' in value) {
    const node = value as { properties: Record<string, unknown> };
    return convertNeo4jRecord(node.properties);
  }

  // Array - recursively convert
  if (Array.isArray(value)) {
    return value.map(convertNeo4jValue);
  }

  // Object - recursively convert
  if (typeof value === 'object' && value !== null) {
    return convertNeo4jRecord(value as Record<string, unknown>);
  }

  return value;
}

/**
 * Convert a Neo4j record to plain object
 */
function convertNeo4jRecord(record: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    result[key] = convertNeo4jValue(value);
  }
  return result;
}

/**
 * Execute a Cypher query and return typed results
 *
 * @param query Cypher query string
 * @param params Query parameters
 * @param options Query options
 * @returns Array of result records
 *
 * @example
 * const commands = await runQuery<Command>(
 *   'MATCH (c:Command) WHERE c.name CONTAINS $search RETURN c',
 *   { search: 'nmap' }
 * );
 */
export async function runQuery<T = Record<string, unknown>>(
  query: string,
  params: Record<string, unknown> = {},
  options: QueryOptions = {}
): Promise<T[]> {
  const startTime = Date.now();
  const { logQuery = false, logger } = options;
  const session = options.session ?? neo4jDriver.getSession();
  const shouldCloseSession = !options.session;

  const log = (category: string, message: string, data?: unknown) => {
    if (logQuery && logger) {
      logger(category, message, data);
    } else if (logQuery) {
      console.log(`[${category}] ${message}`, data ?? '');
    }
  };

  log('QUERY', 'Executing Cypher query', {
    query: query.substring(0, 100) + (query.length > 100 ? '...' : ''),
    params: Object.keys(params).length > 0 ? params : 'none',
  });

  try {
    const result = await session.run(query, params);
    const duration = Date.now() - startTime;

    log('PERFORMANCE', 'Query completed', {
      duration_ms: duration,
      records: result.records.length,
    });

    const mapped = result.records.map((record: Neo4jRecord) => {
      const obj: Record<string, unknown> = {};
      record.keys.forEach((key) => {
        obj[key as string] = convertNeo4jValue(record.get(key));
      });
      return obj as T;
    });

    return mapped;
  } catch (error) {
    const duration = Date.now() - startTime;
    log('ERROR', 'Query execution failed', {
      duration_ms: duration,
      error: error instanceof Error ? error.message : String(error),
      query: query.substring(0, 200),
    });
    throw error;
  } finally {
    if (shouldCloseSession) {
      await session.close();
    }
  }
}

/**
 * Execute a query and return single result or null
 */
export async function runQuerySingle<T = Record<string, unknown>>(
  query: string,
  params: Record<string, unknown> = {},
  options: QueryOptions = {}
): Promise<T | null> {
  const results = await runQuery<T>(query, params, options);
  return results.length > 0 ? results[0] : null;
}

/**
 * Execute a write query (CREATE, MERGE, SET, DELETE)
 * Returns the query statistics
 */
export async function runWrite(
  query: string,
  params: Record<string, unknown> = {},
  options: QueryOptions = {}
): Promise<{
  nodesCreated: number;
  nodesDeleted: number;
  relationshipsCreated: number;
  relationshipsDeleted: number;
  propertiesSet: number;
}> {
  const session = options.session ?? neo4jDriver.getSession();
  const shouldCloseSession = !options.session;

  try {
    const result = await session.run(query, params);
    const stats = result.summary.counters.updates();

    return {
      nodesCreated: stats.nodesCreated,
      nodesDeleted: stats.nodesDeleted,
      relationshipsCreated: stats.relationshipsCreated,
      relationshipsDeleted: stats.relationshipsDeleted,
      propertiesSet: stats.propertiesSet,
    };
  } finally {
    if (shouldCloseSession) {
      await session.close();
    }
  }
}

/**
 * Safe query execution - returns empty array on error
 * Useful for non-critical queries where failures should be silent
 */
export async function runQuerySafe<T = Record<string, unknown>>(
  query: string,
  params: Record<string, unknown> = {},
  options: QueryOptions = {}
): Promise<T[]> {
  try {
    return await runQuery<T>(query, params, options);
  } catch {
    return [];
  }
}

/** Re-export driver for direct access when needed */
export { neo4jDriver } from './driver';
