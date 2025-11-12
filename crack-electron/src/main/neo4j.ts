import { ipcMain } from 'electron';
import neo4j, { Driver, Session } from 'neo4j-driver';
import { debug, logNeo4j, logIPC, logQuery, logError, logPerformance } from './debug';

debug.section('NEO4J INITIALIZATION');

// Neo4j connection configuration
const NEO4J_URI = process.env.NEO4J_URI || 'bolt://127.0.0.1:7687';
const NEO4J_USER = process.env.NEO4J_USER || 'neo4j';
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || 'Neo4j123';

logNeo4j('Neo4j configuration loaded', {
  uri: NEO4J_URI,
  user: NEO4J_USER,
  password: NEO4J_PASSWORD ? `${NEO4J_PASSWORD.slice(0, 3)}***` : 'NOT SET',
});

let driver: Driver | null = null;

// Initialize Neo4j driver
function getDriver(): Driver {
  if (!driver) {
    logNeo4j('Creating Neo4j driver instance', {
      uri: NEO4J_URI,
      maxPoolSize: 50,
      timeout: 2000,
    });

    driver = neo4j.driver(
      NEO4J_URI,
      neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD),
      {
        maxConnectionPoolSize: 50,
        connectionAcquisitionTimeout: 2000,
      }
    );

    logNeo4j('Neo4j driver created successfully');
  }
  return driver;
}

// Helper to run queries
async function runQuery<T = any>(
  query: string,
  params: Record<string, any> = {}
): Promise<T[]> {
  const startTime = Date.now();
  const session: Session = getDriver().session();

  logQuery('Executing Cypher query', {
    query: query.substring(0, 100) + (query.length > 100 ? '...' : ''),
    params: Object.keys(params).length > 0 ? params : 'none',
  });

  try {
    const result = await session.run(query, params);
    const duration = Date.now() - startTime;

    logPerformance('Query completed', {
      duration_ms: duration,
      records: result.records.length,
    });

    const mapped = result.records.map((record) => {
      const obj: any = {};
      record.keys.forEach((key) => {
        const value = record.get(key);
        // Handle Neo4j types
        if (value && typeof value === 'object' && 'properties' in value) {
          // Preserve the original ID from properties, don't overwrite with Neo4j's internal node ID
          obj[key] = { ...value.properties };
        } else if (value && typeof value === 'object' && 'low' in value) {
          obj[key] = value.toNumber();
        } else {
          obj[key] = value;
        }
      });
      return obj as T;
    });

    logQuery('Query results mapped successfully', { count: mapped.length });
    return mapped;
  } catch (error) {
    const duration = Date.now() - startTime;
    logError('Query execution failed', {
      duration_ms: duration,
      error: error instanceof Error ? error.message : String(error),
      query: query.substring(0, 200),
    });
    console.error('Neo4j query error:', error);
    throw error;
  } finally {
    await session.close();
    logQuery('Session closed');
  }
}

debug.subsection('IPC HANDLERS REGISTRATION');

// IPC Handler: Search commands
ipcMain.handle('search-commands', async (_event, searchQuery: string, filters?: {
  category?: string;
  tags?: string[];
  oscp_only?: boolean;
}) => {
  logIPC('IPC: search-commands called', {
    query: searchQuery || '(empty)',
    filters,
  });

  try {
    let query = `
      MATCH (c:Command)
    `;

    const params: Record<string, any> = {};

    // Build WHERE clause
    const conditions: string[] = [];

    if (searchQuery && searchQuery.trim()) {
      conditions.push(`(
        toLower(c.name) CONTAINS toLower($searchQuery)
        OR toLower(c.description) CONTAINS toLower($searchQuery)
        OR toLower(c.command) CONTAINS toLower($searchQuery)
      )`);
      params.searchQuery = searchQuery.trim();
    }

    if (filters?.category) {
      conditions.push('c.category = $category');
      params.category = filters.category;
    }

    if (filters?.oscp_only) {
      conditions.push('c.oscp_relevance = true');
    }

    if (filters?.tags && filters.tags.length > 0) {
      conditions.push(`
        EXISTS {
          MATCH (c)-[:TAGGED]->(t:Tag)
          WHERE t.name IN $tags
        }
      `);
      params.tags = filters.tags;
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += `
      RETURN c.id as id, c.name as name, c.category as category,
             c.description as description, c.tags as tags,
             c.oscp_relevance as oscp_relevance
      ORDER BY c.name
      LIMIT 100
    `;

    const results = await runQuery(query, params);
    logIPC('IPC: search-commands completed', { resultCount: results.length });
    return results;
  } catch (error) {
    logError('IPC: search-commands failed', error);
    console.error('Search error:', error);
    return [];
  }
});
logIPC('Registered IPC handler: search-commands');

// IPC Handler: Get command details
ipcMain.handle('get-command', async (_event, commandId: string) => {
  logIPC('IPC: get-command called', { commandId });

  try {
    const query = `
      MATCH (c:Command {id: $commandId})
      OPTIONAL MATCH (c)-[:HAS_FLAG]->(f:Flag)
      OPTIONAL MATCH (c)-[:USES_VARIABLE]->(v:Variable)
      OPTIONAL MATCH (c)-[:HAS_INDICATOR]->(i:Indicator)
      OPTIONAL MATCH (c)-[:TAGGED]->(t:Tag)
      RETURN c as command,
             collect(DISTINCT f{.*}) as flags,
             collect(DISTINCT v{.*}) as variables,
             collect(DISTINCT i{.*}) as indicators,
             collect(DISTINCT t.name) as tags
    `;

    const results = await runQuery(query, { commandId });
    if (results.length > 0) {
      const record = results[0];
      const command = {
        ...record.command,
        flags: record.flags.filter((f: any) => f.name),
        variables: record.variables.filter((v: any) => v.name),
        indicators: record.indicators.filter((i: any) => i.pattern),
        tags: record.tags.filter((t: string) => t),
      };
      logIPC('IPC: get-command completed', {
        id: command.id,
        name: command.name,
        flagCount: command.flags.length,
      });
      return command;
    }
    logIPC('IPC: get-command - command not found', { commandId });
    return null;
  } catch (error) {
    logError('IPC: get-command failed', error);
    console.error('Get command error:', error);
    return null;
  }
});
logIPC('Registered IPC handler: get-command');

// IPC Handler: Get command graph (relationships)
ipcMain.handle('get-graph', async (_event, commandId: string) => {
  logIPC('IPC: get-graph called', { commandId });

  try {
    const query = `
      MATCH (c:Command {id: $commandId})
      OPTIONAL MATCH (c)-[r:ALTERNATIVE]->(alt:Command)
      OPTIONAL MATCH (c)-[p:PREREQUISITE]->(pre:Command)
      OPTIONAL MATCH (c)-[n:NEXT_STEP]->(next:Command)
      OPTIONAL MATCH (c)<-[ra:ALTERNATIVE]-(altFrom:Command)
      OPTIONAL MATCH (c)<-[pa:PREREQUISITE]-(preFrom:Command)

      WITH c,
           collect(DISTINCT {source: c.id, target: alt.id, type: 'ALTERNATIVE', command: alt{.*}}) as alternatives,
           collect(DISTINCT {source: c.id, target: pre.id, type: 'PREREQUISITE', command: pre{.*}}) as prerequisites,
           collect(DISTINCT {source: c.id, target: next.id, type: 'NEXT_STEP', command: next{.*}}) as nextSteps,
           collect(DISTINCT {source: altFrom.id, target: c.id, type: 'ALTERNATIVE', command: altFrom{.*}}) as alternativesFrom,
           collect(DISTINCT {source: preFrom.id, target: c.id, type: 'PREREQUISITE', command: preFrom{.*}}) as prerequisitesFrom

      RETURN c as center,
             alternatives,
             prerequisites,
             nextSteps,
             alternativesFrom,
             prerequisitesFrom
    `;

    const results = await runQuery(query, { commandId });
    if (results.length > 0) {
      const data = results[0];

      // Build nodes and edges for Cytoscape
      const nodes = new Map();
      const edges: any[] = [];

      // Add center node
      nodes.set(commandId, {
        data: { id: commandId, label: data.center.name, ...data.center, type: 'center' }
      });

      // Process relationships
      const processEdges = (rels: any[], reverse = false) => {
        rels.forEach((rel: any) => {
          if (rel.target && rel.command.id) {
            nodes.set(rel.command.id, {
              data: { id: rel.command.id, label: rel.command.name, ...rel.command }
            });
            edges.push({
              data: {
                id: `${rel.source}-${rel.target}`,
                source: reverse ? rel.target : rel.source,
                target: reverse ? rel.source : rel.target,
                label: rel.type,
                type: rel.type.toLowerCase()
              }
            });
          }
        });
      };

      processEdges(data.alternatives);
      processEdges(data.prerequisites);
      processEdges(data.nextSteps);
      processEdges(data.alternativesFrom, true);
      processEdges(data.prerequisitesFrom, true);

      const graphData = {
        elements: {
          nodes: Array.from(nodes.values()),
          edges: edges
        }
      };

      logIPC('IPC: get-graph completed', {
        nodeCount: graphData.elements.nodes.length,
        edgeCount: graphData.elements.edges.length,
      });

      return graphData;
    }
    logIPC('IPC: get-graph - no data found', { commandId });
    return { elements: { nodes: [], edges: [] } };
  } catch (error) {
    logError('IPC: get-graph failed', error);
    console.error('Get graph error:', error);
    return { elements: { nodes: [], edges: [] } };
  }
});
logIPC('Registered IPC handler: get-graph');

// IPC Handler: Health check
ipcMain.handle('neo4j-health-check', async () => {
  logIPC('IPC: neo4j-health-check called');

  try {
    const driver = getDriver();
    await driver.verifyConnectivity();
    logNeo4j('Health check passed - connectivity verified');
    return { connected: true, uri: NEO4J_URI };
  } catch (error) {
    logError('Neo4j health check failed', error);
    console.error('Neo4j health check failed:', error);
    return { connected: false, error: String(error) };
  }
});
logIPC('Registered IPC handler: neo4j-health-check');

// IPC Handler: Console bridge (renderer logs to terminal)
ipcMain.on('log-to-terminal', (_event, level: string, message: string) => {
  const prefix = `[RENDERER:${level.toUpperCase()}]`;
  switch (level) {
    case 'error':
      console.error(prefix, message);
      break;
    case 'warn':
      console.warn(prefix, message);
      break;
    case 'info':
      console.info(prefix, message);
      break;
    default:
      console.log(prefix, message);
  }
});
logIPC('Registered IPC handler: log-to-terminal');

// Cleanup on app quit
process.on('exit', async () => {
  if (driver) {
    logNeo4j('Closing Neo4j driver on exit');
    await driver.close();
    logNeo4j('Neo4j driver closed successfully');
  }
});

debug.subsection('NEO4J MODULE READY');
logNeo4j('Neo4j IPC handlers initialized successfully');
console.log('Neo4j IPC handlers initialized');
