import { ipcMain } from 'electron';
import neo4j, { Driver, Session } from 'neo4j-driver';
import { debug, logNeo4j, logIPC, logQuery, logError, logPerformance } from './debug';
import * as fs from 'fs';
import * as path from 'path';

debug.section('NEO4J INITIALIZATION');

// Neo4j connection configuration (password required via environment variable)
const NEO4J_URI = process.env.NEO4J_URI || 'bolt://127.0.0.1:7687';
const NEO4J_USER = process.env.NEO4J_USER || 'neo4j';
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || '';

// Warn if password not set
if (!NEO4J_PASSWORD) {
  console.warn('[NEO4J] WARNING: NEO4J_PASSWORD not set. Set via: export NEO4J_PASSWORD="your_password"');
}

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
  subcategory?: string;
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

    if (filters?.subcategory) {
      // "General" is the display name for empty subcategories
      if (filters.subcategory === 'General') {
        conditions.push('(c.subcategory = "" OR c.subcategory IS NULL)');
      } else {
        conditions.push('c.subcategory = $subcategory');
        params.subcategory = filters.subcategory;
      }
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

// IPC Handler: Get category hierarchy with subcategories
ipcMain.handle('get-category-hierarchy', async () => {
  logIPC('IPC: get-category-hierarchy called');

  try {
    const query = `
      MATCH (c:Command)
      WITH c.category as category,
           COALESCE(c.subcategory, '') as subcategory,
           c
      WITH category, subcategory, count(c) as count
      ORDER BY category, subcategory
      WITH category, collect({name: subcategory, count: count}) as subcategories
      RETURN category,
             subcategories,
             reduce(total = 0, sub IN subcategories | total + sub.count) as totalCount
      ORDER BY totalCount DESC
    `;

    const results = await runQuery(query);

    // Process results to group "General" for empty subcategories
    const processed = results.map((row: any) => ({
      category: row.category,
      totalCount: typeof row.totalCount === 'number' ? row.totalCount : (row.totalCount?.toNumber?.() || 0),
      subcategories: row.subcategories.map((sub: any) => ({
        name: sub.name === '' ? 'General' : sub.name,
        count: typeof sub.count === 'number' ? sub.count : (sub.count?.toNumber?.() || 0)
      }))
    }));

    logIPC('IPC: get-category-hierarchy completed', {
      categoryCount: processed.length
    });
    return processed;
  } catch (error) {
    logError('IPC: get-category-hierarchy failed', error);
    console.error('Get category hierarchy error:', error);
    return [];
  }
});
logIPC('Registered IPC handler: get-category-hierarchy');

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

      // Parse JSON fields if they're strings
      const parseJsonField = (field: any) => {
        if (typeof field === 'string') {
          try {
            return JSON.parse(field);
          } catch {
            return field;
          }
        }
        return field;
      };

      // Parse success/failure indicators from command properties (string arrays)
      const successIndicators = parseJsonField(record.command.success_indicators) || [];
      const failureIndicators = parseJsonField(record.command.failure_indicators) || [];

      // Transform string indicators to structured format for UI
      const transformedIndicators = [
        ...successIndicators.map((s: string) => ({ pattern: s, type: 'success', description: '' })),
        ...failureIndicators.map((s: string) => ({ pattern: s, type: 'failure', description: '' })),
      ];

      const command = {
        ...record.command,
        flags: record.flags.filter((f: any) => f.flag),  // Fixed: was f.name
        variables: record.variables.filter((v: any) => v.name),
        indicators: transformedIndicators.length > 0
          ? transformedIndicators
          : record.indicators.filter((i: any) => i.pattern),  // Fallback to relationship-based indicators
        success_indicators: successIndicators,
        failure_indicators: failureIndicators,
        tags: record.tags.filter((t: string) => t),
        troubleshooting: parseJsonField(record.command.troubleshooting),
        flag_explanations: parseJsonField(record.command.flag_explanations),
        prerequisites: parseJsonField(record.command.prerequisites),
        alternatives: parseJsonField(record.command.alternatives),
        next_steps: parseJsonField(record.command.next_steps),
        examples: parseJsonField(record.command.examples),
        educational: parseJsonField(record.command.educational),
        related_commands: parseJsonField(record.command.related_commands),
        filled_example: record.command.filled_example || null,
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
      OPTIONAL MATCH (c)<-[na:NEXT_STEP]-(nextFrom:Command)

      WITH c,
           collect(DISTINCT {source: c.id, target: alt.id, type: 'ALTERNATIVE', command: alt{.*}}) as alternatives,
           collect(DISTINCT {source: c.id, target: pre.id, type: 'PREREQUISITE', command: pre{.*}}) as prerequisites,
           collect(DISTINCT {source: c.id, target: next.id, type: 'NEXT_STEP', command: next{.*}}) as nextSteps,
           collect(DISTINCT {source: altFrom.id, target: c.id, type: 'ALTERNATIVE', command: altFrom{.*}}) as alternativesFrom,
           collect(DISTINCT {source: preFrom.id, target: c.id, type: 'PREREQUISITE', command: preFrom{.*}}) as prerequisitesFrom,
           collect(DISTINCT {source: nextFrom.id, target: c.id, type: 'NEXT_STEP', command: nextFrom{.*}}) as nextStepsFrom

      RETURN c as center,
             alternatives,
             prerequisites,
             nextSteps,
             alternativesFrom,
             prerequisitesFrom,
             nextStepsFrom
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
          if (rel.command && rel.command.id && rel.source && rel.target) {
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
      processEdges(data.nextStepsFrom, true);

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

// IPC Handler: Get command graph with metadata (for Chain Explorer - includes hasRelationships flag)
ipcMain.handle('get-graph-with-metadata', async (_event, commandId: string) => {
  logIPC('IPC: get-graph-with-metadata called', { commandId });

  try {
    // Same query as get-graph to fetch relationships
    const query = `
      MATCH (c:Command {id: $commandId})
      OPTIONAL MATCH (c)-[r:ALTERNATIVE]->(alt:Command)
      OPTIONAL MATCH (c)-[p:PREREQUISITE]->(pre:Command)
      OPTIONAL MATCH (c)-[n:NEXT_STEP]->(next:Command)
      OPTIONAL MATCH (c)<-[ra:ALTERNATIVE]-(altFrom:Command)
      OPTIONAL MATCH (c)<-[pa:PREREQUISITE]-(preFrom:Command)
      OPTIONAL MATCH (c)<-[na:NEXT_STEP]-(nextFrom:Command)

      WITH c,
           collect(DISTINCT {source: c.id, target: alt.id, type: 'ALTERNATIVE', command: alt{.*}}) as alternatives,
           collect(DISTINCT {source: c.id, target: pre.id, type: 'PREREQUISITE', command: pre{.*}}) as prerequisites,
           collect(DISTINCT {source: c.id, target: next.id, type: 'NEXT_STEP', command: next{.*}}) as nextSteps,
           collect(DISTINCT {source: altFrom.id, target: c.id, type: 'ALTERNATIVE', command: altFrom{.*}}) as alternativesFrom,
           collect(DISTINCT {source: preFrom.id, target: c.id, type: 'PREREQUISITE', command: preFrom{.*}}) as prerequisitesFrom,
           collect(DISTINCT {source: nextFrom.id, target: c.id, type: 'NEXT_STEP', command: nextFrom{.*}}) as nextStepsFrom

      RETURN c as center,
             alternatives,
             prerequisites,
             nextSteps,
             alternativesFrom,
             prerequisitesFrom,
             nextStepsFrom
    `;

    const results = await runQuery(query, { commandId });
    if (results.length > 0) {
      const data = results[0];

      // Build nodes and edges for Cytoscape
      const nodes = new Map();
      const edges: any[] = [];

      // Add center node (being expanded, so hasRelationships = false to prevent re-expansion indicator)
      nodes.set(commandId, {
        data: {
          id: commandId,
          label: data.center.name,
          ...data.center,
          type: 'center',
          hasRelationships: false
        }
      });

      // Process relationships - same as get-graph but include hasRelationships placeholder
      const processEdges = (rels: any[], reverse = false) => {
        rels.forEach((rel: any) => {
          if (rel.command && rel.command.id && rel.source && rel.target) {
            nodes.set(rel.command.id, {
              data: {
                id: rel.command.id,
                label: rel.command.name,
                ...rel.command,
                hasRelationships: true // Default true, will be updated by batch query
              }
            });
            edges.push({
              data: {
                id: `${rel.source}-${rel.target}-${rel.type}`,
                source: reverse ? rel.target : rel.source,
                target: reverse ? rel.source : rel.target,
                label: rel.type.replace('_', ' '),
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
      processEdges(data.nextStepsFrom, true);

      // Batch query to check which nodes have their own relationships
      const nodeIds = Array.from(nodes.keys()).filter(id => id !== commandId);
      if (nodeIds.length > 0) {
        const batchQuery = `
          UNWIND $nodeIds as nodeId
          MATCH (c:Command {id: nodeId})
          OPTIONAL MATCH (c)-[:ALTERNATIVE|PREREQUISITE|NEXT_STEP]->(out:Command)
          OPTIONAL MATCH (in:Command)-[:ALTERNATIVE|PREREQUISITE|NEXT_STEP]->(c)
          WITH nodeId, count(DISTINCT out) + count(DISTINCT in) as relCount
          RETURN nodeId, relCount > 0 as hasRelationships
        `;

        const relResults = await runQuery(batchQuery, { nodeIds });
        relResults.forEach((r: any) => {
          const node = nodes.get(r.nodeId);
          if (node) {
            node.data.hasRelationships = r.hasRelationships;
          }
        });
      }

      const graphData = {
        elements: {
          nodes: Array.from(nodes.values()),
          edges: edges
        }
      };

      logIPC('IPC: get-graph-with-metadata completed', {
        nodeCount: graphData.elements.nodes.length,
        edgeCount: graphData.elements.edges.length,
      });

      return graphData;
    }

    logIPC('IPC: get-graph-with-metadata - no data found', { commandId });
    return { elements: { nodes: [], edges: [] } };
  } catch (error) {
    logError('IPC: get-graph-with-metadata failed', error);
    console.error('Get graph with metadata error:', error);
    return { elements: { nodes: [], edges: [] } };
  }
});
logIPC('Registered IPC handler: get-graph-with-metadata');

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

// IPC Handler: Get project root path (for source file references)
ipcMain.handle('get-project-root', () => {
  // In dev: __dirname = .../crack/crackpedia/dist-electron/main
  // Project root (crack) = 3 levels up from dist-electron/main
  const projectRoot = path.resolve(__dirname, '..', '..', '..');
  logIPC('IPC: get-project-root called', { projectRoot });
  return projectRoot;
});
logIPC('Registered IPC handler: get-project-root');

// IPC Handler: Search cheatsheets
ipcMain.handle('search-cheatsheets', async (_event, searchQuery: string, filters?: {
  tags?: string[];
}) => {
  logIPC('IPC: search-cheatsheets called', {
    query: searchQuery || '(empty)',
    filters,
  });

  try {
    let query = `
      MATCH (cs:Cheatsheet)
    `;

    const params: Record<string, any> = {};
    const conditions: string[] = [];

    if (searchQuery && searchQuery.trim()) {
      conditions.push(`(
        toLower(cs.name) CONTAINS toLower($searchQuery)
        OR toLower(cs.description) CONTAINS toLower($searchQuery)
      )`);
      params.searchQuery = searchQuery.trim();
    }

    if (filters?.tags && filters.tags.length > 0) {
      conditions.push(`
        ANY(tag IN cs.tags WHERE tag IN $tags)
      `);
      params.tags = filters.tags;
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += `
      RETURN cs.id as id, cs.name as name,
             cs.description as description, cs.tags as tags
      ORDER BY cs.name
      LIMIT 100
    `;

    const results = await runQuery(query, params);

    // Split pipe-separated tags string into array
    results.forEach(sheet => {
      if (sheet.tags && typeof sheet.tags === 'string') {
        sheet.tags = sheet.tags.split('|').filter(tag => tag.trim());
      } else {
        sheet.tags = [];
      }
    });

    logIPC('IPC: search-cheatsheets completed', { resultCount: results.length });
    return results;
  } catch (error) {
    logError('IPC: search-cheatsheets failed', error);
    console.error('Search cheatsheets error:', error);
    return [];
  }
});
logIPC('Registered IPC handler: search-cheatsheets');

// IPC Handler: Get cheatsheet details
ipcMain.handle('get-cheatsheet', async (_event, cheatsheetId: string) => {
  logIPC('IPC: get-cheatsheet called', { cheatsheetId });

  try {
    const query = `
      MATCH (cs:Cheatsheet {id: $cheatsheetId})
      RETURN cs.id as id, cs.name as name,
             cs.description as description, cs.tags as tags,
             cs.educational_header as educational_header,
             cs.scenarios as scenarios,
             cs.sections as sections
    `;

    const results = await runQuery(query, { cheatsheetId });

    if (results && results.length > 0) {
      const sheet = results[0];

      // Parse JSON strings back to objects
      try {
        sheet.educational_header = JSON.parse(sheet.educational_header || '{}');
      } catch (e) {
        logError('Failed to parse educational_header JSON', e);
        sheet.educational_header = { how_to_recognize: [], when_to_look_for: [] };
      }

      try {
        sheet.scenarios = JSON.parse(sheet.scenarios || '[]');
      } catch (e) {
        logError('Failed to parse scenarios JSON', e);
        sheet.scenarios = [];
      }

      try {
        sheet.sections = JSON.parse(sheet.sections || '[]');
      } catch (e) {
        logError('Failed to parse sections JSON', e);
        sheet.sections = [];
      }

      // Split pipe-separated tags string into array
      if (sheet.tags && typeof sheet.tags === 'string') {
        sheet.tags = sheet.tags.split('|').filter(tag => tag.trim());
      } else {
        sheet.tags = [];
      }

      logIPC('IPC: get-cheatsheet completed', { name: sheet.name });
      return sheet;
    }

    logIPC('IPC: get-cheatsheet - not found', { cheatsheetId });
    return null;
  } catch (error) {
    logError('IPC: get-cheatsheet failed', error);
    console.error('Get cheatsheet error:', error);
    return null;
  }
});
logIPC('Registered IPC handler: get-cheatsheet');

// IPC Handler: Search attack chains
ipcMain.handle('search-chains', async (_event, searchQuery: string, filters?: {
  category?: string;
}) => {
  logIPC('IPC: search-chains called', {
    query: searchQuery || '(empty)',
    filters,
  });

  try {
    let query = `
      MATCH (ac:AttackChain)
    `;

    const params: Record<string, any> = {};
    const conditions: string[] = [];

    if (searchQuery && searchQuery.trim()) {
      conditions.push(`(
        toLower(ac.name) CONTAINS toLower($searchQuery)
        OR toLower(ac.description) CONTAINS toLower($searchQuery)
      )`);
      params.searchQuery = searchQuery.trim();
    }

    // Filter by category if provided (though currently empty in DB)
    if (filters?.category && filters.category !== 'all') {
      conditions.push('ac.category = $category');
      params.category = filters.category;
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += `
      RETURN ac.id as id, ac.name as name,
             ac.description as description, ac.category as category,
             ac.platform as platform, ac.difficulty as difficulty,
             ac.time_estimate as time_estimate, ac.oscp_relevant as oscp_relevant
      ORDER BY ac.name
      LIMIT 100
    `;

    const results = await runQuery(query, params);
    logIPC('IPC: search-chains completed', { resultCount: results.length });
    return results;
  } catch (error) {
    logError('IPC: search-chains failed', error);
    console.error('Search chains error:', error);
    return [];
  }
});
logIPC('Registered IPC handler: search-chains');

// IPC Handler: Get attack chain details with steps
ipcMain.handle('get-chain', async (_event, chainId: string) => {
  logIPC('IPC: get-chain called', { chainId });

  try {
    const query = `
      MATCH (ac:AttackChain {id: $chainId})
      OPTIONAL MATCH (ac)-[:HAS_STEP]->(step:ChainStep)
      OPTIONAL MATCH (step)-[:EXECUTES]->(cmd:Command)
      WITH ac, step, cmd
      ORDER BY step.order
      RETURN ac,
             collect({
               step: step,
               command: cmd
             }) as steps
    `;

    const results = await runQuery(query, { chainId });

    if (results && results.length > 0) {
      const record = results[0];

      // Debug: Log raw Neo4j structure
      console.log('[DEBUG] Raw steps from Neo4j:', JSON.stringify(record.steps.slice(0, 1), null, 2));
      if (record.steps.length > 0 && record.steps[0].step) {
        console.log('[DEBUG] First step object keys:', Object.keys(record.steps[0].step));
        console.log('[DEBUG] Has .properties?', 'properties' in record.steps[0].step);
        if ('properties' in record.steps[0].step) {
          console.log('[DEBUG] Properties content:', record.steps[0].step.properties);
        }
      }

      // Extract steps - manually unwrap Neo4j node properties
      const steps = record.steps
        .filter((s: any) => s.step && s.step.properties)
        .map((s: any) => {
          const stepProps = s.step.properties || {};
          const cmdProps = s.command?.properties || null;

          // Helper function to parse array fields (may be JSON strings)
          const parseArrayField = (field: any): string[] | undefined => {
            if (!field) return undefined;
            if (Array.isArray(field)) return field;
            if (typeof field === 'string') {
              try {
                const parsed = JSON.parse(field);
                return Array.isArray(parsed) ? parsed : undefined;
              } catch {
                return undefined;
              }
            }
            return undefined;
          };

          return {
            id: stepProps.id || '',
            name: stepProps.name || '',
            objective: stepProps.objective || '',
            description: stepProps.description || '',
            command_ref: stepProps.command_ref,
            evidence: parseArrayField(stepProps.evidence),
            dependencies: parseArrayField(stepProps.dependencies),
            repeatable: stepProps.repeatable,
            success_criteria: parseArrayField(stepProps.success_criteria),
            failure_conditions: parseArrayField(stepProps.failure_conditions),
            next_steps: parseArrayField(stepProps.next_steps),
            order: stepProps.order,
            command: cmdProps ? {
              id: cmdProps.id || '',
              name: cmdProps.name || '',
              command: cmdProps.command || '',
              description: cmdProps.description || ''
            } : null
          };
        });

      const chain = {
        ...record.ac,
        steps
      };

      logIPC('IPC: get-chain completed', {
        id: chain.id,
        name: chain.name,
        stepCount: chain.steps.length
      });
      return chain;
    }

    logIPC('IPC: get-chain - not found', { chainId });
    return null;
  } catch (error) {
    logError('IPC: get-chain failed', error);
    console.error('Get chain error:', error);
    return null;
  }
});
logIPC('Registered IPC handler: get-chain');

// IPC Handler: Get chain graph (steps as nodes with dependencies)
ipcMain.handle('get-chain-graph', async (_event, chainId: string) => {
  logIPC('IPC: get-chain-graph called', { chainId });

  try {
    const query = `
      MATCH (ac:AttackChain {id: $chainId})-[:HAS_STEP]->(step:ChainStep)
      OPTIONAL MATCH (step)-[:EXECUTES]->(cmd:Command)
      WITH ac, step, cmd
      ORDER BY step.order
      RETURN ac.name as chainName,
             collect({
               id: step.id,
               name: step.name,
               objective: step.objective,
               description: step.description,
               order: step.order,
               command: cmd
             }) as steps
    `;

    const results = await runQuery(query, { chainId });

    if (results && results.length > 0 && results[0].steps) {
      const steps = results[0].steps.filter((s: any) => s.id);
      const nodes = steps.map((step: any, index: number) => ({
        data: {
          id: step.id,
          label: `Step ${index + 1}`,
          name: step.name || 'Unnamed Step',
          objective: step.objective,
          description: step.description || '',
          type: 'step',
          order: step.order || index,
          command: step.command
        }
      }));

      // Create edges based on sequential order (step dependencies)
      const edges: any[] = [];
      for (let i = 0; i < steps.length - 1; i++) {
        edges.push({
          data: {
            id: `${steps[i].id}-${steps[i + 1].id}`,
            source: steps[i].id,
            target: steps[i + 1].id,
            label: 'NEXT',
            type: 'next'
          }
        });
      }

      const graphData = {
        elements: {
          nodes,
          edges
        }
      };

      logIPC('IPC: get-chain-graph completed', {
        nodeCount: nodes.length,
        edgeCount: edges.length
      });

      return graphData;
    }

    logIPC('IPC: get-chain-graph - no steps found', { chainId });
    return { elements: { nodes: [], edges: [] } };
  } catch (error) {
    logError('IPC: get-chain-graph failed', error);
    console.error('Get chain graph error:', error);
    return { elements: { nodes: [], edges: [] } };
  }
});
logIPC('Registered IPC handler: get-chain-graph');

// IPC Handler: Get attack chains containing a specific command
ipcMain.handle('get-command-chains', async (_event, commandId: string) => {
  logIPC('IPC: get-command-chains called', { commandId });

  try {
    const query = `
      MATCH (cmd:Command {id: $commandId})
      MATCH (step:ChainStep)-[:EXECUTES]->(cmd)
      MATCH (chain:AttackChain)-[:HAS_STEP]->(step)

      // Get all steps from the chains containing this command
      MATCH (chain)-[:HAS_STEP]->(allSteps:ChainStep)
      OPTIONAL MATCH (allSteps)-[:EXECUTES]->(stepCmd:Command)

      WITH chain, allSteps, stepCmd, cmd
      ORDER BY chain.id, allSteps.order

      WITH chain,
           collect({
             step: allSteps,
             command: stepCmd,
             isTargetCommand: stepCmd.id = cmd.id
           }) as steps

      RETURN chain, steps
    `;

    const results = await runQuery(query, { commandId });

    if (results && results.length > 0) {
      // Build graph from all chains containing this command
      const nodes = new Map();
      const edges: any[] = [];
      let targetNodeId = commandId;

      results.forEach((record: any) => {
        const chain = record.chain;
        const steps = record.steps || [];

        // Process each step as a node
        steps.forEach((stepData: any, index: number) => {
          if (!stepData.step) return;

          const step = stepData.step;
          const cmd = stepData.command;
          const isTarget = stepData.isTargetCommand;

          // Create unique ID for step node
          const nodeId = `${chain.id}_step_${index}`;

          // Add node
          nodes.set(nodeId, {
            data: {
              id: nodeId,
              label: `${chain.name}\nStep ${index + 1}`,
              description: step.description?.substring(0, 100) || '',
              type: isTarget ? 'center' : 'step',
              chainId: chain.id,
              chainName: chain.name,
              stepOrder: index,
              command: cmd,
            }
          });

          // Track the target command node for highlighting
          if (isTarget) {
            targetNodeId = nodeId;
          }

          // Add edge from previous step (if not first)
          if (index > 0) {
            const prevNodeId = `${chain.id}_step_${index - 1}`;
            edges.push({
              data: {
                id: `${prevNodeId}_${nodeId}`,
                source: prevNodeId,
                target: nodeId,
                label: 'NEXT',
                type: 'next_step'
              }
            });
          }
        });
      });

      const graphData = {
        elements: {
          nodes: Array.from(nodes.values()),
          edges: edges
        }
      };

      logIPC('IPC: get-command-chains completed', {
        chainCount: results.length,
        nodeCount: graphData.elements.nodes.length,
        edgeCount: graphData.elements.edges.length,
      });

      return graphData;
    }

    logIPC('IPC: get-command-chains - command not in any chains', { commandId });
    return { elements: { nodes: [], edges: [] } };
  } catch (error) {
    logError('IPC: get-command-chains failed', error);
    console.error('Get command chains error:', error);
    return { elements: { nodes: [], edges: [] } };
  }
});
logIPC('Registered IPC handler: get-command-chains');

// IPC Handler: Search writeups
ipcMain.handle('search-writeups', async (_event, searchQuery: string, filters?: {
  platform?: string;
  difficulty?: string;
  oscp_relevance?: string;
  os?: string;
  exam_applicable?: boolean;
}) => {
  logIPC('IPC: search-writeups called', {
    query: searchQuery || '(empty)',
    filters,
  });

  try {
    let query = `
      MATCH (w:Writeup)
    `;

    const params: Record<string, any> = {};
    const conditions: string[] = [];

    if (searchQuery && searchQuery.trim()) {
      conditions.push(`(
        toLower(w.name) CONTAINS toLower($searchQuery)
        OR toLower(w.synopsis) CONTAINS toLower($searchQuery)
        OR toLower(w.oscp_reasoning) CONTAINS toLower($searchQuery)
      )`);
      params.searchQuery = searchQuery.trim();
    }

    if (filters?.platform) {
      conditions.push('w.platform = $platform');
      params.platform = filters.platform;
    }

    if (filters?.difficulty) {
      conditions.push('w.difficulty = $difficulty');
      params.difficulty = filters.difficulty;
    }

    if (filters?.oscp_relevance) {
      conditions.push('w.oscp_relevance = $oscp_relevance');
      params.oscp_relevance = filters.oscp_relevance;
    }

    if (filters?.os) {
      conditions.push('w.os = $os');
      params.os = filters.os;
    }

    if (filters?.exam_applicable !== undefined) {
      conditions.push('w.exam_applicable = $exam_applicable');
      params.exam_applicable = filters.exam_applicable;
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += `
      RETURN w.id as id, w.name as name, w.platform as platform,
             w.difficulty as difficulty, w.oscp_relevance as oscp_relevance,
             w.machine_type as machine_type, w.os as os,
             w.total_duration_minutes as total_duration_minutes
      ORDER BY w.name
      LIMIT 100
    `;

    const results = await runQuery(query, params);
    logIPC('IPC: search-writeups completed', { resultCount: results.length });
    return results;
  } catch (error) {
    logError('IPC: search-writeups failed', error);
    console.error('Search writeups error:', error);
    return [];
  }
});
logIPC('Registered IPC handler: search-writeups');

// IPC Handler: Get writeup details
ipcMain.handle('get-writeup', async (_event, writeupId: string) => {
  logIPC('IPC: get-writeup called', { writeupId });

  try {
    const query = `
      MATCH (w:Writeup {id: $writeupId})

      // Fetch required skills
      OPTIONAL MATCH (w)-[rs:REQUIRES_SKILL]->(requiredSkill:Skill)
      WITH w, collect(DISTINCT requiredSkill.name) as requiredSkills

      // Fetch learned skills
      OPTIONAL MATCH (w)-[ts:TEACHES_SKILL]->(learnedSkill:Skill)
      WITH w, requiredSkills, collect(DISTINCT learnedSkill.name) as learnedSkills

      RETURN w, requiredSkills, learnedSkills
    `;

    const results = await runQuery(query, { writeupId });
    if (results.length > 0) {
      const writeup = results[0].w;
      const requiredSkills = results[0].requiredSkills || [];
      const learnedSkills = results[0].learnedSkills || [];

      logIPC('[DEBUG] Skills from relationships:', {
        required: requiredSkills.length,
        learned: learnedSkills.length
      });

      // Helper function to safely parse JSON fields
      const parseJsonField = (field: any): any => {
        if (!field) return null;
        if (typeof field === 'string') {
          try {
            return JSON.parse(field);
          } catch (error) {
            logError(`Failed to parse JSON field: ${field.substring(0, 100)}...`, error);
            return field;
          }
        }
        return field;
      };

      // Build the complete writeup object with parsed nested structures
      const fullWriteup = {
        id: writeup.id,
        name: writeup.name,

        // Parse nested objects
        source: parseJsonField(writeup.source) || {
          platform: writeup.platform,
          type: writeup.machine_type,
          release_date: writeup.release_date,
          retire_date: writeup.retirement_date,
        },

        metadata: parseJsonField(writeup.metadata) || {
          difficulty: writeup.difficulty,
          os: writeup.os,
          ip_address: writeup.ip_address,
          machine_author: writeup.author,
          rating: writeup.rating,
          user_owns: writeup.user_owns,
          system_owns: writeup.root_owns,
        },

        oscp_relevance: parseJsonField(writeup.oscp_relevance_full) || {
          score: writeup.oscp_relevance,
          reasoning: writeup.oscp_reasoning,
          exam_applicable: writeup.exam_applicable,
        },

        synopsis: writeup.synopsis,
        skills: {
          required: requiredSkills,
          learned: learnedSkills
        },
        tags: typeof writeup.tags === 'string'
          ? writeup.tags.split('|').filter(tag => tag.trim())
          : (writeup.tags || []),

        // Parse large nested arrays with explicit string handling
        attack_phases: (() => {
          const rawValue = writeup.attack_phases;
          logIPC('[DEBUG] attack_phases raw type:', typeof rawValue);

          // If null/undefined, return empty array
          if (!rawValue) {
            logIPC('[DEBUG] attack_phases is null/undefined, returning []');
            return [];
          }

          // If already an array, return it directly
          if (Array.isArray(rawValue)) {
            logIPC('[DEBUG] attack_phases is already array, length:', rawValue.length);
            return rawValue;
          }

          // If it's a string, sanitize and parse properly
          if (typeof rawValue === 'string') {
            logIPC('[DEBUG] attack_phases is string, sanitizing and parsing...');

            try {
              // CRITICAL FIX: Replace only LITERAL control characters, not escape sequences
              // Use regex to replace literal control chars with their JSON escape sequences
              const sanitized = rawValue
                .replace(/\\/g, '\\\\')   // Escape backslashes first (so \n stays as \\n)
                .replace(/\n/g, '\\n')     // Escape literal newlines
                .replace(/\r/g, '\\r')     // Escape literal carriage returns
                .replace(/\t/g, '\\t')     // Escape literal tabs
                .replace(/"/g, '\\"');     // Escape unescaped quotes

              // Wait, this will double-escape already-escaped sequences. Need different approach:
              // Just escape the actual control characters (ASCII < 32)
              const properlyEscaped = rawValue.replace(/[\x00-\x1F]/g, (char) => {
                switch (char) {
                  case '\n': return '\\n';
                  case '\r': return '\\r';
                  case '\t': return '\\t';
                  case '\b': return '\\b';
                  case '\f': return '\\f';
                  default: return '\\u' + ('0000' + char.charCodeAt(0).toString(16)).slice(-4);
                }
              });

              logIPC('[DEBUG] String sanitized, attempting parse...');
              const parsed = JSON.parse(properlyEscaped);

              if (Array.isArray(parsed)) {
                logIPC('[DEBUG] Successfully parsed to array, length:', parsed.length);
                return parsed;
              } else {
                logError('[DEBUG] Parsed but not array, type:', typeof parsed);
                return [];
              }
            } catch (error) {
              logError('[DEBUG] Failed to parse attack_phases after sanitization:', error);
              logError('[DEBUG] Raw value preview (first 300 chars):', rawValue.substring(0, 300));
              return [];
            }
          }

          // If not string, try parseJsonField anyway (handles objects, arrays)
          const parsed = parseJsonField(rawValue);
          if (Array.isArray(parsed)) {
            logIPC('[DEBUG] parseJsonField returned array from non-string, length:', parsed.length);
            return parsed;
          }

          // Unknown type, return empty array
          logError('[DEBUG] attack_phases is unexpected type, returning []:', typeof rawValue);
          return [];
        })(),
        key_learnings: (() => {
          const parsed = parseJsonField(writeup.key_learnings);
          if (Array.isArray(parsed)) return parsed;
          if (typeof parsed === 'string') {
            try {
              const reparsed = JSON.parse(parsed);
              return Array.isArray(reparsed) ? reparsed : [];
            } catch {
              return [];
            }
          }
          return [];
        })(),
        alternative_approaches: parseJsonField(writeup.alternative_approaches) || {},
        time_breakdown: parseJsonField(writeup.time_breakdown) || {
          total_minutes: writeup.total_duration_minutes,
          total_hours: writeup.total_duration_minutes ? writeup.total_duration_minutes / 60 : 0,
        },
        references: (() => {
          const parsed = parseJsonField(writeup.references);
          if (Array.isArray(parsed)) return parsed;
          if (typeof parsed === 'string') {
            try {
              const reparsed = JSON.parse(parsed);
              return Array.isArray(reparsed) ? reparsed : [];
            } catch {
              return [];
            }
          }
          return [];
        })(),
        files: parseJsonField(writeup.files) || {},
      };

      logIPC('IPC: get-writeup completed', {
        writeupId,
        hasAttackPhases: Array.isArray(fullWriteup.attack_phases) && fullWriteup.attack_phases.length > 0,
        hasKeyLearnings: Array.isArray(fullWriteup.key_learnings) && fullWriteup.key_learnings.length > 0,
        attackPhasesType: typeof fullWriteup.attack_phases,
      });
      return fullWriteup;
    }

    logIPC('IPC: get-writeup - no writeup found', { writeupId });
    return null;
  } catch (error) {
    logError('IPC: get-writeup failed', error);
    console.error('Get writeup error:', error);
    return null;
  }
});
logIPC('Registered IPC handler: get-writeup');

// IPC Handler: Get all images from writeup images directory
ipcMain.handle('get-writeup-images', async (_event, imagesPath: string) => {
  logIPC('IPC: get-writeup-images called', { imagesPath });

  try {
    // Check if path exists
    if (!fs.existsSync(imagesPath)) {
      logError('Images directory does not exist', { imagesPath });
      return [];
    }

    // Read directory contents
    const files = fs.readdirSync(imagesPath);

    // Filter for image files only
    const imageExtensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'];
    const imageFiles = files
      .filter(file => {
        const ext = path.extname(file).toLowerCase();
        return imageExtensions.includes(ext);
      })
      .sort() // Sort alphabetically (page01_img01, page01_img02, etc.)
      .map(filename => ({
        file: `images/${filename}`,
        filename: filename,
        // Extract page number from filename (e.g., page05_img01.png -> 5)
        extracted_from_page: parseInt(filename.match(/page(\d+)/)?.[1] || '0', 10) || undefined
      }));

    logIPC('Images loaded from directory', { count: imageFiles.length });
    return imageFiles;

  } catch (error) {
    logError('Failed to read images directory', { imagesPath, error });
    return [];
  }
});
logIPC('Registered IPC handler: get-writeup-images');

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
