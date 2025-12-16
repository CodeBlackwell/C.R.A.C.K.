/**
 * Modules IPC Handlers
 *
 * IPC handlers for fetching command module data from Neo4j.
 * Supports lazy loading of modules with command grouping by subcategory.
 */

import { ipcMain } from 'electron';
import { runQuery } from '@shared/neo4j/query';
import { debug } from '../debug';
import { CATEGORY_TAG_MAP } from '@shared/actions/service-mapping';
import type {
  ModuleMetadata,
  CommandModule,
  CommandTool,
  CommandVariant,
} from '@shared/types/module-preferences';

/** Command record from Neo4j query */
interface CommandRecord {
  id: string;
  name: string;
  command: string;
  description?: string;
  subcategory?: string;
  oscpRelevance?: string;
  flagExplanations?: string;
}

/** Format module ID to display name */
function formatModuleName(id: string): string {
  return id
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

/** Group commands by subcategory/tool */
function groupByTool(
  commands: CommandRecord[],
  moduleId: string
): CommandModule {
  const toolMap = new Map<string, CommandVariant[]>();

  for (const cmd of commands) {
    const toolKey = cmd.subcategory || 'general';
    if (!toolMap.has(toolKey)) {
      toolMap.set(toolKey, []);
    }

    // Parse flag explanations if stored as JSON string
    let flagExplanations: Record<string, string> | undefined;
    if (cmd.flagExplanations) {
      try {
        flagExplanations =
          typeof cmd.flagExplanations === 'string'
            ? JSON.parse(cmd.flagExplanations)
            : cmd.flagExplanations;
      } catch {
        // Ignore parse errors
      }
    }

    toolMap.get(toolKey)!.push({
      id: cmd.id,
      label: cmd.name,
      command: cmd.command,
      description: cmd.description,
      oscpRelevance: cmd.oscpRelevance as 'high' | 'medium' | 'low' | undefined,
      flagExplanations,
    });
  }

  const tools: CommandTool[] = Array.from(toolMap.entries()).map(
    ([id, variants]) => ({
      id,
      name: formatModuleName(id),
      variants,
    })
  );

  return {
    id: moduleId,
    name: formatModuleName(moduleId),
    commandCount: commands.length,
    tools,
  };
}

/** Register module-related IPC handlers */
export function registerModulesHandlers(): void {
  debug.ipc('Registering modules IPC handlers');

  // List available modules with command counts
  ipcMain.handle('modules-list', async () => {
    console.log('[modules-list] Fetching modules from Neo4j...');
    debug.ipc('modules-list called');

    try {
      const results = await runQuery(`
        MATCH (c:Command)
        WHERE c.category IS NOT NULL
        WITH c.category AS categoryId, count(c) AS commandCount
        RETURN categoryId, commandCount
        ORDER BY commandCount DESC
      `);

      console.log('[modules-list] Raw results:', results.length, 'categories');

      const modules: ModuleMetadata[] = (
        results as Array<{ categoryId: string; commandCount: number }>
      ).map((r) => ({
        id: r.categoryId,
        name: formatModuleName(r.categoryId),
        commandCount:
          typeof r.commandCount === 'number'
            ? r.commandCount
            : Number(r.commandCount),
      }));

      console.log('[modules-list] Returning modules:', modules.map((m) => m.id).join(', '));
      debug.ipc('modules-list found modules', { count: modules.length });
      return modules;
    } catch (error) {
      console.error('[modules-list] Failed:', error);
      debug.error('modules-list failed', error);
      return [];
    }
  });

  // Load a single module's commands (lazy load)
  ipcMain.handle('modules-load', async (_, moduleId: string) => {
    console.log('[modules-load] Loading module:', moduleId);
    debug.ipc('modules-load called', { moduleId });

    // Get tags for this module from CATEGORY_TAG_MAP
    const tags = CATEGORY_TAG_MAP[moduleId] || [];
    if (tags.length === 0) {
      console.warn('[modules-load] No tags found for module:', moduleId);
      // Return empty module structure
      return {
        id: moduleId,
        name: formatModuleName(moduleId),
        commandCount: 0,
        tools: [],
      };
    }

    console.log('[modules-load] Using tags:', tags.join(', '));

    try {
      // Query commands by tags (via TAGGED relationship)
      const results = await runQuery(
        `
        MATCH (c:Command)-[:TAGGED]->(t:Tag)
        WHERE t.name IN $tags
        RETURN DISTINCT c.id as id, c.name as name, c.command as command,
               c.description as description, c.subcategory as subcategory,
               c.oscp_relevance as oscpRelevance, c.flag_explanations as flagExplanations
        ORDER BY
          CASE c.oscp_relevance
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            ELSE 3
          END,
          c.name
        `,
        { tags }
      );

      console.log('[modules-load] Found', results.length, 'commands for', moduleId);

      const commands = results as unknown as CommandRecord[];
      const module = groupByTool(commands, moduleId);

      console.log('[modules-load] Module', moduleId, 'has', module.tools.length, 'tools');
      debug.ipc('modules-load loaded module', {
        moduleId,
        commandCount: module.commandCount,
        toolCount: module.tools.length,
      });

      return module;
    } catch (error) {
      console.error('[modules-load] Failed for', moduleId, ':', error);
      debug.error('modules-load failed', error);
      return null;
    }
  });

  // Batch load multiple modules (using tags, parallel queries)
  ipcMain.handle('modules-load-batch', async (_, moduleIds: string[]) => {
    debug.ipc('modules-load-batch called', { moduleIds });

    try {
      const modules: Record<string, CommandModule> = {};

      // Load each module using tags (parallel queries for efficiency)
      await Promise.all(
        moduleIds.map(async (moduleId) => {
          const tags = CATEGORY_TAG_MAP[moduleId] || [];
          if (tags.length === 0) {
            modules[moduleId] = {
              id: moduleId,
              name: formatModuleName(moduleId),
              commandCount: 0,
              tools: [],
            };
            return;
          }

          const results = await runQuery(
            `
            MATCH (c:Command)-[:TAGGED]->(t:Tag)
            WHERE t.name IN $tags
            RETURN DISTINCT c.id as id, c.name as name, c.command as command,
                   c.description as description, c.subcategory as subcategory,
                   c.oscp_relevance as oscpRelevance, c.flag_explanations as flagExplanations
            ORDER BY
              CASE c.oscp_relevance
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                ELSE 3
              END,
              c.name
            `,
            { tags }
          );

          const commands = results as unknown as CommandRecord[];
          modules[moduleId] = groupByTool(commands, moduleId);
        })
      );

      debug.ipc('modules-load-batch loaded modules', {
        requested: moduleIds.length,
        loaded: Object.keys(modules).length,
      });

      return modules;
    } catch (error) {
      debug.error('modules-load-batch failed', error);
      return {};
    }
  });

  // Global search across all commands in Neo4j
  ipcMain.handle(
    'commands-search-global',
    async (
      _,
      options: {
        query: string;
        filters: {
          name: boolean;
          command: boolean;
          description: boolean;
          tags: boolean;
          oscpHigh: boolean;
        };
        filterLogic: 'AND' | 'OR';
        limit?: number;
      }
    ) => {
      const { query, filters, filterLogic, limit = 50 } = options;
      console.log('[commands-search-global] Searching:', { query, filters, filterLogic });

      try {
        const conditions: string[] = [];

        // Text-based search conditions
        if (query && query.length >= 2) {
          const textConditions: string[] = [];
          if (filters.name) {
            textConditions.push('toLower(c.name) CONTAINS toLower($query)');
          }
          if (filters.command) {
            textConditions.push('toLower(c.command) CONTAINS toLower($query)');
          }
          if (filters.description) {
            textConditions.push(
              'c.description IS NOT NULL AND toLower(c.description) CONTAINS toLower($query)'
            );
          }

          if (textConditions.length > 0) {
            const joiner = filterLogic === 'AND' ? ' AND ' : ' OR ';
            conditions.push(`(${textConditions.join(joiner)})`);
          }
        }

        // OSCP:HIGH filter
        if (filters.oscpHigh) {
          conditions.push("c.oscp_relevance = 'high'");
        }

        // Tag search (requires subquery)
        if (filters.tags && query && query.length >= 2) {
          conditions.push(`
            EXISTS {
              MATCH (c)-[:TAGGED]->(t:Tag)
              WHERE toLower(t.name) CONTAINS toLower($query)
            }
          `);
        }

        // Build WHERE clause
        const whereClause =
          conditions.length > 0
            ? `WHERE ${conditions.join(filterLogic === 'AND' ? ' AND ' : ' OR ')}`
            : '';

        const results = await runQuery(
          `
          MATCH (c:Command)
          ${whereClause}
          RETURN c.id as id, c.name as name, c.command as command,
                 c.description as description, c.category as category,
                 c.subcategory as subcategory, c.oscp_relevance as oscpRelevance
          ORDER BY
            CASE c.oscp_relevance WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
            c.name
          LIMIT $limit
          `,
          { query: query || '', limit }
        );

        console.log('[commands-search-global] Found', results.length, 'results');
        return results;
      } catch (error) {
        console.error('[commands-search-global] Failed:', error);
        debug.error('commands-search-global failed', error);
        return [];
      }
    }
  );

  debug.ipc('Modules IPC handlers registered');
}
