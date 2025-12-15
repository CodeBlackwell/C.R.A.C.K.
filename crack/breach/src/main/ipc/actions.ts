/**
 * Actions IPC Handlers
 *
 * IPC handlers for fetching action data from Neo4j command database.
 * Used by ActionsPanel to enrich curated categories with command details.
 */

import { ipcMain } from 'electron';
import { runQuery } from '@shared/neo4j/query';
import { debug } from '../debug';
import { CATEGORY_TAG_MAP } from '@shared/actions/service-mapping';

/** Command result from Neo4j query */
interface CommandRecord {
  id: string;
  name: string;
  command: string;
  description?: string;
  oscpRelevance?: string;
  category?: string;
  subcategory?: string;
}

/** Detailed command result with flags/variables */
interface CommandDetailResult {
  command: Record<string, unknown>;
  flags: Array<{ flag?: string; [key: string]: unknown }>;
  variables: Array<{ name?: string; [key: string]: unknown }>;
}

/** Register action-related IPC handlers */
export function registerActionsHandlers(): void {
  debug.ipc('Registering actions IPC handlers');

  // Get enriched category data from Neo4j
  ipcMain.handle('actions-get-category', async (_, categoryId: string) => {
    debug.ipc('actions-get-category called', { categoryId });

    const tags = CATEGORY_TAG_MAP[categoryId] || [];
    if (tags.length === 0) {
      debug.ipc('actions-get-category no tags for category', { categoryId });
      return null;
    }

    try {
      // Query commands by tag
      const results = await runQuery(
        `MATCH (c:Command)-[:TAGGED]->(t:Tag)
         WHERE t.name IN $tags
         RETURN DISTINCT c.id as id, c.name as name, c.command as command,
                c.description as description, c.oscp_relevance as oscpRelevance,
                c.category as category, c.subcategory as subcategory
         ORDER BY
           CASE c.oscp_relevance
             WHEN 'high' THEN 1
             WHEN 'medium' THEN 2
             ELSE 3
           END,
           c.name`,
        { tags }
      );

      debug.ipc('actions-get-category found commands', {
        categoryId,
        count: results.length,
      });

      // Group by subcategory (tool)
      const toolMap = new Map<string, any[]>();
      for (const record of results) {
        const cmd = record as unknown as CommandRecord;
        const toolKey = cmd.subcategory || cmd.category || 'general';
        if (!toolMap.has(toolKey)) {
          toolMap.set(toolKey, []);
        }
        toolMap.get(toolKey)!.push({
          id: cmd.id,
          label: cmd.name,
          command: cmd.command,
          description: cmd.description,
          oscpRelevance: cmd.oscpRelevance,
        });
      }

      // Return enriched structure
      return {
        id: categoryId,
        tools: Array.from(toolMap.entries()).map(([toolId, variants]) => ({
          id: toolId,
          name: toolId.replace(/-/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
          variants,
        })),
      };
    } catch (error) {
      debug.error('actions-get-category failed', error);
      return null;
    }
  });

  // Search commands by query string
  ipcMain.handle('actions-search', async (_, query: string) => {
    debug.ipc('actions-search called', { query });

    if (!query || query.length < 2) {
      return [];
    }

    try {
      const results = await runQuery(
        `MATCH (c:Command)
         WHERE toLower(c.name) CONTAINS toLower($query)
            OR toLower(c.description) CONTAINS toLower($query)
            OR toLower(c.command) CONTAINS toLower($query)
         RETURN c.id as id, c.name as name, c.command as command,
                c.description as description, c.category as category,
                c.oscp_relevance as oscpRelevance
         ORDER BY
           CASE
             WHEN toLower(c.name) STARTS WITH toLower($query) THEN 1
             WHEN toLower(c.name) CONTAINS toLower($query) THEN 2
             ELSE 3
           END,
           c.name
         LIMIT 20`,
        { query }
      );

      debug.ipc('actions-search found results', { query, count: results.length });
      return results;
    } catch (error) {
      debug.error('actions-search failed', error);
      return [];
    }
  });

  // Get command details (with flags, variables)
  ipcMain.handle('actions-get-command', async (_, commandId: string) => {
    debug.ipc('actions-get-command called', { commandId });

    try {
      const results = await runQuery(
        `MATCH (c:Command {id: $commandId})
         OPTIONAL MATCH (c)-[:HAS_FLAG]->(f:Flag)
         OPTIONAL MATCH (c)-[:USES_VARIABLE]->(v:Variable)
         WITH c, collect(DISTINCT f{.*}) as flags, collect(DISTINCT v{.*}) as variables
         RETURN c{.*} as command, flags, variables`,
        { commandId }
      );

      if (results.length === 0) {
        return null;
      }

      const result = results[0] as unknown as CommandDetailResult;
      return {
        ...(result.command || {}),
        flags: (result.flags || []).filter((f) => f.flag),
        variables: (result.variables || []).filter((v) => v.name),
      };
    } catch (error) {
      debug.error('actions-get-command failed', error);
      return null;
    }
  });

  debug.ipc('Actions IPC handlers registered');
}
