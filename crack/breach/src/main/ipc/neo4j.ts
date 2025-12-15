/**
 * Neo4j IPC Handlers
 *
 * Health check and direct query handlers for Neo4j database.
 */

import { ipcMain } from 'electron';
import { neo4jDriver, runQuery } from '@shared/neo4j/query';
import { debug } from '../debug';

/** Register Neo4j-related IPC handlers */
export function registerNeo4jHandlers(): void {
  debug.ipc('Registering Neo4j IPC handlers');

  // Health check
  ipcMain.handle('neo4j-health-check', async () => {
    debug.ipc('neo4j-health-check called');
    const result = await neo4jDriver.verifyConnectivity();
    debug.neo4j('Health check result', result);
    return result;
  });

  // Get active engagement
  ipcMain.handle('get-active-engagement', async () => {
    debug.ipc('get-active-engagement called');
    try {
      const results = await runQuery<{ e: Record<string, unknown> }>(
        `MATCH (e:Engagement {status: 'active'})
         RETURN e
         ORDER BY e.created_at DESC
         LIMIT 1`
      );
      return results.length > 0 ? results[0].e : null;
    } catch (error) {
      debug.error('get-active-engagement failed', error);
      return null;
    }
  });

  // Get engagement by ID
  ipcMain.handle('get-engagement', async (_, engagementId: string) => {
    debug.ipc('get-engagement called', { engagementId });
    try {
      const results = await runQuery<{ e: Record<string, unknown> }>(
        `MATCH (e:Engagement {id: $engagementId})
         RETURN e`,
        { engagementId }
      );
      return results.length > 0 ? results[0].e : null;
    } catch (error) {
      debug.error('get-engagement failed', error);
      return null;
    }
  });

  debug.ipc('Neo4j IPC handlers registered');
}
