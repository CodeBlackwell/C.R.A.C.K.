/**
 * Engagement IPC Handlers
 *
 * CRUD operations for engagements (simplified model without clients).
 */

import { ipcMain } from 'electron';
import { runQuery, runWrite } from '@shared/neo4j/query';
import { debug } from '../debug';
import type {
  Engagement,
  CreateEngagementData,
  EngagementStats,
  EngagementStatus,
} from '@shared/types/engagement';

/** Generate a unique ID with prefix */
function generateId(prefix: string): string {
  const uuid = Math.random().toString(36).substring(2, 10);
  return `${prefix}-${uuid}`;
}

/** Register engagement IPC handlers */
export function registerEngagementHandlers(): void {
  debug.ipc('Registering Engagement IPC handlers');

  /** List all engagements */
  ipcMain.handle('engagement-list', async () => {
    debug.ipc('engagement-list called');
    try {
      const results = await runQuery<{ e: Engagement }>(
        `MATCH (e:Engagement)
         RETURN e
         ORDER BY e.status DESC, e.created_at DESC`
      );
      return results.map((r) => r.e);
    } catch (error) {
      debug.error('engagement-list failed', error);
      return [];
    }
  });

  /** Get engagement by ID */
  ipcMain.handle('engagement-get', async (_, engagementId: string) => {
    debug.ipc('engagement-get called', { engagementId });
    try {
      const results = await runQuery<{ e: Engagement }>(
        `MATCH (e:Engagement {id: $engagementId})
         RETURN e`,
        { engagementId }
      );
      return results.length > 0 ? results[0].e : null;
    } catch (error) {
      debug.error('engagement-get failed', error);
      return null;
    }
  });

  /** Create a new engagement */
  ipcMain.handle('engagement-create', async (_, data: CreateEngagementData) => {
    debug.ipc('engagement-create called', { name: data.name });
    try {
      const id = generateId('eng');
      const now = new Date().toISOString();

      const results = await runQuery<{ e: Engagement }>(
        `CREATE (e:Engagement {
           id: $id,
           name: $name,
           status: 'paused',
           start_date: $start_date,
           scope_type: $scope_type,
           scope_text: $scope_text,
           notes: $notes,
           created_at: $created_at
         })
         RETURN e`,
        {
          id,
          name: data.name,
          start_date: now.split('T')[0],
          scope_type: data.scope_type || null,
          scope_text: data.scope_text || null,
          notes: data.notes || null,
          created_at: now,
        }
      );
      return results.length > 0 ? results[0].e : null;
    } catch (error) {
      debug.error('engagement-create failed', error);
      return null;
    }
  });

  /** Activate an engagement (sets status to 'active', deactivates others) */
  ipcMain.handle('engagement-activate', async (_, engagementId: string) => {
    debug.ipc('engagement-activate called', { engagementId });
    try {
      // Deactivate all currently active engagements
      await runWrite(
        `MATCH (e:Engagement {status: 'active'})
         SET e.status = 'paused'`
      );

      // Activate the selected engagement
      await runWrite(
        `MATCH (e:Engagement {id: $engagementId})
         SET e.status = 'active'`,
        { engagementId }
      );

      // Return the activated engagement
      const results = await runQuery<{ e: Engagement }>(
        `MATCH (e:Engagement {id: $engagementId})
         RETURN e`,
        { engagementId }
      );
      return results.length > 0 ? results[0].e : null;
    } catch (error) {
      debug.error('engagement-activate failed', error);
      return null;
    }
  });

  /** Deactivate all engagements */
  ipcMain.handle('engagement-deactivate', async () => {
    debug.ipc('engagement-deactivate called');
    try {
      await runWrite(
        `MATCH (e:Engagement {status: 'active'})
         SET e.status = 'paused'`
      );
      return true;
    } catch (error) {
      debug.error('engagement-deactivate failed', error);
      return false;
    }
  });

  /** Update engagement status */
  ipcMain.handle(
    'engagement-update-status',
    async (_, engagementId: string, status: EngagementStatus) => {
      debug.ipc('engagement-update-status called', { engagementId, status });
      try {
        const updates: Record<string, unknown> = { status };

        // Add end_date if completing/archiving
        if (status === 'completed' || status === 'archived') {
          updates.end_date = new Date().toISOString().split('T')[0];
        }

        await runWrite(
          `MATCH (e:Engagement {id: $engagementId})
           SET e.status = $status, e.end_date = $end_date`,
          { engagementId, status, end_date: updates.end_date || null }
        );
        return true;
      } catch (error) {
        debug.error('engagement-update-status failed', error);
        return false;
      }
    }
  );

  /** Update engagement details */
  ipcMain.handle(
    'engagement-update',
    async (_, engagementId: string, updates: Partial<Engagement>) => {
      debug.ipc('engagement-update called', { engagementId });
      try {
        // Build dynamic SET clause, excluding protected fields
        const setClause = Object.keys(updates)
          .filter((k) => !['id', 'created_at'].includes(k))
          .map((k) => `e.${k} = $${k}`)
          .join(', ');

        if (!setClause) return false;

        await runWrite(
          `MATCH (e:Engagement {id: $engagementId})
           SET ${setClause}`,
          { engagementId, ...updates }
        );
        return true;
      } catch (error) {
        debug.error('engagement-update failed', error);
        return false;
      }
    }
  );

  /** Delete an engagement */
  ipcMain.handle('engagement-delete', async (_, engagementId: string) => {
    debug.ipc('engagement-delete called', { engagementId });
    try {
      // Delete engagement and all related data
      await runWrite(
        `MATCH (e:Engagement {id: $engagementId})
         OPTIONAL MATCH (e)-[:TARGETS]->(t:Target)
         OPTIONAL MATCH (t)-[:HAS_SERVICE]->(s:Service)
         OPTIONAL MATCH (e)-[:HAS_FINDING]->(f:Finding)
         OPTIONAL MATCH (e)-[:HAS_CREDENTIAL]->(c:Credential)
         OPTIONAL MATCH (e)-[:HAS_LOOT]->(l:Loot)
         DETACH DELETE e, t, s, f, c, l`,
        { engagementId }
      );
      return { success: true };
    } catch (error) {
      debug.error('engagement-delete failed', error);
      return { success: false, error: String(error) };
    }
  });

  /** Get engagement statistics */
  ipcMain.handle('engagement-stats', async (_, engagementId: string) => {
    debug.ipc('engagement-stats called', { engagementId });
    try {
      const results = await runQuery<EngagementStats>(
        `MATCH (e:Engagement {id: $engagementId})
         OPTIONAL MATCH (e)-[:TARGETS]->(t:Target)
         OPTIONAL MATCH (t)-[:HAS_SERVICE]->(s:Service)
         OPTIONAL MATCH (e)-[:HAS_FINDING]->(f:Finding)
         OPTIONAL MATCH (e)-[:HAS_CREDENTIAL]->(c:Credential)
         OPTIONAL MATCH (e)-[:HAS_LOOT]->(l:Loot)
         RETURN
           count(DISTINCT t) as target_count,
           count(DISTINCT s) as service_count,
           count(DISTINCT f) as finding_count,
           count(DISTINCT c) as credential_count,
           count(DISTINCT l) as loot_count`,
        { engagementId }
      );
      return results.length > 0 ? results[0] : null;
    } catch (error) {
      debug.error('engagement-stats failed', error);
      return null;
    }
  });

  debug.ipc('Engagement IPC handlers registered');
}
