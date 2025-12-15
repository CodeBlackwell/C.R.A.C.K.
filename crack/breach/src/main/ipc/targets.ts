/**
 * Target IPC Handlers
 *
 * IPC handlers for target and service management.
 */

import { ipcMain } from 'electron';
import { runQuery, runWrite } from '@shared/neo4j/query';
import { createDebugLogger } from '@shared/electron/debug';

const debug = createDebugLogger({ appName: 'breach' });

/** Register target-related IPC handlers */
export function registerTargetHandlers(): void {
  debug.ipc('Registering target IPC handlers');

  // List targets for engagement
  ipcMain.handle('target-list', async (_, engagementId: string) => {
    debug.ipc('target-list called', { engagementId });
    try {
      const results = await runQuery(
        `MATCH (e:Engagement {id: $engagementId})-[:TARGETS]->(t:Target)
         OPTIONAL MATCH (t)-[:HAS_SERVICE]->(s:Service)
         WITH t, count(s) as serviceCount
         RETURN t.id as id, t.ip_address as ip_address, t.hostname as hostname,
                t.os_guess as os_guess, t.status as status, t.notes as notes,
                serviceCount
         ORDER BY t.ip_address`,
        { engagementId }
      );
      debug.ipc('target-list completed', { count: results.length });
      return results;
    } catch (error) {
      debug.error('target-list failed', error);
      return [];
    }
  });

  // Get target details
  ipcMain.handle('target-get', async (_, targetId: string) => {
    debug.ipc('target-get called', { targetId });
    try {
      const results = await runQuery(
        `MATCH (t:Target {id: $targetId})
         OPTIONAL MATCH (t)-[:HAS_SERVICE]->(s:Service)
         WITH t, collect(s{.*}) as services
         RETURN t{.*, services: services}`,
        { targetId }
      );
      return results.length > 0 ? results[0].t : null;
    } catch (error) {
      debug.error('target-get failed', error);
      return null;
    }
  });

  // Get services for target
  ipcMain.handle('target-services', async (_, targetId: string) => {
    debug.ipc('target-services called', { targetId });
    try {
      const results = await runQuery(
        `MATCH (t:Target {id: $targetId})-[:HAS_SERVICE]->(s:Service)
         RETURN s.id as id, s.port as port, s.protocol as protocol,
                s.service_name as service_name, s.version as version,
                s.banner as banner, s.state as state
         ORDER BY s.port`,
        { targetId }
      );
      return results;
    } catch (error) {
      debug.error('target-services failed', error);
      return [];
    }
  });

  // Get findings for target
  ipcMain.handle('target-findings', async (_, targetId: string) => {
    debug.ipc('target-findings called', { targetId });
    try {
      const results = await runQuery(
        `MATCH (f:Finding)-[:AFFECTS]->(t:Target {id: $targetId})
         RETURN f.id as id, f.title as title, f.severity as severity,
                f.status as status, f.cve_id as cve_id, f.description as description
         ORDER BY
           CASE f.severity
             WHEN 'critical' THEN 1
             WHEN 'high' THEN 2
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 4
             ELSE 5
           END`,
        { targetId }
      );
      return results;
    } catch (error) {
      debug.error('target-findings failed', error);
      return [];
    }
  });

  // Update target status
  ipcMain.handle('target-update-status', async (_, targetId: string, status: string) => {
    debug.ipc('target-update-status called', { targetId, status });
    try {
      const stats = await runWrite(
        `MATCH (t:Target {id: $targetId})
         SET t.status = $status, t.last_seen = datetime()
         RETURN t`,
        { targetId, status }
      );
      return stats.propertiesSet > 0;
    } catch (error) {
      debug.error('target-update-status failed', error);
      return false;
    }
  });

  debug.ipc('Target IPC handlers registered');
}
