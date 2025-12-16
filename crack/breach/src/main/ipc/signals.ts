/**
 * IPC Handlers for Network Signals
 *
 * Handles signal queries and operations from the renderer process.
 */

import { ipcMain } from 'electron';
import { debug } from '../debug';
import { getNetworkParser, getPotfileWatcher } from '../parser';
import { runQuery } from '@shared/neo4j/query';
import type {
  Signal,
  SignalType,
  HostReachabilitySignal,
  PortStatusSignal,
  DnsResolutionSignal,
  OsDetectionSignal,
  HostIdentitySignal,
  UserEnumerationSignal,
  CrackedHashSignal,
  SignalSummary,
} from '@shared/types/signal';

/**
 * Register signal-related IPC handlers
 */
export function registerSignalHandlers(): void {
  debug.ipc('Registering signal IPC handlers');

  // Get signals by engagement
  ipcMain.handle('signals:list', async (_, engagementId: string, type?: SignalType) => {
    debug.ipc('signals:list', { engagementId, type });

    try {
      let query: string;
      const params: Record<string, unknown> = { engagementId };

      if (type) {
        query = `
          MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:Signal {type: $type})
          RETURN s
          ORDER BY s.timestamp DESC
          LIMIT 500
        `;
        params.type = type;
      } else {
        query = `
          MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:Signal)
          RETURN s
          ORDER BY s.timestamp DESC
          LIMIT 500
        `;
      }

      const result = await runQuery(query, params);
      return result.map((r: { s: Signal }) => r.s);
    } catch (error) {
      debug.error('Failed to list signals', error);
      return [];
    }
  });

  // Get host reachability signals
  ipcMain.handle('signals:reachability', async (_, engagementId: string) => {
    debug.ipc('signals:reachability', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:HostReachability)
        RETURN s
        ORDER BY s.timestamp DESC
      `;

      const result = await runQuery(query, { engagementId });
      return result.map((r: { s: HostReachabilitySignal }) => r.s);
    } catch (error) {
      debug.error('Failed to get reachability signals', error);
      return [];
    }
  });

  // Get port status signals
  ipcMain.handle('signals:ports', async (_, engagementId: string, targetIp?: string) => {
    debug.ipc('signals:ports', { engagementId, targetIp });

    try {
      let query: string;
      const params: Record<string, unknown> = { engagementId };

      if (targetIp) {
        query = `
          MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:PortStatus {ip: $ip})
          RETURN s
          ORDER BY s.port ASC
        `;
        params.ip = targetIp;
      } else {
        query = `
          MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:PortStatus)
          RETURN s
          ORDER BY s.ip, s.port ASC
        `;
      }

      const result = await runQuery(query, params);
      return result.map((r: { s: PortStatusSignal }) => r.s);
    } catch (error) {
      debug.error('Failed to get port signals', error);
      return [];
    }
  });

  // Get open ports only
  ipcMain.handle('signals:open-ports', async (_, engagementId: string, targetIp?: string) => {
    debug.ipc('signals:open-ports', { engagementId, targetIp });

    try {
      let query: string;
      const params: Record<string, unknown> = { engagementId };

      if (targetIp) {
        query = `
          MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:PortStatus {ip: $ip, state: 'open'})
          RETURN s
          ORDER BY s.port ASC
        `;
        params.ip = targetIp;
      } else {
        query = `
          MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:PortStatus {state: 'open'})
          RETURN s
          ORDER BY s.ip, s.port ASC
        `;
      }

      const result = await runQuery(query, params);
      return result.map((r: { s: PortStatusSignal }) => r.s);
    } catch (error) {
      debug.error('Failed to get open port signals', error);
      return [];
    }
  });

  // Get DNS resolution signals
  ipcMain.handle('signals:dns', async (_, engagementId: string) => {
    debug.ipc('signals:dns', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:DnsResolution)
        RETURN s
        ORDER BY s.hostname ASC
      `;

      const result = await runQuery(query, { engagementId });
      return result.map((r: { s: DnsResolutionSignal }) => r.s);
    } catch (error) {
      debug.error('Failed to get DNS signals', error);
      return [];
    }
  });

  // Get OS detection signals
  ipcMain.handle('signals:os', async (_, engagementId: string, targetIp?: string) => {
    debug.ipc('signals:os', { engagementId, targetIp });

    try {
      let query: string;
      const params: Record<string, unknown> = { engagementId };

      if (targetIp) {
        query = `
          MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:OsDetection {ip: $ip})
          RETURN s
          ORDER BY s.confidence DESC
          LIMIT 1
        `;
        params.ip = targetIp;
      } else {
        query = `
          MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:OsDetection)
          RETURN s
          ORDER BY s.ip, s.confidence DESC
        `;
      }

      const result = await runQuery(query, params);
      return result.map((r: { s: OsDetectionSignal }) => r.s);
    } catch (error) {
      debug.error('Failed to get OS detection signals', error);
      return [];
    }
  });

  // Get user enumeration signals
  ipcMain.handle('signals:users', async (_, engagementId: string) => {
    debug.ipc('signals:users', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:UserEnumeration)
        RETURN s
        ORDER BY s.isPrivileged DESC, s.username ASC
      `;

      const result = await runQuery(query, { engagementId });
      return result.map((r: { s: UserEnumerationSignal }) => r.s);
    } catch (error) {
      debug.error('Failed to get user enumeration signals', error);
      return [];
    }
  });

  // Get cracked hash signals
  ipcMain.handle('signals:cracked-hashes', async (_, engagementId: string) => {
    debug.ipc('signals:cracked-hashes', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:CrackedHash)
        RETURN s
        ORDER BY s.timestamp DESC
      `;

      const result = await runQuery(query, { engagementId });
      return result.map((r: { s: CrackedHashSignal }) => r.s);
    } catch (error) {
      debug.error('Failed to get cracked hash signals', error);
      return [];
    }
  });

  // Get signal summary (counts)
  ipcMain.handle('signals:summary', async (_, engagementId: string) => {
    debug.ipc('signals:summary', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})
        OPTIONAL MATCH (e)-[:HAS_SIGNAL]->(hr:HostReachability)
        OPTIONAL MATCH (e)-[:HAS_SIGNAL]->(ps:PortStatus)
        OPTIONAL MATCH (e)-[:HAS_SIGNAL]->(dns:DnsResolution)
        OPTIONAL MATCH (e)-[:HAS_SIGNAL]->(ue:UserEnumeration)
        OPTIONAL MATCH (e)-[:HAS_SIGNAL]->(ch:CrackedHash)
        WITH e,
          collect(DISTINCT hr) AS reachabilities,
          collect(DISTINCT ps) AS ports,
          count(DISTINCT dns) AS dnsCount,
          count(DISTINCT ue) AS userCount,
          count(DISTINCT ch) AS crackCount
        RETURN {
          hosts: {
            reachable: size([r IN reachabilities WHERE r.reachable = true]),
            unreachable: size([r IN reachabilities WHERE r.reachable = false])
          },
          ports: {
            open: size([p IN ports WHERE p.state = 'open']),
            closed: size([p IN ports WHERE p.state = 'closed']),
            filtered: size([p IN ports WHERE p.state = 'filtered'])
          },
          dns: dnsCount,
          users: userCount,
          crackedHashes: crackCount
        } AS summary
      `;

      const result = await runQuery(query, { engagementId });
      if (result && result.length > 0) {
        return result[0].summary as SignalSummary;
      }

      return {
        hosts: { reachable: 0, unreachable: 0 },
        ports: { open: 0, closed: 0, filtered: 0 },
        dns: 0,
        users: 0,
        crackedHashes: 0,
      };
    } catch (error) {
      debug.error('Failed to get signal summary', error);
      return {
        hosts: { reachable: 0, unreachable: 0 },
        ports: { open: 0, closed: 0, filtered: 0 },
        dns: 0,
        users: 0,
        crackedHashes: 0,
      };
    }
  });

  // Get parser statistics
  ipcMain.handle('signals:parser-stats', async () => {
    debug.ipc('signals:parser-stats');

    return {
      networkParser: getNetworkParser().getStats(),
      potfileWatcher: getPotfileWatcher().getStats(),
    };
  });

  // Control potfile watcher
  ipcMain.handle('signals:start-potfile-watcher', async (_, engagementId: string) => {
    debug.ipc('signals:start-potfile-watcher', { engagementId });

    try {
      getPotfileWatcher().start(engagementId);
      return { success: true };
    } catch (error) {
      debug.error('Failed to start potfile watcher', error);
      return { success: false, error: String(error) };
    }
  });

  ipcMain.handle('signals:stop-potfile-watcher', async () => {
    debug.ipc('signals:stop-potfile-watcher');

    try {
      getPotfileWatcher().stop();
      return { success: true };
    } catch (error) {
      debug.error('Failed to stop potfile watcher', error);
      return { success: false, error: String(error) };
    }
  });

  // Add custom potfile to watch
  ipcMain.handle('signals:add-potfile', async (_, path: string, type: 'hashcat' | 'john') => {
    debug.ipc('signals:add-potfile', { path, type });

    try {
      getPotfileWatcher().addPotfile(path, type);
      return { success: true };
    } catch (error) {
      debug.error('Failed to add potfile', error);
      return { success: false, error: String(error) };
    }
  });

  // Get signals by target
  ipcMain.handle('signals:by-target', async (_, engagementId: string, targetId: string) => {
    debug.ipc('signals:by-target', { engagementId, targetId });

    try {
      const query = `
        MATCH (t:Target {id: $targetId})-[:HAS_SIGNAL]->(s:Signal)
        WHERE s.engagementId = $engagementId
        RETURN s
        ORDER BY s.timestamp DESC
      `;

      const result = await runQuery(query, { engagementId, targetId });
      return result.map((r: { s: Signal }) => r.s);
    } catch (error) {
      debug.error('Failed to get signals by target', error);
      return [];
    }
  });

  debug.ipc('Signal IPC handlers registered');
}
