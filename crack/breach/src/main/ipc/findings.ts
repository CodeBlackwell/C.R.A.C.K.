/**
 * Finding IPC Handlers
 *
 * CRUD operations for findings stored in Neo4j.
 * Findings represent vulnerabilities and issues discovered during engagements.
 */

import { ipcMain, BrowserWindow } from 'electron';
import { debug } from '../debug';
import { runQuery, runWrite } from '@shared/neo4j/query';
import type { Finding, CreateFindingData, FindingSummary } from '@shared/types/finding';
import { generateFindingId } from '@shared/types/finding';

/**
 * Register finding IPC handlers
 */
export function registerFindingHandlers(): void {
  debug.ipc('Registering finding IPC handlers');

  // List all findings for an engagement
  ipcMain.handle('finding-list', async (_, engagementId: string) => {
    debug.ipc('finding-list called', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_FINDING]->(f:Finding)
        OPTIONAL MATCH (f)-[:AFFECTS]->(t:Target)
        RETURN f, collect(DISTINCT t.ip) AS targetIps, collect(DISTINCT t.hostname) AS targetHostnames
        ORDER BY
          CASE f.severity
            WHEN 'critical' THEN 0
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 3
            WHEN 'info' THEN 4
            ELSE 5
          END,
          f.createdAt DESC
      `;
      const results = await runQuery(query, { engagementId });

      const findings: Finding[] = results.map((r: any) => ({
        ...r.f,
        targetIps: r.targetIps.filter((ip: string | null) => ip !== null),
        targetHostnames: r.targetHostnames.filter((h: string | null) => h !== null),
      }));

      debug.ipc('finding-list completed', { count: findings.length });
      return findings;
    } catch (error) {
      debug.error('finding-list failed', error);
      return [];
    }
  });

  // Add a new finding
  ipcMain.handle('finding-add', async (_, engagementId: string, findingData: CreateFindingData) => {
    debug.ipc('finding-add called', {
      title: findingData.title,
      severity: findingData.severity,
      category: findingData.category,
    });

    try {
      const id = generateFindingId();
      const createdAt = new Date().toISOString();

      const query = `
        MATCH (e:Engagement {id: $engagementId})
        CREATE (f:Finding {
          id: $id,
          title: $title,
          severity: $severity,
          category: $category,
          description: $description,
          evidence: $evidence,
          status: 'open',
          cveId: $cveId,
          cvssScore: $cvssScore,
          targetId: $targetId,
          sourceSessionId: $sourceSessionId,
          engagementId: $engagementId,
          createdAt: $createdAt
        })
        MERGE (e)-[:HAS_FINDING]->(f)
        WITH f
        OPTIONAL MATCH (t:Target {id: $targetId})
        FOREACH (_ IN CASE WHEN t IS NOT NULL THEN [1] ELSE [] END |
          MERGE (f)-[:AFFECTS]->(t)
        )
        OPTIONAL MATCH (s:TerminalSession {id: $sourceSessionId})
        FOREACH (_ IN CASE WHEN s IS NOT NULL THEN [1] ELSE [] END |
          MERGE (f)-[:DISCOVERED_BY]->(s)
        )
        RETURN f
      `;

      const params = {
        id,
        title: findingData.title,
        severity: findingData.severity,
        category: findingData.category,
        description: findingData.description,
        evidence: findingData.evidence,
        cveId: findingData.cveId || '',
        cvssScore: findingData.cvssScore || '',
        targetId: findingData.targetId || '',
        sourceSessionId: findingData.sourceSessionId || '',
        engagementId,
        createdAt,
      };

      await runWrite(query, params);

      const newFinding: Finding = {
        id,
        title: findingData.title,
        severity: findingData.severity,
        category: findingData.category,
        description: findingData.description,
        evidence: findingData.evidence,
        status: 'open',
        cveId: findingData.cveId,
        cvssScore: findingData.cvssScore,
        targetId: findingData.targetId,
        sourceSessionId: findingData.sourceSessionId,
        engagementId,
        createdAt,
      };

      debug.ipc('finding-add completed', { id });
      return newFinding;
    } catch (error) {
      debug.error('finding-add failed', error);
      throw error;
    }
  });

  // Update a finding
  ipcMain.handle('finding-update', async (_, id: string, updates: Partial<Finding>) => {
    debug.ipc('finding-update called', { id, updates: Object.keys(updates) });

    try {
      const setParts: string[] = [];
      const params: Record<string, any> = { id };

      if (updates.status !== undefined) {
        setParts.push('f.status = $status');
        params.status = updates.status;
      }
      if (updates.description !== undefined) {
        setParts.push('f.description = $description');
        params.description = updates.description;
      }
      if (updates.evidence !== undefined) {
        setParts.push('f.evidence = $evidence');
        params.evidence = updates.evidence;
      }
      if (updates.cveId !== undefined) {
        setParts.push('f.cveId = $cveId');
        params.cveId = updates.cveId;
      }
      if (updates.cvssScore !== undefined) {
        setParts.push('f.cvssScore = $cvssScore');
        params.cvssScore = updates.cvssScore;
      }
      if (updates.severity !== undefined) {
        setParts.push('f.severity = $severity');
        params.severity = updates.severity;
      }

      if (setParts.length === 0) {
        return true;
      }

      const query = `
        MATCH (f:Finding {id: $id})
        SET ${setParts.join(', ')}
        RETURN f
      `;

      await runWrite(query, params);
      debug.ipc('finding-update completed', { id });
      return true;
    } catch (error) {
      debug.error('finding-update failed', error);
      return false;
    }
  });

  // Delete a finding
  ipcMain.handle('finding-delete', async (_, id: string) => {
    debug.ipc('finding-delete called', { id });

    try {
      const query = `
        MATCH (f:Finding {id: $id})
        DETACH DELETE f
      `;
      await runWrite(query, { id });
      debug.ipc('finding-delete completed', { id });
      return true;
    } catch (error) {
      debug.error('finding-delete failed', error);
      return false;
    }
  });

  // Get findings by target
  ipcMain.handle('finding-by-target', async (_, targetId: string) => {
    debug.ipc('finding-by-target called', { targetId });

    try {
      const query = `
        MATCH (f:Finding)-[:AFFECTS]->(t:Target {id: $targetId})
        RETURN f
        ORDER BY
          CASE f.severity
            WHEN 'critical' THEN 0
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 3
            WHEN 'info' THEN 4
            ELSE 5
          END,
          f.createdAt DESC
      `;
      const results = await runQuery(query, { targetId });
      const findings = results.map((r: any) => r.f.properties);

      debug.ipc('finding-by-target completed', { count: findings.length });
      return findings;
    } catch (error) {
      debug.error('finding-by-target failed', error);
      return [];
    }
  });

  // Get findings summary (counts by severity)
  ipcMain.handle('finding-summary', async (_, engagementId: string) => {
    debug.ipc('finding-summary called', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_FINDING]->(f:Finding)
        RETURN f.severity AS severity, count(f) AS count
      `;
      const results = await runQuery(query, { engagementId });

      const summary: FindingSummary = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: 0,
      };

      for (const r of results) {
        const sev = r.severity as keyof Omit<FindingSummary, 'total'>;
        // Handle Neo4j Integer type (has toNumber method) or plain number
        let count: number;
        if (r.count && typeof r.count === 'object' && 'toNumber' in r.count) {
          count = (r.count as { toNumber: () => number }).toNumber();
        } else {
          count = Number(r.count) || 0;
        }
        if (sev in summary) {
          summary[sev] = count;
          summary.total += count;
        }
      }

      debug.ipc('finding-summary completed', summary);
      return summary;
    } catch (error) {
      debug.error('finding-summary failed', error);
      return { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    }
  });

  debug.ipc('Finding IPC handlers registered');
}

/**
 * Emit finding-discovered event to renderer
 * Called by the parser when a new finding is detected
 */
export function emitFindingDiscovered(finding: Finding, sessionId: string): void {
  const mainWindow = BrowserWindow.getAllWindows()[0];
  if (mainWindow) {
    mainWindow.webContents.send('finding-discovered', {
      finding,
      sessionId,
      isHighValue: finding.severity === 'critical' || finding.severity === 'high',
    });
    debug.ipc('finding-discovered emitted', { findingId: finding.id, severity: finding.severity });
  }
}
