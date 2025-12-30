/**
 * Report Neo4j Queries
 *
 * Gathers all engagement data for report generation.
 */

import { runQuery } from '@shared/neo4j/query';
import type { Engagement, EngagementStats } from '@shared/types/engagement';
import type { Target } from '@shared/types/target';
import type { Finding, FindingSummary } from '@shared/types/finding';
import type { Credential } from '@shared/types/credential';
import type { Loot } from '@shared/types/loot';
import type { Signal, SignalSummary, PortStatusSignal, CrackedHashSignal } from '@shared/types/signal';
import type { TerminalSession } from '@shared/types/session';
import type { ReportData, TimelineEvent } from './types';
import { debug } from '../debug';

/**
 * Get engagement by ID
 */
async function getEngagement(engagementId: string): Promise<Engagement | null> {
  const query = `
    MATCH (e:Engagement {id: $engagementId})
    RETURN e
  `;
  const results = await runQuery<{ e: Engagement }>(query, { engagementId });
  return results.length > 0 ? results[0].e : null;
}

/**
 * Get engagement statistics
 */
async function getEngagementStats(engagementId: string): Promise<EngagementStats> {
  const query = `
    MATCH (e:Engagement {id: $engagementId})
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
      count(DISTINCT l) as loot_count
  `;
  const results = await runQuery(query, { engagementId });

  if (results.length === 0) {
    return { target_count: 0, service_count: 0, finding_count: 0, credential_count: 0, loot_count: 0 };
  }

  const r = results[0] as any;
  return {
    target_count: typeof r.target_count === 'object' ? r.target_count.toNumber() : Number(r.target_count) || 0,
    service_count: typeof r.service_count === 'object' ? r.service_count.toNumber() : Number(r.service_count) || 0,
    finding_count: typeof r.finding_count === 'object' ? r.finding_count.toNumber() : Number(r.finding_count) || 0,
    credential_count: typeof r.credential_count === 'object' ? r.credential_count.toNumber() : Number(r.credential_count) || 0,
    loot_count: typeof r.loot_count === 'object' ? r.loot_count.toNumber() : Number(r.loot_count) || 0,
  };
}

/**
 * Get all targets for engagement
 */
async function getTargets(engagementId: string): Promise<Target[]> {
  const query = `
    MATCH (e:Engagement {id: $engagementId})-[:TARGETS]->(t:Target)
    RETURN t
    ORDER BY t.ip_address
  `;
  const results = await runQuery<{ t: Target }>(query, { engagementId });
  return results.map((r) => r.t);
}

/**
 * Get all findings for engagement (sorted by severity)
 */
async function getFindings(engagementId: string): Promise<Finding[]> {
  const query = `
    MATCH (e:Engagement {id: $engagementId})-[:HAS_FINDING]->(f:Finding)
    OPTIONAL MATCH (f)-[:AFFECTS]->(t:Target)
    RETURN f, collect(DISTINCT t.ip_address) AS targetIps
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
  return results.map((r: any) => ({
    ...r.f,
    targetIps: r.targetIps.filter((ip: string | null) => ip !== null),
  }));
}

/**
 * Get finding summary (counts by severity)
 */
async function getFindingSummary(engagementId: string): Promise<FindingSummary> {
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

  for (const r of results as any[]) {
    const sev = r.severity as keyof Omit<FindingSummary, 'total'>;
    const count = typeof r.count === 'object' && 'toNumber' in r.count
      ? r.count.toNumber()
      : Number(r.count) || 0;
    if (sev in summary) {
      summary[sev] = count;
      summary.total += count;
    }
  }

  return summary;
}

/**
 * Get all credentials for engagement
 */
async function getCredentials(engagementId: string): Promise<Credential[]> {
  const query = `
    MATCH (e:Engagement {id: $engagementId})-[:HAS_CREDENTIAL]->(c:Credential)
    OPTIONAL MATCH (c)-[:FOUND_ON]->(t:Target)
    RETURN c, t.ip_address AS targetIp
    ORDER BY c.createdAt DESC
  `;
  const results = await runQuery(query, { engagementId });
  return results.map((r: any) => ({
    ...r.c,
    targetIp: r.targetIp,
  }));
}

/**
 * Get all loot for engagement
 */
async function getLoot(engagementId: string): Promise<Loot[]> {
  const query = `
    MATCH (e:Engagement {id: $engagementId})-[:HAS_LOOT]->(l:Loot)
    OPTIONAL MATCH (l)-[:FROM_TARGET]->(t:Target)
    RETURN l, t.ip_address AS targetIp
    ORDER BY l.createdAt DESC
  `;
  const results = await runQuery(query, { engagementId });
  return results.map((r: any) => ({
    ...r.l,
    detectedPatterns: r.l.detectedPatterns || [],
    targetIp: r.targetIp,
  }));
}

/**
 * Get key signals for engagement (port status, cracked hashes, OS detection)
 */
async function getSignals(engagementId: string): Promise<Signal[]> {
  const query = `
    MATCH (e:Engagement {id: $engagementId})-[:HAS_SIGNAL]->(s:Signal)
    WHERE s.type IN ['port_status', 'cracked_hash', 'os_detection', 'user_enumeration']
    RETURN s
    ORDER BY s.timestamp DESC
    LIMIT 500
  `;
  const results = await runQuery<{ s: Signal }>(query, { engagementId });
  return results.map((r) => r.s);
}

/**
 * Get signal summary
 */
async function getSignalSummary(engagementId: string): Promise<SignalSummary> {
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

  const results = await runQuery<{ summary: SignalSummary }>(query, { engagementId });
  if (results.length > 0) {
    return results[0].summary;
  }

  return {
    hosts: { reachable: 0, unreachable: 0 },
    ports: { open: 0, closed: 0, filtered: 0 },
    dns: 0,
    users: 0,
    crackedHashes: 0,
  };
}

/**
 * Get terminal sessions for engagement
 */
async function getSessions(engagementId: string): Promise<TerminalSession[]> {
  const query = `
    MATCH (e:Engagement {id: $engagementId})-[:HAS_TERMINAL_SESSION]->(s:TerminalSession)
    RETURN s
    ORDER BY s.startedAt DESC
  `;
  const results = await runQuery<{ s: TerminalSession }>(query, { engagementId });
  return results.map((r) => r.s);
}

/**
 * Build unified timeline from all timestamped events
 */
function buildTimeline(
  findings: Finding[],
  credentials: Credential[],
  loot: Loot[],
  signals: Signal[],
  sessions: TerminalSession[]
): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  // Map findings
  for (const f of findings) {
    if (f.createdAt) {
      events.push({
        timestamp: f.createdAt,
        type: 'finding',
        title: f.title,
        description: f.description || f.evidence?.slice(0, 100) || '',
        severity: f.severity,
        targetIp: (f as any).targetIps?.[0],
      });
    }
  }

  // Map credentials
  for (const c of credentials) {
    if (c.createdAt) {
      events.push({
        timestamp: c.createdAt,
        type: 'credential',
        title: `${c.username} (${c.secretType})`,
        description: `Source: ${c.source || 'unknown'}`,
        targetIp: (c as any).targetIp,
      });
    }
  }

  // Map loot
  for (const l of loot) {
    if (l.createdAt) {
      events.push({
        timestamp: l.createdAt,
        type: 'loot',
        title: l.name,
        description: `Type: ${l.type}${l.detectedPatterns?.length ? `, Patterns: ${l.detectedPatterns.join(', ')}` : ''}`,
        targetIp: (l as any).targetIp,
      });
    }
  }

  // Map key signals (open ports, cracked hashes)
  for (const s of signals) {
    if (s.timestamp && (s.type === 'port_status' || s.type === 'cracked_hash')) {
      let title = s.type.replace(/_/g, ' ');
      let description = '';

      if (s.type === 'port_status') {
        const ps = s as PortStatusSignal;
        title = `Port ${ps.port}/${ps.protocol} ${ps.state}`;
        description = ps.service ? `Service: ${ps.service}` : '';
        events.push({
          timestamp: s.timestamp,
          type: 'signal',
          title,
          description,
          targetIp: ps.ip,
        });
      } else if (s.type === 'cracked_hash') {
        const ch = s as CrackedHashSignal;
        title = `Hash cracked: ${ch.plaintext?.slice(0, 20) || '[redacted]'}`;
        description = `Type: ${ch.hashType || 'unknown'}`;
        events.push({
          timestamp: s.timestamp,
          type: 'signal',
          title,
          description,
        });
      }
    }
  }

  // Map session starts/stops
  for (const sess of sessions) {
    if (sess.startedAt) {
      events.push({
        timestamp: sess.startedAt,
        type: 'session_start',
        title: (sess as any).label || sess.command || 'Session',
        description: `Type: ${sess.type || 'terminal'}`,
      });
    }
    if ((sess as any).stoppedAt) {
      events.push({
        timestamp: (sess as any).stoppedAt,
        type: 'session_stop',
        title: `Stopped: ${(sess as any).label || sess.command || 'Session'}`,
        description: `Exit code: ${(sess as any).exitCode ?? 'unknown'}`,
      });
    }
  }

  // Sort descending (most recent first)
  return events.sort((a, b) =>
    new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
}

/**
 * Gather all report data for an engagement
 */
export async function gatherReportData(engagementId: string): Promise<ReportData> {
  debug.ipc('gatherReportData', { engagementId });

  // Execute all queries in parallel for performance
  const [
    engagement,
    stats,
    targets,
    findings,
    findingSummary,
    credentials,
    loot,
    signals,
    signalSummary,
    sessions,
  ] = await Promise.all([
    getEngagement(engagementId),
    getEngagementStats(engagementId),
    getTargets(engagementId),
    getFindings(engagementId),
    getFindingSummary(engagementId),
    getCredentials(engagementId),
    getLoot(engagementId),
    getSignals(engagementId),
    getSignalSummary(engagementId),
    getSessions(engagementId),
  ]);

  // Build unified timeline
  const timeline = buildTimeline(findings, credentials, loot, signals, sessions);

  debug.ipc('gatherReportData completed', {
    hasEngagement: !!engagement,
    targetCount: targets.length,
    findingCount: findings.length,
    credentialCount: credentials.length,
    lootCount: loot.length,
    signalCount: signals.length,
    timelineCount: timeline.length,
  });

  return {
    engagement: engagement!,
    stats,
    targets,
    findings,
    findingSummary,
    credentials,
    loot,
    signals,
    signalSummary,
    sessions,
    timeline,
    generatedAt: new Date().toISOString(),
  };
}
