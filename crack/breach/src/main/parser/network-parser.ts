/**
 * PRISM Network Parser for Terminal Output
 *
 * Real-time parsing of terminal output for network signals:
 * - Host reachability (ping)
 * - Port status (nmap, masscan, netcat)
 * - DNS resolution
 * - OS detection
 * - Host identity
 * - User enumeration
 */

import { BrowserWindow } from 'electron';
import { debug } from '../debug';
import { Deduplicator } from './deduplicator';
import {
  matchPing,
  matchPorts,
  matchDns,
  matchOs,
  matchHostIdentity,
  matchUsers,
  matchCrackedHashes,
  ParsedPing,
  ParsedPort,
  ParsedDns,
  ParsedOs,
  ParsedHost,
  ParsedUser,
  ParsedCrackedHash,
} from './patterns';
import {
  Signal,
  SignalType,
  SignalConfidence,
  HostReachabilitySignal,
  PortStatusSignal,
  DnsResolutionSignal,
  OsDetectionSignal,
  HostIdentitySignal,
  UserEnumerationSignal,
  CrackedHashSignal,
  generateSignalId,
  CommandProvenance,
} from '@shared/types/signal';
import { runWrite } from '@shared/neo4j/query';

/** Session context for parsing */
interface SessionContext {
  engagementId?: string;
  targetId?: string;
  targetIp?: string;
}

/** Parser configuration */
const CONFIG = {
  maxBufferLines: 100,       // Max lines to buffer per session
  parseDebounceMs: 300,      // Wait after last output before parsing
  minLinesForParse: 3,       // Minimum lines before parsing
};

/** Signal deduplication cache */
interface SignalDedup {
  pings: Set<string>;        // ip
  ports: Set<string>;        // ip:port/protocol
  dns: Set<string>;          // hostname:ip
  os: Set<string>;           // ip:osFamily
  hosts: Set<string>;        // ip:hostname
  users: Set<string>;        // domain\username
  cracks: Set<string>;       // hash
}

/**
 * Network Parser - extracts network signals from terminal output
 */
export class NetworkParser {
  private sessionDedup: Map<string, SignalDedup> = new Map();
  private enabled: boolean = true;

  constructor() {
    debug.prism('NetworkParser initialized');
  }

  /**
   * Enable/disable parsing
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
    debug.prism('NetworkParser enabled:', { enabled });
  }

  /**
   * Get or create dedup cache for session
   */
  private getDedup(sessionId: string): SignalDedup {
    let dedup = this.sessionDedup.get(sessionId);
    if (!dedup) {
      dedup = {
        pings: new Set(),
        ports: new Set(),
        dns: new Set(),
        os: new Set(),
        hosts: new Set(),
        users: new Set(),
        cracks: new Set(),
      };
      this.sessionDedup.set(sessionId, dedup);
    }
    return dedup;
  }

  /**
   * Parse text for all network signals
   */
  async parseText(
    text: string,
    sessionId: string,
    context: SessionContext,
    provenance?: CommandProvenance
  ): Promise<void> {
    if (!this.enabled || !context.engagementId) {
      return;
    }

    const dedup = this.getDedup(sessionId);

    try {
      // Parse all signal types in parallel
      await Promise.all([
        this.parsePings(text, sessionId, context, dedup, provenance),
        this.parsePorts(text, sessionId, context, dedup, provenance),
        this.parseDns(text, sessionId, context, dedup, provenance),
        this.parseOs(text, sessionId, context, dedup, provenance),
        this.parseHostIdentity(text, sessionId, context, dedup, provenance),
        this.parseUsers(text, sessionId, context, dedup, provenance),
        this.parseCrackedHashes(text, sessionId, context, dedup, provenance),
      ]);
    } catch (error) {
      debug.error('Error parsing network signals', { sessionId, error });
    }
  }

  /**
   * Parse ping results
   */
  private async parsePings(
    text: string,
    sessionId: string,
    context: SessionContext,
    dedup: SignalDedup,
    provenance?: CommandProvenance
  ): Promise<void> {
    const ping = matchPing(text, context.targetIp);
    if (!ping || !ping.ip) return;

    const key = ping.ip;
    if (dedup.pings.has(key)) return;
    dedup.pings.add(key);

    const signal: HostReachabilitySignal = {
      id: generateSignalId('host_reachability'),
      type: 'host_reachability',
      timestamp: new Date().toISOString(),
      confidence: ping.reachable ? 'high' : 'medium',
      engagementId: context.engagementId!,
      targetId: context.targetId,
      sourceSessionId: sessionId,
      sourceCommand: provenance?.command,
      provenance,
      ip: ping.ip,
      reachable: ping.reachable,
      ttl: ping.ttl,
      latencyMs: ping.latencyMs,
      packetsTransmitted: ping.packetsTransmitted,
      packetsReceived: ping.packetsReceived,
      packetLoss: ping.packetLoss,
    };

    await this.storeSignal(signal, 'HostReachability');
    this.emitSignal('host-reachability', signal, sessionId);

    // If we got TTL, also infer OS
    if (ping.ttl && !dedup.os.has(`${ping.ip}:ttl`)) {
      const os = matchOs('', ping.ttl);
      if (os) {
        dedup.os.add(`${ping.ip}:ttl`);
        const osSignal: OsDetectionSignal = {
          id: generateSignalId('os_detection'),
          type: 'os_detection',
          timestamp: new Date().toISOString(),
          confidence: 'low', // TTL inference is low confidence
          engagementId: context.engagementId!,
          targetId: context.targetId,
          sourceSessionId: sessionId,
          sourceCommand: provenance?.command,
          provenance,
          ip: ping.ip,
          osFamily: os.osFamily,
          inferredFromTtl: true,
        };
        await this.storeSignal(osSignal, 'OsDetection');
        this.emitSignal('os-detected', osSignal, sessionId);
      }
    }
  }

  /**
   * Parse port scan results
   */
  private async parsePorts(
    text: string,
    sessionId: string,
    context: SessionContext,
    dedup: SignalDedup,
    provenance?: CommandProvenance
  ): Promise<void> {
    const ports = matchPorts(text, context.targetIp);
    if (ports.length === 0) return;

    for (const port of ports) {
      const key = `${port.ip}:${port.port}/${port.protocol}`;
      if (dedup.ports.has(key)) continue;
      dedup.ports.add(key);

      const signal: PortStatusSignal = {
        id: generateSignalId('port_status'),
        type: 'port_status',
        timestamp: new Date().toISOString(),
        confidence: port.state === 'open' ? 'high' : 'medium',
        engagementId: context.engagementId!,
        targetId: context.targetId,
        sourceSessionId: sessionId,
        sourceCommand: provenance?.command,
        provenance,
        ip: port.ip,
        port: port.port,
        protocol: port.protocol,
        state: port.state,
        service: port.service,
        version: port.version,
      };

      await this.storeSignal(signal, 'PortStatus');
      this.emitSignal('port-discovered', signal, sessionId);
    }
  }

  /**
   * Parse DNS resolution results
   */
  private async parseDns(
    text: string,
    sessionId: string,
    context: SessionContext,
    dedup: SignalDedup,
    provenance?: CommandProvenance
  ): Promise<void> {
    const dnsResults = matchDns(text);
    if (dnsResults.length === 0) return;

    for (const dns of dnsResults) {
      const key = `${dns.hostname}:${dns.ip}`;
      if (dedup.dns.has(key)) continue;
      dedup.dns.add(key);

      const signal: DnsResolutionSignal = {
        id: generateSignalId('dns_resolution'),
        type: 'dns_resolution',
        timestamp: new Date().toISOString(),
        confidence: 'high',
        engagementId: context.engagementId!,
        targetId: context.targetId,
        sourceSessionId: sessionId,
        sourceCommand: provenance?.command,
        provenance,
        hostname: dns.hostname,
        ip: dns.ip,
        recordType: dns.recordType,
        ttl: dns.ttl,
      };

      await this.storeSignal(signal, 'DnsResolution');
      this.emitSignal('dns-resolved', signal, sessionId);
    }
  }

  /**
   * Parse OS detection results
   */
  private async parseOs(
    text: string,
    sessionId: string,
    context: SessionContext,
    dedup: SignalDedup,
    provenance?: CommandProvenance
  ): Promise<void> {
    const os = matchOs(text);
    if (!os) return;

    const ip = context.targetIp || '';
    const key = `${ip}:${os.osFamily}`;
    if (dedup.os.has(key)) return;
    dedup.os.add(key);

    const signal: OsDetectionSignal = {
      id: generateSignalId('os_detection'),
      type: 'os_detection',
      timestamp: new Date().toISOString(),
      confidence: os.cpe ? 'high' : os.osVersion ? 'medium' : 'low',
      engagementId: context.engagementId!,
      targetId: context.targetId,
      sourceSessionId: sessionId,
      sourceCommand: provenance?.command,
      provenance,
      ip,
      osFamily: os.osFamily,
      osVersion: os.osVersion,
      kernelVersion: os.kernelVersion,
      cpe: os.cpe,
      inferredFromTtl: os.inferredFromTtl,
    };

    await this.storeSignal(signal, 'OsDetection');
    this.emitSignal('os-detected', signal, sessionId);
  }

  /**
   * Parse host identity info
   */
  private async parseHostIdentity(
    text: string,
    sessionId: string,
    context: SessionContext,
    dedup: SignalDedup,
    provenance?: CommandProvenance
  ): Promise<void> {
    const host = matchHostIdentity(text);
    if (!host) return;

    const ip = context.targetIp || '';
    const key = `${ip}:${host.hostname || host.netbiosDomain}`;
    if (dedup.hosts.has(key)) return;
    dedup.hosts.add(key);

    const signal: HostIdentitySignal = {
      id: generateSignalId('host_identity'),
      type: 'host_identity',
      timestamp: new Date().toISOString(),
      confidence: host.fqdn ? 'high' : 'medium',
      engagementId: context.engagementId!,
      targetId: context.targetId,
      sourceSessionId: sessionId,
      sourceCommand: provenance?.command,
      provenance,
      ip,
      hostname: host.hostname,
      netbiosDomain: host.netbiosDomain,
      dnsDomain: host.dnsDomain,
      fqdn: host.fqdn,
    };

    await this.storeSignal(signal, 'HostIdentity');
    this.emitSignal('host-identity', signal, sessionId);
  }

  /**
   * Parse user enumeration results
   */
  private async parseUsers(
    text: string,
    sessionId: string,
    context: SessionContext,
    dedup: SignalDedup,
    provenance?: CommandProvenance
  ): Promise<void> {
    const users = matchUsers(text);
    if (users.length === 0) return;

    for (const user of users) {
      const key = `${user.domain || ''}\\${user.username}`.toLowerCase();
      if (dedup.users.has(key)) continue;
      dedup.users.add(key);

      const signal: UserEnumerationSignal = {
        id: generateSignalId('user_enumeration'),
        type: 'user_enumeration',
        timestamp: new Date().toISOString(),
        confidence: user.uid !== undefined ? 'high' : 'medium',
        engagementId: context.engagementId!,
        targetId: context.targetId,
        sourceSessionId: sessionId,
        sourceCommand: provenance?.command,
        provenance,
        domain: user.domain,
        username: user.username,
        uid: user.uid,
        gid: user.gid,
        groups: user.groups,
        isPrivileged: user.isPrivileged,
        isMachine: user.username.endsWith('$'),
        shell: user.shell,
      };

      await this.storeSignal(signal, 'UserEnumeration');
      this.emitSignal('user-enumerated', signal, sessionId);
    }
  }

  /**
   * Parse cracked hash results
   */
  private async parseCrackedHashes(
    text: string,
    sessionId: string,
    context: SessionContext,
    dedup: SignalDedup,
    provenance?: CommandProvenance
  ): Promise<void> {
    const cracks = matchCrackedHashes(text);
    if (cracks.length === 0) return;

    for (const crack of cracks) {
      if (dedup.cracks.has(crack.originalHash)) continue;
      dedup.cracks.add(crack.originalHash);

      const signal: CrackedHashSignal = {
        id: generateSignalId('cracked_hash'),
        type: 'cracked_hash',
        timestamp: new Date().toISOString(),
        confidence: 'high',
        engagementId: context.engagementId!,
        targetId: context.targetId,
        sourceSessionId: sessionId,
        sourceCommand: provenance?.command,
        provenance,
        originalHash: crack.originalHash,
        plaintext: crack.plaintext,
        hashType: crack.hashType,
        crackedBy: 'terminal',
      };

      await this.storeSignal(signal, 'CrackedHash');
      this.emitSignal('hash-cracked', signal, sessionId);

      // Attempt to correlate with existing credentials
      await this.correlateCrackedHash(signal);
    }
  }

  /**
   * Store signal in Neo4j
   */
  private async storeSignal(signal: Signal, nodeLabel: string): Promise<void> {
    const query = `
      MATCH (e:Engagement {id: $engagementId})
      CREATE (s:${nodeLabel}:Signal)
      SET s = $props
      MERGE (e)-[:HAS_SIGNAL]->(s)
      WITH s
      OPTIONAL MATCH (t:Target {id: $targetId})
      FOREACH (_ IN CASE WHEN t IS NOT NULL THEN [1] ELSE [] END |
        MERGE (t)-[:HAS_SIGNAL]->(s)
      )
      RETURN s.id
    `;

    try {
      await runWrite(query, {
        engagementId: signal.engagementId,
        targetId: signal.targetId || '',
        props: {
          ...signal,
          provenance: signal.provenance ? JSON.stringify(signal.provenance) : null,
        },
      });

      debug.prism('Signal stored', { type: signal.type, id: signal.id });
    } catch (error) {
      debug.error('Failed to store signal', { type: signal.type, error });
    }
  }

  /**
   * Correlate cracked hash with existing credentials
   */
  private async correlateCrackedHash(signal: CrackedHashSignal): Promise<void> {
    // Find credentials where secret matches the hash
    const query = `
      MATCH (c:Credential)
      WHERE c.engagementId = $engagementId
        AND c.secret CONTAINS $hashFragment
      SET c.crackedPlaintext = $plaintext,
          c.isCracked = true,
          c.crackedAt = datetime($timestamp),
          c.crackedBy = $crackedBy
      RETURN c.id, c.username
    `;

    try {
      // Use first 32 chars of hash for matching (NTLM hash length)
      const hashFragment = signal.originalHash.substring(0, 32);

      const result = await runWrite(query, {
        engagementId: signal.engagementId,
        hashFragment,
        plaintext: signal.plaintext,
        timestamp: signal.timestamp,
        crackedBy: signal.crackedBy || 'terminal',
      });

      if (result && result.length > 0) {
        debug.prism('Correlated cracked hash with credentials', {
          hash: signal.originalHash.substring(0, 20) + '...',
          count: result.length,
        });
      }
    } catch (error) {
      debug.error('Failed to correlate cracked hash', error);
    }
  }

  /**
   * Emit signal event to renderer
   */
  private emitSignal(channel: string, signal: Signal, sessionId: string): void {
    const mainWindow = BrowserWindow.getAllWindows()[0];
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send(channel, {
        signal,
        sessionId,
        isHighValue: this.isHighValueSignal(signal),
      });
    }
  }

  /**
   * Determine if signal is high value (for notifications)
   */
  private isHighValueSignal(signal: Signal): boolean {
    switch (signal.type) {
      case 'port_status':
        const portSignal = signal as PortStatusSignal;
        // High-value ports: SMB, RDP, SSH, WinRM
        const highValuePorts = [22, 445, 3389, 5985, 5986];
        return portSignal.state === 'open' && highValuePorts.includes(portSignal.port);

      case 'user_enumeration':
        const userSignal = signal as UserEnumerationSignal;
        return userSignal.isPrivileged === true;

      case 'cracked_hash':
        return true; // All cracked hashes are high value

      case 'os_detection':
        const osSignal = signal as OsDetectionSignal;
        return !osSignal.inferredFromTtl; // Direct detection is high value

      default:
        return false;
    }
  }

  /**
   * Clear dedup cache for session
   */
  clearSession(sessionId: string): void {
    this.sessionDedup.delete(sessionId);
  }

  /**
   * Handle engagement change
   */
  onEngagementChange(engagementId: string | null): void {
    // Clear all session dedup caches on engagement change
    this.sessionDedup.clear();
  }

  /**
   * Get parser statistics
   */
  getStats(): {
    enabled: boolean;
    sessions: number;
    signalCounts: Record<string, number>;
  } {
    const signalCounts: Record<string, number> = {
      pings: 0,
      ports: 0,
      dns: 0,
      os: 0,
      hosts: 0,
      users: 0,
      cracks: 0,
    };

    for (const dedup of this.sessionDedup.values()) {
      signalCounts.pings += dedup.pings.size;
      signalCounts.ports += dedup.ports.size;
      signalCounts.dns += dedup.dns.size;
      signalCounts.os += dedup.os.size;
      signalCounts.hosts += dedup.hosts.size;
      signalCounts.users += dedup.users.size;
      signalCounts.cracks += dedup.cracks.size;
    }

    return {
      enabled: this.enabled,
      sessions: this.sessionDedup.size,
      signalCounts,
    };
  }
}

// Singleton instance
let networkParserInstance: NetworkParser | null = null;

/**
 * Get or create network parser instance
 */
export function getNetworkParser(): NetworkParser {
  if (!networkParserInstance) {
    networkParserInstance = new NetworkParser();
  }
  return networkParserInstance;
}
