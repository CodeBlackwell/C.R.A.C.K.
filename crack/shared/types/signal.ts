/**
 * B.R.E.A.C.H. Signal Types
 *
 * Unified signal types for all reconnaissance data captured from terminal output.
 * Signals include: network reachability, port status, DNS, OS detection, and more.
 */

/** Signal confidence level */
export type SignalConfidence = 'high' | 'medium' | 'low' | 'uncertain';

/** Base signal type enumeration */
export type SignalType =
  | 'host_reachability'    // Ping results
  | 'port_status'          // Nmap, masscan, netcat port scans
  | 'dns_resolution'       // Dig, nslookup, host
  | 'os_detection'         // OS fingerprinting
  | 'host_identity'        // Hostname/domain discovery
  | 'user_enumeration'     // User/group discovery
  | 'cracked_hash';        // Hash cracked via hashcat/john

/** Command provenance - tracks what command produced a signal */
export interface CommandProvenance {
  sessionId: string;
  command: string;           // The exact command run
  workingDirectory?: string; // pwd when command was run
  timestamp: string;         // ISO timestamp when command was executed
  duration?: number;         // How long it took (ms)
  exitCode?: number;         // Success/failure
}

/** Base signal interface */
export interface Signal {
  id: string;
  type: SignalType;
  timestamp: string;
  confidence: SignalConfidence;
  engagementId: string;
  targetId?: string;
  sourceSessionId: string;
  sourceCommand?: string;
  provenance?: CommandProvenance;
}

// ============================================================================
// NETWORK SIGNALS
// ============================================================================

/** Host reachability signal (ping results) */
export interface HostReachabilitySignal extends Signal {
  type: 'host_reachability';
  ip: string;
  reachable: boolean;
  ttl?: number;              // TTL value (Windows=128, Linux=64)
  latencyMs?: number;        // Round-trip time
  packetsTransmitted?: number;
  packetsReceived?: number;
  packetLoss?: number;       // Percentage
}

/** Port state from scan results */
export type PortState = 'open' | 'closed' | 'filtered' | 'open|filtered' | 'unfiltered';

/** Port status signal (nmap, masscan, netcat) */
export interface PortStatusSignal extends Signal {
  type: 'port_status';
  ip: string;
  port: number;
  protocol: 'tcp' | 'udp';
  state: PortState;
  service?: string;          // http, ssh, smb, etc.
  version?: string;          // OpenSSH 8.9p1 Ubuntu
  banner?: string;           // Raw service banner
  scripts?: Record<string, string>; // Nmap script output
}

/** DNS resolution signal */
export interface DnsResolutionSignal extends Signal {
  type: 'dns_resolution';
  hostname: string;
  ip: string;
  recordType: 'A' | 'AAAA' | 'CNAME' | 'PTR' | 'MX' | 'TXT' | 'NS' | 'SRV';
  ttl?: number;
  dnsServer?: string;
}

// ============================================================================
// ENUMERATION SIGNALS
// ============================================================================

/** OS family classification */
export type OsFamily = 'Windows' | 'Linux' | 'macOS' | 'BSD' | 'Unix' | 'Network' | 'Unknown';

/** OS detection signal */
export interface OsDetectionSignal extends Signal {
  type: 'os_detection';
  ip: string;
  osFamily: OsFamily;
  osVersion?: string;        // "Windows Server 2019", "Ubuntu 22.04"
  kernelVersion?: string;    // "10.0.17763", "5.15.0-76-generic"
  cpe?: string;              // CPE identifier
  inferredFromTtl?: boolean; // If OS was guessed from TTL
}

/** Host identity signal (hostname/domain) */
export interface HostIdentitySignal extends Signal {
  type: 'host_identity';
  ip: string;
  hostname?: string;
  netbiosDomain?: string;
  dnsDomain?: string;
  fqdn?: string;
  workgroup?: string;
}

/** User enumeration signal */
export interface UserEnumerationSignal extends Signal {
  type: 'user_enumeration';
  domain?: string;
  username: string;
  uid?: number;
  gid?: number;
  groups?: string[];
  isPrivileged?: boolean;    // Admin/root
  isMachine?: boolean;       // Machine account (ends with $)
  isService?: boolean;       // Service account
  shell?: string;            // /bin/bash, etc.
  homeDir?: string;
}

// ============================================================================
// HASH CRACKING SIGNALS
// ============================================================================

/** Cracked hash signal (from potfile or terminal) */
export interface CrackedHashSignal extends Signal {
  type: 'cracked_hash';
  originalHash: string;
  plaintext: string;
  hashType?: string;         // NTLM, bcrypt, sha256, etc.
  hashcatMode?: number;      // 1000, 13100, 18200, etc.
  crackedBy?: 'hashcat' | 'john' | 'terminal';
  originalCredentialId?: string; // Link to original credential if found
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/** Generate signal ID */
export function generateSignalId(type: SignalType): string {
  const prefix = type.replace(/_/g, '-');
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

/** Infer OS family from TTL value */
export function inferOsFromTtl(ttl: number): OsFamily {
  if (ttl <= 64) return 'Linux';       // Linux/Unix default TTL is 64
  if (ttl <= 128) return 'Windows';    // Windows default TTL is 128
  if (ttl <= 255) return 'Network';    // Cisco/network devices use 255
  return 'Unknown';
}

/** Get severity for port state */
export function getPortStateSeverity(state: PortState): 'high' | 'medium' | 'low' {
  switch (state) {
    case 'open': return 'high';
    case 'filtered': return 'medium';
    case 'open|filtered': return 'medium';
    default: return 'low';
  }
}

/** Common service port mapping */
export const COMMON_PORTS: Record<number, string> = {
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'dns',
  80: 'http',
  88: 'kerberos',
  110: 'pop3',
  111: 'rpcbind',
  135: 'msrpc',
  139: 'netbios-ssn',
  143: 'imap',
  389: 'ldap',
  443: 'https',
  445: 'microsoft-ds',
  464: 'kpasswd',
  465: 'smtps',
  587: 'submission',
  593: 'http-rpc-epmap',
  636: 'ldaps',
  993: 'imaps',
  995: 'pop3s',
  1433: 'mssql',
  1521: 'oracle',
  2049: 'nfs',
  3306: 'mysql',
  3389: 'ms-wbt-server',
  5432: 'postgresql',
  5985: 'wsman',
  5986: 'wsmans',
  6379: 'redis',
  8080: 'http-proxy',
  8443: 'https-alt',
  9200: 'elasticsearch',
  27017: 'mongodb',
};

/** Get service name from port */
export function getServiceFromPort(port: number): string | undefined {
  return COMMON_PORTS[port];
}

/** Signal summary for engagement */
export interface SignalSummary {
  hosts: {
    reachable: number;
    unreachable: number;
  };
  ports: {
    open: number;
    closed: number;
    filtered: number;
  };
  dns: number;
  users: number;
  crackedHashes: number;
}
