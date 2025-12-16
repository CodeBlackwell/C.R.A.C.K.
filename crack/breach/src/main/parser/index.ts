/**
 * PRISM Parser Module
 *
 * Real-time terminal output parsing for:
 * - Credentials (mimikatz, secretsdump, kerberoast, GPP)
 * - Findings (SQLi, LFI, RCE indicators)
 * - Network signals (ping, ports, DNS, OS detection)
 * - User enumeration
 * - Cracked hashes
 */

// Credential Parser
export { CredentialParser, getCredentialParser } from './credential-parser';

// Network Parser
export { NetworkParser, getNetworkParser } from './network-parser';

// Potfile Watcher
export { PotfileWatcher, getPotfileWatcher } from './potfile-watcher';

// Deduplicator
export { Deduplicator } from './deduplicator';

// Credential patterns and matchers
export {
  CREDENTIAL_PATTERNS,
  FINDING_PATTERNS,
  matchCredentials,
  matchFindings,
  type ParsedCredential,
  type ParsedFinding,
} from './patterns';

// Network patterns and matchers
export {
  NETWORK_PATTERNS,
  OS_PATTERNS,
  HOST_IDENTITY_PATTERNS,
  USER_PATTERNS,
  CRACK_PATTERNS,
  matchPing,
  matchPorts,
  matchDns,
  matchOs,
  matchHostIdentity,
  matchUsers,
  matchCrackedHashes,
  type ParsedPing,
  type ParsedPort,
  type ParsedDns,
  type ParsedOs,
  type ParsedHost,
  type ParsedUser,
  type ParsedCrackedHash,
} from './patterns';
