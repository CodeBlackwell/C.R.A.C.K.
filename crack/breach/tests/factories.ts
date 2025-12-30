/**
 * Test Data Factories for B.R.E.A.C.H. IPC Tests
 *
 * Provides factory functions for creating test data with sensible defaults.
 * Override only the fields that matter for your specific test.
 */

import type { Credential, SecretType } from '@shared/types/credential';
import type { TerminalSession, SessionType, SessionStatus, CreateSessionOptions } from '@shared/types/session';
import type { Engagement, EngagementStatus, CreateEngagementData, EngagementStats } from '@shared/types/engagement';
import type { Loot, LootType, PatternType } from '@shared/types/loot';

// ============================================================================
// Credential Factory
// ============================================================================

let credentialCounter = 0;

export interface CredentialOverrides {
  id?: string;
  username?: string;
  secret?: string;
  secretType?: SecretType;
  domain?: string;
  source?: string;
  sourceSessionId?: string;
  targetId?: string;
  engagementId?: string;
  validatedAccess?: string[];
  isAdmin?: boolean;
  createdAt?: string;
  notes?: string;
}

/**
 * Create a test credential with sensible defaults
 */
export function createCredential(overrides: CredentialOverrides = {}): Credential {
  credentialCounter++;
  return {
    id: overrides.id ?? `cred-test-${credentialCounter}`,
    username: overrides.username ?? `testuser${credentialCounter}`,
    secret: overrides.secret ?? 'TestPassword123!',
    secretType: overrides.secretType ?? 'password',
    domain: overrides.domain ?? 'TESTDOMAIN',
    source: overrides.source ?? 'mimikatz',
    sourceSessionId: overrides.sourceSessionId,
    targetId: overrides.targetId,
    engagementId: overrides.engagementId ?? 'eng-test-123',
    validatedAccess: overrides.validatedAccess ?? [],
    isAdmin: overrides.isAdmin ?? false,
    createdAt: overrides.createdAt ?? new Date().toISOString(),
    notes: overrides.notes,
  };
}

/**
 * Create an NTLM hash credential
 */
export function createNtlmCredential(overrides: CredentialOverrides = {}): Credential {
  return createCredential({
    ...overrides,
    secretType: 'ntlm',
    secret: overrides.secret ?? 'aad3b435b51404eeaad3b435b51404ee:' + 'a'.repeat(32),
  });
}

/**
 * Create a GPP decrypted credential
 */
export function createGppCredential(overrides: CredentialOverrides = {}): Credential {
  return createCredential({
    ...overrides,
    secretType: 'gpp',
    source: 'Groups.xml',
  });
}

/**
 * Create a Kerberos hash credential
 */
export function createKerberosCredential(overrides: CredentialOverrides = {}): Credential {
  return createCredential({
    ...overrides,
    secretType: 'kerberos',
    secret: overrides.secret ?? '$krb5tgs$23$*user$DOMAIN*$testservice$' + 'a'.repeat(64),
    source: 'kerberoast',
  });
}

/**
 * Create an admin credential
 */
export function createAdminCredential(overrides: CredentialOverrides = {}): Credential {
  return createCredential({
    ...overrides,
    username: overrides.username ?? 'Administrator',
    isAdmin: true,
    validatedAccess: overrides.validatedAccess ?? ['smb:ADMIN$', 'winrm'],
  });
}

// ============================================================================
// Session Factory
// ============================================================================

let sessionCounter = 0;

export interface SessionOverrides {
  id?: string;
  type?: SessionType;
  status?: SessionStatus;
  command?: string;
  args?: string[];
  workingDir?: string;
  env?: Record<string, string>;
  pid?: number;
  exitCode?: number;
  targetId?: string;
  engagementId?: string;
  linkedSessions?: string[];
  parentSessionId?: string;
  label?: string;
  icon?: string;
  persistent?: boolean;
  interactive?: boolean;
  startedAt?: string;
  stoppedAt?: string;
  lastActivityAt?: string;
}

/**
 * Create a test session with sensible defaults
 */
export function createSession(overrides: SessionOverrides = {}): TerminalSession {
  sessionCounter++;
  return {
    id: overrides.id ?? `session-test-${sessionCounter}`,
    type: overrides.type ?? 'shell',
    status: overrides.status ?? 'running',
    command: overrides.command ?? '/bin/bash',
    args: overrides.args ?? [],
    workingDir: overrides.workingDir ?? '/home/kali',
    env: overrides.env,
    pid: overrides.pid ?? 12345 + sessionCounter,
    exitCode: overrides.exitCode,
    targetId: overrides.targetId,
    engagementId: overrides.engagementId ?? 'eng-test-123',
    linkedSessions: overrides.linkedSessions ?? [],
    parentSessionId: overrides.parentSessionId,
    label: overrides.label,
    icon: overrides.icon,
    persistent: overrides.persistent ?? true,
    interactive: overrides.interactive ?? true,
    startedAt: overrides.startedAt ?? new Date().toISOString(),
    stoppedAt: overrides.stoppedAt,
    lastActivityAt: overrides.lastActivityAt,
  };
}

/**
 * Create a listener session
 */
export function createListenerSession(overrides: SessionOverrides = {}): TerminalSession {
  return createSession({
    ...overrides,
    type: 'listener',
    command: 'nc',
    args: ['-lvnp', '4444'],
    label: overrides.label ?? 'NC Listener',
  });
}

/**
 * Create a scan session
 */
export function createScanSession(overrides: SessionOverrides = {}): TerminalSession {
  return createSession({
    ...overrides,
    type: 'scan',
    command: 'nmap',
    args: ['-sC', '-sV', '192.168.1.0/24'],
    label: overrides.label ?? 'Nmap Scan',
  });
}

// ============================================================================
// Engagement Factory
// ============================================================================

let engagementCounter = 0;

export interface EngagementOverrides {
  id?: string;
  name?: string;
  status?: EngagementStatus;
  start_date?: string;
  end_date?: string;
  scope_type?: string;
  scope_text?: string;
  notes?: string;
  created_at?: string;
}

/**
 * Create a test engagement with sensible defaults
 */
export function createEngagement(overrides: EngagementOverrides = {}): Engagement {
  engagementCounter++;
  const now = new Date().toISOString();
  return {
    id: overrides.id ?? `eng-test-${engagementCounter}`,
    name: overrides.name ?? `Test Engagement ${engagementCounter}`,
    status: overrides.status ?? 'paused',
    start_date: overrides.start_date ?? now.split('T')[0],
    end_date: overrides.end_date,
    scope_type: overrides.scope_type,
    scope_text: overrides.scope_text,
    notes: overrides.notes,
    created_at: overrides.created_at ?? now,
  };
}

/**
 * Create an active engagement
 */
export function createActiveEngagement(overrides: EngagementOverrides = {}): Engagement {
  return createEngagement({
    ...overrides,
    status: 'active',
  });
}

/**
 * Create engagement creation data
 */
export function createEngagementData(overrides: Partial<CreateEngagementData> = {}): CreateEngagementData {
  return {
    name: overrides.name ?? 'New Engagement',
    scope_type: overrides.scope_type,
    scope_text: overrides.scope_text,
    notes: overrides.notes,
  };
}

/**
 * Create engagement stats
 */
export function createEngagementStats(overrides: Partial<EngagementStats> = {}): EngagementStats {
  return {
    target_count: overrides.target_count ?? 0,
    service_count: overrides.service_count ?? 0,
    finding_count: overrides.finding_count ?? 0,
    credential_count: overrides.credential_count ?? 0,
    loot_count: overrides.loot_count ?? 0,
  };
}

// ============================================================================
// Loot Factory
// ============================================================================

let lootCounter = 0;

export interface LootOverrides {
  id?: string;
  type?: LootType;
  name?: string;
  path?: string;
  sourcePath?: string;
  sourceSessionId?: string;
  targetId?: string;
  engagementId?: string;
  contentPreview?: string;
  size?: number;
  detectedPatterns?: PatternType[];
  extractedData?: Record<string, string>;
  createdAt?: string;
  notes?: string;
}

/**
 * Create a test loot item with sensible defaults
 */
export function createLoot(overrides: LootOverrides = {}): Loot {
  lootCounter++;
  return {
    id: overrides.id ?? `loot-test-${lootCounter}`,
    type: overrides.type ?? 'file',
    name: overrides.name ?? `testfile${lootCounter}.txt`,
    path: overrides.path ?? `/tmp/loot/testfile${lootCounter}.txt`,
    sourcePath: overrides.sourcePath,
    sourceSessionId: overrides.sourceSessionId ?? 'session-test-123',
    targetId: overrides.targetId ?? 'target-test-123',
    engagementId: overrides.engagementId ?? 'eng-test-123',
    contentPreview: overrides.contentPreview,
    size: overrides.size,
    detectedPatterns: overrides.detectedPatterns ?? [],
    extractedData: overrides.extractedData,
    createdAt: overrides.createdAt ?? new Date().toISOString(),
    notes: overrides.notes,
  };
}

/**
 * Create a flag loot item
 */
export function createFlag(overrides: LootOverrides = {}): Loot {
  return createLoot({
    ...overrides,
    type: 'flag',
    name: overrides.name ?? 'user.txt',
    contentPreview: overrides.contentPreview ?? '32characterflaghashgoeshere12345',
  });
}

/**
 * Create a GPP config loot item
 */
export function createGppLoot(overrides: LootOverrides = {}): Loot {
  return createLoot({
    ...overrides,
    type: 'config',
    name: 'Groups.xml',
    detectedPatterns: ['gpp_password'],
    extractedData: { gpp_password: 'encrypted_value' },
  });
}

/**
 * Create an SSH key loot item
 */
export function createSshKeyLoot(overrides: LootOverrides = {}): Loot {
  return createLoot({
    ...overrides,
    type: 'key',
    name: overrides.name ?? 'id_rsa',
    detectedPatterns: ['ssh_key'],
    contentPreview: '-----BEGIN RSA PRIVATE KEY-----\nMIIE...',
  });
}

/**
 * Create a hash loot item
 */
export function createHashLoot(overrides: LootOverrides = {}): Loot {
  return createLoot({
    ...overrides,
    type: 'hash',
    name: overrides.name ?? 'kerberoast.txt',
    detectedPatterns: ['kerberos_hash'],
    extractedData: { kerberos_hash: '$krb5tgs$23$*user$DOMAIN*$test' },
  });
}

// ============================================================================
// Reset Functions
// ============================================================================

/**
 * Reset all factory counters
 */
export function resetFactories(): void {
  credentialCounter = 0;
  sessionCounter = 0;
  engagementCounter = 0;
  lootCounter = 0;
}
