/**
 * Loot Types for B.R.E.A.C.H.
 *
 * Represents downloaded files, captured flags, and discovered secrets.
 */

export type LootType = 'file' | 'flag' | 'hash' | 'config' | 'key';

export type PatternType =
  | 'gpp_password'
  | 'ntlm_hash'
  | 'kerberos_hash'
  | 'ssh_key'
  | 'flag'
  | 'flag_format'
  | 'password_in_file'
  | 'connection_string';

export interface Loot {
  id: string;
  type: LootType;
  name: string;                      // "Groups.xml", "user.txt"
  path: string;                      // Local path where saved
  sourcePath?: string;               // Remote path where found
  sourceSessionId: string;
  targetId: string;
  engagementId: string;
  contentPreview?: string;           // First 500 chars
  size?: number;                     // File size in bytes
  detectedPatterns: PatternType[];
  extractedData?: Record<string, string>;  // Pattern matches
  createdAt: string;
  notes?: string;
}

export interface LootPattern {
  type: PatternType;
  regex: RegExp;
  description: string;
  action?: {
    label: string;
    handler: string;
  };
}

// Patterns to detect in loot files
export const LOOT_PATTERNS: LootPattern[] = [
  {
    type: 'gpp_password',
    regex: /cpassword="([A-Za-z0-9+/=]+)"/,
    description: 'GPP Encrypted Password',
    action: { label: 'Decrypt GPP', handler: 'gpp-decrypt' },
  },
  {
    type: 'ntlm_hash',
    regex: /[a-fA-F0-9]{32}:[a-fA-F0-9]{32}/,
    description: 'NTLM Hash (LM:NT)',
    action: { label: 'Crack NTLM', handler: 'hashcat-ntlm' },
  },
  {
    type: 'kerberos_hash',
    regex: /\$krb5tgs\$\d+\$\*[^*]+\*[^*]+\*[^*]+\*[A-Fa-f0-9]+/,
    description: 'Kerberos TGS Hash',
    action: { label: 'Crack Kerberos', handler: 'hashcat-kerberoast' },
  },
  {
    type: 'ssh_key',
    regex: /-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
    description: 'SSH Private Key',
  },
  {
    type: 'flag',
    regex: /([a-f0-9]{32}|HTB\{[^}]+\}|flag\{[^}]+\}|OSCP\{[^}]+\})/i,
    description: 'CTF Flag',
  },
  {
    type: 'password_in_file',
    regex: /password\s*[=:]\s*["']?([^"'\s]+)["']?/i,
    description: 'Password in Config',
  },
  {
    type: 'connection_string',
    regex: /(?:jdbc:|mongodb:\/\/|mysql:\/\/|postgresql:\/\/)([^;\s]+)/i,
    description: 'Database Connection String',
  },
];

// Common flag file names to detect
export const FLAG_FILENAMES = [
  'user.txt',
  'root.txt',
  'proof.txt',
  'local.txt',
  'flag.txt',
  'user.flag',
  'root.flag',
];

/**
 * Detect patterns in file content
 */
export function detectPatterns(content: string): {
  patterns: PatternType[];
  matches: Record<string, string>;
} {
  const patterns: PatternType[] = [];
  const matches: Record<string, string> = {};

  for (const pattern of LOOT_PATTERNS) {
    const match = content.match(pattern.regex);
    if (match) {
      patterns.push(pattern.type);
      matches[pattern.type] = match[1] || match[0];
    }
  }

  return { patterns, matches };
}

/**
 * Check if filename indicates a flag file
 */
export function isFlagFile(filename: string): boolean {
  const normalized = filename.toLowerCase();
  return FLAG_FILENAMES.some(flag => normalized.endsWith(flag));
}

/**
 * Get action for a detected pattern
 */
export function getPatternAction(patternType: PatternType): LootPattern['action'] | undefined {
  return LOOT_PATTERNS.find(p => p.type === patternType)?.action;
}

/**
 * Generate loot ID
 */
export function generateLootId(): string {
  return `loot-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}
