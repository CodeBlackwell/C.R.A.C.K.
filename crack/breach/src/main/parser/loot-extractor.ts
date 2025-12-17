/**
 * Loot Extractor - PRISM Integration
 *
 * Extracts credentials from loot files using PRISM patterns.
 * Called by IPC handler when user clicks loot badge.
 */

import { BrowserWindow } from 'electron';
import { runWrite } from '@shared/neo4j/query';
import { debug } from '../debug';
import {
  CREDENTIAL_PATTERNS,
  decryptGppPassword,
  type ParsedCredential,
} from './patterns';
import { Deduplicator } from './deduplicator';
import type { Credential, SecretType } from '@shared/types/credential';
import type { PatternType } from '@shared/types/loot';

/** Context for extraction */
export interface ExtractionContext {
  engagementId: string;
  targetId?: string;
  lootId: string;
  lootName: string;
}

/** Result of extraction */
export interface ExtractionResult {
  success: boolean;
  credential?: Credential;
  hash?: string;
  formatted?: string;
  error?: string;
}

// Singleton deduplicator instance
const deduplicator = new Deduplicator();

/**
 * Extract credential from loot file content
 */
export async function extractFromLoot(
  content: string,
  pattern: PatternType,
  context: ExtractionContext
): Promise<ExtractionResult> {
  debug.prism('Extracting from loot', { pattern, lootName: context.lootName });

  switch (pattern) {
    case 'gpp_password':
      return extractGpp(content, context);
    case 'ntlm_hash':
      return extractNtlm(content, context);
    case 'kerberos_hash':
      return extractKerberos(content, context);
    case 'ssh_key':
      return extractSshKey(content, context);
    case 'password_in_file':
      return extractPasswordInFile(content, context);
    default:
      return { success: false, error: `Unsupported pattern: ${pattern}` };
  }
}

/**
 * Extract GPP cpassword and decrypt
 */
async function extractGpp(content: string, context: ExtractionContext): Promise<ExtractionResult> {
  const cpassMatch = content.match(CREDENTIAL_PATTERNS.gpp.cpassword);
  if (!cpassMatch) {
    return { success: false, error: 'No GPP cpassword found in file' };
  }

  const encryptedPass = cpassMatch[1];
  const decrypted = decryptGppPassword(encryptedPass);

  if (!decrypted) {
    return { success: false, error: 'GPP decryption failed - invalid cpassword' };
  }

  // Extract username
  const userMatch = content.match(CREDENTIAL_PATTERNS.gpp.userName);
  let username = userMatch?.[1] || 'unknown';
  let domain: string | undefined;

  // Parse domain from username
  if (username.includes('\\')) {
    const parts = username.split('\\');
    domain = parts[0];
    username = parts[1];
  } else if (username.includes('@')) {
    const parts = username.split('@');
    username = parts[0];
    domain = parts[1];
  }

  const parsedCred: ParsedCredential = {
    username,
    domain,
    secret: decrypted,
    secretType: 'gpp',
    source: `GPP (${context.lootName})`,
  };

  // Check dedup
  if (deduplicator.isCredentialDuplicate(context.engagementId, parsedCred)) {
    return { success: false, error: 'Credential already extracted' };
  }

  // Store in Neo4j
  const credential = await storeCredential(parsedCred, context);
  if (!credential) {
    return { success: false, error: 'Failed to store credential in database' };
  }

  return { success: true, credential };
}

/**
 * Extract NTLM hashes
 */
async function extractNtlm(content: string, context: ExtractionContext): Promise<ExtractionResult> {
  // SAM/NTDS format: user:rid:lmhash:nthash:::
  const samMatches = [...content.matchAll(new RegExp(CREDENTIAL_PATTERNS.secretsdump.samNtds, 'gm'))];
  const domainMatches = [...content.matchAll(new RegExp(CREDENTIAL_PATTERNS.secretsdump.domainUser, 'gm'))];

  // Combine all matches
  const allMatches = [...samMatches, ...domainMatches];

  if (allMatches.length === 0) {
    // Try generic NTLM format
    const genericMatch = content.match(CREDENTIAL_PATTERNS.generic.ntlmHash);
    if (genericMatch) {
      const hash = genericMatch[0];
      const parsedCred: ParsedCredential = {
        username: 'unknown',
        secret: hash,
        secretType: 'ntlm',
        source: `NTLM (${context.lootName})`,
      };

      if (deduplicator.isCredentialDuplicate(context.engagementId, parsedCred)) {
        return { success: false, error: 'Hash already extracted' };
      }

      const credential = await storeCredential(parsedCred, context);
      return {
        success: !!credential,
        credential: credential || undefined,
        hash,
        formatted: hash,
        error: credential ? undefined : 'Failed to store hash',
      };
    }
    return { success: false, error: 'No NTLM hashes found in file' };
  }

  // Process first match (UI can handle multiple later)
  const match = allMatches[0];
  let username: string;
  let domain: string | undefined;
  let lm: string;
  let nt: string;

  if (match.length === 5) {
    // SAM format: [full, user, rid, lm, nt]
    [, username, , lm, nt] = match;
    const parsed = parseDomainUser(username);
    username = parsed.username;
    domain = parsed.domain;
  } else {
    // Domain format: [full, domain, user, rid, lm, nt]
    [, domain, username, , lm, nt] = match;
  }

  const hash = `${lm}:${nt}`;
  const formatted = `${username}:${match[2]}:${hash}:::`;

  const parsedCred: ParsedCredential = {
    username,
    domain,
    secret: hash,
    secretType: 'ntlm',
    source: `NTLM (${context.lootName})`,
  };

  if (deduplicator.isCredentialDuplicate(context.engagementId, parsedCred)) {
    return { success: false, error: 'Hash already extracted' };
  }

  const credential = await storeCredential(parsedCred, context);
  return {
    success: !!credential,
    credential: credential || undefined,
    hash,
    formatted,
    error: credential ? undefined : 'Failed to store hash',
  };
}

/**
 * Extract Kerberos hashes (TGS/AS-REP)
 */
async function extractKerberos(content: string, context: ExtractionContext): Promise<ExtractionResult> {
  // Try TGS hash first
  let match = content.match(CREDENTIAL_PATTERNS.kerberoast.krb5tgs);
  let hashType = 'TGS';

  if (!match) {
    // Try AS-REP hash
    match = content.match(CREDENTIAL_PATTERNS.kerberoast.krb5asrep);
    hashType = 'AS-REP';
  }

  if (!match) {
    return { success: false, error: 'No Kerberos hashes found in file' };
  }

  const fullHash = match[0];
  const username = match[2];
  const realm = match[3];

  const parsedCred: ParsedCredential = {
    username,
    domain: realm,
    secret: fullHash,
    secretType: 'kerberos',
    source: `Kerberos ${hashType} (${context.lootName})`,
  };

  if (deduplicator.isCredentialDuplicate(context.engagementId, parsedCred)) {
    return { success: false, error: 'Hash already extracted' };
  }

  const credential = await storeCredential(parsedCred, context);
  return {
    success: !!credential,
    credential: credential || undefined,
    hash: fullHash,
    formatted: fullHash,
    error: credential ? undefined : 'Failed to store hash',
  };
}

/**
 * Extract SSH private key
 */
async function extractSshKey(content: string, context: ExtractionContext): Promise<ExtractionResult> {
  const keyPattern = /-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----([\s\S]*?)-----END \1?PRIVATE KEY-----/;
  const match = content.match(keyPattern);

  if (!match) {
    return { success: false, error: 'No SSH private key found in file' };
  }

  const fullKey = match[0];
  const keyType = (match[1] || 'RSA').trim();

  const parsedCred: ParsedCredential = {
    username: 'ssh_key',
    secret: fullKey,
    secretType: 'ssh_key',
    source: `SSH Key (${context.lootName})`,
  };

  if (deduplicator.isCredentialDuplicate(context.engagementId, parsedCred)) {
    return { success: false, error: 'SSH key already extracted' };
  }

  const credential = await storeCredential(parsedCred, context);
  if (credential) {
    // Update notes with key type
    credential.notes = `Key type: ${keyType}`;
  }

  return {
    success: !!credential,
    credential: credential || undefined,
    error: credential ? undefined : 'Failed to store SSH key',
  };
}

/**
 * Extract password from config file
 */
async function extractPasswordInFile(content: string, context: ExtractionContext): Promise<ExtractionResult> {
  const match = content.match(CREDENTIAL_PATTERNS.generic.passwordInOutput);

  if (!match) {
    return { success: false, error: 'No password found in file' };
  }

  const password = match[1];

  const parsedCred: ParsedCredential = {
    username: 'unknown',
    secret: password,
    secretType: 'password',
    source: `Config (${context.lootName})`,
  };

  if (deduplicator.isCredentialDuplicate(context.engagementId, parsedCred)) {
    return { success: false, error: 'Password already extracted' };
  }

  const credential = await storeCredential(parsedCred, context);
  return {
    success: !!credential,
    credential: credential || undefined,
    error: credential ? undefined : 'Failed to store password',
  };
}

/**
 * Store credential in Neo4j and emit event
 */
async function storeCredential(
  cred: ParsedCredential,
  context: ExtractionContext
): Promise<Credential | null> {
  const id = `cred-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const createdAt = new Date().toISOString();

  try {
    const query = `
      MATCH (e:Engagement {id: $engagementId})
      CREATE (c:Credential {
        id: $id,
        username: $username,
        secret: $secret,
        secretType: $secretType,
        domain: $domain,
        source: $source,
        sourceSessionId: $sourceSessionId,
        targetId: $targetId,
        engagementId: $engagementId,
        validatedAccess: [],
        isAdmin: false,
        createdAt: $createdAt,
        notes: ''
      })
      MERGE (e)-[:HAS_CREDENTIAL]->(c)
      WITH c
      OPTIONAL MATCH (t:Target {id: $targetId})
      FOREACH (_ IN CASE WHEN t IS NOT NULL THEN [1] ELSE [] END |
        MERGE (c)-[:FOUND_ON]->(t)
      )
      OPTIONAL MATCH (l:Loot {id: $lootId})
      FOREACH (_ IN CASE WHEN l IS NOT NULL THEN [1] ELSE [] END |
        MERGE (c)-[:EXTRACTED_FROM]->(l)
      )
      RETURN c
    `;

    await runWrite(query, {
      id,
      username: cred.username,
      secret: cred.secret,
      secretType: cred.secretType,
      domain: cred.domain || '',
      source: cred.source,
      sourceSessionId: 'loot-extract',
      targetId: context.targetId || '',
      engagementId: context.engagementId,
      lootId: context.lootId,
      createdAt,
    });

    // Mark as seen in dedup cache
    deduplicator.markCredentialSeen(context.engagementId, cred, id);

    // Build credential object
    const storedCredential: Credential = {
      id,
      username: cred.username,
      secret: cred.secret,
      secretType: cred.secretType,
      domain: cred.domain,
      source: cred.source,
      sourceSessionId: 'loot-extract',
      targetId: context.targetId,
      engagementId: context.engagementId,
      validatedAccess: [],
      isAdmin: false,
      createdAt,
    };

    // Emit to renderer
    emitCredentialDiscovered(storedCredential);

    debug.prism('Loot credential extracted', {
      id,
      username: cred.username,
      secretType: cred.secretType,
      source: cred.source,
    });

    return storedCredential;
  } catch (error) {
    debug.error('Failed to store loot credential', error);
    return null;
  }
}

/**
 * Emit credential-discovered event to renderer
 */
function emitCredentialDiscovered(credential: Credential): void {
  const mainWindow = BrowserWindow.getAllWindows()[0];
  if (mainWindow) {
    const isHighValue =
      credential.secretType === 'password' ||
      credential.secretType === 'gpp' ||
      credential.isAdmin;

    mainWindow.webContents.send('credential-discovered', {
      credential,
      sessionId: 'loot-extract',
      isHighValue,
    });
  }
}

/**
 * Parse domain from username (DOMAIN\user or user@domain)
 */
function parseDomainUser(input: string): { username: string; domain?: string } {
  if (input.includes('\\')) {
    const parts = input.split('\\');
    return { domain: parts[0], username: parts[1] };
  } else if (input.includes('@')) {
    const parts = input.split('@');
    return { username: parts[0], domain: parts[1] };
  }
  return { username: input };
}
