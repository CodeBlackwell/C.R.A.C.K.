/**
 * PRISM Credential Parser for Terminal Output
 *
 * Real-time parsing of terminal output for credentials and findings.
 * Uses line buffering with debounced batch parsing.
 */

import { BrowserWindow, ipcMain } from 'electron';
import { debug } from '../debug';
import { Deduplicator } from './deduplicator';
import { matchCredentials, matchFindings, ParsedCredential, ParsedFinding } from './patterns';
import type { Credential } from '@shared/types/credential';
import type { Finding, CreateFindingData } from '@shared/types/finding';
import { generateFindingId } from '@shared/types/finding';
import { runWrite } from '@shared/neo4j/query';

/** Session context for parsing */
interface SessionContext {
  engagementId?: string;
  targetId?: string;
}

/** Per-session line buffer */
interface SessionBuffer {
  lines: string[];
  lastActivity: number;
  parseTimeout: NodeJS.Timeout | null;
}

/** Parser configuration */
const CONFIG = {
  maxBufferLines: 50,       // Max lines to buffer per session
  parseDebounceMs: 200,     // Wait after last output before parsing
  minLinesForParse: 5,      // Minimum lines before parsing (unless debounce)
};

/**
 * Credential Parser - orchestrates output parsing
 */
export class CredentialParser {
  private deduplicator: Deduplicator;
  private sessionBuffers: Map<string, SessionBuffer> = new Map();
  private enabled: boolean = true;

  constructor() {
    this.deduplicator = new Deduplicator();
    debug.prism('CredentialParser initialized');
  }

  /**
   * Enable/disable parsing
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
    debug.prism('CredentialParser enabled:', { enabled });
  }

  /**
   * Ingest terminal output for parsing
   * Called from PTY manager's handleOutput
   */
  ingestOutput(sessionId: string, data: string, context: SessionContext): void {
    if (!this.enabled || !context.engagementId) {
      return;
    }

    // Get or create buffer for session
    let buffer = this.sessionBuffers.get(sessionId);
    if (!buffer) {
      buffer = {
        lines: [],
        lastActivity: Date.now(),
        parseTimeout: null,
      };
      this.sessionBuffers.set(sessionId, buffer);
    }

    // Add lines to buffer
    const newLines = data.split('\n');
    buffer.lines.push(...newLines);
    buffer.lastActivity = Date.now();

    // Trim buffer if too large
    if (buffer.lines.length > CONFIG.maxBufferLines) {
      buffer.lines = buffer.lines.slice(-CONFIG.maxBufferLines);
    }

    // Clear existing timeout
    if (buffer.parseTimeout) {
      clearTimeout(buffer.parseTimeout);
    }

    // Schedule parsing after debounce
    buffer.parseTimeout = setTimeout(() => {
      this.parseBuffer(sessionId, context);
    }, CONFIG.parseDebounceMs);
  }

  /**
   * Parse buffered output for credentials and findings
   */
  private async parseBuffer(sessionId: string, context: SessionContext): Promise<void> {
    const buffer = this.sessionBuffers.get(sessionId);
    if (!buffer || buffer.lines.length < CONFIG.minLinesForParse) {
      return;
    }

    const text = buffer.lines.join('\n');
    buffer.lines = []; // Clear buffer after parsing
    buffer.parseTimeout = null;

    if (!context.engagementId) {
      return;
    }

    try {
      // Match credentials
      const credentials = matchCredentials(text);
      for (const cred of credentials) {
        if (!this.deduplicator.isCredentialDuplicate(context.engagementId, cred)) {
          await this.storeCredential(cred, sessionId, context);
        }
      }

      // Match findings
      const findings = matchFindings(text);
      for (const finding of findings) {
        if (!this.deduplicator.isFindingDuplicate(context.engagementId, finding)) {
          await this.storeFinding(finding, sessionId, context);
        }
      }
    } catch (error) {
      debug.error('Error parsing buffer', { sessionId, error });
    }
  }

  /**
   * Store discovered credential in Neo4j and emit event
   */
  private async storeCredential(
    cred: ParsedCredential,
    sessionId: string,
    context: SessionContext
  ): Promise<void> {
    if (!context.engagementId) return;

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
        RETURN c
      `;

      await runWrite(query, {
        id,
        username: cred.username,
        secret: cred.secret,
        secretType: cred.secretType,
        domain: cred.domain || '',
        source: cred.source,
        sourceSessionId: sessionId,
        targetId: context.targetId || '',
        engagementId: context.engagementId,
        createdAt,
      });

      // Mark as seen in dedup cache
      this.deduplicator.markCredentialSeen(context.engagementId, cred, id);

      // Build credential object for event
      const storedCredential: Credential = {
        id,
        username: cred.username,
        secret: cred.secret,
        secretType: cred.secretType,
        domain: cred.domain,
        source: cred.source,
        sourceSessionId: sessionId,
        targetId: context.targetId,
        engagementId: context.engagementId,
        validatedAccess: [],
        isAdmin: false,
        createdAt,
      };

      // Emit to renderer
      this.emitCredentialDiscovered(storedCredential, sessionId);

      debug.prism('Credential discovered', {
        username: cred.username,
        secretType: cred.secretType,
        source: cred.source,
      });
    } catch (error) {
      debug.error('Failed to store credential', error);
    }
  }

  /**
   * Store discovered finding in Neo4j and emit event
   */
  private async storeFinding(
    finding: ParsedFinding,
    sessionId: string,
    context: SessionContext
  ): Promise<void> {
    if (!context.engagementId) return;

    const id = generateFindingId();
    const createdAt = new Date().toISOString();

    try {
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
          cveId: '',
          cvssScore: '',
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
        RETURN f
      `;

      await runWrite(query, {
        id,
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
        description: finding.description,
        evidence: finding.evidence,
        targetId: context.targetId || '',
        sourceSessionId: sessionId,
        engagementId: context.engagementId,
        createdAt,
      });

      // Mark as seen in dedup cache
      this.deduplicator.markFindingSeen(context.engagementId, finding, id);

      // Build finding object for event
      const storedFinding: Finding = {
        id,
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
        description: finding.description,
        evidence: finding.evidence,
        status: 'open',
        targetId: context.targetId,
        sourceSessionId: sessionId,
        engagementId: context.engagementId,
        createdAt,
      };

      // Emit to renderer
      this.emitFindingDiscovered(storedFinding, sessionId);

      debug.prism('Finding discovered', {
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
      });
    } catch (error) {
      debug.error('Failed to store finding', error);
    }
  }

  /**
   * Emit credential-discovered event to renderer
   */
  private emitCredentialDiscovered(credential: Credential, sessionId: string): void {
    const mainWindow = BrowserWindow.getAllWindows()[0];
    if (mainWindow) {
      const isHighValue =
        credential.secretType === 'password' ||
        credential.secretType === 'gpp' ||
        credential.isAdmin;

      mainWindow.webContents.send('credential-discovered', {
        credential,
        sessionId,
        isHighValue,
      });
    }
  }

  /**
   * Emit finding-discovered event to renderer
   */
  private emitFindingDiscovered(finding: Finding, sessionId: string): void {
    const mainWindow = BrowserWindow.getAllWindows()[0];
    if (mainWindow) {
      const isHighValue = finding.severity === 'critical' || finding.severity === 'high';

      mainWindow.webContents.send('finding-discovered', {
        finding,
        sessionId,
        isHighValue,
      });
    }
  }

  /**
   * Flush buffer for session (on session exit)
   */
  async flushSession(sessionId: string, context: SessionContext): Promise<void> {
    const buffer = this.sessionBuffers.get(sessionId);
    if (buffer && buffer.lines.length > 0) {
      if (buffer.parseTimeout) {
        clearTimeout(buffer.parseTimeout);
      }
      await this.parseBuffer(sessionId, context);
    }
    this.sessionBuffers.delete(sessionId);
  }

  /**
   * Clear session buffer without parsing
   */
  clearSession(sessionId: string): void {
    const buffer = this.sessionBuffers.get(sessionId);
    if (buffer?.parseTimeout) {
      clearTimeout(buffer.parseTimeout);
    }
    this.sessionBuffers.delete(sessionId);
  }

  /**
   * Handle engagement change (clear dedup cache)
   */
  onEngagementChange(engagementId: string | null): void {
    this.deduplicator.setEngagement(engagementId);
  }

  /**
   * Get parser statistics
   */
  getStats(): { enabled: boolean; sessions: number; dedup: { credentials: number; findings: number } } {
    return {
      enabled: this.enabled,
      sessions: this.sessionBuffers.size,
      dedup: this.deduplicator.getStats(),
    };
  }
}

// Singleton instance
let parserInstance: CredentialParser | null = null;

/**
 * Get or create parser instance
 */
export function getCredentialParser(): CredentialParser {
  if (!parserInstance) {
    parserInstance = new CredentialParser();
  }
  return parserInstance;
}
