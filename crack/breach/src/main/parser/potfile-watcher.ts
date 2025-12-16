/**
 * PRISM Potfile Watcher
 *
 * Monitors hashcat and John the Ripper potfiles for cracked hashes.
 * Correlates cracked passwords with existing credentials in Neo4j.
 * Uses Node.js native fs.watchFile for Electron compatibility.
 */

import { BrowserWindow } from 'electron';
import * as fs from 'fs';
import * as path from 'path';
import { debug } from '../debug';
import {
  CrackedHashSignal,
  generateSignalId,
} from '@shared/types/signal';
import { runWrite } from '@shared/neo4j/query';

/** Potfile configuration */
interface PotfileConfig {
  path: string;
  type: 'hashcat' | 'john';
  enabled: boolean;
}

/** Default potfile locations */
const DEFAULT_POTFILES: PotfileConfig[] = [
  // Hashcat potfile
  {
    path: path.join(process.env.HOME || '/root', '.local/share/hashcat/hashcat.potfile'),
    type: 'hashcat',
    enabled: true,
  },
  // Alternative hashcat location
  {
    path: path.join(process.env.HOME || '/root', '.hashcat/hashcat.potfile'),
    type: 'hashcat',
    enabled: true,
  },
  // John the Ripper potfile
  {
    path: path.join(process.env.HOME || '/root', '.john/john.pot'),
    type: 'john',
    enabled: true,
  },
  // Alternative john location
  {
    path: '/usr/share/john/john.pot',
    type: 'john',
    enabled: true,
  },
];

/** Tracked watcher info */
interface WatcherInfo {
  listener: (curr: fs.Stats, prev: fs.Stats) => void;
  path: string;
}

/**
 * Potfile Watcher - monitors potfiles for cracked hashes
 */
export class PotfileWatcher {
  private watchers: Map<string, WatcherInfo> = new Map();
  private seenHashes: Set<string> = new Set();
  private currentEngagementId: string | null = null;
  private potfiles: PotfileConfig[] = DEFAULT_POTFILES;
  private enabled: boolean = false;
  private filePositions: Map<string, number> = new Map();

  constructor() {
    debug.prism('PotfileWatcher initialized');
  }

  /**
   * Start watching potfiles
   */
  start(engagementId: string): void {
    this.currentEngagementId = engagementId;
    this.enabled = true;

    // Load existing hashes from potfiles
    this.loadExistingHashes();

    // Start watching each potfile
    for (const potfile of this.potfiles) {
      if (!potfile.enabled) continue;

      // Check if file exists
      if (!fs.existsSync(potfile.path)) {
        debug.prism('Potfile not found, skipping', { path: potfile.path });
        continue;
      }

      try {
        // Create listener for this potfile
        const listener = (curr: fs.Stats, prev: fs.Stats) => {
          // File was modified (size changed or mtime changed)
          if (curr.mtime > prev.mtime || curr.size > prev.size) {
            this.processNewEntries(potfile);
          }
        };

        // Use fs.watchFile for polling-based watching (more reliable for potfiles)
        fs.watchFile(potfile.path, { interval: 1000 }, listener);

        this.watchers.set(potfile.path, { listener, path: potfile.path });
        debug.prism('Started watching potfile', {
          path: potfile.path,
          type: potfile.type,
        });
      } catch (error) {
        debug.error('Failed to watch potfile', { path: potfile.path, error });
      }
    }
  }

  /**
   * Stop watching potfiles
   */
  stop(): void {
    this.enabled = false;

    for (const [watchPath, info] of this.watchers) {
      try {
        fs.unwatchFile(watchPath, info.listener);
        debug.prism('Stopped watching potfile', { path: watchPath });
      } catch (error) {
        debug.error('Failed to close watcher', { path: watchPath, error });
      }
    }

    this.watchers.clear();
    this.seenHashes.clear();
    this.filePositions.clear();
  }

  /**
   * Add custom potfile to watch
   */
  addPotfile(potfilePath: string, type: 'hashcat' | 'john'): void {
    this.potfiles.push({
      path: potfilePath,
      type,
      enabled: true,
    });

    // If already running, start watching the new file
    if (this.enabled && this.currentEngagementId) {
      this.start(this.currentEngagementId);
    }
  }

  /**
   * Load existing hashes from potfiles to avoid re-processing
   */
  private loadExistingHashes(): void {
    for (const potfile of this.potfiles) {
      if (!potfile.enabled || !fs.existsSync(potfile.path)) continue;

      try {
        const content = fs.readFileSync(potfile.path, 'utf8');
        const lines = content.split('\n');

        for (const line of lines) {
          if (!line.trim()) continue;

          const hash = this.extractHash(line, potfile.type);
          if (hash) {
            this.seenHashes.add(hash);
          }
        }

        // Track file position for incremental reading
        const stats = fs.statSync(potfile.path);
        this.filePositions.set(potfile.path, stats.size);

        debug.prism('Loaded existing hashes from potfile', {
          path: potfile.path,
          count: lines.filter(l => l.trim()).length,
        });
      } catch (error) {
        debug.error('Failed to load potfile', { path: potfile.path, error });
      }
    }
  }

  /**
   * Process new entries in a potfile
   */
  private async processNewEntries(potfile: PotfileConfig): Promise<void> {
    if (!this.enabled || !this.currentEngagementId) return;

    try {
      const stats = fs.statSync(potfile.path);
      const previousPosition = this.filePositions.get(potfile.path) || 0;

      // Read only new content
      if (stats.size <= previousPosition) {
        // File was truncated or unchanged
        this.filePositions.set(potfile.path, stats.size);
        return;
      }

      const fd = fs.openSync(potfile.path, 'r');
      const buffer = Buffer.alloc(stats.size - previousPosition);
      fs.readSync(fd, buffer, 0, buffer.length, previousPosition);
      fs.closeSync(fd);

      const newContent = buffer.toString('utf8');
      const newLines = newContent.split('\n');

      this.filePositions.set(potfile.path, stats.size);

      // Process new cracks
      for (const line of newLines) {
        if (!line.trim()) continue;

        const { hash, plaintext } = this.parsePotfileLine(line, potfile.type);
        if (!hash || !plaintext || this.seenHashes.has(hash)) continue;

        this.seenHashes.add(hash);

        // Create signal and store
        const signal: CrackedHashSignal = {
          id: generateSignalId('cracked_hash'),
          type: 'cracked_hash',
          timestamp: new Date().toISOString(),
          confidence: 'high',
          engagementId: this.currentEngagementId,
          sourceSessionId: 'potfile-watcher',
          sourceCommand: `${potfile.type} (potfile)`,
          originalHash: hash,
          plaintext,
          crackedBy: potfile.type,
        };

        await this.storeAndCorrelate(signal);
        this.emitSignal(signal);

        debug.prism('New hash cracked from potfile', {
          type: potfile.type,
          hash: hash.substring(0, 20) + '...',
          plaintext: plaintext.substring(0, 3) + '***',
        });
      }
    } catch (error) {
      debug.error('Failed to process potfile updates', {
        path: potfile.path,
        error,
      });
    }
  }

  /**
   * Extract hash from potfile line
   */
  private extractHash(line: string, type: 'hashcat' | 'john'): string | null {
    const trimmed = line.trim();
    if (!trimmed) return null;

    if (type === 'hashcat') {
      // Hashcat format: hash:plaintext
      // The hash part can contain colons (for some hash types)
      // Use rsplit to split from the right
      const lastColon = trimmed.lastIndexOf(':');
      if (lastColon > 0) {
        return trimmed.substring(0, lastColon);
      }
    } else if (type === 'john') {
      // John format: user:password or $hash$:password
      // Similar logic - password is after last colon
      const lastColon = trimmed.lastIndexOf(':');
      if (lastColon > 0) {
        return trimmed.substring(0, lastColon);
      }
    }

    return null;
  }

  /**
   * Parse potfile line into hash and plaintext
   */
  private parsePotfileLine(
    line: string,
    type: 'hashcat' | 'john'
  ): { hash: string | null; plaintext: string | null } {
    const trimmed = line.trim();
    if (!trimmed) return { hash: null, plaintext: null };

    // Both hashcat and john use similar format: hash:plaintext
    // But hash can contain colons, so split from right
    const lastColon = trimmed.lastIndexOf(':');
    if (lastColon > 0) {
      const hash = trimmed.substring(0, lastColon);
      const plaintext = trimmed.substring(lastColon + 1);

      // Validate: plaintext shouldn't be empty and shouldn't look like a hash
      if (plaintext && !this.looksLikeHash(plaintext)) {
        return { hash, plaintext };
      }
    }

    return { hash: null, plaintext: null };
  }

  /**
   * Check if a string looks like a hash (to avoid false positives)
   */
  private looksLikeHash(value: string): boolean {
    // Common hash patterns
    const hashPatterns = [
      /^[a-fA-F0-9]{32}$/,    // MD5, NTLM
      /^[a-fA-F0-9]{40}$/,    // SHA1
      /^[a-fA-F0-9]{64}$/,    // SHA256
      /^\$[a-z0-9]+\$/i,      // Mode prefix
    ];

    return hashPatterns.some(p => p.test(value));
  }

  /**
   * Store signal and correlate with existing credentials
   */
  private async storeAndCorrelate(signal: CrackedHashSignal): Promise<void> {
    // Store the signal
    const storeQuery = `
      MATCH (e:Engagement {id: $engagementId})
      CREATE (s:CrackedHash:Signal {
        id: $id,
        type: $type,
        timestamp: datetime($timestamp),
        confidence: $confidence,
        engagementId: $engagementId,
        sourceSessionId: $sourceSessionId,
        sourceCommand: $sourceCommand,
        originalHash: $originalHash,
        plaintext: $plaintext,
        crackedBy: $crackedBy
      })
      MERGE (e)-[:HAS_SIGNAL]->(s)
      RETURN s.id
    `;

    try {
      await runWrite(storeQuery, {
        id: signal.id,
        type: signal.type,
        timestamp: signal.timestamp,
        confidence: signal.confidence,
        engagementId: signal.engagementId,
        sourceSessionId: signal.sourceSessionId,
        sourceCommand: signal.sourceCommand || '',
        originalHash: signal.originalHash,
        plaintext: signal.plaintext,
        crackedBy: signal.crackedBy || 'unknown',
      });
    } catch (error) {
      debug.error('Failed to store cracked hash signal', error);
    }

    // Correlate with existing credentials
    // Try multiple correlation strategies
    await this.correlateByExactHash(signal);
    await this.correlateByPartialHash(signal);
  }

  /**
   * Correlate by exact hash match
   */
  private async correlateByExactHash(signal: CrackedHashSignal): Promise<void> {
    const query = `
      MATCH (c:Credential)
      WHERE c.engagementId = $engagementId
        AND c.secret = $hash
      SET c.crackedPlaintext = $plaintext,
          c.isCracked = true,
          c.crackedAt = datetime($timestamp),
          c.crackedBy = $crackedBy
      RETURN c.id, c.username
    `;

    try {
      const result = await runWrite(query, {
        engagementId: signal.engagementId,
        hash: signal.originalHash,
        plaintext: signal.plaintext,
        timestamp: signal.timestamp,
        crackedBy: signal.crackedBy || 'potfile',
      });

      if (result && result.length > 0) {
        debug.prism('Correlated cracked hash (exact match)', {
          hash: signal.originalHash.substring(0, 20) + '...',
          credentials: result.length,
        });
      }
    } catch (error) {
      debug.error('Failed to correlate by exact hash', error);
    }
  }

  /**
   * Correlate by partial hash match (for NTLM LM:NT format)
   */
  private async correlateByPartialHash(signal: CrackedHashSignal): Promise<void> {
    // For NTLM hashes stored as lm:nt, try matching the NT part
    const hashParts = signal.originalHash.split(':');
    if (hashParts.length < 2) return;

    // Try the second part (NT hash in LM:NT format)
    const ntHash = hashParts[hashParts.length - 1];
    if (ntHash.length !== 32) return; // NTLM hash is 32 chars

    const query = `
      MATCH (c:Credential)
      WHERE c.engagementId = $engagementId
        AND c.secret CONTAINS $ntHash
        AND c.isCracked IS NULL
      SET c.crackedPlaintext = $plaintext,
          c.isCracked = true,
          c.crackedAt = datetime($timestamp),
          c.crackedBy = $crackedBy
      RETURN c.id, c.username
    `;

    try {
      const result = await runWrite(query, {
        engagementId: signal.engagementId,
        ntHash,
        plaintext: signal.plaintext,
        timestamp: signal.timestamp,
        crackedBy: signal.crackedBy || 'potfile',
      });

      if (result && result.length > 0) {
        debug.prism('Correlated cracked hash (partial match)', {
          ntHash: ntHash.substring(0, 10) + '...',
          credentials: result.length,
        });
      }
    } catch (error) {
      debug.error('Failed to correlate by partial hash', error);
    }
  }

  /**
   * Emit signal event to renderer
   */
  private emitSignal(signal: CrackedHashSignal): void {
    const mainWindow = BrowserWindow.getAllWindows()[0];
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('hash-cracked', {
        signal,
        sessionId: 'potfile-watcher',
        isHighValue: true, // All cracked hashes are high value
      });
    }
  }

  /**
   * Handle engagement change
   */
  onEngagementChange(engagementId: string | null): void {
    if (engagementId) {
      this.stop();
      this.start(engagementId);
    } else {
      this.stop();
    }
  }

  /**
   * Get watcher statistics
   */
  getStats(): {
    enabled: boolean;
    watchedFiles: string[];
    seenHashesCount: number;
  } {
    return {
      enabled: this.enabled,
      watchedFiles: Array.from(this.watchers.keys()),
      seenHashesCount: this.seenHashes.size,
    };
  }
}

// Singleton instance
let potfileWatcherInstance: PotfileWatcher | null = null;

/**
 * Get or create potfile watcher instance
 */
export function getPotfileWatcher(): PotfileWatcher {
  if (!potfileWatcherInstance) {
    potfileWatcherInstance = new PotfileWatcher();
  }
  return potfileWatcherInstance;
}
