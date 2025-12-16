/**
 * Deduplication Cache for PRISM Parser
 *
 * Prevents duplicate credentials and findings from being stored.
 * Uses content-based hashing for dedup keys.
 */

import type { ParsedCredential, ParsedFinding } from './patterns';
import crypto from 'crypto';

/** Cache entry with timestamp */
interface CacheEntry {
  id: string;
  seenAt: number;
}

/**
 * Deduplication cache for parsed items
 */
export class Deduplicator {
  private credentialCache: Map<string, CacheEntry> = new Map();
  private findingCache: Map<string, CacheEntry> = new Map();
  private currentEngagementId: string | null = null;

  /**
   * Generate dedup key for credential
   * Format: engagementId:secretType:username:domain:contentHash
   */
  private generateCredentialKey(engagementId: string, cred: ParsedCredential): string {
    // Hash first 32 chars of secret for privacy
    const contentHash = crypto
      .createHash('sha256')
      .update(cred.secret.substring(0, 32))
      .digest('hex')
      .substring(0, 16);

    return [
      engagementId,
      cred.secretType,
      cred.username.toLowerCase(),
      (cred.domain || '').toLowerCase(),
      contentHash,
    ].join(':');
  }

  /**
   * Generate dedup key for finding
   * Format: engagementId:category:title:evidenceHash
   */
  private generateFindingKey(engagementId: string, finding: ParsedFinding): string {
    const evidenceHash = crypto
      .createHash('sha256')
      .update(finding.evidence.substring(0, 100))
      .digest('hex')
      .substring(0, 16);

    return [
      engagementId,
      finding.category,
      finding.title,
      evidenceHash,
    ].join(':');
  }

  /**
   * Check if credential is duplicate
   */
  isCredentialDuplicate(engagementId: string, cred: ParsedCredential): boolean {
    const key = this.generateCredentialKey(engagementId, cred);
    return this.credentialCache.has(key);
  }

  /**
   * Check if finding is duplicate
   */
  isFindingDuplicate(engagementId: string, finding: ParsedFinding): boolean {
    const key = this.generateFindingKey(engagementId, finding);
    return this.findingCache.has(key);
  }

  /**
   * Mark credential as seen
   */
  markCredentialSeen(engagementId: string, cred: ParsedCredential, storedId: string): void {
    const key = this.generateCredentialKey(engagementId, cred);
    this.credentialCache.set(key, {
      id: storedId,
      seenAt: Date.now(),
    });
  }

  /**
   * Mark finding as seen
   */
  markFindingSeen(engagementId: string, finding: ParsedFinding, storedId: string): void {
    const key = this.generateFindingKey(engagementId, finding);
    this.findingCache.set(key, {
      id: storedId,
      seenAt: Date.now(),
    });
  }

  /**
   * Clear cache for engagement (call on engagement switch)
   */
  clearEngagement(engagementId: string): void {
    // Clear credentials for this engagement
    for (const [key] of this.credentialCache) {
      if (key.startsWith(`${engagementId}:`)) {
        this.credentialCache.delete(key);
      }
    }

    // Clear findings for this engagement
    for (const [key] of this.findingCache) {
      if (key.startsWith(`${engagementId}:`)) {
        this.findingCache.delete(key);
      }
    }
  }

  /**
   * Set current engagement (clears cache if changed)
   */
  setEngagement(engagementId: string | null): void {
    if (this.currentEngagementId !== engagementId) {
      if (this.currentEngagementId) {
        this.clearEngagement(this.currentEngagementId);
      }
      this.currentEngagementId = engagementId;
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): { credentials: number; findings: number } {
    return {
      credentials: this.credentialCache.size,
      findings: this.findingCache.size,
    };
  }

  /**
   * Clear all caches
   */
  clearAll(): void {
    this.credentialCache.clear();
    this.findingCache.clear();
    this.currentEngagementId = null;
  }
}
