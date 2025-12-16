/**
 * Recommendation Engine Types for B.R.E.A.C.H.
 *
 * Phase-aware command recommendations that guide users through
 * a logical attack workflow based on current engagement state.
 */

import type { ServiceInfo } from './actions-panel';
import type { Credential } from './credential';
import type { Loot, PatternType } from './loot';
import type { TerminalSession } from './session';

/** Attack phases in penetration testing methodology */
export type AttackPhase =
  | 'initial_recon'
  | 'service_enum'
  | 'credential_usage'
  | 'loot_processing'
  | 'post_exploitation';

/** Human-readable phase names */
export const PHASE_LABELS: Record<AttackPhase, string> = {
  initial_recon: 'Initial Recon',
  service_enum: 'Service Enumeration',
  credential_usage: 'Credential Usage',
  loot_processing: 'Loot Processing',
  post_exploitation: 'Post Exploitation',
};

/** A single recommended action */
export interface RecommendedAction {
  id: string;
  phase: AttackPhase;
  score: number; // 0-100, higher = more relevant
  label: string;
  command: string;
  rationale: string; // Why this is recommended NOW

  // Prerequisites (for filtering)
  requiresPort?: number; // Port must be open
  requiresPorts?: number[]; // Any of these ports must be open
  requiresCredential?: boolean; // Requires at least one credential
  requiresCredentialType?: 'password' | 'ntlm' | 'any'; // Specific credential type
  requiresLootPattern?: PatternType; // Requires loot with this pattern
  requiresShell?: boolean; // Requires an active shell session

  // Context references
  credentialId?: string; // If command uses specific credential
  lootId?: string; // If command uses specific loot item
  categoryId?: string; // Link to ACTION_CATEGORIES
  toolId?: string; // Link to ActionTool
  variantId?: string; // Link to ActionVariant

  // Next steps (follow-up suggestions after execution)
  nextSteps?: string[]; // IDs of recommended follow-up actions
}

/** Result from the recommendation engine */
export interface RecommendationResult {
  phase: AttackPhase;
  phaseReason: string; // Why we're in this phase
  recommendations: RecommendedAction[];
}

/** Context passed to the recommendation engine */
export interface RecommendationContext {
  services: ServiceInfo[];
  credentials: Credential[];
  loot: Loot[];
  sessions: TerminalSession[];
  targetIp: string;
  domain?: string;
}

/** Actionable loot patterns that trigger loot_processing phase */
export const ACTIONABLE_LOOT_PATTERNS: PatternType[] = [
  'gpp_password',
  'ntlm_hash',
  'kerberos_hash',
  'ssh_key',
  'password_in_file',
];

/** Check if loot has actionable patterns */
export function hasActionableLoot(loot: Loot[]): boolean {
  return loot.some((l) =>
    l.detectedPatterns.some((p) => ACTIONABLE_LOOT_PATTERNS.includes(p))
  );
}

/** Check if there's an active shell session */
export function hasActiveShell(sessions: TerminalSession[]): boolean {
  return sessions.some(
    (s) => s.type === 'shell' && (s.status === 'running' || s.status === 'backgrounded')
  );
}
