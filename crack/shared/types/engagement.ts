/**
 * B.R.E.A.C.H. Engagement Types
 *
 * Shared type definitions for engagement tracking.
 * Simplified model: Engagement → Target → Service (no Client layer)
 */

/** Engagement status values */
export type EngagementStatus = 'active' | 'paused' | 'completed' | 'archived';

/** Penetration test engagement */
export interface Engagement {
  id: string;
  name: string;
  status: EngagementStatus;
  start_date?: string;
  end_date?: string;
  scope_type?: string;
  scope_text?: string;
  notes?: string;
  created_at: string;
}

/** Input for creating a new engagement */
export interface CreateEngagementData {
  name: string;
  scope_type?: string;
  scope_text?: string;
  notes?: string;
}

/** Engagement statistics */
export interface EngagementStats {
  target_count: number;
  service_count: number;
  finding_count: number;
  credential_count: number;
  loot_count: number;
}
