/**
 * B.R.E.A.C.H. Target Types
 *
 * Shared type definitions for target management.
 */

/** Target status values */
export type TargetStatus = 'unknown' | 'up' | 'down' | 'scanning' | 'compromised';

/** Target machine in an engagement */
export interface Target {
  id: string;
  ip_address: string;
  hostname?: string;
  os_guess?: string;
  status: TargetStatus;
  notes?: string;
  created_at: string;
}

/** Input for creating a new target */
export interface CreateTargetData {
  ip_address: string;
  hostname?: string;
  notes?: string;
}

/** Target with service count (for list views) */
export interface TargetWithServiceCount extends Target {
  serviceCount: number;
}
