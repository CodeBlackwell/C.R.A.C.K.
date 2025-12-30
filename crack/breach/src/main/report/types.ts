/**
 * Report Types for B.R.E.A.C.H.
 *
 * Type definitions for engagement report generation.
 */

import type { Engagement, EngagementStats } from '@shared/types/engagement';
import type { Target } from '@shared/types/target';
import type { Finding, FindingSummary } from '@shared/types/finding';
import type { Credential } from '@shared/types/credential';
import type { Loot } from '@shared/types/loot';
import type { Signal, SignalSummary } from '@shared/types/signal';
import type { TerminalSession } from '@shared/types/session';

/** Timeline event types */
export type TimelineEventType =
  | 'finding'
  | 'credential'
  | 'loot'
  | 'signal'
  | 'session_start'
  | 'session_stop';

/** Unified timeline event for chronological display */
export interface TimelineEvent {
  timestamp: string;
  type: TimelineEventType;
  title: string;
  description: string;
  severity?: string;
  targetIp?: string;
  metadata?: Record<string, unknown>;
}

/** Complete report data structure */
export interface ReportData {
  engagement: Engagement;
  stats: EngagementStats;
  targets: Target[];
  findings: Finding[];
  findingSummary: FindingSummary;
  credentials: Credential[];
  loot: Loot[];
  signals: Signal[];
  signalSummary: SignalSummary;
  sessions: TerminalSession[];
  timeline: TimelineEvent[];
  generatedAt: string;
}

/** Report generation options */
export interface ReportOptions {
  format: 'markdown' | 'json';
  outputPath?: string;
  includeTimeline?: boolean;
  includeCredentials?: boolean;
  includeSensitive?: boolean;
}

/** Result of report generation */
export interface GenerateReportResult {
  success: boolean;
  outputPath?: string;
  content?: string;
  error?: string;
  canceled?: boolean;
}
