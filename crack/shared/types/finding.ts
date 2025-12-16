/**
 * B.R.E.A.C.H. Finding Types
 *
 * Represents vulnerabilities and issues discovered during engagements.
 * Used by PRISM parser for auto-detected findings (SQLi, LFI, RCE indicators).
 */

/** Finding severity levels (CVSS-aligned) */
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Finding lifecycle status */
export type FindingStatus = 'open' | 'confirmed' | 'exploited' | 'reported' | 'remediated';

/** Finding category for grouping */
export type FindingCategory =
  | 'sqli'       // SQL Injection indicators
  | 'lfi'        // Local File Inclusion
  | 'rfi'        // Remote File Inclusion
  | 'rce'        // Remote Code Execution
  | 'privesc'    // Privilege Escalation indicators
  | 'credential' // Credential-related (duplicate creds, weak passwords)
  | 'config'     // Misconfigurations (SMB signing, LDAP, etc.)
  | 'vuln'       // Known vulnerabilities (MS17-010, BlueKeep, etc.)
  | 'recon'      // Reconnaissance findings (DC detected, domain name)
  | 'info'       // Information disclosure
  | 'other';     // Uncategorized

/** Vulnerability or issue discovered during engagement */
export interface Finding {
  id: string;
  title: string;
  severity: FindingSeverity;
  category: FindingCategory;
  description: string;
  evidence: string;                 // Raw output that triggered detection
  status: FindingStatus;
  cveId?: string;
  cvssScore?: string;
  impact?: string;
  remediation?: string;
  targetId?: string;                // Affected target
  sourceSessionId?: string;         // Session that discovered it
  engagementId: string;
  createdAt: string;
}

/** Input for creating a new finding */
export interface CreateFindingData {
  title: string;
  severity: FindingSeverity;
  category: FindingCategory;
  description: string;
  evidence: string;
  targetId?: string;
  sourceSessionId?: string;
  cveId?: string;
  cvssScore?: string;
}

/** Summary of findings by severity */
export interface FindingSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

/**
 * Generate finding ID
 */
export function generateFindingId(): string {
  return `finding-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Get severity color for UI display
 */
export function getSeverityColor(severity: FindingSeverity): string {
  switch (severity) {
    case 'critical': return '#dc2626'; // Red 600
    case 'high': return '#ea580c';     // Orange 600
    case 'medium': return '#ca8a04';   // Yellow 600
    case 'low': return '#2563eb';      // Blue 600
    case 'info': return '#6b7280';     // Gray 500
    default: return '#6b7280';
  }
}

/**
 * Get severity badge styles
 */
export function getSeverityBadge(severity: FindingSeverity): { bg: string; text: string } {
  switch (severity) {
    case 'critical': return { bg: '#fef2f2', text: '#dc2626' };
    case 'high': return { bg: '#fff7ed', text: '#ea580c' };
    case 'medium': return { bg: '#fefce8', text: '#ca8a04' };
    case 'low': return { bg: '#eff6ff', text: '#2563eb' };
    case 'info': return { bg: '#f9fafb', text: '#6b7280' };
    default: return { bg: '#f9fafb', text: '#6b7280' };
  }
}
