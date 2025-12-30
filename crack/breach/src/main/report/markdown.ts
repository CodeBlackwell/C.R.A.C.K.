/**
 * Markdown Report Template
 *
 * Renders engagement report data as formatted markdown.
 */

import type { ReportData, ReportOptions } from './types';

/**
 * Render report data as markdown
 */
export function renderMarkdown(data: ReportData, options: ReportOptions): string {
  const lines: string[] = [];

  // Header
  lines.push(`# Engagement Report: ${data.engagement?.name || 'Unknown'}`);
  lines.push('');
  lines.push(`**Generated:** ${new Date(data.generatedAt).toLocaleString()}`);
  lines.push(`**Status:** ${data.engagement?.status || 'unknown'}`);
  if (data.engagement?.start_date) {
    lines.push(`**Period:** ${data.engagement.start_date} - ${data.engagement.end_date || 'ongoing'}`);
  }
  if (data.engagement?.scope_text) {
    lines.push(`**Scope:** ${data.engagement.scope_text}`);
  }
  lines.push('');

  // Executive Summary
  lines.push('## Executive Summary');
  lines.push('');
  lines.push(`- **Targets:** ${data.stats.target_count}`);
  lines.push(`- **Services:** ${data.stats.service_count}`);
  lines.push(`- **Findings:** ${data.stats.finding_count}`);
  lines.push(`- **Credentials:** ${data.stats.credential_count}`);
  lines.push(`- **Loot:** ${data.stats.loot_count}`);
  lines.push('');

  // Finding Severity Distribution
  if (data.findingSummary.total > 0) {
    lines.push('### Finding Severity Distribution');
    lines.push('');
    lines.push('| Severity | Count |');
    lines.push('|----------|-------|');
    lines.push(`| Critical | ${data.findingSummary.critical} |`);
    lines.push(`| High | ${data.findingSummary.high} |`);
    lines.push(`| Medium | ${data.findingSummary.medium} |`);
    lines.push(`| Low | ${data.findingSummary.low} |`);
    lines.push(`| Info | ${data.findingSummary.info} |`);
    lines.push('');
  }

  // Targets Section
  if (data.targets.length > 0) {
    lines.push('## Targets');
    lines.push('');
    for (const target of data.targets) {
      lines.push(`### ${target.ip_address}${target.hostname ? ` (${target.hostname})` : ''}`);
      lines.push('');
      lines.push(`- **Status:** ${target.status}`);
      if (target.os_guess) lines.push(`- **OS:** ${target.os_guess}`);
      if (target.notes) lines.push(`- **Notes:** ${target.notes}`);
      lines.push('');
    }
  }

  // Findings Section (grouped by severity)
  if (data.findings.length > 0) {
    lines.push('## Findings');
    lines.push('');
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const;
    for (const sev of severityOrder) {
      const sevFindings = data.findings.filter(f => f.severity === sev);
      if (sevFindings.length === 0) continue;

      lines.push(`### ${sev.toUpperCase()} (${sevFindings.length})`);
      lines.push('');
      for (const f of sevFindings) {
        lines.push(`#### ${f.title}`);
        lines.push('');
        if (f.cveId) lines.push(`**CVE:** ${f.cveId}`);
        if (f.cvssScore) lines.push(`**CVSS:** ${f.cvssScore}`);
        lines.push(`**Category:** ${f.category}`);
        lines.push(`**Status:** ${f.status}`);
        if ((f as any).targetIps?.length) {
          lines.push(`**Affected Targets:** ${(f as any).targetIps.join(', ')}`);
        }
        if (f.description) {
          lines.push('');
          lines.push(f.description);
        }
        if (f.evidence) {
          lines.push('');
          lines.push('**Evidence:**');
          lines.push('```');
          lines.push(f.evidence.slice(0, 500));
          if (f.evidence.length > 500) lines.push('... (truncated)');
          lines.push('```');
        }
        if (f.remediation) {
          lines.push('');
          lines.push(`**Remediation:** ${f.remediation}`);
        }
        lines.push('');
      }
    }
  }

  // Credentials Section (optional)
  if (options.includeCredentials !== false && data.credentials.length > 0) {
    lines.push('## Credentials');
    lines.push('');
    lines.push('| Username | Type | Domain | Source | Target |');
    lines.push('|----------|------|--------|--------|--------|');
    for (const c of data.credentials) {
      const secret = options.includeSensitive !== false
        ? (c.secret.length > 20 ? c.secret.slice(0, 20) + '...' : c.secret)
        : '[REDACTED]';
      lines.push(`| ${c.username} | ${c.secretType} | ${c.domain || '-'} | ${c.source} | ${(c as any).targetIp || '-'} |`);
    }
    lines.push('');
  }

  // Loot Section
  if (data.loot.length > 0) {
    lines.push('## Loot');
    lines.push('');
    for (const l of data.loot) {
      lines.push(`### ${l.name}`);
      lines.push('');
      lines.push(`- **Type:** ${l.type}`);
      lines.push(`- **Path:** ${l.path}`);
      if ((l as any).targetIp) lines.push(`- **Target:** ${(l as any).targetIp}`);
      if (l.detectedPatterns?.length > 0) {
        lines.push(`- **Patterns:** ${l.detectedPatterns.join(', ')}`);
      }
      if (l.contentPreview) {
        lines.push('');
        lines.push('**Preview:**');
        lines.push('```');
        lines.push(l.contentPreview.slice(0, 300));
        if (l.contentPreview.length > 300) lines.push('... (truncated)');
        lines.push('```');
      }
      if (l.notes) {
        lines.push('');
        lines.push(`**Notes:** ${l.notes}`);
      }
      lines.push('');
    }
  }

  // Signal Summary
  lines.push('## Reconnaissance Summary');
  lines.push('');
  lines.push(`- **Hosts Reachable:** ${data.signalSummary.hosts.reachable}`);
  lines.push(`- **Hosts Unreachable:** ${data.signalSummary.hosts.unreachable}`);
  lines.push(`- **Open Ports:** ${data.signalSummary.ports.open}`);
  lines.push(`- **Closed Ports:** ${data.signalSummary.ports.closed}`);
  lines.push(`- **Filtered Ports:** ${data.signalSummary.ports.filtered}`);
  lines.push(`- **DNS Records:** ${data.signalSummary.dns}`);
  lines.push(`- **Users Enumerated:** ${data.signalSummary.users}`);
  lines.push(`- **Hashes Cracked:** ${data.signalSummary.crackedHashes}`);
  lines.push('');

  // Timeline Appendix (optional)
  if (options.includeTimeline !== false && data.timeline.length > 0) {
    lines.push('## Appendix: Chronological Timeline');
    lines.push('');
    lines.push('| Timestamp | Type | Event | Details |');
    lines.push('|-----------|------|-------|---------|');

    // Limit to 100 events
    const timelineEvents = data.timeline.slice(0, 100);
    for (const event of timelineEvents) {
      const ts = new Date(event.timestamp).toLocaleString();
      const type = event.type.replace(/_/g, ' ');
      const title = event.title.replace(/\|/g, '\\|');
      const desc = event.description.slice(0, 50).replace(/\|/g, '\\|');
      lines.push(`| ${ts} | ${type} | ${title} | ${desc}${event.description.length > 50 ? '...' : ''} |`);
    }

    if (data.timeline.length > 100) {
      lines.push('');
      lines.push(`*... and ${data.timeline.length - 100} more events*`);
    }
    lines.push('');
  }

  // Footer
  lines.push('---');
  lines.push('*Report generated by B.R.E.A.C.H. - Box Reconnaissance, Exploitation & Attack Command Hub*');

  return lines.join('\n');
}
