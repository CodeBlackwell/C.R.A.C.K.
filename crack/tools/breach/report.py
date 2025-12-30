"""
B.R.E.A.C.H. Report Generator - Python CLI

Generates engagement reports from Neo4j data.
Mirrors the TypeScript implementation for consistency.
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

from crack.db.config import Neo4jConfig
from crack.core.themes import Colors
from crack.tools.engagement.storage import get_active_engagement_id


class ReportGenerator:
    """Generate engagement reports from Neo4j data."""

    def __init__(self):
        if not NEO4J_AVAILABLE:
            raise RuntimeError("neo4j package not installed. Run: pip install neo4j")

        config = Neo4jConfig.from_env()
        self.driver = GraphDatabase.driver(
            config.uri,
            auth=(config.user, config.password),
        )
        self.database = config.database

    def _query(self, query: str, **params) -> List[Dict]:
        """Execute read query."""
        with self.driver.session(database=self.database) as session:
            result = session.run(query, **params)
            return [dict(r) for r in result]

    def _convert_neo4j_types(self, data: Any) -> Any:
        """Convert Neo4j types to Python types."""
        if data is None:
            return None
        if hasattr(data, 'toNumber'):
            return data.toNumber()
        if hasattr(data, 'items'):
            return {k: self._convert_neo4j_types(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self._convert_neo4j_types(item) for item in data]
        return data

    def get_engagement(self, engagement_id: str) -> Optional[Dict]:
        """Get engagement by ID."""
        results = self._query(
            "MATCH (e:Engagement {id: $id}) RETURN e",
            id=engagement_id
        )
        if results:
            return self._convert_neo4j_types(dict(results[0]['e']))
        return None

    def get_stats(self, engagement_id: str) -> Dict:
        """Get engagement statistics."""
        results = self._query("""
            MATCH (e:Engagement {id: $id})
            OPTIONAL MATCH (e)-[:TARGETS]->(t:Target)
            OPTIONAL MATCH (t)-[:HAS_SERVICE]->(s:Service)
            OPTIONAL MATCH (e)-[:HAS_FINDING]->(f:Finding)
            OPTIONAL MATCH (e)-[:HAS_CREDENTIAL]->(c:Credential)
            OPTIONAL MATCH (e)-[:HAS_LOOT]->(l:Loot)
            RETURN
              count(DISTINCT t) as target_count,
              count(DISTINCT s) as service_count,
              count(DISTINCT f) as finding_count,
              count(DISTINCT c) as credential_count,
              count(DISTINCT l) as loot_count
        """, id=engagement_id)

        if results:
            r = results[0]
            return {
                'target_count': self._convert_neo4j_types(r['target_count']) or 0,
                'service_count': self._convert_neo4j_types(r['service_count']) or 0,
                'finding_count': self._convert_neo4j_types(r['finding_count']) or 0,
                'credential_count': self._convert_neo4j_types(r['credential_count']) or 0,
                'loot_count': self._convert_neo4j_types(r['loot_count']) or 0,
            }
        return {'target_count': 0, 'service_count': 0, 'finding_count': 0, 'credential_count': 0, 'loot_count': 0}

    def get_targets(self, engagement_id: str) -> List[Dict]:
        """Get all targets for engagement."""
        results = self._query("""
            MATCH (e:Engagement {id: $id})-[:TARGETS]->(t:Target)
            RETURN t ORDER BY t.ip_address
        """, id=engagement_id)
        return [self._convert_neo4j_types(dict(r['t'])) for r in results]

    def get_findings(self, engagement_id: str) -> List[Dict]:
        """Get all findings for engagement (sorted by severity)."""
        results = self._query("""
            MATCH (e:Engagement {id: $id})-[:HAS_FINDING]->(f:Finding)
            OPTIONAL MATCH (f)-[:AFFECTS]->(t:Target)
            RETURN f, collect(DISTINCT t.ip_address) AS targetIps
            ORDER BY
              CASE f.severity
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                WHEN 'info' THEN 4
                ELSE 5
              END,
              f.createdAt DESC
        """, id=engagement_id)
        findings = []
        for r in results:
            f = self._convert_neo4j_types(dict(r['f']))
            f['targetIps'] = [ip for ip in r['targetIps'] if ip]
            findings.append(f)
        return findings

    def get_finding_summary(self, engagement_id: str) -> Dict:
        """Get finding summary (counts by severity)."""
        results = self._query("""
            MATCH (e:Engagement {id: $id})-[:HAS_FINDING]->(f:Finding)
            RETURN f.severity AS severity, count(f) AS count
        """, id=engagement_id)

        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}
        for r in results:
            sev = r['severity']
            count = self._convert_neo4j_types(r['count']) or 0
            if sev in summary:
                summary[sev] = count
                summary['total'] += count
        return summary

    def get_credentials(self, engagement_id: str) -> List[Dict]:
        """Get all credentials for engagement."""
        results = self._query("""
            MATCH (e:Engagement {id: $id})-[:HAS_CREDENTIAL]->(c:Credential)
            OPTIONAL MATCH (c)-[:FOUND_ON]->(t:Target)
            RETURN c, t.ip_address AS targetIp
            ORDER BY c.createdAt DESC
        """, id=engagement_id)
        creds = []
        for r in results:
            c = self._convert_neo4j_types(dict(r['c']))
            c['targetIp'] = r['targetIp']
            creds.append(c)
        return creds

    def get_loot(self, engagement_id: str) -> List[Dict]:
        """Get all loot for engagement."""
        results = self._query("""
            MATCH (e:Engagement {id: $id})-[:HAS_LOOT]->(l:Loot)
            OPTIONAL MATCH (l)-[:FROM_TARGET]->(t:Target)
            RETURN l, t.ip_address AS targetIp
            ORDER BY l.createdAt DESC
        """, id=engagement_id)
        loot = []
        for r in results:
            l = self._convert_neo4j_types(dict(r['l']))
            l['detectedPatterns'] = l.get('detectedPatterns', []) or []
            l['targetIp'] = r['targetIp']
            loot.append(l)
        return loot

    def get_signals(self, engagement_id: str) -> List[Dict]:
        """Get key signals for engagement."""
        results = self._query("""
            MATCH (e:Engagement {id: $id})-[:HAS_SIGNAL]->(s:Signal)
            WHERE s.type IN ['port_status', 'cracked_hash', 'os_detection', 'user_enumeration']
            RETURN s ORDER BY s.timestamp DESC LIMIT 500
        """, id=engagement_id)
        return [self._convert_neo4j_types(dict(r['s'])) for r in results]

    def get_signal_summary(self, engagement_id: str) -> Dict:
        """Get signal summary."""
        results = self._query("""
            MATCH (e:Engagement {id: $id})
            OPTIONAL MATCH (e)-[:HAS_SIGNAL]->(hr:HostReachability)
            OPTIONAL MATCH (e)-[:HAS_SIGNAL]->(ps:PortStatus)
            OPTIONAL MATCH (e)-[:HAS_SIGNAL]->(dns:DnsResolution)
            OPTIONAL MATCH (e)-[:HAS_SIGNAL]->(ue:UserEnumeration)
            OPTIONAL MATCH (e)-[:HAS_SIGNAL]->(ch:CrackedHash)
            WITH e,
              collect(DISTINCT hr) AS reachabilities,
              collect(DISTINCT ps) AS ports,
              count(DISTINCT dns) AS dnsCount,
              count(DISTINCT ue) AS userCount,
              count(DISTINCT ch) AS crackCount
            RETURN {
              hosts: {
                reachable: size([r IN reachabilities WHERE r.reachable = true]),
                unreachable: size([r IN reachabilities WHERE r.reachable = false])
              },
              ports: {
                open: size([p IN ports WHERE p.state = 'open']),
                closed: size([p IN ports WHERE p.state = 'closed']),
                filtered: size([p IN ports WHERE p.state = 'filtered'])
              },
              dns: dnsCount,
              users: userCount,
              crackedHashes: crackCount
            } AS summary
        """, id=engagement_id)

        if results:
            return self._convert_neo4j_types(results[0]['summary'])
        return {
            'hosts': {'reachable': 0, 'unreachable': 0},
            'ports': {'open': 0, 'closed': 0, 'filtered': 0},
            'dns': 0, 'users': 0, 'crackedHashes': 0
        }

    def build_timeline(self, findings: List, credentials: List, loot: List, signals: List) -> List[Dict]:
        """Build chronological timeline from all timestamped events."""
        events = []

        for f in findings:
            if f.get('createdAt'):
                events.append({
                    'timestamp': f['createdAt'],
                    'type': 'finding',
                    'title': f.get('title', 'Unknown'),
                    'description': f.get('description', f.get('evidence', '')[:100] if f.get('evidence') else ''),
                    'severity': f.get('severity'),
                })

        for c in credentials:
            if c.get('createdAt'):
                events.append({
                    'timestamp': c['createdAt'],
                    'type': 'credential',
                    'title': f"{c.get('username', 'unknown')} ({c.get('secretType', 'unknown')})",
                    'description': f"Source: {c.get('source', 'unknown')}",
                })

        for l in loot:
            if l.get('createdAt'):
                patterns = l.get('detectedPatterns', [])
                events.append({
                    'timestamp': l['createdAt'],
                    'type': 'loot',
                    'title': l.get('name', 'Unknown'),
                    'description': f"Type: {l.get('type', 'file')}" + (f", Patterns: {', '.join(patterns)}" if patterns else ''),
                })

        for s in signals:
            if s.get('timestamp') and s.get('type') in ('port_status', 'cracked_hash'):
                if s.get('type') == 'port_status':
                    title = f"Port {s.get('port', '?')}/{s.get('protocol', 'tcp')} {s.get('state', 'unknown')}"
                    desc = f"Service: {s.get('service', 'unknown')}" if s.get('service') else ''
                else:
                    title = f"Hash cracked: {s.get('plaintext', '[redacted]')[:20]}"
                    desc = f"Type: {s.get('hashType', 'unknown')}"
                events.append({
                    'timestamp': s['timestamp'],
                    'type': 'signal',
                    'title': title,
                    'description': desc,
                })

        return sorted(events, key=lambda e: e['timestamp'], reverse=True)

    def gather_data(self, engagement_id: str) -> Dict:
        """Gather all report data for engagement."""
        engagement = self.get_engagement(engagement_id)
        stats = self.get_stats(engagement_id)
        targets = self.get_targets(engagement_id)
        findings = self.get_findings(engagement_id)
        finding_summary = self.get_finding_summary(engagement_id)
        credentials = self.get_credentials(engagement_id)
        loot = self.get_loot(engagement_id)
        signals = self.get_signals(engagement_id)
        signal_summary = self.get_signal_summary(engagement_id)
        timeline = self.build_timeline(findings, credentials, loot, signals)

        return {
            'engagement': engagement,
            'stats': stats,
            'targets': targets,
            'findings': findings,
            'findingSummary': finding_summary,
            'credentials': credentials,
            'loot': loot,
            'signals': signals,
            'signalSummary': signal_summary,
            'timeline': timeline,
            'generatedAt': datetime.now().isoformat(),
        }

    def render_markdown(self, data: Dict, options: Dict) -> str:
        """Render report as markdown."""
        lines = []

        # Header
        eng = data.get('engagement') or {}
        lines.append(f"# Engagement Report: {eng.get('name', 'Unknown')}")
        lines.append('')
        lines.append(f"**Generated:** {datetime.fromisoformat(data['generatedAt']).strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Status:** {eng.get('status', 'unknown')}")
        if eng.get('start_date'):
            lines.append(f"**Period:** {eng.get('start_date')} - {eng.get('end_date', 'ongoing')}")
        if eng.get('scope_text'):
            lines.append(f"**Scope:** {eng.get('scope_text')}")
        lines.append('')

        # Executive Summary
        stats = data.get('stats', {})
        lines.append('## Executive Summary')
        lines.append('')
        lines.append(f"- **Targets:** {stats.get('target_count', 0)}")
        lines.append(f"- **Services:** {stats.get('service_count', 0)}")
        lines.append(f"- **Findings:** {stats.get('finding_count', 0)}")
        lines.append(f"- **Credentials:** {stats.get('credential_count', 0)}")
        lines.append(f"- **Loot:** {stats.get('loot_count', 0)}")
        lines.append('')

        # Finding Severity Distribution
        fs = data.get('findingSummary', {})
        if fs.get('total', 0) > 0:
            lines.append('### Finding Severity Distribution')
            lines.append('')
            lines.append('| Severity | Count |')
            lines.append('|----------|-------|')
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                lines.append(f"| {sev.capitalize()} | {fs.get(sev, 0)} |")
            lines.append('')

        # Targets
        targets = data.get('targets', [])
        if targets:
            lines.append('## Targets')
            lines.append('')
            for t in targets:
                hostname = f" ({t.get('hostname')})" if t.get('hostname') else ''
                lines.append(f"### {t.get('ip_address', 'unknown')}{hostname}")
                lines.append('')
                lines.append(f"- **Status:** {t.get('status', 'unknown')}")
                if t.get('os_guess'):
                    lines.append(f"- **OS:** {t.get('os_guess')}")
                if t.get('notes'):
                    lines.append(f"- **Notes:** {t.get('notes')}")
                lines.append('')

        # Findings (grouped by severity)
        findings = data.get('findings', [])
        if findings:
            lines.append('## Findings')
            lines.append('')
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                sev_findings = [f for f in findings if f.get('severity') == sev]
                if not sev_findings:
                    continue
                lines.append(f"### {sev.upper()} ({len(sev_findings)})")
                lines.append('')
                for f in sev_findings:
                    lines.append(f"#### {f.get('title', 'Unknown')}")
                    lines.append('')
                    if f.get('cveId'):
                        lines.append(f"**CVE:** {f.get('cveId')}")
                    if f.get('cvssScore'):
                        lines.append(f"**CVSS:** {f.get('cvssScore')}")
                    lines.append(f"**Category:** {f.get('category', 'unknown')}")
                    lines.append(f"**Status:** {f.get('status', 'open')}")
                    if f.get('targetIps'):
                        lines.append(f"**Affected Targets:** {', '.join(f['targetIps'])}")
                    if f.get('description'):
                        lines.append('')
                        lines.append(f.get('description'))
                    if f.get('evidence'):
                        lines.append('')
                        lines.append('**Evidence:**')
                        lines.append('```')
                        lines.append(f.get('evidence')[:500])
                        lines.append('```')
                    lines.append('')

        # Credentials (optional)
        credentials = data.get('credentials', [])
        if options.get('include_credentials', True) and credentials:
            lines.append('## Credentials')
            lines.append('')
            lines.append('| Username | Type | Domain | Source | Target |')
            lines.append('|----------|------|--------|--------|--------|')
            for c in credentials:
                lines.append(f"| {c.get('username', '-')} | {c.get('secretType', '-')} | {c.get('domain', '-')} | {c.get('source', '-')} | {c.get('targetIp', '-')} |")
            lines.append('')

        # Loot
        loot = data.get('loot', [])
        if loot:
            lines.append('## Loot')
            lines.append('')
            for l in loot:
                lines.append(f"### {l.get('name', 'Unknown')}")
                lines.append('')
                lines.append(f"- **Type:** {l.get('type', 'file')}")
                lines.append(f"- **Path:** {l.get('path', '-')}")
                if l.get('targetIp'):
                    lines.append(f"- **Target:** {l.get('targetIp')}")
                patterns = l.get('detectedPatterns', [])
                if patterns:
                    lines.append(f"- **Patterns:** {', '.join(patterns)}")
                if l.get('contentPreview'):
                    lines.append('')
                    lines.append('**Preview:**')
                    lines.append('```')
                    lines.append(l.get('contentPreview')[:300])
                    lines.append('```')
                lines.append('')

        # Signal Summary
        ss = data.get('signalSummary', {})
        hosts = ss.get('hosts', {})
        ports = ss.get('ports', {})
        lines.append('## Reconnaissance Summary')
        lines.append('')
        lines.append(f"- **Hosts Reachable:** {hosts.get('reachable', 0)}")
        lines.append(f"- **Hosts Unreachable:** {hosts.get('unreachable', 0)}")
        lines.append(f"- **Open Ports:** {ports.get('open', 0)}")
        lines.append(f"- **Closed Ports:** {ports.get('closed', 0)}")
        lines.append(f"- **Filtered Ports:** {ports.get('filtered', 0)}")
        lines.append(f"- **DNS Records:** {ss.get('dns', 0)}")
        lines.append(f"- **Users Enumerated:** {ss.get('users', 0)}")
        lines.append(f"- **Hashes Cracked:** {ss.get('crackedHashes', 0)}")
        lines.append('')

        # Timeline (optional)
        timeline = data.get('timeline', [])
        if options.get('include_timeline', True) and timeline:
            lines.append('## Appendix: Chronological Timeline')
            lines.append('')
            lines.append('| Timestamp | Type | Event | Details |')
            lines.append('|-----------|------|-------|---------|')
            for event in timeline[:100]:
                ts = datetime.fromisoformat(event['timestamp']).strftime('%Y-%m-%d %H:%M')
                etype = event.get('type', 'unknown').replace('_', ' ')
                title = event.get('title', '').replace('|', '\\|')
                desc = event.get('description', '')[:50].replace('|', '\\|')
                lines.append(f"| {ts} | {etype} | {title} | {desc} |")
            if len(timeline) > 100:
                lines.append('')
                lines.append(f"*... and {len(timeline) - 100} more events*")
            lines.append('')

        # Footer
        lines.append('---')
        lines.append('*Report generated by B.R.E.A.C.H. - Box Reconnaissance, Exploitation & Attack Command Hub*')

        return '\n'.join(lines)

    def generate(
        self,
        engagement_id: str,
        format: str = 'markdown',
        output_path: Optional[str] = None,
        include_timeline: bool = True,
        include_credentials: bool = True,
    ) -> Dict[str, Any]:
        """Generate engagement report."""
        data = self.gather_data(engagement_id)

        if not data.get('engagement'):
            return {'success': False, 'error': 'Engagement not found'}

        options = {
            'include_timeline': include_timeline,
            'include_credentials': include_credentials,
        }

        if format == 'json':
            content = json.dumps(data, indent=2, default=str)
            ext = 'json'
        else:
            content = self.render_markdown(data, options)
            ext = 'md'

        if output_path:
            if not output_path.endswith(f'.{ext}'):
                output_path = f'{output_path}.{ext}'
            Path(output_path).write_text(content)
            return {'success': True, 'output_path': output_path}

        return {'success': True, 'content': content}

    def close(self):
        """Close Neo4j connection."""
        self.driver.close()


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Generate B.R.E.A.C.H. engagement report',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  crack breach-report --active
  crack breach-report -e eng-abc123 --format json -o report.json
  crack breach-report --active --format markdown -o report.md
  crack breach-report --active --no-credentials  # For sharing
        """
    )

    parser.add_argument(
        '--engagement', '-e',
        help='Engagement ID to generate report for'
    )
    parser.add_argument(
        '--active', '-a',
        action='store_true',
        help='Use currently active engagement'
    )
    parser.add_argument(
        '--format', '-f',
        choices=['markdown', 'json'],
        default='markdown',
        help='Output format (default: markdown)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file path (prints to stdout if not specified)'
    )
    parser.add_argument(
        '--no-timeline',
        action='store_true',
        help='Exclude chronological timeline appendix'
    )
    parser.add_argument(
        '--no-credentials',
        action='store_true',
        help='Exclude credentials section (for sharing)'
    )

    args = parser.parse_args()

    # Determine engagement ID
    engagement_id = args.engagement
    if args.active:
        engagement_id = get_active_engagement_id()
        if not engagement_id:
            print(f"{Colors.RED}Error:{Colors.END} No active engagement")
            sys.exit(1)

    if not engagement_id:
        print(f"{Colors.RED}Error:{Colors.END} Must specify --engagement or --active")
        sys.exit(1)

    try:
        generator = ReportGenerator()
        result = generator.generate(
            engagement_id=engagement_id,
            format=args.format,
            output_path=args.output,
            include_timeline=not args.no_timeline,
            include_credentials=not args.no_credentials,
        )
        generator.close()

        if result['success']:
            if args.output:
                print(f"{Colors.GREEN}Report saved to:{Colors.END} {result['output_path']}")
            else:
                print(result['content'])
        else:
            print(f"{Colors.RED}Error:{Colors.END} {result['error']}")
            sys.exit(1)

    except Exception as e:
        print(f"{Colors.RED}Error:{Colors.END} {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
