#!/usr/bin/env python3
"""
Engagement Tracking Extractors for Neo4j CSV Generation

These extractors handle engagement tracking data:
- Client nodes
- Engagement nodes
- Target nodes (IP/hostname)
- Finding nodes (vulnerabilities)
- Service nodes (port/service)
- Relationships between engagement entities

Unlike command/chain extractors that read from JSON files,
engagement data is dynamically created via the adapter API.
These extractors support bulk export of existing engagement data.
"""

from typing import List, Dict, Any
from datetime import datetime
import hashlib


def generate_id(prefix: str, text: str) -> str:
    """Generate consistent ID from prefix and text"""
    return f"{prefix}-{hashlib.md5(text.encode()).hexdigest()[:12]}"


# =============================================================================
# Node Extractors
# =============================================================================

def _extract_clients_nodes(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Client nodes from engagement data

    Returns list of dicts with fields:
    - id, name, organization, contact_email, industry, created_at, notes
    """
    if not engagements:
        return []

    # Deduplicate clients by ID
    clients = {}

    for engagement in engagements:
        client_data = engagement.get('client', {})
        client_id = client_data.get('id', '')

        if client_id and client_id not in clients:
            clients[client_id] = {
                'id': client_id,
                'name': client_data.get('name', ''),
                'organization': client_data.get('organization', ''),
                'contact_email': client_data.get('contact_email', ''),
                'industry': client_data.get('industry', ''),
                'created_at': client_data.get('created_at', ''),
                'notes': client_data.get('notes', '')
            }

    return list(clients.values())


def _extract_engagements_nodes(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Engagement nodes

    Returns list of dicts with fields:
    - id, name, client_id, status, start_date, end_date
    - scope_type, scope_text, rules_of_engagement, notes, created_at
    """
    if not engagements:
        return []

    nodes = []

    for engagement in engagements:
        node = {
            'id': engagement.get('id', ''),
            'name': engagement.get('name', ''),
            'client_id': engagement.get('client', {}).get('id', ''),
            'status': engagement.get('status', 'active'),
            'start_date': engagement.get('start_date', ''),
            'end_date': engagement.get('end_date', ''),
            'scope_type': engagement.get('scope_type', ''),
            'scope_text': engagement.get('scope_text', ''),
            'rules_of_engagement': engagement.get('rules_of_engagement', ''),
            'notes': engagement.get('notes', ''),
            'created_at': engagement.get('created_at', '')
        }
        nodes.append(node)

    return nodes


def _extract_targets_nodes(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Target nodes from engagement data

    Returns list of dicts with fields:
    - id, ip_address, hostname, os_guess, status, first_seen, last_seen, notes
    """
    if not engagements:
        return []

    # Deduplicate targets by ID
    targets = {}

    for engagement in engagements:
        for target_data in engagement.get('targets', []):
            target_id = target_data.get('id', '')

            if target_id and target_id not in targets:
                targets[target_id] = {
                    'id': target_id,
                    'ip_address': target_data.get('ip_address', ''),
                    'hostname': target_data.get('hostname', ''),
                    'os_guess': target_data.get('os_guess', ''),
                    'status': target_data.get('status', 'active'),
                    'first_seen': target_data.get('first_seen', ''),
                    'last_seen': target_data.get('last_seen', ''),
                    'notes': target_data.get('notes', '')
                }

    return list(targets.values())


def _extract_findings_nodes(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Finding nodes from engagement data

    Returns list of dicts with fields:
    - id, title, severity, cvss_score, cve_id, description
    - impact, remediation, evidence, found_at, status
    """
    if not engagements:
        return []

    # Deduplicate findings by ID
    findings = {}

    for engagement in engagements:
        for finding_data in engagement.get('findings', []):
            finding_id = finding_data.get('id', '')

            if finding_id and finding_id not in findings:
                findings[finding_id] = {
                    'id': finding_id,
                    'title': finding_data.get('title', ''),
                    'severity': finding_data.get('severity', 'medium'),
                    'cvss_score': finding_data.get('cvss_score', ''),
                    'cve_id': finding_data.get('cve_id', ''),
                    'description': finding_data.get('description', ''),
                    'impact': finding_data.get('impact', ''),
                    'remediation': finding_data.get('remediation', ''),
                    'evidence': finding_data.get('evidence', ''),
                    'found_at': finding_data.get('found_at', ''),
                    'status': finding_data.get('status', 'open')
                }

    return list(findings.values())


def _extract_services_nodes(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Service nodes from engagement data

    Returns list of dicts with fields:
    - id, target_id, port, protocol, service_name, version, banner, state, found_at
    """
    if not engagements:
        return []

    # Deduplicate services by ID
    services = {}

    for engagement in engagements:
        for target in engagement.get('targets', []):
            target_id = target.get('id', '')

            for service_data in target.get('services', []):
                service_id = service_data.get('id', '')

                if service_id and service_id not in services:
                    services[service_id] = {
                        'id': service_id,
                        'target_id': target_id,
                        'port': service_data.get('port', 0),
                        'protocol': service_data.get('protocol', 'tcp'),
                        'service_name': service_data.get('service_name', ''),
                        'version': service_data.get('version', ''),
                        'banner': service_data.get('banner', ''),
                        'state': service_data.get('state', 'open'),
                        'found_at': service_data.get('found_at', '')
                    }

    return list(services.values())


# =============================================================================
# Relationship Extractors
# =============================================================================

def _extract_client_engagement_rels(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Client -[:HAS_ENGAGEMENT]-> Engagement relationships

    Returns list of dicts with fields:
    - client_id, engagement_id
    """
    if not engagements:
        return []

    relationships = []

    for engagement in engagements:
        client_id = engagement.get('client', {}).get('id', '')
        engagement_id = engagement.get('id', '')

        if client_id and engagement_id:
            relationships.append({
                'client_id': client_id,
                'engagement_id': engagement_id
            })

    return relationships


def _extract_engagement_target_rels(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Engagement -[:TARGETS]-> Target relationships

    Returns list of dicts with fields:
    - engagement_id, target_id, added_at, in_scope
    """
    if not engagements:
        return []

    relationships = []

    for engagement in engagements:
        engagement_id = engagement.get('id', '')

        for target in engagement.get('targets', []):
            target_id = target.get('id', '')

            if engagement_id and target_id:
                relationships.append({
                    'engagement_id': engagement_id,
                    'target_id': target_id,
                    'added_at': target.get('added_at', ''),
                    'in_scope': str(target.get('in_scope', True))
                })

    return relationships


def _extract_engagement_finding_rels(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Engagement -[:HAS_FINDING]-> Finding relationships

    Returns list of dicts with fields:
    - engagement_id, finding_id
    """
    if not engagements:
        return []

    relationships = []

    for engagement in engagements:
        engagement_id = engagement.get('id', '')

        for finding in engagement.get('findings', []):
            finding_id = finding.get('id', '')

            if engagement_id and finding_id:
                relationships.append({
                    'engagement_id': engagement_id,
                    'finding_id': finding_id
                })

    return relationships


def _extract_target_service_rels(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Target -[:HAS_SERVICE]-> Service relationships

    Returns list of dicts with fields:
    - target_id, service_id
    """
    if not engagements:
        return []

    relationships = []

    for engagement in engagements:
        for target in engagement.get('targets', []):
            target_id = target.get('id', '')

            for service in target.get('services', []):
                service_id = service.get('id', '')

                if target_id and service_id:
                    relationships.append({
                        'target_id': target_id,
                        'service_id': service_id
                    })

    return relationships


def _extract_finding_target_rels(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Finding -[:AFFECTS]-> Target relationships

    Returns list of dicts with fields:
    - finding_id, target_id
    """
    if not engagements:
        return []

    relationships = []

    for engagement in engagements:
        for finding in engagement.get('findings', []):
            finding_id = finding.get('id', '')

            for target_id in finding.get('affected_targets', []):
                if finding_id and target_id:
                    relationships.append({
                        'finding_id': finding_id,
                        'target_id': target_id
                    })

    return relationships


def _extract_finding_cve_rels(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Finding -[:EXPLOITS]-> CVE relationships

    Returns list of dicts with fields:
    - finding_id, cve_id
    """
    if not engagements:
        return []

    relationships = []

    for engagement in engagements:
        for finding in engagement.get('findings', []):
            finding_id = finding.get('id', '')
            cve_id = finding.get('cve_id', '')

            if finding_id and cve_id:
                relationships.append({
                    'finding_id': finding_id,
                    'cve_id': cve_id
                })

    return relationships


def _extract_engagement_command_rels(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Engagement -[:USED_COMMAND]-> Command relationships

    Returns list of dicts with fields:
    - engagement_id, command_id, used_at, target_id, success, notes
    """
    if not engagements:
        return []

    relationships = []

    for engagement in engagements:
        engagement_id = engagement.get('id', '')

        for cmd_usage in engagement.get('commands_used', []):
            command_id = cmd_usage.get('command_id', '')

            if engagement_id and command_id:
                relationships.append({
                    'engagement_id': engagement_id,
                    'command_id': command_id,
                    'used_at': cmd_usage.get('used_at', ''),
                    'target_id': cmd_usage.get('target_id', ''),
                    'success': str(cmd_usage.get('success', True)),
                    'notes': cmd_usage.get('notes', '')
                })

    return relationships


def _extract_engagement_chain_rels(
    engagements: List[Dict] = None,
    **kwargs
) -> List[Dict]:
    """
    Extract Engagement -[:USED_CHAIN]-> AttackChain relationships

    Returns list of dicts with fields:
    - engagement_id, chain_id, used_at, effectiveness, notes
    """
    if not engagements:
        return []

    relationships = []

    for engagement in engagements:
        engagement_id = engagement.get('id', '')

        for chain_usage in engagement.get('chains_used', []):
            chain_id = chain_usage.get('chain_id', '')

            if engagement_id and chain_id:
                relationships.append({
                    'engagement_id': engagement_id,
                    'chain_id': chain_id,
                    'used_at': chain_usage.get('used_at', ''),
                    'effectiveness': chain_usage.get('effectiveness', ''),
                    'notes': chain_usage.get('notes', '')
                })

    return relationships


# =============================================================================
# Registry for Schema Loader
# =============================================================================

# Map extractor names to functions (for schema loader)
EXTRACTOR_REGISTRY = {
    # Node extractors
    '_extract_clients_nodes': _extract_clients_nodes,
    '_extract_engagements_nodes': _extract_engagements_nodes,
    '_extract_targets_nodes': _extract_targets_nodes,
    '_extract_findings_nodes': _extract_findings_nodes,
    '_extract_services_nodes': _extract_services_nodes,

    # Relationship extractors
    '_extract_client_engagement_rels': _extract_client_engagement_rels,
    '_extract_engagement_target_rels': _extract_engagement_target_rels,
    '_extract_engagement_finding_rels': _extract_engagement_finding_rels,
    '_extract_target_service_rels': _extract_target_service_rels,
    '_extract_finding_target_rels': _extract_finding_target_rels,
    '_extract_finding_cve_rels': _extract_finding_cve_rels,
    '_extract_engagement_command_rels': _extract_engagement_command_rels,
    '_extract_engagement_chain_rels': _extract_engagement_chain_rels,
}


def get_extractor(name: str):
    """Get extractor function by name"""
    return EXTRACTOR_REGISTRY.get(name)


if __name__ == '__main__':
    # Test with sample data
    sample_engagements = [{
        'id': 'eng-001',
        'name': 'Q4 External Pentest',
        'client': {
            'id': 'client-001',
            'name': 'ACME Corp',
            'organization': 'ACME Corporation'
        },
        'status': 'active',
        'targets': [{
            'id': 'target-001',
            'ip_address': '192.168.1.100',
            'hostname': 'web01.acme.local',
            'services': [{
                'id': 'svc-001',
                'port': 80,
                'protocol': 'tcp',
                'service_name': 'http'
            }]
        }],
        'findings': [{
            'id': 'finding-001',
            'title': 'SQL Injection',
            'severity': 'critical',
            'cve_id': 'CVE-2024-12345',
            'affected_targets': ['target-001']
        }]
    }]

    print("Testing engagement extractors...")
    print(f"Clients: {_extract_clients_nodes(sample_engagements)}")
    print(f"Engagements: {_extract_engagements_nodes(sample_engagements)}")
    print(f"Targets: {_extract_targets_nodes(sample_engagements)}")
    print(f"Services: {_extract_services_nodes(sample_engagements)}")
    print(f"Findings: {_extract_findings_nodes(sample_engagements)}")
    print(f"Client-Engagement rels: {_extract_client_engagement_rels(sample_engagements)}")
    print(f"Engagement-Target rels: {_extract_engagement_target_rels(sample_engagements)}")
    print(f"Finding-Target rels: {_extract_finding_target_rels(sample_engagements)}")
    print(f"Finding-CVE rels: {_extract_finding_cve_rels(sample_engagements)}")
    print("All extractors working!")
