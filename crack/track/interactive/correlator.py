"""
Finding Correlator - Detect credential reuse, attack chains, and CVE matches

Minimalist correlation engine for OSCP workflows:
- Credential reuse opportunities (found creds vs untested services)
- Attack chain detection (LFI → Config → DB → Shell)
- CVE correlation with service versions
"""

from typing import Dict, List, Tuple, Any, Optional
import json
from pathlib import Path


class FindingCorrelator:
    """Correlate findings to identify attack opportunities"""

    # Attack chain patterns (simple string matching)
    ATTACK_CHAINS = [
        {
            'name': 'LFI → Config → Database → Shell',
            'steps': ['lfi', 'config', 'database', 'shell'],
            'description': 'LFI reads config → DB creds → SQL shell upload'
        },
        {
            'name': 'SQLi → File Read → SSH Key → Shell',
            'steps': ['sqli', 'file read', 'ssh', 'shell'],
            'description': 'SQL injection → Read SSH keys → Login'
        },
        {
            'name': 'File Upload → LFI → Code Execution',
            'steps': ['upload', 'lfi', 'rce'],
            'description': 'Upload file → LFI to execute uploaded code'
        },
        {
            'name': 'RCE → Database → Credentials → Escalation',
            'steps': ['rce', 'database', 'credential', 'privesc'],
            'description': 'RCE → Dump DB → Find admin creds → Escalate'
        }
    ]

    # Services that accept authentication
    AUTH_SERVICES = ['ssh', 'ftp', 'smb', 'mysql', 'postgresql', 'mssql', 'http', 'https', 'rdp', 'vnc', 'telnet']

    def __init__(self, profile):
        """
        Args:
            profile: TargetProfile instance
        """
        self.profile = profile
        self.cve_cache = self._load_cve_cache()

    def _load_cve_cache(self) -> Dict[str, List[Dict]]:
        """Load static CVE cache from JSON"""
        cache_path = Path(__file__).parent.parent / 'data' / 'cve_cache.json'

        if not cache_path.exists():
            return {}

        with open(cache_path, 'r') as f:
            return json.load(f)

    def detect_credential_reuse(self) -> List[Dict]:
        """Find credentials not tested on all auth services"""
        opportunities = []
        credentials = self.profile.credentials or []
        auth_ports = [
            p for p in self.profile.ports.values()
            if p.get('service', '').lower() in self.AUTH_SERVICES
        ]

        for cred in credentials:
            # Determine which services have been tested
            tested_services = cred.get('tested_services', [])

            # Find untested services
            untested = []
            for port_info in auth_ports:
                service_key = f"{port_info.get('service')}:{port_info.get('port', 0)}"
                if service_key not in tested_services:
                    untested.append(port_info)

            if untested:
                # Calculate confidence
                confidence = self._calculate_cred_confidence(cred)

                opportunities.append({
                    'credential': cred,
                    'untested_services': untested,
                    'confidence': confidence,
                    'actions': self._suggest_cred_actions(cred, untested)
                })

        return opportunities

    def _calculate_cred_confidence(self, cred: Dict) -> str:
        """Heuristic confidence scoring for credentials"""
        username = cred.get('username', '').lower()
        password = cred.get('password', '')
        source = cred.get('source', '').lower()

        # HIGH: Strong credentials from config files
        if any(word in source for word in ['config', 'database', 'backup']):
            return 'HIGH'

        # MEDIUM: Default credentials or patterns
        if username in ['admin', 'root', 'administrator'] or not password:
            return 'MEDIUM'

        # LOW: Everything else
        return 'LOW'

    def _suggest_cred_actions(self, cred: Dict, untested: List[Dict]) -> List[str]:
        """Suggest actions for testing credentials"""
        actions = []

        for service_info in untested[:3]:  # Limit to 3 suggestions
            service = service_info.get('service', 'unknown')
            port = service_info.get('port', 0)

            if service == 'ssh':
                actions.append(f"Try SSH login: ssh {cred.get('username')}@{self.profile.target} -p {port}")
            elif service in ['smb', 'smb2']:
                actions.append(f"Try SMB shares: smbclient -U {cred.get('username')} //{self.profile.target}/")
            elif service == 'ftp':
                actions.append(f"Try FTP login: ftp {self.profile.target} {port}")
            else:
                actions.append(f"Test {service} auth on port {port}")

        return actions

    def detect_attack_chains(self) -> List[Dict]:
        """Match findings to known attack chain patterns"""
        chains = []
        findings = self.profile.findings or []

        # Simple keyword matching
        finding_keywords = [
            f.get('description', '').lower() + ' ' + f.get('type', '').lower()
            for f in findings
        ]

        for chain_pattern in self.ATTACK_CHAINS:
            steps = chain_pattern['steps']
            matched_steps = []

            for step in steps:
                # Check if any finding matches this step
                if any(step in keywords for keywords in finding_keywords):
                    matched_steps.append(step)

            # If all steps matched, this is a viable chain
            if len(matched_steps) == len(steps):
                chains.append({
                    'name': chain_pattern['name'],
                    'description': chain_pattern['description'],
                    'confidence': 'HIGH',
                    'next_step': self._suggest_next_chain_step(chain_pattern)
                })

        return chains

    def _suggest_next_chain_step(self, chain: Dict) -> str:
        """Suggest next step in attack chain"""
        # Simple: return first step as next action
        steps = chain['steps']
        return f"Test {steps[0]} vulnerability" if steps else "No next step"

    def correlate_cves(self) -> List[Dict]:
        """Match service versions to CVE cache"""
        matches = []

        for port, info in self.profile.ports.items():
            service = info.get('service', '')
            version = info.get('version', '')

            if not service or not version:
                continue

            # Build cache key (service:version)
            cache_key = f"{service.lower()}:{version.lower()}"

            # Check for exact match
            if cache_key in self.cve_cache:
                for cve in self.cve_cache[cache_key]:
                    matches.append({
                        'port': port,
                        'service': service,
                        'version': version,
                        'cve_id': cve['id'],
                        'description': cve['description'],
                        'cvss': cve.get('cvss', 0),
                        'severity': cve.get('severity', 'Unknown'),
                        'exploit_url': cve.get('exploit_db'),
                        'confidence': 'HIGH'
                    })

            # Fuzzy match: check service without version
            service_only = service.lower()
            for key, cves in self.cve_cache.items():
                if key.startswith(service_only + ':') and key != cache_key:
                    # Version range match (simple heuristic)
                    for cve in cves:
                        matches.append({
                            'port': port,
                            'service': service,
                            'version': version,
                            'cve_id': cve['id'],
                            'description': cve['description'],
                            'cvss': cve.get('cvss', 0),
                            'severity': cve.get('severity', 'Unknown'),
                            'exploit_url': cve.get('exploit_db'),
                            'confidence': 'MEDIUM'
                        })
                    break  # Only add one fuzzy match per service

        # Sort by CVSS score
        matches.sort(key=lambda x: x.get('cvss', 0), reverse=True)
        return matches
