"""
HTTP/HTTPS service enumeration plugin

Generates tasks for web application enumeration including:
- Technology fingerprinting
- Directory/file brute-forcing
- Vulnerability scanning
- CMS-specific enumeration
- Exploit research based on versions
"""

from typing import Dict, Any, List
from .base import ServicePlugin
from .registry import ServiceRegistry


@ServiceRegistry.register
class HTTPPlugin(ServicePlugin):
    """HTTP/HTTPS enumeration plugin"""

    @property
    def name(self) -> str:
        return "http"

    @property
    def default_ports(self) -> List[int]:
        return [80, 443, 8000, 8080, 8443, 8888]

    @property
    def service_names(self) -> List[str]:
        return ['http', 'https', 'http-proxy', 'http-alt', 'ssl/http']

    def detect(self, port_info: Dict[str, Any]) -> bool:
        """Detect HTTP/HTTPS services"""
        service = port_info.get('service', '').lower()
        port = port_info.get('port')

        # Check service name
        if any(svc in service for svc in self.service_names):
            return True

        # Check common HTTP ports
        if port in self.default_ports:
            return True

        return False

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate HTTP enumeration task tree"""
        version = service_info.get('version', '')
        is_https = port in [443, 8443] or 'https' in service_info.get('service', '').lower()
        protocol = 'https' if is_https else 'http'
        url = f"{protocol}://{target}:{port}"

        tasks = {
            'id': f'http-enum-{port}',
            'name': f'HTTP Enumeration (Port {port})',
            'type': 'parent',
            'children': []
        }

        # 1. Technology fingerprinting
        tasks['children'].append({
            'id': f'whatweb-{port}',
            'name': 'Technology Fingerprinting',
            'type': 'command',
            'metadata': {
                'command': f'whatweb {url} -v',
                'description': 'Identify web technologies, CMS, frameworks',
                'tags': ['OSCP:HIGH', 'QUICK_WIN'],
                'flag_explanations': {
                    '-v': 'Verbose output (shows all detected technologies)'
                },
                'success_indicators': [
                    'Technology stack identified',
                    'CMS version detected'
                ],
                'next_steps': [
                    'Research detected versions for CVEs',
                    'Look for CMS-specific exploits'
                ]
            }
        })

        # 2. Directory/file brute-force
        tasks['children'].append({
            'id': f'gobuster-{port}',
            'name': 'Directory Brute-force',
            'type': 'command',
            'metadata': {
                'command': f'gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -o gobuster_{port}.txt',
                'description': 'Discover hidden directories and files',
                'tags': ['OSCP:HIGH'],
                'flag_explanations': {
                    'dir': 'Directory/file brute-forcing mode',
                    '-u': 'Target URL',
                    '-w': 'Wordlist path',
                    '-o': 'Output file (for documentation)'
                },
                'success_indicators': [
                    'Directories found (Status: 200, 301, 302)',
                    'Admin panels, upload forms, etc.'
                ],
                'alternatives': [
                    f'feroxbuster -u {url} -w /usr/share/wordlists/dirb/common.txt',
                    f'dirbuster # GUI tool',
                    f'Manual: curl {url}/admin, curl {url}/upload, etc.'
                ],
                'notes': 'Try multiple wordlists: common.txt, big.txt, raft-medium-*'
            }
        })

        # 3. Vulnerability scanning
        tasks['children'].append({
            'id': f'nikto-{port}',
            'name': 'Vulnerability Scan',
            'type': 'command',
            'metadata': {
                'command': f'nikto -h {url} -output nikto_{port}.txt',
                'description': 'Automated vulnerability scanner for web servers',
                'tags': ['OSCP:MEDIUM', 'AUTOMATED'],
                'flag_explanations': {
                    '-h': 'Target host/URL',
                    '-output': 'Save results to file'
                },
                'success_indicators': [
                    'Vulnerabilities found',
                    'Outdated software detected'
                ],
                'notes': 'Nikto is noisy - use carefully in production environments'
            }
        })

        # 4. Manual checks
        tasks['children'].append({
            'id': f'manual-checks-{port}',
            'name': 'Manual Enumeration',
            'type': 'parent',
            'children': [
                {
                    'id': f'robots-{port}',
                    'name': 'Check robots.txt',
                    'type': 'command',
                    'metadata': {
                        'command': f'curl {url}/robots.txt',
                        'description': 'Check for disallowed paths in robots.txt',
                        'tags': ['MANUAL', 'QUICK_WIN']
                    }
                },
                {
                    'id': f'sitemap-{port}',
                    'name': 'Check sitemap.xml',
                    'type': 'command',
                    'metadata': {
                        'command': f'curl {url}/sitemap.xml',
                        'description': 'Discover site structure from sitemap',
                        'tags': ['MANUAL', 'QUICK_WIN']
                    }
                },
                {
                    'id': f'source-review-{port}',
                    'name': 'Review page source',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Manually review HTML source for comments, hidden fields, JS files',
                        'tags': ['MANUAL', 'OSCP:HIGH'],
                        'notes': 'Look for: credentials in comments, API endpoints, version numbers'
                    }
                }
            ]
        })

        # 5. Exploit research if version detected
        if version:
            tasks['children'].append({
                'id': f'exploit-research-http-{port}',
                'name': f'Exploit Research: {version}',
                'type': 'parent',
                'children': [
                    {
                        'id': f'searchsploit-http-{port}',
                        'name': f'SearchSploit: {version}',
                        'type': 'command',
                        'metadata': {
                            'command': f'searchsploit {version}',
                            'description': 'Search for known exploits',
                            'tags': ['OSCP:HIGH', 'RESEARCH']
                        }
                    },
                    {
                        'id': f'cve-lookup-http-{port}',
                        'name': f'CVE Lookup: {version}',
                        'type': 'command',
                        'metadata': {
                            'command': f'crack cve-lookup {version}',
                            'description': 'Search CVE databases',
                            'tags': ['RESEARCH']
                        }
                    }
                ]
            })

        return tasks

    def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
        """Parse results and spawn additional tasks"""
        new_tasks = []

        # If gobuster found /admin, add login testing
        if 'gobuster' in task_id and '/admin' in result.lower():
            port = task_id.split('-')[-1]
            new_tasks.append({
                'id': f'admin-login-test-{port}',
                'name': 'Test Admin Panel Authentication',
                'type': 'manual',
                'metadata': {
                    'description': 'Try default credentials on admin panel',
                    'tags': ['MANUAL', 'OSCP:HIGH'],
                    'notes': 'Try: admin:admin, admin:password, root:root, etc.'
                }
            })

        # If WordPress detected, add WPScan
        if 'whatweb' in task_id and 'wordpress' in result.lower():
            port = task_id.split('-')[-1]
            protocol = 'https' if '443' in port or '8443' in port else 'http'
            new_tasks.append({
                'id': f'wpscan-{port}',
                'name': 'WordPress Scan',
                'type': 'command',
                'metadata': {
                    'command': f'wpscan --url {protocol}://{target}:{port} --enumerate u,vp',
                    'description': 'WordPress-specific vulnerability scanner',
                    'tags': ['OSCP:HIGH', 'CMS'],
                    'flag_explanations': {
                        '--enumerate u': 'Enumerate usernames',
                        '--enumerate vp': 'Enumerate vulnerable plugins'
                    }
                }
            })

        return new_tasks

    def get_manual_alternatives(self, task_id: str) -> List[str]:
        """Get manual alternatives for HTTP enumeration"""
        alternatives = {
            'whatweb': [
                'curl -I <URL> # Check HTTP headers manually',
                'View page source in browser',
                'Check Wappalyzer browser extension'
            ],
            'gobuster': [
                'Manually try common paths: /admin, /upload, /backup, /config',
                'curl <URL>/<path> -I # Check each path manually',
                'Use browser developer tools to find referenced files'
            ],
            'nikto': [
                'Manual testing for common vulns',
                'nmap --script http-* <target>',
                'curl with various payloads to test for SQLi, XSS, etc.'
            ]
        }

        for key, cmds in alternatives.items():
            if key in task_id:
                return cmds

        return []
