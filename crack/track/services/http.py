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

    def detect(self, port_info: Dict[str, Any], profile: 'TargetProfile') -> float:
        """Detect HTTP/HTTPS services with confidence scoring

        Returns:
            Confidence score (0-100):
            - 100: Exact service match (e.g., 'http' service on port 80)
            - 90: Service name contains HTTP/HTTPS
            - 80: Version info indicates web server
            - 60: Common HTTP port with no service info
            - 40: Uncommon port with web-like service hints
            - 0: No match
        """
        service = port_info.get('service', '').lower()
        port = port_info.get('port')
        version = port_info.get('version', '').lower()

        confidence = 0

        # Perfect match: HTTP service on standard port
        if service in ['http', 'https'] and port in [80, 443]:
            return 100

        # High confidence: Service explicitly mentions HTTP
        if any(svc in service for svc in ['http', 'https', 'ssl/http']):
            confidence = 90

        # Check version for web server signatures
        elif any(srv in version for srv in ['apache', 'nginx', 'iis', 'lighttpd', 'tomcat']):
            confidence = 80

        # Medium confidence: Common HTTP ports
        elif port in self.default_ports:
            # If we have service info but it's not HTTP, lower confidence
            if service and service != 'unknown':
                confidence = 40
            else:
                confidence = 60

        # Low confidence: Port ends with 80, 443, 8080, etc.
        elif port and str(port).endswith(('80', '443', '8080', '8443')):
            confidence = 30

        # Check for web-related keywords in service/version
        if confidence == 0:
            web_keywords = ['web', 'www', 'portal', 'api', 'rest']
            if any(kw in service for kw in web_keywords):
                confidence = 40
            elif any(kw in version for kw in web_keywords):
                confidence = 35

        return confidence

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
                ],
                # Phase 6: Alternative commands linkage
                'alternative_ids': [
                    'alt-http-headers-inspect'
                ],
                'alternative_context': {
                    'service': 'http',
                    'port': port,
                    'purpose': 'web-enumeration'
                }
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
                'notes': 'Try multiple wordlists: common.txt, big.txt, raft-medium-*',
                # Phase 6: Alternative commands linkage
                'alternative_ids': [
                    'alt-manual-dir-check',
                    'alt-robots-check'
                ],
                'alternative_context': {
                    'service': 'http',
                    'port': port,
                    'purpose': 'web-enumeration'
                },
                # Phase 4: Wordlist selection metadata
                'wordlist_purpose': 'web-enumeration'
            }
        })

        # 3. NSE HTTP Methods Enumeration
        tasks['children'].append({
            'id': f'http-methods-{port}',
            'name': 'HTTP Methods Enumeration',
            'type': 'command',
            'metadata': {
                'command': f'nmap -p{port} --script http-methods --script-args http-methods.retest {target}',
                'description': 'Enumerate supported HTTP methods and test each individually',
                'tags': ['OSCP:HIGH', 'QUICK_WIN', 'ENUM'],
                'flag_explanations': {
                    '-p{port}': f'Target port {port}',
                    '--script http-methods': 'NSE script to enumerate HTTP methods via OPTIONS',
                    '--script-args http-methods.retest': 'Test each method individually (not just trust OPTIONS response)',
                    '--script-args http-methods.url-path': 'Optional: test different path (default: /)'
                },
                'success_indicators': [
                    'Methods enumerated (GET, POST, HEAD, OPTIONS)',
                    'Risky methods detected (TRACE, PUT, DELETE, CONNECT)',
                    'Individual method testing completed'
                ],
                'failure_indicators': [
                    'Connection refused',
                    'OPTIONS method disabled',
                    'Firewall blocking requests'
                ],
                'next_steps': [
                    'If TRACE enabled: Test for XST vulnerability',
                    'If PUT enabled: Attempt file upload',
                    'If DELETE enabled: Test file deletion capabilities',
                    'Run http-trace script for XST detection'
                ],
                'alternatives': [
                    f'Manual: curl -X OPTIONS -i {url}',
                    f'Manual: curl -X TRACE -i {url}',
                    f'Manual: curl -X PUT -i {url}/test.txt -d "test content"'
                ],
                'notes': 'TRACE=XST risk, CONNECT=proxy abuse, PUT/DELETE=file manipulation. See OWASP-CM-008.',
                # Phase 6: Alternative commands linkage
                'alternative_ids': [
                    'alt-http-methods-manual',
                    'alt-http-trace-xst'
                ],
                'alternative_context': {
                    'service': 'http',
                    'port': port,
                    'purpose': 'web-enumeration'
                }
            }
        })

        # 4. NSE XST Vulnerability Detection
        tasks['children'].append({
            'id': f'http-trace-{port}',
            'name': 'Cross Site Tracing (XST) Detection',
            'type': 'command',
            'metadata': {
                'command': f'nmap -p{port} --script http-trace,http-methods {target}',
                'description': 'Detect TRACE method (XST vulnerability - bypass httpOnly cookies)',
                'tags': ['OSCP:MEDIUM', 'QUICK_WIN', 'VULN_SCAN'],
                'flag_explanations': {
                    '--script http-trace': 'Test if TRACE method is enabled and accessible',
                    '--script http-methods': 'Enumerate all methods (TRACE may not be in OPTIONS)',
                    '--script-args http-trace.path': 'Optional: test specific path'
                },
                'success_indicators': [
                    'TRACE is enabled (status 200)',
                    'Request echoed back by server',
                    'Listed in http-methods output'
                ],
                'failure_indicators': [
                    'TRACE disabled (expected on hardened servers)',
                    'Method not accessible (blocked by firewall/config)'
                ],
                'next_steps': [
                    'If vulnerable: Test XSS exploitation via TRACE',
                    'Document for report (medium severity finding)',
                    'Recommend: Disable TRACE in web server config'
                ],
                'alternatives': [
                    f'Manual: curl -X TRACE -i {url}',
                    f'Manual: Check if request is echoed back',
                    'Burp Suite: Send TRACE request, inspect response'
                ],
                'notes': 'XST allows XSS to bypass httpOnly cookie protection. Combined with XSS = session hijacking.'
            }
        })

        # 5. NSE Directory Enumeration (http-enum)
        tasks['children'].append({
            'id': f'http-enum-{port}',
            'name': 'NSE Directory/Application Enumeration',
            'type': 'command',
            'metadata': {
                'command': f'nmap -p{port} --script http-enum {target}',
                'description': 'Discover directories, files, and vulnerable web applications using NSE fingerprint database',
                'tags': ['OSCP:HIGH', 'ENUM'],
                'flag_explanations': {
                    '--script http-enum': 'Use NSE fingerprint database (/nselib/data/http-fingerprints.lua)',
                    '--script-args http-enum.basepath': 'Optional: set different base path (default: /)',
                    '--script-args http-enum.displayall': 'Show all discovered paths (not just interesting ones)',
                    '--script-args http-enum.fingerprintfile': 'Use custom fingerprint file'
                },
                'success_indicators': [
                    'Interesting directories found (/admin, /upload, /backup)',
                    'Web applications detected (WordPress, Joomla, CakePHP)',
                    'Configuration files discovered (robots.txt, crossdomain.xml)',
                    'Vulnerable apps identified (CVE fingerprints)'
                ],
                'failure_indicators': [
                    'No interesting paths found',
                    'All requests return 404',
                    'WAF blocking enumeration'
                ],
                'next_steps': [
                    'Manually browse discovered directories',
                    'If CMS detected: Run CMS-specific scanners (wpscan, joomscan)',
                    'Check for default credentials in detected apps',
                    'Test upload directories for file upload vulnerabilities'
                ],
                'alternatives': [
                    f'gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt',
                    f'feroxbuster -u {url}',
                    f'Manual: Try common paths (/admin, /upload, /backup, /config)'
                ],
                'notes': 'http-enum has 150+ vuln app fingerprints. Faster than full dir brute-force but less comprehensive.'
            }
        })

        # 6. NSE WAF Detection
        tasks['children'].append({
            'id': f'http-waf-detect-{port}',
            'name': 'Web Application Firewall Detection',
            'type': 'command',
            'metadata': {
                'command': f'nmap -p{port} --script http-waf-detect {target}',
                'description': 'Detect Web Application Firewall or Intrusion Prevention System',
                'tags': ['OSCP:HIGH', 'QUICK_WIN', 'RECON'],
                'flag_explanations': {
                    '--script http-waf-detect': 'Send malicious payloads and detect filtering',
                    '--script-args http-waf-detect.aggro': 'Use more aggressive payloads (more HTTP requests)',
                    '--script-args http-waf-detect.detectBodyChanges': 'Detect changes in response body (use for static pages)',
                    '--script-args http-waf-detect.uri': 'Test specific URI path'
                },
                'success_indicators': [
                    'IDS/IPS/WAF detected',
                    'Status code changes on malicious payloads (403 Forbidden)',
                    'Response body modifications detected'
                ],
                'failure_indicators': [
                    'No WAF detected (direct access to application)',
                    'Unable to determine (application errors mimic WAF behavior)'
                ],
                'next_steps': [
                    'If WAF detected: Adjust testing strategy for evasion',
                    'Use encoding/obfuscation techniques',
                    'Try alternative attack vectors',
                    'Document WAF presence in report'
                ],
                'alternatives': [
                    f'Manual: Send SQLi payload and check for blocking',
                    f'wafw00f {url}',
                    f'whatwaf -u {url}'
                ],
                'notes': 'WAF detection informs strategy. If present, focus on manual testing and evasion techniques.',
                'estimated_time': '1-2 minutes (5-10 min with --script-args http-waf-detect.aggro)'
            }
        })

        # 7. Vulnerability scanning (Nikto - kept for compatibility)
        tasks['children'].append({
            'id': f'nikto-{port}',
            'name': 'Nikto Vulnerability Scan',
            'type': 'command',
            'metadata': {
                'command': f'nikto -h {url} -output nikto_{port}.txt',
                'description': 'Automated vulnerability scanner for web servers',
                'tags': ['OSCP:MEDIUM', 'AUTOMATED', 'NOISY'],
                'flag_explanations': {
                    '-h': 'Target host/URL',
                    '-output': 'Save results to file (required for OSCP documentation)'
                },
                'success_indicators': [
                    'Vulnerabilities found',
                    'Outdated software detected',
                    'Misconfigurations identified'
                ],
                'failure_indicators': [
                    'WAF blocking (all requests return 403)',
                    'Scan too slow (tune with -Tuning options)',
                    'Connection timeouts'
                ],
                'next_steps': [
                    'Manually verify findings (false positive check)',
                    'Research detected versions for CVEs',
                    'Test for identified misconfigurations'
                ],
                'alternatives': [
                    f'nmap -p{port} --script http-vuln-* {target}',
                    f'Manual testing based on version info'
                ],
                'notes': 'Nikto is NOISY - use carefully. Consider NSE http-vuln-* scripts for quieter scans.',
                # Phase 6: Alternative commands linkage
                'alternative_ids': [
                    'alt-apache-cve-2021-41773'  # If Apache detected, check for common CVEs
                ],
                'alternative_context': {
                    'service': 'http',
                    'port': port,
                    'purpose': 'vulnerability-scan'
                }
            }
        })

        # 8. NSE Default Credentials Testing
        tasks['children'].append({
            'id': f'http-default-accounts-{port}',
            'name': 'Test Default Credentials',
            'type': 'command',
            'metadata': {
                'command': f'nmap -p{port} --script http-default-accounts {target}',
                'description': 'Test default credentials on web applications (Tomcat, Cacti, routers)',
                'tags': ['OSCP:HIGH', 'QUICK_WIN', 'EXPLOIT'],
                'flag_explanations': {
                    '--script http-default-accounts': 'Test default creds from fingerprint database',
                    '--script-args http-default-accounts.category': 'Filter by category (web, router, voip, security)',
                    '--script-args http-default-accounts.basepath': 'Set different base path',
                    '--script-args http-default-accounts.fingerprintfile': 'Use custom fingerprint file'
                },
                'success_indicators': [
                    'Valid default credentials found (admin:admin, tomcat:tomcat)',
                    'Application detected (Tomcat, Cacti, Axis2, routers)',
                    'Access granted to management interface'
                ],
                'failure_indicators': [
                    'No default credentials working (changed by admin)',
                    'Application not detected',
                    'Login attempts blocked'
                ],
                'next_steps': [
                    'Use found credentials to access admin panel',
                    'Look for file upload or command execution',
                    'Enumerate application functionality',
                    'Test for privilege escalation'
                ],
                'alternatives': [
                    f'Manual: Try admin:admin on {url}/manager/html',
                    f'Manual: Try tomcat:tomcat on Tomcat Manager',
                    f'hydra -C /usr/share/wordlists/default-credentials.txt {target} http-get /admin/'
                ],
                'notes': 'Covers: Tomcat, Cacti, Axis2, Arris/Cisco routers. QUICK WIN in OSCP - always try defaults first.',
                'estimated_time': '1-3 minutes'
            }
        })

        # 9. NSE HTTP Brute-force (if auth detected)
        tasks['children'].append({
            'id': f'http-brute-{port}',
            'name': 'HTTP Authentication Brute-force',
            'type': 'command',
            'metadata': {
                'command': f'nmap -p{port} --script http-brute --script-args http-brute.path=/admin/ {target}',
                'description': 'Dictionary attack against HTTP Basic Authentication',
                'tags': ['OSCP:MEDIUM', 'BRUTE_FORCE', 'NOISY'],
                'flag_explanations': {
                    '--script http-brute': 'Brute-force HTTP Basic Auth',
                    '--script-args http-brute.path': 'Target path (default: /)',
                    '--script-args userdb': 'Custom username wordlist',
                    '--script-args passdb': 'Custom password wordlist',
                    '--script-args brute.firstOnly': 'Stop after first valid account',
                    '--script-args unpwdb.timelimit': 'Set timeout (0=unlimited, default varies by -T)'
                },
                'success_indicators': [
                    'Valid credentials found',
                    'Access to protected resource',
                    'Accounts listed in output'
                ],
                'failure_indicators': [
                    'Account lockout triggered',
                    'Rate limiting detected',
                    'All attempts failed',
                    'Timeout reached'
                ],
                'next_steps': [
                    'Use found credentials to access protected areas',
                    'Enumerate with authenticated access',
                    'Test for session hijacking/privilege escalation'
                ],
                'alternatives': [
                    f'hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt {target} http-get /admin/',
                    f'medusa -h {target} -U users.txt -P passwords.txt -M http -m DIR:/admin/',
                    f'Manual: Try common combos (admin:admin, admin:password, root:root)'
                ],
                'notes': 'OSCP WARNING: Brute-force often triggers lockouts. Try defaults first. Use small wordlists.',
                'estimated_time': '5-30 minutes (depends on wordlist)'
            }
        })

        # 10. Manual checks
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
                        'tags': ['MANUAL', 'QUICK_WIN', 'OSCP:HIGH'],
                        'flag_explanations': {
                            'curl': 'HTTP client for manual requests',
                            url: 'Target URL',
                            '/robots.txt': 'Standard robots file location'
                        },
                        'success_indicators': [
                            'File exists (200 response)',
                            'Disallowed paths revealed (Disallow: /admin)',
                            'Interesting directories listed'
                        ],
                        'next_steps': [
                            'Browse all Disallow entries',
                            'Check for admin panels, backups, configs'
                        ],
                        'alternatives': [
                            f'Manual: Open {url}/robots.txt in browser',
                            f'curl -s {url}/robots.txt | grep Disallow'
                        ]
                    }
                },
                {
                    'id': f'sitemap-{port}',
                    'name': 'Check sitemap.xml',
                    'type': 'command',
                    'metadata': {
                        'command': f'curl {url}/sitemap.xml',
                        'description': 'Discover site structure from sitemap',
                        'tags': ['MANUAL', 'QUICK_WIN', 'OSCP:HIGH'],
                        'flag_explanations': {
                            '/sitemap.xml': 'Standard sitemap location for SEO'
                        },
                        'success_indicators': [
                            'Sitemap exists',
                            'Site structure revealed',
                            'All URLs listed'
                        ],
                        'next_steps': [
                            'Browse all discovered URLs',
                            'Look for admin/upload/sensitive pages'
                        ],
                        'alternatives': [
                            f'Browser: {url}/sitemap.xml',
                            f'curl {url}/sitemap_index.xml'
                        ]
                    }
                },
                {
                    'id': f'http-headers-{port}',
                    'name': 'Analyze HTTP Headers',
                    'type': 'command',
                    'metadata': {
                        'command': f'curl -I {url}',
                        'description': 'View HTTP response headers for security info',
                        'tags': ['MANUAL', 'QUICK_WIN', 'OSCP:MEDIUM'],
                        'flag_explanations': {
                            '-I': 'Fetch headers only (HEAD request)'
                        },
                        'success_indicators': [
                            'Server version revealed',
                            'Security headers analyzed',
                            'Cookies visible'
                        ],
                        'next_steps': [
                            'Research server version for CVEs',
                            'Check for missing security headers',
                            'Analyze cookie flags (HttpOnly, Secure)'
                        ],
                        'alternatives': [
                            f'nmap -p{port} --script http-headers {target}',
                            'Browser DevTools: Network tab → Headers'
                        ],
                        'notes': 'Look for: Server/X-Powered-By (version info), missing CSP/X-Frame-Options (XSS risk)'
                    }
                },
                {
                    'id': f'source-review-{port}',
                    'name': 'Review page source',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Manually review HTML source for comments, hidden fields, JS files',
                        'tags': ['MANUAL', 'OSCP:HIGH'],
                        'success_indicators': [
                            'Comments with sensitive info found',
                            'Hidden form fields discovered',
                            'API endpoints revealed in JavaScript',
                            'Version numbers in comments'
                        ],
                        'next_steps': [
                            'Extract credentials from comments',
                            'Test hidden parameters',
                            'Analyze JavaScript for logic flaws',
                            'Check included JS libraries for CVEs'
                        ],
                        'alternatives': [
                            f'curl {url} | grep -i "password\\|user\\|admin\\|key"',
                            f'curl {url} | grep -i "TODO\\|FIXME\\|XXX"',
                            'Browser: View → Page Source (Ctrl+U)'
                        ],
                        'notes': 'Look for: credentials in comments, API endpoints, version numbers, debug info, TODO comments'
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
