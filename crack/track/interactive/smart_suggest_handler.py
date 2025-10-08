"""
Smart Suggest Handler - Pattern-based suggestion engine

Provides AI-lite suggestions based on current enumeration state.
Uses pattern matching rules to identify overlooked attack vectors.
"""

from typing import List, Dict, Any
import time


def get_suggestion_rules(target: str) -> List[Dict]:
    """
    Load all suggestion rules

    Args:
        target: Target IP/hostname

    Returns:
        List of rule dictionaries with conditions, suggestions, and commands
    """
    return [
        # Rule 1: MySQL without enumeration
        {
            'id': 'mysql-no-enum',
            'pattern': 'mysql_open_no_tasks',
            'priority': 'high',
            'condition': lambda p: (
                any(port_info.get('service', '').lower() == 'mysql'
                    for port_info in p.ports.values()) and
                not any('mysql' in t.name.lower()
                    for t in p.task_tree.get_all_pending())
            ),
            'suggestion': 'MySQL port open but no enumeration tasks created',
            'command': f'mysql -h {target} -u root',
            'reasoning': 'MySQL commonly has weak/default credentials worth testing'
        },

        # Rule 2: SMB without null session test
        {
            'id': 'smb-no-null',
            'pattern': 'smb_no_null_session',
            'priority': 'high',
            'condition': lambda p: (
                any(port_info.get('service', '').lower() == 'smb'
                    for port_info in p.ports.values()) and
                not any('null' in t.name.lower() or 'anonymous' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'SMB service found but null session not tested',
            'command': f'smbclient -L //{target} -N',
            'reasoning': 'Null sessions can reveal share information without credentials'
        },

        # Rule 3: Web + No robots.txt check
        {
            'id': 'http-no-robots',
            'pattern': 'http_no_robots_check',
            'priority': 'medium',
            'condition': lambda p: (
                any(port_info.get('service', '').lower() in ['http', 'https']
                    for port_info in p.ports.values()) and
                not any('robots' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'Web service found but robots.txt not checked',
            'command': f'curl http://{target}/robots.txt',
            'reasoning': 'robots.txt often reveals hidden directories'
        },

        # Rule 4: Credentials without reuse testing
        {
            'id': 'creds-no-reuse',
            'pattern': 'credentials_no_reuse',
            'priority': 'high',
            'condition': lambda p: (
                len(p.credentials) > 0 and
                len([port for port, info in p.ports.items()
                     if info.get('service', '').lower() in ['ssh', 'smb', 'ftp']]) > 1
            ),
            'suggestion': 'Credentials found but not tested on all services',
            'command': 'Test credentials on SSH/SMB/FTP services',
            'reasoning': 'Credential reuse is common in OSCP environments'
        },

        # Rule 5: High port without investigation
        {
            'id': 'high-port-unknown',
            'pattern': 'high_port_unknown_service',
            'priority': 'medium',
            'condition': lambda p: (
                any(int(port) > 10000 and info.get('service', '') == 'unknown'
                    for port, info in p.ports.items())
            ),
            'suggestion': 'High-numbered port with unknown service',
            'command': f'nc -nv {target} <PORT>',
            'reasoning': 'High ports often run custom services worth investigating'
        },

        # Rule 6: Web without screenshot
        {
            'id': 'web-no-screenshot',
            'pattern': 'http_no_visual_recon',
            'priority': 'low',
            'condition': lambda p: (
                any(info.get('service', '').lower() in ['http', 'https']
                    for info in p.ports.values()) and
                not any('screenshot' in n.get('note', '').lower()
                    for n in p.notes)
            ),
            'suggestion': 'Web service found but no visual reconnaissance documented',
            'command': 'Browse to site and screenshot interesting pages',
            'reasoning': 'Visual inspection often reveals details missed by automated tools'
        },

        # Rule 7: FTP anonymous not tested
        {
            'id': 'ftp-no-anon',
            'pattern': 'ftp_no_anonymous',
            'priority': 'high',
            'condition': lambda p: (
                any(info.get('service', '').lower() == 'ftp'
                    for info in p.ports.values()) and
                not any('anon' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'FTP service without anonymous login test',
            'command': f'ftp {target}  # Try user: anonymous, pass: anonymous',
            'reasoning': 'Anonymous FTP is a common misconfiguration'
        },

        # Rule 8: Version disclosure without CVE search
        {
            'id': 'version-no-cve',
            'pattern': 'version_no_exploit_search',
            'priority': 'high',
            'condition': lambda p: (
                any(info.get('version') and info.get('version') != 'unknown'
                    for info in p.ports.values()) and
                not any('searchsploit' in t.name.lower() or 'cve' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'Service versions detected but no exploit search performed',
            'command': 'searchsploit <SERVICE> <VERSION>',
            'reasoning': 'Known vulnerabilities are quick wins in OSCP'
        },

        # Rule 9: Multiple web ports
        {
            'id': 'multi-web-incomplete',
            'pattern': 'multiple_web_ports_incomplete',
            'priority': 'medium',
            'condition': lambda p: (
                len([port for port, info in p.ports.items()
                     if info.get('service', '').lower() in ['http', 'https']]) > 1 and
                len([t for t in p.task_tree.get_all_pending()
                     if 'http' in t.name.lower()]) < 2
            ),
            'suggestion': 'Multiple web ports open but not all enumerated',
            'command': 'Enumerate all discovered HTTP/HTTPS ports',
            'reasoning': 'Different ports may host different applications'
        },

        # Rule 10: Directory listing without file download
        {
            'id': 'dir-no-download',
            'pattern': 'directory_no_file_download',
            'priority': 'medium',
            'condition': lambda p: (
                any('directory' in f.get('description', '').lower()
                    for f in p.findings) and
                not any('download' in n.get('note', '').lower() or 'wget' in n.get('note', '').lower()
                    for n in p.notes)
            ),
            'suggestion': 'Directories found but files not downloaded for inspection',
            'command': 'wget -r -np http://<TARGET>/<DIRECTORY>/',
            'reasoning': 'Files may contain credentials, config data, or vulnerabilities'
        },

        # Rule 11: SSH without user enumeration
        {
            'id': 'ssh-no-enum',
            'pattern': 'ssh_no_user_enum',
            'priority': 'medium',
            'condition': lambda p: (
                any(info.get('service', '').lower() == 'ssh'
                    for info in p.ports.values()) and
                not any('user' in t.name.lower() and 'enum' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'SSH service without user enumeration attempt',
            'command': f'enum4linux -U {target} or hydra user enumeration',
            'reasoning': 'User enumeration can provide valid usernames for brute-force'
        },

        # Rule 12: SNMP without community string test
        {
            'id': 'snmp-no-community',
            'pattern': 'snmp_no_community_test',
            'priority': 'high',
            'condition': lambda p: (
                any(info.get('service', '').lower() == 'snmp'
                    for info in p.ports.values()) and
                not any('community' in t.name.lower() or 'onesixtyone' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'SNMP service without community string enumeration',
            'command': f'onesixtyone {target} -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt',
            'reasoning': 'SNMP often uses default community strings like "public"'
        },

        # Rule 13: NFS without showmount
        {
            'id': 'nfs-no-showmount',
            'pattern': 'nfs_no_showmount',
            'priority': 'high',
            'condition': lambda p: (
                any(info.get('service', '').lower() in ['nfs', 'rpcbind']
                    for info in p.ports.values()) and
                not any('showmount' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'NFS/RPC service without showmount enumeration',
            'command': f'showmount -e {target}',
            'reasoning': 'NFS shares may be mountable without authentication'
        },

        # Rule 14: DNS without zone transfer test
        {
            'id': 'dns-no-axfr',
            'pattern': 'dns_no_zone_transfer',
            'priority': 'medium',
            'condition': lambda p: (
                any(info.get('service', '').lower() == 'dns' or int(port) == 53
                    for port, info in p.ports.items()) and
                not any('axfr' in t.name.lower() or 'zone transfer' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'DNS service without zone transfer test',
            'command': f'dig axfr @{target} <DOMAIN>',
            'reasoning': 'Zone transfers can reveal entire DNS records'
        },

        # Rule 15: RDP without screenshot
        {
            'id': 'rdp-no-screenshot',
            'pattern': 'rdp_no_visual',
            'priority': 'low',
            'condition': lambda p: (
                any(info.get('service', '').lower() in ['rdp', 'ms-wbt-server']
                    for info in p.ports.values()) and
                not any('screenshot' in n.get('note', '').lower()
                    for n in p.notes)
            ),
            'suggestion': 'RDP service without visual reconnaissance',
            'command': f'nmap -p 3389 --script rdp-screenshot {target}',
            'reasoning': 'RDP screenshots can reveal Windows version and login screen'
        },

        # Rule 16: MSSQL without version-specific exploits
        {
            'id': 'mssql-no-version-check',
            'pattern': 'mssql_no_version_exploits',
            'priority': 'high',
            'condition': lambda p: (
                any(info.get('service', '').lower() in ['mssql', 'ms-sql-s']
                    for info in p.ports.values()) and
                not any('xp_cmdshell' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'MSSQL service without xp_cmdshell exploitation attempt',
            'command': f'impacket-mssqlclient <USER>@{target}',
            'reasoning': 'xp_cmdshell provides command execution on MSSQL servers'
        },

        # Rule 17: Tomcat without default credentials
        {
            'id': 'tomcat-no-default',
            'pattern': 'tomcat_no_default_creds',
            'priority': 'high',
            'condition': lambda p: (
                any('tomcat' in info.get('service', '').lower() or
                    'tomcat' in info.get('version', '').lower()
                    for info in p.ports.values()) and
                not any('tomcat' in t.name.lower() and 'credential' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'Tomcat service without default credential test',
            'command': 'Try tomcat:tomcat, admin:admin, tomcat:s3cret',
            'reasoning': 'Tomcat often uses default credentials'
        },

        # Rule 18: LDAP without enumeration
        {
            'id': 'ldap-no-enum',
            'pattern': 'ldap_no_enumeration',
            'priority': 'medium',
            'condition': lambda p: (
                any(info.get('service', '').lower() in ['ldap', 'ldaps']
                    for info in p.ports.values()) and
                not any('ldap' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'LDAP service without directory enumeration',
            'command': f'ldapsearch -x -h {target} -b "dc=example,dc=com"',
            'reasoning': 'LDAP may allow anonymous bind and directory enumeration'
        },

        # Rule 19: Wordpress without wpscan
        {
            'id': 'wordpress-no-scan',
            'pattern': 'wordpress_no_wpscan',
            'priority': 'high',
            'condition': lambda p: (
                any('wordpress' in f.get('description', '').lower() or
                    'wp-content' in f.get('description', '').lower()
                    for f in p.findings) and
                not any('wpscan' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'WordPress site without wpscan enumeration',
            'command': f'wpscan --url http://{target} --enumerate u,p,t',
            'reasoning': 'wpscan identifies vulnerable plugins and themes'
        },

        # Rule 20: No manual verification tasks
        {
            'id': 'no-manual-tasks',
            'pattern': 'missing_manual_verification',
            'priority': 'low',
            'condition': lambda p: (
                len(p.ports) > 0 and
                not any('manual' in t.name.lower() or 'verify' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'Automated scans complete but no manual verification tasks',
            'command': 'Create manual verification checklist',
            'reasoning': 'Manual testing often finds issues automated tools miss'
        },

        # Rule 21: Findings without exploitation attempts
        {
            'id': 'findings-no-exploit',
            'pattern': 'findings_not_exploited',
            'priority': 'critical',
            'condition': lambda p: (
                len([f for f in p.findings if f.get('type') == 'vulnerability']) > 0 and
                not any('exploit' in t.name.lower()
                    for t in p.task_tree.get_all_tasks())
            ),
            'suggestion': 'Vulnerabilities documented but no exploitation tasks created',
            'command': 'Create exploitation tasks for documented vulnerabilities',
            'reasoning': 'Documented vulnerabilities should be attempted for exploitation'
        },

        # Rule 22: Credentials without documentation source
        {
            'id': 'creds-missing-source',
            'pattern': 'credentials_missing_source',
            'priority': 'medium',
            'condition': lambda p: (
                any(not c.get('source') or c.get('source') == 'N/A'
                    for c in p.credentials)
            ),
            'suggestion': 'Credentials found without proper source documentation',
            'command': 'Review credentials and add source documentation',
            'reasoning': 'OSCP requires documentation of credential discovery methods'
        },
    ]


def create_suggestion_tasks(profile, suggestions: List[Dict]) -> int:
    """
    Create tasks from suggestions

    Args:
        profile: TargetProfile instance
        suggestions: List of suggestion dictionaries

    Returns:
        Number of tasks created
    """
    from ..core.task_tree import TaskNode
    from .display import DisplayManager

    created = 0

    for suggestion in suggestions:
        # Create task
        task_id = f"suggest-{suggestion['id']}-{int(time.time())}"

        # Build task metadata
        metadata = {
            'command': suggestion['command'],
            'description': suggestion['suggestion'],
            'tags': ['SUGGESTION', f"OSCP:{suggestion['priority'].upper()}"],
            'suggestion_type': suggestion['pattern'],
            'reasoning': suggestion['reasoning']
        }

        # Create task node
        task_node = TaskNode(
            task_id=task_id,
            name=f"[SUGGEST] {suggestion['suggestion'][:60]}",
            task_type='command'
        )

        # Set metadata
        task_node.metadata.update(metadata)

        # Add to task tree
        profile.task_tree.add_child(task_node)

        print(DisplayManager.format_success(f"✓ Created: {suggestion['suggestion']}"))
        created += 1

    profile.save()
    return created
