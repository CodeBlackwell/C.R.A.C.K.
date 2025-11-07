#!/usr/bin/env python3
"""
OSCP Toolkit Gap Analysis

Identifies missing essential tools from OSCP/OSWP/OSED exam requirements
by comparing against current database and extracted candidates.

Categories analyzed:
1. Reconnaissance & Enumeration
2. Web Application Testing
3. Exploitation Tools
4. Post-Exploitation
5. Privilege Escalation
6. Tunneling & Pivoting
7. Password Attacks
8. Active Directory
"""

import json
from pathlib import Path
from typing import Dict, List, Set
import sys

# Add parent directory to path for imports
crack_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(crack_root))
db_dir = crack_root / "db"
sys.path.insert(0, str(db_dir))

from config import get_db_config
import psycopg2


# OSCP Essential Tools by Category
OSCP_TOOLKIT = {
    "Reconnaissance & Enumeration": {
        "nmap": ["nmap-quick-scan", "nmap-full-scan", "nmap-vuln-scan", "nmap-udp-scan"],
        "rustscan": ["rustscan-fast-scan"],
        "masscan": ["masscan-fast-scan"],
        "autorecon": ["autorecon-full"],
        "enum4linux": ["enum4linux-smb", "enum4linux-ng"],
        "ldapsearch": ["ldapsearch-basic", "ldapsearch-dump"],
        "dig": ["dig-domain-enum", "dig-zone-transfer"],
        "dnsenum": ["dnsenum-domain"],
        "dnsrecon": ["dnsrecon-domain"],
        "whatweb": ["whatweb-scan"],
        "wappalyzer": ["wappalyzer-tech-detect"],
    },
    "Web Application Testing": {
        "gobuster": ["gobuster-dir-basic"],  # Already exists
        "ffuf": ["ffuf-dir-fuzz", "ffuf-vhost-fuzz", "ffuf-param-fuzz"],
        "wfuzz": ["wfuzz-dir", "wfuzz-param"],
        "nikto": ["nikto-web-scan"],  # Already exists
        "burpsuite": ["burp-proxy", "burp-intruder", "burp-scanner"],
        "zaproxy": ["zap-baseline-scan"],
        "sqlmap": ["sqlmap-basic", "sqlmap-advanced"],
        "wpscan": ["wpscan-enumerate"],
        "joomscan": ["joomscan-enumerate"],
        "droopescan": ["droopescan-enumerate"],
        "curl": ["curl-get", "curl-post", "curl-headers"],
        "wget": ["wget-download", "wget-recursive"],
    },
    "Exploitation Tools": {
        "metasploit": ["msfconsole-search", "msfconsole-exploit"],
        "msfvenom": ["msfvenom-linux-shell", "msfvenom-windows-shell", "msfvenom-staged"],
        "searchsploit": ["searchsploit-search", "searchsploit-update"],
        "exploit-db": ["exploit-db-search"],
        "nc": ["nc-listener", "nc-reverse-shell", "nc-bind-shell"],
        "socat": ["socat-listener", "socat-file-transfer"],
        "powercat": ["powercat-listener"],
        "chisel": ["chisel-server", "chisel-client"],
    },
    "Post-Exploitation": {
        "linpeas": ["linpeas-run"],
        "linenum": ["linenum-run"],
        "linux-exploit-suggester": ["les-run"],
        "pspy": ["pspy-monitor"],
        "winpeas": ["winpeas-run"],
        "windows-exploit-suggester": ["wes-run"],
        "powerup": ["powerup-run"],
        "privesccheck": ["privesccheck-run"],
        "seatbelt": ["seatbelt-run"],
        "sharphound": ["sharphound-collect"],
        "bloodhound": ["bloodhound-analyze"],
    },
    "Privilege Escalation": {
        "sudo": ["sudo-check", "sudo-exploit"],
        "suid": ["suid-find", "suid-exploit"],
        "capabilities": ["cap-find", "cap-exploit"],
        "cronjobs": ["cron-enum"],
        "kernel-exploits": ["kernel-exploit-search"],
        "gtfobins": ["gtfobins-lookup"],
        "lolbas": ["lolbas-lookup"],
    },
    "Tunneling & Pivoting": {
        "chisel": ["chisel-socks", "chisel-reverse"],
        "ligolo-ng": ["ligolo-server", "ligolo-agent"],
        "sshuttle": ["sshuttle-vpn"],
        "ssh": ["ssh-local-forward", "ssh-remote-forward", "ssh-dynamic-forward"],
        "proxychains": ["proxychains-config"],
        "proxytunnel": ["proxytunnel-connect"],
        "socat": ["socat-port-forward"],
    },
    "Password Attacks": {
        "hydra": ["hydra-ssh", "hydra-ftp", "hydra-http"],
        "medusa": ["medusa-ssh", "medusa-smb"],
        "crackmapexec": ["cme-smb", "cme-winrm", "cme-ssh"],
        "john": ["john-crack", "john-format"],
        "hashcat": ["hashcat-crack", "hashcat-modes"],
        "hashid": ["hashid-identify"],
        "hash-identifier": ["hash-identifier-run"],
        "kerbrute": ["kerbrute-userenum", "kerbrute-bruteuser"],
        "rubeus": ["rubeus-asreproast", "rubeus-kerberoast"],
    },
    "Active Directory": {
        "bloodhound": ["bloodhound-ingest", "bloodhound-query"],
        "sharphound": ["sharphound-collect"],
        "crackmapexec": ["cme-smb-shares", "cme-smb-users"],
        "impacket-psexec": ["psexec-shell"],
        "impacket-smbexec": ["smbexec-shell"],
        "impacket-wmiexec": ["wmiexec-shell"],
        "impacket-secretsdump": ["secretsdump-hashes"],
        "impacket-GetNPUsers": ["getnpusers-asreproast"],
        "impacket-GetUserSPNs": ["getuserspns-kerberoast"],
        "evil-winrm": ["evil-winrm-shell"],
        "rpcclient": ["rpcclient-enum"],
        "smbclient": ["smbclient-connect"],
        "smbmap": ["smbmap-shares"],
        "ldapsearch": ["ldapsearch-ad"],
    },
    "File Transfer": {
        "python-http-server": ["python-http-server"],
        "php-http-server": ["php-http-server"],
        "ruby-http-server": ["ruby-http-server"],
        "scp": ["scp-upload", "scp-download"],
        "ftp": ["ftp-connect"],
        "tftp": ["tftp-upload"],
        "smb-server": ["impacket-smbserver"],
        "certutil": ["certutil-download"],
        "bitsadmin": ["bitsadmin-download"],
        "powershell-download": ["powershell-wget", "powershell-invoke-webrequest"],
    },
}


def get_existing_commands() -> Set[str]:
    """Get command IDs from database."""
    try:
        config = get_db_config()
        conn = psycopg2.connect(**config)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM commands;')
        existing = set(row[0] for row in cursor.fetchall())
        conn.close()
        return existing
    except Exception as e:
        print(f"Database error: {e}")
        return set()


def analyze_gaps():
    """Analyze which OSCP tools are missing."""
    existing_commands = get_existing_commands()

    print("=" * 80)
    print("OSCP TOOLKIT GAP ANALYSIS")
    print("=" * 80)
    print(f"\nExisting Commands in Database: {len(existing_commands)}")

    total_oscp_commands = sum(len(cmds) for cat in OSCP_TOOLKIT.values() for cmds in cat.values())
    print(f"Total OSCP Essential Commands: {total_oscp_commands}")

    missing_by_category = {}
    total_missing = 0

    for category, tools in OSCP_TOOLKIT.items():
        missing_tools = {}

        for tool, command_ids in tools.items():
            missing_cmds = [cmd for cmd in command_ids if cmd not in existing_commands]
            if missing_cmds:
                missing_tools[tool] = missing_cmds
                total_missing += len(missing_cmds)

        if missing_tools:
            missing_by_category[category] = missing_tools

    print(f"Missing Commands: {total_missing}")
    print(f"Coverage: {((total_oscp_commands - total_missing) / total_oscp_commands * 100):.1f}%")

    print("\n" + "=" * 80)
    print("MISSING COMMANDS BY CATEGORY")
    print("=" * 80)

    for category, tools in missing_by_category.items():
        print(f"\n{category.upper()}")
        print("-" * 80)

        for tool, missing_cmds in sorted(tools.items()):
            print(f"\n  {tool}: {len(missing_cmds)} missing")
            for cmd in missing_cmds:
                status = "✓" if cmd in existing_commands else "✗"
                print(f"    {status} {cmd}")

    print("\n" + "=" * 80)
    print("PRIORITY RECOMMENDATIONS")
    print("=" * 80)

    # Calculate priority by category
    priority_order = [
        ("Reconnaissance & Enumeration", "Critical - needed for initial foothold"),
        ("Web Application Testing", "High - primary attack vector"),
        ("Exploitation Tools", "High - needed for initial access"),
        ("Password Attacks", "Medium - common attack vector"),
        ("Post-Exploitation", "Medium - needed after initial access"),
        ("Privilege Escalation", "High - required for root/system"),
        ("Tunneling & Pivoting", "Medium - needed for multi-host networks"),
        ("Active Directory", "High - common in OSCP labs"),
        ("File Transfer", "Critical - needed for all stages"),
    ]

    for category, priority in priority_order:
        if category in missing_by_category:
            count = sum(len(cmds) for cmds in missing_by_category[category].values())
            print(f"\n[{priority}]")
            print(f"{category}: {count} missing commands")

    # Export detailed gap analysis
    export_path = Path(__file__).parent / "oscp_toolkit_gaps.json"
    export_data = {
        "total_oscp_commands": total_oscp_commands,
        "existing_commands": len(existing_commands),
        "missing_commands": total_missing,
        "coverage_percentage": round((total_oscp_commands - total_missing) / total_oscp_commands * 100, 1),
        "missing_by_category": missing_by_category,
        "priority_recommendations": [
            {"category": cat, "priority": pri, "missing_count": sum(len(cmds) for cmds in missing_by_category.get(cat, {}).values())}
            for cat, pri in priority_order if cat in missing_by_category
        ]
    }

    with open(export_path, 'w') as f:
        json.dump(export_data, f, indent=2)

    print(f"\n✓ Detailed gap analysis exported to: {export_path}")


if __name__ == "__main__":
    analyze_gaps()
