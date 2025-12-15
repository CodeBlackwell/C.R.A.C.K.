"""
Nmap Parser Regex Patterns

Compiled regex patterns for parsing nmap human-readable output.
"""

import re
from datetime import datetime
from typing import Optional


# ============================================================================
# File Detection Patterns (for can_parse)
# ============================================================================

NMAP_HEADER = re.compile(
    r'^#?\s*Nmap\s+(\d+\.\d+)\s+scan\s+initiated',
    re.IGNORECASE | re.MULTILINE
)

NMAP_FOOTER = re.compile(
    r'^#?\s*Nmap\s+done\s+at\s+(.+?)\s+--\s+(\d+)\s+IP\s+address',
    re.IGNORECASE | re.MULTILINE
)

SCAN_REPORT = re.compile(
    r'^Nmap\s+scan\s+report\s+for\s+(.+)$',
    re.IGNORECASE | re.MULTILINE
)


# ============================================================================
# Scan Metadata Patterns
# ============================================================================

SCAN_COMMAND = re.compile(
    r'^#?\s*Nmap\s+(\d+\.\d+)\s+scan\s+initiated\s+(.+?)\s+as:\s*(.+)$',
    re.IGNORECASE | re.MULTILINE
)

SCAN_COMPLETE = re.compile(
    r'^#?\s*Nmap\s+done\s+at\s+(.+?)\s+--\s+(\d+)\s+IP\s+address(?:es)?\s+'
    r'\((\d+)\s+hosts?\s+up\)\s+scanned\s+in\s+([\d.]+)\s+seconds',
    re.IGNORECASE
)


# ============================================================================
# Host Patterns
# ============================================================================

# Matches: "Nmap scan report for hostname (IP)" or "Nmap scan report for IP"
HOST_REPORT = re.compile(
    r'^Nmap\s+scan\s+report\s+for\s+'
    r'(?:(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)|(\d+\.\d+\.\d+\.\d+))'
    r'(?:\s+\[(.+?)\])?',
    re.IGNORECASE
)

# Host status line
HOST_STATUS = re.compile(
    r'^Host\s+is\s+(up|down)'
    r'(?:,\s+received\s+(\S+))?'
    r'(?:\s+\(ttl\s+(\d+)\))?'
    r'(?:\s+\(([\d.]+)s\s+latency\))?',
    re.IGNORECASE
)

# Host down marker (without brackets - they're stripped by HOST_REPORT)
HOST_DOWN_MARKER = re.compile(
    r'host\s+down,?\s+received\s+(\S+)',
    re.IGNORECASE
)

# Scanned at timestamp
SCANNED_AT = re.compile(
    r'^Scanned\s+at\s+(.+?)\s+for\s+(\d+)s$',
    re.IGNORECASE | re.MULTILINE
)


# ============================================================================
# Port Summary Patterns
# ============================================================================

NOT_SHOWN = re.compile(
    r'^Not\s+shown:\s+(\d+)\s+(closed|filtered|open)\s+(?:tcp|udp)\s+ports?\s+\((.+?)\)',
    re.IGNORECASE
)

PORT_TABLE_HEADER = re.compile(
    r'^PORT\s+STATE\s+SERVICE',
    re.IGNORECASE
)


# ============================================================================
# Port Entry Patterns
# ============================================================================

# Standard port entry: 22/tcp open ssh syn-ack ttl 64 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
PORT_ENTRY = re.compile(
    r'^(\d+)/(tcp|udp)\s+'
    r'(open|closed|filtered|open\|filtered)\s+'
    r'(\S+)'
    r'(?:\s+(.+))?$',
    re.IGNORECASE
)

# Verbose port entry with reason and ttl
PORT_ENTRY_VERBOSE = re.compile(
    r'^(\d+)/(tcp|udp)\s+'
    r'(open|closed|filtered)\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'(?:ttl\s+)?(\d+)'
    r'(?:\s+(.+))?$',
    re.IGNORECASE
)


# ============================================================================
# NSE Script Patterns
# ============================================================================

# Script output line (starts with |)
SCRIPT_LINE = re.compile(r'^\|[_\s]?\s*(.*)$')

# Script name header: |_script-name: output or | script-name:
SCRIPT_NAME = re.compile(r'^\|[_\s]?([a-z0-9_-]+):\s*(.*)$', re.IGNORECASE)

# Script continuation (indented under script)
SCRIPT_CONTINUATION = re.compile(r'^\|\s{2,}(.+)$')


# ============================================================================
# Service Info Patterns
# ============================================================================

SERVICE_INFO = re.compile(
    r'^Service\s+Info:\s+(.+)$',
    re.IGNORECASE | re.MULTILINE
)

SERVICE_INFO_HOST = re.compile(r'Host:\s*(\S+)', re.IGNORECASE)
SERVICE_INFO_OS = re.compile(r'OS:\s*([^;]+)', re.IGNORECASE)
SERVICE_INFO_CPE = re.compile(r'CPE:\s*(\S+)', re.IGNORECASE)


# ============================================================================
# RDP/NTLM Info Extraction
# ============================================================================

RDP_NTLM_INFO = re.compile(r'rdp-ntlm-info:', re.IGNORECASE)
NTLM_TARGET_NAME = re.compile(r'Target_Name:\s*(\S+)', re.IGNORECASE)
NTLM_NETBIOS_DOMAIN = re.compile(r'NetBIOS_Domain_Name:\s*(\S+)', re.IGNORECASE)
NTLM_NETBIOS_COMPUTER = re.compile(r'NetBIOS_Computer_Name:\s*(\S+)', re.IGNORECASE)
NTLM_DNS_DOMAIN = re.compile(r'DNS_Domain_Name:\s*(\S+)', re.IGNORECASE)
NTLM_DNS_COMPUTER = re.compile(r'DNS_Computer_Name:\s*(\S+)', re.IGNORECASE)


# ============================================================================
# LDAP Info Extraction
# ============================================================================

LDAP_DOMAIN = re.compile(
    r'Microsoft\s+Windows\s+Active\s+Directory\s+LDAP\s+\(Domain:\s*([^,)]+)',
    re.IGNORECASE
)


# ============================================================================
# SMB Patterns
# ============================================================================

SMB_SECURITY_MODE = re.compile(r'smb2?-security-mode:', re.IGNORECASE)
SMB_SIGNING = re.compile(
    r'Message\s+signing\s+(enabled|disabled)(?:\s+(?:and\s+)?(required|not required))?',
    re.IGNORECASE
)

SMB_TIME = re.compile(r'smb2?-time:', re.IGNORECASE)


# ============================================================================
# OS Detection Patterns
# ============================================================================

OS_GUESS = re.compile(
    r'^(?:Aggressive\s+)?OS\s+guesses?:\s*(.+)$',
    re.IGNORECASE | re.MULTILINE
)

OS_DETAILS = re.compile(
    r'^OS\s+details:\s*(.+)$',
    re.IGNORECASE | re.MULTILINE
)

OS_CPE = re.compile(
    r'^OS\s+CPE:\s*(.+)$',
    re.IGNORECASE | re.MULTILINE
)

OS_FINGERPRINT = re.compile(r'^OS:(.+)$', re.MULTILINE)

UPTIME_GUESS = re.compile(
    r'^Uptime\s+guess:\s*([\d.]+)\s+days(?:\s+\(since\s+(.+?)\))?',
    re.IGNORECASE | re.MULTILINE
)

NETWORK_DISTANCE = re.compile(
    r'^Network\s+Distance:\s*(\d+)\s+hops?',
    re.IGNORECASE | re.MULTILINE
)


# ============================================================================
# Traceroute Patterns
# ============================================================================

TRACEROUTE_HEADER = re.compile(
    r'^TRACEROUTE\s+\(using\s+port\s+(\d+)/(\w+)\)',
    re.IGNORECASE
)

TRACEROUTE_HOP = re.compile(
    r'^(\d+)\s+([\d.]+)\s+ms\s+(\S+)$',
    re.MULTILINE
)


# ============================================================================
# Host Scripts Section
# ============================================================================

HOST_SCRIPT_HEADER = re.compile(
    r'^Host\s+script\s+results:',
    re.IGNORECASE
)


# ============================================================================
# SSH Hostkey Patterns
# ============================================================================

SSH_HOSTKEY = re.compile(r'ssh-hostkey:', re.IGNORECASE)
SSH_KEY_ENTRY = re.compile(
    r'^\|\s+(\d+)\s+(\S+)\s+\((\w+)\)$',
    re.MULTILINE
)


# ============================================================================
# HTTP Patterns
# ============================================================================

HTTP_TITLE = re.compile(r'http-title:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
HTTP_SERVER = re.compile(r'http-server-header:\s*(.+)$', re.IGNORECASE | re.MULTILINE)


# ============================================================================
# Utility Functions
# ============================================================================

def clean_value(value: str) -> str:
    """Clean extracted value by stripping whitespace"""
    if not value:
        return ""
    return value.strip()


def parse_datetime(date_str: str) -> Optional[datetime]:
    """Parse nmap date/time formats"""
    formats = [
        '%a %b %d %H:%M:%S %Y',       # Wed Nov 26 18:21:28 2025
        '%Y-%m-%d %H:%M:%S',          # 2025-11-26 18:21:28
        '%a %b %d %H:%M:%S %Z %Y',    # Wed Nov 26 18:21:28 UTC 2025
        '%a %b %d %H:%M:%S %z %Y',    # With timezone offset
        '%a %b  %d %H:%M:%S %Y',      # Extra space before single-digit day
    ]

    date_str = clean_value(date_str)
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    return None


def is_port_line(line: str) -> bool:
    """Check if line looks like a port entry"""
    return bool(PORT_ENTRY.match(line.strip()))


def is_script_line(line: str) -> bool:
    """Check if line is NSE script output"""
    stripped = line.strip()
    return stripped.startswith('|') or stripped.startswith('|_')


def is_host_report(line: str) -> bool:
    """Check if line starts a new host report"""
    return bool(HOST_REPORT.match(line.strip()))
