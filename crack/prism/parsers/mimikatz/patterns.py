"""
Regex patterns for parsing mimikatz output
"""

import re


# Compiled patterns for performance
PATTERNS = {
    # ========================================
    # Session header patterns
    # ========================================
    'session_header': re.compile(
        r'Authentication Id\s*:\s*(\d+)\s*;\s*(\d+)\s*\(([0-9a-fA-Fx:]+)\)',
        re.IGNORECASE
    ),
    'session_header_simple': re.compile(
        r'Authentication Id\s*:\s*(\d+)\s*;\s*(\d+)',
        re.IGNORECASE
    ),
    'session_type': re.compile(
        r'^Session\s*:\s*(.+)$',
        re.IGNORECASE | re.MULTILINE
    ),
    'user_name': re.compile(
        r'^User Name\s*:\s*(.+)$',
        re.IGNORECASE | re.MULTILINE
    ),
    'domain': re.compile(
        r'^Domain\s*:\s*(.+)$',
        re.IGNORECASE | re.MULTILINE
    ),
    'logon_server': re.compile(
        r'^Logon Server\s*:\s*(.+)$',
        re.IGNORECASE | re.MULTILINE
    ),
    'logon_time': re.compile(
        r'^Logon Time\s*:\s*(.+)$',
        re.IGNORECASE | re.MULTILINE
    ),
    'sid': re.compile(
        r'^SID\s*:\s*(S-[\d-]+)',
        re.IGNORECASE | re.MULTILINE
    ),

    # ========================================
    # Provider markers
    # ========================================
    'provider_msv': re.compile(r'^\s*msv\s*:', re.IGNORECASE),
    'provider_tspkg': re.compile(r'^\s*tspkg\s*:', re.IGNORECASE),
    'provider_wdigest': re.compile(r'^\s*wdigest\s*:', re.IGNORECASE),
    'provider_kerberos': re.compile(r'^\s*kerberos\s*:', re.IGNORECASE),
    'provider_ssp': re.compile(r'^\s*ssp\s*:', re.IGNORECASE),
    'provider_credman': re.compile(r'^\s*credman\s*:', re.IGNORECASE),

    # ========================================
    # Credential value patterns
    # ========================================
    'cred_username': re.compile(
        r'^\s*\*\s*Username\s*:\s*(.+)$',
        re.IGNORECASE | re.MULTILINE
    ),
    'cred_domain': re.compile(
        r'^\s*\*\s*Domain\s*:\s*(.+)$',
        re.IGNORECASE | re.MULTILINE
    ),
    'cred_password': re.compile(
        r'^\s*\*\s*Password\s*:\s*(.+)$',
        re.IGNORECASE | re.MULTILINE
    ),
    'cred_ntlm': re.compile(
        r'^\s*\*\s*NTLM\s*:\s*([a-fA-F0-9]{32})\s*$',
        re.IGNORECASE | re.MULTILINE
    ),
    'cred_sha1': re.compile(
        r'^\s*\*\s*SHA1\s*:\s*([a-fA-F0-9]{40})\s*$',
        re.IGNORECASE | re.MULTILINE
    ),
    'cred_lm': re.compile(
        r'^\s*\*\s*LM\s*:\s*([a-fA-F0-9]{32})\s*$',
        re.IGNORECASE | re.MULTILINE
    ),

    # ========================================
    # Ticket patterns (sekurlsa::tickets)
    # ========================================
    'ticket_group': re.compile(
        r'^\s*Group\s+(\d+)\s*-\s*(.+)$',
        re.IGNORECASE | re.MULTILINE
    ),
    'ticket_index': re.compile(
        r'^\s*\[(\d+)\]\s*$',
        re.MULTILINE
    ),
    'ticket_start_end_renew': re.compile(
        r'Start/End/MaxRenew:\s*(.+?)\s*;\s*(.+?)\s*;\s*(.+)',
        re.IGNORECASE
    ),
    'ticket_service_name': re.compile(
        r'Service Name\s*\(\d+\)\s*:\s*(.+?)\s*;\s*(.+?)\s*;\s*@\s*(.+)',
        re.IGNORECASE
    ),
    'ticket_service_simple': re.compile(
        r'Service Name\s*\([^)]+\)\s*:\s*(.+)',
        re.IGNORECASE
    ),
    'ticket_target_name': re.compile(
        r'Target Name\s*\([^)]+\)\s*:\s*(.+)',
        re.IGNORECASE
    ),
    'ticket_client_name': re.compile(
        r'Client Name\s*\(\d+\)\s*:\s*(.+?)\s*;\s*@\s*(.+)',
        re.IGNORECASE
    ),
    'ticket_flags': re.compile(
        r'Flags\s+([0-9a-fA-F]+)\s*:\s*(.+)',
        re.IGNORECASE
    ),
    'ticket_session_key': re.compile(
        r'Session Key\s*:\s*(\S+)\s*-\s*(\S+)',
        re.IGNORECASE
    ),
    'ticket_session_key_value': re.compile(
        r'^\s+([a-fA-F0-9]{64})\s*$',
        re.MULTILINE
    ),
    'ticket_encryption': re.compile(
        r'Ticket\s*:\s*(\S+)\s*-\s*(\S+)\s*;\s*kvno\s*=\s*(\d+)',
        re.IGNORECASE
    ),
    'ticket_saved': re.compile(
        r'\*\s*Saved to file\s+(.+\.kirbi)',
        re.IGNORECASE
    ),

    # ========================================
    # Detection patterns (for can_parse)
    # ========================================
    'mimikatz_banner': re.compile(
        r'mimikatz\s+\d+\.\d+',
        re.IGNORECASE
    ),
    'sekurlsa_cmd': re.compile(
        r'sekurlsa::',
        re.IGNORECASE
    ),
    'auth_id_marker': re.compile(
        r'Authentication Id\s*:',
        re.IGNORECASE
    ),
}


def is_hex_blob(value: str) -> bool:
    """Check if value is a hex blob (machine account password)"""
    if not value:
        return False
    # Machine passwords are hex blobs with spaces, like:
    # "41 61 ab fc cb 27 f6 1b 74 de 3c 24..."
    cleaned = value.replace(' ', '')
    if len(cleaned) < 64:  # Too short for machine password
        return False
    try:
        int(cleaned[:32], 16)  # Try to parse first 32 chars as hex
        return True
    except ValueError:
        return False


def is_null_value(value: str) -> bool:
    """Check if credential value is null/empty"""
    if not value:
        return True
    cleaned = value.strip().lower()
    return cleaned in ('(null)', 'null', '', 'n/a')


def clean_value(value: str) -> str:
    """Clean extracted value (strip whitespace, handle nulls)"""
    if not value:
        return ""
    cleaned = value.strip()
    if cleaned.lower() in ('(null)', 'null'):
        return '(null)'
    return cleaned
