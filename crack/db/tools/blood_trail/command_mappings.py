"""
Blood-trail Query to Attack Command Mappings v2

DRY mapping system that:
- Maps blood-trail query IDs to CRACK command database IDs
- Specifies which result fields contain arrays vs single values
- Defines access types for conditional command filtering
- Filters out invalid targets (groups misused as computers)
"""

from typing import Dict, List, Any, Optional


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

QUERY_COMMAND_MAPPINGS: Dict[str, Any] = {
    # ==================== LATERAL MOVEMENT (Array fields) ====================
    "lateral-adminto-nonpriv": {
        "commands": ["psexec-shell", "wmiexec-shell", "smbexec-shell"],
        "access_type": "AdminTo",
        "array_field": "AdminOnComputers",
        "user_field": "User",
    },
    "lateral-all-admins-per-computer": {
        "commands": ["psexec-shell"],
        "access_type": "AdminTo",
        "array_field": "LocalAdmins",  # Users who can admin
        "target_field": "Computer",     # Single computer per row
        "filter_groups": True,          # Filter out "DOMAIN ADMINS@..." etc.
    },
    "lateral-rdp-targets": {
        "commands": ["xfreerdp-connect"],
        "access_type": "CanRDP",
        "array_field": "RDPTargets",
        "user_field": "User",
    },
    "lateral-psremote-targets": {
        "commands": ["evil-winrm-shell"],
        "access_type": "CanPSRemote",
        "array_field": "PSRemoteTargets",
        "user_field": "User",
    },
    "lateral-dcom-targets": {
        "commands": ["wmiexec-shell"],
        "access_type": "ExecuteDCOM",
        "array_field": "DCOMTargets",
        "user_field": "User",
    },
    "lateral-da-sessions-workstations": {
        "commands": ["psexec-shell"],
        "access_type": "HasSession",
        "target_field": "Workstation",
        "array_field": "PrivilegedSessions",  # Who's logged in
        "context": "Credential harvest - privileged session on target",
    },
    "lateral-sessions-on-computer": {
        "commands": ["psexec-shell"],
        "access_type": "HasSession",
        "target_field": "Computer",
        "user_field": "LoggedOnUser",
        "context": "Credential harvest opportunity",
    },
    "lateral-user-access-all": {
        "commands": ["psexec-shell", "evil-winrm-shell", "xfreerdp-connect"],
        "target_field": "Target",
        "access_type_field": "AccessType",  # Dynamic: AdminTo|CanRDP|CanPSRemote
    },
    "lateral-domain-users-admin": {
        "commands": ["psexec-shell"],
        "access_type": "AdminTo",
        "target_field": "Computer",
        "context": "Domain Users = local admin (any user can compromise)",
    },
    "lateral-da-sessions": {
        "commands": ["psexec-shell"],
        "access_type": "HasSession",
        "target_field": "Computer",
        "context": "DA session - prime mimikatz target",
    },

    # ==================== QUICK WINS (Single value targets) ====================
    "quick-asrep-roastable": {
        "commands": ["impacket-getnpusers-asreproast"],
        "access_type": None,  # No lateral access check
        "target_is_user": True,
        "user_field": "User",
        "context": "AS-REP roast - no auth required",
    },
    "quick-kerberoastable": {
        "commands": ["impacket-getuserspns-kerberoast"],
        "access_type": None,
        "target_is_user": True,
        "user_field": "ServiceAccount",
        "context": "Kerberoast - request TGS for offline cracking",
    },
    "quick-kerberoastable-privileged": {
        "commands": ["impacket-getuserspns-kerberoast"],
        "access_type": None,
        "target_is_user": True,
        "user_field": "HighValueTarget",
        "context": "Priority Kerberoast - privileged account",
    },
    "quick-unconstrained-delegation": {
        "commands": ["rubeus-monitor"],
        "access_type": None,
        "target_field": "Computer",
        "context": "Unconstrained delegation - monitor for TGT capture",
    },
    "quick-constrained-delegation": {
        "commands": ["rubeus-s4u"],
        "access_type": None,
        "target_field": "Principal",
        "context": "Constrained delegation - S4U2Self/S4U2Proxy",
    },
    "quick-password-in-description": {
        "commands": ["crackmapexec-smb-spray", "evil-winrm-shell"],
        "access_type": None,
        "user_field": "User",
        "context": "Password in description - validate and use",
    },

    # ==================== PRIVILEGE ESCALATION ====================
    "privesc-dcsync-rights": {
        "commands": ["ad-dcsync-impacket-secretsdump-user"],
        "access_type": "DCSync",
        "principal_field": "Principal",
        "filter_groups": True,  # Filter "DOMAIN CONTROLLERS@..." etc.
        "domain_level": True,
        "context": "DCSync - dump domain hashes",
    },
    "privesc-genericall-highvalue": {
        "commands": ["bloodyad-genericall", "crackmapexec-smb-spray"],
        "access_type": "GenericAll",
        "user_field": "Attacker",
        "target_field": "Target",
        "context": "GenericAll - reset password or add to group",
    },
    "privesc-shadow-admins": {
        "commands": ["ad-dcsync-impacket-secretsdump-user"],
        "access_type": "GenericAll",
        "user_field": "Attacker",
        "target_field": "Victim",
        "context": "Shadow admin - control over DA",
    },
    "privesc-force-change-password": {
        "commands": ["rpcclient-setuserinfo", "crackmapexec-smb-spray"],
        "access_type": "ForceChangePassword",
        "user_field": "Attacker",
        "target_field": "Victim",
        "context": "ForceChangePassword - reset and use",
    },
    "privesc-genericwrite": {
        "commands": ["impacket-getuserspns-kerberoast"],
        "access_type": "GenericWrite",
        "user_field": "Attacker",
        "target_field": "Victim",
        "context": "GenericWrite - add SPN then Kerberoast",
    },
    "privesc-add-member": {
        "commands": ["psexec-shell"],
        "access_type": "AddMember",
        "user_field": "Attacker",
        "target_field": "Group",
        "context": "AddMember - add self to admin group",
    },
    "privesc-readgmsapassword": {
        "commands": ["gmsadumper", "evil-winrm-shell"],
        "access_type": "ReadGMSAPassword",
        "user_field": "Reader",
        "target_field": "GMSA",
        "context": "Read GMSA password - use for access",
    },

    # ==================== ATTACK CHAINS ====================
    "chain-shortest-to-da": "BUILD_SEQUENCE",
    "chain-all-paths-to-da": "BUILD_SEQUENCE",
    "chain-owned-to-pivot-to-da": "BUILD_SEQUENCE",
    "chain-credential-harvest": "BUILD_SEQUENCE",
    "chain-complete-compromise": "BUILD_SEQUENCE",
    "chain-lateral-to-privilege": "BUILD_SEQUENCE",

    # ==================== OWNED PRINCIPAL ====================
    "owned-what-can-access": {
        "commands": ["psexec-shell", "evil-winrm-shell", "xfreerdp-connect"],
        "target_field": "Target",
        "access_type_field": "AccessType",  # Dynamic from query result
    },
    "owned-path-to-da": "BUILD_SEQUENCE",
    "owned-first-hop": {
        "commands": ["psexec-shell", "evil-winrm-shell"],
        "target_field": "Target",
        "access_type_field": "AccessType",
    },
    "owned-admin-on": {
        "commands": ["psexec-shell", "wmiexec-shell"],
        "access_type": "AdminTo",
        "target_field": "Target",
    },
    "owned-cred-harvest-targets": {
        "commands": ["psexec-shell"],
        "access_type": "HasSession",
        "target_field": "Computer",
        "context": "Credential harvest from DA session",
    },
}


# =============================================================================
# EDGE TYPE -> COMMAND MAPPINGS (for attack sequence building)
# =============================================================================

EDGE_COMMAND_MAPPINGS: Dict[str, List[str]] = {
    # Access Edges
    "AdminTo": ["psexec-shell", "wmiexec-shell", "smbexec-shell"],
    "CanRDP": ["xfreerdp-connect"],
    "CanPSRemote": ["evil-winrm-shell"],
    "ExecuteDCOM": ["wmiexec-shell"],
    "HasSession": ["psexec-shell"],  # Get shell to harvest creds

    # Permission Edges (ACL abuse)
    "GenericAll": ["bloodyad-genericall", "crackmapexec-smb-spray"],
    "GenericWrite": ["impacket-getuserspns-kerberoast"],
    "WriteDacl": ["dacledit"],
    "WriteOwner": ["owneredit"],
    "ForceChangePassword": ["rpcclient-setuserinfo", "crackmapexec-smb-spray"],
    "AddMember": ["net-group-add"],
    "Owns": ["bloodyad-genericall"],

    # Privilege Edges
    "GetChanges": ["ad-dcsync-impacket-secretsdump-user"],
    "GetChangesAll": ["ad-dcsync-impacket-secretsdump-user"],
    "AllExtendedRights": ["ad-dcsync-impacket-secretsdump-user"],

    # Credential Edges
    "ReadGMSAPassword": ["gmsadumper", "evil-winrm-shell"],
    "ReadLAPSPassword": ["crackmapexec-smb-spray"],
    "AddKeyCredentialLink": ["pywhisker"],

    # Delegation Edges
    "AllowedToDelegate": ["rubeus-s4u"],
    "AllowedToAct": ["rbcd-attack"],

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
# ACCESS TYPE -> PHASE MAPPING (for output grouping)
# =============================================================================

ACCESS_TYPE_PHASES = {
    # Quick Wins
    None: "Quick Wins",

    # Lateral Movement
    "AdminTo": "Lateral Movement",
    "CanRDP": "Lateral Movement",
    "CanPSRemote": "Lateral Movement",
    "ExecuteDCOM": "Lateral Movement",
    "HasSession": "Lateral Movement",

    # Privilege Escalation
    "DCSync": "Privilege Escalation",
    "GenericAll": "Privilege Escalation",
    "GenericWrite": "Privilege Escalation",
    "WriteDacl": "Privilege Escalation",
    "WriteOwner": "Privilege Escalation",
    "ForceChangePassword": "Privilege Escalation",
    "AddMember": "Privilege Escalation",
    "ReadGMSAPassword": "Privilege Escalation",
    "ReadLAPSPassword": "Privilege Escalation",
    "AddKeyCredentialLink": "Privilege Escalation",
    "AllowedToDelegate": "Privilege Escalation",
    "AllowedToAct": "Privilege Escalation",
}
