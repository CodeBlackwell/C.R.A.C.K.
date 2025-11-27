"""
Blood-trail Query to Attack Command Mappings

Maps blood-trail query IDs to CRACK command database IDs for automated
attack command suggestions based on BloodHound analysis results.
"""

from typing import Dict, List, Any

# Query ID -> List of command suggestions
# Each suggestion has: command_id (from CRACK db), context (why this command)
QUERY_COMMAND_MAPPINGS: Dict[str, Any] = {
    # ==================== QUICK WINS ====================
    "quick-asrep-roastable": [
        {"command_id": "impacket-getnpusers-asreproast", "context": "Extract AS-REP hash for offline cracking"},
        {"command_id": "rubeus-asreproast", "context": "Windows: AS-REP roast from domain-joined host"},
    ],
    "quick-kerberoastable": [
        {"command_id": "impacket-getuserspns-kerberoast", "context": "Request TGS tickets for service accounts"},
        {"command_id": "rubeus-kerberoast", "context": "Windows: Kerberoast from domain-joined host"},
    ],
    "quick-kerberoastable-privileged": [
        {"command_id": "impacket-getuserspns-kerberoast", "context": "Priority target - privileged account with SPN"},
    ],
    "quick-unconstrained-delegation": [
        # TODO: Add coercer commands when available
        {"command_id": "rubeus-kerberoast", "context": "Monitor for TGT capture after coercion"},
    ],
    "quick-constrained-delegation": [
        # S4U2Self/S4U2Proxy attack commands
        {"command_id": "rubeus-kerberoast", "context": "Request impersonation ticket via S4U2Self"},
    ],
    "quick-password-in-description": [
        # Direct credential - try lateral movement
        {"command_id": "crackmapexec-smb-spray", "context": "Validate discovered password"},
        {"command_id": "evil-winrm-shell", "context": "Test WinRM access with discovered creds"},
    ],

    # ==================== LATERAL MOVEMENT ====================
    "lateral-adminto-nonpriv": [
        {"command_id": "psexec-shell", "context": "Get SYSTEM shell via SMB (creates service)"},
        {"command_id": "wmiexec-shell", "context": "Semi-interactive shell via WMI (stealthier)"},
        {"command_id": "smbexec-shell", "context": "Shell via SMB without service creation"},
        {"command_id": "evil-winrm-shell", "context": "PowerShell remoting (if WinRM enabled)"},
    ],
    "lateral-all-admins-per-computer": [
        {"command_id": "psexec-shell", "context": "Target high-value system with admin access"},
    ],
    "lateral-rdp-targets": [
        {"command_id": "xfreerdp-connect", "context": "RDP connection (GUI access)"},
    ],
    "lateral-psremote-targets": [
        {"command_id": "evil-winrm-shell", "context": "PowerShell remoting via WinRM"},
        {"command_id": "ps-winrm-invoke-command", "context": "Windows: Invoke-Command to target"},
    ],
    "lateral-dcom-targets": [
        {"command_id": "wmiexec-shell", "context": "DCOM execution via WMI"},
    ],
    "lateral-sessions-on-computer": [
        # Credential harvest opportunity
        {"command_id": "psexec-shell", "context": "Get shell to dump credentials"},
    ],
    "lateral-user-access-all": [
        {"command_id": "psexec-shell", "context": "Lateral movement to accessible systems"},
    ],
    "lateral-da-sessions": [
        {"command_id": "psexec-shell", "context": "Target system with DA session for cred theft"},
    ],

    # ==================== PRIVILEGE ESCALATION ====================
    "privesc-dcsync-rights": [
        {"command_id": "ad-dcsync-impacket-secretsdump-user", "context": "DCSync via Impacket secretsdump"},
        {"command_id": "ad-dcsync-mimikatz-user", "context": "Windows: DCSync via Mimikatz"},
        {"command_id": "secretsdump-hashes", "context": "Dump all domain hashes"},
    ],
    "privesc-genericall-highvalue": [
        # ACL abuse - reset password or add to group
        {"command_id": "crackmapexec-smb-spray", "context": "After password reset, validate new creds"},
    ],
    "privesc-shadow-admins": [
        # Control over DA users
        {"command_id": "ad-dcsync-impacket-secretsdump-user", "context": "DCSync after gaining control"},
    ],
    "privesc-force-change-password": [
        # Password reset rights
        {"command_id": "crackmapexec-smb-spray", "context": "Validate after password reset"},
        {"command_id": "evil-winrm-shell", "context": "Access target after password change"},
    ],
    "privesc-genericwrite": [
        # Modify user attributes
        {"command_id": "impacket-getuserspns-kerberoast", "context": "After adding SPN - Kerberoast target"},
    ],
    "privesc-add-member": [
        {"command_id": "psexec-shell", "context": "After adding to admin group - lateral move"},
    ],
    "privesc-readgmsapassword": [
        {"command_id": "evil-winrm-shell", "context": "Use GMSA password for access"},
    ],

    # ==================== ATTACK CHAINS ====================
    # These trigger sequence building from path data
    "chain-shortest-to-da": "BUILD_SEQUENCE",
    "chain-all-paths-to-da": "BUILD_SEQUENCE",
    "chain-owned-to-pivot-to-da": "BUILD_SEQUENCE",
    "chain-credential-harvest": "BUILD_SEQUENCE",
    "chain-complete-compromise": "BUILD_SEQUENCE",
    "chain-lateral-to-privilege": "BUILD_SEQUENCE",

    # ==================== OWNED PRINCIPAL ====================
    "owned-what-can-access": [
        {"command_id": "psexec-shell", "context": "Access systems owned user can reach"},
    ],
    "owned-path-to-da": "BUILD_SEQUENCE",
    "owned-first-hop": [
        {"command_id": "psexec-shell", "context": "First lateral movement hop"},
        {"command_id": "evil-winrm-shell", "context": "Alternative: WinRM access"},
    ],
    "owned-admin-on": [
        {"command_id": "psexec-shell", "context": "Access admin targets"},
    ],
    "owned-cred-harvest-targets": [
        {"command_id": "psexec-shell", "context": "Harvest credentials from DA session"},
    ],
}


# Edge type -> Command mappings for building attack sequences
# Maps BloodHound relationship types to exploitation commands
EDGE_COMMAND_MAPPINGS: Dict[str, List[str]] = {
    # Access Edges
    "AdminTo": ["psexec-shell", "wmiexec-shell", "smbexec-shell"],
    "CanRDP": ["xfreerdp-connect"],
    "CanPSRemote": ["evil-winrm-shell", "ps-winrm-invoke-command"],
    "ExecuteDCOM": ["wmiexec-shell"],
    "HasSession": ["psexec-shell"],  # Get shell to harvest creds

    # Permission Edges (ACL abuse)
    "GenericAll": ["crackmapexec-smb-spray"],  # After password reset
    "GenericWrite": ["impacket-getuserspns-kerberoast"],  # After adding SPN
    "WriteDacl": ["crackmapexec-smb-spray"],  # After granting permissions
    "WriteOwner": ["crackmapexec-smb-spray"],  # After taking ownership
    "ForceChangePassword": ["crackmapexec-smb-spray"],  # After reset
    "AddMember": ["psexec-shell"],  # After adding to group
    "Owns": ["crackmapexec-smb-spray"],  # Full control

    # Privilege Edges
    "GetChanges": ["ad-dcsync-impacket-secretsdump-user"],
    "GetChangesAll": ["ad-dcsync-impacket-secretsdump-user"],
    "AllExtendedRights": ["ad-dcsync-impacket-secretsdump-user"],

    # Credential Edges
    "ReadGMSAPassword": ["evil-winrm-shell"],
    "ReadLAPSPassword": ["crackmapexec-smb-spray"],
    "AddKeyCredentialLink": ["evil-winrm-shell"],  # Shadow credentials

    # Delegation Edges
    "AllowedToDelegate": ["psexec-shell"],  # After S4U2Proxy
    "AllowedToAct": ["psexec-shell"],  # After RBCD

    # Membership
    "MemberOf": [],  # Informational - no direct command
}


# Variable extraction patterns
# Maps query result field names to command placeholder names
VARIABLE_MAPPINGS: Dict[str, str] = {
    # User fields
    "User": "<USERNAME>",
    "user": "<USERNAME>",
    "Principal": "<USERNAME>",
    "principal": "<USERNAME>",
    "Attacker": "<USERNAME>",
    "ServiceAccount": "<USERNAME>",
    "HighValueTarget": "<USERNAME>",

    # Computer/Target fields
    "Computer": "<TARGET>",
    "computer": "<TARGET>",
    "Target": "<TARGET>",
    "target": "<TARGET>",
    "Victim": "<TARGET>",
    "Machine": "<TARGET>",

    # Domain fields
    "Domain": "<DOMAIN>",
    "domain": "<DOMAIN>",

    # Other
    "DC": "<DC_IP>",
    "DomainController": "<DC_IP>",
    "SPNs": "<SPN>",
    "SPN": "<SPN>",
}


# Context templates for attack phases
# Used to generate descriptive context for each command
ATTACK_PHASE_CONTEXT = {
    "quick_wins": "Quick win - {vulnerability}",
    "lateral_movement": "Lateral movement via {edge_type}",
    "privilege_escalation": "Privilege escalation - {technique}",
    "credential_access": "Credential access - {method}",
    "persistence": "Establish persistence via {technique}",
}


# Commands that should always show the template (learning mode)
EDUCATIONAL_COMMANDS = {
    "impacket-getnpusers-asreproast",
    "impacket-getuserspns-kerberoast",
    "ad-dcsync-impacket-secretsdump-user",
    "psexec-shell",
    "evil-winrm-shell",
}


# Sensitive placeholders that should NOT be auto-filled
SENSITIVE_PLACEHOLDERS = {
    "<PASSWORD>",
    "<HASH>",
    "<NTLM_HASH>",
    "<LM_HASH>",
    "<TICKET>",
    "<PRIVATE_KEY>",
}
