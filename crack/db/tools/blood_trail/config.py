"""
Configuration for BloodHound Edge Enhancer

Credentials:
  - Neo4j:      neo4j / Neo4j123
  - BloodHound: admin / 1PlaySmarter*
"""

from dataclasses import dataclass
from typing import Dict, Set

# Neo4j connection defaults
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "Neo4j123"

# Batch processing
DEFAULT_BATCH_SIZE = 500

# Well-known SIDs that appear in BloodHound data
# These are consistent across all Windows domains
WELL_KNOWN_SIDS: Dict[str, tuple] = {
    # Local groups (BUILTIN)
    "S-1-5-32-544": ("BUILTIN\\Administrators", "Group"),
    "S-1-5-32-545": ("BUILTIN\\Users", "Group"),
    "S-1-5-32-546": ("BUILTIN\\Guests", "Group"),
    "S-1-5-32-547": ("BUILTIN\\Power Users", "Group"),
    "S-1-5-32-548": ("BUILTIN\\Account Operators", "Group"),
    "S-1-5-32-549": ("BUILTIN\\Server Operators", "Group"),
    "S-1-5-32-550": ("BUILTIN\\Print Operators", "Group"),
    "S-1-5-32-551": ("BUILTIN\\Backup Operators", "Group"),
    "S-1-5-32-552": ("BUILTIN\\Replicator", "Group"),
    "S-1-5-32-554": ("BUILTIN\\Pre-Windows 2000 Compatible Access", "Group"),
    "S-1-5-32-555": ("BUILTIN\\Remote Desktop Users", "Group"),
    "S-1-5-32-556": ("BUILTIN\\Network Configuration Operators", "Group"),
    "S-1-5-32-557": ("BUILTIN\\Incoming Forest Trust Builders", "Group"),
    "S-1-5-32-558": ("BUILTIN\\Performance Monitor Users", "Group"),
    "S-1-5-32-559": ("BUILTIN\\Performance Log Users", "Group"),
    "S-1-5-32-560": ("BUILTIN\\Windows Authorization Access Group", "Group"),
    "S-1-5-32-561": ("BUILTIN\\Terminal Server License Servers", "Group"),
    "S-1-5-32-562": ("BUILTIN\\Distributed COM Users", "Group"),
    "S-1-5-32-568": ("BUILTIN\\IIS_IUSRS", "Group"),
    "S-1-5-32-569": ("BUILTIN\\Cryptographic Operators", "Group"),
    "S-1-5-32-573": ("BUILTIN\\Event Log Readers", "Group"),
    "S-1-5-32-574": ("BUILTIN\\Certificate Service DCOM Access", "Group"),
    "S-1-5-32-575": ("BUILTIN\\RDS Remote Access Servers", "Group"),
    "S-1-5-32-576": ("BUILTIN\\RDS Endpoint Servers", "Group"),
    "S-1-5-32-577": ("BUILTIN\\RDS Management Servers", "Group"),
    "S-1-5-32-578": ("BUILTIN\\Hyper-V Administrators", "Group"),
    "S-1-5-32-579": ("BUILTIN\\Access Control Assistance Operators", "Group"),
    "S-1-5-32-580": ("BUILTIN\\Remote Management Users", "Group"),

    # Special identities
    "S-1-1-0": ("Everyone", "Group"),
    "S-1-5-7": ("Anonymous Logon", "User"),
    "S-1-5-9": ("Enterprise Domain Controllers", "Group"),
    "S-1-5-11": ("Authenticated Users", "Group"),
    "S-1-5-18": ("Local System", "User"),
    "S-1-5-19": ("Local Service", "User"),
    "S-1-5-20": ("Network Service", "User"),
}

# Domain-relative RIDs (append to domain SID)
DOMAIN_RIDS: Dict[int, tuple] = {
    500: ("Administrator", "User"),
    501: ("Guest", "User"),
    502: ("krbtgt", "User"),
    512: ("Domain Admins", "Group"),
    513: ("Domain Users", "Group"),
    514: ("Domain Guests", "Group"),
    515: ("Domain Computers", "Group"),
    516: ("Domain Controllers", "Group"),
    517: ("Cert Publishers", "Group"),
    518: ("Schema Admins", "Group"),
    519: ("Enterprise Admins", "Group"),
    520: ("Group Policy Creator Owners", "Group"),
    521: ("Read-only Domain Controllers", "Group"),
    522: ("Cloneable Domain Controllers", "Group"),
    525: ("Protected Users", "Group"),
    526: ("Key Admins", "Group"),
    527: ("Enterprise Key Admins", "Group"),
    553: ("RAS and IAS Servers", "Group"),
    571: ("Allowed RODC Password Replication Group", "Group"),
    572: ("Denied RODC Password Replication Group", "Group"),
}

# ACE RightName -> Neo4j relationship type mapping
ACE_EDGE_MAPPINGS: Dict[str, str] = {
    # Ownership
    "Owns": "Owns",

    # Generic permissions
    "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite",

    # ACL modification
    "WriteDacl": "WriteDacl",
    "WriteOwner": "WriteOwner",

    # Extended rights
    "AllExtendedRights": "AllExtendedRights",
    "ForceChangePassword": "ForceChangePassword",
    "AddKeyCredentialLink": "AddKeyCredentialLink",

    # DCSync rights (critical for attack paths)
    "GetChanges": "GetChanges",
    "GetChangesAll": "GetChangesAll",
    "GetChangesInFilteredSet": "GetChangesInFilteredSet",

    # Group membership
    "AddMember": "AddMember",
    "AddSelf": "AddSelf",

    # Other
    "ReadLAPSPassword": "ReadLAPSPassword",
    "ReadGMSAPassword": "ReadGMSAPassword",
    "Enroll": "Enroll",
    "ManageCA": "ManageCA",
    "ManageCertificates": "ManageCertificates",
}

# Attack-path focused edge types (--preset attack-paths)
ATTACK_PATH_EDGES: Set[str] = {
    # Computer access
    "AdminTo",
    "CanPSRemote",
    "CanRDP",
    "ExecuteDCOM",
    "HasSession",

    # ACL abuse
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "Owns",
    "ForceChangePassword",
    "AddKeyCredentialLink",

    # DCSync
    "GetChanges",
    "GetChangesAll",

    # Membership
    "MemberOf",

    # Delegation
    "AllowedToDelegate",
    "AllowedToAct",
}


@dataclass
class Neo4jConfig:
    """Neo4j connection configuration"""
    uri: str = NEO4J_URI
    user: str = NEO4J_USER
    password: str = NEO4J_PASSWORD
    batch_size: int = DEFAULT_BATCH_SIZE
