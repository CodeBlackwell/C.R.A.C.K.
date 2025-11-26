# BloodHound Enhanced Report

**Generated:** 2025-11-26 02:41:35

---

## Quick Wins

### ✅ AS-REP Roastable Users
**OSCP Relevance:** HIGH | **Results:** 2

> Find users with Kerberos pre-authentication disabled (dontreqpreauth=true). These can be AS-REP roasted without authentication using GetNPUsers.py.

| User | IsPrivileged | Description |
| --- | --- | --- |
| MIKE@CORP.COM | False | None |
| DAVE@CORP.COM | False | None |

### ✅ Kerberoastable Service Accounts
**OSCP Relevance:** HIGH | **Results:** 1

> Find users with Service Principal Names (SPNs). These can be Kerberoasted to obtain TGS hashes for offline cracking.

| ServiceAccount | SPNs | IsPrivileged | Description |
| --- | --- | --- | --- |
| IIS_SERVICE@CORP.COM | ['HTTP/web04.corp.com', 'HTTP/web04', 'HTTP/web04. | False | None |

### ⚪ High-Value Kerberoastable (Privileged + SPN)
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Unconstrained Delegation Systems
**OSCP Relevance:** HIGH | **Results:** 1

> Find computers with unconstrained delegation enabled. These can be abused to capture TGTs from authenticating users (printer bug, coercion attacks).

| Computer | OS | Description |
| --- | --- | --- |
| DC1.CORP.COM | WINDOWS SERVER 2022 STANDARD | None |

### ⚪ Constrained Delegation Principals
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Users with Passwords in Description
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Accounts with Password Never Expires
**OSCP Relevance:** MEDIUM | **Results:** 8

> Find accounts with non-expiring passwords. Often service accounts with weak passwords or credentials in documentation.

| User | IsPrivileged | Description |
| --- | --- | --- |
| JEFFADMIN@CORP.COM | True | None |
| ADMINISTRATOR@CORP.COM | True | Built-in account for administering the computer/do |
| JEN@CORP.COM | False | None |
| PETE@CORP.COM | False | None |
| IIS_SERVICE@CORP.COM | False | None |
| JEFF@CORP.COM | False | None |
| DAVE@CORP.COM | False | None |
| STEPHANIE@CORP.COM | False | None |

### ✅ Accounts That Never Logged In
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find accounts that have never logged in. May have default or documented passwords.

| User | Description | Created |
| --- | --- | --- |
| MIKE@CORP.COM | None | 1763971889.0 |

### ✅ Computers Without LAPS
**OSCP Relevance:** MEDIUM | **Results:** 5

> Find computers that don't have LAPS deployed. Local admin passwords may be reused or weak.

| Computer | OS |
| --- | --- |
| CLIENT74.CORP.COM | WINDOWS 11 ENTERPRISE |
| CLIENT75.CORP.COM | WINDOWS 11 PRO |
| CLIENT76.CORP.COM | WINDOWS 10 PRO |
| FILES04.CORP.COM | WINDOWS SERVER 2022 STANDARD |
| WEB04.CORP.COM | WINDOWS SERVER 2022 STANDARD |

### ✅ Pre-Windows 2000 Compatible Access Accounts
**OSCP Relevance:** LOW | **Results:** 1

> Find computers in Pre-Windows 2000 Compatible Access group. Legacy compatibility may expose vulnerabilities.

| Member | Type | ViaGroup |
| --- | --- | --- |
| AUTHENTICATED USERS@CORP.COM | ['Group', 'Base'] | PRE-WINDOWS 2000 COMPATIBLE ACCESS@CORP.COM |

---

## Lateral Movement

### ⚪ Non-DA Users with Local Admin on Workstations
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ All Local Admins per Computer
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ PSRemote Access (Evil-WinRM Targets)
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ RDP Access Targets
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ DCOM Execution Rights
**OSCP Relevance:** MEDIUM | **Results:** None

### Sessions on Specific Computer
*Skipped - requires variables: COMPUTER*

### All Computer Access for Specific User
*Skipped - requires variables: USER*

### All Users Who Can Access Specific Computer
*Skipped - requires variables: COMPUTER*

### ⚪ Computers Where Domain Users Are Local Admin
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Computers with Multiple Admin Paths
**OSCP Relevance:** MEDIUM | **Results:** None

### ⚪ Workstations with Domain Admin Sessions
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Cross-Trust Lateral Movement
**OSCP Relevance:** MEDIUM | **Results:** None

---

## Privilege Escalation

### ✅ DCSync Rights
**OSCP Relevance:** HIGH | **Results:** 6

> Find principals with DCSync rights (GetChanges + GetChangesAll on Domain). Can perform secretsdump.py to extract all domain hashes.

| Principal | Type | Right |
| --- | --- | --- |
| DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] | GetChangesAll |
| ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |
| ENTERPRISE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |
| ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] | GetChanges |

### ✅ GenericAll on High-Value Targets
**OSCP Relevance:** HIGH | **Results:** 26

> Find principals with GenericAll (full control) over privileged users, groups, or computers. Can reset passwords, modify group memberships, etc.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ACCOUNT OPERATORS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
*... and 1 more rows*

### ⚪ Shadow Admins (Control over DA Users)
**OSCP Relevance:** HIGH | **Results:** None

### ✅ WriteDacl Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 69

> Find principals with WriteDacl on high-value targets. Can grant themselves GenericAll then escalate further.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| DOMAIN ADMINS@CORP.COM | MARIA@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | MARIA@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | MARIA@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
*... and 44 more rows*

### ✅ WriteOwner Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 65

> Find principals with WriteOwner on targets. Can take ownership, then WriteDacl, then GenericAll.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| DOMAIN ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | MARIA@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | REPLICATOR@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | REPLICATOR@CORP.COM | ['Group', 'Base'] |
*... and 40 more rows*

### ⚪ AddKeyCredentialLink (Shadow Credentials)
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ ForceChangePassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ AddMember to Privileged Groups
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Owns Relationships on Users/Groups
**OSCP Relevance:** HIGH | **Results:** 27

> Find principals who own other users or groups. Owner can grant themselves full control.

| Owner | OwnedObject | ObjectType |
| --- | --- | --- |
| DOMAIN ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | REPLICATOR@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | MARIA@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
*... and 2 more rows*

### ⚪ GPO Abuse Paths
**OSCP Relevance:** MEDIUM | **Results:** None

### ⚪ OU Control for Object Manipulation
**OSCP Relevance:** MEDIUM | **Results:** None

### ⚪ AllExtendedRights Enumeration
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Read LAPS Password Rights
**OSCP Relevance:** HIGH | **Results:** None

### ✅ All Domain Admins
**OSCP Relevance:** HIGH | **Results:** 3

> List all members of Domain Admins group (including nested membership). Know your targets.

| DomainAdmin | Enabled | AdminCount |
| --- | --- | --- |
| MARIA@CORP.COM | True | True |
| JEFFADMIN@CORP.COM | True | True |
| ADMINISTRATOR@CORP.COM | True | True |

### ⚪ GenericWrite on Users
**OSCP Relevance:** HIGH | **Results:** None

---

## Attack Chains

### ⚪ Full Attack Path: Owned User -> Pivot -> DA
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Shortest Path to Domain Admins
**OSCP Relevance:** HIGH | **Results:** 7

> Find shortest privilege escalation path from any enabled user to Domain Admins group.

| StartUser | Hops | Path |
| --- | --- | --- |
| MIKE@CORP.COM | 3 | ['MIKE@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@ |
| JEN@CORP.COM | 3 | ['JEN@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@C |
| PETE@CORP.COM | 3 | ['PETE@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@ |
| IIS_SERVICE@CORP.COM | 3 | ['IIS_SERVICE@CORP.COM', 'CORP.COM', 'USERS@CORP.C |
| JEFF@CORP.COM | 3 | ['JEFF@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@ |
| DAVE@CORP.COM | 3 | ['DAVE@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@ |
| STEPHANIE@CORP.COM | 3 | ['STEPHANIE@CORP.COM', 'DOMAIN USERS@CORP.COM', 'U |

### ⚪ All Paths to Domain Admin (Multi-Hop)
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Credential Harvest Opportunities
**OSCP Relevance:** HIGH | **Results:** None

### Find Paths Through Specific Computer
*Skipped - requires variables: COMPUTER*

### Shortest Path Between Two Users
*Skipped - requires variables: SOURCE_USER, TARGET_USER*

### ⚪ Path to High-Value Targets
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Circular Group Memberships
**OSCP Relevance:** LOW | **Results:** None

---

## Owned Principal

### What Can Owned User Access?
*Skipped - requires variables: USER*

### Quick Wins from Owned User Context
*Skipped - requires variables: USER*

### Path to DA from Owned User
*Skipped - requires variables: USER*

### Owned User Group Memberships
*Skipped - requires variables: USER*

### Outbound Object Control from Owned
*Skipped - requires variables: USER*

### First Hop Lateral Movement
*Skipped - requires variables: USER*

### Kerberoastable from Owned Context
*Skipped - requires variables: USER*

### ✅ AS-REP Targets from Owned Context
**OSCP Relevance:** HIGH | **Results:** 2

> Find AS-REP roastable accounts. These can be attacked without any additional access.

| User | IsPrivileged | Description |
| --- | --- | --- |
| MIKE@CORP.COM | False | None |
| DAVE@CORP.COM | False | None |

### Session Harvest Opportunities
*Skipped - requires variables: USER*

### Chained Privilege Escalation
*Skipped - requires variables: USER*

---

## Operational

### ✅ Computers by Operating System (Find Legacy)
**OSCP Relevance:** MEDIUM | **Results:** 4

> Enumerate computers grouped by OS. Legacy systems (2008, 2003, XP) are often more vulnerable.

| OS | Computers | Count |
| --- | --- | --- |
| WINDOWS SERVER 2022 STANDARD | ['FILES04.CORP.COM', 'WEB04.CORP.COM', 'DC1.CORP.C | 3 |
| WINDOWS 10 PRO | ['CLIENT76.CORP.COM'] | 1 |
| WINDOWS 11 ENTERPRISE | ['CLIENT74.CORP.COM'] | 1 |
| WINDOWS 11 PRO | ['CLIENT75.CORP.COM'] | 1 |

### ⚪ Legacy Windows Systems
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Password Age Distribution
**OSCP Relevance:** MEDIUM | **Results:** 10

> Find users with old passwords. Old passwords may be weak or appear in breach databases.

| User | PasswordLastSet | IsPrivileged | Description |
| --- | --- | --- | --- |
| PETE@CORP.COM | 1662493314.0 | False | None |
| JEFF@CORP.COM | 1763971888.0 | False | None |
| DAVE@CORP.COM | 1763971888.0 | False | None |
| STEPHANIE@CORP.COM | 1763971888.0 | False | None |
| ADMINISTRATOR@CORP.COM | 1763971888.0 | True | Built-in account for administering the computer/do |
| MARIA@CORP.COM | 1763971889.0 | True | None |
| JEFFADMIN@CORP.COM | 1763971889.0 | True | None |
| MIKE@CORP.COM | 1763971889.0 | False | None |
| JEN@CORP.COM | 1763971889.0 | False | None |
| IIS_SERVICE@CORP.COM | 1763971889.0 | False | None |

### ✅ Inactive User Accounts
**OSCP Relevance:** MEDIUM | **Results:** 9

> Find enabled users who haven't logged in recently. May have default or forgotten passwords.

| User | LastLogon | Description |
| --- | --- | --- |
| PETE@CORP.COM | 1675248162.0 | None |
| IIS_SERVICE@CORP.COM | 1677670802.0 | None |
| STEPHANIE@CORP.COM | 1695805630.0 | None |
| JEFF@CORP.COM | 1702972516.0 | None |
| JEN@CORP.COM | 1704705963.0 | None |
| JEFFADMIN@CORP.COM | 1704714421.0 | None |
| ADMINISTRATOR@CORP.COM | 1763971888.0 | Built-in account for administering the computer/do |
| MARIA@CORP.COM | 1763971909.0 | None |
| DAVE@CORP.COM | 1763972907.0 | None |

### ✅ Enabled vs Disabled Account Ratio
**OSCP Relevance:** LOW | **Results:** 3

> Count enabled vs disabled accounts. High disabled count may indicate account churn.

| Enabled | Count |
| --- | --- |
| None | 2 |
| True | 10 |
| False | 2 |

### ⚪ Domain Trust Relationships
**OSCP Relevance:** MEDIUM | **Results:** None

### ✅ Relationship Count by Type
**OSCP Relevance:** LOW | **Results:** 30

> Count all relationship types in the database. Helps understand AD structure and attack surface.

| Relationship | Count |
| --- | --- |
| HAS_INDICATOR | 20224 |
| TAGGED | 14720 |
| HAS_FLAG | 5682 |
| ALTERNATIVE | 1382 |
| REFERENCES_COMMAND | 876 |
| PREREQUISITE | 636 |
| HAS_STEP | 412 |
| GenericAll | 380 |
| EXECUTES | 348 |
| WriteDacl | 283 |
| WriteOwner | 276 |
| WriteOwnerRaw | 276 |
| GenericWrite | 221 |
| Owns | 180 |
| OwnsRaw | 180 |
| MemberOf | 112 |
| DEMONSTRATES | 106 |
| Contains | 94 |
| AddKeyCredentialLink | 56 |
| AllExtendedRights | 44 |
| TEACHES_SKILL | 30 |
| REQUIRES_SKILL | 18 |
| GetChangesAll | 6 |
| GetChanges | 6 |
| GPLink | 4 |
*... and 5 more rows*

### ✅ High-Value Target Summary
**OSCP Relevance:** HIGH | **Results:** 9

> List all objects marked as high-value in BloodHound. Primary targets for attack planning.

| Target | Type | Description |
| --- | --- | --- |
| CORP.COM | ['Base', 'Domain', 'Tag_Tier_Zero'] |  |
| ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain user and group accou |
| ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Administrators have complete and unrestricted acce |
| BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Backup Operators can override security restriction |
| DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Designated administrators of the domain |
| DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | All domain controllers in the domain |
| ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Designated administrators of the enterprise |
| PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer printers installed on domai |
| SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain servers |

---

## Summary

| Metric | Count |
| ------ | ----- |
| Total Queries | 63 |
| With Results | 21 |
| No Results | 28 |
| Skipped | 14 |
| Failed | 0 |

### Key Findings

- **WriteDacl Abuse Paths**: 69 results (Privilege Escalation)
- **WriteOwner Abuse Paths**: 65 results (Privilege Escalation)
- **Owns Relationships on Users/Groups**: 27 results (Privilege Escalation)
- **GenericAll on High-Value Targets**: 26 results (Privilege Escalation)
- **High-Value Target Summary**: 9 results (Operational)
- **Shortest Path to Domain Admins**: 7 results (Attack Chains)
- **DCSync Rights**: 6 results (Privilege Escalation)
- **All Domain Admins**: 3 results (Privilege Escalation)
- **AS-REP Roastable Users**: 2 results (Quick Wins)
- **AS-REP Targets from Owned Context**: 2 results (Owned Principal)
- **Kerberoastable Service Accounts**: 1 results (Quick Wins)
- **Unconstrained Delegation Systems**: 1 results (Quick Wins)
