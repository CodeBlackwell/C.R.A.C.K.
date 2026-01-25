# BloodHound Enhanced Report

**Generated:** 2026-01-04 12:14:38

---

## Data Inventory

**Domains:** RETURN.LOCAL

| Type | Count | Details |
|------|-------|---------|
| Users | 5 | 2 enabled |
| Computers | 0 | - |
| Groups | 52 | ACCOUNT OPERATORS@RETURN.LOCAL, ADMINISTRATORS@RETURN.LOCAL, BACKUP OPERATORS@RETURN.LOCAL |

**Relationships:** GenericAll: 110 | WriteDacl: 87 | MemberOf: 25 | DCSync: 4

## Attack Commands

## Attack Commands

---

## Quick Wins

### [-] AS-REP Roastable Users
**OSCP Relevance:** HIGH | **Results:** None

### [-] Kerberoastable Service Accounts
**OSCP Relevance:** HIGH | **Results:** None

### [-] High-Value Kerberoastable (Privileged + SPN)
**OSCP Relevance:** HIGH | **Results:** None

### [-] Unconstrained Delegation Systems
**OSCP Relevance:** HIGH | **Results:** None

### [-] Constrained Delegation Principals
**OSCP Relevance:** HIGH | **Results:** None

### [-] Users with Passwords in Description
**OSCP Relevance:** HIGH | **Results:** None

### [OK] Accounts with Password Never Expires
**OSCP Relevance:** MEDIUM | **Results:** 2

> Find accounts with non-expiring passwords. Often service accounts with weak passwords or credentials in documentation.

| User | IsPrivileged | Description |
| --- | --- | --- |
| SVC-PRINTER@RETURN.LOCAL | True | Service Account for Printer |
| ADMINISTRATOR@RETURN.LOCAL | True | Built-in account for administering the computer/domain |

### [-] Accounts That Never Logged In
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Computers Without LAPS
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] Pre-Windows 2000 Compatible Access Accounts
**OSCP Relevance:** LOW | **Results:** 1

> Find computers in Pre-Windows 2000 Compatible Access group. Legacy compatibility may expose vulnerabilities.

| Member | Type | ViaGroup |
| --- | --- | --- |
| AUTHENTICATED USERS@RETURN.LOCAL | ['Group'] | PRE-WINDOWS 2000 COMPATIBLE ACCESS@RETURN.LOCAL |

### [-] ReadGMSAPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### [-] ReadLAPSPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### [-] All gMSA Accounts
**OSCP Relevance:** HIGH | **Results:** None

---

## Lateral Movement

### [-] Non-DA Users with Local Admin on Workstations
**OSCP Relevance:** HIGH | **Results:** None

### [-] All Local Admins per Computer
**OSCP Relevance:** HIGH | **Results:** None

### [-] PSRemote Access (Evil-WinRM Targets)
**OSCP Relevance:** HIGH | **Results:** None

### [-] RDP Access Targets
**OSCP Relevance:** HIGH | **Results:** None

### [-] DCOM Execution Rights
**OSCP Relevance:** MEDIUM | **Results:** None

### Sessions on Specific Computer
*Skipped - requires variables: COMPUTER*

### All Computer Access for Specific User
*Skipped - requires variables: USER*

### All Users Who Can Access Specific Computer
*Skipped - requires variables: COMPUTER*

### [-] Computers Where Domain Users Are Local Admin
**OSCP Relevance:** HIGH | **Results:** None

### [-] Computers with Multiple Admin Paths
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Workstations with Domain Admin Sessions
**OSCP Relevance:** HIGH | **Results:** None

### [-] Cross-Trust Lateral Movement
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Coercion Targets (Unconstrained Delegation)
**OSCP Relevance:** HIGH | **Results:** None

### [-] SID History Abuse Paths
**OSCP Relevance:** HIGH | **Results:** None

### [-] Domain Trust Relationships
**OSCP Relevance:** HIGH | **Results:** None

---

## Privilege Escalation

### [OK] DCSync Rights
**OSCP Relevance:** HIGH | **Results:** 5

> Find principals with DCSync rights (GetChanges + GetChangesAll on Domain). Can perform secretsdump.py to extract all domain hashes.

| Principal | Type | Right |
| --- | --- | --- |
| ADMINISTRATORS@RETURN.LOCAL | ['Group'] | GetChangesAll |
| DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] | GetChangesAll |
| ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] | GetChanges |
| ENTERPRISE DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] | GetChanges |
| ADMINISTRATORS@RETURN.LOCAL | ['Group'] | GetChanges |

### [OK] GenericAll on High-Value Targets
**OSCP Relevance:** HIGH | **Results:** 25

> Find principals with GenericAll (full control) over privileged users, groups, or computers. Can reset passwords, modify group memberships, etc.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ACCOUNT OPERATORS@RETURN.LOCAL | DNSADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DNSADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | DNSADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | CLONEABLE DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@RETURN.LOCAL | CLONEABLE DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | CLONEABLE DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@RETURN.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | DOMAIN USERS@RETURN.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@RETURN.LOCAL | DOMAIN USERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN USERS@RETURN.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@RETURN.LOCAL | DOMAIN GUESTS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN GUESTS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | DOMAIN GUESTS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | DOMAIN COMPUTERS@RETURN.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@RETURN.LOCAL | DOMAIN COMPUTERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN COMPUTERS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | STORAGE REPLICA ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | STORAGE REPLICA ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@RETURN.LOCAL | STORAGE REPLICA ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@RETURN.LOCAL | HYPER-V ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | HYPER-V ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | HYPER-V ADMINISTRATORS@RETURN.LOCAL | ['Group'] |

### [-] Shadow Admins (Control over DA Users)
**OSCP Relevance:** HIGH | **Results:** None

### [OK] WriteDacl Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 56

> Find principals with WriteDacl on high-value targets. Can grant themselves GenericAll then escalate further.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ADMINISTRATORS@RETURN.LOCAL | DNSADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | KEY ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | KEY ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | KEY ADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ENTERPRISE KEY ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ENTERPRISE KEY ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | ENTERPRISE KEY ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | CLONEABLE DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | ACCOUNT OPERATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ACCOUNT OPERATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ACCOUNT OPERATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | SERVER OPERATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | SERVER OPERATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | SERVER OPERATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | DOMAIN USERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | DOMAIN GUESTS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | DOMAIN ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | DOMAIN ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | ENTERPRISE ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ENTERPRISE ADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ENTERPRISE ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | SCHEMA ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | SCHEMA ADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | SCHEMA ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | DOMAIN COMPUTERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | STORAGE REPLICA ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | HYPER-V ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | REPLICATOR@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | REPLICATOR@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | REPLICATOR@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | BACKUP OPERATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | BACKUP OPERATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | BACKUP OPERATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | PRINT OPERATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | PRINT OPERATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | PRINT OPERATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | SVC-PRINTER@RETURN.LOCAL | ['User'] |
| DOMAIN ADMINS@RETURN.LOCAL | SVC-PRINTER@RETURN.LOCAL | ['User'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | SVC-PRINTER@RETURN.LOCAL | ['User'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | KRBTGT@RETURN.LOCAL | ['User'] |
| ADMINISTRATORS@RETURN.LOCAL | KRBTGT@RETURN.LOCAL | ['User'] |
| DOMAIN ADMINS@RETURN.LOCAL | KRBTGT@RETURN.LOCAL | ['User'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ADMINISTRATOR@RETURN.LOCAL | ['User'] |
| DOMAIN ADMINS@RETURN.LOCAL | ADMINISTRATOR@RETURN.LOCAL | ['User'] |
| ADMINISTRATORS@RETURN.LOCAL | ADMINISTRATOR@RETURN.LOCAL | ['User'] |

### [OK] WriteOwner Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 56

> Find principals with WriteOwner on targets. Can take ownership, then WriteDacl, then GenericAll.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ADMINISTRATORS@RETURN.LOCAL | DNSADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | KEY ADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | KEY ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | KEY ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | ENTERPRISE KEY ADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ENTERPRISE KEY ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ENTERPRISE KEY ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | CLONEABLE DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ACCOUNT OPERATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | ACCOUNT OPERATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ACCOUNT OPERATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | SERVER OPERATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | SERVER OPERATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | SERVER OPERATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | DOMAIN USERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | DOMAIN GUESTS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | DOMAIN ADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | DOMAIN ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | ENTERPRISE ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ENTERPRISE ADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ENTERPRISE ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | SCHEMA ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | SCHEMA ADMINS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | SCHEMA ADMINS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | DOMAIN COMPUTERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | STORAGE REPLICA ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | HYPER-V ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | REPLICATOR@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | REPLICATOR@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | REPLICATOR@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | BACKUP OPERATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | BACKUP OPERATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | BACKUP OPERATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | PRINT OPERATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | PRINT OPERATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | PRINT OPERATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | SVC-PRINTER@RETURN.LOCAL | ['User'] |
| DOMAIN ADMINS@RETURN.LOCAL | SVC-PRINTER@RETURN.LOCAL | ['User'] |
| ADMINISTRATORS@RETURN.LOCAL | SVC-PRINTER@RETURN.LOCAL | ['User'] |
| DOMAIN ADMINS@RETURN.LOCAL | KRBTGT@RETURN.LOCAL | ['User'] |
| ADMINISTRATORS@RETURN.LOCAL | KRBTGT@RETURN.LOCAL | ['User'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | KRBTGT@RETURN.LOCAL | ['User'] |
| DOMAIN ADMINS@RETURN.LOCAL | ADMINISTRATOR@RETURN.LOCAL | ['User'] |
| ADMINISTRATORS@RETURN.LOCAL | ADMINISTRATOR@RETURN.LOCAL | ['User'] |
| ENTERPRISE ADMINS@RETURN.LOCAL | ADMINISTRATOR@RETURN.LOCAL | ['User'] |

### [-] AddKeyCredentialLink (Shadow Credentials)
**OSCP Relevance:** HIGH | **Results:** None

### [-] ForceChangePassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### [-] AddMember to Privileged Groups
**OSCP Relevance:** HIGH | **Results:** None

### [OK] Owns Relationships on Users/Groups
**OSCP Relevance:** HIGH | **Results:** 23

> Find principals who own other users or groups. Owner can grant themselves full control.

| Owner | OwnedObject | ObjectType |
| --- | --- | --- |
| DOMAIN ADMINS@RETURN.LOCAL | KEY ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ENTERPRISE KEY ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | CLONEABLE DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | READ-ONLY DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ACCOUNT OPERATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | SERVER OPERATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN USERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN GUESTS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ENTERPRISE ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | SCHEMA ADMINS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | DOMAIN COMPUTERS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | STORAGE REPLICA ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| ADMINISTRATORS@RETURN.LOCAL | HYPER-V ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | REPLICATOR@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | BACKUP OPERATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | PRINT OPERATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | ADMINISTRATORS@RETURN.LOCAL | ['Group'] |
| DOMAIN ADMINS@RETURN.LOCAL | SVC-PRINTER@RETURN.LOCAL | ['User'] |
| DOMAIN ADMINS@RETURN.LOCAL | KRBTGT@RETURN.LOCAL | ['User'] |
| DOMAIN ADMINS@RETURN.LOCAL | ADMINISTRATOR@RETURN.LOCAL | ['User'] |

### [-] GPO Abuse Paths
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] OU Control for Object Manipulation
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] AllExtendedRights Enumeration
**OSCP Relevance:** HIGH | **Results:** None

### [-] Read LAPS Password Rights
**OSCP Relevance:** HIGH | **Results:** None

### [OK] All Domain Admins
**OSCP Relevance:** HIGH | **Results:** 1

> List all members of Domain Admins group (including nested membership). Know your targets.

| DomainAdmin | Enabled | AdminCount |
| --- | --- | --- |
| ADMINISTRATOR@RETURN.LOCAL | True | True |

### [-] GenericWrite on Users
**OSCP Relevance:** HIGH | **Results:** None

### [-] WriteSPN for Targeted Kerberoasting
**OSCP Relevance:** HIGH | **Results:** None

### [-] WriteAccountRestrictions for RBCD
**OSCP Relevance:** HIGH | **Results:** None

### [-] SyncLAPSPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### [-] AddAllowedToAct Rights
**OSCP Relevance:** HIGH | **Results:** None

### [-] DCSync (Composite Check)
**OSCP Relevance:** HIGH | **Results:** None

### Check Account Operators Membership
*Skipped - requires variables: USER*

### [-] Check Exchange WriteDACL on Domain
**OSCP Relevance:** HIGH | **Results:** None

### Check Backup Operators Membership
*Skipped - requires variables: USER*

### Check Server Operators Membership
*Skipped - requires variables: USER*

### Check AddMember to Specific Group
*Skipped - requires variables: USER, TARGET_GROUP*

---

## Attack Chains

### [-] Full Attack Path: Owned User -> Pivot -> DA
**OSCP Relevance:** HIGH | **Results:** None

### [-] Shortest Path to Domain Admins
**OSCP Relevance:** HIGH | **Results:** None

### [-] All Paths to Domain Admin (Multi-Hop)
**OSCP Relevance:** HIGH | **Results:** None

### [-] Credential Harvest Opportunities
**OSCP Relevance:** HIGH | **Results:** None

### Find Paths Through Specific Computer
*Skipped - requires variables: COMPUTER*

### Shortest Path Between Two Users
*Skipped - requires variables: SOURCE_USER, TARGET_USER*

### [-] Path to High-Value Targets
**OSCP Relevance:** HIGH | **Results:** None

### [-] Circular Group Memberships
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

### [-] AS-REP Targets from Owned Context
**OSCP Relevance:** HIGH | **Results:** None

### Session Harvest Opportunities
*Skipped - requires variables: USER*

### Chained Privilege Escalation
*Skipped - requires variables: USER*

---

## Operational

### [-] Computers by Operating System (Find Legacy)
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Legacy Windows Systems
**OSCP Relevance:** HIGH | **Results:** None

### [OK] Password Age Distribution
**OSCP Relevance:** MEDIUM | **Results:** 2

> Find users with old passwords. Old passwords may be weak or appear in breach databases.

| User | PasswordLastSet | IsPrivileged | Description |
| --- | --- | --- | --- |
| SVC-PRINTER@RETURN.LOCAL | 4 years ago | True | Service Account for Printer |
| ADMINISTRATOR@RETURN.LOCAL | 4 years ago | True | Built-in account for administering the computer/domain |

### [OK] Inactive User Accounts
**OSCP Relevance:** MEDIUM | **Results:** 2

> Find enabled users who haven't logged in recently. May have default or forgotten passwords.

| User | LastLogon | Description |
| --- | --- | --- |
| SVC-PRINTER@RETURN.LOCAL | 4 years ago | Service Account for Printer |
| ADMINISTRATOR@RETURN.LOCAL | 1 hour ago | Built-in account for administering the computer/domain |

### [OK] Enabled vs Disabled Account Ratio
**OSCP Relevance:** LOW | **Results:** 2

> Count enabled vs disabled accounts. High disabled count may indicate account churn.

| Enabled | Count |
| --- | --- |
| True | 2 |
| False | 3 |

### [-] Domain Trust Relationships
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] Relationship Count by Type
**OSCP Relevance:** LOW | **Results:** 10

> Count all relationship types in the database. Helps understand AD structure and attack surface.

| Relationship | Count |
| --- | --- |
| GenericAll | 220 |
| WriteDacl | 171 |
| WriteOwner | 171 |
| GenericWrite | 165 |
| Owns | 103 |
| MemberOf | 50 |
| AllExtendedRights | 24 |
| GetChanges | 6 |
| AddKeyCredentialLink | 4 |
| GetChangesAll | 4 |

### [OK] High-Value Target Summary
**OSCP Relevance:** HIGH | **Results:** 9

> List all objects marked as high-value in BloodHound. Primary targets for attack planning.

| Target | Type | Description |
| --- | --- | --- |
| RETURN.LOCAL | ['Domain'] |  |
| ACCOUNT OPERATORS@RETURN.LOCAL | ['Group'] | Members can administer domain user and group accounts |
| ADMINISTRATORS@RETURN.LOCAL | ['Group'] | Administrators have complete and unrestricted access to the computer/domain |
| BACKUP OPERATORS@RETURN.LOCAL | ['Group'] | Backup Operators can override security restrictions for the sole purpose of backing up or restoring files |
| DOMAIN ADMINS@RETURN.LOCAL | ['Group'] | Designated administrators of the domain |
| DOMAIN CONTROLLERS@RETURN.LOCAL | ['Group'] | All domain controllers in the domain |
| ENTERPRISE ADMINS@RETURN.LOCAL | ['Group'] | Designated administrators of the enterprise |
| PRINT OPERATORS@RETURN.LOCAL | ['Group'] | Members can administer printers installed on domain controllers |
| SERVER OPERATORS@RETURN.LOCAL | ['Group'] | Members can administer domain servers |

---

## Summary

| Metric | Count |
| ------ | ----- |
| Total Queries | 79 |
| With Results | 13 |
| No Results | 48 |
| Skipped | 18 |
| Failed | 0 |

### Key Findings

- **WriteDacl Abuse Paths**: 56 results (Privilege Escalation)
- **WriteOwner Abuse Paths**: 56 results (Privilege Escalation)
- **GenericAll on High-Value Targets**: 25 results (Privilege Escalation)
- **Owns Relationships on Users/Groups**: 23 results (Privilege Escalation)
- **High-Value Target Summary**: 9 results (Operational)
- **DCSync Rights**: 5 results (Privilege Escalation)
- **All Domain Admins**: 1 results (Privilege Escalation)
