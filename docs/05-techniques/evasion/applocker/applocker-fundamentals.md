# AppLocker Fundamentals Reference

## ELI5: What is AppLocker?

**The Castle Gatekeeper Analogy:**
Imagine your computer is a medieval castle. AppLocker is like the head gatekeeper who has a list of rules about who can enter. But instead of people, we're talking about programs trying to run.

**The Gatekeeper's Rules:**
- ✅ "Knights from our kingdom can enter" (Trusted Microsoft programs)
- ✅ "Merchants with proper papers can enter" (Signed software)
- ❌ "Unknown travelers must stay out" (Unsigned/unknown executables)
- 🤔 "Check the special list for exceptions" (Custom rules)

**Why Do Castles Need Gatekeepers?**
- **Ransomware** = Viking raiders trying to burn everything
- **Malware** = Spies sneaking in to steal secrets
- **Trojans** = "Gifts" that hide enemy soldiers
- **Living off the Land** = Using the castle's own tools against it

### The Eternal Bypass Game

Think of it like the Tom and Jerry cartoon:
- **Tom (AppLocker)**: Sets up elaborate traps and rules
- **Jerry (Attackers)**: Always finds creative ways around them
- **The House (System)**: Gets wrecked in the process

This creates an eternal cycle:
1. 🏰 **Defenders**: "We blocked all unauthorized executables!"
2. 🦹 **Attackers**: "Cool, we'll use PowerShell instead"
3. 🏰 **Defenders**: "We restricted PowerShell!"
4. 🦹 **Attackers**: "Nice, we'll use MSBuild"
5. 🏰 **Defenders**: "We blocked that too!"
6. 🦹 **Attackers**: "Have you heard of InstallUtil?"
7. ♾️ **And so it continues...**

## Understanding the Context

### Why Organizations Use Application Control

**The Business Case:**
- **Compliance**: "We need to prove we control what runs" (SOC2, ISO 27001)
- **Risk Reduction**: "Stop users from installing CryptoMiner2024.exe"
- **License Management**: "Only approved software = controlled costs"
- **Incident Response**: "If it's not whitelisted, it's suspicious"

**The Reality Check:**
- Most organizations implement AppLocker poorly
- Default rules have massive gaps
- Users hate it and find workarounds
- IT often creates broad exceptions that defeat the purpose

### Historical Evolution

```
1995: "Just use antivirus!"
     ↓
2005: "Antivirus isn't enough, add firewall!"
     ↓
2010: "We need application whitelisting!" (AppLocker introduced)
     ↓
2015: "AppLocker has too many bypasses, add EDR!"
     ↓
2020: "EDR is bypassed, add Zero Trust!"
     ↓
2024: "AI will save us!" (Spoiler: It won't)
```

## Quick Command Reference

### PowerShell Enumeration Commands

```powershell
# Check if AppLocker is configured
Get-AppLockerPolicy -Effective

# Export current policy to XML
Get-AppLockerPolicy -Effective -Xml > applocker_policy.xml

# Check specific rule types
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Test if a file would be blocked
Test-AppLockerPolicy -Path "C:\temp\suspicious.exe" -User Everyone

# Get AppLocker event logs
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" | Select-Object -First 20

# Check service status
Get-Service "AppIDSvc" | Select-Object Name, Status, StartType

# View rules by type
(Get-AppLockerPolicy -Effective).RuleCollections | Where {$_.RuleCollectionType -eq "Exe"}
```

### Registry Enumeration

```powershell
# Check if AppLocker policies exist
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\*"

# Check enforcement mode
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" -Name "EnforcementMode"

# List all rule GUIDs
Get-ChildItem -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\"
```

## Understanding AppLocker Architecture

### The Five Rule Types Explained

#### 1. Executable Rules (.exe, .com)
**What They Control:** Traditional executables
**Default Behavior:** Allow all if no rules defined
**Common Locations:**
- `%PROGRAMFILES%\*`
- `%WINDIR%\*`
- `%SYSTEMROOT%\system32\*`

**ELI5:** These are the main gates - they control who gets to be the star of the show (run as a process).

#### 2. Windows Installer Rules (.msi, .msp, .mst)
**What They Control:** Installation packages
**Why It Matters:** Installers often run with elevated privileges
**Bypass Potential:** MSI files can contain scripts and custom actions

**ELI5:** These control the delivery trucks bringing new software into the castle.

#### 3. Script Rules (.ps1, .vbs, .js, .cmd, .bat)
**What They Control:** Interpreted scripts
**Critical Note:** Only controls scripts run through Windows Script Host
**Major Gap:** Doesn't control scripts run through other interpreters

**ELI5:** These are supposed to control the castle's instruction manuals, but only if you read them the "official" way.

#### 4. DLL Rules (.dll, .ocx)
**What They Control:** Libraries loaded by processes
**Performance Impact:** HIGH - every DLL load is checked
**Reality:** Usually not enforced due to performance

**ELI5:** Imagine checking every single tool before a worker uses it - slows everything down!

#### 5. Packaged App Rules (Modern Windows Apps)
**What They Control:** Windows Store apps
**Relevance:** Low for most pentesting scenarios
**Note:** Different from classic Win32 applications

### Default Rules Analysis

#### The "Default Rules" Trap

When you create default rules, AppLocker generates:

```xml
<!-- Allow everyone to run from Program Files -->
<FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20"
              Name="(Default Rule) All files located in the Program Files folder"
              Description="Allows members of the Everyone group to run applications"
              UserOrGroupSid="S-1-1-0"
              Action="Allow">
  <Conditions>
    <FilePathCondition Path="%PROGRAMFILES%\*"/>
  </Conditions>
</FilePathRule>
```

**The Security Gaps:**
1. **Writable Subdirectories**: Some folders under Program Files are writable
2. **Missing Locations**: Doesn't cover all execution paths
3. **Version Confusion**: 32-bit vs 64-bit Program Files
4. **User Directories**: Completely ignored

### Enforcement Modes Deep Dive

#### Audit Mode
```powershell
# Set to Audit Only
Set-AppLockerPolicy -EnforcementMode AuditOnly
```

**What Happens:**
- ✅ Everything still runs
- 📝 Violations logged to event log
- 🔍 Good for discovering what would break
- ⚠️ No actual protection

**ELI5:** Like a security camera that records crimes but doesn't stop them.

#### Enforce Mode
```powershell
# Set to Enforce
Set-AppLockerPolicy -EnforcementMode Enabled
```

**What Happens:**
- ❌ Blocked programs won't run
- 📝 Blocks are logged
- 😤 Users get angry
- 🚨 Helpdesk tickets skyrocket

**ELI5:** The bouncer actually kicks people out, not just writes down their names.

### Policy Precedence and Conflicts

**Rule Priority Order:**
1. **Explicit Deny** (Always wins)
2. **Explicit Allow** (Beats implicit deny)
3. **Default Rules** (If no explicit rules)
4. **Implicit Deny** (Everything else)

**Example Conflict:**
```xml
<!-- Rule 1: Allow all from C:\Tools\ -->
<FilePathRule Action="Allow" Path="C:\Tools\*"/>

<!-- Rule 2: Deny hacktools.exe specifically -->
<FileHashRule Action="Deny" Hash="5D6F8C5A..."/>
```
**Result:** hacktools.exe is denied even if it's in C:\Tools\

## Common Misconfigurations

### Real-World Fail #1: The "Just Allow IT" Mistake

```xml
<!-- Actual rule from a pentest -->
<FilePathRule Name="Allow IT folder" Action="Allow">
  <Conditions>
    <FilePathCondition Path="\\fileserver\IT\*"/>
  </Conditions>
</FilePathRule>
```

**The Problem:**
- IT folder is often writable by IT staff
- Attackers compromise one IT account = game over
- No integrity checking on files
- Network path = MitM potential

### Real-World Fail #2: The "Version Wildcard" Disaster

```xml
<!-- Trying to allow Chrome updates -->
<FilePathRule Name="Allow Chrome" Action="Allow">
  <Conditions>
    <FilePathCondition Path="C:\Program Files\Google\Chrome\Application\*.exe"/>
  </Conditions>
</FilePathRule>
```

**The Problem:**
- Wildcard allows ANY executable name
- Attacker creates: `C:\Program Files\Google\Chrome\Application\totally_not_malware.exe`
- It runs because it matches the pattern!

### Real-World Fail #3: The "User Temp Exclusion"

```powershell
# "Users need to run installers from temp"
New-AppLockerPolicy -RuleType Path -Path "$env:TEMP\*" -Action Allow
```

**Why This is Terrible:**
- Every malware ever downloads to temp
- Legitimate excuse to execute from temp
- Defeats entire purpose of AppLocker

### Case Study: The Finance Department Bypass

**The Setup:**
- Finance department "needed" to run macros
- IT created exception for Excel with macros
- Policy: Allow anything signed by Microsoft

**The Attack:**
1. Send malicious Excel with macro
2. Macro spawns `rundll32.exe` (signed by Microsoft!)
3. Rundll32 loads attacker DLL
4. AppLocker sees Microsoft signature = Allowed
5. Complete compromise

## Lab Setup Guide

### Building Your AppLocker Lab

#### VM Requirements
```powershell
# VM 1: Domain Controller
- Windows Server 2019/2022
- 2 CPU, 4GB RAM
- Role: AD DC, DNS, Group Policy

# VM 2: Workstation
- Windows 10/11 Pro or Enterprise
- 2 CPU, 4GB RAM
- Joined to domain
```

#### Step 1: Enable AppLocker Service

```powershell
# On the workstation
# Check service status
Get-Service AppIDSvc

# Set to automatic and start
Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc

# Verify it's running
Get-Service AppIDSvc | Select Status, StartType
```

#### Step 2: Create Basic Policy via Group Policy

```powershell
# On Domain Controller
# Create new GPO
New-GPO -Name "AppLocker_Testing"

# Link to test OU
New-GPLink -Name "AppLocker_Testing" -Target "OU=TestComputers,DC=lab,DC=local"

# Edit in Group Policy Management:
# Computer Configuration > Policies > Windows Settings > Security Settings > Application Control Policies > AppLocker
```

#### Step 3: Configure Default Rules

```powershell
# Generate default rules for testing
$defaultRules = Get-AppLockerPolicy -Local

# Create executable rules
$exeRule = New-AppLockerPolicy -RuleType Publisher `
    -Publisher "O=Microsoft Corporation, L=Redmond, S=Washington, C=US" `
    -ProductName "*" `
    -BinaryName "*" `
    -Action Allow

# Apply policy
Set-AppLockerPolicy -PolicyObject $exeRule
```

#### Step 4: Testing Environment Setup

```powershell
# Create test directories
New-Item -Path "C:\TestApps" -ItemType Directory
New-Item -Path "C:\TestApps\Allowed" -ItemType Directory
New-Item -Path "C:\TestApps\Blocked" -ItemType Directory

# Create test executables
# Simple test binary (compile with Visual Studio or download)
# Place in both directories

# Create logging directory
New-Item -Path "C:\AppLockerLogs" -ItemType Directory
```

### Testing Your Rules

#### Basic Functionality Test

```powershell
# Test 1: Verify AppLocker is working
# Should work (system directory)
Start-Process "C:\Windows\System32\calc.exe"

# Should block (non-standard location)
Start-Process "C:\Temp\calc_copy.exe"

# Check event log for block
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" |
    Where-Object {$_.Id -eq 8003} |
    Select-Object -First 5
```

#### Policy Testing Script

```powershell
# Comprehensive testing script
$testPaths = @(
    "C:\Windows\System32\cmd.exe",
    "C:\Windows\SysWOW64\cmd.exe",
    "C:\Program Files\test.exe",
    "C:\ProgramData\test.exe",
    "C:\Users\Public\test.exe",
    "$env:TEMP\test.exe"
)

foreach ($path in $testPaths) {
    $result = Test-AppLockerPolicy -Path $path -User "lab\testuser"
    Write-Host "$path : $result"
}
```

### Monitoring and Logging

```powershell
# Enable AppLocker logging
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable

# Configure event log size
wevtutil sl "Microsoft-Windows-AppLocker/EXE and DLL" /ms:100000000

# Export logs for analysis
wevtutil epl "Microsoft-Windows-AppLocker/EXE and DLL" C:\AppLockerLogs\exe_dll.evtx

# Parse logs with PowerShell
Get-WinEvent -Path "C:\AppLockerLogs\exe_dll.evtx" |
    Select-Object TimeCreated, Id, Message |
    Export-Csv "C:\AppLockerLogs\analysis.csv"
```

## Detection and OPSEC Considerations

### Blue Team Indicators

**Event IDs to Monitor:**
- **8002**: Process would have been blocked (Audit mode)
- **8003**: Process was blocked (Enforce mode)
- **8004**: Process was allowed
- **8006**: Packaged app would have been blocked
- **8007**: Packaged app was blocked

### Red Team OPSEC

**Reconnaissance Phase:**
```powershell
# Stealthy AppLocker detection
# Check registry without admin rights
$applocker = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\*" -ErrorAction SilentlyContinue
if ($applocker) { Write-Host "AppLocker configured" }

# Check running services
$appIdSvc = Get-Service AppIDSvc -ErrorAction SilentlyContinue
if ($appIdSvc.Status -eq "Running") { Write-Host "AppLocker enforced" }
```

**Minimize Noise:**
- Test with Audit mode logs if possible
- Use living-off-the-land binaries
- Avoid repeated failed attempts
- Time attacks during busy periods

## Common Pitfalls and Solutions

### Pitfall 1: "We'll Just Block Everything"

**The Problem:** Over-restrictive policies break business
**The Result:** Exceptions everywhere, security weakened
**The Solution:** Start with audit, gradually restrict

### Pitfall 2: "Default Rules Are Enough"

**The Problem:** Default rules have known gaps
**The Result:** False sense of security
**The Solution:** Custom rules based on environment

### Pitfall 3: "Set and Forget"

**The Problem:** No monitoring or updates
**The Result:** Bypasses accumulate over time
**The Solution:** Regular reviews and updates

## Advanced Concepts

### Certificate Rules vs Path Rules

**Certificate Rules:**
- ✅ Harder to bypass
- ✅ Survives file moves
- ❌ Requires code signing
- ❌ Certificate management overhead

**Path Rules:**
- ✅ Simple to implement
- ✅ No certificates needed
- ❌ Easily bypassed
- ❌ Breaks with file movement

### AppLocker vs WDAC

**AppLocker:**
- User-mode enforcement
- Group Policy managed
- Easier bypasses
- Less performance impact

**Windows Defender Application Control (WDAC):**
- Kernel-mode enforcement
- Much harder to bypass
- Better security
- Harder to manage

## Conclusion

AppLocker is like a lock on your front door - it stops casual intruders but won't stop a determined attacker with the right tools. Understanding its fundamentals is crucial for both defenders implementing it correctly and pentesters finding creative ways around it.

Remember: Security is layers. AppLocker is one layer, not a complete solution.

## Lab Exercises

1. **Setup Challenge**: Create an AppLocker policy that allows only Calculator and Notepad
2. **Bypass Challenge**: Find 3 ways to run code despite the policy
3. **Detection Challenge**: Create PowerShell script to detect AppLocker bypasses
4. **Hardening Challenge**: Create the most restrictive (but functional) policy possible

## Additional Resources

- [Microsoft AppLocker Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)
- [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList)
- [Living Off The Land Binaries](https://lolbas-project.github.io/)