# Privilege Escalation Alternative Commands

**EXTRACTION REPORT**

**Date**: 2025-10-09
**Source Plugins**:
- `/home/kali/OSCP/crack/track/services/linux_privesc_advanced.py`
- `/home/kali/OSCP/crack/track/services/linux_kernel_exploit.py`
- `/home/kali/OSCP/crack/track/services/linux_enumeration.py`

**Quality Standard**: HIGH IMPACT manual alternatives only

---

## Extracted Commands Summary

**Total Extracted**: 5 high-impact alternatives (+ 1 existing = 6 total)

All commands meet quality criteria:
- ✅ Manual alternatives to automated tools (LinPEAS, etc.)
- ✅ OSCP exam-viable (no Metasploit, no enterprise tools)
- ✅ Different techniques (not just flag variations)
- ✅ Immediate value (quick wins, common OSCP vectors)
- ✅ No duplicates (checked against existing registry)

---

## Commands Extracted

### 1. **Check Sudo Privileges** (`alt-sudo-list`)
```bash
sudo -l
```

**Why this matters**: First command to run on shell access - instant privesc if NOPASSWD found

**OSCP Relevance**: HIGH - Common exam vector, GTFOBins exploitation

**Key Success Indicators**:
- NOPASSWD entries (execute without password)
- Specific binaries listed (check GTFOBins)

**Next Steps**:
- Check https://gtfobins.github.io/ for exploitation
- Look for wildcard injection vulnerabilities

**Educational Value**: Teaches sudo permission model and GTFOBins usage

---

### 2. **Find File Capabilities** (`alt-linux-capabilities`)
```bash
getcap -r / 2>/dev/null
```

**Why this matters**: Alternative to SUID for privilege escalation (less common, often overlooked)

**OSCP Relevance**: HIGH - Bypasses traditional SUID checks

**Key Success Indicators**:
- CAP_SETUID (instant privesc)
- CAP_DAC_READ_SEARCH (read any file including /etc/shadow)

**Next Steps**:
- If CAP_SETUID found: use binary to escalate to root
- If CAP_DAC_READ_SEARCH: read /etc/shadow and crack hashes

**Educational Value**: Teaches Linux capabilities system vs traditional permissions

---

### 3. **Check Kernel Version** (`alt-kernel-version-check`)
```bash
uname -a && cat /proc/version
```

**Why this matters**: Essential for kernel exploit research - old kernels have known exploits

**OSCP Relevance**: HIGH - Kernel exploits common on older OSCP boxes

**Key Success Indicators**:
- Kernel version displayed (e.g., 4.4.0-116-generic)
- Architecture identified (x86_64, i686)
- Build date shown (older = more vulnerabilities)

**Next Steps**:
- `searchsploit "Linux Kernel <version>"`
- Download linux-exploit-suggester.sh
- Check lucyoa/kernel-exploits on GitHub

**Educational Value**: Teaches kernel version enumeration and exploit research workflow

---

### 4. **Enumerate Cron Jobs** (`alt-cron-enumeration`)
```bash
cat /etc/crontab; ls -la /etc/cron.*; crontab -l
```

**Why this matters**: Writable cron scripts run by root = instant privesc

**OSCP Relevance**: HIGH - Classic OSCP privilege escalation vector

**Key Success Indicators**:
- Cron jobs listed
- Scripts referenced in cron
- World-writable scripts found

**Next Steps**:
- Check script permissions: `ls -la /path/to/script`
- If writable, inject reverse shell
- Monitor execution: `watch -n 1 ps aux`

**Educational Value**: Teaches scheduled task enumeration and exploitation

---

### 5. **Check NFS no_root_squash** (`alt-nfs-no-root-squash`)
```bash
cat /etc/exports
```

**Why this matters**: Mount as root from attacker machine, create SUID binary on target

**OSCP Relevance**: HIGH - Classic OSCP privesc technique

**Key Success Indicators**:
- NFS exports found
- `no_root_squash` option present
- Writable exports with `*` or attacker IP

**Next Steps**:
- On attacker: `showmount -e <TARGET>`
- Mount share: `mount -t nfs <TARGET>:/share /mnt`
- Create SUID binary on share as root
- Execute SUID binary on target for root shell

**Educational Value**: Teaches NFS misconfigurations and remote exploitation

---

## Testing Results

**Test Suite**: `/home/kali/OSCP/crack/track/tests/test_privilege_escalation_alternatives.py`

**Results**: ✅ **35/35 tests passed (100%)**

**Test Coverage**:
- Command syntax validation
- OSCP relevance verification
- Success/failure indicators completeness
- Educational metadata (flag explanations, notes)
- Quick win tagging accuracy
- No duplicate commands
- Next steps guidance quality

---

## Quality Gate Results

Each command passed all quality checks:

✅ **Would I use this in an exam?** - YES (all commands are quick, safe enumeration)
✅ **Is every field necessary?** - YES (minimal, essential fields only)
✅ **Could I explain this in 30 seconds?** - YES (clear, concise descriptions)
✅ **Does this duplicate existing alternative?** - NO (checked registry)
✅ **Will the test prove value to OSCP student?** - YES (exam-focused tests)

---

## Commands NOT Extracted

**Why some commands were excluded:**

1. **Docker/LXD group checks** - Too specialized, not manual alternative to automated tool
2. **LD_PRELOAD exploitation** - Requires compilation, not pure enumeration
3. **PATH hijacking** - Exploitation technique, not enumeration
4. **Process enumeration** - Already covered by `ps aux` (too basic)
5. **Network connections** - Already covered by `netstat`/`ss` (too basic)

**Exclusion Principle**: Only extracted commands that are:
- Manual alternatives to LinPEAS/automated enumeration
- Quick wins (< 5 minutes)
- Common OSCP vectors (high success rate)
- No compilation/file upload required

---

## File Locations

**Alternative Commands**:
`/home/kali/OSCP/crack/track/alternatives/commands/privilege_escalation.py`

**Test Suite**:
`/home/kali/OSCP/crack/track/tests/test_privilege_escalation_alternatives.py`

**This Report**:
`/home/kali/OSCP/crack/track/alternatives/PRIVILEGE_ESCALATION_ALTERNATIVES.md`

---

## Usage Examples

### View All Alternatives
```python
from alternatives.commands.privilege_escalation import ALTERNATIVES

for cmd in ALTERNATIVES:
    print(f"{cmd.name}: {cmd.command_template}")
```

### Filter by Quick Wins
```python
quick_wins = [cmd for cmd in ALTERNATIVES if 'QUICK_WIN' in cmd.tags]
print(f"Found {len(quick_wins)} quick win commands")
```

### Get Command by ID
```python
sudo_check = next(cmd for cmd in ALTERNATIVES if cmd.id == 'alt-sudo-list')
print(sudo_check.description)
print(sudo_check.success_indicators)
```

---

## Integration Points

These alternatives integrate with CRACK Track:

1. **Auto-suggestion**: When LinPEAS fails, suggest manual alternatives
2. **Task tree**: Display as alternative tasks under privilege escalation
3. **Command reference**: Accessible via `crack reference privilege-escalation`
4. **Interactive mode**: Present as manual options when automation blocked

---

## Future Enhancements

**NOT included in this extraction** (requires separate analysis):

- Windows privilege escalation alternatives
- Container escape enumeration
- Active Directory enumeration (separate category)
- Post-exploitation persistence techniques

**These require dedicated extraction from:**
- `windows_privesc.py`
- `linux_container_escape.py`
- `ad_enumeration.py`
- `linux_persistence.py`

---

## Conclusion

**Extraction Success**: ✅ 5 high-impact alternatives extracted

**Quality Achieved**: All commands meet OSCP exam requirements:
- No tools required (just standard Linux commands)
- Quick execution (< 5 minutes each)
- High success rate (common OSCP vectors)
- Educational value (flag explanations, next steps)

**Test Coverage**: 100% (35/35 tests passing)

**Ready for OSCP Exam**: YES - All commands executable in exam environment

---

**Generated**: 2025-10-09
**By**: Claude (Alternative Command Miner)
**For**: CRACK Track - OSCP Preparation Toolkit
