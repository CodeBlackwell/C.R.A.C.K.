# Remapping Phase - Complete

**Date**: 2025-11-26  
**Status**: COMPLETE  
**Time**: ~10 minutes

---

## Results

Successfully remapped 5 broken references to existing command IDs:

**Before**: 38 broken references  
**After**: 33 broken references  
**Reduction**: 5 violations (13% reduction)

---

## Changes Made

| Broken ID | Remapped To | File Updated | Line |
|-----------|-------------|--------------|------|
| `as-rep-roasting` | `impacket-getnpusers-asreproast` | active-directory/ad-user-enumeration.json | 59 |
| `john-list` | `john-show-cracked` | enumeration/auto-generated-full-syntax-enumeration.json | 137 |
| `msfconsole` | **REMOVED** (invalid reference) | exploitation/metasploit-core.json | 123-124 |
| `winpeas` | `win-privesc-winpeas` | post-exploit/auto-generated-full-syntax-post-exploit.json | 1009 |
| `wfuzz-list` | `wfuzz-dir` | enumeration/tool-specific.json | 49 |

---

## Files Modified (5)

1. **data/commands/active-directory/ad-user-enumeration.json**
   - Command: `kerbrute-userenum-ad`
   - Field: `next_steps`
   - Change: `as-rep-roasting` → `impacket-getnpusers-asreproast`

2. **data/commands/enumeration/auto-generated-full-syntax-enumeration.json**
   - Command: `manual-hash-generation-loop`
   - Field: `alternatives`
   - Change: `john-list` → `john-show-cracked`

3. **data/commands/exploitation/metasploit-core.json**
   - Command: `msf-console-start`
   - Field: `alternatives`
   - Change: `msfconsole` → **REMOVED** (empty array)
   - Reason: "msfconsole" is not a command ID, it's the base command

4. **data/commands/post-exploit/auto-generated-full-syntax-post-exploit.json**
   - Command: `invoke-watson`
   - Field: `alternatives`
   - Change: `winpeas` → `win-privesc-winpeas`

5. **data/commands/enumeration/tool-specific.json**
   - Command: `burp-intruder`
   - Field: `alternatives`
   - Change: `wfuzz-list` → `wfuzz-dir`

---

## Validation

```bash
# Re-ran violations analysis
python3 scripts/analyze_relationship_violations.py --commands-dir data/commands

# Results:
Total Commands: 1237
Total Violations: 33 (down from 38)
```

All 5 remapped IDs now reference valid command IDs that exist in the database.

---

## Remaining Broken References (33)

**Breakdown by category**:
- File Transfer: 4 (ft-file-verify-md5 x4)
- Impacket Tools: 4 (psexec, smbexec, wmiexec, secretsdump)
- Active Directory: 14 (various AD operations)
- Windows Post-Exploit: 7 (credential hunting, screenshots, etc.)
- System Monitoring: 2 (systemctl-list, lsof-list)
- Deprecated/Duplicates: 4 (to be removed)

---

## Next Steps

1. **Remove 4 strategic broken references** (deprecated/duplicates) → ETA: 15 min
   - `rubeus-klist-display` → Use native `klist`
   - `get-wmiobject` → Use `Get-CimInstance`
   - `windows-exploit-suggester` → Move to methodology_guidance
   - `john-crack-ntlm` → Use `john-crack` with format

2. **Create 19 canonical commands** → ETA: 3-4 hours
   - High priority: Impacket, AD credential extraction, file verification
   - Medium priority: Windows credential hunting, networking
   - Low priority: System monitoring tools

3. **Validate** → ETA: 5 min
   - Target: 0 broken references

---

## Progress Summary

- [x] Analyze violations (1,952 → 38)
- [x] Apply automated cleanup (98% reduction)
- [x] Categorize 38 broken references
- [x] Remap 5 references (38 → 33)
- [ ] Remove 4 strategic references
- [ ] Create 19 canonical commands
- [ ] Validate: 0 broken references

**Current Status**: 33 broken references remaining (98.3% reduction from original 1,952)
