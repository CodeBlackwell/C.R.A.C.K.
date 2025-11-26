# Broken References Categorization - Summary

**Date**: 2025-11-26  
**Status**: COMPLETE  
**Total Time**: ~30 minutes

---

## Results

Successfully categorized all 38 broken command references into 4 resolution strategies:

| Category | Count | Status | Priority |
|----------|-------|--------|----------|
| **1. Create Canonical Commands** | 19 IDs | Ready for implementation | HIGH |
| **2. Remap to Existing Commands** | 5 IDs | All verified to exist | HIGH |
| **3. Create Wrapper Commands** | 0 IDs | N/A | - |
| **4. Strategic Removal** | 4 IDs | Ready for cleanup | MEDIUM |

**Total Unique Broken IDs**: 28  
**Total Occurrences**: 38 (some IDs referenced multiple times)

---

## Category Breakdown

### Category 1: Create Canonical Commands (19 IDs)

**File Transfer & Verification** (2)
- `ft-file-verify-md5` (4 occurrences)
- `ft-powershell-execute-memory`

**Impacket Tools** (4)
- `psexec`, `smbexec`, `wmiexec`, `secretsdump`

**Active Directory Operations** (7)
- `ad-dcsync-check-privileges`
- `ad-dcsync-ntds-credentials`
- `ad-lsass-dump-procdump` (4 occurrences)
- `ad-sam-dump-reg-save` (2 occurrences)
- `crackmapexec-sam-dump`
- `powerview-enumerate-spns`
- `windows-psexec-system-shell`

**Windows Post-Exploitation** (4)
- `windows-search-sensitive-files` (4 occurrences)
- `windows-screenshot-capture`
- `windows-net-use-smb-connect` (2 occurrences)
- `kerberos-klist-purge`

**System Monitoring** (2)
- `systemctl-list`
- `lsof-list`

### Category 2: Remap to Existing (5 IDs) - ALL VERIFIED

| Broken ID | Remap To | Status |
|-----------|----------|--------|
| `as-rep-roasting` | `impacket-getnpusers-asreproast` | ✓ EXISTS |
| `john-list` | `john-show-cracked` | ✓ EXISTS |
| `msfconsole` | `msfconsole-exploit` | ✓ EXISTS |
| `winpeas` | `win-privesc-winpeas` | ✓ EXISTS |
| `wfuzz-list` | `wfuzz-dir` | ✓ EXISTS |

### Category 3: Wrapper Commands (0 IDs)

No wrapper/hub commands needed - all references are specific tools.

### Category 4: Strategic Removal (4 IDs)

- `rubeus-klist-display` → Use native `klist`
- `get-wmiobject` → Deprecated, use `Get-CimInstance`
- `windows-exploit-suggester` → Move to methodology_guidance
- `john-crack-ntlm` → Use `john-crack` with format specification

---

## Implementation Plan

### **Next Step: Remap 5 Commands** (Estimated: 15 minutes)

Files to update:
1. `active-directory/ad-user-enumeration.json`
2. `enumeration/auto-generated-full-syntax-enumeration.json`
3. `exploitation/metasploit-core.json`
4. `post-exploit/auto-generated-full-syntax-post-exploit.json`
5. `enumeration/tool-specific.json`

### **Then: Strategic Removal** (Estimated: 15 minutes)

Remove 4 deprecated/duplicate references and add guidance.

### **Then: Create 19 Commands** (Estimated: 3-4 hours)

Priority order:
1. Impacket Core (1 hour)
2. AD Credential Extraction (1 hour)
3. File Transfer Verification (30 min)
4. Windows Credential Hunting (1 hour)
5. Remaining commands (1 hour)

---

## Files Created

- `broken_references_categorization.md` - Detailed categorization with implementation plan
- `CATEGORIZATION_SUMMARY.md` - This executive summary

---

## Validation

After all remapping/removal/creation:
```bash
python3 scripts/analyze_relationship_violations.py --commands-dir data/commands
# Expected: 0 violations
```

---

## Progress Tracking

- [x] Analyze violations (1,952 → 38)
- [x] Apply automated cleanup (98% reduction)
- [x] Categorize 38 broken references
- [ ] Remap 5 references
- [ ] Remove 4 strategic references
- [ ] Create 19 canonical commands
- [ ] Validate: 0 broken references

**Current Status**: Ready to proceed with remapping phase
