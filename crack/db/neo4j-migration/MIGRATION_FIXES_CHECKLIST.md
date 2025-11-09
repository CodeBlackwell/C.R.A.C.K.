# Neo4j Migration - Fixes Checklist

**Generated**: 2025-11-08
**Status**: 644 violations identified across 791 commands
**Migration Status**: Blocked - must fix violations before migration

---

## Executive Summary

### Violation Counts

| Violation Type | Count | Severity | Blocks Migration |
|----------------|-------|----------|------------------|
| Alternatives using text | 387 | 🔴 Critical | ✅ YES |
| Prerequisites using text | 189 | 🔴 Critical | ✅ YES |
| Duplicate command IDs | 14 | 🔴 Critical | ✅ YES |
| Orphaned references | 53 | 🟡 High | ✅ YES |
| Parse errors | 1 | 🟡 High | ✅ YES |
| **TOTAL** | **644** | | |

### Impact

- **Current State**: 10 test commands in Neo4j (1.3% of target)
- **Target State**: 791 commands fully migrated
- **Blocked Commands**: 576 commands cannot migrate due to violations
- **Estimated Effort**: 12-16 hours (automated + manual review)

---

## 🔴 Critical: Duplicate Command IDs (14)

**Issue**: Same command ID used in multiple JSON files
**Impact**: Neo4j constraint violation - only first command loads
**Fix Strategy**: Manual rename with semantic versioning or context suffix

### Checklist

- [ ] **verify-root-access** (3 duplicates)
  - [ ] Location 1: `data/commands/post-exploit/linux-sudo-commands.json`
  - [ ] Location 2: `data/commands/post-exploit/linux-suid-basic-commands.json`
  - [ ] Location 3: `data/commands/exploitation/ad-lateral-movement-helpers.json`
  - **Action**: Rename to `verify-root-access-sudo`, `verify-root-access-suid`, `verify-root-access-ad`

- [ ] **netsh-portproxy-add** (2 duplicates)
  - [ ] Location 1: `data/commands/firewall.json`
  - [ ] Location 2: `data/commands/pivoting/windows-utilities.json`
  - **Action**: Keep in `firewall.json`, remove from `windows-utilities.json` (duplicate)

- [ ] **netsh-portproxy-show** (2 duplicates)
  - [ ] Location 1: `data/commands/firewall.json`
  - [ ] Location 2: `data/commands/pivoting/windows-utilities.json`
  - **Action**: Keep in `firewall.json`, remove from `windows-utilities.json`

- [ ] **netsh-firewall-add-rule** (2 duplicates)
  - [ ] Location 1: `data/commands/firewall.json`
  - [ ] Location 2: `data/commands/pivoting/windows-utilities.json`
  - **Action**: Keep in `firewall.json`, remove from `windows-utilities.json`

- [ ] **netsh-firewall-delete-rule** (2 duplicates)
  - [ ] Location 1: `data/commands/firewall.json`
  - [ ] Location 2: `data/commands/pivoting/windows-utilities.json`
  - **Action**: Keep in `firewall.json`, remove from `windows-utilities.json`

- [ ] **netsh-firewall-show** (2 duplicates)
  - [ ] Location 1: `data/commands/firewall.json`
  - [ ] Location 2: `data/commands/pivoting/windows-utilities.json`
  - **Action**: Keep in `firewall.json`, remove from `windows-utilities.json`

- [ ] **powershell-wget** (2 duplicates)
  - [ ] Location 1: `data/commands/generated/file-transfer-additions.json`
  - [ ] Location 2: `data/commands/pivoting/windows-utilities.json`
  - **Action**: Keep in `file-transfer-additions.json`, remove from `windows-utilities.json`

- [ ] **certutil-download** (2 duplicates)
  - [ ] Location 1: `data/commands/post-exploit/general-transfer.json`
  - [ ] Location 2: `data/commands/pivoting/windows-utilities.json`
  - **Action**: Keep in `general-transfer.json`, remove from `windows-utilities.json`

- [ ] **socat-port-forward** (2 duplicates)
  - [ ] Location 1: `data/commands/generated/tunneling-additions.json`
  - [ ] Location 2: `data/commands/pivoting/ssh-tunneling.json`
  - **Action**: Keep in `tunneling-additions.json`, remove from `ssh-tunneling.json`

- [ ] **sshuttle-vpn** (2 duplicates)
  - [ ] Location 1: `data/commands/generated/tunneling-additions.json`
  - [ ] Location 2: `data/commands/pivoting/pivot-utilities.json`
  - **Action**: Keep in `tunneling-additions.json`, remove from `pivot-utilities.json`

- [ ] **proxychains-config** (2 duplicates)
  - [ ] Location 1: `data/commands/generated/tunneling-additions.json`
  - [ ] Location 2: `data/commands/pivoting/proxychains-utilities.json`
  - **Action**: Keep in `tunneling-additions.json`, remove from `proxychains-utilities.json`

- [ ] **john-test-rules** (2 duplicates)
  - [ ] Location 1: `data/commands/enumeration/password-attacks-wordlist-rules.json`
  - [ ] Location 2: `data/commands/enumeration/password-attacks-john.json`
  - **Action**: Keep in `password-attacks-john.json`, remove from `wordlist-rules.json`

- [ ] **cme-smb-shares** (2 duplicates)
  - [ ] Location 1: `data/commands/generated/active-directory-additions.json`
  - [ ] Location 2: `data/commands/exploitation/ad-lateral-movement-psexec.json`
  - **Action**: Keep in `ad-lateral-movement-psexec.json`, remove from `active-directory-additions.json`

**Total Tasks**: 14 duplicate resolutions

---

## 🔴 Critical: Alternatives Using Text (387)

**Issue**: Alternatives field contains command strings instead of command IDs
**Impact**: Cannot create `[:ALTERNATIVE]` relationships in Neo4j
**Fix Strategy**: Automated mapping (Script 03) + manual review

### Auto-Mapped (168 successful)

✅ **Already fixed by automation** - Script 03 successfully mapped 168 alternatives

### Failed Mappings - Missing Commands (848 unique)

**Action Required**: Create missing command entries before migration

#### High-Priority Missing Commands (referenced 10+ times)

- [ ] **Import PowerView** (30 references)
  - **Suggested ID**: `import-powerview`
  - **Action**: Create new command for PowerView import
  - **Category**: active-directory
  - **Command**: `. .\PowerView.ps1` or `Import-Module .\PowerView.ps1`

- [ ] **PowerShell access on compromised Windows host** (20 references)
  - **Note**: This is a prerequisite state, not a command
  - **Action**: Remove from prerequisites (state condition, not executable)

- [ ] **Valid credentials** (20 references)
  - **Note**: This is a prerequisite state, not a command
  - **Action**: Remove from prerequisites (state condition, not executable)

- [ ] **cat** (15 references)
  - **Suggested ID**: `cat-file`
  - **Action**: Create utility command
  - **Category**: utility
  - **Command**: `cat <FILE>`

- [ ] **shell** (13 references)
  - **Note**: Context-dependent (reverse shell, web shell, etc.)
  - **Action**: Review each reference, map to specific shell command ID

- [ ] **Manual** (12 references)
  - **Note**: Not a command - manual testing guidance
  - **Action**: Remove from alternatives (workflow note, not executable)

- [ ] **SSH** (11 references)
  - **Suggested ID**: `ssh-connect`
  - **Action**: Create basic SSH connection command
  - **Category**: pivoting
  - **Command**: `ssh <USERNAME>@<TARGET>`

- [ ] **Network connectivity to target** (11 references)
  - **Note**: Prerequisite state, not a command
  - **Action**: Remove from prerequisites

- [ ] **Check-check** (10 references)
  - **Note**: Malformed suggestion (likely PowerShell command)
  - **Action**: Review original text, map to correct PowerShell command

- [ ] **NTLM** (10 references)
  - **Note**: Context-dependent (hash capture, relay, etc.)
  - **Action**: Review each reference individually

#### Tool-Specific Missing Commands (referenced 5-9 times)

- [ ] **fping-sweep** (9 references)
  - **Suggested ID**: `fping-sweep`
  - **Command**: `fping -a -g <TARGET_SUBNET>`
  - **Category**: enumeration

- [ ] **arp-scan** (8 references)
  - **Suggested ID**: `arp-scan-local`
  - **Command**: `arp-scan -l`
  - **Category**: enumeration

- [ ] **smbmap** (7 references)
  - **Suggested ID**: `smbmap-enum`
  - **Command**: `smbmap -H <TARGET>`
  - **Category**: enumeration

- [ ] **wfuzz** (6 references)
  - **Suggested ID**: `wfuzz-dir`
  - **Command**: `wfuzz -u <URL>/FUZZ -w <WORDLIST>`
  - **Category**: web

- [ ] **dirb** (6 references)
  - **Suggested ID**: `dirb-scan`
  - **Command**: `dirb <URL>`
  - **Category**: web

- [ ] **fierce** (5 references)
  - **Suggested ID**: `fierce-dns`
  - **Command**: `fierce --domain <DOMAIN>`
  - **Category**: enumeration

**Strategy for 848 missing commands**:

1. **Automated bulk creation** (Script 04 - to be created)
   - Extract unique tools from failed mappings
   - Generate command templates
   - Auto-fill categories based on usage context

2. **Manual review required** (~100 commands)
   - State conditions (credentials, access, etc.) → Remove
   - Workflow notes (manual testing, etc.) → Remove
   - Ambiguous references → Map to specific command

3. **Testing after creation**
   - Re-run Script 03 to validate new mappings
   - Target: >95% success rate

---

## 🔴 Critical: Prerequisites Using Text (189)

**Issue**: Prerequisites field contains command strings instead of command IDs
**Impact**: Cannot create `[:PREREQUISITE]` relationships in Neo4j
**Fix Strategy**: Same as alternatives - automated mapping + create missing commands

### Common Prerequisite Patterns

**Utility Commands** (need creation):

- [ ] `mkdir -p <OUTPUT_DIR>` → `mkdir-directory`
- [ ] `chmod +x <FILE>` → `chmod-executable`
- [ ] `sudo systemctl start ssh` → `systemctl-start-ssh`
- [ ] `pip install <PACKAGE>` → `pip-install`

**State Conditions** (remove from prerequisites):

- [ ] "Valid credentials"
- [ ] "Network connectivity to target"
- [ ] "Administrator privileges"
- [ ] "Domain user access"

**Action**: Run Script 03 on prerequisites after creating utility commands

---

## 🟡 High: Orphaned References (53)

**Issue**: Alternatives/prerequisites reference command IDs that don't exist
**Impact**: Neo4j relationship creation fails
**Fix Strategy**: Create missing commands OR fix typos

### Sample Orphaned References

- [ ] Reference to `dirb-scan` - Command doesn't exist
  - **Action**: Create `dirb-scan` command

- [ ] Reference to `ffuf-dir` - Command doesn't exist
  - **Action**: Create `ffuf-dir` command

- [ ] Reference to `wfuzz-dir` - Command doesn't exist
  - **Action**: Create `wfuzz-dir` command

**Full list**: See `mapping_report.json` failed_mappings section

---

## 🟡 High: Parse Errors (1)

**Issue**: JSON syntax error in file
**Impact**: Commands in file cannot be loaded

- [ ] **password-attacks-wordlist-rules.json**
  - **Error**: `expected string or bytes-like object, got 'dict'`
  - **Action**: Inspect file structure, fix JSON syntax
  - **Location**: `data/commands/enumeration/password-attacks-wordlist-rules.json`

---

## Execution Plan

### Phase 1: Fix Critical Blockers (Week 1)

**Day 1-2: Duplicate IDs**
- [ ] Review 14 duplicate IDs
- [ ] Rename or remove duplicates
- [ ] Re-run `json_stats.py` to validate
- **Goal**: 0 duplicate IDs

**Day 3: Parse Errors**
- [ ] Fix JSON syntax error in `password-attacks-wordlist-rules.json`
- [ ] Validate JSON structure
- **Goal**: 0 parse errors

**Day 4-5: Create High-Priority Missing Commands**
- [ ] Create 20 most-referenced missing commands
- [ ] Add to appropriate JSON files
- [ ] Validate command structure
- **Goal**: 20 new commands added

### Phase 2: Automated Mapping (Week 2)

**Day 1: Script 04 - Bulk Command Creation**
- [ ] Create Script 04: `04_bulk_create_commands.py`
- [ ] Generate command templates for 848 missing commands
- [ ] Auto-categorize based on tool name
- [ ] Output: `missing_commands.json`

**Day 2: Manual Review**
- [ ] Review auto-generated commands
- [ ] Remove state conditions
- [ ] Fix ambiguous references
- [ ] Merge into main JSON files

**Day 3: Re-run Mapping**
- [ ] Run Script 03 again with new commands
- [ ] Validate >95% success rate
- [ ] Document remaining failures

**Day 4-5: Fix Orphaned References**
- [ ] Create or fix 53 orphaned command references
- [ ] Re-run validation
- **Goal**: 0 orphaned references

### Phase 3: Validation (Week 3)

**Day 1: Schema Validation**
- [ ] Run `json_stats.py --verbose`
- [ ] Verify 0 violations
- [ ] Check command count (should be ~1,600 after additions)

**Day 2: Migration Dry Run**
- [ ] Run Script 06 (migration) in test mode
- [ ] Verify Neo4j constraint checks pass
- [ ] Check relationship creation

**Day 3-5: Full Migration**
- [ ] Backup current state
- [ ] Run full migration to Neo4j
- [ ] Verify graph integrity
- [ ] Test CLI with `--graph` patterns

---

## Success Criteria

- [ ] ✅ Duplicate IDs: 0 (currently 14)
- [ ] ✅ Parse errors: 0 (currently 1)
- [ ] ✅ Alternatives using text: 0% (currently 73.6%)
- [ ] ✅ Prerequisites using text: 0% (currently 57.1%)
- [ ] ✅ Orphaned references: 0 (currently 53)
- [ ] ✅ Neo4j command count: 791 (currently 10)
- [ ] ✅ CLI shows "791 commands" (currently shows "10 commands")
- [ ] ✅ All 10 graph patterns working
- [ ] ✅ Migration success rate: 100%

---

## Scripts to Run

### Diagnostic
```bash
# Quick health check
./db/neo4j-migration/scripts/utils/quick_report.sh

# Detailed violations
python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose
```

### Mapping
```bash
# Build command index
python3 db/neo4j-migration/scripts/02_build_command_index.py

# Map text to IDs
python3 db/neo4j-migration/scripts/03_map_text_to_ids.py
```

### Validation
```bash
# After fixes, verify
python3 db/neo4j-migration/scripts/utils/json_stats.py
python3 db/neo4j-migration/scripts/utils/compare_backends.py
```

---

## Notes

- **Backup strategy**: Git commit before each phase
- **Rollback**: Use `.backup` files created by scripts
- **Testing**: Run `crack reference --status` after each phase
- **Timeline**: Estimated 3 weeks (12-16 hours effort)

**Last Updated**: 2025-11-08
**Next Review**: After Phase 1 completion
