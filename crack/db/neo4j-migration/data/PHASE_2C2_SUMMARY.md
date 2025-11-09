# Phase 2C.2 Summary: Failed Mappings Analysis

**Task:** Analyze 295 remaining failed mappings after Phase 2B command creation

**Result:** Successfully categorized all 245 unique failed text values into actionable categories

---

## Key Findings

### Categorization Results

| Category | Items | Occurrences | Description | Action |
|----------|-------|-------------|-------------|--------|
| **A** - Already Exists | 11 | 42 | Command exists in index, needs ID update | Apply immediately |
| **D** - Fuzzy Match | 22 | 22 | Close match to existing command | Review & apply |
| **C** - Not Command | 111 | 127 | Instructions, state conditions to remove | Cleanup |
| **B** - Create Command | 66 | 68 | Potential new commands | Selective creation |
| **E** - Manual Review | 35 | 36 | Context-dependent | Case-by-case |
| **TOTAL** | **245** | **295** | | |

---

## Quick-Win Opportunities (Categories A + D)

**33 items (64 occurrences)** can be fixed immediately with high confidence.

### Impact Projection

| Metric | Current | After Quick-Wins | After Cleanup | Gain |
|--------|---------|------------------|---------------|------|
| Total Mappings | 883 | 883 | 756 | -127 (noise removed) |
| Successful | 588 | 652 | 652 | +64 |
| Success Rate | **66.6%** | **73.8%** | **86.2%** | **+19.7%** |

---

## Top Quick-Win Examples

### High-Confidence Updates (Score 1.0)

1. **"Import PowerView" → `import-powerview`**
   - 30 occurrences across AD enumeration commands
   - Perfect match, safe to auto-apply

2. **"burp intruder" → `burp-intruder`**
   - 2 occurrences in web testing commands
   - Exact match

3. **"nessus scan" → `nessus-scan`**
   - 1 occurrence
   - Command created in Phase 2B.6

4. **"bitsadmin download" → `bitsadmin-download`**
   - 1 occurrence
   - File transfer command

### Medium-Confidence Updates (Score 0.5-0.9)

- "PowerView imported" → `verify-powerview-imported` (0.9)
- "Get-GPPPassword (PowerSploit)" → `get-gpppassword` (0.67)
- "Rubeus ptt /ticket:<FILE>" → `rubeus-ptt` (0.67)
- "wpscan-enumerate-all (to discover usernames)" → `wpscan-enumerate-all` (0.5)

---

## Category C: Items to Remove (127 occurrences)

These are **not commands** but rather:

### State Conditions (should be preconditions, not prerequisites)
- "Neo4j running"
- "Mimikatz on Windows host"
- "CrackMapExec installed"
- "Evil-WinRM installed on Kali"
- "WinRM enabled on target"
- "SMB port 445 open"

### Instructions (descriptive text, not executable)
- "Transfer script"
- "Check /etc/sudoers if readable"
- "Use /dev/tcp for raw download"
- "Find exploit first: searchsploit <SERVICE>"
- "Manual check with: sc qc <servicename>"
- "Run directly: \\<LHOST>\share\file.exe"

### PowerShell Cmdlets Used as Instructions
- "Get-CimInstance win32_process"
- "Get-ScheduledTask"
- "Get-Process -Id <PID> | Select *"
- "Get-Acl in PowerShell"

**Action:** Remove from `alternatives` and `prerequisites` arrays to clean up data.

---

## Category B: Commands Worth Creating (Selective)

66 potential commands identified. Recommended subset:

### High Priority (Actually Useful)
1. `chmod-x` - Make file executable (3 occurrences)
2. `docker-info` - Display Docker system info
3. `docker-version` - Check Docker version
4. `python3-smbserver` - Start Impacket SMB server
5. `certutil-base64` - Base64 encode with certutil
6. `reg-save-sam` - Export SAM registry hive
7. `reg-save-system` - Export SYSTEM registry hive
8. `mimikatz-dpapi-masterkey` - Extract DPAPI master key
9. `journalctl-kernel` - View kernel messages
10. `wfuzz-wp-login-brute` - WordPress login bruteforce

### Low Priority (Trivial/Redundant)
- "docker pull alpine" - Too specific
- "w (includes user info)" - Too basic
- "grep time range in syslog files" - Too generic
- "python requests.post()" - Not a shell command
- "burp suite XML-RPC plugin" - Tool reference, not command

**Recommendation:** Create ~15-20 high-priority commands, ignore the rest.

---

## Category E: Manual Review Items (35 items)

Most are actually resolvable:

### Should be Commands (Create)
- "PowerUp's Get-RegistryAlwaysInstallElevated" → `get-registryalwaysinstallelevated`
- "Watson (PowerShell-based)" → `watson-scan`
- "mimikatz: vault::list" → `mimikatz-vault-list`
- "Rubeus.exe kerberoast" → `rubeus-kerberoast`
- "Mimikatz: sekurlsa::tickets" → `mimikatz-sekurlsa-tickets`
- "Mimikatz: kerberos::purge" → `mimikatz-kerberos-purge`

### Should be Removed (State/Instructions)
- "Mimikatz on Windows host" (state)
- "HTTP server on attacker" (state)
- "Transfer LinEnum.sh" (instruction)
- "Proxychains configured" (state)

### Could be Alternatives (Tool References)
- "SFTP for interactive transfer" → Consider `sftp-interactive`
- "Python Flask upload server" → Consider `flask-upload-server`
- "TFTP for simpler transfers" → Consider `tftp-transfer`

---

## Files with Most Quick-Win Updates

1. **ad-powerview-core.json** - 14 updates (all "Import PowerView")
2. **ad-powerview-permissions.json** - 10 updates (PowerView imports)
3. **ad-session-share-enum.json** - 7 updates (PowerView verifications)
4. **linux-utilities.json** - 4 updates (various)
5. **general.json** (exploitation) - 3 updates (mixed)

**See `QUICK_WIN_UPDATES.json` for complete file-by-file update plan.**

---

## Recommended Action Plan

### Phase 1: Apply Quick-Wins (Immediate)

**Script: `apply_quick_wins.py`** (to be created)

1. Apply high-confidence updates (39 items, score ≥ 0.9)
   - Automated, safe
   - **Impact:** +39 successful mappings

2. Review medium-confidence updates (13 items, 0.6 ≤ score < 0.9)
   - Manual verification
   - **Impact:** +13 successful mappings (if verified)

3. Skip low-confidence updates (12 items, score < 0.6)
   - Defer to manual review

**Estimated Impact:** 66.6% → 73.8% success rate

### Phase 2: Cleanup (Medium Priority)

**Script: `remove_non_commands.py`** (to be created)

1. Remove Category C items (127 occurrences)
   - Instructions → Remove
   - State conditions → Remove or convert to notes
   - PowerShell instructions → Remove

**Estimated Impact:** 73.8% → 86.2% success rate (fewer total mappings)

### Phase 3: Selective Command Creation (Lower Priority)

1. Create high-value Category E commands (~20 items)
   - Mimikatz subcommands
   - Rubeus variations
   - PowerUp functions

2. Create useful Category B commands (~15 items)
   - chmod-x, docker-info, python3-smbserver, etc.
   - Skip trivial/redundant ones

**Estimated Impact:** 86.2% → ~90% success rate

### Phase 4: Final Manual Review (Lowest Priority)

1. Review remaining edge cases (~15 items)
2. Make context-dependent decisions

**Estimated Final Success Rate:** 90-95%

---

## Automation Scripts Needed

### 1. High-Confidence Auto-Update

```bash
python3 scripts/utils/apply_quick_wins.py \
  --input data/QUICK_WIN_UPDATES.json \
  --min-score 0.9 \
  --dry-run
```

**Function:** Apply Category A updates with score ≥ 0.9

### 2. Category C Cleanup

```bash
python3 scripts/utils/remove_non_commands.py \
  --input data/FAILED_MAPPINGS_CATEGORIZED.json \
  --category C \
  --dry-run
```

**Function:** Remove instructions/state conditions from relationship arrays

### 3. Verification

```bash
python3 scripts/03_map_text_to_ids.py  # Re-run mapping
python3 scripts/utils/json_stats.py --verbose  # Check violations
```

---

## Files Generated

| File | Purpose |
|------|---------|
| `FAILED_MAPPINGS_CATEGORIZED.json` | Full categorization data (245 items) |
| `QUICK_WIN_UPDATES.json` | File-by-file update plan (64 updates) |
| `FAILED_MAPPINGS_TRIAGE.md` | Detailed human-readable analysis |
| `PHASE_2C2_SUMMARY.md` | This executive summary |

---

## Success Metrics

| Metric | Value |
|--------|-------|
| Failed Mappings Analyzed | 295 |
| Unique Values Categorized | 245 |
| Quick-Win Opportunities | 64 |
| Items to Remove | 127 |
| New Commands to Create | ~35-40 (selective) |
| Estimated Final Success Rate | 90-95% |

---

## Next Decision Point

**Choose automation approach:**

1. **Option A: Fully Automated**
   - Apply all Category A+D updates automatically
   - Risk: May introduce some incorrect mappings (low-confidence items)
   - Speed: Fast (~5 minutes)

2. **Option B: Semi-Automated (RECOMMENDED)**
   - Auto-apply high-confidence (score ≥ 0.9)
   - Manual review medium-confidence (0.6 ≤ score < 0.9)
   - Speed: Medium (~30 minutes)

3. **Option C: Fully Manual**
   - Review every update
   - Risk: None
   - Speed: Slow (~2-3 hours)

**Recommendation:** Option B (Semi-Automated)

---

**Analysis Complete:** 2025-11-09

**Scripts Used:**
- `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/scripts/utils/categorize_failed_mappings.py`
- `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/scripts/utils/generate_quick_wins.py`
