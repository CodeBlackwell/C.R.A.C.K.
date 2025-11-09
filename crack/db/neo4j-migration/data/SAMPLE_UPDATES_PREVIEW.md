# Sample Updates Preview

This document shows **exact JSON changes** that will be made when quick-wins are applied.

---

## Example 1: High-Confidence Update (Score 1.0)

**File:** `data/commands/enumeration/ad-powerview-core.json`

**Command ID:** `powerview-get-netuser`

**Field:** `prerequisites`

**Change:**

```diff
{
  "id": "powerview-get-netuser",
  "name": "Get-NetUser - List All Domain Users",
  "category": "enumeration",
  "command": "Get-NetUser",
  "description": "Enumerate all domain users using PowerView",
  "prerequisites": [
-   "Import PowerView"
+   "import-powerview"
  ],
  ...
}
```

**Reason:** Command `import-powerview` exists in index (score: 1.00)

**Confidence:** HIGH - Safe to auto-apply

---

## Example 2: Multiple Occurrences

**File:** `data/commands/enumeration/ad-powerview-core.json`

**14 commands** with same update:

```diff
{
  "id": "powerview-get-netdomaincontroller",
  "prerequisites": [
-   "Import PowerView"
+   "import-powerview"
  ]
}

{
  "id": "powerview-get-netuser",
  "prerequisites": [
-   "Import PowerView"
+   "import-powerview"
  ]
}

{
  "id": "powerview-get-netuser-filter",
  "prerequisites": [
-   "Import PowerView"
+   "import-powerview"
  ]
}

... (11 more similar updates)
```

**Impact:** 14 successful mappings from single file

---

## Example 3: Fuzzy Match Update (Score 0.9)

**File:** `data/commands/enumeration/ad-powerview-core.json`

**Command ID:** `powerview-verify-import`

**Field:** `alternatives`

**Change:**

```diff
{
  "id": "powerview-verify-import",
  "name": "Verify PowerView Import",
  "alternatives": [
-   "PowerView imported"
+   "verify-powerview-imported"
  ],
  ...
}
```

**Reason:** Fuzzy match to existing command (score: 0.90)

**Confidence:** HIGH - Recommended auto-apply

---

## Example 4: Medium-Confidence Update (Score 0.67)

**File:** `data/commands/post-exploit/windows.json`

**Command ID:** `gpp-password-extract`

**Field:** `alternatives`

**Change:**

```diff
{
  "id": "gpp-password-extract",
  "name": "Extract GPP Passwords",
  "alternatives": [
-   "Get-GPPPassword (PowerSploit)"
+   "get-gpppassword"
  ],
  ...
}
```

**Reason:** Fuzzy match to existing command (score: 0.67)

**Confidence:** MEDIUM - Review recommended before applying

**Manual Verification:**
- Check if `get-gpppassword` is the correct command
- Verify it's the PowerSploit version
- Confirm it's a suitable alternative

---

## Example 5: Low-Confidence Update (Score 0.50)

**File:** `data/commands/web/wordpress.json`

**Command ID:** `wpscan-password-attack`

**Field:** `prerequisites`

**Change:**

```diff
{
  "id": "wpscan-password-attack",
  "name": "WPScan WordPress Password Attack",
  "prerequisites": [
-   "wpscan-enumerate-all (to discover usernames)"
+   "wpscan-enumerate-all"
  ],
  ...
}
```

**Reason:** Fuzzy match to existing command (score: 0.50)

**Confidence:** LOW - Manual review required

**Manual Verification:**
- Text has parenthetical note "(to discover usernames)"
- Base command is `wpscan-enumerate-all`
- Match is correct, but low score due to extra text
- Safe to apply after verification

---

## Example 6: Category C - Item to Remove

**File:** `data/commands/generated/post-exploitation-additions.json`

**Command ID:** `bloodhound-ingest`

**Field:** `prerequisites`

**Change:**

```diff
{
  "id": "bloodhound-ingest",
  "name": "BloodHound - Ingest Data",
  "prerequisites": [
    "import-sharphound",
-   "Neo4j running"
  ],
  ...
}
```

**Reason:** "Neo4j running" is a state condition, not a command

**Action:** Remove from array

**Confidence:** HIGH - This is not a command prerequisite, it's a runtime requirement

---

## Example 7: Category C - PowerShell Instruction

**File:** `data/commands/post-exploit/windows.json`

**Command ID:** `windows-scheduled-tasks-enum`

**Field:** `alternatives`

**Change:**

```diff
{
  "id": "windows-scheduled-tasks-enum",
  "name": "Enumerate Windows Scheduled Tasks",
  "command": "schtasks /query /fo LIST /v",
  "alternatives": [
    "dir-scheduled-tasks",
-   "Get-ScheduledTask",
-   "Get-ScheduledTask in PowerShell"
  ],
  ...
}
```

**Reason:** These are PowerShell cmdlet instructions, not command IDs

**Action:** Remove from alternatives array

**Note:** If we want a PowerShell alternative, create proper command:
- ID: `get-scheduledtask-ps`
- Command: `Get-ScheduledTask`
- Then reference that ID

---

## Summary of Changes

### High-Confidence Updates (39 occurrences)

| Pattern | Old Text | New ID | Count |
|---------|----------|--------|-------|
| PowerView Import | "Import PowerView" | `import-powerview` | 30 |
| Burp Intruder | "burp intruder" | `burp-intruder` | 2 |
| SharpHound | "Import SharpHound data" | `import-sharphound` | 1 |
| Nessus | "nessus scan" | `nessus-scan` | 1 |
| Bitsadmin | "bitsadmin download" | `bitsadmin-download` | 1 |
| Others | Various | Various | 4 |

**Recommendation:** Auto-apply all 39 updates

---

### Medium-Confidence Updates (13 occurrences)

| Pattern | Old Text | New ID | Score | Review? |
|---------|----------|--------|-------|---------|
| GPP Password | "Get-GPPPassword (PowerSploit)" | `get-gpppassword` | 0.67 | Yes |
| Unquoted Service | "PowerUp's Get-UnquotedService" | `get-unquotedservice` | 0.67 | Yes |
| Rubeus PTT | "Rubeus ptt /ticket:<FILE>" | `rubeus-ptt` | 0.67 | Yes |
| MSFConsole | "msfconsole search scanner/<SERVICE>" | `msfconsole-search` | 0.67 | Yes |
| Others | Various | Various | 0.5-0.67 | Yes |

**Recommendation:** Manual review, then apply approved items

---

### Removals (127 occurrences)

**State Conditions:**
- "Neo4j running" (2)
- "Mimikatz on Windows host" (2)
- "CrackMapExec installed" (1)
- "Evil-WinRM installed on Kali" (1)
- "WinRM enabled on target" (3)
- "SMB port 445 open" (1)

**Instructions:**
- "Transfer script" (1)
- "Check /etc/sudoers if readable" (1)
- "Use /dev/tcp for raw download" (1)
- "Find exploit first: searchsploit <SERVICE>" (1)
- "Manual check with: sc qc <servicename>" (1)

**PowerShell Cmdlets as Instructions:**
- "Get-CimInstance win32_process" (1)
- "Get-ScheduledTask" (1)
- "Get-Process -Id <PID> | Select *" (1)
- "Get-Acl in PowerShell" (1)

**Total:** 127 items to remove

**Recommendation:** Auto-remove all Category C items

---

## Verification After Updates

After applying updates, run:

```bash
# Re-run mapping
python3 db/neo4j-migration/scripts/03_map_text_to_ids.py

# Check violations
python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose

# Verify improvement
jq '.stats' db/neo4j-migration/data/mapping_report.json
```

**Expected Results:**
- Mapping success: 66.6% → 73.8%+ (after quick-wins)
- Mapping success: 66.6% → 86.2%+ (after cleanup)
- Zero "alternatives using text" violations (after all updates)
- Zero "prerequisites using text" violations (after all updates)

---

**Preview Generated:** 2025-11-09
