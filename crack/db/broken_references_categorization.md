# Broken References Categorization Report

**Generated**: 2025-11-26
**Total Broken References**: 38 (28 unique IDs)
**Source**: violations_analysis.json

---

## Executive Summary

After automated cleanup reduced violations from 1,952 to 38 (98% reduction), the remaining broken references fall into 4 resolution categories:

- **Category 1 - Create Canonical Commands**: 19 unique IDs (missing tool variations)
- **Category 2 - Remap to Existing Commands**: 5 IDs (exist under different names) → **VERIFIED ALL EXIST**
- **Category 3 - Create Wrapper/Hub Commands**: 0 IDs (none applicable)
- **Category 4 - Strategic Removal**: 4 IDs (duplicates/deprecated)

**Total Unique Broken IDs**: 28 (38 total occurrences across all files)

---

## Category 1: Create Canonical Command Entries (19 IDs)

These are legitimate tools/variations that need full command JSON entries created.

### 1.1 File Transfer & Verification (2 IDs)
| Broken ID | Occurrences | Category | Priority | Notes |
|-----------|-------------|----------|----------|-------|
| `ft-file-verify-md5` | 4 | file-transfer | HIGH | MD5 hash verification after file transfer |
| `ft-powershell-execute-memory` | - | file-transfer | MEDIUM | Execute PowerShell script from memory (anti-forensics) |

**Commands to Create**:
- `db/data/commands/file-transfer/file-verification.json`
  - `ft-file-verify-md5`: `md5sum <FILE>` (Linux) / `Get-FileHash -Algorithm MD5 <FILE>` (Windows)
  - `ft-file-verify-sha256`: `sha256sum <FILE>` (Linux) / `Get-FileHash <FILE>` (Windows)

### 1.2 Impacket Tools (4 IDs)
| Broken ID | Occurrences | Existing Similar | Priority | Notes |
|-----------|-------------|------------------|----------|-------|
| `psexec` | 1 | `ad-pass-the-hash-impacket-psexec` | HIGH | Generic psexec command ID |
| `smbexec` | 1 | None | HIGH | Impacket's smbexec.py tool |
| `wmiexec` | 1 | `ad-pass-the-hash-impacket-wmiexec` | HIGH | Generic wmiexec command ID |
| `secretsdump` | 1 | `ad-dcsync-secretsdump-all` | HIGH | Generic secretsdump command ID |

**Commands to Create**:
- `db/data/commands/exploitation/impacket-core.json`
  - `impacket-psexec`: `impacket-psexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET>`
  - `impacket-smbexec`: `impacket-smbexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET>`
  - `impacket-wmiexec`: `impacket-wmiexec <DOMAIN>/<USER>:<PASSWORD>@<TARGET>`
  - `impacket-secretsdump`: `impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<TARGET>`

### 1.3 Active Directory Operations (7 IDs)
| Broken ID | Occurrences | Category | Priority | Notes |
|-----------|-------------|----------|----------|-------|
| `ad-dcsync-check-privileges` | 1 | active-directory | HIGH | Check if user has DCSync rights |
| `ad-dcsync-ntds-credentials` | 1 | active-directory | HIGH | Extract credentials from NTDS.DIT |
| `ad-lsass-dump-procdump` | 4 | active-directory | HIGH | Dump LSASS with ProcDump |
| `ad-sam-dump-reg-save` | 2 | active-directory | HIGH | Dump SAM/SYSTEM with reg save |
| `crackmapexec-sam-dump` | 1 | active-directory | HIGH | CME SAM credential dumping |
| `powerview-enumerate-spns` | 1 | active-directory | MEDIUM | PowerView SPN enumeration |
| `windows-psexec-system-shell` | 1 | active-directory | HIGH | Get SYSTEM shell via PSExec |

**Commands to Create**:
- `db/data/commands/active-directory/ad-credential-extraction.json`
  - `ad-lsass-dump-procdump`: `procdump.exe -ma lsass.exe lsass.dmp`
  - `ad-sam-dump-reg-save`: `reg save HKLM\SAM sam.hive && reg save HKLM\SYSTEM system.hive`
  - `ad-dcsync-ntds-credentials`: `impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL`

- `db/data/commands/active-directory/ad-dcsync-operations.json`
  - `ad-dcsync-check-privileges`: PowerShell/Bloodhound query for DS-Replication-Get-Changes rights

### 1.4 Windows Post-Exploitation (4 IDs)
| Broken ID | Occurrences | Category | Priority | Notes |
|-----------|-------------|----------|----------|-------|
| `windows-search-sensitive-files` | 4 | post-exploit | HIGH | Search for passwords, configs, credentials |
| `windows-screenshot-capture` | 1 | post-exploit | MEDIUM | Take screenshot (RDP sessions) |
| `windows-net-use-smb-connect` | 2 | post-exploit | MEDIUM | Connect to SMB share with net use |
| `kerberos-klist-purge` | 1 | active-directory | MEDIUM | Clear Kerberos ticket cache |

**Commands to Create**:
- `db/data/commands/post-exploit/windows-credential-hunting.json`
  - `windows-search-sensitive-files`: `dir /s /b *password* *cred* *vnc* *.config`
  - `windows-search-passwords-registry`: `reg query HKLM /f password /t REG_SZ /s`

- `db/data/commands/post-exploit/windows-situational-awareness.json`
  - `windows-screenshot-capture`: PowerShell screenshot script

### 1.5 System Monitoring (2 IDs)
| Broken ID | Occurrences | Category | Priority | Notes |
|-----------|-------------|----------|----------|-------|
| `systemctl-list` | 1 | monitoring | LOW | List systemd services |
| `lsof-list` | 1 | monitoring | LOW | List open files/sockets |

**Commands to Create**:
- `db/data/commands/monitoring/linux-process-monitoring.json`
  - `systemctl-list-services`: `systemctl list-units --type=service --all`
  - `lsof-list-all`: `sudo lsof` or `lsof -i` (network only)

---

## Category 2: Remap to Existing Commands (5 IDs)

These IDs reference commands that already exist under different names. Update references to use existing IDs.

| Broken ID | Remap To | Existing ID | File Location | Notes |
|-----------|----------|-------------|---------------|-------|
| `as-rep-roasting` | `impacket-getnpusers-asreproast` | EXISTS | active-directory/ad-kerberos-attacks.json | ASREPRoast attack |
| `john-list` | `john-show-cracked` | EXISTS | enumeration/auto-generated-full-syntax-enumeration.json | Show cracked passwords |
| `msfconsole` | `msfconsole-exploit` or `msfconsole-search` | EXISTS | exploitation/metasploit-core.json | Metasploit console |
| `winpeas` | `win-privesc-winpeas` or `winpeas-run` | EXISTS | post-exploit/windows-privilege-escalation.json | Windows privilege escalation enumeration |
| `wfuzz-list` | `wfuzz-dir` | EXISTS | web/wfuzz-enumeration.json | Web fuzzing/directory enumeration |

**Action Required**:
1. Update source files to use correct command IDs:
   - `active-directory/ad-user-enumeration.json`: Change `as-rep-roasting` → `impacket-getnpusers-asreproast`
   - `enumeration/auto-generated-full-syntax-enumeration.json`: Change `john-list` → `john-show-cracked`
   - `exploitation/metasploit-core.json`: Change `msfconsole` → `msfconsole-exploit`
   - `post-exploit/auto-generated-full-syntax-post-exploit.json`: Change `winpeas` → `win-privesc-winpeas`
   - `enumeration/tool-specific.json`: Change `wfuzz-list` → `wfuzz-dir`

2. Commands to verify existence:
   ```bash
   grep -r '"id": "win-privesc-winpeas"' .
   grep -r '"id": "wfuzz-dir"' .
   grep -r '"id": "impacket-getnpusers-asreproast"' .
   grep -r '"id": "john-show-cracked"' .
   grep -r '"id": "msfconsole-exploit"' .
   ```

---

## Category 3: Create Wrapper/Hub Commands (0 IDs)

**No wrapper commands needed**. All broken references are specific tools/actions, not decision tree patterns.

---

## Category 4: Strategic Removal (4 IDs)

These references should be removed as they're duplicates, deprecated, or better handled via methodology_guidance.

| Broken ID | Reason for Removal | Source Command | Replacement Strategy |
|-----------|-------------------|----------------|----------------------|
| `rubeus-klist-display` | Duplicate of native `klist` | ad-golden-ticket-verify-klist | Use `klist` (Windows native) |
| `get-wmiobject` | Deprecated cmdlet | get-ciminstance | Use `Get-CimInstance` (modern replacement) |
| `windows-exploit-suggester` | Tool name, not command | meterpreter-getsystem | Move to methodology_guidance |
| `john-crack-ntlm` | Too generic, duplicates exist | windows-hashcat-crack-ntlm | Use `john-crack` with format specification |

**Action Required**:
1. Remove these IDs from alternatives/next_steps fields
2. Add context to methodology_guidance instead:
   - `rubeus-klist-display` → methodology_guidance.manual_alternative: "Use native klist command"
   - `get-wmiobject` → methodology_guidance.oscp_tips: "Get-WMIObject deprecated, use Get-CimInstance"
   - `john-crack-ntlm` → Use existing `john-crack` with `--format=NT`

---

## Implementation Priority

### Phase 1: High-Impact Canonical Commands (3-4 hours)
1. **Impacket Core** (psexec, smbexec, wmiexec, secretsdump) - 1 hour
2. **AD Credential Extraction** (lsass-dump, sam-dump, dcsync) - 1 hour
3. **File Transfer Verification** (ft-file-verify-md5) - 30 min
4. **Windows Credential Hunting** (windows-search-sensitive-files) - 1 hour

### Phase 2: Remapping (30 minutes)
1. Search for existing winpeas/wfuzz commands
2. Update 5 source files with correct command IDs
3. Validate with `python3 scripts/analyze_relationship_violations.py`

### Phase 3: Strategic Removal (30 minutes)
1. Remove 4 broken reference IDs from source files
2. Add methodology_guidance context where needed

### Phase 4: Medium-Priority Commands (2 hours)
1. Kerberos operations (klist-purge, rubeus-klist)
2. Windows networking (net-use-smb-connect)
3. PowerView commands
4. System monitoring (systemctl-list, lsof-list)

---

## Expected Outcome

- **Before**: 38 broken references
- **After Phase 1-2**: ~10 broken references remaining (74% reduction)
- **After Phase 3**: ~6 broken references remaining (84% reduction)
- **After Phase 4**: 0 broken references (100% complete)

---

## Validation Commands

```bash
# Check current violations
python3 scripts/analyze_relationship_violations.py --commands-dir data/commands

# Verify specific remapping
grep -r "as-rep-roasting" data/commands/
grep -r "john-list" data/commands/

# Validate after each phase
python3 neo4j-migration/scripts/utils/validate_all_commands.py --verbose
```

---

## Files to Create (Summary)

1. `data/commands/file-transfer/file-verification.json` (2 commands)
2. `data/commands/exploitation/impacket-core.json` (4 commands)
3. `data/commands/active-directory/ad-credential-extraction.json` (4 commands)
4. `data/commands/active-directory/ad-dcsync-operations.json` (1 command)
5. `data/commands/post-exploit/windows-credential-hunting.json` (2 commands)
6. `data/commands/post-exploit/windows-situational-awareness.json` (1 command)
7. `data/commands/monitoring/linux-process-monitoring.json` (2 commands)
8. `data/commands/post-exploit/windows-networking.json` (1 command)
9. `data/commands/active-directory/ad-kerberos-operations.json` (2 commands)
10. `data/commands/active-directory/ad-powerview-enumeration.json` (1 command)

**Total**: 10 new JSON files, ~20 new command entries

---

## Notes

- All Category 1 commands follow existing schema patterns
- Prioritize OSCP:HIGH tags for exam-critical commands
- Include flag_explanations, troubleshooting, and notes for Grade A/B quality
- Cross-reference with CLAUDE.md patterns for naming conventions
- Validate each file creation with `python3 scripts/validate_commands.py`
