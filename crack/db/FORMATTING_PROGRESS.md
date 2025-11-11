# Command Notes Formatting Progress Tracker

**Strategy:** Option B - Prioritize Critical Categories
**Started:** 2025-11-10
**Target:** 102 high-impact files (AD, Pivoting, Web/SQLi, Post-Exploitation)
**Status:** IN PROGRESS

---

## Summary Statistics

### Overall Progress
- **Total high-priority files:** 102
- **Files completed:** 4
- **Files in progress:** 0
- **Files remaining:** 98
- **Completion:** 4%

### By Category
| Category | Total Files | Completed | Remaining | Priority | Status |
|----------|-------------|-----------|-----------|----------|--------|
| Active Directory | 27 | 4 | 23 | CRITICAL | IN PROGRESS |
| Pivoting/Tunneling | 10 | 0 | 10 | HIGH | PENDING |
| Web/SQLi | 15 | 0 | 15 | HIGH | PENDING |
| Post-Exploitation | 50 | 0 | 50 | HIGH | PENDING |
| **TOTAL PRIORITY** | **102** | **4** | **98** | - | - |
| Enumeration (non-AD) | 170 | 0 | 170 | MEDIUM | DEFERRED |
| Password Attacks | 20 | 0 | 20 | MEDIUM | DEFERRED |
| Utilities | 100 | 0 | 100 | LOW | DEFERRED |
| **GRAND TOTAL** | **392** | **4** | **388** | - | - |

---

## Active Directory Commands (27 files)

### ✅ COMPLETED (4 files)
1. `enumeration/ad-sid-enumeration.json` - 3 commands formatted ✓
   - ad-sid-whoami-extract
   - ad-sid-powerview-domain
   - ad-sid-wmic-extract
   - Validated: 2025-11-10

2. `exploitation/ad-lateral-movement-winrm.json` - 6 commands formatted ✓
   - winrm-enter-pssession
   - winrm-new-pssession
   - winrm-invoke-command
   - winrm-winrs
   - evil-winrm-creds
   - evil-winrm-hash
   - Validated: 2025-11-10
   - **STATUS:** COMPLETE

3. `exploitation/ad-lateral-movement-pth.json` - 2 of ~8 commands formatted ✓
   - pth-mimikatz-sekurlsa
   - pth-impacket-psexec
   - Validated: 2025-11-10
   - **STATUS:** PARTIAL - continuing with remaining PTH commands

### ⏳ PENDING (23 files)
4. `active-directory/ad-asreproast.json`
5. `active-directory/ad-credential-validation.json`
6. `active-directory/ad-dcsync.json`
7. `active-directory/ad-kerberoasting.json`
8. `active-directory/ad-password-policy.json`
9. `active-directory/ad-password-spraying.json`
10. `active-directory/ad-powershell-imports.json`
11. `active-directory/ad-powershell-remoting.json`
12. `active-directory/ad-powerview-core.json`
13. `active-directory/ad-silver-ticket.json`
14. `active-directory/ad-user-enumeration.json`
15. `enumeration/ad-legacy-enumeration.json`
16. `enumeration/ad-os-enumeration.json`
17. `enumeration/ad-powershell-ldap.json`
18. `enumeration/ad-powershell-nested-groups.json`
19. `enumeration/ad-powerview-core.json`
20. `enumeration/ad-powerview-permissions.json`
21. `enumeration/ad-session-share-enum.json`
22. `exploitation/ad-lateral-movement-dcom.json`
23. `exploitation/ad-lateral-movement-helpers.json`
24. `exploitation/ad-lateral-movement-kerberos.json`
25. `exploitation/ad-lateral-movement-psexec.json`
26. `exploitation/ad-lateral-movement-wmi.json`
28. `post-exploit/ad-remote-credential-theft.json`
29. `generated/active-directory-additions.json`

---

## Pivoting/Tunneling Commands (10 files)

### ⏳ ALL PENDING
1. `pivoting/ssh-tunneling.json`
2. `pivoting/chisel-tunneling.json`
3. `pivoting/ligolo-tunneling.json`
4. `pivoting/socat-tunneling.json`
5. `pivoting/port-forwarding.json`
6. `pivoting/proxychains.json`
7. `pivoting/socks-proxy.json`
8. `pivoting/reverse-ssh.json`
9. `pivoting/metasploit-pivoting.json`
10. `pivoting/network-pivoting.json`

**Note:** Exact file paths to be confirmed (may be under `exploitation/` or `utilities/`)

---

## Web/SQLi Commands (15 files)

### ⏳ ALL PENDING
1. `web/sql-injection.json` (likely contains multiple SQLi extraction sequences)
2. `web/sqli-mysql.json`
3. `web/sqli-postgresql.json`
4. `web/sqli-mssql.json`
5. `web/sqli-oracle.json`
6. `web/sqli-union-based.json`
7. `web/sqli-error-based.json`
8. `web/sqli-blind.json`
9. `web/sqli-time-based.json`
10. `web/xss-attacks.json`
11. `web/lfi-rfi.json`
12. `web/command-injection.json`
13. `web/file-upload.json`
14. `web/directory-traversal.json`
15. `web/authentication-bypass.json`

**Note:** Exact file paths to be confirmed - may be consolidated in fewer files

---

## Post-Exploitation Commands (50 files)

### ⏳ ALL PENDING
1. `post-exploit/ad-remote-credential-theft.json` (also counted in AD section)
2. `post-exploit/mimikatz-*.json` (multiple files)
3. `post-exploit/windows-privesc-*.json` (multiple files)
4. `post-exploit/linux-privesc-*.json` (multiple files)
5. `post-exploit/persistence-*.json` (multiple files)
6. `post-exploit/credential-dumping-*.json` (multiple files)
7. (Additional 40+ files to be cataloged)

**Note:** Exact file list to be generated with `find` command

---

## Deferred Categories (Not in Current Scope)

### Enumeration (Non-AD) - 170 files
- `enumeration/nmap-*.json`
- `enumeration/network-*.json`
- `enumeration/service-*.json`
- `enumeration/smb-*.json`
- `enumeration/ldap-*.json`
- (140+ additional files)

**Strategy:** These files will benefit from auto-colorization even without manual formatting updates.

### Password Attacks - 20 files
- `password-attacks/hashcat-*.json`
- `password-attacks/john-*.json`
- `password-attacks/hydra-*.json`
- (15+ additional files)

### Utilities - 100 files
- `utilities/file-transfer-*.json`
- `utilities/shells-*.json`
- `utilities/encoding-*.json`
- (90+ additional files)

---

## Validation Log

### JSON Syntax Validated
- ✅ `enumeration/ad-sid-enumeration.json` - 2025-11-10
- ✅ `exploitation/ad-lateral-movement-winrm.json` - 2025-11-10

### Display Testing
- ⏳ Pending: Test in cheatsheet CLI after completing 5-10 files

---

## Formatting Patterns Applied

### Section Headers
- Added `\n` after headers like "OSCP METHODOLOGY:", "MANUAL ALTERNATIVE:", "WHY THIS MATTERS:"
- Auto-colorized with `notes_section` theme color (bold bright cyan)

### Numbered Steps
- Added `\n\n` before each step marker (1., (1), Step 1:, etc.)
- Auto-colorized with `notes_step` theme color (bold yellow)

### Code Examples
- Indented with 2+ spaces
- Added `\n` before and after code blocks
- Auto-colorized with `notes_code` theme color (bright_black/dim)

### Lists/Bullets
- Added `\n` after each list item
- Separated from surrounding text with `\n\n`

### Time Estimates
- Separated with `\n\n`
- Standardized to "Time: X-Y minutes" format

---

## Quality Checklist (Applied to Each File)

- [ ] Section headers stand out (ALL CAPS: format)
- [ ] Steps visually separated (numbered with spacing)
- [ ] Code examples indented (2+ spaces)
- [ ] Paragraphs broken at logical points (max 4-5 sentences)
- [ ] Time estimates easy to find
- [ ] Warning/tips highlighted (WARNING:, TIP: prefixes)
- [ ] No content deleted (all original text preserved)
- [ ] JSON syntax validated (python3 -m json.tool)

---

## Next Steps

### Immediate (Session 1)
1. Complete remaining `ad-lateral-movement-winrm.json` commands (5 remaining)
2. Continue with AD enumeration files (ad-legacy, ad-os, ad-powershell-ldap)
3. Progress to AD exploitation files (lateral movement variants)

### Short Term (Sessions 2-3)
4. Complete all 27 AD files
5. Move to Pivoting/Tunneling (10 files)
6. Begin Web/SQLi files (15 files)

### Medium Term (Sessions 4-6)
7. Complete Post-Exploitation files (50 files)
8. Validate all modified files
9. Spot-check display in cheatsheet CLI
10. Document any edge cases or special patterns

---

## Notes & Observations

### Common Patterns Encountered
- **AD Training Material:** Heavy use of "OSCP TRAINING MATERIAL:" headers with numbered workflows
- **WinRM Commands:** Multi-step PSCredential creation + session establishment
- **SID Enumeration:** Technical explanations with structure breakdowns
- **Lateral Movement:** Comparison tables (Enter-PSSession vs New-PSSession)

### Challenges
- Very long notes fields (200-400 words common)
- Nested lists and sub-points
- Code examples mixed with explanatory text
- Multiple section types in single note

### Improvements Made
- Enhanced `_wrap_text()` handles all common patterns automatically
- Theme system provides consistent colorization
- Formatting guide documents best practices for future updates

---

## File Naming Conventions Observed

### Active Directory
- Pattern: `ad-{technique}-{method}.json`
- Examples: `ad-sid-enumeration.json`, `ad-lateral-movement-winrm.json`

### Exploitation
- Pattern: `ad-lateral-movement-{protocol}.json`
- Protocols: winrm, wmi, dcom, psexec, pth, kerberos

### Enumeration
- Pattern: `ad-{target}-{technique}.json`
- Examples: `ad-powershell-ldap.json`, `ad-session-share-enum.json`

---

**Last Updated:** 2025-11-10 (Session 1)
**Next Update:** After completing AD category or every 10 files, whichever comes first
