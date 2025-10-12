# CRACK Reference System - Enhancement Roadmap

**Date Created:** 2025-10-12
**Source:** Capstone analysis (8 OSCP machine writeups)
**Current Commands:** 110
**Target Commands:** 147 (+37)
**Status:** Planning Phase

---

## Executive Summary

Capstone analysis revealed CRACK has **excellent post-exploitation coverage** (76% of commands) but significant gaps in **initial enumeration** and **exploitation** phases. Students need commands for service-specific enumeration, SQL injection workflows, shell establishment, and credential testing.

---

## Phase 1: Foundation - SQLi Workflow (Week 1)

### Priority: CRITICAL
**Objective:** Add complete SQL injection attack chain (most educational value)

### Tasks

- [ ] Create `reference/data/commands/web/sql-injection.json`
- [ ] Add command: `sqli-detection-error` (curl POST with single quote)
- [ ] Add command: `sqli-column-enum-orderby` (ORDER BY enumeration)
- [ ] Add command: `sqli-union-select-basic` (UNION SELECT extraction)
- [ ] Add command: `sqlmap-post-exploitation` (automated exploitation)
- [ ] Add command: `sqli-union-mysql-info` (MySQL-specific queries)
- [ ] Add command: `sqli-union-postgresql-info` (PostgreSQL-specific queries)
- [ ] Add command: `sqli-union-mssql-info` (MSSQL-specific queries)
- [ ] Update `reference/core/registry.py` to include new category
- [ ] Test all SQLi commands on lab machines
- [ ] Document in `reference/docs/USAGE.md`

**Commands Added:** 7
**Files Modified:** 3
**Reference:** Sample JSON in analysis report lines 600-900

---

## Phase 2: Core Exploitation - Shell Establishment (Week 2)

### Priority: CRITICAL
**Objective:** Add shell listeners, reverse shells, payload generation

### Tasks

- [ ] Create `reference/data/commands/exploitation/shells.json`
- [ ] Add command: `nc-listener-setup` (netcat listener)
- [ ] Add command: `bash-reverse-shell` (bash /dev/tcp)
- [ ] Add command: `python-shell-upgrade` (PTY spawn)
- [ ] Add command: `msfvenom-windows-reverse-tcp` (Windows payload)
- [ ] Add command: `msfvenom-linux-reverse-tcp` (Linux payload)
- [ ] Add command: `msfvenom-php-webshell` (PHP payload)
- [ ] Add command: `msfvenom-aspx-webshell` (ASP.NET payload)
- [ ] Add command: `netcat-reverse-shell-mkfifo` (nc without -e)
- [ ] Add command: `python-reverse-shell` (Python socket)
- [ ] Add command: `perl-reverse-shell` (Perl one-liner)
- [ ] Add command: `php-reverse-shell` (PHP fsockopen)
- [ ] Add command: `stty-shell-stabilization` (full TTY upgrade)
- [ ] Update registry.py
- [ ] Test on Windows and Linux targets
- [ ] Document shell upgrade procedures

**Commands Added:** 12
**Files Modified:** 2
**Reference:** Sample JSON in analysis report lines 1100-1400

---

## Phase 3: Service Enumeration - WordPress & SMB (Week 3)

### Priority: HIGH
**Objective:** Add service-specific enumeration tools

### Tasks

#### WordPress Enumeration
- [ ] Create `reference/data/commands/recon/wordpress.json`
- [ ] Add command: `wpscan-enumerate-all` (users, plugins, themes)
- [ ] Add command: `wpscan-enumerate-users` (user enumeration only)
- [ ] Add command: `wpscan-enumerate-plugins` (vulnerable plugins)
- [ ] Add command: `wpscan-password-attack` (password spraying)
- [ ] Add command: `wpscan-api-token-usage` (WPVulnDB integration)

#### SMB Enumeration
- [ ] Enhance `reference/data/commands/recon.json`
- [ ] Add command: `smb-null-session-shares` (smbclient -L)
- [ ] Add command: `smb-authenticated-access` (smbclient with creds)
- [ ] Add command: `crackmapexec-smb-auth` (credential validation)
- [ ] Add command: `enum4linux-full-enum` (comprehensive SMB enum)
- [ ] Add command: `rpcclient-enumdomusers` (RPC user enumeration)
- [ ] Add command: `smbmap-share-permissions` (smbmap usage)

#### Web Technology Detection
- [ ] Add command: `whatweb-scan` (technology fingerprinting)
- [ ] Add command: `curl-form-extraction` (HTML form parsing)
- [ ] Add command: `curl-virtual-host-testing` (vhost discovery)

**Commands Added:** 14
**Files Modified:** 3
**Reference:** Sample JSON in analysis report lines 200-600

---

## Phase 4: Research & Utilities (Week 4)

### Priority: HIGH
**Objective:** Add CVE research and common utilities

### Tasks

- [ ] Enhance `reference/data/commands/exploitation.json`
- [ ] Add command: `searchsploit-service` (CVE lookup)
- [ ] Add command: `searchsploit-mirror-exploit` (copy exploit to local)
- [ ] Add command: `searchsploit-examine-exploit` (view exploit code)
- [ ] Add command: `nmap-version-detection` (service fingerprinting)
- [ ] Add command: `nmap-vulnerability-scanning` (NSE vuln scripts)
- [ ] Add command: `gobuster-dir-enum` (directory enumeration)
- [ ] Add command: `gobuster-vhost-enum` (virtual host discovery)
- [ ] Add command: `nikto-web-scan` (web vulnerability scanner)

**Commands Added:** 8
**Files Modified:** 1
**Reference:** Capstone frequency analysis

---

## Phase 5: Database Exploitation (Week 5)

### Priority: MEDIUM
**Objective:** Add direct database connection and RCE commands

### Tasks

- [ ] Create `reference/data/commands/exploitation/databases.json`
- [ ] Add command: `psql-direct-connection` (PostgreSQL connection)
- [ ] Add command: `psql-read-file` (pg_read_file)
- [ ] Add command: `psql-list-directory` (pg_ls_dir)
- [ ] Add command: `psql-copy-from-program` (RCE via COPY)
- [ ] Add command: `mssql-enable-xp-cmdshell` (enable command execution)
- [ ] Add command: `mssql-xp-cmdshell-execution` (execute commands)
- [ ] Add command: `mysql-load-file` (file read)
- [ ] Add command: `mysql-into-outfile` (file write)

**Commands Added:** 8
**Files Modified:** 2
**Reference:** Capstone 3 (PostgreSQL), Capstone offsecatk (MSSQL)

---

## Phase 6: Password Attacks (Week 6)

### Priority: MEDIUM
**Objective:** Add credential testing and cracking tools

### Tasks

- [ ] Create `reference/data/commands/exploitation/passwords.json`
- [ ] Add command: `hydra-ssh-brute` (SSH brute force)
- [ ] Add command: `hydra-smb-brute` (SMB brute force)
- [ ] Add command: `hydra-http-post-form` (web login brute)
- [ ] Add command: `crackmapexec-password-spray` (SMB password spray)
- [ ] Add command: `hashcat-wordpress-hash` (phpass cracking)
- [ ] Add command: `hashcat-ntlm-hash` (Windows NTLM)
- [ ] Add command: `john-zip-crack` (ZIP password recovery)
- [ ] Add command: `john-ssh-key-crack` (SSH key passphrase)

**Commands Added:** 8
**Files Modified:** 2
**Reference:** Capstone 1 (hashcat), Capstone Lab 1 (password spray)

---

## Phase 7: Advanced Exploitation (Week 7)

### Priority: LOW
**Objective:** Add exploit modification and advanced techniques

### Tasks

- [ ] Create `reference/data/commands/exploitation/advanced.json`
- [ ] Add command: `mingw-cross-compile` (compile Windows exploits on Kali)
- [ ] Add command: `msfvenom-bad-characters` (shellcode with bad char avoidance)
- [ ] Add command: `msfvenom-encoder-usage` (payload encoding)
- [ ] Add command: `wine-execute-exploit` (run Windows exploits on Kali)
- [ ] Add command: `curl-path-as-is` (Apache CVE-2021-41773 exploitation)
- [ ] Add command: `asp-net-viewstate-extraction` (ASP.NET parameter extraction)
- [ ] Add command: `asp-net-sqli-waitfor` (MSSQL time-based detection)

**Commands Added:** 7
**Files Modified:** 2
**Reference:** Capstone Lab 2 (Apache), Lab 4 (buffer overflow), offsecatk (ASP.NET)

---

## Implementation Checklist

### Per-Command Addition Process

For each command:
- [ ] Create JSON definition with all required fields
- [ ] Add `id`, `name`, `category`, `subcategory`, `command`
- [ ] Add `description`, `tags`, `variables`
- [ ] Add `flags` with explanations
- [ ] Add `success_indicators` and `failure_indicators`
- [ ] Add `oscp_relevance` and `time_estimate`
- [ ] Add `manual_alternative` section
- [ ] Add `common_issues` with solutions
- [ ] Test command on lab machine
- [ ] Verify `crack reference --fill <ID>` works
- [ ] Update stats: `crack reference --stats`
- [ ] Commit changes

### Per-Category Addition Process

For each new category file:
- [ ] Create JSON file in appropriate directory
- [ ] Follow schema: `reference/data/schemas/command.schema.json`
- [ ] Update `reference/core/registry.py` categories dict
- [ ] Add to `reference/docs/CATEGORIES.md`
- [ ] Run validation: `crack reference --validate`
- [ ] Test category query: `crack reference --category=<NAME> --list`
- [ ] Update README with new category
- [ ] Commit changes

---

## Testing Requirements

### Per-Phase Testing

After each phase:
- [ ] Run full validation: `crack reference --validate`
- [ ] Check stats: `crack reference --stats`
- [ ] Test all new commands on OSCP lab machines
- [ ] Verify flag explanations are accurate
- [ ] Verify placeholder substitution works
- [ ] Verify manual alternatives work
- [ ] Update `reference/docs/USAGE.md` with examples
- [ ] Run command search: `crack reference --search <KEYWORD>`
- [ ] Test tag filtering: `crack reference --tag=OSCP:HIGH`

### Final Testing (After Phase 7)

- [ ] Test all 147 commands (110 existing + 37 new)
- [ ] Verify category distribution balanced (recon/web/exploit/post-exploit)
- [ ] Generate comprehensive usage examples
- [ ] Update CHANGELOG.md with all additions
- [ ] Create PR with detailed summary
- [ ] Review with command-registry-maintainer agent

---

## Success Metrics

### Before Enhancement
- Total commands: 110
- Recon: 7 (6.4%)
- Web: 9 (8.2%)
- Exploitation: 10 (9.1%)
- Post-exploit: 84 (76.3%)

### After Enhancement (Target)
- Total commands: 147 (+37)
- Recon: 17 (11.6%) ✓ +10 commands
- Web: 17 (11.6%) ✓ +8 commands
- Exploitation: 35 (23.8%) ✓ +25 commands
- Post-exploit: 84 (57.1%) ✓ No change

### Quality Metrics
- [ ] All commands have complete JSON definitions
- [ ] All commands tested on lab machines
- [ ] All commands have manual alternatives
- [ ] All commands have OSCP relevance tags
- [ ] 100% schema validation passing
- [ ] Zero duplicate command IDs
- [ ] All placeholders have variable definitions

---

## Reference Files

### Analysis Documents
- **Capstone Analysis Report:** Lines 1-2000 of this conversation
- **Gap Analysis:** Lines 200-400
- **Priority Matrix:** Lines 500-700
- **Sample JSON Commands:** Lines 800-1500

### Code References
- **Registry:** `reference/core/registry.py:97-106` (categories dict)
- **Schema:** `reference/data/schemas/command.schema.json`
- **Validator:** `reference/core/validator.py:60` (valid_categories)
- **CLI:** `reference/cli.py` (command routing)

### Documentation
- **Usage Guide:** `reference/docs/USAGE.md`
- **Categories:** `reference/docs/CATEGORIES.md`
- **Placeholders:** `reference/docs/PLACEHOLDERS.md`
- **Tags:** `reference/docs/TAGS.md`

---

## Timeline

| Week | Phase | Commands | Focus Area |
|------|-------|----------|------------|
| 1 | SQLi Workflow | +7 | Web exploitation |
| 2 | Shell Establishment | +12 | Reverse shells |
| 3 | Service Enumeration | +14 | WordPress, SMB |
| 4 | Research & Utilities | +8 | CVE lookup |
| 5 | Database Exploitation | +8 | Direct DB access |
| 6 | Password Attacks | +8 | Credential testing |
| 7 | Advanced Exploitation | +7 | Exploit modification |
| **Total** | **7 Phases** | **+64** | **All areas** |

**Note:** Original target was +37 commands. With detailed analysis, we identified +64 valuable commands. Prioritize Phases 1-4 first (+41 commands) to meet original goal.

---

## Quick Start (Priority Commands Only)

If implementing only TIER 1 critical commands (15 total):

### Week 1: Immediate Value
- [ ] `wpscan-enumerate-all` (WordPress)
- [ ] `smb-null-session-shares` (SMB)
- [ ] `searchsploit-service` (CVE research)
- [ ] `whatweb-scan` (Web fingerprinting)
- [ ] `crackmapexec-smb-auth` (Credential testing)

### Week 2: Exploitation Core
- [ ] `sqli-detection-error` (SQLi detection)
- [ ] `sqli-column-enum-orderby` (Column enumeration)
- [ ] `sqli-union-select-basic` (Data extraction)
- [ ] `sqlmap-post-exploitation` (Automated SQLi)

### Week 3: Shell Establishment
- [ ] `nc-listener-setup` (Listener)
- [ ] `bash-reverse-shell` (Bash shell)
- [ ] `python-shell-upgrade` (TTY upgrade)
- [ ] `msfvenom-windows-reverse-tcp` (Payload generation)

### Week 4: Additional Utilities
- [ ] `enum4linux-full-enum` (SMB enumeration)
- [ ] `rpcclient-enumdomusers` (RPC users)

**Total:** 15 commands (+13.6% to existing 110)

---

## Maintenance

### Post-Implementation
- [ ] Monthly review of command usage statistics
- [ ] Quarterly update based on new OSCP machine releases
- [ ] Continuous testing on lab machines
- [ ] Community feedback integration
- [ ] Version tagging in git

### Documentation Updates
- [ ] Update README.md with new command count
- [ ] Update USAGE.md with new examples
- [ ] Create video tutorials for new workflows
- [ ] Add to track module service plugins if applicable

---

**Status:** Planning Complete
**Next Action:** Begin Phase 1 (SQLi Workflow)
**Estimated Completion:** 7 weeks (full) OR 4 weeks (priority only)
