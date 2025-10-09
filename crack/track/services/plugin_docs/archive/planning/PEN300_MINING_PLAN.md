# PEN-300 CRACK Track Plugin Mining Plan

**Document Version:** 1.0
**Date:** 2025-10-08
**Objective:** Extract OSCP-relevant enumeration tasks from PEN-300 chapters to enhance CRACK Track plugins using parallel CrackPot agents

---

## Executive Summary

### Resources Available
- **14 chapters** extracted from PEN-300 (705 pages, ~41,563 lines)
- **120+ existing plugins** in `crack/track/services/`
- **Target:** Zero-duplicate, lean, comprehensive enhancement

### Chapter Inventory

| Chapter | Lines | Size | Focus Area |
|---------|-------|------|------------|
| Ch 1    | 420   | Small | Course intro, methodology |
| Ch 2    | 4,858 | Large | Programming theory, Windows concepts |
| Ch 4    | 1,680 | Medium | JScript droppers |
| Ch 5    | 1,671 | Medium | Shellcode injection, DLL injection |
| Ch 6    | 16,950 | **MASSIVE** | AV evasion (301 pages!) |
| Ch 7    | 58    | Tiny | AMSI bypasses |
| Ch 8    | 116   | Small | AppLocker bypasses |
| Ch 10   | 116   | Small | Linux config files, shared libs |
| Ch 12   | 2,786 | Large | Windows credentials, Kerberos |
| Ch 13   | 4,344 | Large | RDP, lateral movement |
| Ch 15   | 2,186 | Medium | MS SQL in AD |
| Ch 16   | 6,261 | Large | AD permissions, forests, delegation |
| Ch 17   | 57    | Tiny | AD enumeration |
| Ch 18   | 60    | Tiny | Real-world simulations |

### Existing Plugin Coverage

**Strong Coverage (likely minimal additions):**
- `ad_attacks.py`, `ad_enumeration.py`, `ad_persistence.py`
- `windows_privesc.py`, `windows_privesc_extended.py`
- `smb.py`, `ssh.py`, `remote_access.py`
- `client_side_attacks.py`, `phishing.py`
- `lateral_movement.py`

**Potentially Sparse Coverage:**
- Windows evasion techniques (AV, AMSI, AppLocker)
- Advanced AD delegation attacks
- MS SQL in AD context
- Linux post-exploitation enumeration
- Credential extraction techniques

---

## Critical Pre-Mining Requirements

### MANDATORY AGENT WORKFLOW

**Every agent MUST follow this sequence:**

```
1. READ: /home/kali/OSCP/crack/track/PLUGIN_CONTRIBUTION_GUIDE.md
   └─> Understand schema, metadata requirements, OSCP focus

2. IDENTIFY: Target plugin file(s) for enhancement
   └─> Map chapter content to existing plugin(s)

3. READ: Existing plugin file(s) completely
   └─> Document current tasks, commands, coverage gaps

4. ANALYZE: Chapter content with gap analysis lens
   └─> Extract ONLY novel techniques not in existing plugin

5. GENERATE: Enhancement proposals (new tasks only)
   └─> Full metadata: commands, flags, alternatives, OSCP tags

6. VALIDATE: Against contribution guide checklist
   └─> Ensure schema compliance, no duplicates

7. DOCUMENT: Mining report with before/after comparison
   └─> Show exactly what's new vs. what already exists
```

### Duplicate Prevention Protocol

**Before proposing ANY task addition:**

1. **Command-level check:** Does this exact command already exist?
2. **Technique-level check:** Does an equivalent technique exist with different syntax?
3. **Tool-level check:** Is this tool already covered in alternatives?
4. **Value assessment:** Does this add substantive OSCP value?

**If uncertain:** Document as "POTENTIAL DUPLICATE - NEEDS REVIEW" with comparison notes.

---

## Phase 1: Core Service Enumeration (PRIORITY: CRITICAL)

**Focus:** Direct enumeration techniques for network services
**Agents:** 3 parallel
**Estimated Runtime:** 2-3 hours per agent

### Agent 1.1: Windows RDP & Lateral Movement

**Assignment:**
- **Source:** Chapter 13 (4,344 lines) - Remote Desktop Protocol
- **Target Plugins:** `remote_access.py`, `lateral_movement.py`, `windows_core.py`
- **Focus Areas:**
  - RDP enumeration commands
  - Fileless lateral movement techniques
  - WMI/DCOM/PSRemoting alternatives
  - Credential relay attacks

**Mandatory Pre-Mining:**
1. Read existing `remote_access.py` - document all RDP tasks
2. Read existing `lateral_movement.py` - document all lateral movement methods
3. Read existing `windows_core.py` - document Windows-specific techniques
4. **GAP ANALYSIS:** Identify what Chapter 13 adds beyond current coverage

**Extraction Criteria:**
- ✅ Enumeration commands (service discovery, user enumeration)
- ✅ Lateral movement techniques with command examples
- ✅ Manual alternatives for tool failures
- ❌ Skip: Pure exploitation code, payload generation
- ❌ Skip: Theory without actionable commands

**Deliverable:** `PEN300_RDP_LATERAL_MINING_REPORT.md`
- Section 1: Existing plugin task inventory
- Section 2: Chapter 13 novel techniques (with line numbers)
- Section 3: Proposed new tasks (full schema)
- Section 4: Duplicate analysis (what was skipped and why)

---

### Agent 1.2: MS SQL in Active Directory

**Assignment:**
- **Source:** Chapter 15 (2,186 lines) - MS SQL in Active Directory
- **Target Plugins:** `sql.py`, `ad_attacks.py`, `postgresql.py` (for comparison)
- **Focus Areas:**
  - MS SQL enumeration in domain context
  - Linked SQL server traversal
  - SQL-based privilege escalation
  - xp_cmdshell abuse, TRUSTWORTHY abuse

**Mandatory Pre-Mining:**
1. Read `sql.py` - document all MS SQL tasks
2. Read `ad_attacks.py` - document SQL-related AD attacks
3. Read `postgresql.py` - compare enumeration patterns
4. **GAP ANALYSIS:** Chapter 15 AD-specific SQL techniques vs. generic SQL plugin

**Extraction Criteria:**
- ✅ SQL enumeration commands (users, roles, linked servers)
- ✅ AD integration checks (Kerberos auth, SPNs)
- ✅ Privilege escalation paths unique to MS SQL
- ✅ Manual SQL queries for tool-less enumeration
- ❌ Skip: Database-agnostic attacks (already in sql.py)

**Deliverable:** `PEN300_MSSQL_AD_MINING_REPORT.md`

---

### Agent 1.3: SSH & Linux Lateral Movement

**Assignment:**
- **Source:** Chapter 14 (MISSING - use Ch 10 as proxy: 116 lines)
- **Fallback Source:** Chapter 10 - User Config Files, Shared Libraries
- **Target Plugins:** `ssh.py`, `linux_enumeration.py`, `linux_persistence.py`
- **Focus Areas:**
  - SSH key discovery and abuse
  - Linux lateral movement techniques
  - Shared library hijacking enumeration
  - User config file mining (.bashrc, .ssh/config, etc.)

**Mandatory Pre-Mining:**
1. Read `ssh.py` - document all SSH enumeration tasks
2. Read `linux_enumeration.py` - document config file checks
3. Read `linux_persistence.py` - document shared lib techniques
4. **GAP ANALYSIS:** Chapter 10 practical techniques vs. theoretical coverage

**Extraction Criteria:**
- ✅ SSH configuration enumeration
- ✅ User config file locations and parsing commands
- ✅ Shared library discovery commands
- ✅ Kerberos on Linux (if present)
- ❌ Skip: Techniques already in linux_enumeration.py

**Deliverable:** `PEN300_LINUX_LATERAL_MINING_REPORT.md`

---

## Phase 2: Active Directory Attacks (PRIORITY: HIGH)

**Focus:** AD-specific enumeration and attack paths
**Agents:** 3 parallel
**Estimated Runtime:** 2-3 hours per agent

### Agent 2.1: AD Credentials & Kerberos

**Assignment:**
- **Source:** Chapter 12 (2,786 lines) - Local Windows Credentials
- **Target Plugins:** `ad_enumeration.py`, `credential_theft.py`, `ad_attacks.py`
- **Focus Areas:**
  - Access token enumeration
  - Kerberos ticket extraction
  - Domain credential discovery
  - Offline credential processing (mimikatz, pypykatz alternatives)

**Mandatory Pre-Mining:**
1. Read `credential_theft.py` - full task inventory
2. Read `ad_enumeration.py` - credential discovery tasks
3. Read `ad_attacks.py` - Kerberos attack methods
4. **GAP ANALYSIS:** Chapter 12 enumeration vs. exploitation focus

**Extraction Criteria:**
- ✅ **ENUMERATION ONLY:** Commands to discover/extract credentials
- ✅ Manual techniques (registry, LSA secrets, SAM)
- ✅ Kerberos ticket discovery commands
- ❌ Skip: Pure exploitation (pass-the-hash execution)
- ❌ Skip: Duplicate mimikatz commands already documented

**Deliverable:** `PEN300_AD_CREDS_MINING_REPORT.md`

---

### Agent 2.2: AD Permissions & Delegation

**Assignment:**
- **Source:** Chapter 16 (6,261 lines) - AD Object Security Permissions
- **Target Plugins:** `ad_attacks.py`, `ad_persistence.py`, `ad_enumeration.py`
- **Focus Areas:**
  - ACL enumeration (BloodHound alternatives)
  - Kerberos delegation attacks (unconstrained, constrained, RBCD)
  - Forest trust enumeration
  - Cross-forest attack paths

**Mandatory Pre-Mining:**
1. Read `ad_attacks.py` - document delegation techniques
2. Read `ad_persistence.py` - document ACL abuse
3. Read `ad_enumeration.py` - document permission checks
4. **GAP ANALYSIS:** Chapter 16 advanced techniques vs. basic AD coverage

**Extraction Criteria:**
- ✅ ACL enumeration commands (PowerView, native tools)
- ✅ Delegation discovery commands
- ✅ Forest trust enumeration
- ✅ Manual LDAP queries for tool-less enumeration
- ❌ Skip: Techniques already in ad_attacks.py

**Deliverable:** `PEN300_AD_DELEGATION_MINING_REPORT.md`

---

### Agent 2.3: AD Enumeration Fundamentals

**Assignment:**
- **Source:** Chapter 17 (57 lines) - Enumeration and Shell
- **Supplemental:** Chapter 1 (420 lines) - Course methodology
- **Target Plugins:** `ad_enumeration.py`, `external_recon.py`
- **Focus Areas:**
  - Foundational AD enumeration commands
  - Manual enumeration techniques
  - Methodology for assumed breach scenarios

**Mandatory Pre-Mining:**
1. Read `ad_enumeration.py` - complete task list
2. Read `external_recon.py` - recon methodology
3. **GAP ANALYSIS:** Chapters 1 & 17 foundational vs. existing coverage

**Extraction Criteria:**
- ✅ Basic AD enumeration (users, groups, computers)
- ✅ Manual alternatives to PowerView/SharpHound
- ✅ Methodology tips (convert to task metadata/notes)
- ❌ Skip: Duplicate PowerView commands

**Deliverable:** `PEN300_AD_ENUM_FUNDAMENTALS_MINING_REPORT.md`

---

## Phase 3: Privilege Escalation (PRIORITY: HIGH)

**Focus:** Post-exploitation privilege escalation techniques
**Agents:** 3 parallel
**Estimated Runtime:** 1.5-2 hours per agent

### Agent 3.1: Windows Privilege Escalation Advanced

**Assignment:**
- **Source:** Chapter 11 (MISSING - use Ch 8 as proxy: 116 lines)
- **Fallback:** Chapter 8 - AppLocker bypasses
- **Target Plugins:** `windows_privesc.py`, `windows_privesc_extended.py`
- **Focus Areas:**
  - Kiosk breakout techniques
  - AppLocker bypass enumeration
  - Privilege escalation post-bypass

**Mandatory Pre-Mining:**
1. Read `windows_privesc.py` - document all PrivEsc tasks
2. Read `windows_privesc_extended.py` - document extended techniques
3. **GAP ANALYSIS:** Chapter 8 bypass techniques vs. existing coverage

**Extraction Criteria:**
- ✅ Enumeration commands to detect AppLocker configuration
- ✅ Kiosk breakout enumeration techniques
- ✅ Manual bypass verification commands
- ❌ Skip: Pure bypass code/payloads (not enumeration)

**Deliverable:** `PEN300_WINDOWS_PRIVESC_ADVANCED_MINING_REPORT.md`

---

### Agent 3.2: Linux Post-Exploitation

**Assignment:**
- **Source:** Chapter 10 (116 lines) - User Configuration Files
- **Target Plugins:** `linux_privesc.py`, `linux_privesc_advanced.py`, `linux_enumeration.py`
- **Focus Areas:**
  - User config file enumeration (.bashrc, .profile, .ssh/)
  - Shared library hijacking detection
  - AV bypass on Linux (if applicable)

**Mandatory Pre-Mining:**
1. Read `linux_privesc.py` - document PrivEsc techniques
2. Read `linux_enumeration.py` - document config checks
3. **GAP ANALYSIS:** Chapter 10 practical config mining vs. existing

**Extraction Criteria:**
- ✅ Config file discovery commands
- ✅ Sensitive data in config files (API keys, passwords)
- ✅ Shared library path checks
- ❌ Skip: Generic Linux enum already covered

**Deliverable:** `PEN300_LINUX_POSTEXPLOIT_MINING_REPORT.md`

---

### Agent 3.3: Advanced Process Injection

**Assignment:**
- **Source:** Chapter 5 (1,671 lines) - Finding a Home for Our Shellcode
- **Target Plugins:** `windows_core.py`, `reversing.py`, `post_exploit.py`
- **Focus Areas:**
  - DLL injection detection
  - Reflective DLL injection indicators
  - Process hollowing detection
  - Memory enumeration techniques

**Mandatory Pre-Mining:**
1. Read `windows_core.py` - document injection techniques
2. Read `reversing.py` - document analysis methods
3. Read `post_exploit.py` - document process manipulation
4. **GAP ANALYSIS:** Chapter 5 defensive enumeration perspective

**Extraction Criteria:**
- ✅ **DETECTION FOCUS:** Enumerate running processes for injection
- ✅ Memory analysis commands (task manager alternatives)
- ✅ DLL enumeration for suspicious injections
- ❌ Skip: Offensive injection code (out of scope)
- ❌ Skip: Duplicate process enumeration

**Deliverable:** `PEN300_PROCESS_INJECTION_ENUM_MINING_REPORT.md`

---

## Phase 4: Client-Side & Evasion (PRIORITY: MEDIUM)

**Focus:** Client-side attack enumeration and defensive evasion detection
**Agents:** 5 parallel
**Estimated Runtime:** 1-2 hours per agent

### Agent 4.1: Antivirus Evasion - Part 1 (Detection)

**Assignment:**
- **Source:** Chapter 6 (16,950 lines) - FIRST 5,000 lines
- **Target Plugins:** `windows_core.py`, `anti_forensics.py`
- **Focus Areas:**
  - AV software detection and enumeration
  - Signature location techniques
  - Behavior analysis indicators

**Mandatory Pre-Mining:**
1. Read `anti_forensics.py` - document AV detection tasks
2. Read `windows_core.py` - document security software checks
3. **GAP ANALYSIS:** Chapter 6 (first third) detection techniques

**Extraction Criteria:**
- ✅ Commands to detect installed AV software
- ✅ AV configuration enumeration (disabled features)
- ✅ Signature database locations
- ✅ Manual registry checks for AV presence
- ❌ Skip: AV bypass code (not enumeration)

**Deliverable:** `PEN300_AV_DETECTION_PART1_MINING_REPORT.md`

---

### Agent 4.2: Antivirus Evasion - Part 2 (Configuration)

**Assignment:**
- **Source:** Chapter 6 (16,950 lines) - Lines 5,001-10,000
- **Target Plugins:** `windows_core.py`, `anti_forensics.py`
- **Focus Areas:**
  - AV behavior simulation enumeration
  - Sandbox detection techniques
  - Exclusion path discovery

**Mandatory Pre-Mining:**
1. Review Agent 4.1's deliverable (avoid overlap)
2. Read relevant sections of `anti_forensics.py`
3. **GAP ANALYSIS:** Middle third of Chapter 6

**Extraction Criteria:**
- ✅ Sandbox environment detection
- ✅ AV exclusion path enumeration
- ✅ Real-time protection status checks
- ❌ Skip: Content covered by Agent 4.1

**Deliverable:** `PEN300_AV_CONFIG_PART2_MINING_REPORT.md`

---

### Agent 4.3: Antivirus Evasion - Part 3 (Advanced)

**Assignment:**
- **Source:** Chapter 6 (16,950 lines) - Lines 10,001-16,950
- **Target Plugins:** `windows_core.py`, `anti_forensics.py`, `phishing.py`
- **Focus Areas:**
  - Office macro security detection
  - Advanced evasion technique enumeration
  - EDR detection

**Mandatory Pre-Mining:**
1. Review Agent 4.1 & 4.2 deliverables (avoid overlap)
2. Read `phishing.py` - Office security tasks
3. **GAP ANALYSIS:** Final third of Chapter 6

**Extraction Criteria:**
- ✅ Office security settings enumeration
- ✅ Macro policy detection commands
- ✅ EDR presence indicators
- ❌ Skip: Content from Parts 1 & 2

**Deliverable:** `PEN300_AV_ADVANCED_PART3_MINING_REPORT.md`

---

### Agent 4.4: AMSI & Windows Defenses

**Assignment:**
- **Source:** Chapter 7 (58 lines) - AMSI bypasses
- **Target Plugins:** `windows_core.py`, `anti_forensics.py`
- **Focus Areas:**
  - AMSI status detection
  - UAC configuration enumeration
  - Windows Defender status checks

**Mandatory Pre-Mining:**
1. Read `windows_core.py` - Windows security checks
2. Read `anti_forensics.py` - defense mechanism detection
3. **GAP ANALYSIS:** Chapter 7 defense enumeration

**Extraction Criteria:**
- ✅ AMSI status detection commands
- ✅ UAC level enumeration
- ✅ Windows Defender feature checks (real-time, cloud, etc.)
- ❌ Skip: AMSI bypass code (not enumeration)

**Deliverable:** `PEN300_AMSI_DEFENSES_MINING_REPORT.md`

---

### Agent 4.5: Client-Side Attack Preparation

**Assignment:**
- **Source:** Chapter 4 (1,680 lines) - JScript Droppers
- **Supplemental:** Chapter 2 (4,858 lines) - Programming Theory (selective)
- **Target Plugins:** `client_side_attacks.py`, `phishing.py`
- **Focus Areas:**
  - Client environment enumeration
  - Target reconnaissance for client-side attacks
  - Office/browser version detection

**Mandatory Pre-Mining:**
1. Read `client_side_attacks.py` - document recon tasks
2. Read `phishing.py` - document target profiling
3. **GAP ANALYSIS:** Chapters 2 & 4 recon vs. attack delivery

**Extraction Criteria:**
- ✅ **ENUMERATION ONLY:** Target environment discovery
- ✅ Office version detection commands
- ✅ PowerShell version enumeration
- ✅ Execution policy checks
- ❌ Skip: Dropper code, payload generation

**Deliverable:** `PEN300_CLIENT_RECON_MINING_REPORT.md`

---

## Phase 5: Advanced Topics (PRIORITY: MEDIUM)

**Focus:** Specialized techniques and real-world scenarios
**Agents:** 3 parallel
**Estimated Runtime:** 1 hour per agent

### Agent 5.1: Network Evasion & Tunneling

**Assignment:**
- **Source:** Chapter 9 (MISSING - use available content)
- **Fallback:** Table of Contents references (Web Proxies, DNS Tunneling)
- **Target Plugins:** `network_poisoning.py`, `c2_operations.py`
- **Focus Areas:**
  - Proxy detection and enumeration
  - DNS configuration discovery
  - Network security control detection

**Mandatory Pre-Mining:**
1. Read `network_poisoning.py` - network detection tasks
2. Read `c2_operations.py` - C2 infrastructure checks
3. **GAP ANALYSIS:** Infer from ToC what enumeration applies

**Extraction Criteria:**
- ✅ Proxy configuration discovery
- ✅ DNS server enumeration
- ✅ Firewall/IDS detection techniques
- ❌ Skip: Pure tunneling tools (not enumeration)

**Deliverable:** `PEN300_NETWORK_EVASION_MINING_REPORT.md`

---

### Agent 5.2: Real-World Scenario Methodology

**Assignment:**
- **Source:** Chapter 18 (60 lines) - Real Life Simulations
- **Target Plugins:** `external_recon.py`, `web_methodology.py`
- **Focus Areas:**
  - Engagement methodology
  - Practical enumeration workflows
  - OSCP exam-relevant tips

**Mandatory Pre-Mining:**
1. Read `web_methodology.py` - methodology tasks
2. Read `external_recon.py` - recon workflows
3. **GAP ANALYSIS:** Chapter 18 practical vs. theoretical

**Extraction Criteria:**
- ✅ Methodology tips (convert to task metadata)
- ✅ Enumeration workflow recommendations
- ✅ Common pitfalls (convert to failure_indicators)
- ❌ Skip: Pure theory without commands

**Deliverable:** `PEN300_METHODOLOGY_MINING_REPORT.md`

---

### Agent 5.3: Cross-Cutting Techniques

**Assignment:**
- **Source:** Multi-chapter review (Chapters 1, 2, 17, 18)
- **Target Plugins:** Multiple (based on findings)
- **Focus Areas:**
  - Techniques mentioned across multiple chapters
  - Foundational enumeration patterns
  - Common pitfalls and alternatives

**Mandatory Pre-Mining:**
1. Review all previous agent deliverables
2. Identify cross-cutting patterns
3. **GAP ANALYSIS:** Cross-chapter insights vs. plugin coverage

**Extraction Criteria:**
- ✅ Techniques mentioned in 2+ chapters (high importance)
- ✅ Foundational enumeration commands (often skipped)
- ✅ Manual alternatives emphasized across chapters
- ❌ Skip: Already captured by other agents

**Deliverable:** `PEN300_CROSSCUTTING_MINING_REPORT.md`

---

## Output Format Standard

**Every agent deliverable MUST include:**

### Section 1: Pre-Mining Analysis
```markdown
## Existing Plugin Review

**Plugin:** `plugin_name.py`
**Current Task Count:** XX tasks
**Current Coverage:**
- Task 1: [command] - [description]
- Task 2: [command] - [description]
...

**Coverage Gaps Identified:**
1. Gap 1 description
2. Gap 2 description
...
```

### Section 2: Chapter Analysis
```markdown
## Chapter Content Analysis

**Source:** Chapter X (Y lines)
**Relevant Sections:**
- Section X.Y (pages Z1-Z2): [topic]
- Section X.Z (pages Z3-Z4): [topic]

**Novel Techniques Found:** XX
**Duplicate Techniques Found:** YY
**Irrelevant Content Skipped:** ZZ pages
```

### Section 3: Proposed Enhancements
```markdown
## Proposed Plugin Enhancements

### Enhancement 1: [Task Name]

**Duplicate Check:** ❌ NOT in existing plugin
**Source:** Chapter X, Section X.Y, Page Z, Lines A-B

**Proposed Task Schema:**
```python
{
    'id': 'task-id-with-port',
    'name': 'Task Name',
    'type': 'command',
    'metadata': {
        'command': 'full command here',
        'description': 'What this accomplishes',
        'flag_explanations': {
            '-flag': 'Explanation'
        },
        'success_indicators': [...],
        'failure_indicators': [...],
        'next_steps': [...],
        'alternatives': [...],
        'tags': ['OSCP:HIGH', 'QUICK_WIN', ...],
        'estimated_time': 'X minutes',
        'notes': 'Additional context from chapter'
    }
}
```

**Justification:** Why this adds value
**OSCP Relevance:** High/Medium/Low
```

### Section 4: Duplicates Identified
```markdown
## Duplicate Analysis

### Technique: [name]
**Found in Chapter:** X, Page Y
**Already in Plugin:** `plugin.py`, Line Z
**Command Comparison:**
- Chapter: `command from chapter`
- Existing: `command from plugin`
**Decision:** SKIP - duplicate

### Technique: [name]
**Found in Chapter:** X, Page Y
**Similar to Plugin:** `plugin.py`, Line Z
**Key Difference:** [explanation]
**Decision:** INCLUDE - adds unique value because [reason]
```

### Section 5: Summary
```markdown
## Mining Summary

**Total Techniques in Chapter:** XX
**Novel Techniques Proposed:** YY
**Duplicates Skipped:** ZZ
**Enhancements to Plugin:** `plugin.py`

**Quality Metrics:**
- Schema compliance: ✅ All tasks validated
- Flag explanations: ✅ All flags explained
- Alternatives: ✅ All tasks have manual alternatives
- OSCP tags: ✅ All tasks prioritized

**Recommendations:**
- [Any special notes or considerations]
```

---

## Execution Strategy

### Parallel Execution Plan

**Phase 1 Agents (Run simultaneously):**
```bash
# Terminal 1
crack-agent CrackPot --task="PEN300 Mining Agent 1.1" --config=agent_1_1_config.json

# Terminal 2
crack-agent CrackPot --task="PEN300 Mining Agent 1.2" --config=agent_1_2_config.json

# Terminal 3
crack-agent CrackPot --task="PEN300 Mining Agent 1.3" --config=agent_1_3_config.json
```

**Wait for Phase 1 completion, review outputs, then proceed to Phase 2**

### Agent Configuration Template

Each agent should receive:

```json
{
  "agent_name": "PEN300_Mining_Agent_X.Y",
  "pre_mining_requirements": [
    "READ: /home/kali/OSCP/crack/track/PLUGIN_CONTRIBUTION_GUIDE.md",
    "READ: /home/kali/OSCP/crack/track/services/target_plugin.py",
    "ANALYZE: Existing task coverage"
  ],
  "source_chapter": "/home/kali/OSCP/crack/.references/pen-300-chapters/chapter_XX.txt",
  "source_lines": "1-XXXX or XXXX-YYYY for splits",
  "target_plugins": [
    "/home/kali/OSCP/crack/track/services/plugin1.py",
    "/home/kali/OSCP/crack/track/services/plugin2.py"
  ],
  "focus_areas": ["area1", "area2", "area3"],
  "extraction_criteria": {
    "include": ["enumeration commands", "manual techniques"],
    "exclude": ["pure exploitation code", "duplicate commands"]
  },
  "output_file": "/home/kali/OSCP/crack/track/services/plugin_docs/PENXXX_TOPIC_MINING_REPORT.md",
  "output_format": "Standard format from plan",
  "duplicate_prevention": true,
  "quality_checklist": true
}
```

---

## Quality Control

### Pre-Submission Checklist (Per Agent)

**Agent Self-Validation:**
- [ ] Pre-mining: Read PLUGIN_CONTRIBUTION_GUIDE.md
- [ ] Pre-mining: Read all target plugins completely
- [ ] Gap analysis: Documented existing coverage
- [ ] Extraction: Only novel techniques proposed
- [ ] Schema: All tasks follow plugin contribution schema
- [ ] Metadata: All required fields present
- [ ] Flags: Every flag explained with "why"
- [ ] Alternatives: Every task has manual alternatives
- [ ] Tags: OSCP priority tags assigned
- [ ] Duplicates: Duplicate analysis section complete
- [ ] Justification: Each addition justified

### Human Review Checklist (Post-Mining)

**Before integration:**
- [ ] Review duplicate analysis - verify no false negatives
- [ ] Spot-check commands for accuracy
- [ ] Verify OSCP relevance (High priority tasks are truly valuable)
- [ ] Check schema compliance across all proposals
- [ ] Assess lean principle - no bloat, only value-adds

---

## Success Metrics

### Quantitative Goals
- **Zero duplicates:** No proposed task already exists in target plugin
- **Coverage improvement:** 10-30% increase in task coverage per plugin
- **OSCP relevance:** 80%+ of proposals tagged OSCP:HIGH or OSCP:MEDIUM
- **Schema compliance:** 100% of proposals pass contribution guide validation

### Qualitative Goals
- **Lean library:** Every addition adds substantive value
- **Manual alternatives:** 100% of automated tasks have manual fallbacks
- **Flag education:** Every flag explained with purpose
- **Attack chain guidance:** next_steps connect tasks logically

---

## Timeline Estimate

| Phase | Agents | Est. Runtime | Deliverables |
|-------|--------|--------------|--------------|
| Phase 1 | 3 parallel | 2-3 hours | 3 mining reports |
| Phase 2 | 3 parallel | 2-3 hours | 3 mining reports |
| Phase 3 | 3 parallel | 1.5-2 hours | 3 mining reports |
| Phase 4 | 5 parallel | 1-2 hours | 5 mining reports |
| Phase 5 | 3 parallel | 1 hour | 3 mining reports |
| **Review** | Manual | 2-3 hours | Integration plan |
| **Total** | 17 agents | ~8-11 hours | 17 reports + integration |

**Total Wall-Clock Time (with parallel execution):** ~10-14 hours
**Total Agent-Hours:** ~28-38 hours

---

## Risk Mitigation

### Risk: Duplicate Work Between Agents

**Mitigation:**
- Clear chapter/focus area boundaries
- Pre-mining plugin review requirement
- Post-phase review before next phase
- Agent 5.3 performs cross-cutting duplicate check

### Risk: Low-Quality Extractions

**Mitigation:**
- Mandatory contribution guide review
- Detailed extraction criteria per agent
- Self-validation checklist
- Human review gate before integration

### Risk: OSCP Irrelevance

**Mitigation:**
- Focus on enumeration (exam-safe)
- Exclude pure exploitation code
- Prioritize manual alternatives
- Tag-based relevance filtering

---

## Next Steps

1. **Review this plan** with project lead
2. **Create agent configuration files** (17 configs)
3. **Prepare parallel execution environment** (5 terminals for max phase)
4. **Execute Phase 1** (3 agents)
5. **Review Phase 1 outputs** before proceeding
6. **Iterate through Phases 2-5**
7. **Consolidate findings** and create integration PR

---

**Document Owner:** Pentesting Mentor
**Review Status:** DRAFT - Awaiting Approval
**Last Updated:** 2025-10-08
