# CRACK Toolkit - Master Documentation Index

> **Last Updated:** 2025-10-10 | **Total Files:** 302 | **Active Docs:** 209 | **Archived:** 67 | **Internal Dev:** 26

## Quick Navigation

**By Audience:**
- [User Guides](#user-guides) - Getting started, usage, tutorials
- [Developer Guides](#developer-guides) - Contributing, architecture, implementation
- [OSCP Exam Prep](#mining-reports-oscp-focus) - Attack techniques by category
- [Command Reference](#reference-material) - Manual commands, NSE scripts

**By Task:**
- [I want to learn CRACK Track](#i-want-to-learn-crack-track)
- [I'm developing a new feature](#im-developing-a-new-feature)
- [I'm preparing for OSCP exam](#im-preparing-for-oscp-exam)
- [I need a specific command](#i-need-a-specific-command)

**By Module:**
- [Track Module](#track-module-documentation) - Enumeration tracking system
- [Reference System](#reference-system-documentation) - Command reference
- [Interactive Mode](#interactive-mode-tui) - Terminal UI system
- [Alternative Commands](#alternative-commands) - Manual fallback methods

---

## Documentation by Audience

### User Guides

**Project Overview & Getting Started**
- [`/home/kali/OSCP/crack/README.md`](/home/kali/OSCP/crack/README.md) - Main project README
- [`/home/kali/OSCP/crack/docs/guides/GETTING_STARTED.md`](/home/kali/OSCP/crack/docs/guides/GETTING_STARTED.md) - Quick start guide (relocated from STARTER_USAGE.md)

**Track Module**
- [`/home/kali/OSCP/crack/track/README.md`](/home/kali/OSCP/crack/track/README.md) - Comprehensive Track module guide
- [`/home/kali/OSCP/crack/track/docs/QUICKSTART_INTERACTIVE_TOOLS.md`](/home/kali/OSCP/crack/track/docs/QUICKSTART_INTERACTIVE_TOOLS.md) - Interactive tools quick start
- [`/home/kali/OSCP/crack/track/docs/USAGE_GUIDE.md`](/home/kali/OSCP/crack/track/docs/USAGE_GUIDE.md) - Detailed usage guide
- [`/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_GUIDE.md`](/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_GUIDE.md) - Interactive mode guide
- [`/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_TOOLS_GUIDE.md`](/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_TOOLS_GUIDE.md) - Interactive tools guide

**Alternative Commands**
- [`/home/kali/OSCP/crack/track/alternatives/README.md`](/home/kali/OSCP/crack/track/alternatives/README.md) - Alternative commands system
- [`/home/kali/OSCP/crack/track/alternatives/QUICKSTART.md`](/home/kali/OSCP/crack/track/alternatives/QUICKSTART.md) - Alternative commands quick start

**Reference System**
- [`/home/kali/OSCP/crack/reference/README.md`](/home/kali/OSCP/crack/reference/README.md) - Command reference system
- [`/home/kali/OSCP/crack/reference/docs/quick-reference.md`](/home/kali/OSCP/crack/reference/docs/quick-reference.md) - Quick command reference
- [`/home/kali/OSCP/crack/reference/docs/quick-wins.md`](/home/kali/OSCP/crack/reference/docs/quick-wins.md) - Quick win techniques

**Session Management**
- [`/home/kali/OSCP/crack/sessions/README.md`](/home/kali/OSCP/crack/sessions/README.md) - Session management
- [`/home/kali/OSCP/crack/sessions/TUNNEL_GUIDE.md`](/home/kali/OSCP/crack/sessions/TUNNEL_GUIDE.md) - Tunneling guide
- [`/home/kali/OSCP/crack/sessions/DNS_TUNNEL_GUIDE.md`](/home/kali/OSCP/crack/sessions/DNS_TUNNEL_GUIDE.md) - DNS tunneling
- [`/home/kali/OSCP/crack/sessions/ICMP_TUNNEL_GUIDE.md`](/home/kali/OSCP/crack/sessions/ICMP_TUNNEL_GUIDE.md) - ICMP tunneling
- [`/home/kali/OSCP/crack/sessions/SHELL_ENHANCEMENT_GUIDE.md`](/home/kali/OSCP/crack/sessions/SHELL_ENHANCEMENT_GUIDE.md) - Shell enhancement
- [`/home/kali/OSCP/crack/sessions/HTTP_BEACON_USAGE.md`](/home/kali/OSCP/crack/sessions/HTTP_BEACON_USAGE.md) - HTTP beacon usage

---

### Developer Guides

**Core Development**
- [`/home/kali/OSCP/crack/CLAUDE.md`](/home/kali/OSCP/crack/CLAUDE.md) - Development workflows & patterns
- [`/home/kali/OSCP/crack/track/docs/ARCHITECTURE.md`](/home/kali/OSCP/crack/track/docs/ARCHITECTURE.md) - System architecture
- [`/home/kali/OSCP/crack/track/docs/TUI_ARCHITECTURE.md`](/home/kali/OSCP/crack/track/docs/TUI_ARCHITECTURE.md) - TUI architecture

**Panel & Plugin Development**
- [`/home/kali/OSCP/crack/track/docs/PANEL_DEVELOPER_GUIDE.md`](/home/kali/OSCP/crack/track/docs/PANEL_DEVELOPER_GUIDE.md) - TUI panel development
- [`/home/kali/OSCP/crack/track/services/PLUGIN_CONTRIBUTION_GUIDE.md`](/home/kali/OSCP/crack/track/services/PLUGIN_CONTRIBUTION_GUIDE.md) - Service plugin development
- [`/home/kali/OSCP/crack/track/interactive/DEBUG_LOGGING_GUIDE.md`](/home/kali/OSCP/crack/track/interactive/DEBUG_LOGGING_GUIDE.md) - Debug logging guide
- [`/home/kali/OSCP/crack/track/docs/DEBUG_LOGGING_CHEATSHEET.md`](/home/kali/OSCP/crack/track/docs/DEBUG_LOGGING_CHEATSHEET.md) - Debug logging cheatsheet

**Component Documentation**
- [`/home/kali/OSCP/crack/track/interactive/components/ERROR_HANDLER_README.md`](/home/kali/OSCP/crack/track/interactive/components/ERROR_HANDLER_README.md) - Error handler
- [`/home/kali/OSCP/crack/track/interactive/state/README.md`](/home/kali/OSCP/crack/track/interactive/state/README.md) - State management
- [`/home/kali/OSCP/crack/track/wordlists/README.md`](/home/kali/OSCP/crack/track/wordlists/README.md) - Wordlist management

**Form Development**
- [`/home/kali/OSCP/crack/track/docs/panels/CREDENTIAL_FORM.md`](/home/kali/OSCP/crack/track/docs/panels/CREDENTIAL_FORM.md) - Credential form docs (relocated)
- [`/home/kali/OSCP/crack/track/docs/panels/CREDENTIAL_FORM_QUICKREF.md`](/home/kali/OSCP/crack/track/docs/panels/CREDENTIAL_FORM_QUICKREF.md) - Credential form quick ref (relocated)
- [`/home/kali/OSCP/crack/track/interactive/panels/FINDING_FORM_QUICKREF.md`](/home/kali/OSCP/crack/track/interactive/panels/FINDING_FORM_QUICKREF.md) - Finding form quick ref
- [`/home/kali/OSCP/crack/track/docs/components/INPUT_VALIDATOR.md`](/home/kali/OSCP/crack/track/docs/components/INPUT_VALIDATOR.md) - Input validator usage (relocated)

**Feature Implementation Docs**
- [`/home/kali/OSCP/crack/track/docs/implementation/`](/home/kali/OSCP/crack/track/docs/implementation/) - Feature implementation guides
  - `batch_execute.md` - Batch execution
  - `quick_execute.md` - Quick execution
  - `quick_export.md` - Quick export
  - `smart_suggest.md` - Smart suggestions
  - `task_filter.md` - Task filtering
  - `workflow_recorder.md` - Workflow recording

**Nmap Cookbook Integration**
- [`/home/kali/OSCP/crack/track/docs/nmap_cookbook/`](/home/kali/OSCP/crack/track/docs/nmap_cookbook/) - Nmap cookbook chapters
  - `chapter_03_enhancements.md` - Chapter 3 enhancements
  - `chapter_03_scan_profiles.md` - Scan profiles
  - `chapter_04_integration.md` - Chapter 4 integration
  - `chapter_08_quickstart.md` - Chapter 8 quickstart
  - `chapter_08_summary.md` - Chapter 8 summary
  - `chapter_09_nse_advanced.md` - NSE advanced

**Tool-Specific Guides**
- [`/home/kali/OSCP/crack/docs/PARAM_DISCOVERY_GUIDE.md`](/home/kali/OSCP/crack/docs/PARAM_DISCOVERY_GUIDE.md) - Parameter discovery
- [`/home/kali/OSCP/crack/docs/SCAN_ANALYZER.md`](/home/kali/OSCP/crack/docs/SCAN_ANALYZER.md) - Scan analyzer
- [`/home/kali/OSCP/crack/docs/PIPELINE_SQLI_FU.md`](/home/kali/OSCP/crack/docs/PIPELINE_SQLI_FU.md) - SQLi pipeline
- [`/home/kali/OSCP/crack/docs/TIME_SQLI_METHODOLOGY.md`](/home/kali/OSCP/crack/docs/TIME_SQLI_METHODOLOGY.md) - Time-based SQLi

**Integration & Checklists**
- [`/home/kali/OSCP/crack/track/docs/TOOL_INTEGRATION_MATRIX.md`](/home/kali/OSCP/crack/track/docs/TOOL_INTEGRATION_MATRIX.md) - Tool integration matrix
- ~~[`INTEGRATION_CHECKLIST.md`]~~ - ARCHIVED to `docs/archive/2025-10-10/`

**Troubleshooting & Analysis**
- [`/home/kali/OSCP/crack/track/docs/WINDOWS_PRIVESC_FIX.md`](/home/kali/OSCP/crack/track/docs/WINDOWS_PRIVESC_FIX.md) - Windows PrivEsc fix
- ~~[`FREEZE_ANALYSIS.md`]~~ - ARCHIVED to `docs/archive/2025-10-09/` (issue resolved)
- ~~[`HTTP_PLUGIN_FIX_REPORT.md`]~~ - ARCHIVED to `docs/archive/2025-10-09/` (issue resolved)

**Phase Implementation Reports** (ARCHIVED - See `track/docs/archive/development/`)
- ~~[`PHASE_2_IMPLEMENTATION_REPORT.md`]~~ - Archived (2025-10-10)
- ~~[`PHASE_4_COMPLETION_REPORT.md`]~~ - Archived (2025-10-10)
- ~~[`PHASE_5_6_COMPLETION_REPORT.md`]~~ - Archived (2025-10-10)
- ~~[`PHASE_6.4_6.5_COMPLETION_REPORT.md`]~~ - Archived (2025-10-10)
- ~~[`PHASE_6_1_6_2_IMPLEMENTATION_SUMMARY.md`]~~ - Archived (2025-10-10)
- ~~[`PHASE_6_3_COMPLETION_REPORT.md`]~~ - Archived (2025-10-10)

---

### API Documentation

- [`/home/kali/OSCP/crack/track/docs/INTERACTIVE_TOOLS_API.md`](/home/kali/OSCP/crack/track/docs/INTERACTIVE_TOOLS_API.md) - Interactive mode API

---

### Reference Material

**Command Reference System**
- [`/home/kali/OSCP/crack/reference/README.md`](/home/kali/OSCP/crack/reference/README.md) - Reference system overview
- [`/home/kali/OSCP/crack/reference/docs/config.md`](/home/kali/OSCP/crack/reference/docs/config.md) - Config management
- [`/home/kali/OSCP/crack/reference/docs/placeholders.md`](/home/kali/OSCP/crack/reference/docs/placeholders.md) - Variable placeholders
- [`/home/kali/OSCP/crack/reference/docs/tags.md`](/home/kali/OSCP/crack/reference/docs/tags.md) - Command tags
- [`/home/kali/OSCP/crack/reference/docs/quick-wins.md`](/home/kali/OSCP/crack/reference/docs/quick-wins.md) - Quick win techniques

**Nmap NSE Scripts**
- [`/home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md`](/home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md) - NSE scripts reference
- [`/home/kali/OSCP/crack/track/docs/NSE_QUICK_REFERENCE.md`](/home/kali/OSCP/crack/track/docs/NSE_QUICK_REFERENCE.md) - NSE quick reference

**Alternative Commands**
- [`/home/kali/OSCP/crack/track/alternatives/README.md`](/home/kali/OSCP/crack/track/alternatives/README.md) - Manual alternatives system
- [`/home/kali/OSCP/crack/track/alternatives/PRIVILEGE_ESCALATION_ALTERNATIVES.md`](/home/kali/OSCP/crack/track/alternatives/PRIVILEGE_ESCALATION_ALTERNATIVES.md) - PrivEsc alternatives
- [`/home/kali/OSCP/crack/track/alternatives/commands/FILE_TRANSFER_MINING_REPORT.md`](/home/kali/OSCP/crack/track/alternatives/commands/FILE_TRANSFER_MINING_REPORT.md) - File transfer methods

**Category Reference**
- [`/home/kali/OSCP/crack/track/interactive/CATEGORY_REFERENCE.md`](/home/kali/OSCP/crack/track/interactive/CATEGORY_REFERENCE.md) - Task categories reference

---

### Mining Reports (OSCP Focus)

#### High Priority (OSCP Exam Topics)

**Active Directory & Windows (22 reports)**
- [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/README.md) - PEN-300 overview
- AD Enumeration & Fundamentals:
  - `AD_INFRASTRUCTURE_MINING_REPORT.md` - AD infrastructure
  - `PEN300_AD_ENUM_FUNDAMENTALS_MINING_REPORT.md` - AD enumeration fundamentals
  - `PEN300_METHODOLOGY_MINING_REPORT.md` - Methodology
- Credential Attacks:
  - `PEN300_AD_CREDS_MINING_REPORT.md` - AD credential attacks
  - `PEN300_AD_DELEGATION_MINING_REPORT.md` - AD delegation attacks
- Lateral Movement:
  - `PEN300_RDP_LATERAL_MINING_REPORT.md` - RDP lateral movement
  - `PEN300_LINUX_LATERAL_MINING_REPORT.md` - Linux lateral movement
  - `PEN300_MSSQL_AD_MINING_REPORT.md` - MSSQL in AD
- Windows Privilege Escalation:
  - `PEN300_WINDOWS_PRIVESC_ADVANCED_MINING_REPORT.md` - Advanced Windows PrivEsc
- Evasion Techniques:
  - `PEN300_AV_DETECTION_PART1_MINING_REPORT.md` - AV detection (Part 1)
  - `PEN300_AV_CONFIG_PART2_MINING_REPORT.md` - AV config (Part 2)
  - `PEN300_AV_ADVANCED_PART3_MINING_REPORT.md` - AV advanced (Part 3)
  - `PEN300_AMSI_DEFENSES_REMINE_REPORT.md` - AMSI defenses
  - `PEN300_APPLOCKER_MINING_REPORT.md` - AppLocker bypasses
  - `PEN300_NETWORK_EVASION_REMINE_REPORT.md` - Network evasion
- Process & Code Injection:
  - `PEN300_PROCESS_INJECTION_ENUM_MINING_REPORT.md` - Process injection
- Client-Side Attacks:
  - `PEN300_CLIENT_RECON_MINING_REPORT.md` - Client reconnaissance
  - `PEN300_PHISHING_OFFICE_MINING_REPORT.md` - Phishing & Office exploits
- Linux Post-Exploitation:
  - `PEN300_LINUX_POSTEXPLOIT_REMINE_REPORT.md` - Linux post-exploitation
- Cross-Cutting Topics:
  - `PEN300_CROSSCUTTING_MINING_REPORT.md` - Cross-cutting techniques

**Linux Privilege Escalation (9 reports)**
- [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/hacktricks_linux/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/hacktricks_linux/README.md) - Linux overview
- `LINUX_PRIVESC_BASICS_MINING_REPORT.md` - PrivEsc basics
- `linux_enumeration_mining_report.md` - Linux enumeration
- `CAPABILITIES_MINING_REPORT.md` - Linux capabilities
- `LINUX_KERNEL_EXPLOIT_MINING_REPORT.md` - Kernel exploits
- `LINUX_PERSISTENCE_MINING_REPORT.md` - Persistence techniques
- `linux_shell_escaping_mining_report.md` - Shell escaping
- `linux_shell_escaping_summary.md` - Shell escaping summary
- `MINING_REPORT_LinuxContainerEscape.md` - Container escape

**Network Services (11 reports)**
- [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/network_services/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/network_services/README.md) - Network services overview
- `NETWORK_SERVICES_MINING_REPORT.md` - General network services
- `network_services_mining_report.md` - Additional network services
- `MSSQL_MINING_REPORT.md` - MSSQL enumeration
- `DEV_TOOLS_MINING_REPORT.md` - Development tools
- `LEGACY_PROTOCOLS_MINING_REPORT.md` - Legacy protocols
- Nmap Cookbook:
  - `NMAP_CH01_FUNDAMENTALS_MINING_REPORT.md` - Nmap fundamentals
  - `NMAP_CH02_NETWORK_EXPLORATION_MINING_REPORT.md` - Network exploration
  - `NMAP_CH03_HOST_INFORMATION_MINING_REPORT.md` - Host information
  - `NMAP_CH07_LARGE_NETWORKS_MINING_REPORT.md` - Large network scanning
  - `NMAP_COOKBOOK_CH5_DATABASE_ENHANCEMENTS.md` - Database scanning

**Web Attacks (7 reports)**
- [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/web_attacks/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/web_attacks/README.md) - Web attacks overview
- `FILE_UPLOAD_MINING_REPORT.md` - File upload vulnerabilities
- `GENERIC_ATTACKS_MINING_REPORT.md` - Generic web attacks
- `REDIRECT_ATTACKS_MINING_REPORT.md` - Redirect attacks
- `SSRF_ATTACKS_MINING_REPORT.md` - SSRF attacks
- `PYTHON_WEB_MINING_REPORT_2025-10-07.md` - Python web attacks
- `RUBY_RAILS_MINING_REPORT.md` - Ruby on Rails attacks

#### Medium Priority

**Binary Exploitation (4 reports)**
- [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/binary_exploitation/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/binary_exploitation/README.md) - Binary exploitation overview
- `stack_overflow_mining_report.md` - Stack overflow exploitation
- `rop_mining_report.md` - ROP chain exploitation
- `REVERSE_SHELLS_MINING_REPORT.md` - Reverse shell techniques

**Miscellaneous (4 reports)**
- [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/miscellaneous/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/miscellaneous/README.md) - Miscellaneous overview
- `cryptography_mining_report.md` - Cryptography attacks
- `cryptography_remine_report.md` - Cryptography (updated)
- `steganography_mining_report.md` - Steganography techniques

---

### Testing Documentation

- [`/home/kali/OSCP/crack/tests/README.md`](/home/kali/OSCP/crack/tests/README.md) - Test suite overview
- [`/home/kali/OSCP/crack/tests/track/README.md`](/home/kali/OSCP/crack/tests/track/README.md) - Track tests
- [`/home/kali/OSCP/crack/tests/track/TEST_STRATEGY.md`](/home/kali/OSCP/crack/tests/track/TEST_STRATEGY.md) - Test strategy
- [`/home/kali/OSCP/crack/tests/reference/README.md`](/home/kali/OSCP/crack/tests/reference/README.md) - Reference tests

---

### Archive (67 files)

**Development History**
- [`/home/kali/OSCP/crack/track/docs/archive/development/`](/home/kali/OSCP/crack/track/docs/archive/development/) - Historical development docs
  - Phase 4-7 implementation reports
  - Feature changelogs
  - Test coverage reports
  - Verification summaries

**Planning & Roadmap**
- [`/home/kali/OSCP/crack/track/docs/archive/planning/`](/home/kali/OSCP/crack/track/docs/archive/planning/) - Historical planning docs
  - `IMPROVEMENTS.md` - Improvement backlog
  - `PRODUCTION_CHECKLIST.md` - Production checklist
  - `ROADMAP.md` - Historical roadmap

**QA Reports**
- [`/home/kali/OSCP/crack/track/docs/archive/qa/`](/home/kali/OSCP/crack/track/docs/archive/qa/) - QA reports
  - Error handling reports
  - Documentation verification
  - Final QA report

**Testing & Verification**
- [`/home/kali/OSCP/crack/track/docs/archive/testing/`](/home/kali/OSCP/crack/track/docs/archive/testing/) - Historical test docs
  - Integration test reports
  - Verification summaries

**Low Priority Mining Reports (37 files)**
- [`/home/kali/OSCP/crack/track/services/plugin_docs/archive/low_priority/`](/home/kali/OSCP/crack/track/services/plugin_docs/archive/low_priority/) - Non-OSCP reports
  - iOS pentesting (7 reports)
  - macOS pentesting (11 reports)
  - Mobile/Android (2 reports)
  - Hardware hacking
  - Blockchain security
  - AI/LLM security
  - Browser exploits

---

## Documentation by Task

### "I want to learn CRACK Track"

**Step 1: Overview**
1. [`/home/kali/OSCP/crack/README.md`](/home/kali/OSCP/crack/README.md) - Project overview
2. [`/home/kali/OSCP/crack/docs/guides/GETTING_STARTED.md`](/home/kali/OSCP/crack/docs/guides/GETTING_STARTED.md) - Quick start (relocated)

**Step 2: Core Usage**
3. [`/home/kali/OSCP/crack/track/README.md`](/home/kali/OSCP/crack/track/README.md) - Comprehensive Track guide
4. [`/home/kali/OSCP/crack/track/docs/USAGE_GUIDE.md`](/home/kali/OSCP/crack/track/docs/USAGE_GUIDE.md) - Detailed usage

**Step 3: Interactive Mode**
5. [`/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_GUIDE.md`](/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_GUIDE.md) - TUI usage
6. [`/home/kali/OSCP/crack/track/docs/QUICKSTART_INTERACTIVE_TOOLS.md`](/home/kali/OSCP/crack/track/docs/QUICKSTART_INTERACTIVE_TOOLS.md) - Quick start

**Step 4: Advanced Features**
7. [`/home/kali/OSCP/crack/track/alternatives/README.md`](/home/kali/OSCP/crack/track/alternatives/README.md) - Manual alternatives
8. [`/home/kali/OSCP/crack/reference/README.md`](/home/kali/OSCP/crack/reference/README.md) - Command reference

---

### "I'm developing a new feature"

**Step 1: Architecture**
1. [`/home/kali/OSCP/crack/CLAUDE.md`](/home/kali/OSCP/crack/CLAUDE.md) - Development patterns
2. [`/home/kali/OSCP/crack/track/docs/ARCHITECTURE.md`](/home/kali/OSCP/crack/track/docs/ARCHITECTURE.md) - System architecture

**Step 2: Component Guides**
3. [`/home/kali/OSCP/crack/track/docs/PANEL_DEVELOPER_GUIDE.md`](/home/kali/OSCP/crack/track/docs/PANEL_DEVELOPER_GUIDE.md) - TUI panels
4. [`/home/kali/OSCP/crack/track/services/PLUGIN_CONTRIBUTION_GUIDE.md`](/home/kali/OSCP/crack/track/services/PLUGIN_CONTRIBUTION_GUIDE.md) - Service plugins

**Step 3: Debugging**
5. [`/home/kali/OSCP/crack/track/docs/DEBUG_LOGGING_CHEATSHEET.md`](/home/kali/OSCP/crack/track/docs/DEBUG_LOGGING_CHEATSHEET.md) - Debug logging
6. [`/home/kali/OSCP/crack/track/interactive/DEBUG_LOGGING_GUIDE.md`](/home/kali/OSCP/crack/track/interactive/DEBUG_LOGGING_GUIDE.md) - Debug guide

**Step 4: Testing**
7. [`/home/kali/OSCP/crack/tests/track/TEST_STRATEGY.md`](/home/kali/OSCP/crack/tests/track/TEST_STRATEGY.md) - Test strategy
8. [`/home/kali/OSCP/crack/tests/README.md`](/home/kali/OSCP/crack/tests/README.md) - Test suite

---

### "I'm preparing for OSCP exam"

**Step 1: High Priority Techniques**
1. [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/README.md) - AD & Windows (22 reports)
2. [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/hacktricks_linux/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/hacktricks_linux/README.md) - Linux PrivEsc (9 reports)
3. [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/web_attacks/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/web_attacks/README.md) - Web attacks (7 reports)

**Step 2: Network Enumeration**
4. [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/network_services/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/network_services/README.md) - Network services (11 reports)
5. [`/home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md`](/home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md) - NSE scripts

**Step 3: Manual Methods**
6. [`/home/kali/OSCP/crack/track/alternatives/README.md`](/home/kali/OSCP/crack/track/alternatives/README.md) - Manual alternatives
7. [`/home/kali/OSCP/crack/reference/docs/quick-wins.md`](/home/kali/OSCP/crack/reference/docs/quick-wins.md) - Quick wins

**Step 4: Binary Exploitation**
8. [`/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/binary_exploitation/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/binary_exploitation/README.md) - Binary exploitation (4 reports)

---

### "I need a specific command"

**Step 1: Quick Reference**
1. [`/home/kali/OSCP/crack/reference/docs/quick-reference.md`](/home/kali/OSCP/crack/reference/docs/quick-reference.md) - Quick command reference
2. [`/home/kali/OSCP/crack/reference/docs/quick-wins.md`](/home/kali/OSCP/crack/reference/docs/quick-wins.md) - Quick win techniques

**Step 2: Command System**
3. [`/home/kali/OSCP/crack/reference/README.md`](/home/kali/OSCP/crack/reference/README.md) - Command reference system
4. [`/home/kali/OSCP/crack/reference/docs/config.md`](/home/kali/OSCP/crack/reference/docs/config.md) - Config management

**Step 3: NSE Scripts**
5. [`/home/kali/OSCP/crack/track/docs/NSE_QUICK_REFERENCE.md`](/home/kali/OSCP/crack/track/docs/NSE_QUICK_REFERENCE.md) - NSE quick reference
6. [`/home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md`](/home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md) - NSE scripts reference

**Step 4: Manual Alternatives**
7. [`/home/kali/OSCP/crack/track/alternatives/README.md`](/home/kali/OSCP/crack/track/alternatives/README.md) - Alternative commands
8. [`/home/kali/OSCP/crack/track/alternatives/PRIVILEGE_ESCALATION_ALTERNATIVES.md`](/home/kali/OSCP/crack/track/alternatives/PRIVILEGE_ESCALATION_ALTERNATIVES.md) - PrivEsc alternatives

---

## Documentation by Module

### Track Module Documentation

**Core Usage**
- [`/home/kali/OSCP/crack/track/README.md`](/home/kali/OSCP/crack/track/README.md) - Complete Track guide
- [`/home/kali/OSCP/crack/track/docs/USAGE_GUIDE.md`](/home/kali/OSCP/crack/track/docs/USAGE_GUIDE.md) - Usage guide
- [`/home/kali/OSCP/crack/track/docs/QUICKSTART_INTERACTIVE_TOOLS.md`](/home/kali/OSCP/crack/track/docs/QUICKSTART_INTERACTIVE_TOOLS.md) - Quick start

**Architecture & Development**
- [`/home/kali/OSCP/crack/track/docs/ARCHITECTURE.md`](/home/kali/OSCP/crack/track/docs/ARCHITECTURE.md) - Architecture
- [`/home/kali/OSCP/crack/track/docs/TUI_ARCHITECTURE.md`](/home/kali/OSCP/crack/track/docs/TUI_ARCHITECTURE.md) - TUI architecture
- [`/home/kali/OSCP/crack/track/services/PLUGIN_CONTRIBUTION_GUIDE.md`](/home/kali/OSCP/crack/track/services/PLUGIN_CONTRIBUTION_GUIDE.md) - Plugin development

**Advanced Features**
- [`/home/kali/OSCP/crack/track/docs/SCAN_PROFILES.md`](/home/kali/OSCP/crack/track/docs/SCAN_PROFILES.md) - Scan profiles
- [`/home/kali/OSCP/crack/track/docs/TEMPLATES.md`](/home/kali/OSCP/crack/track/docs/TEMPLATES.md) - Templates
- [`/home/kali/OSCP/crack/track/docs/FUZZY_SEARCH.md`](/home/kali/OSCP/crack/track/docs/FUZZY_SEARCH.md) - Fuzzy search
- [`/home/kali/OSCP/crack/track/docs/SCREENED_MODE.md`](/home/kali/OSCP/crack/track/docs/SCREENED_MODE.md) - Screened mode

**Service Plugins & Mining Reports**
- [`/home/kali/OSCP/crack/track/services/plugin_docs/README.md`](/home/kali/OSCP/crack/track/services/plugin_docs/README.md) - Plugin documentation
- 58 mining reports across 7 categories (see [Mining Reports](#mining-reports-oscp-focus))

---

### Reference System Documentation

**Core System**
- [`/home/kali/OSCP/crack/reference/README.md`](/home/kali/OSCP/crack/reference/README.md) - Reference system overview
- [`/home/kali/OSCP/crack/reference/docs/config.md`](/home/kali/OSCP/crack/reference/docs/config.md) - Configuration management
- [`/home/kali/OSCP/crack/reference/docs/placeholders.md`](/home/kali/OSCP/crack/reference/docs/placeholders.md) - Variable placeholders
- [`/home/kali/OSCP/crack/reference/docs/tags.md`](/home/kali/OSCP/crack/reference/docs/tags.md) - Command tags

**Quick Reference**
- [`/home/kali/OSCP/crack/reference/docs/quick-reference.md`](/home/kali/OSCP/crack/reference/docs/quick-reference.md) - Quick command reference
- [`/home/kali/OSCP/crack/reference/docs/quick-wins.md`](/home/kali/OSCP/crack/reference/docs/quick-wins.md) - Quick win techniques

---

### Interactive Mode (TUI)

**User Guides**
- [`/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_GUIDE.md`](/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_GUIDE.md) - Interactive mode guide
- [`/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_TOOLS_GUIDE.md`](/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_TOOLS_GUIDE.md) - Interactive tools guide
- [`/home/kali/OSCP/crack/track/docs/QUICKSTART_INTERACTIVE_TOOLS.md`](/home/kali/OSCP/crack/track/docs/QUICKSTART_INTERACTIVE_TOOLS.md) - Quick start

**Developer Guides**
- [`/home/kali/OSCP/crack/track/docs/PANEL_DEVELOPER_GUIDE.md`](/home/kali/OSCP/crack/track/docs/PANEL_DEVELOPER_GUIDE.md) - Panel development
- [`/home/kali/OSCP/crack/track/docs/INTERACTIVE_TOOLS_API.md`](/home/kali/OSCP/crack/track/docs/INTERACTIVE_TOOLS_API.md) - API documentation
- [`/home/kali/OSCP/crack/track/interactive/DEBUG_LOGGING_GUIDE.md`](/home/kali/OSCP/crack/track/interactive/DEBUG_LOGGING_GUIDE.md) - Debug logging

**Components**
- [`/home/kali/OSCP/crack/track/interactive/components/ERROR_HANDLER_README.md`](/home/kali/OSCP/crack/track/interactive/components/ERROR_HANDLER_README.md) - Error handler
- [`/home/kali/OSCP/crack/track/interactive/state/README.md`](/home/kali/OSCP/crack/track/interactive/state/README.md) - State management
- [`/home/kali/OSCP/crack/track/interactive/CATEGORY_REFERENCE.md`](/home/kali/OSCP/crack/track/interactive/CATEGORY_REFERENCE.md) - Category reference

---

### Alternative Commands

**Core System**
- [`/home/kali/OSCP/crack/track/alternatives/README.md`](/home/kali/OSCP/crack/track/alternatives/README.md) - Alternative commands system
- [`/home/kali/OSCP/crack/track/alternatives/QUICKSTART.md`](/home/kali/OSCP/crack/track/alternatives/QUICKSTART.md) - Quick start

**Specific Techniques**
- [`/home/kali/OSCP/crack/track/alternatives/PRIVILEGE_ESCALATION_ALTERNATIVES.md`](/home/kali/OSCP/crack/track/alternatives/PRIVILEGE_ESCALATION_ALTERNATIVES.md) - PrivEsc alternatives
- [`/home/kali/OSCP/crack/track/alternatives/commands/FILE_TRANSFER_MINING_REPORT.md`](/home/kali/OSCP/crack/track/alternatives/commands/FILE_TRANSFER_MINING_REPORT.md) - File transfer methods

**Implementation Details** (ARCHIVED - See `track/docs/archive/development/`)
- ~~[`ALTERNATIVE_COMMANDS_IMPLEMENTATION_SUMMARY.md`]~~ - Archived (2025-10-10)
- ~~[`ALTERNATIVES_PHASE2_SUMMARY.md`]~~ - Archived (2025-10-10)

---

## Search Patterns

### Find by Topic

```bash
# Active Directory
grep -r "Active Directory\|Kerberos\|LDAP\|BloodHound" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/

# Web Attacks
ls /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/web_attacks/

# Linux Privilege Escalation
ls /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/hacktricks_linux/

# Windows Privilege Escalation
grep -l "Windows.*PrivEsc\|Windows.*Privilege" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/*.md

# SQL Injection
find /home/kali/OSCP/crack -name "*sqli*" -o -name "*SQL*" | grep -i "\.md$"

# Buffer Overflow
ls /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/binary_exploitation/

# File Transfer
grep -r "file transfer" /home/kali/OSCP/crack --include="*.md"

# Credential Dumping
grep -r "credential\|mimikatz\|lsass" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/ --include="*.md"

# Lateral Movement
grep -r "lateral movement\|psexec\|winrm" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/ --include="*.md"

# Network Evasion
grep -l "evasion\|IDS\|firewall" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/*.md
```

### Find by OSCP Priority

```bash
# High priority techniques (search across all mining reports)
grep -r "OSCP:HIGH\|PRIORITY:HIGH" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/

# Quick wins (2-5 minutes)
grep -r "QUICK_WIN\|quick win" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/

# Exam-relevant topics
grep -r "OSCP\|exam" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/ --include="*.md"

# Core enumeration
grep -r "enumeration\|recon" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/network_services/
```

### Find by Type

```bash
# All READMEs
find /home/kali/OSCP/crack -name "README.md" | grep -v ".git"

# All mining reports
find /home/kali/OSCP/crack -name "*mining_report*.md" -o -name "*MINING_REPORT*.md"

# All guides
find /home/kali/OSCP/crack -name "*GUIDE*.md" | grep -v ".git"

# All quick references
find /home/kali/OSCP/crack -name "*QUICK*" -o -name "*quick*" | grep "\.md$"

# All implementation docs
find /home/kali/OSCP/crack/track/docs/implementation -name "*.md"

# All phase reports
find /home/kali/OSCP/crack -name "*PHASE*" | grep "\.md$"

# All archived docs
find /home/kali/OSCP/crack -path "*/archive/*" -name "*.md"
```

### Find by Service/Technology

```bash
# HTTP/Web
grep -r "http\|web server\|apache\|nginx" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/ --include="*.md"

# SMB
grep -r "smb\|samba\|445" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/ --include="*.md"

# SSH
grep -r "ssh\|22" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/ --include="*.md"

# MSSQL
grep -r "mssql\|sql server" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/ --include="*.md"

# RDP
grep -r "rdp\|3389" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/ --include="*.md"

# DNS
grep -r "dns\|53" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/ --include="*.md"

# LDAP
grep -r "ldap\|389" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/ --include="*.md"
```

---

## Documentation Statistics

### Overall Statistics
- **Total Documentation Files:** 302
- **Active Documentation:** 209 files
- **Archived Documentation:** 67 files
- **Internal Development:** 26 files
- **Total Lines:** 149,341 lines
- **Repository Size:** 117 MB

### By Category
- **User Guides:** 29 files
- **Developer Guides:** 111 files
- **API Documentation:** 1 file
- **Reference Material:** 6 files
- **Mining Reports:** 58 files (active)
- **Testing Documentation:** 4 files
- **Archived (Development History):** 67 files
- **Low Priority Mining Reports:** 37 files (archived)

### Mining Reports Breakdown
- **PEN-300 (AD/Windows):** 22 reports
- **HackTricks Linux:** 9 reports
- **Network Services:** 11 reports
- **Web Attacks:** 7 reports
- **Binary Exploitation:** 4 reports
- **Miscellaneous:** 4 reports
- **Mobile:** 1 report

### Top 10 Largest Documents (by estimated lines)
1. Track Module README (~2000+ lines)
2. NSE Scripts OSCP Reference (~1500+ lines)
3. CLAUDE.md Development Guide (~1000+ lines)
4. Panel Developer Guide (~800+ lines)
5. Alternative Commands README (~700+ lines)
6. Interactive Mode Guide (~600+ lines)
7. Reference System README (~500+ lines)
8. Plugin Contribution Guide (~500+ lines)
9. Architecture Documentation (~400+ lines)
10. Debug Logging Cheatsheet (~300+ lines)

---

## Maintenance

### Adding New Documentation

**Step 1: Create file in appropriate directory**
```bash
# User guide
/home/kali/OSCP/crack/docs/guides/NEW_GUIDE.md

# Developer guide
/home/kali/OSCP/crack/track/docs/NEW_DEVELOPER_GUIDE.md

# Mining report
/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/[category]/NEW_MINING_REPORT.md

# Reference material
/home/kali/OSCP/crack/reference/docs/new-reference.md
```

**Step 2: Update category README**
```bash
# Add entry to category README if exists
vim /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/[category]/README.md
```

**Step 3: Update this master index**
```bash
# Add entry to appropriate section in this file
vim /home/kali/OSCP/crack/docs/MASTER_INDEX.md
```

**Step 4: Update "Last Updated" date**
```bash
# Update date at top of this file
sed -i 's/Last Updated:.*/Last Updated: '$(date +%Y-%m-%d)'/' /home/kali/OSCP/crack/docs/MASTER_INDEX.md
```

---

### Archiving Documentation

**Step 1: Move to archive directory**
```bash
# Development docs
mv /home/kali/OSCP/crack/track/docs/OLD_DOC.md \
   /home/kali/OSCP/crack/track/docs/archive/development/OLD_DOC.md

# Mining reports (low priority)
mv /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/category/LOW_PRIORITY.md \
   /home/kali/OSCP/crack/track/services/plugin_docs/archive/low_priority/LOW_PRIORITY.md
```

**Step 2: Update category README**
```bash
# Add archive note to category README
echo "## Archived: OLD_DOC.md → See archive/development/" >> README.md
```

**Step 3: Update master index**
```bash
# Move entry from active section to Archive section
vim /home/kali/OSCP/crack/docs/MASTER_INDEX.md
```

**Step 4: Update archive manifest**
```bash
# Add entry to archive manifest
vim /home/kali/OSCP/crack/track/services/plugin_docs/archive/ARCHIVE_MANIFEST.md
```

---

### Documentation Standards

**File Naming Conventions**
- User guides: `USAGE.md`, `QUICKSTART.md`, `GUIDE.md`
- Developer guides: `DEVELOPER_GUIDE.md`, `ARCHITECTURE.md`, `IMPLEMENTATION.md`
- Mining reports: `[TOPIC]_MINING_REPORT.md`
- Reference: `[topic]-reference.md`, `[topic]-quickref.md`
- Quick reference: `[TOPIC]_QUICKREF.md`, `[TOPIC]_QUICK_REFERENCE.md`

**Content Requirements**
- **Table of Contents:** Required for files >200 lines
- **Breadcrumb Navigation:** Add "← Back to [Parent]" at top
- **OSCP Relevance Tags:** Use `OSCP:HIGH`, `OSCP:MEDIUM`, `OSCP:LOW`
- **Cross-References:** Link to related documentation
- **Example Commands:** Include flag explanations
- **Manual Alternatives:** Provide non-tool methods where applicable

**Markdown Formatting**
- Use ATX-style headers (`# Header`)
- Code blocks with language tags (```bash, ```python)
- Absolute paths for cross-references
- Bullet lists for commands/steps
- Tables for comparison/reference data

**OSCP Priority Tags**
- `OSCP:HIGH` - Core exam techniques (AD, Linux PrivEsc, Web)
- `OSCP:MEDIUM` - Secondary techniques (Binary Exploitation, Misc)
- `OSCP:LOW` - Edge cases or non-exam topics
- `QUICK_WIN` - Techniques that take 2-5 minutes

---

## Quick Access by Audience

### For Beginners
1. `/home/kali/OSCP/crack/README.md` - Start here
2. `/home/kali/OSCP/crack/docs/guides/GETTING_STARTED.md` - Quick start (relocated)
3. `/home/kali/OSCP/crack/track/docs/USAGE_GUIDE.md` - Basic usage
4. `/home/kali/OSCP/crack/reference/docs/quick-wins.md` - Quick techniques

### For OSCP Students
1. `/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/README.md` - AD & Windows
2. `/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/hacktricks_linux/README.md` - Linux PrivEsc
3. `/home/kali/OSCP/crack/track/alternatives/README.md` - Manual methods
4. `/home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md` - Nmap enumeration

### For Power Users
1. `/home/kali/OSCP/crack/track/README.md` - Full Track guide
2. `/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_GUIDE.md` - Advanced TUI
3. `/home/kali/OSCP/crack/reference/README.md` - Command system
4. `/home/kali/OSCP/crack/track/docs/SCAN_PROFILES.md` - Scan profiles

### For Developers
1. `/home/kali/OSCP/crack/CLAUDE.md` - Development guide
2. `/home/kali/OSCP/crack/track/docs/ARCHITECTURE.md` - Architecture
3. `/home/kali/OSCP/crack/track/docs/PANEL_DEVELOPER_GUIDE.md` - Panel development
4. `/home/kali/OSCP/crack/track/services/PLUGIN_CONTRIBUTION_GUIDE.md` - Plugin development

---

## Related Documentation

- **Audit Reports:** [`/home/kali/OSCP/crack/docs/audit_reports/INDEX.md`](/home/kali/OSCP/crack/docs/audit_reports/INDEX.md)
- **Track Index:** [`/home/kali/OSCP/crack/track/docs/INDEX.md`](/home/kali/OSCP/crack/track/docs/INDEX.md)
- **Quick Reference:** [`/home/kali/OSCP/crack/docs/QUICK_REFERENCE.md`](/home/kali/OSCP/crack/docs/QUICK_REFERENCE.md) *(to be created)*

---

## Getting Help

**Documentation Issues**
- Missing documentation? Check [Archive](#archive-67-files)
- Outdated content? Open issue with file path
- Broken links? Run link checker (TBD)

**Finding Specific Content**
- Use [Search Patterns](#search-patterns) section above
- Check task-based navigation: [By Task](#documentation-by-task)
- Browse module documentation: [By Module](#documentation-by-module)

**Contributing Documentation**
- Follow [Documentation Standards](#documentation-standards)
- See [Maintenance](#maintenance) section for workflow
- Reference `/home/kali/OSCP/crack/CLAUDE.md` for patterns

---

*Generated: 2025-10-10 | Maintained by: Agent 8 | Format: Master Index v1.0*
