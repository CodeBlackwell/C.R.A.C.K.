# CRACK Toolkit - Quick Reference Card

> **One-page reference for common tasks and file locations**

---

## Most Common Commands

### Track Module
```bash
# Start interactive mode
crack track --tui <target>

# Import nmap scan
crack track <target> --import nmap_scan.xml

# View target status
crack track <target> --status

# Export findings
crack track <target> --export markdown > report.md
```

### Reference System
```bash
# Auto-fill command with config
crack reference --fill bash-reverse-shell

# Browse by category
crack reference post-exploit linux

# Filter by tag
crack reference --tag QUICK_WIN

# Auto-detect network settings
crack reference --config auto
```

### Alternative Commands (in TUI)
```bash
# Press 'alt' key when on a task
# System auto-fills variables from context
# Manual alternatives for when tools fail
```

---

## Top 10 Most-Used Guides

### 1. Getting Started
**Path:** `/home/kali/OSCP/crack/STARTER_USAGE.md`
**Use:** First-time setup and basic usage

### 2. Track Module Complete Guide
**Path:** `/home/kali/OSCP/crack/track/README.md`
**Use:** Comprehensive Track module documentation

### 3. Interactive Mode Guide
**Path:** `/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_GUIDE.md`
**Use:** TUI navigation and features

### 4. NSE Scripts Reference
**Path:** `/home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md`
**Use:** Nmap enumeration for OSCP

### 5. Alternative Commands System
**Path:** `/home/kali/OSCP/crack/track/alternatives/README.md`
**Use:** Manual methods when tools fail

### 6. Quick Win Techniques
**Path:** `/home/kali/OSCP/crack/reference/docs/quick-wins.md`
**Use:** Fast exploitation techniques (2-5 min)

### 7. PEN-300 Mining Reports
**Path:** `/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/README.md`
**Use:** Active Directory & Windows techniques (22 reports)

### 8. Linux PrivEsc Reports
**Path:** `/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/hacktricks_linux/README.md`
**Use:** Linux privilege escalation (9 reports)

### 9. Panel Developer Guide
**Path:** `/home/kali/OSCP/crack/track/docs/PANEL_DEVELOPER_GUIDE.md`
**Use:** Creating custom TUI panels

### 10. Debug Logging Cheatsheet
**Path:** `/home/kali/OSCP/crack/track/docs/DEBUG_LOGGING_CHEATSHEET.md`
**Use:** Troubleshooting TUI issues

---

## File Locations Cheatsheet

### User Documentation
- **Main README:** `/home/kali/OSCP/crack/README.md`
- **Quick Start:** `/home/kali/OSCP/crack/STARTER_USAGE.md`
- **Master Index:** `/home/kali/OSCP/crack/docs/MASTER_INDEX.md`

### Track Module
- **Main Guide:** `/home/kali/OSCP/crack/track/README.md`
- **Usage Guide:** `/home/kali/OSCP/crack/track/docs/USAGE_GUIDE.md`
- **Architecture:** `/home/kali/OSCP/crack/track/docs/ARCHITECTURE.md`

### Interactive Mode
- **TUI Guide:** `/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_GUIDE.md`
- **Panel Development:** `/home/kali/OSCP/crack/track/docs/PANEL_DEVELOPER_GUIDE.md`
- **Debug Logging:** `/home/kali/OSCP/crack/track/docs/DEBUG_LOGGING_CHEATSHEET.md`

### Reference System
- **System Overview:** `/home/kali/OSCP/crack/reference/README.md`
- **Quick Reference:** `/home/kali/OSCP/crack/reference/docs/quick-reference.md`
- **Quick Wins:** `/home/kali/OSCP/crack/reference/docs/quick-wins.md`
- **Config Guide:** `/home/kali/OSCP/crack/reference/docs/config.md`

### Alternative Commands
- **System Guide:** `/home/kali/OSCP/crack/track/alternatives/README.md`
- **Quick Start:** `/home/kali/OSCP/crack/track/alternatives/QUICKSTART.md`
- **PrivEsc Alts:** `/home/kali/OSCP/crack/track/alternatives/PRIVILEGE_ESCALATION_ALTERNATIVES.md`

### Mining Reports
- **PEN-300:** `/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/`
- **Linux:** `/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/hacktricks_linux/`
- **Web Attacks:** `/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/web_attacks/`
- **Network Services:** `/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/network_services/`
- **Binary Exploitation:** `/home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/binary_exploitation/`

### Development
- **Dev Guide:** `/home/kali/OSCP/crack/CLAUDE.md`
- **Plugin Dev:** `/home/kali/OSCP/crack/track/services/PLUGIN_CONTRIBUTION_GUIDE.md`
- **Test Strategy:** `/home/kali/OSCP/crack/tests/track/TEST_STRATEGY.md`

---

## Grep Patterns for Finding Content

### By Topic
```bash
# Active Directory
grep -r "Active Directory\|Kerberos\|LDAP" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/

# Linux PrivEsc
grep -r "privilege\|suid\|sudo" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/hacktricks_linux/

# Web Attacks
grep -r "sqli\|xss\|file upload" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/web_attacks/

# Buffer Overflow
grep -r "buffer overflow\|rop\|stack" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/binary_exploitation/

# File Transfer
grep -r "file transfer\|upload\|download" /home/kali/OSCP/crack --include="*.md"

# Credential Dumping
grep -r "mimikatz\|lsass\|credential" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/
```

### By Priority
```bash
# High priority OSCP techniques
grep -r "OSCP:HIGH" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/

# Quick wins (2-5 minutes)
grep -r "QUICK_WIN" /home/kali/OSCP/crack --include="*.md"

# Exam-relevant
grep -r "exam\|OSCP" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/
```

### By Service
```bash
# HTTP/Web
grep -r "http\|80\|443" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/

# SMB
grep -r "smb\|445\|samba" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/

# MSSQL
grep -r "mssql\|1433" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/

# SSH
grep -r "ssh\|22" /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/
```

### By Type
```bash
# All READMEs
find /home/kali/OSCP/crack -name "README.md" | grep -v ".git"

# All quick references
find /home/kali/OSCP/crack -name "*QUICK*" -o -name "*quick*" | grep "\.md$"

# All mining reports
find /home/kali/OSCP/crack -name "*MINING_REPORT*.md"

# All guides
find /home/kali/OSCP/crack -name "*GUIDE*.md" | grep -v ".git"
```

---

## Interactive Mode Hotkeys

```
's' - Show current status
't' - Show task tree
'r' - Show recent activity
'n' - Show next recommendations
'alt' - Execute alternative command for current task
'q' - Quit
'h' - Help
```

---

## Common Task Workflows

### Workflow 1: New Target Enumeration
```bash
# 1. Create target profile
crack track --tui 192.168.45.100

# 2. Import nmap scan
# (in TUI, select "Import Nmap Scan")

# 3. Review auto-generated tasks
# (press 't' to view task tree)

# 4. Execute enumeration tasks
# (navigate and select tasks to execute)

# 5. Export findings
# (press 'e' for export menu)
```

### Workflow 2: Finding Specific Command
```bash
# 1. Quick search
crack reference --tag QUICK_WIN

# 2. Browse by category
crack reference post-exploit linux

# 3. Auto-fill with config
crack reference --fill reverse-shell-bash

# 4. Copy to clipboard and execute
```

### Workflow 3: Manual Alternative Method
```bash
# 1. Open target in TUI
crack track --tui <target>

# 2. Navigate to failing task
# (e.g., gobuster scan timing out)

# 3. Press 'alt' key
# System shows manual curl/browser method

# 4. Execute manual command
# Results logged to profile
```

### Workflow 4: OSCP Exam Prep
```bash
# 1. Review AD techniques
ls /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/pen300/

# 2. Study Linux PrivEsc
ls /home/kali/OSCP/crack/track/services/plugin_docs/mining_reports/hacktricks_linux/

# 3. Practice quick wins
cat /home/kali/OSCP/crack/reference/docs/quick-wins.md

# 4. Review NSE scripts
cat /home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md
```

---

## Configuration Files

### Track Module
- **Target Profiles:** `~/.crack/targets/<TARGET>.json`
- **Config:** `~/.crack/config.json`
- **Sessions:** `~/.crack/sessions/<TARGET>.json`

### Reference System
- **Config:** `~/.crack/config.json`
- **Command Definitions:** `/home/kali/OSCP/crack/reference/data/commands/`

### Debug Logs
- **TUI Logs:** `/home/kali/OSCP/crack/.debug_logs/tui_debug_*.log`
- **Track Logs:** `/home/kali/OSCP/crack/.debug_logs/track_*.log`

---

## Quick Stats

- **Total Documentation:** 302 files
- **Active Docs:** 209 files
- **Mining Reports:** 58 reports (OSCP-focused)
- **Service Plugins:** 235+ plugins
- **Alternative Commands:** 45+ commands
- **Reference Commands:** 70+ commands

---

## OSCP Exam Quick Links

### Must-Review Before Exam
1. **Manual Alternatives** - `/home/kali/OSCP/crack/track/alternatives/README.md`
2. **NSE Scripts** - `/home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md`
3. **Quick Wins** - `/home/kali/OSCP/crack/reference/docs/quick-wins.md`

### AD/Windows Topics (High Priority)
- **Enumeration:** `pen300/PEN300_AD_ENUM_FUNDAMENTALS_MINING_REPORT.md`
- **Credentials:** `pen300/PEN300_AD_CREDS_MINING_REPORT.md`
- **Lateral Movement:** `pen300/PEN300_RDP_LATERAL_MINING_REPORT.md`
- **PrivEsc:** `pen300/PEN300_WINDOWS_PRIVESC_ADVANCED_MINING_REPORT.md`

### Linux Topics (High Priority)
- **Enumeration:** `hacktricks_linux/linux_enumeration_mining_report.md`
- **PrivEsc Basics:** `hacktricks_linux/LINUX_PRIVESC_BASICS_MINING_REPORT.md`
- **Capabilities:** `hacktricks_linux/CAPABILITIES_MINING_REPORT.md`
- **Shell Escaping:** `hacktricks_linux/linux_shell_escaping_summary.md`

### Web Topics (High Priority)
- **File Upload:** `web_attacks/FILE_UPLOAD_MINING_REPORT.md`
- **SSRF:** `web_attacks/SSRF_ATTACKS_MINING_REPORT.md`
- **Generic Attacks:** `web_attacks/GENERIC_ATTACKS_MINING_REPORT.md`

---

## Troubleshooting

### TUI Not Responding
```bash
# Enable debug logging
crack track --tui <target> --debug --debug-categories=UI:VERBOSE,STATE:VERBOSE

# Check logs
tail -f /home/kali/OSCP/crack/.debug_logs/tui_debug_*.log

# See: /home/kali/OSCP/crack/track/docs/DEBUG_LOGGING_CHEATSHEET.md
```

### Command Not Found
```bash
# Reinstall after code changes
cd /home/kali/OSCP/crack
./reinstall.sh

# See: /home/kali/OSCP/crack/CLAUDE.md (When to Reinstall section)
```

### Missing Documentation
```bash
# Check archive
find /home/kali/OSCP/crack -path "*/archive/*" -name "*[keyword]*"

# Check master index
cat /home/kali/OSCP/crack/docs/MASTER_INDEX.md
```

---

## Getting More Help

- **Master Index:** `/home/kali/OSCP/crack/docs/MASTER_INDEX.md`
- **Development Guide:** `/home/kali/OSCP/crack/CLAUDE.md`
- **Main README:** `/home/kali/OSCP/crack/README.md`

---

*Last Updated: 2025-10-10 | Quick Reference v1.0*
