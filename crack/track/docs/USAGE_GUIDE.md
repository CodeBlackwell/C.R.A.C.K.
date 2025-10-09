# 📖 CRACK Track Usage Guide

> **Your complete guide to mastering enumeration tracking for OSCP success**

## Table of Contents

- [⚠️ WARNING: Use CRACK Responsibly (Not That Kind)](#️-warning-use-crack-responsibly-not-that-kind)
- [🚀 Quick Start (30 Seconds)](#-quick-start-30-seconds)
- [🎯 Core Concepts](#-core-concepts)
  - [What is CRACK Track?](#what-is-crack-track)
  - [Key Concepts (2-Minute Primer)](#key-concepts-2-minute-primer)
- [📋 Common Commands](#-common-commands)
  - [Getting Started](#getting-started)
  - [Import & Scan](#import--scan)
  - [Work on Tasks](#work-on-tasks)
  - [Document Findings](#document-findings)
  - [Export & Reporting](#export--reporting)
  - [Target Management](#target-management)
  - [Visualization](#visualization)
- [🎮 Interactive Mode Deep Dive](#-interactive-mode-deep-dive)
  - [Why Use Interactive Mode?](#why-use-interactive-mode)
  - [Launching Interactive Mode](#launching-interactive-mode)
  - [What You'll See](#what-youll-see)
  - [Keyboard Shortcuts](#keyboard-shortcuts)
  - [Search & Filter](#search--filter)
  - [Session Management](#session-management)
  - [Context-Aware Menus](#context-aware-menus)
- [📊 Real Workflow Examples](#-real-workflow-examples)
  - [Example 1: Fresh OSCP Lab Box](#example-1-fresh-oscp-lab-box)
  - [Example 2: Post-Scan Enumeration](#example-2-post-scan-enumeration)
  - [Example 3: Documentation & Export](#example-3-documentation--export)
- [📖 Complete CLI Reference](#-complete-cli-reference)
  - [Positional Arguments](#positional-arguments)
  - [Interactive Mode Options](#interactive-mode-options)
  - [Import Options](#import-options)
  - [Task Management Options](#task-management-options)
  - [Documentation Options](#documentation-options)
  - [Display Options](#display-options)
  - [Export Options](#export-options)
  - [Management Options](#management-options)
  - [Visualization Options](#visualization-options)
  - [Advanced Options](#advanced-options)
- [💡 Tips & Tricks](#-tips--tricks)
  - [Speed Up Your Workflow](#speed-up-your-workflow)
  - [Search Like a Pro](#search-like-a-pro)
  - [Document as You Go](#document-as-you-go)
  - [Parallel Tasks Save Time](#parallel-tasks-save-time)
  - [Quick Win Priority](#quick-win-priority)
  - [Source Tracking Best Practices](#source-tracking-best-practices)
  - [Exam Day Workflow](#exam-day-workflow)
  - [Workflow Phases Explained](#workflow-phases-explained)
- [❓ Troubleshooting](#-troubleshooting)
  - ["crack: command not found"](#crack-command-not-found)
  - ["Profile not found"](#profile-not-found)
  - ["Import fails" / "No tasks generated"](#import-fails--no-tasks-generated)
  - ["Error: --source is required"](#error---source-is-required)
  - ["Task ID not found"](#task-id-not-found)
  - ["Interactive mode not responding"](#interactive-mode-not-responding)
  - ["Export generates empty report"](#export-generates-empty-report)
  - [Common Mistakes](#common-mistakes)
- [🎓 Learning Path](#-learning-path)
  - [Beginner (Week 1)](#beginner-week-1)
  - [Intermediate (Week 2-3)](#intermediate-week-2-3)
  - [Advanced (Week 4+)](#advanced-week-4)
- [📚 Additional Resources](#-additional-resources)
- [💬 Getting Help](#-getting-help)
- [✅ Quick Checklist for OSCP Success](#-quick-checklist-for-oscp-success)

---

## ⚠️ WARNING: Use CRACK Responsibly (Not That Kind)

**IMPORTANT LEGAL & ETHICAL NOTICE:**

The usage of **CRACK** (Comprehensive Recon & Attack Creation Kit) in **unauthorized settings is dangerous, illegal, and will get you arrested**. This tool is designed **exclusively** for:
- ✅ OSCP labs and exam environments (where you paid for access)
- ✅ Authorized penetration testing engagements (with signed contracts)
- ✅ Your own systems and networks (that you legally own)
- ✅ Bug bounty programs (that explicitly permit testing)

**DO NOT** use CRACK on systems you don't have explicit written permission to test. Seriously. Prison food is terrible, and "but I was just learning" is not a valid legal defense.

---

**ALSO IMPORTANT - THE OTHER KIND OF CRACK:**

While we appreciate wordplay, please note:
- 🚭 **Do not smoke crack** (the illicit substance)
- 🚫 **Do not use CRACK** (this tool) **while smoking crack** (that drug)
- ⚡ **ESPECIALLY do not do both simultaneously** just because you had a "really cool idea" at 3 AM

We've been informed by our legal team (who don't exist) that combining pentesting with controlled substances leads to:
- Terrible OSCP exam scores
- Even worse code commits
- Very confusing IRC conversations
- Disappointed mothers worldwide

**Your mileage may vary, but we strongly recommend against it.** Like, *really* strongly. The kind of strong where we make you read this warning before getting to the good stuff.

---

**TL;DR:**
- ✅ Use CRACK (the tool) on authorized systems
- ❌ Don't use CRACK on unauthorized systems (illegal!)
- 🚭 Don't smoke crack (the drug)
- 🧠 Don't combine pentesting with poor life choices
- 🎯 When in doubt, ask yourself: "Would this decision make my mom proud?"

**Happy (legal, authorized, sober) hacking!** 🎉

*Anthropic, the CRACK developers, and anyone remotely associated with this project accept absolutely zero responsibility for your choices. You're an adult. Make good ones.*

---

## 🚀 Quick Start (30 Seconds)

**New to CRACK Track?** Start here:

```bash
# Launch interactive mode - it guides you through everything
crack track -i 192.168.45.100
```

That's it. Press `h` for help, `q` to quit. Everything auto-saves.

**Already ran nmap?** Import your results:

```bash
# Interactive import (recommended)
crack track -i 192.168.45.100
# Then press 'i' and select your scan file

# Or import directly
crack track import 192.168.45.100 scan.xml
crack track show 192.168.45.100
```

**Want the CLI way?** See [Common Commands](#-common-commands) below.

---

## 🎯 Core Concepts

### What is CRACK Track?

**C.R.A.C.K. T.R.A.C.K.**
**C**omprehensive **R**econ & **A**ttack **C**reation **K**it
**T**argeted **R**econnaissance **A**nd **C**ommand **K**onsole

CRACK Track is an **enumeration tracking system** that:
- Auto-generates task lists from nmap scans
- Tracks your progress across ports/services
- Documents findings with sources (OSCP requirement!)
- Exports complete writeups for OSCP reports
- Never lets you forget what you've tried

### Key Concepts (2-Minute Primer)

#### **Target**
A single IP/hostname you're pentesting
- Example: `192.168.45.100`
- Stored in: `~/.crack/targets/192.168.45.100.json`
- Contains: ports, tasks, findings, credentials, notes

#### **Task**
A specific enumeration action
- Example: "Directory bruteforce on port 80 (gobuster)"
- Has: command, description, tags, success indicators
- Status: pending, in-progress, completed, skipped

#### **Phase**
Your current enumeration stage:
1. **Discovery** - Initial port scanning
2. **Service Detection** - Identify services/versions
3. **Service-Specific** - Enumerate each service deeply
4. **Exploitation** - Attack found vulnerabilities
5. **Post-Exploitation** - Privilege escalation, persistence

The system **auto-advances** phases when appropriate.

#### **Finding**
Something you discovered:
- **Types**: vulnerability, directory, user, config, file, etc.
- **MUST have source**: "How did you find this?"
- **Timestamped**: For timeline reconstruction

#### **Session**
Your interactive mode state:
- **Auto-saves**: After every action
- **Resumable**: `crack track -i TARGET --resume`
- **Stored in**: `~/.crack/sessions/`

---

## 📋 Common Commands

### Getting Started

| Command | Purpose | Output |
|---------|---------|--------|
| `crack track -i TARGET` | **Start interactive mode** (recommended) | Progressive prompting |
| `crack track new TARGET` | Create target manually | Profile created |
| `crack track list` | Show all tracked targets | Target list with progress |

**Example:**
```bash
# Interactive mode - best for beginners
crack track -i 192.168.45.100

# CLI mode - for automation
crack track new 192.168.45.100
crack track show 192.168.45.100
```

### Import & Scan

| Command | Purpose | When to Use |
|---------|---------|-------------|
| `crack track import TARGET FILE` | Parse nmap results | After running nmap |
| `crack track show TARGET` | View recommendations | After import, anytime |

**Supported formats:** XML (`.xml`), Gnmap (`.gnmap`)

**Example:**
```bash
# Run nmap first
nmap -sV -sC -p- 192.168.45.100 -oA fullscan

# Import results (generates 50+ tasks automatically!)
crack track import 192.168.45.100 fullscan.xml

# See what to do next
crack track show 192.168.45.100
```

### Work on Tasks

| Command | Purpose | When to Use |
|---------|---------|-------------|
| `crack track done TARGET TASK_ID` | Mark task complete | After executing task |
| `crack track skip TARGET TASK_ID --skip-reason "..."` | Skip task | Task not applicable |
| `crack track show TARGET --show-all` | View all tasks | See completed tasks |

**Finding task IDs:** Use interactive mode's search (`f` key) or `show` command output.

**Example:**
```bash
# Execute a task
whatweb http://192.168.45.100:80 -v

# Mark it done
crack track done 192.168.45.100 whatweb-80

# Skip irrelevant task
crack track skip 192.168.45.100 wordpress-enum \
  --skip-reason "Not a WordPress site"
```

### Document Findings

| Command | Purpose | Required |
|---------|---------|----------|
| `crack track finding TARGET --type TYPE --description "..." --source "..."` | Add finding | `--source` |
| `crack track creds TARGET --username X --password Y --service S --port P --source "..."` | Add credentials | `--source` |
| `crack track note TARGET "..."` | Add note | Optional `--source` |

**Finding types:** vulnerability, directory, user, config, file, hash, subdomain, general

**Why --source is required:** OSCP graders need proof of methodology.

**Example:**
```bash
# Document vulnerability
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "Directory traversal in /download.php" \
  --source "Manual testing: curl http://192.168.45.100/download.php?file=../../../../etc/passwd"

# Document credentials
crack track creds 192.168.45.100 \
  --username admin \
  --password "SuperSecret123!" \
  --service wordpress \
  --port 80 \
  --source "Found in /backup/config.php.bak"

# Quick note
crack track note 192.168.45.100 "Apache 2.4.41 vulnerable to CVE-2021-41773" \
  --source "searchsploit apache 2.4"
```

### Export & Reporting

| Command | Purpose | Output |
|---------|---------|--------|
| `crack track export TARGET` | Generate OSCP writeup | Markdown report |
| `crack track timeline TARGET` | Show attack timeline | Chronological events |
| `crack track export TARGET --export-commands cmds.md` | Export command reference | Command list only |

**Example:**
```bash
# Full OSCP writeup (ready for submission)
crack track export 192.168.45.100 > 192.168.45.100-writeup.md

# Timeline view (for documentation)
crack track timeline 192.168.45.100

# Output:
# 2025-10-08 12:00:00 - Created target profile
# 2025-10-08 12:05:00 - Imported nmap scan (3 ports)
# 2025-10-08 12:30:00 - Finding: Directory traversal
# 2025-10-08 13:00:00 - Credential: admin discovered
# Total time: 1 hour
```

### Target Management

| Command | Purpose | Notes |
|---------|---------|-------|
| `crack track list` | Show all targets | With progress % |
| `crack track show TARGET` | View target status | Ports, findings, tasks |
| `crack track reset TARGET` | Delete target | Asks confirmation |
| `crack track show TARGET --show-findings` | View findings only | Filtered view |
| `crack track show TARGET --show-creds` | View credentials only | Filtered view |

**Example:**
```bash
# List all targets
crack track list
# Output:
# Tracked targets (3):
#   • 192.168.45.100
#     Phase: exploitation | Progress: 15/47 (32%)
#     Ports: 3 | Findings: 5
#
#   • 192.168.45.101
#     Phase: service-specific | Progress: 8/52 (15%)
#     Ports: 5 | Findings: 2

# Show specific target
crack track show 192.168.45.100

# View only findings
crack track show 192.168.45.100 --show-findings

# Delete target (with confirmation)
crack track reset 192.168.45.100
```

### Visualization

| Command | Purpose | Use Case |
|---------|---------|----------|
| `crack track --viz master` | System architecture | Understanding CRACK Track |
| `crack track --viz plugin-flow` | Plugin trigger diagram | See event flow |
| `crack track TARGET --viz task-tree` | Task hierarchy | See all target tasks |
| `crack track TARGET --viz progress` | Progress visualization | Check status |

**Export to file:** Add `-o FILE` to any viz command.

**Example:**
```bash
# System architecture
crack track --viz master --viz-color

# Task tree for target
crack track 192.168.45.100 --viz task-tree

# Export to markdown
crack track --viz master -o architecture.md
```

---

## 🎮 Interactive Mode Deep Dive

### Why Use Interactive Mode?

Interactive mode (`crack track -i TARGET`) is the **recommended** way to use CRACK Track because:

✅ **Guided workflow** - Shows you what to do next
✅ **Instant search** - Find tasks in 150+ task trees in <100ms
✅ **Context-aware** - Menus adapt to your current phase
✅ **Auto-saves** - Never lose progress
✅ **Keyboard shortcuts** - Faster than typing commands
✅ **No memorization** - Don't need to remember CLI flags

### Launching Interactive Mode

```bash
# Start fresh session
crack track -i 192.168.45.100

# Resume previous session (picks up where you left off)
crack track -i 192.168.45.100 --resume
```

### What You'll See

```
======================================================================
Target: 192.168.45.100
Phase: Service-Specific Enumeration
Progress: 12/47 tasks completed (26%)
Last Action: Completed gobuster scan on port 80
Time Elapsed: 01:23:00
======================================================================

What would you like to do?

  1. Import scan results
     → Load nmap/masscan output

  2. Execute next recommended task
     → Directory bruteforce on port 80 (gobuster)

  3. View task tree
     → See all 47 tasks organized by service

  4. Search tasks 🔍
     → Find specific tasks by name, port, or tag

  5. Mark task complete
     → Update progress

  6. Document finding
     → Add vulnerabilities, directories, credentials

  7. Export report
     → Generate OSCP writeup

  8. Settings
     → Configure preferences

  9. Help
     → Show keyboard shortcuts

Choice [or shortcut]: _
```

### Keyboard Shortcuts

**Core Navigation:**
| Key | Action | Use Case |
|-----|--------|----------|
| `s` | Show full status | "Where am I? What's my progress?" |
| `t` | Task tree | "Show me all tasks organized" |
| `r` | Recommendations | "What should I do next?" |
| `h` | Help | "Show all shortcuts" |
| `q` | Quit (auto-saves) | "Done for now" |

**Task Execution:**
| Key | Action | Use Case |
|-----|--------|----------|
| `n` | Execute next task | "Do the recommended action" |
| `f` | Search/filter tasks | "Find all gobuster tasks" |
| `m` | Mark task complete | "Just finished a task" |
| `k` | Skip task | "Not applicable to this target" |

**Documentation:**
| Key | Action | Use Case |
|-----|--------|----------|
| `d` | Document finding | "Found a vulnerability" |
| `c` | Add credentials | "Found username/password" |
| `o` | Add note | "Quick observation" |

**Other:**
| Key | Action | Use Case |
|-----|--------|----------|
| `i` | Import scan | "Load nmap results" |
| `e` | Export report | "Generate writeup" |
| `b` | Back | "Go to previous menu" |

### Search & Filter

**The killer feature.** Find specific tasks instantly in massive task trees.

**Launching search:**
- Press `f` in main menu
- Or select "Search tasks" option

**Search capabilities:**
```bash
# Search by tool name
Search: gobuster
# Finds: All gobuster tasks across all ports

# Search by port
Search: 445
# Finds: All tasks for port 445

# Search by tag
Search: QUICK_WIN
# Finds: All quick-win tasks

# Search by service
Search: http
# Finds: All HTTP-related tasks

# Search by status (in filters)
Search: pending
# Finds: Only incomplete tasks
```

**Example search results:**
```
Found 3 tasks matching 'gobuster':

  1. [⏳] Directory Bruteforce - Port 80
     Command: gobuster dir -u http://192.168.45.100 -w common.txt
     Tags: OSCP:HIGH, QUICK_WIN
     Est. time: 5 minutes

  2. [⏳] Directory Bruteforce - Port 8080
     Command: gobuster dir -u http://192.168.45.100:8080 -w common.txt
     Tags: OSCP:HIGH
     Est. time: 5 minutes

  3. [✓] API Endpoint Discovery - Port 443
     Command: gobuster dir -u https://192.168.45.100/api -w api.txt
     Status: Completed (2025-10-08 12:45)

Actions:
  [1-3] - Execute task
  [m]   - Mark task complete
  [v]   - View task details
  [b]   - Back to menu

Choice: _
```

**Search tips:**
- Search is **case-insensitive**
- Partial matches work ("gob" finds "gobuster")
- Results show instantly (optimized for 150+ tasks)
- Can act on results immediately (execute, mark done, view details)

### Session Management

**Auto-save:** Every action saves to `~/.crack/sessions/TARGET.json`

**Resume session:**
```bash
# Power outage? System crash? Just resume:
crack track -i 192.168.45.100 --resume

# Output:
# ✓ Restored session from 2025-10-08 14:23:00
# ✓ Last action: Completed SMB enumeration
# ✓ Continuing from service-specific phase
```

**Session data saved:**
- Last action performed
- Current phase
- Navigation history
- Start time
- User preferences

### Context-Aware Menus

Menus adapt based on your situation:

**No ports discovered yet:**
```
No ports found. Let's scan first! 🔍

  1. Quick scan (top 1000 ports) - ~30 seconds
  2. Full scan (all 65535 ports) - ~10 minutes
  3. Import existing scan
```

**HTTP service detected:**
```
Web server on port 80 detected! 🕸️

Quick wins:
  1. Technology fingerprinting (whatweb) - 30 sec ⚡
  2. Check robots.txt - 5 sec ⚡
  3. Check sitemap.xml - 5 sec ⚡

Deeper enumeration:
  4. Directory bruteforce (gobuster) - 5 min
  5. Vulnerability scan (nikto) - 2 min
  6. Manual source review
```

**Vulnerabilities found:**
```
💥 Boom! You found 3 vulnerabilities

  1. Document findings (add sources)
  2. Research exploits (searchsploit)
  3. Attempt exploitation
  4. Export findings to report
```

---

## 📊 Real Workflow Examples

### Example 1: Fresh OSCP Lab Box

**Scenario:** Just started attacking 192.168.45.100

```bash
# ========== DAY 1: 12:00 PM - Initial Enumeration ==========

# 1. Launch interactive mode
crack track -i 192.168.45.100

# 2. You see "No ports discovered" menu
#    Select: "Full scan (all 65535 ports)"

# 3. In another terminal, run nmap
nmap -p- --min-rate 1000 192.168.45.100 -oA discovery
# Wait for completion (~10 min)

nmap -sV -sC -p 22,80,445 192.168.45.100 -oA services
# Service scan on found ports (~2 min)

# 4. Back in interactive mode
#    Press 'i' to import → Select services.xml

# Output:
# ✓ Imported 3 ports
# ✓ Generated 47 tasks
# ✓ Phase advanced: Discovery → Service-Specific

# ========== 12:15 PM - Quick Wins ==========

# Menu now shows quick wins:
# Press 'n' to execute next recommended task

# Recommended: whatweb http://192.168.45.100:80
whatweb http://192.168.45.100:80 -v

# Output shows:
# - Apache 2.4.41
# - PHP 7.4.3
# - WordPress 5.8.1

# Press 'm' to mark complete → Enter task ID: whatweb-80

# ========== 12:20 PM - Check Robots.txt ==========

# Menu recommends: Check robots.txt
# Press 'n' again

curl http://192.168.45.100/robots.txt

# Found: Disallow: /admin-panel

# Document finding:
# Press 'd' (Document finding)
# Type: directory
# Description: Found /admin-panel via robots.txt
# Source: Manual curl request to robots.txt

# ✓ Finding saved with timestamp

# ========== 12:30 PM - Directory Bruteforce ==========

# Search for gobuster:
# Press 'f' → Type: gobuster → Select port 80 task

gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt

# Results:
# /admin-panel (200)
# /backup (301)
# /uploads (200)

# Document each:
# Press 'd' three times with details

# ========== 13:00 PM - Found Credentials ==========

# Browse to /backup → Find config.php.bak
curl http://192.168.45.100/backup/config.php.bak

# Contains:
# $db_user = "admin";
# $db_pass = "SuperS3cr3t!";

# Document credentials:
# Press 'c' (Add credentials)
# Username: admin
# Password: SuperS3cr3t!
# Service: mysql (or wordpress)
# Port: 80
# Source: Found in /backup/config.php.bak

# ========== 13:30 PM - Shell Access ==========

# Test credentials on /admin-panel → Success!
# Upload reverse shell via plugin upload
# Get shell as www-data

# Press 'o' to add note:
# "Gained shell via WordPress plugin upload. User: www-data"

# ========== DAY 2: 14:00 PM - Export Report ==========

# Press 'e' to export report
# Or use CLI:
crack track export 192.168.45.100 > 192.168.45.100-writeup.md

# Timeline view:
crack track timeline 192.168.45.100

# Output shows complete attack chain:
# 12:00 - Created profile
# 12:05 - Imported nmap scan
# 12:15 - Discovered WordPress
# 12:20 - Found /admin-panel
# 12:30 - Found /backup directory
# 13:00 - Discovered credentials
# 13:30 - Gained shell
# Total time: 1.5 hours
```

### Example 2: Post-Scan Enumeration

**Scenario:** Already ran nmap, just want to organize enumeration

```bash
# Import results
crack track import 192.168.45.100 fullscan.xml

# View recommendations
crack track show 192.168.45.100

# Output shows:
# 🎯 Next: Technology Fingerprinting (Port 80)
#    Command: whatweb http://192.168.45.100:80 -v
#    Est. time: ~30 seconds
#    Tags: OSCP:HIGH, QUICK_WIN
#
# 🚀 Quick Wins (5 tasks):
#   1. whatweb (Port 80) - 30 sec
#   2. robots.txt check - 5 sec
#   3. Anonymous SMB test - 10 sec
#   4. SSH banner grab - 5 sec
#   5. searchsploit Apache 2.4.41 - 2 min

# Execute quick wins:
whatweb http://192.168.45.100:80 -v
crack track done 192.168.45.100 whatweb-80

curl http://192.168.45.100/robots.txt
crack track done 192.168.45.100 robots-txt-80

smbclient -L //192.168.45.100 -N
crack track done 192.168.45.100 smb-anonymous-445

# Document findings as you go
crack track finding 192.168.45.100 \
  --type directory \
  --description "Found /backup directory (301)" \
  --source "gobuster dir -u http://192.168.45.100 -w common.txt"
```

### Example 3: Documentation & Export

**Scenario:** Pwned the box, now need to write report

```bash
# View what you've documented
crack track show 192.168.45.100 --show-findings
crack track show 192.168.45.100 --show-creds

# Export full writeup
crack track export 192.168.45.100 > writeup.md

# View timeline (for report reconstruction)
crack track timeline 192.168.45.100

# Export command reference (commands only)
crack track export 192.168.45.100 --export-commands commands.md
```

**Generated writeup includes:**
- Target information
- All ports/services discovered
- Complete task list (with completed/skipped status)
- All findings (with timestamps and sources)
- All credentials (with locations)
- Timeline of events
- Flag explanations for each command
- Manual alternatives

---

## 📖 Complete CLI Reference

### Positional Arguments

| Argument | Description | Required | Example |
|----------|-------------|----------|---------|
| `target` | Target IP or hostname | Most commands | `192.168.45.100` |

**When target is optional:** `list`, `--visualize` (some views)

### Interactive Mode Options

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--interactive` | `-i` | Launch interactive mode | `crack track -i 192.168.45.100` |
| `--resume` | - | Resume previous session | `crack track -i 192.168.45.100 --resume` |

### Import Options

| Flag | Description | Example |
|------|-------------|---------|
| `--import FILE` | Import nmap XML/gnmap | `crack track import TARGET scan.xml` |

**Supported formats:**
- Nmap XML (`.xml`) - Recommended
- Nmap Gnmap (`.gnmap`)
- Output from `nmap -oA` (imports XML)

### Task Management Options

| Flag | Description | Example |
|------|-------------|---------|
| `--mark-done TASK_ID` | Mark task complete | `crack track done TARGET whatweb-80` |
| `--skip TASK_ID` | Skip task | `crack track skip TARGET task-123` |
| `--skip-reason REASON` | Reason for skipping | `--skip-reason "Not a WordPress site"` |

**Finding task IDs:**
- Interactive mode search (`f` key)
- `crack track show TARGET` output

### Documentation Options

#### Findings

| Flag | Description | Required | Example |
|------|-------------|----------|---------|
| `--finding DESCRIPTION` | Add finding | Yes | `--finding "SQLi in id param"` |
| `--finding-type TYPE` | Finding type | No (default: general) | `--finding-type vulnerability` |
| `--source SOURCE` | How you found it | **YES** (OSCP!) | `--source "sqlmap -u http://..."` |

**Finding types:** vulnerability, directory, user, config, file, hash, subdomain, general

**Example:**
```bash
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "SQL injection in id parameter allows auth bypass" \
  --source "Manual testing: sqlmap -u 'http://192.168.45.100/page.php?id=1' --dbs"
```

#### Credentials

| Flag | Description | Required | Example |
|------|-------------|----------|---------|
| `--cred USER:PASS` | Add credential | Yes | `--cred admin:password123` |
| `--service SERVICE` | Service name | No | `--service wordpress` |
| `--port PORT` | Port number | No | `--port 80` |
| `--source SOURCE` | Where found | **YES** | `--source "config.php.bak"` |

**Format:** `username:password` (colon-separated)

**Example:**
```bash
crack track creds 192.168.45.100 \
  --username admin \
  --password "P@ssw0rd!" \
  --service mysql \
  --port 3306 \
  --source "Found in /var/www/html/config.php"
```

#### Notes

| Flag | Description | Example |
|------|-------------|---------|
| `--note NOTE` | Add freeform note | `--note "Apache 2.4.41 vulnerable"` |

**Optional:** `--source` (recommended but not required for notes)

### Display Options

| Flag | Description | Example |
|------|-------------|---------|
| `--show-all` | Show all tasks (including completed) | `crack track show TARGET --show-all` |
| `--show-findings` | Show only findings | `crack track show TARGET --show-findings` |
| `--show-creds` | Show only credentials | `crack track show TARGET --show-creds` |
| `--phase PHASE` | Filter by phase | `crack track show TARGET --phase exploitation` |

**Phases:** discovery, service-detection, service-specific, exploitation, post-exploit

### Export Options

| Flag | Description | Output |
|------|-------------|--------|
| `--export FILE` | Export full writeup | Markdown report |
| `--export-commands FILE` | Export commands only | Command reference |

**Example:**
```bash
# Full report
crack track export 192.168.45.100 > writeup.md

# Commands only
crack track export 192.168.45.100 --export-commands commands.md

# Or specify file directly
crack track export 192.168.45.100 --export report.md
```

### Management Options

| Flag | Description | Notes |
|------|-------------|-------|
| `--list` | List all targets | Shows progress |
| `--reset` | Delete target | Requires confirmation |
| `--stats` | Show statistics | System-wide stats |

### Visualization Options

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--visualize VIEW` | `--viz`, `-v` | Visualize architecture | `--viz master` |
| `--viz-style STYLE` | - | Style (tree/columnar/compact) | `--viz-style compact` |
| `--viz-color` | - | Enable colors | `--viz master --viz-color` |
| `--viz-theme THEME` | - | Color theme | `--viz-theme dark` |
| `--viz-phase PHASE` | - | Phase for decision-tree | `--viz-phase discovery` |
| `--viz-focus SECTION` | - | Focus master view section | `--viz-focus chains` |
| `--viz-output FILE` | `-o` | Export to file | `-o architecture.md` |

**Views:**
- `master` - Complete system overview
- `architecture` - Core architecture
- `plugin-flow` - Event-driven flow
- `plugin-graph` - Plugin dependencies
- `task-tree` - Target task hierarchy (requires TARGET)
- `progress` - Progress visualization (requires TARGET)
- `decision-tree` - Interactive mode decision tree
- `plugins` - Plugin list
- `themes` - Available themes

**Themes:** `oscp`, `dark`, `light`, `mono`

**Example:**
```bash
# System architecture with colors
crack track --viz master --viz-color

# Task tree for target
crack track 192.168.45.100 --viz task-tree

# Export to markdown file
crack track --viz master --viz-style compact -o arch.md
```

### Advanced Options

| Flag | Description | Use Case |
|------|-------------|----------|
| `--debug` | Enable debug output | Troubleshooting |

---

## 💡 Tips & Tricks

### Speed Up Your Workflow

**Create alias:**
```bash
echo "alias ct='crack track -i'" >> ~/.bashrc
source ~/.bashrc

# Now just:
ct 192.168.45.100
```

**Use shortcuts:**
- Don't type long commands in interactive mode
- Press single keys: `s`, `t`, `r`, `n`, `f`

### Search Like a Pro

**Search strategies:**
```
Quick wins:       QUICK_WIN
High priority:    OSCP:HIGH
By tool:          gobuster, nikto, enum4linux
By port:          80, 445, 3306
By service:       http, smb, mysql
Incomplete only:  pending
```

### Document as You Go

**DON'T wait until the end to document!**

❌ Wrong: Do all enumeration → Write report at 2 AM
✅ Right: Document findings as you discover them

**In interactive mode:**
- Press `d` immediately when you find something
- Include detailed sources (exact commands)
- Future you will thank present you

### Parallel Tasks Save Time

When CRACK Track shows parallel-capable tasks, **run them simultaneously**:

```bash
# Terminal 1
gobuster dir -u http://target -w common.txt

# Terminal 2
nikto -h http://target

# Terminal 3
curl http://target/robots.txt
```

Mark all complete when done. Saves hours on exam day!

### Quick Win Priority

**Always execute quick wins first:**
1. **30 seconds:** whatweb, robots.txt, sitemap.xml
2. **2 minutes:** searchsploit lookups, manual checks
3. **5 minutes:** Quick enumeration (SMB null session, anonymous FTP)
4. **10+ minutes:** Brute-forcing (gobuster, hydra)

Get low-hanging fruit before running slow scans.

### Source Tracking Best Practices

**Good sources:**
```bash
# ✅ Specific command with flags
--source "gobuster dir -u http://192.168.45.100 -w common.txt"

# ✅ Manual methodology
--source "Manual testing: Tried LFI with ../../../../etc/passwd"

# ✅ Multiple techniques
--source "Tried SQLi: ' OR 1=1--, sqlmap confirmed boolean-based blind"
```

**Bad sources:**
```bash
# ❌ Too vague
--source "Found it online"

# ❌ No methodology
--source "Guessed the password"

# ❌ Missing details
--source "Used gobuster"
```

### Exam Day Workflow

**24-hour time management:**

```bash
# Hour 1-2: Discovery & enumeration
crack track -i TARGET
# Import scans, execute quick wins

# Hour 3-12: Service-specific enumeration
# Follow recommendations, document findings

# Hour 13-18: Exploitation attempts
# Document ALL attempts (even failures)

# Hour 19-23: Post-exploitation
# Privilege escalation, flags

# Hour 24: Report polish
crack track export TARGET > writeup.md
crack track timeline TARGET
```

### Workflow Phases Explained

**Discovery:**
- Initial port scanning
- OS detection
- Quick service identification

**Service-Specific:**
- Deep enumeration per service
- HTTP: whatweb, gobuster, nikto
- SMB: enum4linux, smbclient
- SQL: nmap scripts, version research

**Exploitation:**
- Researching exploits (searchsploit)
- Testing vulnerabilities
- Gaining initial access

**Post-Exploitation:**
- Privilege escalation enumeration
- Credential hunting
- Persistence (for practice labs)

---

## ❓ Troubleshooting

### "crack: command not found"

**Problem:** CRACK toolkit not installed or not in PATH

**Solution:**
```bash
# Install CRACK toolkit
cd /path/to/crack
pip install -e . --break-system-packages

# Or use reinstall script
./reinstall.sh

# Verify installation
crack track --help
```

### "Profile not found"

**Problem:** Target not created or wrong IP

**Solution:**
```bash
# Check existing targets
crack track list

# Create new profile
crack track new 192.168.45.100

# Verify creation
crack track show 192.168.45.100
```

### "Import fails" / "No tasks generated"

**Problem:** Nmap file format not recognized or no services detected

**Solution:**
```bash
# Check file format
file scan.xml  # Should say "XML document"

# Try different format
crack track import 192.168.45.100 scan.gnmap

# Ensure service versions detected
nmap -sV -sC -p 80,445 192.168.45.100 -oA services
crack track import 192.168.45.100 services.xml
```

### "Error: --source is required"

**Problem:** Forgot to provide source for finding/credential

**Solution:**
```bash
# ❌ Missing source
crack track finding TARGET --type vuln --description "SQLi"

# ✅ With source
crack track finding TARGET \
  --type vulnerability \
  --description "SQLi in id param" \
  --source "sqlmap -u 'http://target/page.php?id=1'"
```

### "Task ID not found"

**Problem:** Wrong task ID or task doesn't exist

**Solution:**
```bash
# Use interactive search to find correct ID
crack track -i TARGET
# Press 'f' and search for task

# Or list all tasks
crack track show TARGET --show-all
```

### "Interactive mode not responding"

**Problem:** Python dependencies issue or terminal compatibility

**Solution:**
```bash
# Check Python version (needs 3.8+)
python3 --version

# Reinstall
cd /path/to/crack
./reinstall.sh

# Run with debug mode
crack track -i 192.168.45.100 --debug
```

### "Export generates empty report"

**Problem:** No findings/credentials documented

**Solution:**
```bash
# Check what's documented
crack track show TARGET --show-findings
crack track show TARGET --show-creds

# Document findings first
crack track finding TARGET --type vuln --description "..." --source "..."

# Then export
crack track export TARGET > writeup.md
```

### Common Mistakes

| Mistake | Problem | Solution |
|---------|---------|----------|
| Forgetting `--source` | OSCP requirement | Always include methodology |
| Not importing scans | No tasks generated | `crack track import TARGET scan.xml` |
| Wrong task ID format | Task not found | Use interactive search or `show` output |
| Skipping documentation | No report at end | Document as you go, not at 2 AM |
| Not resuming sessions | Lost context | Use `--resume` flag |

---

## 🎓 Learning Path

### Beginner (Week 1)
1. ✅ Launch interactive mode: `crack track -i TARGET`
2. ✅ Import nmap scan
3. ✅ Execute recommended tasks
4. ✅ Document one finding with source
5. ✅ Export simple report

### Intermediate (Week 2-3)
1. ✅ Use keyboard shortcuts (s, t, r, n, f)
2. ✅ Search tasks efficiently
3. ✅ Document findings in real-time
4. ✅ Track multiple targets
5. ✅ Resume sessions

### Advanced (Week 4+)
1. ✅ CLI-only workflows (no interactive mode)
2. ✅ Custom task creation
3. ✅ Phase management
4. ✅ Visualization exports
5. ✅ Integration with other tools

---

## 📚 Additional Resources

- **Architecture Deep Dive:** `track/README.md`
- **Plugin Development:** `PLUGIN_GUIDE.md` (coming soon)
- **Interactive Mode Details:** `INTERACTIVE_MODE.md` (coming soon)
- **Quick Reference:** `QUICK_REFERENCE.md` (coming soon)
- **Main CRACK Docs:** `/crack/README.md`

---

## 💬 Getting Help

**In interactive mode:** Press `h` for help

**CLI help:** `crack track --help`

**Report issues:** https://github.com/CodeBlackwell/Phantom-Protocol/issues

**Documentation:** This guide!

---

## ✅ Quick Checklist for OSCP Success

Before exam:
- [ ] Practiced interactive mode on 5+ lab boxes
- [ ] Know keyboard shortcuts (s, t, r, n, f, d, c, e)
- [ ] Documented findings with sources multiple times
- [ ] Exported reports and reviewed output
- [ ] Understand workflow phases

During exam:
- [ ] Start tracking immediately: `crack track -i TARGET`
- [ ] Import all nmap scans
- [ ] Document findings AS YOU GO (not at the end!)
- [ ] Include detailed sources for everything
- [ ] Use quick wins to save time
- [ ] Export timeline for report

After exam:
- [ ] Export complete writeup: `crack track export TARGET`
- [ ] Review timeline for completeness
- [ ] Verify all sources are documented
- [ ] Include in OSCP report submission

---

**You're now a CRACK Track expert!** 🎯

Go forth and enumerate methodically. Your future self (and the OSCP graders) will thank you.
