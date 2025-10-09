# 🎯 CRACK Track - Your OSCP Enumeration Superpower

```
  ██████╗    ██████╗     █████╗     ██████╗    ██╗  ██╗
 ██╔════╝    ██╔══██╗   ██╔══██╗   ██╔════╝    ██║ ██╔╝
 ██║         ██████╔╝   ███████║   ██║         █████╔╝
 ██║         ██╔══██╗   ██╔══██║   ██║         ██╔═██╗
 ╚██████╗    ██║  ██║   ██║  ██║   ╚██████╗    ██║  ██╗
  ╚═════╝    ╚═╝  ╚═╝   ╚═╝  ╚═╝    ╚═════╝    ╚═╝  ╚═╝

 ████████╗   ██████╗     █████╗     ██████╗    ██╗  ██╗
 ╚══██╔══╝   ██╔══██╗   ██╔══██╗   ██╔════╝    ██║ ██╔╝
    ██║      ██████╔╝   ███████║   ██║         █████╔╝
    ██║      ██╔══██╗   ██╔══██║   ██║         ██╔═██╗
    ██║      ██║  ██║   ██║  ██║   ╚██████╗    ██║  ██╗
    ╚═╝      ╚═╝  ╚═╝   ╚═╝  ╚═╝    ╚═════╝    ╚═╝  ╚═╝
```

> **"Never forget a port. Never miss a task. Never lose your notes."** — _Every OSCP student who found CRACK Track_

---

## 🚀 What is This Wizardry?

**C.R.A.C.K. T.R.A.C.K.**
**C**omprehensive **R**econ & **A**ttack **C**reation **K**it
**T**argeted **R**econnaissance **A**nd **C**ommand **K**onsole

**CRACK Track** is like having a **genius hacker sidekick** who:
- 📡 Auto-generates perfect task lists from your nmap scans
- 🧠 Remembers EVERYTHING you've tried (even your epic fails)
- 🎓 Teaches you the manual way (for when tools fail in the exam)
- 📝 Writes your OSCP report FOR YOU (with sources, because graders are picky)
- 🔍 Finds that ONE task in your 150+ task tree in 0.1 seconds
- 🎮 Makes enumeration feel like a guided RPG quest

### 🎯 The TL;DR (Too Long; Didn't Root)

```bash
# One command to rule them all
crack track -i 192.168.45.100

# Watch the magic happen ✨
```

**That's it.** You're now in **1nT3R4cT1v3 M0D3** — a progressive prompting system that:
- Shows you exactly what to do next
- Lets you search tasks with lightning speed ⚡
- Tracks every finding with timestamps
- Saves your progress automatically
- Makes you look like an enumeration god 😎

---

## 🎮 Interactive Mode: The Flagship Experience

**THIS IS THE WAY.** Forget CLI flags and subcommands. Launch interactive mode and let CRACK Track guide you through the enumeration process like a choose-your-own-adventure pentesting book.

### ⚡ Launch Sequence

```bash
# Start fresh
crack track -i 192.168.45.100

# Resume where you left off (because you WILL take breaks)
crack track -i 192.168.45.100 --resume
```

### 🎯 What You'll See

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
     → Load nmap/masscan output to auto-generate tasks

  2. Execute next recommended task
     → Directory bruteforce on port 80 (gobuster)

  3. View task tree
     → See all 47 tasks organized by service

  4. Search tasks 🔍
     → Find specific tasks by name, port, or tag

  5. Mark task complete
     → Update progress and get new recommendations

Choice [or shortcut]: _
```

### ⌨️ Keyboard Shortcuts (Because We're H4CK3RS)

Why type when you can press one key?

| Key | Action | Vibe |
|-----|--------|------|
| `s` | Show full status | "Where am I?" |
| `t` | Task tree display | "Show me the matrix" |
| `r` | Recommendations | "What's next, sensei?" |
| `n` | Execute next task | "Let's DO this" |
| `f` | Search/filter | "Where's that gobuster task?" |
| `alt` | Alternative commands | "Show me manual methods" |
| `h` | Help | "I need an adult" |
| `q` | Quit and save | "I'm out ✌️" |

### 🎨 Alternative Commands: Manual Methods for OSCP Exam

**NEW!** CRACK Track now includes **45+ executable alternative commands** for when automated tools fail (they will in the exam!).

Press **`alt`** in interactive mode to see context-aware manual alternatives for the current task.

```
Current Task: Directory Brute-force (Port 80)
Command: gobuster dir -u http://192.168.45.100:80 -w common.txt

Alternative Commands:

  1. Manual Directory Check
     Use curl to manually test common directories
     Variables: TARGET, PORT, DIRECTORY

  2. Check robots.txt
     Check robots.txt for disallowed paths
     Variables: TARGET, PORT

  3. HTTP Headers Inspection
     Manually inspect HTTP headers for clues
     Variables: TARGET, PORT

Select alternative [1-3]: 1

Preparing: Manual Directory Check
  <TARGET> → 192.168.45.100 (from profile)
  <PORT> → 80 (from task metadata)
  <DIRECTORY> → Enter value: admin

Final command: curl http://192.168.45.100:80/admin

Execute? [Y/n]: y
```

#### Key Features

- **Config-Aware Auto-Fill**: Variables auto-fill from `~/.crack/config.json`
  - `<LHOST>` → Your attacking IP (auto-detected)
  - `<LPORT>` → Your listening port (default: 4444)
  - `<TARGET>` → Current target IP from profile

- **Context-Aware Wordlist Selection**: Different wordlists for different purposes
  - **Web enumeration** → `/usr/share/wordlists/dirb/common.txt`
  - **Password cracking** → `/usr/share/wordlists/rockyou.txt`
  - **SSH brute-force** → `/usr/share/seclists/.../ssh-passwords.txt`
  - **Subdomain enum** → `/usr/share/seclists/.../subdomains-top1million.txt`

- **Task-Linked Alternatives**: Each task shows relevant alternatives
  - **gobuster tasks** → curl manual check, robots.txt, sitemap.xml
  - **nikto tasks** → manual vulnerability testing
  - **hydra tasks** → manual authentication testing

- **Pattern-Based Auto-Discovery**: Alternatives auto-link via smart matching
  - Task ID patterns (`gobuster-*` → http alternatives)
  - Service types (`http` → web testing alternatives)
  - OSCP tags (`OSCP:HIGH` → prioritized alternatives)

#### Quick Setup

```bash
# Auto-detect your attacking IP
crack reference --config auto

# Or manually set config variables
crack reference --set LHOST 192.168.45.200
crack reference --set LPORT 4444
crack reference --set WORDLIST /usr/share/wordlists/dirb/common.txt

# View current config
crack reference --config list
```

#### Usage in Interactive Mode

```bash
# Launch interactive mode
crack track -i 192.168.45.100

# Navigate to any task
# Press 'alt' to see alternatives

# System shows context-aware alternatives for current task
# Variables auto-fill from task metadata, profile, and config
# User only enters values that can't be auto-detected

# Command executes and logs to profile
```

#### Alternative Command Categories

| Category | Count | Example |
|----------|-------|---------|
| Web Enumeration | 10+ | Manual dir check, robots.txt, headers |
| Privilege Escalation | 10+ | SUID binaries, sudo -l, capabilities |
| File Transfer | 10+ | Python HTTP server, wget, curl, nc |
| Anti-Forensics | 10+ | Clear history, log deletion, timestomp |
| Database Enum | 10+ | MySQL version, table enum, user dump |
| Network Recon | 10+ | Netcat port check, banner grab, ping |
| **Total** | **45+** | **Growing library** |

**Full guide**: `crack/track/alternatives/README.md`

### 🔍 The Search System: Finding Needles in 150-Task Haystacks

Got 100+ tasks? No problem. CRACK Track has **instant search** that would make Google jealous.

```
Search for: gobuster

Found 3 tasks matching 'gobuster':

  1. [⏳] Directory Bruteforce - Port 80
     Command: gobuster dir -u http://192.168.45.100 -w common.txt
     Tags: OSCP:HIGH, QUICK_WIN

  2. [⏳] Directory Bruteforce - Port 8080
     Command: gobuster dir -u http://192.168.45.100:8080 -w common.txt
     Tags: OSCP:HIGH

  3. [✓] API Endpoint Discovery - Port 443
     Command: gobuster dir -u https://192.168.45.100/api -w api.txt
     Status: Completed

Execute task, mark complete, or view details? [1-3/m/v/b]: _
```

**Search by anything:**
- Task name: `gobuster`, `nikto`, `enum4linux`
- Port: `445`, `80`, `3306`
- Tags: `QUICK_WIN`, `OSCP:HIGH`, `MANUAL`
- Service: `http`, `smb`, `sql`

**Results in <100ms** even with 150+ tasks. Yeah, we benchmarked it. 😎

### 🎯 Context-Aware Menus

CRACK Track adapts to YOUR situation:

**No ports found yet?**
```
Looks like we need to scan first! 🔍

Choose your scan strategy:
  1. Quick Scan (Top 1000 Ports) - Lab optimized, 1-2 minutes
  2. Full Port Scan (All 65535) - OSCP critical, 5-10 minutes
  3. Stealth Scan (Polite - T2) - Production systems, 15-20 minutes
  4. Aggressive Full Scan - Maximum speed/features, 10-15 minutes
  5. Custom scan command - Enter your own nmap flags
  6. Import existing scan

💡 Profiles are dynamic! CrackPot agent can mine new scan strategies.
```

**Found HTTP on port 80?**
```
Web server detected! Time to enumerate 🕸️

  1. Technology fingerprinting (whatweb) - QUICK_WIN ⚡
  2. Directory bruteforce (gobuster)
  3. Vulnerability scan (nikto)
  4. Manual checks (robots.txt, sitemap.xml)
```

**Found vulnerabilities?**
```
Boom! 💥 You found 3 vulnerabilities

  1. Document findings with sources
  2. Research exploits (searchsploit)
  3. Attempt exploitation
  4. Export findings to report
```

### 💾 Session Persistence: Never Lose Progress

Every action auto-saves to `~/.crack/sessions/`. Power outage? Kernel panic? Rage quit? **No problem.**

```bash
# Next day, resume exactly where you left off
crack track -i 192.168.45.100 --resume

# Output:
# ✓ Restored session from 2025-10-08 14:23:00
# ✓ Last action: Completed SMB enumeration
# ✓ Continue from service-specific phase
```

Your profile, tasks, findings, and notes are **ALWAYS** saved.

---

## 🎨 Dynamic Scan Profiles: Adaptive Scanning Strategies

**NEW!** CRACK Track now features a **dynamic scan profile system** that adapts to your environment and can be extended by the CrackPot agent.

### 🚀 What Are Scan Profiles?

Instead of hardcoded scan commands, CRACK Track uses **modular scan strategies** defined in `track/data/scan_profiles.json`:

```json
{
  "id": "lab-full",
  "name": "Full Port Scan (All 65535)",
  "base_command": "nmap -p-",
  "timing": "aggressive",
  "use_case": "OSCP labs - comprehensive port discovery",
  "estimated_time": "5-10 minutes",
  "detection_risk": "medium",
  "tags": ["OSCP:HIGH", "LAB", "THOROUGH"]
}
```

### 📦 Built-In Profiles

| Profile | Use Case | Speed | Stealth | OSCP? |
|---------|----------|-------|---------|-------|
| `lab-quick` | Top 1000 ports | ⚡⚡⚡ | 🥷 | ✅ HIGH |
| `lab-full` | All 65535 ports | ⚡⚡ | 🥷 | ✅ CRITICAL |
| `stealth-slow` | Paranoid (-T0) | 🐌 | 🥷🥷🥷 | 🏢 Production |
| `stealth-normal` | Polite (-T2) | ⚡ | 🥷🥷 | 🏢 Production |
| `aggressive-full` | Maximum speed (-T4) | ⚡⚡⚡ | 💥 | ✅ Labs only |
| `udp-common` | UDP scan (top 100) | ⚡⚡ | 🥷 | ✅ MEDIUM |

### 🎯 Profile Features

Each profile includes:
- **Flag explanations** - Learn what every nmap flag does
- **Success indicators** - Know when scan worked correctly
- **Failure indicators** - Troubleshoot common issues
- **Next steps** - What to do after scan completes
- **Alternatives** - Manual methods for exam scenarios
- **Detection risk warnings** - Know when scan is noisy

### 💡 Environment-Aware Selection

```bash
# Set target environment (affects which profiles are shown)
crack track set-environment 192.168.45.100 lab

# Lab environment shows: lab-quick, lab-full, aggressive
# Production environment shows: stealth-slow, stealth-normal
```

### 🤖 Agent-Extensible

The **CrackPot agent** can mine the Nmap cookbook and automatically add new profiles:

```bash
# Agent mines Nmap 6 cookbook Chapter 7
crack agent mine nmap-cookbook --output track/data/scan_profiles.json

# New profiles auto-load next run - no code changes needed!
```

**Coming soon:** Profiles for:
- Fragmentation evasion (`-f`, `--mtu`)
- Decoy scanning (`-D`)
- Source port manipulation (`--source-port`)
- Firewall bypass techniques

### 🎮 Using Profiles in Interactive Mode

```
Discovery Phase - Choose scan strategy:

  1. Quick Scan (Top 1000 Ports)
     OSCP labs, CTF - fast initial discovery (1-2 minutes)

  2. Full Port Scan (All 65535)
     OSCP labs - comprehensive port discovery (5-10 minutes)
     [OSCP CRITICAL: Always run full port scan]

  3. Stealth Scan (Polite - T2)
     Production systems - moderate stealth (15-20 minutes)

  4. Custom scan command
     Enter your own nmap flags

Choice: 2

Starting Full Port Scan (All 65535)...
Strategy: OSCP labs - comprehensive port discovery
Estimated time: 5-10 minutes

Command: nmap -p- --min-rate 1000 192.168.45.100 -oA lab_full_scan

Flag Explanations:
  -p-: Scan all 65535 TCP ports (thorough, finds unusual high ports)
  --min-rate 1000: Send at least 1000 packets/second (speeds up scan)
  -oA: Save output in all formats (XML, gnmap, nmap)

Execute? [Y/n]: y
```

### 📁 File Structure

```
track/
├── data/
│   └── scan_profiles.json       # Profile definitions (agent-minable!)
├── core/
│   ├── scan_profiles.py         # Profile registry
│   └── command_builder.py       # Modular command composition
└── interactive/
    ├── prompts.py               # Dynamic menu generation
    └── session.py               # Profile-based scan execution
```

---

## 🏗️ Architecture: Event-Driven Plugin Awesomeness

Under the hood, CRACK Track is a **120-plugin** beast powered by an event-driven architecture that would make microservices jealous.

### 🎭 The Magic Flow

```
┌─────────────────┐
│  You run nmap   │
│  and import XML │
└────────┬────────┘
         │
         v
┌─────────────────────────────────────────────────────────┐
│               EventBus (The Neural Network)             │
│  Emits: service_detected(port=80, service='http')       │
└─────────────┬───────────────────────────────────────────┘
              │
              v
┌─────────────────────────────────────────────────────────┐
│          ServiceRegistry (The Matchmaker)               │
│  "Which plugin can handle HTTP on port 80?"             │
└─────────────┬───────────────────────────────────────────┘
              │
              ├──> HTTPPlugin.detect() → Confidence: 100
              ├──> ApachePlugin.detect() → Confidence: 85
              ├──> NginxPlugin.detect() → Confidence: 70
              └──> GenericWebPlugin.detect() → Confidence: 50
              │
              v
┌─────────────────────────────────────────────────────────┐
│           Conflict Resolution (The Judge)               │
│  HTTPPlugin wins with confidence score 100!             │
└─────────────┬───────────────────────────────────────────┘
              │
              v
┌─────────────────────────────────────────────────────────┐
│      HTTPPlugin.get_task_tree() (The Generator)         │
│  Creates 15 HTTP enumeration tasks:                     │
│    ├── Technology fingerprinting (whatweb)              │
│    ├── Directory bruteforce (gobuster)                  │
│    ├── Vulnerability scan (nikto)                       │
│    ├── Manual checks (robots.txt, sitemap.xml)          │
│    └── Exploit research (searchsploit Apache 2.4.41)    │
└─────────────┬───────────────────────────────────────────┘
              │
              v
┌─────────────────────────────────────────────────────────┐
│         TargetProfile (The Memory Bank)                 │
│  Adds tasks to hierarchical tree                        │
│  Checks dependencies                                    │
│  Saves to ~/.crack/targets/192.168.45.100.json          │
└─────────────┬───────────────────────────────────────────┘
              │
              v
┌─────────────────────────────────────────────────────────┐
│      RecommendationEngine (The Advisor)                 │
│  Analyzes 15 tasks and recommends:                      │
│    NEXT: whatweb (30 seconds, QUICK_WIN)                │
│    PARALLEL: robots.txt, sitemap.xml (manual checks)    │
└─────────────┬───────────────────────────────────────────┘
              │
              v
┌─────────────────────────────────────────────────────────┐
│        Interactive UI (The Experience)                  │
│  Displays recommendations, waits for your input         │
│  You execute tasks, mark complete, add findings         │
│  Loop continues until you pwn the box 💀                │
└─────────────────────────────────────────────────────────┘
```

### 🧠 Confidence Scoring: No More Duplicate Tasks

**The Old Way (Broken):**
```python
def detect(port_info):
    return True  # Every plugin says yes!
# Result: 5 plugins generate duplicate HTTP tasks 😱
```

**The CRACK Track Way (Genius):**
```python
def detect(port_info):
    service = port_info.get('service', '').lower()
    port = port_info.get('port')
    version = port_info.get('version', '').lower()

    # Perfect match: HTTP on port 80
    if service == 'http' and port == 80:
        return 100  # 🎯

    # High confidence: Service mentions HTTP
    if 'http' in service:
        return 90  # 👍

    # Medium: Common HTTP port
    if port in [80, 443, 8080, 8443]:
        return 60  # 🤔

    # Low: Port ends with 80
    if str(port).endswith('80'):
        return 30  # 🤷

    # Nope
    return 0  # 👎
```

**Winner takes all.** Highest confidence plugin generates tasks. Problem solved. 🏆

---

## 🚀 Quick Start: Zero to Pwned

### 🎯 The Interactive Way (Recommended for Humans)

```bash
# Launch the experience
crack track -i 192.168.45.100

# Follow the prompts like a boss
# Press 'h' if you get lost
# Press 'q' when you're done (it auto-saves)
```

**Seriously, that's it.** The interactive mode will guide you through:
1. Importing scans
2. Viewing recommendations
3. Executing tasks
4. Documenting findings
5. Exporting reports

### ⚙️ The CLI Way (For Automation Addicts)

```bash
# Create target profile
crack track new 192.168.45.100

# Import nmap scan (auto-generates 50+ service-specific tasks)
nmap -sV -sC -p- 192.168.45.100 -oA fullscan
crack track import 192.168.45.100 fullscan.xml

# See recommendations
crack track show 192.168.45.100
# Output:
# 🎯 Next: Technology Fingerprinting (Port 80)
#    Command: whatweb http://192.168.45.100:80 -v
#    Time: ~30 seconds
#
# 🚀 Quick Wins (5 tasks):
#   1. whatweb (Port 80)
#   2. robots.txt check
#   3. Anonymous SMB access test
#   4. SSH banner grab
#   5. searchsploit Apache 2.4.41

# Execute task
whatweb http://192.168.45.100:80 -v

# Mark it done
crack track done 192.168.45.100 whatweb-80

# Document findings (OSCP requires sources!)
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "Directory traversal in /download.php" \
  --source "Manual testing: /download.php?file=../../../../etc/passwd"

# Add credentials
crack track creds 192.168.45.100 \
  --username admin \
  --password "P@ssw0rd123" \
  --service http \
  --port 80 \
  --source "Found in config.php.bak"

# Export OSCP writeup
crack track export 192.168.45.100 > writeup.md
```

---

## 🎓 OSCP Exam Superpowers

CRACK Track was built by OSCP students, for OSCP students. Every feature is designed to help you **pass the exam.**

### 📚 Manual Alternatives (For When Tools Fail)

**Every automated task includes manual methods**, because Murphy's Law applies to OSCP exams.

```bash
Task: Directory Bruteforce
Command: gobuster dir -u http://target -w common.txt

Manual Alternatives:
  1. curl http://target/admin
  2. curl http://target/upload
  3. curl http://target/backup
  4. curl http://target/config.php.bak
  5. Browser: View page source, look for commented paths
  6. Browser: Check DevTools → Network tab for API calls

Why This Matters:
  ✗ Gobuster crashes or hangs
  ✗ Wordlist missing
  ✗ WAF blocks automated scanning
  ✓ Manual testing still works
  ✓ You pass the exam 🎉
```

### 🔬 Flag Explanations (Learning Mode)

We explain **every flag** because rote memorization is for robots.

```bash
Command: nmap -sV -sC -p- --min-rate 1000 192.168.45.100 -oA fullscan

Flag Explanations:
  -sV: Service version detection
       → Probes open ports to determine exact service/version
       → Critical for CVE matching
       → Example output: "Apache httpd 2.4.41"

  -sC: Default NSE scripts
       → Runs ~50 safe scripts for common vulnerabilities
       → Finds low-hanging fruit (default creds, misconfigs)
       → Equivalent to --script=default

  -p-: All 65535 ports
       → Don't rely on top 1000 (you'll miss services)
       → OSCP boxes often use non-standard ports
       → Takes longer but finds hidden services

  --min-rate 1000: Send packets at minimum 1000/second
       → Speeds up scans significantly
       → Safe for lab environments
       → Avoid in production (can crash old systems)

  -oA fullscan: Output all formats
       → Creates fullscan.xml, fullscan.nmap, fullscan.gnmap
       → XML for tool imports
       → .nmap for human reading
       → .gnmap for grep parsing
       → ALWAYS use this for OSCP documentation
```

### 📝 Source Tracking (Required for Reports)

OSCP graders WILL ask "how did you find this?" CRACK Track makes you document sources **every time.**

```bash
# ❌ This will fail
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "SQL injection"

# Error: --source is required for findings

# ✅ This works
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "SQL injection in id parameter" \
  --source "Manual testing: sqlmap -u 'http://target/page.php?id=1'"

# ✓ Added finding with source timestamp
# ✓ Will appear in exported report with full chain
```

### ⏱️ Timeline Export (Reconstruct Your Attack)

Every action is timestamped. Export a **complete timeline** for your report.

```bash
crack track timeline 192.168.45.100

# Output:
# 2025-10-08 12:00:00 - Created target profile
# 2025-10-08 12:05:00 - Imported nmap scan (3 ports discovered)
# 2025-10-08 12:15:00 - Completed: Technology fingerprinting (Port 80)
# 2025-10-08 12:30:00 - Completed: Directory bruteforce (Port 80)
# 2025-10-08 12:45:00 - Finding: Directory traversal in /download.php
# 2025-10-08 13:00:00 - Finding: LFI allows /etc/passwd read
# 2025-10-08 13:30:00 - Credential: admin / P@ssw0rd123 (config.php.bak)
# 2025-10-08 14:00:00 - Completed: Shell upload via LFI + log poisoning
# 2025-10-08 14:15:00 - Achievement unlocked: Low-privilege shell 🎉
# Total time to initial access: 2 hours 15 minutes
```

Perfect for the "**Proof.txt was located at...**" section. 📜

---

## 🔧 Core Commands Cheat Sheet

### 🎯 Target Management

```bash
# Create new target
crack track new <TARGET>

# List all tracked targets
crack track list

# Show target status
crack track show <TARGET>

# Delete target (asks for confirmation)
crack track delete <TARGET>
```

### 📥 Data Import

```bash
# Import nmap XML (recommended)
crack track import <TARGET> scan.xml

# Import nmap gnmap
crack track import <TARGET> scan.gnmap

# Supports -oX, -oG, and -oA formats
```

### ✅ Task Management

```bash
# View recommendations
crack track show <TARGET>
crack track recommend <TARGET>

# Mark task complete
crack track done <TARGET> <TASK_ID>

# Search tasks (interactive only)
crack track -i <TARGET>
# Then press 'f' for search

# Add custom task
crack track add-task <TARGET> \
  --name "Check phpinfo.php" \
  --command "curl http://target/phpinfo.php"
```

### 📝 Documentation

```bash
# Add finding (source required!)
crack track finding <TARGET> \
  --type <TYPE> \
  --description "What you found" \
  --source "How you found it"

# Types: vulnerability, directory, user, config, file, etc.

# Add credentials
crack track creds <TARGET> \
  --username <USER> \
  --password <PASS> \
  --service <SERVICE> \
  --port <PORT> \
  --source "Where you found it"

# Add note
crack track note <TARGET> "Your observation"
```

### 📤 Export & Reporting

```bash
# Export full OSCP writeup
crack track export <TARGET> > writeup.md

# Export timeline
crack track timeline <TARGET>

# Export task reference (command list only)
crack track export <TARGET> --tasks-only
```

### 🎨 Visualization

```bash
# Master system overview
crack track --viz master

# Plugin flow diagram
crack track --viz plugin-flow

# Task tree for target
crack track <TARGET> --viz task-tree

# Progress bars
crack track <TARGET> --viz progress

# Export to markdown file
crack track --viz master -o architecture.md
```

---

## 🔌 The Plugin Army: 120+ Automated Specialists

CRACK Track has **120+ service plugins** that auto-generate tasks when services are detected. Here's the roster:

### 🌐 Web Application Plugins (40+)

| Plugin | Service | Auto-Generated Tasks |
|--------|---------|---------------------|
| **HTTP/HTTPS** | http, https | whatweb, gobuster, nikto, robots.txt, sitemap.xml |
| **Apache** | apache httpd | Version-specific CVE research, mod_* enumeration |
| **Nginx** | nginx | Config disclosure, version exploits |
| **IIS** | Microsoft IIS | WebDAV, ISAPI, ASP.NET enumeration |
| **Tomcat** | Apache Tomcat | Manager console brute-force, WAR upload |
| **API Attacks** | REST APIs | Endpoint enumeration, auth bypass, parameter fuzzing |
| **WordPress** | WordPress | WPScan, user enum, plugin/theme vulns |
| **Joomla** | Joomla | JoomScan, admin finder |
| **Drupal** | Drupal | Droopescan, version detection |
| **Ruby on Rails** | Rails | Secret token exposure, parameter injection |
| **Python Web** | Flask/Django | Debug mode check, pickle exploits |
| **PHP Attacks** | PHP | LFI, RFI, file upload, PHP info disclosure |
| **File Upload** | upload forms | Extension bypass, MIME type tricks, magic byte |
| **SSRF** | server-side | Cloud metadata, internal port scan |
| **XSS** | reflected/stored | Payload generation, CSP bypass |
| **Auth Bypass** | login forms | Default creds, SQL injection, JWT attacks |

### 🗄️ Database Plugins (15+)

| Plugin | Service | Pwn-ability Level |
|--------|---------|------------------|
| **MySQL** | mysql | UDF privesc, FILE privilege, hash dump | 🔥🔥🔥 |
| **PostgreSQL** | postgresql | Copy from program, large object injection | 🔥🔥 |
| **MSSQL** | ms-sql-s | xp_cmdshell, linked servers, injection | 🔥🔥🔥 |
| **MongoDB** | mongodb | NoSQL injection, unauthorized access | 🔥🔥 |
| **Redis** | redis | RCE via module load, key enumeration | 🔥🔥🔥 |
| **Oracle** | oracle-tns | TNS poisoning, default schema passwords | 🔥 |

### 🖧 Network Service Plugins (30+)

| Plugin | Service | OSCP Relevance |
|--------|---------|---------------|
| **SMB** | smb/smb2 | enum4linux, null sessions, EternalBlue | ⭐⭐⭐ |
| **SSH** | ssh | User enum, weak keys, version exploits | ⭐⭐ |
| **FTP** | ftp | Anonymous login, writable dirs, vsftpd backdoor | ⭐⭐⭐ |
| **NFS** | nfs | no_root_squash, UID spoofing, mount enum | ⭐⭐⭐ |
| **SMTP** | smtp | VRFY/EXPN user enum, open relay | ⭐⭐ |
| **DNS** | domain | Zone transfer, subdomain brute-force | ⭐⭐ |
| **SNMP** | snmp | Community string brute-force, OID enum | ⭐⭐⭐ |
| **LDAP** | ldap | Anonymous bind, LDAP injection | ⭐⭐ |
| **Kerberos** | kerberos | ASREPRoast, Kerberoasting, golden tickets | ⭐⭐⭐ |
| **RDP** | ms-wbt-server | BlueKeep check, session hijacking | ⭐⭐ |

### 🪟 Windows/AD Plugins (20+)

| Plugin | Specialty | 💀 Factor |
|--------|----------|----------|
| **AD Enumeration** | BloodHound, PowerView | Domain mapping | 💀💀💀 |
| **AD Attacks** | Kerberoasting, DCSync | Credential harvesting | 💀💀💀 |
| **AD Delegation** | Constrained/unconstrained | Lateral movement | 💀💀 |
| **AD Certificates** | ESC1-8, Certipy | PKI abuse | 💀💀💀 |
| **AD Persistence** | Golden ticket, DCShadow | Long-term access | 💀💀💀 |
| **Windows PrivEsc** | Token manipulation, UAC bypass | SYSTEM access | 💀💀💀 |
| **MSSQL in AD** | Linked servers, impersonation | SQL to DA | 💀💀💀 |

### 🐧 Linux/Post-Exploit Plugins (15+)

| Plugin | Focus | Critical? |
|--------|-------|----------|
| **Linux Enumeration** | SUID, capabilities, cron, sudoers | ✅ OSCP CORE |
| **Linux PrivEsc** | Kernel exploits, PATH hijack | ✅ OSCP CORE |
| **Linux Capabilities** | cap_setuid, cap_dac_override | ✅ Advanced |
| **Linux Persistence** | SSH keys, cron jobs, systemd | ⚠️ Post-root |
| **Container Escape** | Docker, LXC, Kubernetes | 🔥 Advanced |
| **macOS Enumeration** | TCC bypass, dylib injection | 🍎 Mac-specific |
| **macOS PrivEsc** | AuthorizationPlugin, XPC | 🍎 Mac-specific |

### 🔒 Binary Exploitation Plugins (10+)

| Plugin | Technique | OSCP Level |
|--------|-----------|------------|
| **Stack Buffer Overflow** | EIP control, DEP/ASLR bypass | ✅ Required |
| **Heap Exploitation** | Use-after-free, double-free | ❌ Beyond OSCP |
| **Format String** | Arbitrary read/write | ⚠️ Rare in OSCP |
| **ROP Chains** | Return-oriented programming | ❌ Beyond OSCP |
| **ARM Exploitation** | ARM assembly, Thumb mode | ❌ Specialized |

### 🎭 Specialty Plugins (10+)

- **Phishing** - Office macros, HTA, SCF files
- **C2 Analysis** - Beacon detection, traffic analysis
- **Anti-Forensics** - Log deletion, timestomping
- **Cryptography** - Weak ciphers, ECB mode, padding oracle
- **Hardware** - UART, JTAG, SPI, I2C
- **Radio** - SDR, RFID, NFC
- **Blockchain** - Smart contract auditing
- **AI Security** - LLM prompt injection, model poisoning
- **Mobile** - Android/iOS app security
- **OSINT** - Recon, WHOIS, social media

**Total: 120+ plugins** 🎉 (and growing!)

---

## 📊 Real Example: OSCP Lab Box Workflow

Let's pwn a box from start to finish with CRACK Track:

### 🎯 Scenario: 192.168.45.100 (Linux Web Server)

```bash
# ========== PHASE 1: DISCOVERY ==========

# Launch interactive mode
crack track -i 192.168.45.100

# Menu appears:
# "No ports discovered yet. Let's scan!"
#   1. Quick scan (top 1000 ports)
#   2. Full scan (all 65535 ports)
#   3. Import existing scan

# You choose: 2 (Full scan recommended for OSCP)

# In another terminal:
nmap -p- --min-rate 1000 192.168.45.100 -oA discovery
nmap -sV -sC -p 22,80,445 192.168.45.100 -oA services

# Back in interactive mode:
# Press '1' to import scan
# Select: services.xml

# ✓ Imported 3 open ports
# ✓ Generated 47 enumeration tasks
# ✓ Progressed to service-specific phase

# ========== PHASE 2: SERVICE ENUMERATION ==========

# Menu now shows:
# "3 services detected! Quick wins available 🚀"
#
# Quick Wins (5 tasks):
#   1. whatweb (Port 80) - 30 seconds
#   2. robots.txt check (Port 80) - 5 seconds
#   3. Anonymous SMB (Port 445) - 10 seconds
#   4. SSH banner grab (Port 22) - 5 seconds
#   5. searchsploit Apache 2.4.41 - 2 minutes

# Press 'n' (Execute next)
# CRACK Track runs: whatweb http://192.168.45.100:80 -v

# Output shows:
# Apache 2.4.41, PHP 7.4.3, WordPress 5.8.1

# Auto-marks task complete
# Shows new menu:
#
# "WordPress detected! 🎯"
#   1. WPScan enumeration
#   2. WordPress user enumeration
#   3. Continue HTTP enumeration
#   4. Check other services

# You press 'f' to search for tasks
# Type: "robots"

# Found: Check robots.txt (Port 80)
# Execute? [y/n]: y

# You run: curl http://192.168.45.100/robots.txt
# Output shows: Disallow: /admin-panel

# Document finding:
# Press 'd' (Document finding)
# Type: directory
# Description: Found /admin-panel via robots.txt
# Source: Manual curl request to robots.txt

# ✓ Finding saved with timestamp

# Press 'f' to search again
# Type: "gobuster"

# Found: Directory Bruteforce (Port 80)
# Execute? [y/n]: y

# You run: gobuster dir -u http://192.168.45.100 -w common.txt

# Results:
# /admin-panel (200)
# /backup (301)
# /uploads (200)

# Document all findings:
# Press 'd' three times with details

# ========== PHASE 3: EXPLOITATION ==========

# You browse to /backup
# Find: config.php.bak

# Download and find credentials:
# Username: admin
# Password: SuperS3cr3t!

# Document credentials:
# Press 'c' (Add credentials)
# Username: admin
# Password: SuperS3cr3t!
# Service: wordpress
# Port: 80
# Source: Found in /backup/config.php.bak

# ✓ Credentials saved

# Test credentials on /admin-panel → Success! 🎉
# WordPress admin panel accessed

# Upload reverse shell via plugin upload
# Get shell as www-data

# ========== PHASE 4: POST-EXPLOITATION ==========

# CRACK Track detects phase change
# Menu now shows:
#
# "Shell access detected! 🎊"
#   1. Linux privilege escalation enumeration
#   2. Search for SUID binaries
#   3. Check sudo permissions
#   4. Enumerate capabilities
#   5. Look for kernel exploits

# Press 'n' (Execute next)
# Runs: find / -perm -u=s -type f 2>/dev/null

# Finds unusual SUID binary: /usr/local/bin/backup

# Test binary → Vulnerable to path hijacking!

# Press 'd' to document vulnerability
# Type: privilege_escalation
# Description: SUID binary /usr/local/bin/backup vulnerable to PATH hijack
# Source: Manual testing + GTFOBins research

# Exploit it → Root shell! 💀

# ========== PHASE 5: REPORTING ==========

# Press 'q' to quit interactive mode
# Export full report:
crack track export 192.168.45.100 > 192.168.45.100-writeup.md

# View timeline:
crack track timeline 192.168.45.100

# Output shows complete attack chain:
# 12:00 - Created profile
# 12:05 - Imported nmap scan
# 12:15 - Discovered WordPress
# 12:30 - Found /admin-panel via robots.txt
# 12:45 - Found credentials in config.php.bak
# 13:00 - Gained shell via plugin upload
# 13:15 - Discovered SUID binary
# 13:30 - Achieved root access
# Total time: 1 hour 30 minutes
```

**Result:** Complete OSCP-ready writeup with:
- ✅ All commands executed (with flag explanations)
- ✅ All findings documented (with sources)
- ✅ All credentials tracked (with locations)
- ✅ Complete timeline (for report)
- ✅ Manual alternatives (for exam)
- ✅ Proof screenshots (you took them, right? 📸)

---

## 🧪 Testing: 75% Coverage on Critical Features

CRACK Track has **comprehensive tests** focused on **user value**, not just code coverage.

### 📈 Test Stats

```
Total Tests: 87
✅ Passing: 87 (100%)
📊 Coverage: 75% (critical features)
⚡ Speed: <5 seconds (full suite)
```

### 🎯 Test Categories

**Interactive Mode Tests** (`test_interactive_search.py`):
- 21 test methods
- Proves search finds tasks in <100ms with 150+ tasks
- Validates filter by status, tag, port
- Tests case-insensitive partial matching
- Ensures users can act on search results

**Core Architecture Tests** (`test_core_improvements.py`):
- 15 test methods
- Task dependency validation (no executing out of order)
- Plugin conflict resolution (highest confidence wins)
- Circular dependency detection
- Confidence scoring (0-100 scale)

**Visualizer Tests** (`test_visualizer.py`):
- 12 test methods
- Master view rendering
- Plugin flow diagrams
- Task tree display
- Progress tracking

### 🏆 Test Philosophy

```python
# ✅ Good Test - Proves USER VALUE
def test_user_finds_gobuster_quickly():
    """
    PROVES: User searching for 'gobuster' finds all gobuster tasks

    Real scenario: OSCP exam, multiple web ports, user wants
    to find all gobuster commands across ports 80, 443, 8080.
    """
    session = InteractiveSession("192.168.45.100")

    # Add gobuster tasks on multiple ports
    # ... setup ...

    results = session.search_tasks('gobuster')

    # User gets ALL gobuster tasks
    assert len(results) == 3

    # Search completes in <100ms (performance matters!)
    assert search_time < 0.1

# ❌ Bad Test - Tests MOCKS, not REALITY
def test_search_calls_method(mocker):
    """This doesn't prove the feature WORKS for users"""
    mock_search = mocker.patch('session.search_tasks')
    # This tests the mock, not real behavior!
```

**Run Tests:**
```bash
# All tests
pytest crack/tests/track/ -v

# Specific category
pytest crack/tests/track/test_interactive_search.py -v

# With coverage
pytest crack/tests/track/ --cov=crack.track --cov-report=term-missing

# Fast tests only
pytest crack/tests/track/ -m "not slow"
```

---

## 📁 Storage: Where Your Data Lives

Everything is stored in **human-readable JSON** at `~/.crack/`:

```bash
~/.crack/
├── targets/                    # Target profiles
│   ├── 192.168.45.100.json    # Full enumeration state
│   ├── 192.168.45.101.json
│   └── 192.168.45.102.json
├── sessions/                   # Interactive mode sessions
│   ├── 192.168.45.100.json    # Resume points
│   └── 192.168.45.101.json
└── config.json                 # Global settings

# Profile format (192.168.45.100.json):
{
  "target": "192.168.45.100",
  "created": "2025-10-08T12:00:00",
  "updated": "2025-10-08T14:30:00",
  "phase": "exploitation",
  "status": "in-progress",

  "ports": {
    "80": {
      "state": "open",
      "service": "http",
      "version": "Apache httpd 2.4.41",
      "source": "nmap service scan"
    }
  },

  "findings": [
    {
      "timestamp": "2025-10-08T13:00:00",
      "type": "directory",
      "description": "Found /admin-panel via robots.txt",
      "source": "Manual curl request"
    }
  ],

  "credentials": [
    {
      "timestamp": "2025-10-08T13:30:00",
      "username": "admin",
      "password": "SuperS3cr3t!",
      "service": "wordpress",
      "port": 80,
      "source": "config.php.bak in /backup"
    }
  ],

  "task_tree": {
    "id": "root",
    "name": "Enumeration: 192.168.45.100",
    "children": [ /* 47 tasks */ ]
  }
}
```

**Why JSON?**
- ✅ Human-readable (can edit manually if needed)
- ✅ Git-friendly (track changes to profiles)
- ✅ Easy to parse (integrate with other tools)
- ✅ Debuggable (cat the file to see what's stored)

---

## 🤝 Contributing: Join the Plugin Army

Want to add a service plugin? We'd love to have you! 🎉

### 🔌 Creating a Plugin (5 Minutes)

```python
# 1. Create: crack/track/services/your_service.py

from typing import Dict, Any
from .base import ServicePlugin
from .registry import ServiceRegistry

@ServiceRegistry.register  # ← Auto-registers your plugin!
class YourServicePlugin(ServicePlugin):
    """Your service enumeration plugin"""

    @property
    def name(self) -> str:
        return "your-service"

    def detect(self, port_info: Dict[str, Any]) -> float:
        """Return confidence score (0-100)"""
        service = port_info.get('service', '').lower()
        port = port_info.get('port')

        # Perfect match
        if service == 'your-service' and port == 1337:
            return 100

        # High confidence
        if 'your-service' in service:
            return 90

        # No match
        return 0

    def get_task_tree(self, target: str, port: int,
                     service_info: Dict) -> Dict:
        """Generate tasks for this service"""
        return {
            'id': f'your-service-{port}',
            'name': f'Your Service Enumeration (Port {port})',
            'type': 'parent',
            'children': [
                {
                    'id': f'enum-{port}',
                    'name': 'Basic Enumeration',
                    'type': 'command',
                    'metadata': {
                        'command': f'your-tool {target} -p {port}',
                        'description': 'Enumerate your service',
                        'tags': ['OSCP:HIGH', 'QUICK_WIN'],
                        'flag_explanations': {
                            '-p': 'Target port'
                        },
                        'success_indicators': [
                            'Connection successful',
                            'Data enumerated'
                        ],
                        'alternatives': [
                            f'Manual: nc {target} {port}'
                        ]
                    }
                }
            ]
        }

# 2. That's it! No registration needed - the decorator does it!

# 3. Test:
pytest crack/tests/track/ -v -k your_service
```

### 📋 Plugin Checklist

- [ ] Implements `detect()` with confidence scoring (0-100)
- [ ] Generates meaningful task tree
- [ ] Includes flag explanations for all commands
- [ ] Provides manual alternatives
- [ ] Lists success/failure indicators
- [ ] Tags tasks appropriately (OSCP:HIGH, QUICK_WIN, etc.)
- [ ] Has tests proving user value
- [ ] Documentation in docstrings

### 🎯 Good Plugin Examples

Check out these for inspiration:
- `services/http.py` - Complex plugin with CMS detection
- `services/smb.py` - Simple but comprehensive
- `services/ssh.py` - Good use of version-specific tasks

---

## 🎓 Philosophy: OSCP Success Over Tool Dependency

**CRACK Track teaches methodology, not memorization.**

### 🎯 Design Principles

1. **Manual alternatives for everything**
   - Tools fail in exams
   - Manual methods always work
   - You learn the WHY, not just the HOW

2. **Source tracking is mandatory**
   - OSCP graders demand proof
   - "I used gobuster" → ❌
   - "gobuster with common.txt wordlist found /admin at 12:45" → ✅

3. **Flag explanations everywhere**
   - Don't blindly run commands
   - Understand what each flag does
   - Adapt when default doesn't work

4. **Time awareness**
   - OSCP exam is 24 hours
   - Quick wins tagged clearly
   - Time estimates on tasks
   - Timeline shows where time was spent

5. **Progressive disclosure**
   - Don't overwhelm with 150 tasks at once
   - Show top 5 recommendations
   - Let users search for specific tasks
   - Context-aware menus

6. **Session persistence**
   - Exams have breaks
   - Systems crash
   - Always resume where you left off

---

## 🚨 Troubleshooting

### "crack: command not found"

```bash
# Install CRACK toolkit
cd /path/to/crack
pip install -e . --break-system-packages

# Or use reinstall script
./reinstall.sh
```

### "Profile not found"

```bash
# Check existing targets
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
# Ensure service versions were detected
crack track show 192.168.45.100

# If ports show but no versions:
nmap -sV -sC -p 80,445 192.168.45.100 -oA services
crack track import 192.168.45.100 services.xml
```

### "Interactive mode not working"

```bash
# Check Python version (needs 3.8+)
python3 --version

# Reinstall
cd /path/to/crack
./reinstall.sh

# Check logs
crack track -i 192.168.45.100 --debug
```

---

## 🎯 Pro Tips

### 🚀 Speed Up Your Workflow

```bash
# Alias for interactive mode
echo "alias ct='crack track -i'" >> ~/.bashrc
source ~/.bashrc

# Now just:
ct 192.168.45.100
```

### 🔍 Search Like a Boss

- Search for **quick wins** when time-limited: `QUICK_WIN`
- Search by **port** to see all tasks for one service: `445`
- Search by **tool** to find specific commands: `gobuster`
- Search by **phase** tags: `OSCP:HIGH`

### 📝 Document as You Go

**Don't wait until the end!** Document findings immediately:
- Press `d` in interactive mode
- Add sources EVERY time
- Future you will thank present you 🙏

### ⚡ Parallel Tasks Save Time

When CRACK Track shows "parallel tasks", **run them simultaneously**:

```bash
# Terminal 1
gobuster dir -u http://target

# Terminal 2
nikto -h http://target

# Terminal 3
curl http://target/robots.txt
```

Mark all complete when done. Saves HOURS on exam day. ⏰

### 🎯 Quick Win Priority

**Always do quick wins first:**
1. 30 seconds: `whatweb`, `robots.txt`, `sitemap.xml`
2. 2 minutes: `searchsploit` version lookups
3. 5 minutes: Manual checks (default creds, anonymous access)
4. 10+ minutes: Brute-forcing (gobuster, hydra)

Get the low-hanging fruit before running long scans.

---

## 📚 Further Reading

- **Architecture Deep Dive**: `docs/ARCHITECTURE_REVIEW.md`
- **Testing Strategy**: `tests/track/TEST_STRATEGY.md`
- **Plugin Development**: `PLUGIN_CONTRIBUTION_GUIDE.md`
- **Interactive Mode Guide**: `docs/INTERACTIVE_MODE.md` (coming soon)
- **Main CRACK Docs**: `/crack/README.md`

---

## 🎉 The Bottom Line

**CRACK Track** is your enumeration co-pilot for OSCP success:

✅ **120+ plugins** auto-generate perfect task lists
✅ **Interactive mode** guides you step-by-step
✅ **Search system** finds tasks in 150+ task trees instantly
✅ **Source tracking** builds OSCP reports automatically
✅ **Manual alternatives** for when tools fail (they will!)
✅ **Session persistence** so you never lose progress
✅ **Timeline export** reconstructs your entire attack chain

**No more forgetting tasks. No more lost notes. No more panic.**

Just methodical, documented, successful enumeration. 🎯

---

## 💬 Final Words

This tool was built by OSCP students who know the pain of:
- Forgetting which ports you scanned
- Losing track of which wordlists you tried
- Having no idea what you did 3 hours ago
- Frantically writing reports at 2 AM
- Wishing you documented sources for findings

**CRACK Track solves all of that.**

Now go pwn some boxes. 💀

---

```
 ░▒▓██████▓▒░       ░▒▓███████▓▒░        ░▒▓██████▓▒░        ░▒▓██████▓▒░       ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░             ░▒▓███████▓▒░       ░▒▓████████▓▒░      ░▒▓█▓▒░             ░▒▓███████▓▒░  
░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░░▒▓██████▓▒░░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                               
                                                                                              

 ████████╗   ██╗  ██╗   ███████╗
 ╚══██╔══╝   ██║  ██║   ██╔════╝
    ██║      ███████║   █████╗
    ██║      ██╔══██║   ██╔══╝
    ██║      ██║  ██║   ███████╗
    ╚═╝      ╚═╝  ╚═╝   ╚══════╝

 ██████╗     ██████╗    ██╗  ██╗
 ██╔══██╗   ██╔═══██╗   ╚██╗██╔╝
 ██████╔╝   ██║   ██║    ╚███╔╝
 ██╔══██╗   ██║   ██║    ██╔██╗
 ██████╔╝   ╚██████╔╝   ██╔╝ ██╗
 ╚═════╝     ╚═════╝    ╚═╝  ╚═╝
```

**Part of the CRACK Toolkit** - Comprehensive Recon & Attack Creation Kit
**License**: MIT
**Maintained by**: OSCP students, for OSCP students
**Contributions**: Always welcome! 🤝

🔗 **Report Issues**: https://github.com/CodeBlackwell/Phantom-Protocol/issues
📖 **Full Docs**: https://github.com/CodeBlackwell/Phantom-Protocol/tree/main/crack/track
⭐ **Star Us**: If this saves your OSCP exam, smash that star button!
