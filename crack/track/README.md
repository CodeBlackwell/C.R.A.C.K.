# CRACK Track - Enumeration Tracking & Task Management

**CRACK Track** is an intelligent enumeration tracking system designed for OSCP lab preparation. It automatically generates actionable task lists from scan results, tracks your progress, and exports comprehensive writeups for your OSCP documentation.

## 🎯 What is CRACK Track?

Think of CRACK Track as your **enumeration assistant** that:
- ✅ Auto-generates tasks from nmap scans
- ✅ Prevents duplicate work through progress tracking
- ✅ Requires source documentation for every finding
- ✅ Provides manual alternatives when tools fail
- ✅ Exports complete OSCP writeups with commands

## 🚀 Quick Start

### Create New Target Profile

```bash
# Start tracking a new target
crack track new 192.168.45.100

# You'll see initial discovery tasks:
# ✓ Ping check
# ✓ Quick port scan (top 1000)
# ✓ Full port scan (all 65535)
```

### Import Scan Results

```bash
# Import nmap XML to auto-generate service-specific tasks
crack track import 192.168.45.100 service_scan.xml

# CRACK Track will automatically:
# - Parse open ports and services
# - Generate HTTP enumeration tasks (whatweb, gobuster, nikto)
# - Generate SMB enumeration tasks (enum4linux, smbclient)
# - Create exploit research tasks based on versions
```

### View Current Tasks

```bash
# See what to do next
crack track show 192.168.45.100

# Output shows:
# - Next recommended task
# - Quick wins (fast, high-value tasks)
# - Parallel tasks (can run simultaneously)
# - Progress overview
```

### Track Progress

```bash
# Mark task as done
crack track done 192.168.45.100 gobuster-80

# Add findings with source (required for OSCP documentation)
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "Directory traversal in /download.php" \
  --source "Manual testing: /download.php?file=../../../../etc/passwd"

# Add discovered credentials
crack track creds 192.168.45.100 \
  --username admin \
  --password "P@ssw0rd123" \
  --source "config.php on web server" \
  --port 80
```

### Generate OSCP Writeup

```bash
# Export comprehensive markdown report
crack track export 192.168.45.100 > writeup.md

# Includes:
# - Timeline of all activities
# - All discovered ports/services
# - Findings with sources
# - Credentials discovered
# - Commands executed (reproducible)
# - Task completion status
```

## 📋 Core Commands

### Target Management

```bash
# Create new target profile
crack track new <TARGET>

# List all targets
crack track list

# Show target details
crack track show <TARGET>

# Delete target profile
crack track delete <TARGET>
```

### Task Management

```bash
# View recommendations (what to do next)
crack track recommend <TARGET>

# Mark task as completed
crack track done <TARGET> <TASK_ID>

# Add manual task
crack track add-task <TARGET> \
  --name "Check backup files" \
  --command "curl http://192.168.45.100/backup.zip"

# List all tasks
crack track tasks <TARGET>
```

### Data Import

```bash
# Import nmap XML
crack track import <TARGET> scan.xml

# Import nmap gnmap (greppable format)
crack track import <TARGET> scan.gnmap

# Supports: -oX (XML), -oG (gnmap), -oA (all formats)
```

### Documentation

```bash
# Add finding (requires source!)
crack track finding <TARGET> \
  --type <TYPE> \
  --description "What you found" \
  --source "How you found it"

# Finding types: vulnerability, directory, user, config, database, etc.

# Add credentials
crack track creds <TARGET> \
  --username <USER> \
  --password <PASS> \
  --source "Where found" \
  --service <SERVICE> \
  --port <PORT>

# Add freeform note
crack track note <TARGET> "Your observation here"
```

### Export & Reporting

```bash
# Export full markdown report
crack track export <TARGET>

# Export only task reference (command list)
crack track export <TARGET> --tasks-only

# Export timeline
crack track timeline <TARGET>
```

## 🏗️ Architecture

### Task Tree System

CRACK Track organizes enumeration as a hierarchical task tree:

```
Root: Enumeration 192.168.45.100
├── Discovery Phase
│   ├── Ping check
│   ├── Quick port scan
│   └── Full port scan
├── HTTP Enumeration (Port 80)
│   ├── Technology fingerprinting (whatweb)
│   ├── Directory brute-force (gobuster)
│   ├── Vulnerability scan (nikto)
│   ├── Manual checks
│   │   ├── Check robots.txt
│   │   ├── Check sitemap.xml
│   │   └── Review page source
│   └── Exploit research: Apache 2.4.41
│       ├── searchsploit Apache 2.4.41
│       └── CVE lookup
└── SMB Enumeration (Port 445)
    ├── Anonymous login check
    ├── Share enumeration (enum4linux)
    └── Exploit research: Samba 4.13.13
```

### Service Plugins

CRACK Track uses **service plugins** that automatically generate tasks when services are detected:

**HTTP/HTTPS Plugin:**
- Technology fingerprinting (whatweb)
- Directory/file discovery (gobuster)
- Vulnerability scanning (nikto)
- Manual enumeration checklist
- Version-specific exploit research

**SMB Plugin:**
- Anonymous access testing
- Share enumeration (enum4linux, smbclient)
- User enumeration
- Vulnerability scanning (nmap scripts)

**SSH Plugin:**
- Banner grabbing
- User enumeration
- Key-based auth testing
- Version exploit research

**FTP Plugin:**
- Anonymous login testing
- File enumeration
- Writable directory checks

**SQL Plugin:**
- Version detection
- Default credentials
- SQL injection testing points

**Post-Exploitation Plugin:**
- Privilege escalation enumeration
- Lateral movement checks
- Persistence mechanisms

### Event-Driven Architecture

```
Nmap Parser → Emits "service_detected" event
                ↓
Service Registry → Matches service to plugin
                ↓
HTTP Plugin → Generates task tree
                ↓
Target Profile → Adds tasks to tree
                ↓
Recommendation Engine → Prioritizes tasks
```

## 🎓 OSCP Exam Preparation Features

### 1. Manual Alternatives

Every automated task includes **manual alternatives** for when tools fail or aren't available:

```bash
# Automated: gobuster dir -u http://target
# Manual: curl http://target/admin, curl http://target/upload
```

### 2. Source Tracking

CRACK Track **requires sources** for all findings - critical for OSCP documentation:

```bash
# ❌ This will fail:
crack track finding <TARGET> --type vuln --description "Directory traversal"

# ✅ This works:
crack track finding <TARGET> \
  --type vuln \
  --description "Directory traversal" \
  --source "Manual testing: /download.php?file=../../../etc/passwd"
```

### 3. Flag Explanations

All commands include **educational flag explanations**:

```bash
# gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
#
# dir: Directory/file brute-forcing mode
# -u: Target URL
# -w: Wordlist path
# -o: Output file (for documentation)
```

### 4. Success/Failure Indicators

Tasks include expected outcomes and troubleshooting:

```bash
Success Indicators:
- Directories found (Status: 200, 301, 302)
- Admin panels, upload forms discovered

Failure Indicators:
- All 404 responses (wrong wordlist)
- Connection timeouts (firewall blocking)

Next Steps:
- Try larger wordlist: raft-medium-directories.txt
- Check for .php, .asp, .aspx extensions
```

### 5. Time Tracking

All findings and tasks are timestamped for **timeline reconstruction**:

```bash
crack track timeline 192.168.45.100

# Output:
# 2025-10-07 12:34:56 - Completed: Full port scan
# 2025-10-07 12:45:23 - Finding: Directory traversal in /download.php
# 2025-10-07 13:12:45 - Credential: admin / P@ssw0rd123 (config.php)
```

## 📊 Example Workflow

### Typical OSCP Lab Box Enumeration

```bash
# 1. Start tracking new target
crack track new 192.168.45.100

# 2. Run initial discovery
nmap -p- --min-rate 1000 192.168.45.100 -oA discovery
crack track import 192.168.45.100 discovery.xml

# 3. Service detection scan on open ports
nmap -sV -sC -p 22,80,445 192.168.45.100 -oA services
crack track import 192.168.45.100 services.xml

# 4. Check recommendations
crack track recommend 192.168.45.100

# Output:
# 🎯 Next: Technology Fingerprinting (Port 80)
# Command: whatweb http://192.168.45.100:80 -v
#
# 🚀 Quick Wins (5):
# 1. whatweb (Port 80) - Fast tech stack identification
# 2. robots.txt check - 2 second manual check
# 3. sitemap.xml check - Quick path discovery
# 4. Anonymous SMB - Test null session
# 5. SSH banner grab - Version for exploit research

# 5. Execute tasks and mark complete
whatweb http://192.168.45.100:80 -v
crack track done 192.168.45.100 whatweb-80

# 6. Document findings as you discover them
crack track finding 192.168.45.100 \
  --type directory \
  --description "Found /admin directory (301 redirect)" \
  --source "gobuster with common.txt wordlist"

# 7. Add credentials when found
crack track creds 192.168.45.100 \
  --username administrator \
  --password "admin123" \
  --source "/admin/config.php source code" \
  --service http \
  --port 80

# 8. Export writeup for submission
crack track export 192.168.45.100 > 192.168.45.100-writeup.md
```

## 🔧 Advanced Usage

### Phase Management

CRACK Track follows enumeration phases:

```bash
# Phases (automatically progress):
# 1. discovery - Initial port scanning
# 2. service-detection - Service version identification
# 3. service-specific - Per-service enumeration
# 4. exploitation - Active exploitation attempts
# 5. post-exploitation - Privilege escalation

# Manually change phase
crack track phase 192.168.45.100 exploitation
```

### Custom Tasks

```bash
# Add custom enumeration task
crack track add-task 192.168.45.100 \
  --name "Check phpinfo.php" \
  --command "curl http://192.168.45.100/phpinfo.php" \
  --description "Check for exposed PHP info page" \
  --tags MANUAL QUICK_WIN

# Add parent task with subtasks
crack track add-task 192.168.45.100 \
  --name "WordPress Enumeration" \
  --type parent

crack track add-task 192.168.45.100 \
  --name "WPScan vulnerability scan" \
  --command "wpscan --url http://192.168.45.100 --enumerate vp" \
  --parent wordpress-enum
```

### Filtering and Search

```bash
# Show only pending tasks
crack track tasks 192.168.45.100 --status pending

# Show only quick wins
crack track tasks 192.168.45.100 --tag QUICK_WIN

# Show tasks for specific port
crack track tasks 192.168.45.100 --port 80

# Show only high OSCP relevance
crack track tasks 192.168.45.100 --oscp-relevance high
```

## 📁 Storage Location

CRACK Track stores profiles in `~/.crack/targets/`:

```bash
~/.crack/targets/
├── 192.168.45.100.json
├── 192.168.45.101.json
└── 192.168.45.102.json

# Each profile contains:
# - Target metadata (IP, phase, status)
# - Complete task tree with status
# - All findings with timestamps
# - Discovered credentials
# - Imported scan files list
# - Notes and observations
```

## 🧪 Testing

CRACK Track includes comprehensive test suite:

```bash
# Run all enumeration tests
pytest tests/enumeration/ -v

# Run specific test category
pytest tests/enumeration/test_user_stories.py -v
pytest tests/enumeration/test_guidance_quality.py -v

# With coverage report
pytest tests/enumeration/ --cov=crack.enumeration --cov-report=term-missing
```

**Test Coverage:**
- ✅ 51 tests (100% passing)
- ✅ 18 user story tests (real OSCP workflows)
- ✅ Edge case handling (corrupted storage, malformed input)
- ✅ Documentation requirements (source tracking, timeline)

## 🎨 Output Styles

### Console Output

```
🎯 Target: 192.168.45.100
📊 Phase: service-specific (In Progress)
✅ Progress: 8/24 tasks completed (33%)

🚀 Quick Wins (5 tasks):
  1. ⚡ Technology Fingerprinting (Port 80)
     Command: whatweb http://192.168.45.100:80 -v
     Time: ~30 seconds

  2. 📝 Check robots.txt
     Command: curl http://192.168.45.100/robots.txt
     Time: ~5 seconds

📋 Next Recommended Task:
  Directory Brute-force (Port 80)
  Command: gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt
  Expected Time: 2-5 minutes
```

### Markdown Export

Exports professional OSCP-style writeups:

```markdown
# Enumeration Report: 192.168.45.100

## Metadata
- **Target**: 192.168.45.100
- **Status**: in-progress
- **Phase**: service-specific
- **Started**: 2025-10-07T12:00:00

## Summary
Enumeration of **192.168.45.100** is currently in the **service-specific** phase.
- **Open Ports**: 3
- **Findings**: 5
- **Credentials**: 2
- **Tasks Completed**: 8/24

## Discovered Ports
| Port | State | Service | Version | Source |
|------|-------|---------|---------|--------|
| 22   | open  | ssh     | OpenSSH 8.2p1 | nmap service scan |
| 80   | open  | http    | Apache httpd 2.4.41 | nmap service scan |
| 445  | open  | smb     | Samba 4.13.13 | nmap service scan |

## Findings
### Finding #1: vulnerability
**Description**: Directory traversal in /download.php
**Source**: `Manual testing: /download.php?file=../../../../etc/passwd`
**Timestamp**: 2025-10-07T12:45:23

## Timeline
- **2025-10-07T12:34:56**: Completed: Full port scan
- **2025-10-07T12:45:23**: Finding: Directory traversal
- **2025-10-07T13:12:45**: Credential: admin discovered
```

## 🤝 Integration with CRACK Toolkit

CRACK Track integrates seamlessly with other CRACK tools:

```bash
# Use with SQLi scanner
crack sqli-scan http://192.168.45.100/page.php?id=1
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "SQL injection in id parameter" \
  --source "crack sqli-scan (union-based)"

# Use with port scanner
crack port-scan 192.168.45.100 --output scan.xml
crack track import 192.168.45.100 scan.xml

# Use with CVE lookup
crack cve-lookup "Apache httpd 2.4.41"
# Document findings in CRACK Track
```

## 💡 Tips & Best Practices

### 1. Import Scans Immediately
```bash
# As soon as scan completes, import it
nmap -sV -sC -p- 192.168.45.100 -oA fullscan && \
  crack track import 192.168.45.100 fullscan.xml
```

### 2. Document Everything with Sources
```bash
# OSCP graders need to know HOW you found it
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "Apache 2.4.49 path traversal (CVE-2021-41773)" \
  --source "searchsploit apache 2.4.49, tested with curl"
```

### 3. Use Quick Wins First
```bash
# Always check quick wins before long scans
crack track recommend 192.168.45.100
# Run the 5 quick wins (usually <5 min total)
# Then start longer scans (gobuster, nikto)
```

### 4. Track Your Time
```bash
# OSCP exam is timed - use timeline to estimate
crack track timeline 192.168.45.100

# Example output shows:
# 12:00 - 12:30 (30 min): Discovery scans
# 12:30 - 13:00 (30 min): Service enumeration
# 13:00 - 15:00 (2 hr): Web application testing
# Total: 3 hours to initial foothold
```

### 5. Resume After Breaks
```bash
# CRACK Track persists everything
# Next day, just:
crack track show 192.168.45.100

# You'll see exactly where you left off
```

## 🐛 Troubleshooting

### Profile Not Found
```bash
# Check available targets
crack track list

# Create if missing
crack track new 192.168.45.100
```

### Import Fails
```bash
# Verify file format
file scan.xml  # Should say "XML document"

# Try gnmap if XML fails
nmap -oG scan.gnmap ...
crack track import 192.168.45.100 scan.gnmap
```

### Tasks Not Generating
```bash
# Ensure service versions detected
crack track show 192.168.45.100

# If no versions, run:
nmap -sV -p 80,445 192.168.45.100 -oA services
crack track import 192.168.45.100 services.xml
```

## 📚 Learn More

- **Main CRACK Documentation**: `/docs/`
- **Test Suite**: `/tests/enumeration/README.md`
- **Architecture Deep Dive**: See source comments in `/enumeration/`
- **Plugin Development**: `/enumeration/services/base.py`

## 🎯 OSCP Exam Ready

CRACK Track is specifically designed for OSCP success:

✅ **Methodology Focus**: Teaches systematic enumeration
✅ **Manual Techniques**: Every tool has manual alternatives
✅ **Time Management**: Quick wins and time estimates
✅ **Documentation**: Source tracking for report submission
✅ **Reproducibility**: Every command is saved
✅ **No Tool Dependency**: Manual methods when tools fail

Good luck on your OSCP journey! 🚀

---

**Part of the CRACK Toolkit** - Comprehensive Recon & Attack Creation Kit
