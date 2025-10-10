# CRACK Track Interactive Mode - Guide

**18+ specialized tools for OSCP exam preparation. Reduces enumeration time by 50-70% through automation and workflow optimization.**

## Table of Contents
1. [Overview](#1-overview)
2. [Quick Start](#2-quick-start)
3. [Core Concepts](#3-core-concepts)
4. [Keyboard Shortcuts](#4-keyboard-shortcuts)
5. [Tool Reference](#5-tool-reference)
6. [OSCP Workflows](#6-oscp-workflows)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Overview

### Value Proposition
- ⚡ 50-70% faster enumeration on 2nd+ targets
- 📊 Data-driven optimization (success rate analysis)
- 📝 OSCP-compliant documentation (source tracking)
- 🔄 Repeatable workflows (record/replay)
- ⏱️ Time management (tracking + estimates)

### Design Philosophy
Adapts to expertise level:
- **Beginner**: Full explanations and confirmations
- **Intermediate**: Smart confirmations, reduced prompts (recommended)
- **Expert**: Minimal UI, maximum speed
- **Exam mode**: Optimized for time constraints

### Zero Dependencies
Pure Python stdlib + existing CRACK infrastructure. Works in OSCP exam environment.

---

## 2. Quick Start

### Basic Workflow
```bash
# Create profile
crack track new 192.168.45.100

# Enter interactive mode
crack track -i 192.168.45.100

# Import scan
> import scan.xml
✓ Imported 3 ports, generated 15 tasks

# View progress
> pd
Progress: ████████.... 40% (6/15 tasks)

# Filter tasks
> tf port:80
Found 5 HTTP tasks

# Execute next task
> n
Executing: whatweb http://192.168.45.100

# Quick note
> qn Found admin panel with default creds

# Export findings
> qx findings
✓ Exported to findings_192.168.45.100.md
```

---

## 3. Core Concepts

### Session Persistence
**Auto-saves after every action** - never lose progress.

**Storage**:
- `~/.crack/targets/<TARGET>.json` - Target profiles
- `~/.crack/sessions/<TARGET>.json` - Session checkpoints
- `~/.crack/workflows/<NAME>.json` - Workflow recordings

### Task Status Flow
```
pending → in-progress → completed
                ↓
              failed (retry with 'tr')
```

### Source Tracking
All findings require documented sources (OSCP requirement):
```json
{
  "finding": "SQL injection in id parameter",
  "source": "sqlmap -u http://target/page?id=1",
  "timestamp": "2025-10-08T14:30:00"
}
```

### Confirmation Modes
| Mode | Confirmations | Use Case |
|------|---------------|----------|
| `always` | 100% | Beginner/learning |
| `smart` | ~30% | **Recommended** - balance |
| `never` | 0% | Expert/exam time pressure |
| `batch` | 1 per batch | Batch operations |

---

## 4. Keyboard Shortcuts

### Core Navigation
| Key | Action | Description |
|-----|--------|-------------|
| `h` | Help | Show all shortcuts |
| `s` | Status | Target status |
| `t` | Task tree | Hierarchical tasks |
| `r` | Recommendations | Next recommended tasks |
| `n` | Next task | Execute recommendation |
| `b` | Back | Previous menu |
| `q` | Quit | Save and exit |

### Core UX
| Key | Tool | Description |
|-----|------|-------------|
| `c` | Confirmation mode | Toggle confirmation behavior |
| `x` | Command templates | OSCP command builder |
| `/` | Fuzzy search | Find tasks by keyword |

### Quick Wins (High Value, Low Effort)
| Key | Tool | Description | Time Saved |
|-----|------|-------------|------------|
| `qn` | Quick note | No-form note entry | ~30s |
| `tf` | Task filter | Filter by status/port/service | ~1min |
| `ch` | Command history | Browse/search history | ~1min |
| `pl` | Port lookup | OSCP port reference | ~30s |
| `tt` | Time tracker | Time management | N/A |

### Medium Complexity
| Key | Tool | Description | Time Saved |
|-----|------|-------------|------------|
| `pd` | Progress dashboard | Visual progress | ~30s |
| `ss` | Session snapshot | Save/restore checkpoints | N/A |
| `qe` | Quick execute | Run without task creation | ~1min |
| `qx` | Quick export | Export to file/clipboard | ~2min |
| `tr` | Task retry | Retry failed with editing | ~2min |

### Advanced Workflow
| Key | Tool | Description | Time Saved |
|-----|------|-------------|------------|
| `be` | Batch execute | Multi-task execution | ~5min |
| `fc` | Finding correlator | Identify attack chains | ~3min |
| `sa` | Success analyzer | Task success rates | N/A |

### Expert Pattern-Matching
| Key | Tool | Description | Time Saved |
|-----|------|-------------|------------|
| `wr` | Workflow recorder | Record/replay sequences | ~20min (2nd+ target) |
| `sg` | Smart suggest | Pattern-based suggestions | ~2min |

---

## 5. Tool Reference

### 5.1 Confirmation Mode (`c`)
**Purpose**: Reduce confirmation prompts by 70%

**Modes**:
1. **Always** - Confirm every action (default)
2. **Smart** - Skip read-only tasks (recommended)
3. **Never** - No confirmations (expert mode)
4. **Batch** - Single confirmation per batch

**Usage**: Press `c` → Select mode [1-4]

---

### 5.2 Command Templates (`x`)
**Purpose**: Pre-built OSCP commands with variable substitution

**Categories**:
- Enumeration (15 templates)
- Web Testing (12 templates)
- Privilege Escalation (10 templates)
- File Transfer (8 templates)
- Exploitation (7 templates)

**Example**:
```bash
> x
Template: 2 (HTTP Directory Brute-force)

Command: gobuster dir -u http://<TARGET> -w <WORDLIST> -o <OUTPUT>

Flags:
  dir: Directory brute-forcing
  -u: Target URL
  -w: Wordlist (use common.txt for speed)
  -o: Output file (OSCP documentation required)

Execute? [y/N]: y
```

---

### 5.3 Fuzzy Search (`/`)
**Purpose**: Real-time task finding

**Search Modes**:
```bash
/gobuster         # Fuzzy match
/port:80          # Port filter
/tag:QUICK_WIN    # Tag filter
/status:failed    # Status filter
/port:80 status:pending  # Combined
```

---

### 5.4 Quick Note (`qn`)
**Purpose**: Add notes without forms

```bash
> qn Found admin panel at /dashboard - default creds (admin:admin)
✓ Note added

# With custom source
> qn
Note: SQLi in id parameter
Source [press Enter for 'quick-note']: manual sqlmap testing
✓ Note added
```

**Features**: Timestamped, searchable, exported in all formats

---

### 5.5 Task Filter (`tf`)
**Purpose**: Filter large task trees

**Examples**:
```bash
tf status:pending          # Pending tasks
tf port:80                 # HTTP tasks
tf service:smb             # SMB tasks
tf tag:QUICK_WIN           # High-value tasks
tf port:80 status:pending tag:QUICK_WIN  # Combined
```

**Actions on filtered results**:
1. Execute all (batch)
2. Execute by number
3. Export list
4. Clear filter

---

### 5.6 Command History (`ch`)
**Purpose**: Searchable command history

```bash
> ch                  # View all
> ch gobuster         # Search
> ch --success        # Only successful
> ch --failed         # Only failed
> ch --export cmds.txt  # Export
```

---

### 5.7 Port Lookup (`pl`)
**Purpose**: OSCP port reference

```bash
> pl 445
Port 445 - SMB (Server Message Block)

Enumeration:
  • enum4linux -a <target>
  • smbclient -L //<target> -N
  • smbmap -H <target>

Common Vulnerabilities:
  • EternalBlue (MS17-010)
  • Null session enumeration

Attack Vectors:
  1. Enumerate shares → upload payload
  2. Null session → brute force
  3. Exploit EternalBlue

OSCP Relevance: HIGH (80% of Windows targets)
```

---

### 5.8 Time Tracker (`tt`)
**Purpose**: Time management dashboard

```bash
> tt
Session Time: 1h 45m
Exam Time Remaining: 2h 15m (if exam)

Time by Phase:
  Discovery:           15m  ████░░░░░░  15%
  Service Enumeration: 45m  ████████░░  45%
  Exploitation:        25m  ██████░░░░  25%

Recommendations:
  ⚠️ 'manual-http' running >20min - consider timeout
  ✓ Quick wins available: enum4linux (est. 3min)
```

**Features**: Auto-timing, exam countdown mode, export reports

---

### 5.9 Progress Dashboard (`pd`)
**Purpose**: Visual progress overview

```bash
> pd
Overall: ████████████░░░░ 60% (12/20 tasks)

By Status:
  ✓ Completed:  12  60%
  ⧗ In Progress: 1   5%
  ○ Pending:     7  35%

By Port:
  Port 80 (HTTP)  ████████░░░░  50% (5/10)
  Port 445 (SMB)  ██░░░░░░░░░░  33% (1/3)

Quick Wins: 3 tasks (est. 10min)
```

---

### 5.10 Session Snapshot (`ss`)
**Purpose**: Save/restore checkpoints

```bash
# Create snapshot
> ss before-sqli-testing
✓ Snapshot created

# List snapshots
> ss --list
1. before-sqli-testing (14:30:00)
2. after-initial-enum (13:00:00)

# Restore
> ss --restore before-sqli-testing
✓ Restored

# Compare
> ss --diff before-sqli-testing
Changes: 2 tasks added, 1 finding added
```

---

### 5.11 Quick Execute (`qe`)
**Purpose**: Run commands without task tracking

```bash
> qe curl http://192.168.45.100/admin
[output displayed]

> qe mysql -h target -u dbuser -p'Pass123!'
[test credentials]

> qe --capture curl http://target/robots.txt
Save output? [y/N]: y
```

**Use Cases**: Quick testing, credential verification, exploration

---

### 5.12 Quick Export (`qx`)
**Purpose**: Export to file/clipboard

**Formats**:
```bash
qx findings   # Findings only (Markdown)
qx status     # Full status report
qx commands   # Command history
qx json       # Machine-readable
qx timeline   # Chronological timeline

# With clipboard
qx findings --clipboard
```

---

### 5.13 Task Retry (`tr`)
**Purpose**: Retry failed tasks with editing

```bash
> tr
Failed Tasks (2):
  1. gobuster-80 - Wordlist not found
  2. sqlmap-80   - Timeout

Select: 1

Original: gobuster dir -u http://target -w /wrong/path.txt
Edit? [Y/n]: y

Edit: gobuster dir -u http://target -w /usr/share/wordlists/common.txt
Execute? [Y/n]: y
✓ Completed
```

**Features**: Smart error suggestions, batch retry, preserves metadata

---

### 5.14 Batch Execute (`be`)
**Purpose**: Multi-task execution with dependencies

```bash
> be 1-5
Selected 5 tasks (est. 15min)

Dependency analysis:
  • Parallel: whatweb-80, ssh-keyscan-22
  • Sequential: gobuster-80 → nikto-80

Execute? [Y/n]: y
✓ 5/5 tasks completed (time saved: ~10min)
```

**Advanced Selection**:
```bash
be 1,3,5,7                    # Specific IDs
be --filter "port:80 status:pending"
be --tag QUICK_WIN
be --all-pending
```

---

### 5.15 Finding Correlator (`fc`)
**Purpose**: Identify attack chains

**Correlation Types**:

**Credential Reuse**:
```bash
> fc
🔑 CREDENTIAL REUSE (High Priority)

Found: admin:P@ssw0rd (HTTP config.js)

Untested services:
  → Port 22 (SSH)
  → Port 445 (SMB)

Execute tests? [Y/n]: y
✓ SMB: SUCCESS!
✓ MySQL: SUCCESS!
```

**Attack Chains**:
```bash
🔗 ATTACK CHAIN (Confidence: 85%)

LFI → Config File → DB Access → Shell

Step 1: LFI in page.php?file=
Step 2: Read /var/www/html/config.php
Step 3: Extract MySQL creds
Step 4: Connect to port 3306
Step 5: Write shell via INTO OUTFILE
```

**Version Correlation**:
```bash
🔍 VERSION CORRELATION

OS: Ubuntu 18.04 LTS (Apache 2.4.29 + OpenSSH 7.6)

Known CVEs:
  • CVE-2021-3156 (sudo heap overflow) - OSCP:HIGH
  • CVE-2021-41773 (Apache traversal) - OSCP:HIGH
```

---

### 5.16 Success Analyzer (`sa`)
**Purpose**: Task success rate analysis

```bash
> sa
Overall Statistics (5 targets):
  Success rate: 68% (97/142)
  Avg time: 8m 30s

By Task Type:
  manual-http   95%  [HIGHEST VALUE]
  gobuster      85%  [HIGH VALUE]
  enum4linux    80%  [HIGH VALUE]
  nikto         20%  [LOW VALUE]

Recommendations:
  ✓ Prioritize manual-http tasks
  ⚠️ Consider skipping nikto (low ROI)
```

---

### 5.17 Workflow Recorder (`wr`)
**Purpose**: Record/replay task sequences

```bash
# Record workflow
> wr --record initial-enum
Recording... (press 'q' to stop)
> n  # Execute task 1
> n  # Execute task 2
> qn Found interesting thing
> n  # Execute task 3
✓ Workflow saved: initial-enum (3 tasks, 1 note)

# Replay on new target
> wr --replay initial-enum
Replaying 'initial-enum' on 192.168.45.101
Execute? [Y/n]: y
✓ 3 tasks completed
```

---

### 5.18 Smart Suggest (`sg`)
**Purpose**: Pattern-based suggestions

```bash
> sg
Smart Suggestions (based on 5 similar targets):

High-probability actions:
  1. enum4linux-445 (success rate: 95% on SMB targets)
  2. Default creds test (worked on 3/5 similar targets)
  3. Web vuln scanner (found issues on 4/5)

Pattern match: Similar to target #3
  → Followed by: SQLi testing → Success (60min)
  → Exploit: Upload shell → SYSTEM
```

---

## 6. OSCP Workflows

### Workflow 1: Initial Enumeration
```bash
1. import scan.xml
2. pd  # Check workload
3. tf tag:QUICK_WIN  # Identify high-value tasks
4. be --tag QUICK_WIN  # Execute quick wins
5. fc  # Check for attack chains
6. qx findings  # Export for notes
```

### Workflow 2: Focused Port Attack
```bash
1. tf port:80 status:pending
2. be --filter "port:80"  # Execute all HTTP tasks
3. ch --success  # Review what worked
4. fc  # Correlate findings
5. qn Findings summary
```

### Workflow 3: Credential Reuse
```bash
1. fc  # Find credential reuse opportunities
2. Execute suggested tests
3. qn Document successes
4. sg  # Get next suggestions
```

### Workflow 4: Workflow Replay
```bash
# First target
1. wr --record standard-enum
2. [perform enumeration]
3. ✓ Workflow saved

# Subsequent targets
1. wr --replay standard-enum
2. Saves 50-70% time
```

---

## 7. Troubleshooting

### Issue: Commands not executing
**Check**: Confirmation mode - switch to `smart` or `never`

### Issue: Tasks failing
**Solution**: Use `tr` (task retry) to edit and re-execute

### Issue: Can't find task
**Solution**: Use `/` (fuzzy search) or `tf` (filter)

### Issue: Lost session
**Solution**: Sessions auto-save - just restart `crack track -i <target>`

### Issue: Export not working
**Solution**: Check permissions on export directory

### Performance Tips
- Use `smart` confirmation mode (70% faster)
- Filter before batch: `tf` → `be`
- Review success rates: `sa` (skip low-ROI tasks)
- Use workflow recorder: `wr` (50-70% faster on 2nd+ target)

---

## Quick Reference Card

```
Navigation:  h(help) s(status) t(tree) r(recommend) n(next) b(back) q(quit)
UX:          c(confirm) x(templates) /(search)
Quick Wins:  qn(note) tf(filter) ch(history) pl(port) tt(time)
Medium:      pd(progress) ss(snapshot) qe(execute) qx(export) tr(retry)
Advanced:    be(batch) fc(correlate) sa(analyze)
Expert:      wr(workflow) sg(suggest)
```

---

**Document Version:** 2.0 (Reduced)
**Last Updated:** 2025-10-10
**Reduction:** 1,800+ lines removed (60% reduction)
**Changes:** Converted prose to tables, consolidated examples, removed verbose descriptions
