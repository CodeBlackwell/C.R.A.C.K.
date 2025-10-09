# 5-Minute Quick Start - Interactive Mode Tools

**Get productive with CRACK Track Interactive Mode in 5 minutes**

---

## Your First Session

### Step 1: Import Nmap Scan (30 seconds)

```bash
# Create target profile
crack track new 192.168.45.100

# Enter interactive mode
crack track -i 192.168.45.100

# Import scan results
[crack-track] > import nmap_scan.xml

✓ Imported 3 ports: 22 (ssh), 80 (http), 445 (smb)
✓ Generated 15 service-specific tasks automatically
```

**What just happened?**
- Profile created at `~/.crack/targets/192.168.45.100.json`
- 15 enumeration tasks auto-generated based on discovered services
- Task tree organized by service (SSH, HTTP, SMB)

---

### Step 2: Check Attack Correlations (30 seconds)

```bash
[crack-track] > fc

🔗 Analyzing findings for correlations...

No correlations yet (enumeration needed)
```

**Why check correlations now?**
- Identifies immediate attack chains (if any port correlations exist)
- After enumeration, `fc` becomes your exploitation roadmap

---

### Step 3: Batch Enumerate Services (5 minutes)

```bash
[crack-track] > be all

Select tasks to execute:
  1. whatweb-80        [HTTP] Technology fingerprinting
  2. gobuster-80       [HTTP] Directory brute-force
  3. nikto-80          [HTTP] Vulnerability scan
  4. enum4linux-445    [SMB] Share enumeration
  5. smbclient-445     [SMB] Share access test
  6. ssh-enum-22       [SSH] Version detection
  ... (15 tasks total)

Selection: all

Analyzing dependencies...
✓ No circular dependencies
✓ Parallel safe: whatweb, enum4linux, ssh-enum
✓ Sequential: gobuster → nikto (nikto uses gobuster results)

Execute 15 tasks? [Y/n]: y

[Executing batch]
  ✓ whatweb-80 completed (5s)
  ✓ enum4linux-445 completed (12s)
  ✓ ssh-enum-22 completed (3s)
  ✓ gobuster-80 completed (45s)
  ✓ nikto-80 completed (30s)
  ... (all 15 tasks in 3m 42s)

Batch complete: 15/15 success, 0 failed
```

**What just happened?**
- All enumeration tasks executed automatically
- Dependencies resolved (nikto ran AFTER gobuster)
- Parallel execution where safe (50-70% time savings)
- All output captured and logged

---

### Step 4: Monitor Progress (10 seconds)

```bash
[crack-track] > pd

═══════════════════════════════════════════════════════════
 PROGRESS DASHBOARD - 192.168.45.100
═══════════════════════════════════════════════════════════

Overall Progress: [████████████████████] 100% (15/15 tasks)

Status Breakdown:
  ✓ Completed:    15 tasks (100%)
  ⏳ In Progress:  0 tasks (0%)
  ⏸ Pending:      0 tasks (0%)
  ✗ Failed:       0 tasks (0%)

Progress by Service:
  HTTP (80):   [██████████████████] 100% (5/5)  ✓
  SSH (22):    [██████████████████] 100% (3/3)  ✓
  SMB (445):   [██████████████████] 100% (7/7)  ✓

✓ ALL SERVICES ENUMERATED
```

**Why use progress dashboard?**
- Visual confirmation all services enumerated
- Identify overlooked services (would show 0% or low %)
- Quick status check without scrolling task list

---

### Step 5: Export Findings (30 seconds)

```bash
[crack-track] > qx

Export Options:
  1. Findings only
  2. Task list
  3. Timeline
  4. Full report

Select: 1

Export Format:
  1. Markdown
  2. JSON
  3. CSV

Select: 1

✓ Exported to: /home/kali/.crack/exports/192.168.45.100/findings_2025-10-08_143052.md

Contents:
  • 3 vulnerabilities
  • 2 credentials
  • 7 notes
  • Auto-generated attack recommendations
```

**What's in the export?**
- All vulnerabilities with sources (OSCP-compliant)
- Discovered credentials
- Notes from enumeration
- Timestamped for report

---

## 10 Essential Shortcuts (Copy This List)

**Memorize these 10 shortcuts for 90% of interactive mode usage:**

```
1. fc   - Find attack chains (use after each phase)
2. be   - Batch execute (use for parallel enumeration)
3. pd   - Progress dashboard (use every 30 min)
4. qn   - Quick note (use for ALL findings)
5. ss   - Session snapshot (use before risky actions)
6. tr   - Task retry (use to fix command typos)
7. qx   - Quick export (use for backups)
8. tf   - Task filter (use with 20+ tasks)
9. qe   - Quick execute (use for one-off tests)
10. ch  - Command history (use for report)
```

---

## 3 Common Workflows (Copy-Paste Ready)

### Workflow 1: Initial Target Enumeration (6 minutes)

```bash
# 1. Create and enter profile
crack track new 192.168.45.100
crack track -i 192.168.45.100

# 2. Import scan
import nmap_full.xml

# 3. Execute all enumeration
be all

# 4. Check for correlations
fc

# 5. Export findings
qx
```

**Result**: Complete enumeration + findings documented in 6 minutes

---

### Workflow 2: Rapid Multi-Target (First target: 30 min, others: 5 min)

```bash
# Target 1 (first time - full enumeration)
crack track -i 192.168.45.100
import scan.xml
be all
fc

# Record successful workflow
wr
> Record new workflow: quick-enum
> Select tasks: 1-10 (quick win tasks)
✓ Workflow recorded

# Target 2-5 (workflow replay - 5 min each)
crack track -i 192.168.45.101
import scan_101.xml
wr
> Play workflow: quick-enum
✓ Executed in 5m 12s

# Repeat for remaining targets
```

**Result**: 83% time savings on subsequent targets

---

### Workflow 3: Exploitation Preparation (10 minutes)

```bash
# 1. Verify enumeration complete
pd
> Check: 100% completion

# 2. Snapshot before exploitation
ss
> Create snapshot: post-enumeration

# 3. Find attack chains
fc
> Review correlations (service+creds, vuln chains)

# 4. Get suggestions
sg
> Smart suggestions based on findings

# 5. Test highest confidence suggestion
qe
> Execute suggested command

# 6. Document breakthrough
qn
> Note finding with source
```

**Result**: Attack plan identified and documented

---

## Quick Reference Card

### Tool Usage Patterns

**When to use each tool:**

| Tool | When | Why |
|------|------|-----|
| **be** | After scan import | Execute all enumeration tasks (50-70% faster) |
| **fc** | After enumeration complete | Identify attack chains (10-15 min saved) |
| **pd** | Every 30 minutes | Verify progress, find overlooked services |
| **qn** | Immediately upon finding | Document with source (OSCP required) |
| **qx** | Every 1-2 hours | Backup documentation |
| **ss** | Before exploitation | Checkpoint for rollback |
| **tf** | When 20+ tasks | Filter by port/service/tag |
| **tr** | Command failed | Fix typo and retry (2-3 min saved) |
| **qe** | Quick test needed | Execute without task overhead |
| **ch** | Report time | Recall commands for documentation |
| **tt** | OSCP exam | Track time per target (90 min limit) |
| **pl** | Unknown port | Port reference + enumeration guide |
| **sa** | After 2+ targets | Optimize workflow based on success rates |
| **wr** | After 1st target | Record workflow for subsequent targets |
| **sg** | Stuck/need ideas | Pattern-based suggestions |

---

### Keyboard Shortcuts (Minimal Set)

**Basic shortcuts (always available):**

```
s   - Show status
t   - Show task tree
r   - Show recommendations
n   - Execute next recommended task
h   - Show help
q   - Quit and save
```

**Tool shortcuts (see 10 Essential above):**

```
be, ch, fc, pd, pl, qe, qn, qx, sa, sg, ss, tf, tr, tt, wr
```

---

## First Session Checklist

**Complete this checklist your first time using interactive mode:**

### Setup (one-time)
- [ ] Install CRACK: `pip install crack-toolkit`
- [ ] Verify install: `crack track --help`
- [ ] Create test profile: `crack track new 192.168.1.1`

### First Enumeration Session
- [ ] Import nmap scan: `import scan.xml`
- [ ] Check task generation: Tasks appear for each service
- [ ] Batch execute: `be all` → All tasks complete
- [ ] Check progress: `pd` → Shows 100% completion
- [ ] Document finding: `qn` → Note added with source
- [ ] Export findings: `qx` → File created in ~/.crack/exports/

### First Exploitation Session
- [ ] Create snapshot: `ss` → Checkpoint before exploit
- [ ] Find correlations: `fc` → Attack chains identified
- [ ] Get suggestions: `sg` → Next steps recommended
- [ ] Quick execute test: `qe` → Command executed without task
- [ ] Restore snapshot (test): `ss` → Profile restored

### Report Preparation
- [ ] View command history: `ch` → All commands logged
- [ ] Export timeline: `qx` timeline → Chronological events
- [ ] Export full report: `qx` full → OSCP writeup generated
- [ ] Verify sources: All findings have source attribution

---

## Common First-Time Mistakes

### ❌ Mistake 1: Forgetting to provide source

```bash
# WRONG - No OSCP credit
[crack-track] > qn Found admin panel
Source: [pressed Enter, left blank]
```

**FIX:**
```bash
# CORRECT
[crack-track] > qn Found admin panel at /admin
Source: gobuster dir scan with common.txt wordlist
✓ Note added with source
```

---

### ❌ Mistake 2: Not using batch execute

```bash
# WRONG - Execute tasks one-by-one (30 min)
[crack-track] > execute whatweb-80
[crack-track] > execute gobuster-80
[crack-track] > execute nikto-80
... (manual, slow)
```

**FIX:**
```bash
# CORRECT - Batch execute (5 min)
[crack-track] > be all
✓ All 15 tasks in 5 minutes
```

---

### ❌ Mistake 3: Not creating snapshots before exploitation

```bash
# WRONG - No rollback capability
[crack-track] > qe
Command: python exploit.py
[corrupts profile data]
[no way to recover]
```

**FIX:**
```bash
# CORRECT - Snapshot first
[crack-track] > ss
Create snapshot: before-exploit
✓ Checkpoint saved

[crack-track] > qe
Command: python exploit.py
[if fails, restore from snapshot]
```

---

### ❌ Mistake 4: Not exporting regularly

```bash
# WRONG - No backups during long exam
[2 hours of enumeration]
[system crash]
[all findings lost]
```

**FIX:**
```bash
# CORRECT - Export every 1-2 hours
[crack-track] > qx
Export findings
✓ Backup created

[1 hour later]
[crack-track] > qx
Export findings
✓ Another backup (never lose work)
```

---

### ❌ Mistake 5: Ignoring time tracker in OSCP exam

```bash
# WRONG - No time awareness
[crack-track] > [spends 3 hours on one target]
[fails to complete exam]
```

**FIX:**
```bash
# CORRECT - Set time limits
[crack-track] > tt
Set target time: 90 minutes
Alert at: 75 minutes

[75 min alert fires]
⚠ 15 minutes remaining - consider moving to next target
```

---

## Next Steps

**After completing this quick start:**

1. **Read Full Guide**: `/home/kali/OSCP/crack/track/docs/INTERACTIVE_MODE_TOOLS_GUIDE.md`
   - Complete tool documentation
   - 6 detailed workflows
   - Troubleshooting guide

2. **Practice Workflows**: Run through Workflows 1-3 on test targets
   - Workflow 1: Initial enumeration
   - Workflow 2: Multi-target speed run
   - Workflow 3: Exploitation preparation

3. **Customize Settings**:
   ```bash
   [crack-track] > c
   Change confirmation mode: smart (skip prompts for read-only tasks)
   ```

4. **Review API Docs** (if extending): `INTERACTIVE_TOOLS_API.md`

---

## Troubleshooting Quick Fixes

**Issue**: Tasks not generated after scan import
```bash
# Check scan file format
crack track import --validate scan.xml

# Re-import with verbose
crack track -i 192.168.45.100
import scan.xml -v
```

**Issue**: Batch execute fails
```bash
# Check for dependency issues
be all -v  # Verbose mode shows dependency tree

# Execute smaller batches
tf port:80
be  # Execute only port 80 tasks
```

**Issue**: Export file not found
```bash
# Check export directory
ls ~/.crack/exports/192.168.45.100/

# Tool creates directory automatically
qx  # Try again, should create directory
```

---

## Time Investment vs. Savings

**Initial learning (this guide)**: 5 minutes
**First target (with tools)**: 30 minutes
**Subsequent targets**: 5 minutes each

**Traditional approach**:
- Every target: 60+ minutes (manual enumeration)
- 5 targets: 5+ hours

**With CRACK Track Interactive Mode**:
- First target: 30 minutes (learn + enumerate)
- Targets 2-5: 20 minutes total (4 × 5 min via workflow replay)
- **Total: 50 minutes for 5 targets (83% time savings)**

---

**You're now ready to reduce OSCP enumeration time by 50-70% while maintaining 100% documentation compliance!**
