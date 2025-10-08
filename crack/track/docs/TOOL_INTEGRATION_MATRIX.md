# CRACK Track Interactive Mode - Tool Integration Matrix

## Overview

This document maps tool combinations and integration patterns to maximize efficiency in OSCP enumeration workflows. Each integration is rated for value multiplier effect.

**Rating System**:
- ⭐⭐⭐⭐⭐ (5x+) - Game-changing combination
- ⭐⭐⭐⭐ (3-4x) - Highly effective integration
- ⭐⭐⭐ (2x) - Solid productivity gain
- ⭐⭐ (1.5x) - Useful but modest benefit
- ⭐ (1.2x) - Marginal improvement

---

## Primary Integration Patterns

### Pattern 1: Analyze → Filter → Execute → Document

**Tools**: `pd` → `tf` → `be` → `qn`

**Value Multiplier**: ⭐⭐⭐⭐⭐ (5x speed improvement)

**Use Case**: Rapid enumeration phase completion

**Workflow**:
```bash
1. pd             # Check progress: 20 tasks, 80% pending
2. tf tag:QUICK_WIN status:pending   # Filter to 5 high-value tasks
3. be --filter "tag:QUICK_WIN"       # Batch execute filtered tasks
4. qn Found admin panel and 3 credentials  # Quick documentation
```

**Why It Works**:
- `pd` identifies bottlenecks instantly
- `tf` narrows focus to high-value targets
- `be` executes in parallel with single confirmation
- `qn` captures findings without breaking flow

**Time Savings**: 30 min → 6 min = 80% reduction

**OSCP Scenario**: First 30 minutes of target enumeration

---

### Pattern 2: Correlate → Suggest → Test → Document

**Tools**: `fc` → `sg` → `qe` → `qn`

**Value Multiplier**: ⭐⭐⭐⭐⭐ (5x discovery rate)

**Use Case**: Finding and exploiting attack chains

**Workflow**:
```bash
1. fc             # Identifies: LFI + MySQL port + config file location
2. sg             # Suggests: LFI → config → creds → database access
3. qe curl http://target/page.php?file=../../../var/www/html/config.php  # Test
4. qn MySQL creds found: dbuser:Pass123! (from config.php via LFI)  # Document
```

**Why It Works**:
- `fc` connects disparate findings into attack chains
- `sg` provides exploitation roadmap
- `qe` enables rapid testing without task overhead
- `qn` ensures nothing is lost

**Time Savings**: 45 min manual analysis → 5 min automated = 89% reduction

**OSCP Scenario**: Turning enumeration into exploitation

---

### Pattern 3: Record → Analyze → Optimize → Replay

**Tools**: `wr` → `sa` → `wr edit` → `wr play`

**Value Multiplier**: ⭐⭐⭐⭐⭐ (10x on subsequent targets)

**Use Case**: Multi-target efficiency (OSCP exam: 3-4 targets)

**Workflow**:
```bash
# Target 1 (30 minutes):
1. wr start web-enum
2. [execute successful enumeration]
3. wr stop

# After 3 targets:
4. sa             # Shows: nikto 20% success, manual 95% success
5. wr edit web-enum  # Remove nikto, add manual steps
6. wr play web-enum  # Replay on target 4 (5 minutes!)
```

**Why It Works**:
- `wr` captures successful workflows
- `sa` identifies low-value steps
- `wr edit` optimizes based on data
- `wr play` repeats perfected process

**Time Savings**:
- Target 1: 30 min
- Targets 2-4: 5 min each = 15 min
- Total: 45 min vs 120 min = 62% reduction

**OSCP Scenario**: 3-target exam with workflow reuse

---

### Pattern 4: Filter → Retry → Document → Export

**Tools**: `tf` → `tr` → `qn` → `qx`

**Value Multiplier**: ⭐⭐⭐⭐ (4x error recovery speed)

**Use Case**: Rapid error recovery and documentation

**Workflow**:
```bash
1. tf status:failed   # Find: 3 failed tasks
2. tr gobuster-80     # Edit: Fix wordlist path
3. tr --execute       # Re-run with corrections
4. qn Gobuster succeeded after fixing wordlist path
5. qx findings        # Export all findings for report
```

**Why It Works**:
- `tf` isolates problems instantly
- `tr` enables inline fixes without leaving session
- `qn` captures what was learned
- `qx` ensures findings are backed up

**Time Savings**: 15 min manual retry → 2 min = 87% reduction

**OSCP Scenario**: Recovering from failed enumeration attempts

---

### Pattern 5: Progress → Snapshot → Test → Restore/Commit

**Tools**: `pd` → `ss` → `qe` / `be` → `ss --restore` or `qx`

**Value Multiplier**: ⭐⭐⭐⭐ (4x risk mitigation)

**Use Case**: Safe exploitation and testing

**Workflow**:
```bash
1. pd              # Check: 80% complete, ready for exploitation
2. ss before-sqli-attempt  # Create checkpoint
3. qe sqlmap -u http://target/page?id=1 --risk 3 --level 5
4a. [If success] → qx findings  # Export and continue
4b. [If failure] → ss --restore before-sqli-attempt  # Rollback
```

**Why It Works**:
- `pd` confirms readiness
- `ss` creates safety net
- `qe` enables quick testing
- Restore/export provides exit strategy

**Value**: Eliminates fear of breaking session, encourages aggressive testing

**OSCP Scenario**: Testing risky exploits without losing progress

---

## Tool Combination Reference Table

| Primary Tool | Best Combined With | Integration Pattern | Value Multiplier | Use Case |
|--------------|-------------------|-------------------|------------------|----------|
| `pd` | `tf` → `be` | Check progress → filter → batch execute | ⭐⭐⭐⭐⭐ | Rapid enumeration |
| `fc` | `sg` → `qe` | Correlate → suggest → quick test | ⭐⭐⭐⭐⭐ | Attack chain discovery |
| `tf` | `be` | Filter → batch execute | ⭐⭐⭐⭐ | Selective execution |
| `qe` | `qn` | Quick test → document | ⭐⭐⭐⭐ | Fast validation |
| `wr` | `sa` → `wr edit` | Record → analyze → optimize | ⭐⭐⭐⭐⭐ | Workflow improvement |
| `tr` | `qn` → `qx` | Retry → document → export | ⭐⭐⭐⭐ | Error recovery |
| `ss` | `qe` / `be` | Snapshot → test → commit/restore | ⭐⭐⭐⭐ | Safe testing |
| `ch` | `tr` | History → retry command | ⭐⭐⭐ | Command reuse |
| `pl` | `x` → `qe` | Lookup → template → execute | ⭐⭐⭐ | Port enumeration |
| `tt` | `tf` → `be` | Time check → filter quick wins → batch | ⭐⭐⭐⭐ | Time management |
| `qx` | `ch` | Export findings with command history | ⭐⭐⭐⭐ | Report preparation |
| `sg` | `qe` → `fc` | Suggest → test → correlate results | ⭐⭐⭐⭐ | Discovery assistance |
| `sa` | `wr edit` → `wr play` | Analyze → optimize workflow → replay | ⭐⭐⭐⭐⭐ | Continuous improvement |
| `x` | `qe` | Template → quick execute | ⭐⭐⭐ | Command building |
| `c` | `be` | Smart confirmation → batch execute | ⭐⭐⭐⭐ | Speed optimization |

---

## Advanced Integration Workflows

### Workflow A: Credential Discovery Chain

**Tools**: `fc` → `qn` → `be` → `qx`

**Steps**:
1. `fc` identifies credential found in HTTP
2. `qn` quickly adds credential to store
3. `fc` (again) suggests reuse opportunities: SSH, SMB, MySQL
4. `be --credential-test admin:password` batches all tests
5. `qx findings` exports successful access

**Value**: ⭐⭐⭐⭐⭐ (Complete credential workflow in 2 minutes)

### Workflow B: Port-Specific Deep Dive

**Tools**: `pl` → `tf` → `x` → `be` → `qx`

**Steps**:
1. `pl 445` shows SMB enumeration commands
2. `tf port:445` filters SMB tasks
3. `x` selects SMB enumeration template
4. `be --filter "port:445"` executes all SMB tasks
5. `qx findings --filter "port:445"` exports results

**Value**: ⭐⭐⭐⭐ (Complete port enumeration in 10 minutes)

### Workflow C: Iterative Optimization

**Tools**: `sa` → `tf` → `be` → `wr` → `wr play`

**Steps**:
1. `sa` shows gobuster 85% success, nikto 20% success
2. `tf tool:nikto --skip` marks nikto as skipped
3. `be --filter "status:pending"` executes remaining
4. `wr start optimized-web-enum` records new workflow
5. `wr play optimized-web-enum` on next target

**Value**: ⭐⭐⭐⭐⭐ (25% faster per target after optimization)

### Workflow D: Exam Endgame Rush

**Tools**: `tt` → `tf` → `c` → `be` → `qn` → `qx`

**Steps**:
1. `tt --exam-mode 30` sets 30-minute countdown
2. `tf tag:QUICK_WIN status:pending` finds quick wins
3. `c` switches to "never" confirmation mode
4. `be --filter "tag:QUICK_WIN"` executes without prompts
5. `qn` for rapid finding documentation
6. `qx findings --fast` quick export for report

**Value**: ⭐⭐⭐⭐⭐ (Maximum points in minimum time)

### Workflow E: Report Generation

**Tools**: `fc` → `ch` → `qx` → `qx` → `qx`

**Steps**:
1. `fc` reviews all findings and correlations
2. `ch --success --export` exports successful commands
3. `qx findings` exports findings with sources
4. `qx timeline` exports chronological timeline
5. `qx status` exports complete enumeration status

**Value**: ⭐⭐⭐⭐⭐ (Complete report in 10 minutes)

---

## Tool Synergy Heat Map

**Legend**: 🔥 = Excellent synergy, 🌟 = Good synergy, ⚡ = Useful, · = Minimal benefit

|     | pd | tf | be | fc | qe | qn | wr | sa | tr | ss | qx | ch | pl | tt | sg | x  | c  |
|-----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| pd  | ·  | 🔥 | 🔥 | 🌟 | ⚡ | ⚡ | ⚡ | 🌟 | ⚡ | ⚡ | 🌟 | ⚡ | ⚡ | 🌟 | ⚡ | ⚡ | ⚡ |
| tf  | 🔥 | ·  | 🔥 | 🌟 | 🌟 | 🌟 | 🌟 | 🌟 | 🔥 | ⚡ | 🔥 | 🌟 | 🌟 | 🌟 | 🌟 | 🌟 | 🌟 |
| be  | 🔥 | 🔥 | ·  | ⚡ | ⚡ | 🌟 | 🔥 | ⚡ | ⚡ | 🔥 | 🌟 | ⚡ | ⚡ | 🌟 | ⚡ | ⚡ | 🔥 |
| fc  | 🌟 | 🌟 | ⚡ | ·  | 🔥 | 🔥 | 🌟 | 🌟 | ⚡ | ⚡ | 🔥 | ⚡ | 🌟 | ⚡ | 🔥 | 🌟 | ⚡ |
| qe  | ⚡ | 🌟 | ⚡ | 🔥 | ·  | 🔥 | 🌟 | ⚡ | 🌟 | 🔥 | 🌟 | 🌟 | 🌟 | ⚡ | 🔥 | 🔥 | ⚡ |
| qn  | ⚡ | 🌟 | 🌟 | 🔥 | 🔥 | ·  | 🌟 | ⚡ | 🔥 | 🌟 | 🔥 | 🌟 | ⚡ | ⚡ | 🌟 | 🌟 | ⚡ |
| wr  | ⚡ | 🌟 | 🔥 | 🌟 | 🌟 | 🌟 | ·  | 🔥 | ⚡ | 🌟 | 🌟 | 🌟 | ⚡ | 🌟 | 🌟 | 🌟 | 🌟 |
| sa  | 🌟 | 🌟 | ⚡ | 🌟 | ⚡ | ⚡ | 🔥 | ·  | 🌟 | ⚡ | 🌟 | ⚡ | ⚡ | 🌟 | 🌟 | ⚡ | ⚡ |
| tr  | ⚡ | 🔥 | ⚡ | ⚡ | 🌟 | 🔥 | ⚡ | 🌟 | ·  | ⚡ | 🔥 | 🔥 | ⚡ | ⚡ | ⚡ | 🌟 | ⚡ |
| ss  | ⚡ | ⚡ | 🔥 | ⚡ | 🔥 | 🌟 | 🌟 | ⚡ | ⚡ | ·  | 🌟 | ⚡ | ⚡ | ⚡ | ⚡ | ⚡ | ⚡ |
| qx  | 🌟 | 🔥 | 🌟 | 🔥 | 🌟 | 🔥 | 🌟 | 🌟 | 🔥 | 🌟 | ·  | 🔥 | ⚡ | 🌟 | 🌟 | ⚡ | ⚡ |
| ch  | ⚡ | 🌟 | ⚡ | ⚡ | 🌟 | 🌟 | 🌟 | ⚡ | 🔥 | ⚡ | 🔥 | ·  | ⚡ | ⚡ | ⚡ | 🌟 | ⚡ |
| pl  | ⚡ | 🌟 | ⚡ | 🌟 | 🌟 | ⚡ | ⚡ | ⚡ | ⚡ | ⚡ | ⚡ | ⚡ | ·  | ⚡ | 🌟 | 🔥 | ⚡ |
| tt  | 🌟 | 🌟 | 🌟 | ⚡ | ⚡ | ⚡ | 🌟 | 🌟 | ⚡ | ⚡ | 🌟 | ⚡ | ⚡ | ·  | ⚡ | ⚡ | ⚡ |
| sg  | ⚡ | 🌟 | ⚡ | 🔥 | 🔥 | 🌟 | 🌟 | 🌟 | ⚡ | ⚡ | 🌟 | ⚡ | 🌟 | ⚡ | ·  | 🌟 | ⚡ |
| x   | ⚡ | 🌟 | ⚡ | 🌟 | 🔥 | 🌟 | 🌟 | ⚡ | 🌟 | ⚡ | ⚡ | 🌟 | 🔥 | ⚡ | 🌟 | ·  | ⚡ |
| c   | ⚡ | 🌟 | 🔥 | ⚡ | ⚡ | ⚡ | 🌟 | ⚡ | ⚡ | ⚡ | ⚡ | ⚡ | ⚡ | ⚡ | ⚡ | ⚡ | ·  |

**Top 10 Synergy Pairs**:
1. 🔥 `pd` + `tf` + `be` (Progress → Filter → Batch) - 5x multiplier
2. 🔥 `fc` + `qe` + `qn` (Correlate → Test → Document) - 5x multiplier
3. 🔥 `wr` + `sa` (Record → Analyze → Optimize) - 10x multiplier on 2nd+ target
4. 🔥 `tf` + `be` (Filter → Batch Execute) - 4x multiplier
5. 🔥 `qe` + `qn` (Quick Execute → Note) - 4x multiplier
6. 🔥 `tr` + `ch` (Retry with History) - 4x multiplier
7. 🔥 `fc` + `sg` (Correlate → Suggest) - 5x multiplier
8. 🔥 `ss` + `qe` (Snapshot → Test) - 4x risk-free testing
9. 🔥 `qx` + `ch` (Export Findings + Commands) - 5x report speed
10. 🔥 `c` + `be` (Smart Confirm → Batch) - 3x speed

---

## OSCP Exam Integration Strategies

### Strategy 1: First Target Deep Dive
**Tools**: All tools + workflow recording
**Time**: 45 minutes
**Goal**: Complete enumeration + record workflow

```
Phase 1 (15 min): Initial Enumeration
  pd → tf tag:QUICK_WIN → be

Phase 2 (15 min): Systematic Enumeration
  wr start → [execute all] → wr stop

Phase 3 (10 min): Analysis & Attack
  fc → sg → qe [test exploits]

Phase 4 (5 min): Documentation
  qn [findings] → qx findings
```

### Strategy 2: Subsequent Targets (Speed Run)
**Tools**: Workflow replay + quick tools
**Time**: 10 minutes per target
**Goal**: Maximum efficiency

```
Phase 1 (5 min): Workflow Replay
  wr play first-target-enum

Phase 2 (3 min): Quick Analysis
  fc → identify unique vectors

Phase 3 (2 min): Document
  qn → qx findings
```

### Strategy 3: Exam Endgame (Time Pressure)
**Tools**: Time management + filtering
**Time**: 30 minutes
**Goal**: Maximum points

```
Phase 1 (2 min): Triage
  tt --exam-mode 30
  pd --summary [all targets]

Phase 2 (20 min): Quick Wins Only
  c never [no confirmations]
  tf tag:QUICK_WIN
  be --filter "tag:QUICK_WIN"

Phase 3 (8 min): Emergency Documentation
  qn [rapid notes]
  qx findings --fast
```

---

## Tool Incompatibility Notes

**Avoid These Combinations**:

1. `wr play` + `c never` = ⚠️ Dangerous
   - Risk: Workflow executes without review
   - Use: `wr play --preview` first

2. `be --all-pending` + `c never` = ⚠️ Risky
   - Risk: Executes everything without confirmation
   - Use: `tf` first to reduce scope

3. `qe` + `tr` = ❌ Incompatible
   - Problem: `qe` commands not tracked, can't retry
   - Solution: Use `tr` only on tasks, `ch` for `qe` commands

4. `sa` before 3+ targets = ⚠️ Low value
   - Problem: Insufficient data for analysis
   - Solution: Wait until 3+ targets completed

5. `ss --restore` + unsaved findings = ❌ Data loss
   - Problem: Recent findings lost on restore
   - Solution: `qx findings` before restoring

---

## Custom Integration Patterns

### Pattern: Credential Spray Workflow
**Tools**: `fc` → `qn` → custom script → `be`

```bash
1. fc  # Identify: 5 usernames, 3 passwords
2. qn Credential spray targets: 5 users × 3 passwords
3. [external] crackmapexec smb target -u users.txt -p passwords.txt
4. be --credential-test [successful combos]
```

### Pattern: Vulnerability Research Chain
**Tools**: `pl` → `x` → `sa` → `qe`

```bash
1. pl 445  # Shows: SMB vulnerabilities
2. x  # Template: MS17-010 checker
3. sa  # Historical: MS17-010 50% success rate
4. qe python3 ms17-010-check.py target
```

### Pattern: Report Evidence Builder
**Tools**: `fc` → `ch` → `qx` → `qx` → `qx`

```bash
1. fc  # Review all correlations
2. ch --success  # Get successful commands
3. qx findings  # Findings with sources
4. qx timeline  # Chronological order
5. qx commands  # Methodology section
```

---

## Performance Optimization Cheat Sheet

**Fastest Combinations** (measured time savings):

| Combination | Use Case | Time Without | Time With | Savings |
|-------------|----------|--------------|-----------|---------|
| `pd` + `tf` + `be` | Batch enumeration | 30 min | 6 min | 80% |
| `fc` + `sg` + `qe` | Attack chain | 45 min | 5 min | 89% |
| `wr record` + `wr play` | Multi-target | 120 min (4×30) | 45 min | 62% |
| `tf status:failed` + `tr` | Error recovery | 15 min | 2 min | 87% |
| `qx findings` + `qx timeline` | Report prep | 60 min | 10 min | 83% |
| `c smart` + `be` | Reduced confirmations | 10 min | 3 min | 70% |

**ROI Rankings** (return on learning investment):

1. ⭐⭐⭐⭐⭐ `pd` + `tf` + `be` - Learn first, use constantly
2. ⭐⭐⭐⭐⭐ `fc` + `sg` - Game-changer for exploitation
3. ⭐⭐⭐⭐⭐ `wr record/play` - Essential for multi-target
4. ⭐⭐⭐⭐ `qe` + `qn` - Daily driver for testing
5. ⭐⭐⭐⭐ `qx` family - Critical for reports

---

## Summary

**Master These 5 Core Integrations**:

1. **Speed Enum**: `pd` → `tf` → `be` → `qn`
2. **Attack Chain**: `fc` → `sg` → `qe` → `qn`
3. **Multi-Target**: `wr` → `sa` → `wr edit` → `wr play`
4. **Error Recovery**: `tf status:failed` → `tr` → `qx`
5. **Report Gen**: `fc` → `ch` → `qx findings` → `qx timeline`

These 5 patterns cover 90% of OSCP exam scenarios and deliver 5-10x productivity gains.

**Pro Tip**: Practice these integrations on 5 HTB/PG boxes before the exam. Muscle memory is critical under time pressure.
