# 🔗 Cross-Chain Linking (LINK) - User Guide

## 📋 Table of Contents

1. [Overview](#overview)
2. [How It Works](#how-it-works)
3. [User Workflows](#user-workflows)
4. [Interactive Menu Guide](#interactive-menu-guide)
5. [Variable Inheritance](#variable-inheritance)
6. [Activation History](#activation-history)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

---

## Overview

### 🎯 What is Cross-Chain Linking?

Cross-chain linking is an **automatic discovery system** that detects exploitation opportunities in command output and suggests related attack chains to pursue.

Instead of manually searching for the next step after finding a vulnerability, the system:
- ✓ **Analyzes command output** for interesting findings (SUID binaries, sudo entries, vulnerable services)
- ✓ **Suggests relevant chains** automatically (privilege escalation, exploitation, lateral movement)
- ✓ **Preserves context** by inheriting variables between chains
- ✓ **Prevents circular loops** (won't suggest chain A while inside chain A)

### 🏆 Why Was It Created?

**OSCP Efficiency Problem:**
```
Traditional Workflow (15+ minutes):
1. Run SUID enumeration → See 50 binaries
2. Manually research each binary → Search GTFOBins
3. Find exploitable one → Remember which chain to run
4. Start new chain → Manually enter same target/binary
5. Lose track of where you were → Confusion
```

**LINK Workflow (2 minutes):**
```
Automatic Workflow:
1. Run SUID enumeration → System detects 3 exploitable binaries
2. Menu appears instantly → "Switch to linux-privesc-suid-exploit?"
3. Press '1' → Chain launches with binary pre-filled
4. Complete exploit → Return to parent chain automatically
5. Continue enumeration → Context preserved
```

### ⚡ Key Benefits

| Feature | Traditional | With LINK |
|---------|-------------|-----------|
| **Discovery** | Manual search | Automatic detection |
| **Context** | Re-enter variables | Auto-inherited |
| **Time** | 10-15 minutes | 1-2 minutes |
| **Navigation** | Remember chain IDs | Menu-driven selection |
| **Safety** | Manual prevention | Circular detection |
| **History** | Paper notes | Automated tracking |

---

## How It Works

### 🔄 The Linking Process

```
┌──────────────────────────────────────────────────────────────────┐
│  1. Parent Chain Executes Command                                │
│     ↓                                                             │
│     find / -perm -4000 2>/dev/null                               │
│                                                                   │
│  2. Parser Analyzes Output                                       │
│     ↓                                                             │
│     SUIDParser identifies:                                       │
│     • /usr/bin/find (GTFOBins match)                            │
│     • /usr/bin/vim (GTFOBins match)                             │
│     • /usr/bin/base64 (GTFOBins match)                          │
│                                                                   │
│  3. Parser Emits Activations                                     │
│     ↓                                                             │
│     ChainActivation(                                             │
│       chain_id="linux-privesc-suid-exploit",                    │
│       reason="Found 3 GTFOBins-exploitable SUID binaries",      │
│       confidence="high",                                         │
│       variables={"<TARGET_BIN>": "/usr/bin/find"}               │
│     )                                                             │
│                                                                   │
│  4. Menu Appears                                                 │
│     ↓                                                             │
│     [1] linux-privesc-suid-exploit                              │
│         Found 3 GTFOBins-exploitable SUID binaries              │
│         Confidence: HIGH                                         │
│                                                                   │
│  5. User Selects Option                                          │
│     ↓                                                             │
│     Press '1' → Launch child chain                               │
│     Press 'c' → Continue current chain                           │
│     Press 'i' → Show more details                                │
│                                                                   │
│  6. Child Chain Launches                                         │
│     ↓                                                             │
│     Variables inherited:                                         │
│     • <TARGET> = 192.168.45.100 (from parent)                   │
│     • <TARGET_BIN> = /usr/bin/find (from activation)            │
│                                                                   │
│  7. Child Chain Completes                                        │
│     ↓                                                             │
│     Return to parent chain automatically                         │
│     Session restored to exact same state                         │
└──────────────────────────────────────────────────────────────────┘
```

### 🎨 Parser-Driven Activation

**Parsers are the "intelligence"** that triggers cross-chain linking.

Each parser analyzes command output and decides:
- **Should I suggest a chain?** (Is this finding significant enough?)
- **Which chain should I suggest?** (What's the next logical step?)
- **How confident am I?** (High = immediate action, Low = optional)
- **What variables should I pre-fill?** (Make it effortless)

**Example: SUID Parser Logic**
```python
def parse(self, output: str, step: Dict, command: str) -> ParsingResult:
    # Extract SUID binaries
    binaries = self._extract_suid_binaries(output)

    # Check against GTFOBins database
    exploitable = [b for b in binaries if self._is_gtfobins(b)]

    result = ParsingResult(...)

    # Suggest exploitation chain if we found something good
    if len(exploitable) >= 1:
        result.activates_chains.append(ChainActivation(
            chain_id="linux-privesc-suid-exploit",
            reason=f"Found {len(exploitable)} GTFOBins-exploitable SUID binaries",
            confidence="high",  # High confidence → strong suggestion
            variables={"<TARGET_BIN>": exploitable[0]}  # Pre-fill first binary
        ))

    return result
```

---

## User Workflows

### 🎯 Example 1: SUID Enumeration → Exploitation

**Scenario:** Running Linux privilege escalation enumeration

```bash
# Start enumeration chain
crack reference --chains linux-privesc-enum -i
```

**Output:**
```
════════════════════════════════════════════════════════════════════
Step 3 of 5: Find SUID Binaries
════════════════════════════════════════════════════════════════════

Objective: Enumerate all SUID binaries on system

Final command:
  find / -perm -4000 -type f 2>/dev/null

Run this command? (Y/n): y

Executing...

/usr/bin/sudo
/usr/bin/find
/usr/bin/vim
/usr/bin/base64
... (47 more binaries)

✓ Command completed successfully

Parsing Results:
  Total binaries: 50
  Exploitable: 3 (GTFOBins matches)
  Standard system: 47

════════════════════════════════════════════════════════════════════
Chain Activation Opportunities Detected
════════════════════════════════════════════════════════════════════

  [1] linux-privesc-suid-exploit
      Found 3 GTFOBins-exploitable SUID binaries
      Confidence: HIGH
      Variables: <TARGET_BIN>=/usr/bin/find

  [2] linux-privesc-capabilities
      Detected binaries with capabilities
      Confidence: MEDIUM

Options:
  [1-2] Switch to specific chain
  [c] Continue current chain
  [i] Show more info

Select option: 1

════════════════════════════════════════════════════════════════════
Launching Chain: linux-privesc-suid-exploit
════════════════════════════════════════════════════════════════════

Inherited 2 variable(s) from parent chain

════════════════════════════════════════════════════════════════════
Step 1 of 3: Exploit SUID Binary
════════════════════════════════════════════════════════════════════

Filling command variables...

[*] Auto-filled <TARGET> from session: 192.168.45.100
[*] Auto-filled <TARGET_BIN> from parent: /usr/bin/find

Final command:
  /usr/bin/find . -exec /bin/bash -p \; -quit

Run this command? (Y/n): y

bash-4.2# whoami
root

🎉 Root shell obtained!

════════════════════════════════════════════════════════════════════
Returned to Parent Chain
════════════════════════════════════════════════════════════════════

Mark complete and continue? (Y/n): y
```

### 🔑 Example 2: Sudo Enumeration → Privilege Escalation

**Scenario:** Found sudo NOPASSWD entries

```bash
# Running sudo enumeration
sudo -l

Output:
  User admin may run the following commands:
    (root) NOPASSWD: /usr/bin/vim

════════════════════════════════════════════════════════════════════
Chain Activation Opportunities Detected
════════════════════════════════════════════════════════════════════

  [1] linux-privesc-sudo-exploit
      Found 1 sudo NOPASSWD entry in GTFOBins
      Confidence: HIGH
      Variables: <SUDO_BIN>=/usr/bin/vim, <SUDO_USER>=root

Options:
  [1] Switch to exploitation chain
  [c] Continue enumeration
  [i] Show more info

Select option: 1

# Chain launches with variables pre-filled
# Exploit executes → Root shell
# Returns to enumeration automatically
```

### 🎲 Example 3: Multiple Activations → User Chooses

**Scenario:** Multiple exploitation paths available

```bash
# Parser detects multiple opportunities
nmap -sV -p- 192.168.45.100

════════════════════════════════════════════════════════════════════
Chain Activation Opportunities Detected
════════════════════════════════════════════════════════════════════

  [1] web-exploit-sql-injection
      Detected MySQL on port 3306
      Confidence: HIGH

  [2] smb-exploit-eternalblue
      SMB 1.0 detected (MS17-010 vulnerable)
      Confidence: HIGH

  [3] ssh-password-spray
      SSH on port 22 (common credentials)
      Confidence: MEDIUM

Options:
  [1-3] Switch to specific chain
  [c] Continue scan
  [i] Show more info

Select option: i

════════════════════════════════════════════════════════════════════
Activation Details
════════════════════════════════════════════════════════════════════

[1] web-exploit-sql-injection
    Reason: Detected MySQL on port 3306
    Confidence: high
    Variables:
      <TARGET_PORT> = 3306
      <DB_TYPE> = mysql

[2] smb-exploit-eternalblue
    Reason: SMB 1.0 detected (MS17-010 vulnerable)
    Confidence: high
    Variables:
      <TARGET_PORT> = 445
      <EXPLOIT_NAME> = MS17-010

[3] ssh-password-spray
    Reason: SSH on port 22 (common credentials)
    Confidence: medium
    Variables:
      <TARGET_PORT> = 22

Press any key to continue...

Options:
  [1-3] Switch to specific chain
  [c] Continue scan
  [i] Show more info

Select option: 2

# EternalBlue chain launches with port 445 pre-filled
```

---

## Interactive Menu Guide

### 🎮 Single-Keystroke Operations

**No Enter key needed!** Press number/letter and action executes immediately.

### Menu Options

```
Options:
  [1-3] Switch to specific chain   ← Press digit to launch
  [c]   Continue current chain     ← Press 'c' to ignore
  [i]   Show more info             ← Press 'i' for details
```

### Option Behaviors

| Key | Action | What Happens |
|-----|--------|--------------|
| **1-3** | Launch chain | Saves current session → Launches child chain with inherited variables → Returns when complete |
| **c** | Continue | Ignores activations → Proceeds to next step in current chain |
| **i** | Info | Shows full activation details (reason, confidence, variables) → Redisplays menu |

### 🎨 Color-Coded Confidence Levels

```
Confidence: HIGH      ← Green (strong recommendation)
Confidence: MEDIUM    ← Yellow (worth considering)
Confidence: LOW       ← Gray (optional/experimental)
```

**What confidence means:**

| Level | Meaning | Example |
|-------|---------|---------|
| **HIGH** | Very likely to succeed | GTFOBins match, known CVE |
| **MEDIUM** | Possible success | Weak indicator, requires testing |
| **LOW** | Experimental | Uncommon technique, low success rate |

### Menu Display Limit

**Maximum 3 activations shown** (prevents overwhelming choice)

If parser returns 10 activations → Top 3 by confidence displayed

Use **[i] Show more info** to see full list

---

## Variable Inheritance

### 🔄 How Variables Pass Between Chains

**Parent → Child Flow:**
```
Parent Chain Variables:
  <TARGET> = 192.168.45.100 (from session)
  <LHOST> = 10.10.14.5 (from config)
  <CUSTOM_VAR> = some_value (from user input)

Activation Variables:
  <TARGET_BIN> = /usr/bin/find (from parser)
  <EXPLOIT_TYPE> = gtfobins (from parser)

Child Chain Receives:
  <TARGET> = 192.168.45.100 (inherited)
  <LHOST> = 10.10.14.5 (inherited)
  <CUSTOM_VAR> = some_value (inherited)
  <TARGET_BIN> = /usr/bin/find (new)
  <EXPLOIT_TYPE> = gtfobins (new)
```

### Variable Priority

When child chain starts:
1. **Activation variables** (highest priority - parser's pre-fill)
2. **Parent session variables** (user inputs from parent)
3. **Config variables** (from `~/.crack/config.json`)
4. **Variable defaults** (from command definition)

### 🔍 Verifying Inherited Values

**Check during command fill:**
```
Filling command variables...

[*] Auto-filled <TARGET> from session: 192.168.45.100
[*] Auto-filled <TARGET_BIN> from parent: /usr/bin/find
[*] Auto-filled <LHOST> from config: 10.10.14.5

Need to fill 0 remaining variables

Final command:
  /usr/bin/find . -exec /bin/bash -p \; -quit
```

**Source indicators:**
- `from session` = Parent chain's session
- `from parent` = Activation variables
- `from config` = Config file
- `from default` = Variable definition

### Variables Return Flow

**Child → Parent:**
- ✓ Parent session **restored exactly** after child completes
- ✓ Parent variables **unchanged** (child doesn't modify parent)
- ✗ Child variables **do not** propagate back to parent

**Isolation principle:** Each chain maintains its own variable scope.

---

## Activation History

### 📊 Why History is Tracked

**Purpose:**
1. **OSCP Reporting** - Document exploitation path for report
2. **Troubleshooting** - Understand what was tried
3. **Learning** - Review decision-making process
4. **Circular Prevention** - Prevent infinite loops

### History Storage

**Location:** `~/.crack/chain_sessions/{chain_id}-{target}.json`

**Structure:**
```json
{
  "chain_id": "linux-privesc-enum",
  "target": "192.168.45.100",
  "activation_history": [
    ["linux-privesc-enum", "linux-privesc-suid-exploit"],
    ["linux-privesc-suid-exploit", "gtfobins-find-privesc"],
    ["linux-privesc-enum", "linux-privesc-capabilities"]
  ]
}
```

### Viewing History

**During session:**
```
# History shows in menu after activation
[*] Activation path: enum → suid → gtfobins → enum
```

**After session:**
```bash
cat ~/.crack/chain_sessions/linux-privesc-enum-192_168_45_100.json | jq '.activation_history'
```

### History Use Cases

**1. OSCP Report Documentation:**
```
Attack Path:
1. Started with linux-privesc-enum (initial reconnaissance)
2. Discovered SUID binaries → Activated linux-privesc-suid-exploit
3. Exploited /usr/bin/find → Obtained root shell
4. Returned to enumeration → Completed privilege escalation
```

**2. Troubleshooting:**
```
Why didn't it work?
→ Check history: Did I already try that chain?
→ Check history: Did circular prevention block it?
```

---

## Troubleshooting

### ⚠️ Common Issues

#### 1. "Circular activation prevented"

**Error:**
```
✗ Cannot activate: Circular activation prevented: linux-privesc-enum
  already active at depth 0 in stack ['linux-privesc-enum']
```

**Cause:** You're in chain A, and parser suggests activating chain A again.

**Why it happens:**
- Parser doesn't know it's running inside the chain it's suggesting
- Prevents infinite loop: A → A → A → ...

**Solution:**
```
Option 1: Press 'c' to continue current chain (ignore activation)
Option 2: Complete current chain → Return → Then activate manually
```

**Workaround example:**
```bash
# Inside linux-privesc-enum
# Parser suggests linux-privesc-enum (circular!)

Options:
  [1] linux-privesc-enum ← Would create loop
  [c] Continue current chain

Select option: c  # Continue → Complete → Start fresh after
```

#### 2. "No activations found"

**Scenario:** Expected activation menu, but none appeared.

**Possible reasons:**

| Reason | Solution |
|--------|----------|
| Parser confidence too low | Lower thresholds (dev setting) |
| Output didn't match parser patterns | Check command output manually |
| Parser not triggered | Verify `can_parse()` logic |
| No related chains exist | Create target chain first |

**Debug steps:**
```bash
# 1. Check parser triggered
cat ~/.crack/chain_sessions/{chain}-{target}.json | jq '.step_findings'

# 2. Check output was captured
cat ~/.crack/chain_sessions/{chain}-{target}.json | jq '.step_outputs'

# 3. Verify related chain exists
crack reference --chains | grep {expected-chain-id}
```

#### 3. Session Errors

**Error:** "Failed to load session"

**Causes:**
- Corrupted JSON file
- Permission issues
- Disk full

**Solution:**
```bash
# 1. Check session file
ls -lh ~/.crack/chain_sessions/

# 2. Validate JSON
jq . ~/.crack/chain_sessions/{chain}-{target}.json

# 3. Delete corrupted session (start fresh)
rm ~/.crack/chain_sessions/{chain}-{target}.json

# 4. Restart chain
crack reference --chains {chain-id} -i
```

#### 4. Variables Not Inherited

**Scenario:** Expected auto-fill, but prompted for variable.

**Check:**
```
Filling command variables...

[*] Auto-filled <TARGET> from session: 192.168.45.100
[ ] Need to fill <TARGET_BIN> manually  ← Not inherited!

Why?
→ Variable name mismatch in activation
→ Parser didn't populate activation.variables
→ Parent chain didn't have that variable
```

**Solution:**
```
Check parser code:
  variables={"<TARGET_BIN>": binary}  ← Must match exactly
             ^^^^^^^^^^^^^ Case-sensitive!
```

---

## Best Practices

### ✅ When to Accept Activations

**Accept (press 1-3) when:**
- ✓ Confidence is HIGH
- ✓ You're in enumeration phase (time to exploit)
- ✓ Activation saves manual work (variables pre-filled)
- ✓ You trust the parser's intelligence
- ✓ OSCP exam (maximize efficiency)

**Example:**
```
[1] linux-privesc-suid-exploit
    Found 3 GTFOBins-exploitable SUID binaries
    Confidence: HIGH

→ Press '1' immediately (likely successful)
```

### 🤔 When to Decline Activations

**Decline (press 'c') when:**
- ✗ Confidence is LOW/MEDIUM and you're exploring
- ✗ You want to complete current enumeration first
- ✗ You're learning and want manual control
- ✗ Circular prevention warning appeared

**Example:**
```
[1] ssh-password-spray
    SSH on port 22 (common credentials)
    Confidence: MEDIUM

→ Press 'c' (continue enum, try SSH later manually)
```

### 🎯 OSCP Time Savings

**LINK maximizes exam efficiency:**

| Task | Traditional Time | With LINK | Savings |
|------|------------------|-----------|---------|
| SUID discovery → exploitation | 15 min | 2 min | 13 min |
| Sudo enum → GTFOBins lookup | 10 min | 1 min | 9 min |
| Service enum → CVE research | 20 min | 3 min | 17 min |
| Multi-stage exploit chain | 30 min | 5 min | 25 min |

**Total potential savings per machine: 60+ minutes**

### 📝 Combining with Manual Enumeration

**LINK complements, doesn't replace:**

```
1. Start with chain (automated)
   ↓
2. LINK suggests opportunities
   ↓
3. Accept high-confidence activations
   ↓
4. Complete automated path
   ↓
5. Return to manual testing
   ↓
6. Use findings for custom exploits
```

**Example workflow:**
```bash
# 1. Auto-enumerate with LINK
crack reference --chains linux-privesc-enum -i
  → Accept SUID activation → Root shell (2 min)

# 2. Manual verification
sudo -l  # Check for additional sudo entries
getcap -r / 2>/dev/null  # Check capabilities
  → LINK didn't find these → Manual exploitation

# 3. Combine results in report
Document both automated and manual findings
```

### 🚀 Speed Run Tips

**Maximum efficiency:**

1. **Trust HIGH confidence** - Accept immediately
2. **Skip LOW confidence** - Manual later if needed
3. **Use 'i' sparingly** - Info wastes time
4. **Let chains complete** - Don't interrupt prematurely
5. **Note activation path** - Quick report generation

**OSCP exam strategy:**
```
First 30 minutes: Accept all HIGH confidence activations
Next 30 minutes: Try MEDIUM confidence if HIGH failed
Last hour: Manual exploitation if automated paths exhausted
```

---

## 📚 Related Documentation

- **Developer Guide:** [Adding Chain Activations](../parsing/README.md#adding-chain-activations-to-parsers)
- **Migration Guide:** [Upgrading to LINK](MIGRATION_GUIDE.md)
- **Parsers:** [Parser Architecture](../parsing/README.md)
- **Sessions:** [Session Management](../session_storage.py)

---

## 💡 Pro Tips

### 1. Screenshot Activation Menus
```
OSCP report evidence:
→ Screenshot shows automated discovery
→ Documents decision-making process
→ Proves enumeration methodology
```

### 2. Chain Stack Awareness
```
Current depth shown in menu:
  [*] Depth: 2 (enum → suid → ?)

→ Prevents getting lost in nested chains
→ Know when to return to parent
```

### 3. Variable Override
```
Activation pre-fills <TARGET_BIN> = /usr/bin/find

But you can override:
→ Manually enter different binary
→ Test alternative exploitation paths
```

### 4. Confidence Calibration
```
After exam/lab:
→ Review which activations succeeded
→ Note which confidence levels were accurate
→ Adjust trust accordingly
```

---

## 🎓 Learning Path

**Week 1: Observe**
- Accept all activations
- See what chains are suggested
- Learn parser patterns

**Week 2: Selective**
- Accept only HIGH confidence
- Manually verify MEDIUM
- Decline LOW

**Week 3: Mastery**
- Predict activations before menu appears
- Know which chains relate to which findings
- Optimize activation path

**Exam Day: Automatic**
- Trust system completely
- Accept without hesitation
- Focus on exploitation, not navigation

---

**Last Updated:** Phase 6 - Final Documentation
**Version:** 2.0 (Cross-Chain Linking Complete)
