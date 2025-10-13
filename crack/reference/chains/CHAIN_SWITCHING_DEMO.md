# Chain Switching - User Experience Demo

## Scenario: Linux Privilege Escalation Discovery

User runs the initial enumeration chain and discovers exploitable sudo entries. The system automatically detects this and offers to switch to the specialized sudo exploitation chain.

---

## Step 1: Initial Chain Execution

```
======================================================================
Linux Privilege Escalation Enumeration
======================================================================
Target: 192.168.45.100
Steps: 3
Difficulty: Easy
Time Estimate: 5-10 minutes
OSCP Relevant: Yes

Initial reconnaissance to identify privilege escalation vectors.
======================================================================

======================================================================
Step 1 of 3: Check Sudo Permissions
======================================================================

Objective: List all commands current user can run with sudo

Command Reference: linux-enum-sudo

Filling command variables...

[*] Command: Check sudo permissions
[*] Template: sudo -l
[*] Auto-filled <TARGET> from session: .

[+] Final command: sudo -l

Final command:
  sudo -l


Executing...

Matching Defaults entries for user on victim:
    env_reset, mail_badpass

User user may run the following commands on victim:
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/find
    (root) /usr/bin/systemctl

✓ Command completed successfully

──────────────────────────────────────────────────────────────────────
Parsing Results:

Parser: sudo-parser
Findings:
  • Total entries: 3
  • NOPASSWD entries: 2
  • GTFOBins matches: 2 (vim, find)
  • Exploitable: vim, find

Variables extracted:
  • <SUDO_COMMAND> = /usr/bin/vim
  • <BINARY> = vim
```

---

## Step 2: Activation Menu Appears

```
══════════════════════════════════════════════════════════════════════
Chain Activation Opportunities Detected
══════════════════════════════════════════════════════════════════════

  [1] linux-privesc-sudo
      Found 2 GTFOBins-exploitable NOPASSWD sudo entries (vim, find)
      Confidence: HIGH
      Variables: <BINARY>=vim, <SUDO_COMMAND>=/usr/bin/vim

Options:
  [1] Switch to specific chain
  [c] Continue current chain
  [i] Show more info

Select option: █
```

---

## Step 3a: User Presses `[1]` - Switch to Sudo Chain

```
Select option: 1

Current session saved

══════════════════════════════════════════════════════════════════════
Launching Chain: linux-privesc-sudo
══════════════════════════════════════════════════════════════════════

Inherited 3 variable(s) from parent chain

======================================================================
Linux Privilege Escalation - Sudo Exploitation
======================================================================
Target: 192.168.45.100
Steps: 2
Difficulty: Easy
Time Estimate: 2-5 minutes
OSCP Relevant: Yes

Exploit GTFOBins-listed binaries allowed via NOPASSWD sudo.

Prerequisites:
  • GTFOBins-exploitable binary identified
  • NOPASSWD sudo access confirmed

Notes:
  Always check GTFOBins (https://gtfobins.github.io/) for the latest
  techniques. Focus on file read, command execution, and shell escape
  vectors.
======================================================================

======================================================================
Step 1 of 2: Verify Sudo Access
======================================================================

Objective: Confirm NOPASSWD access to target binary

Command Reference: linux-privesc-sudo-verify

Filling command variables...

[*] Command: Verify sudo access
[*] Template: sudo -l | grep <BINARY>
[*] Auto-filled <TARGET> from session: .
[*] Auto-filled <BINARY> from parent chain: vim

[+] Final command: sudo -l | grep vim

Final command:
  sudo -l | grep vim


Run this command? (Y/n): y

Executing...

    (root) NOPASSWD: /usr/bin/vim

✓ Command completed successfully

... [sudo chain continues] ...

══════════════════════════════════════════════════════════════════════
Returned to Parent Chain
══════════════════════════════════════════════════════════════════════

Mark complete and continue? (Y/n): y
Progress saved.

======================================================================
Step 2 of 3: Check SUID Binaries
======================================================================

... [parent chain resumes from where it left off] ...
```

---

## Step 3b: User Presses `[i]` - View Detailed Info

```
Select option: i

══════════════════════════════════════════════════════════════════════
Activation Details
══════════════════════════════════════════════════════════════════════

[1] linux-privesc-sudo
    Reason: Found 2 GTFOBins-exploitable NOPASSWD sudo entries (vim, find)
    Confidence: high
    Variables:
      <BINARY> = vim
      <SUDO_COMMAND> = /usr/bin/vim

Press any key to continue...

[User presses any key, returns to activation menu]

══════════════════════════════════════════════════════════════════════
Chain Activation Opportunities Detected
══════════════════════════════════════════════════════════════════════

  [1] linux-privesc-sudo
      Found 2 GTFOBins-exploitable NOPASSWD sudo entries (vim, find)
      Confidence: HIGH
      Variables: <BINARY>=vim, <SUDO_COMMAND>=/usr/bin/vim

Options:
  [1] Switch to specific chain
  [c] Continue current chain
  [i] Show more info

Select option: █
```

---

## Step 3c: User Presses `[c]` - Continue Current Chain

```
Select option: c

Mark complete and continue? (Y/n): y
Progress saved.

======================================================================
Step 2 of 3: Check SUID Binaries
======================================================================

Objective: Identify SUID binaries with escalation potential

... [enumeration continues without switching] ...
```

---

## Step 4: Circular Prevention

**Scenario:** Chain A detects something that would activate Chain B, which would activate Chain A again.

```
══════════════════════════════════════════════════════════════════════
Chain Activation Opportunities Detected
══════════════════════════════════════════════════════════════════════

  [1] linux-privesc-enum
      Found new escalation vectors
      Confidence: MEDIUM

Options:
  [1] Switch to specific chain
  [c] Continue current chain
  [i] Show more info

Select option: 1

✗ Cannot activate: Circular activation prevented: linux-privesc-enum
  already active at depth 0 in stack ['linux-privesc-enum']

[Returns to prompt, user can continue current chain]
```

---

## Step 5: Multiple Activations

**Scenario:** Parser detects multiple related chains.

```
══════════════════════════════════════════════════════════════════════
Chain Activation Opportunities Detected
══════════════════════════════════════════════════════════════════════

  [1] linux-privesc-sudo
      Found 2 GTFOBins-exploitable NOPASSWD sudo entries
      Confidence: HIGH
      Variables: <BINARY>=vim

  [2] linux-privesc-suid-basic
      Found 1 exploitable SUID binary (find)
      Confidence: MEDIUM
      Variables: <BINARY>=find

  [3] linux-capabilities
      Found 1 capability-based exploit
      Confidence: LOW

Options:
  [1-3] Switch to specific chain
  [c] Continue current chain
  [i] Show more info

Select option: 2

Current session saved

══════════════════════════════════════════════════════════════════════
Launching Chain: linux-privesc-suid-basic
══════════════════════════════════════════════════════════════════════

Inherited 2 variable(s) from parent chain

... [SUID exploitation chain begins] ...
```

---

## Key UX Features

### Single-Keystroke Operation
- **No Enter Required:** Press `1`, `2`, `3`, `c`, or `i` - immediate action
- **Echo Feedback:** Key is echoed so user sees what they pressed
- **Consistent Pattern:** Matches track module TUI for familiar experience

### Color Coding
- **HIGH Confidence:** Green text (urgent/reliable)
- **MEDIUM Confidence:** Yellow text (promising)
- **LOW Confidence:** Dim text (speculative)
- **Chain Names:** Cyan bold (primary action)
- **Prompts:** Yellow (attention)
- **Success:** Green (completed actions)
- **Errors:** Red (blocked actions)

### Context Preservation
- **Session Saved:** Current progress always saved before switching
- **Variables Inherited:** Child chain gets parent's discoveries
- **Return to Checkpoint:** Parent resumes exactly where it paused
- **Activation History:** Full chain path tracked for reporting

### Error Handling
- **Circular Prevention:** Clear message why activation blocked
- **Keyboard Interrupt:** Graceful return to parent on Ctrl+C
- **Missing Chains:** Warning if target chain doesn't exist
- **Session Corruption:** Fallback to fresh session with warning

### Information Hierarchy
- **Quick View:** Top 3 most relevant activations
- **Detailed View:** Press `[i]` to see full list and all variables
- **Recursive Navigation:** Can return to activation menu after viewing details

---

## Typical Workflows

### Workflow 1: Quick Exploitation
```
Enum Chain → Finds Sudo → Press [1] → Exploit Sudo → Get Root → Done
```

### Workflow 2: Methodical Enumeration
```
Enum Chain → Finds Sudo → Press [c] → Continue Enum → Finds SUID → Press [1] → Try SUID → Fail → Return → Continue
```

### Workflow 3: Multi-Vector Testing
```
Enum Chain → Finds 3 Vectors → Press [1] → Try Sudo → Fail → Return → Press [2] → Try SUID → Success → Root
```

### Workflow 4: Information Gathering
```
Enum Chain → Finds Vectors → Press [i] → Review All → Press [c] → Manual Notes → Complete Enum → Analyze
```

---

## Developer Notes

### Adding Activation to New Parser

```python
# In your parser's parse() method
if self._has_exploitable_finding(output):
    activation = ChainActivation(
        chain_id='target-chain-id',
        reason='Brief explanation visible in menu',
        confidence='high',  # high|medium|low
        variables={'<VAR>': 'value'}
    )
    result.activates_chains.append(activation)
```

### Testing Activation Flow

```python
# Mock activation in test
activation = ChainActivation(
    chain_id='test-chain',
    reason='Test activation',
    confidence='high'
)

# Mock user input
with patch.object(chain, '_read_single_key', return_value='1'):
    chain._handle_chain_activations([activation])
```

---

## Session File Example

**Parent Chain Session:** `~/.crack/sessions/linux-privesc-enum-.json`
```json
{
  "chain_id": "linux-privesc-enum",
  "target": ".",
  "current_step_index": 0,
  "variables": {
    "<TARGET>": ".",
    "<BINARY>": "vim",
    "<SUDO_COMMAND>": "/usr/bin/vim"
  },
  "completed_steps": [],
  "step_outputs": {},
  "created_at": "2025-10-13T10:30:00",
  "updated_at": "2025-10-13T10:32:15"
}
```

**Child Chain Session:** `~/.crack/sessions/linux-privesc-sudo-.json`
```json
{
  "chain_id": "linux-privesc-sudo",
  "target": ".",
  "current_step_index": 0,
  "variables": {
    "<TARGET>": ".",
    "<BINARY>": "vim",
    "<SUDO_COMMAND>": "/usr/bin/vim"
  },
  "completed_steps": [],
  "step_outputs": {},
  "created_at": "2025-10-13T10:32:20",
  "updated_at": "2025-10-13T10:32:20"
}
```

**Note:** Child inherits parent's variables at creation time.
