# SMB Enumeration Reference Guide

## SMB Port Discovery

### Finding SMB Hosts
```bash
# Scan for SMB ports (139 NetBIOS, 445 SMB)
sudo nmap -p139,445 --open 192.168.229.0/24 -oG smb.txt

# Count hosts with SMB
sudo nmap -p445 --open 192.168.229.0/24 -oG - | grep -c "445/open"

# Extract IPs with SMB open
sudo nmap -p445 --open 192.168.229.0/24 -oG - | grep "445/open" | cut -d' ' -f2

# Get unique IPs with either port 139 or 445 open
sudo nmap -p139,445 --open 192.168.229.0/24 -oG - | grep -E "(139|445)/open" | cut -d' ' -f2 | sort -u

# Fast scan from target list
sudo nmap -sS -p445 -T4 -iL targets.txt -oG smb_scan.grep
```

### Key Nmap Flags for SMB
- `-p139,445` = Scan NetBIOS and SMB ports
- `--open` = Show only open ports
- `-oG` = Greppable output format
- `-sS` = SYN stealth scan (requires root)
- `-sV` = Version detection
- `-A` = Aggressive scan (OS detection, version, scripts)

## Nmap SMB Scripts (NSE)

### Common SMB Scripts
```bash
# List available SMB scripts
ls -1 /usr/share/nmap/scripts/smb*

# OS Discovery (requires SMBv1)
nmap -v -p139,445 --script smb-os-discovery 192.168.229.152

# Enumerate shares
nmap -p445 --script smb-enum-shares 192.168.229.0/24

# Enumerate users
nmap -p445 --script smb-enum-users 192.168.229.0/24

# Check vulnerabilities
nmap -p445 --script smb-vuln-* 192.168.229.149

# Multiple scripts
nmap -p139,445 --script "smb-enum*,smb-vuln*" -iL targets.txt

# Full SMB enumeration with aggressive scan
sudo nmap -sS -p445 -A --script smb-os-discovery -iL targets.txt
```

### Useful NSE Scripts
- `smb-os-discovery` = OS and domain info
- `smb-enum-shares` = List shares
- `smb-enum-users` = Enumerate users
- `smb-enum-domains` = Domain info
- `smb-enum-groups` = Group enumeration
- `smb-enum-sessions` = Active sessions
- `smb-security-mode` = Security settings
- `smb-vuln-ms17-010` = EternalBlue check
- `smb2-security-mode` = SMBv2 security
- `smb2-time` = Get system time

## enum4linux Usage

### Basic Syntax
```bash
enum4linux [options] target_ip
```

### Key Options
```bash
# All enumeration
enum4linux -a 192.168.229.13

# User enumeration
enum4linux -U 192.168.229.13

# Share enumeration
enum4linux -S 192.168.229.13

# Password policy
enum4linux -P 192.168.229.13

# Group enumeration
enum4linux -G 192.168.229.13

# With credentials
enum4linux -u student -p lab -a 192.168.229.152

# Verbose output
enum4linux -v -a 192.168.229.13
```

### Finding Specific Information
```bash
# Find user 'alfred'
for ip in $(cat targets.txt); do
    echo "=== $ip ===";
    enum4linux -U $ip 2>/dev/null | grep -i alfred;
done

# Find flags in share comments
for ip in $(cat targets.txt); do
    enum4linux -S $ip 2>/dev/null | grep -E "Flag:|OS{.*}";
done

# Extract share names with comments
enum4linux -S 192.168.229.13 | awk '/Disk/ {print $0}'
```

### enum4linux Flags Reference
- `-a` = All simple enumeration (U+S+G+P+r+o+n+i)
- `-U` = Get userlist
- `-M` = Get machine list
- `-S` = Get sharelist
- `-P` = Get password policy
- `-G` = Get group and member list
- `-d` = Be detailed/verbose
- `-u user` = Specify username
- `-p pass` = Specify password
- `-v` = Verbose output

## Alternative SMB Tools

### smbclient
```bash
# List shares (anonymous)
smbclient -L //192.168.229.13 -N

# List shares with credentials
smbclient -L //192.168.229.152 -U student%lab

# Connect to specific share
smbclient //192.168.229.13/files -N

# Batch mode to check multiple hosts
for ip in $(cat targets.txt); do
    echo "=== $ip ===";
    smbclient -L //$ip -N 2>&1 | grep -v "session setup failed";
done
```

### rpcclient
```bash
# Anonymous connection
rpcclient -U "" -N 192.168.229.149

# With credentials
rpcclient -U "student%lab" 192.168.229.152

# Enumerate users
rpcclient -U "" -N 192.168.229.149 -c "enumdomusers"

# Get user info
rpcclient -U "" -N 192.168.229.149 -c "queryuser alfred"

# Multiple commands
rpcclient -U "" -N 192.168.229.149 -c "enumdomusers;enumdomgroups"
```

### nbtscan
```bash
# Scan subnet for NetBIOS names
sudo nbtscan -r 192.168.229.0/24

# Verbose output
sudo nbtscan -v 192.168.229.0/24

# Specific host
nbtscan 192.168.229.13
```

## Text Processing & Automation

### Grep Patterns
```bash
# Find flags
grep -E "Flag:|OS{[^}]+}"

# Case insensitive search
grep -i "alfred\|comment"

# Show context
grep -B2 -A2 "pattern"

# Extract only matches
grep -oE "pattern"
```

### Loops for Multiple Targets
```bash
# Basic for loop
for ip in $(cat targets.txt); do
    enum4linux -S $ip 2>/dev/null
done

# While read loop
while read ip; do
    echo "Scanning $ip";
    enum4linux -U $ip;
done < targets.txt

# Parallel with xargs
cat targets.txt | xargs -P5 -I{} enum4linux -S {} 2>/dev/null
```

### Output Redirection
```bash
# Save to file
enum4linux -a 192.168.229.13 > output.txt

# Append to file
enum4linux -a 192.168.229.13 >> output.txt

# Save and display
enum4linux -a 192.168.229.13 | tee output.txt

# Error redirection
enum4linux -a 192.168.229.13 2>/dev/null

# Both stdout and stderr
enum4linux -a 192.168.229.13 2>&1 | tee full_output.txt
```

## Practical Examples

### Find Host with Specific User
```bash
#!/bin/bash
# Find host with user 'alfred' and get flag

TARGET_USER="alfred"

for ip in $(cat targets.txt); do
    echo "Checking $ip for user $TARGET_USER..."

    # Check for user
    if enum4linux -U $ip 2>/dev/null | grep -qi "$TARGET_USER"; then
        echo "[+] Found $TARGET_USER on $ip"
        echo "[*] Enumerating shares..."

        # Get share comments
        enum4linux -S $ip 2>/dev/null | grep -i comment

        # Look for flags
        enum4linux -S $ip 2>/dev/null | grep -E "Flag:|OS{"
    fi
done
```

### Extract All Flags
```bash
# Method 1: Direct grep
for ip in $(cat targets.txt); do
    result=$(enum4linux -S $ip 2>/dev/null | grep -oE "Flag:.*OS{[^}]+}")
    [ ! -z "$result" ] && echo "$ip: $result"
done

# Method 2: Parse share table
for ip in $(cat targets.txt); do
    enum4linux -S $ip 2>/dev/null | \
    awk -v ip=$ip '/Disk.*Flag:/ {print ip": "$0}'
done
```

### Parallel SMB Scanning
```bash
# GNU Parallel
parallel -j 10 --bar 'enum4linux -S {} 2>/dev/null | grep -E "Flag|alfred"' :::: targets.txt

# xargs parallel
cat targets.txt | xargs -P5 -I{} sh -c 'echo "=== {} ==="; enum4linux -S {}'
```

## OSCP Lab SMB Enumeration Workflow

### 1. Discovery Phase
```bash
# Find all SMB hosts
sudo nmap -p445 --open 192.168.229.0/24 -oG - | grep "445/open" | cut -d' ' -f2 > smb_hosts.txt

# Quick count
wc -l smb_hosts.txt
```

### 2. Initial Enumeration
```bash
# OS and version detection
sudo nmap -p445 -sV --script smb-os-discovery -iL smb_hosts.txt -oA smb_initial

# Quick share enumeration
for ip in $(cat smb_hosts.txt); do
    echo "=== $ip ===";
    smbclient -L //$ip -N 2>&1 | grep -E "Disk|comment";
done
```

### 3. Deep Enumeration
```bash
# Full enum4linux on interesting targets
for ip in $(cat smb_hosts.txt); do
    enum4linux -a $ip > enum_${ip}.txt 2>&1 &
done

# Wait for completion
wait
```

### 4. Search for Specific Info
```bash
# Find all users
grep -h "user:" enum_*.txt | sort -u

# Find all shares
grep -h "Disk" enum_*.txt | sort -u

# Find flags or interesting comments
grep -hE "Flag:|password|admin" enum_*.txt
```

## Quick Reference Commands

```bash
# Count SMB hosts
sudo nmap -p445 --open 192.168.229.0/24 -oG - | grep -c "445/open"

# List SMB hosts
sudo nmap -p445 --open 192.168.229.0/24 -oG - | grep "445/open" | cut -d' ' -f2

# Quick anonymous share check
smbclient -L //192.168.229.13 -N

# Find specific user
enum4linux -U 192.168.229.13 | grep -i alfred

# Get share comments
enum4linux -S 192.168.229.13 | grep -i comment

# Check SMB signing
nmap -p445 --script smb-security-mode 192.168.229.149

# Test null session
rpcclient -U "" -N 192.168.229.149 -c "getusername;quit"

# Find writable shares
smbmap -H 192.168.229.13

# Mount share
sudo mount -t cifs //192.168.229.13/files /mnt/smb -o username=guest,password=
```

## Common SMB Ports
- **139/tcp** = NetBIOS Session Service
- **445/tcp** = Microsoft-DS (SMB over TCP)
- **137/udp** = NetBIOS Name Service
- **138/udp** = NetBIOS Datagram Service

## Security Notes
- SMBv1 is vulnerable and deprecated but common in labs
- Null sessions (anonymous access) often allowed in CTFs
- Message signing may be disabled allowing relay attacks
- Always check for common vulns: MS17-010, MS08-067

---
*Generated during OSCP SMB enumeration practice*