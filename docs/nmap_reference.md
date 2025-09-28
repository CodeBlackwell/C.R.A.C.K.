# Nmap & Network Scanning Reference Guide

## Host Discovery & Network Sweeping

### Fast Ping Sweep with Clean Output
```bash
sudo nmap -sn -T5 192.168.229.0-154 -oG - | grep "Up" | cut -d' ' -f2
```
- `-sn` = Ping scan (no port scan, just host discovery)
- `-T5` = Insane timing template (fastest, aggressive)
- `-oG -` = Greppable output to stdout (dash means stdout)
- `grep "Up"` = Filter only live hosts
- `cut -d' ' -f2` = Extract just the IP address

## Port Scanning Techniques

### SYN Stealth Scan (Default with sudo)
```bash
sudo nmap -sS -p50000-60000 -T5 -Pn -iL targets.txt -oG output.grep
```
- `-sS` = SYN scan (half-open, doesn't complete TCP handshake)
- `-p50000-60000` = Port range specification
- `-Pn` = Skip host discovery (treat all hosts as online)
- `-iL targets.txt` = Input from list file
- `-oG output.grep` = Save in greppable format

### TCP Connect Scan (No sudo required)
```bash
nmap -sT -p50000-60000 -Pn 192.168.229.149
```
- `-sT` = TCP connect scan (full three-way handshake)
- Used when SYN scan not available (no root privileges)

### Service Version Detection
```bash
sudo nmap -sV -p50000-60000 -T5 -Pn -iL targets.txt
```
- `-sV` = Probe open ports for service/version info
- Sends protocol-specific probes to identify services

### UDP Scanning
```bash
sudo nmap -sU -p161,500 192.168.229.0/24
```
- `-sU` = UDP scan (slower than TCP)
- Good for finding SNMP (161), IPSec (500), DNS (53)

### Combined TCP & UDP
```bash
sudo nmap -sS -sU -p T:80,443,U:161,53 192.168.229.149
```
- `T:` = TCP ports
- `U:` = UDP ports

## NSE (Nmap Scripting Engine)

### HTTP Title Enumeration
```bash
sudo nmap -p80,443,8080 --script http-title -iL targets.txt
```
- `--script http-title` = Fetch and display HTML page titles
- Useful for identifying web application purposes

### Script Help
```bash
nmap --script-help http-headers
```
- View documentation for any NSE script

## Output Processing & Grep Commands

### Extract IPs with Open Ports
```bash
grep "open" scan.grep | cut -d' ' -f2 | sort -u
```
- `sort -u` = Sort and remove duplicates

### Find Unique Open Ports
```bash
grep -oE "[0-9]+/open" file.grep | cut -d'/' -f1 | sort -nu
```
- `grep -oE` = Only output matches, extended regex
- `[0-9]+` = One or more digits
- `sort -nu` = Numerical sort, unique only

### Count Port Occurrences
```bash
grep -oE "[0-9]+/filtered" file.grep | cut -d'/' -f1 | sort | uniq -c | sort -rn
```
- `uniq -c` = Count consecutive identical lines
- `sort -rn` = Reverse numerical sort (highest count first)

### Search with Context
```bash
grep -B2 -A2 -i "pattern" file
```
- `-B2` = Show 2 lines Before match
- `-A2` = Show 2 lines After match
- `-i` = Case-insensitive search

## Parallel Scanning Techniques

### GNU Parallel
```bash
parallel -j 10 --bar 'sudo nmap -sS -p50000-60000 {} -oG {}_scan.grep' :::: targets.txt
```
- `-j 10` = Run 10 parallel jobs
- `--bar` = Show progress bar
- `{}` = Placeholder for input
- `::::` = Read input from file

### xargs Parallel Execution
```bash
cat targets.txt | xargs -P5 -I{} sudo nmap -sS -p80 {} -oG {}_web.grep
```
- `-P5` = 5 parallel processes
- `-I{}` = Replace {} with each input line

### Check System Capacity
```bash
nproc  # Show number of CPU cores
```

## Web Enumeration

### Curl for HTML Titles
```bash
curl -s http://192.168.229.6/ | grep -oP '(?<=<title>).*(?=</title>)'
```
- `curl -s` = Silent mode (no progress bar)
- `grep -oP` = Only match output, Perl regex
- `(?<=<title>)` = Positive lookbehind
- `(?=</title>)` = Positive lookahead

### Parallel Web Title Check
```bash
cat targets.txt | xargs -P5 -I{} sh -c 'echo -n "{}: "; curl -s -m2 http://{}/ | grep -oP "(?<=<title>).*(?=</title>)" || echo "No title"'
```
- `-m2` = 2 second timeout for curl

### Raw HTTP with Netcat
```bash
echo -e "GET / HTTP/1.0\r\n\r\n" | nc 192.168.229.6 80
```
- `echo -e` = Enable escape sequences
- `\r\n\r\n` = HTTP request terminator

## AWK Pattern Matching

### Extract IP with Specific Content
```bash
awk '/Nmap scan report/{ip=$5} /Under Construction/{print ip}' scan_output.txt
```
- First pattern captures IP address
- Second pattern triggers print when found

### Process Nmap Output
```bash
awk '/Host:/{ip=$2} /open/{print ip " has open ports"}' scan.grep
```

## Important Nmap Flags Reference

### Scan Types
- `-sS` = SYN scan (stealth, requires root)
- `-sT` = TCP connect scan (no root needed)
- `-sU` = UDP scan
- `-sA` = ACK scan (firewall rule mapping)
- `-sV` = Version detection
- `-sn` = Ping scan only (no ports)
- `-Pn` = No ping (skip discovery)

### Port Specification
- `-p80` = Single port
- `-p80,443` = Multiple ports
- `-p80-443` = Port range
- `-p-` = All 65535 ports
- `--top-ports 20` = 20 most common ports
- `-F` = Fast scan (100 common ports)

### Timing Templates
- `-T0` = Paranoid (IDS evasion)
- `-T1` = Sneaky (IDS evasion)
- `-T2` = Polite (less bandwidth)
- `-T3` = Normal (default)
- `-T4` = Aggressive (fast)
- `-T5` = Insane (very fast, may miss ports)

### Output Formats
- `-oN file` = Normal output
- `-oG file` = Greppable output
- `-oX file` = XML output
- `-oA basename` = All formats
- `-oG -` = Output to stdout

### Performance Tuning
- `--min-rate 1000` = Minimum 1000 packets/second
- `--max-rate 100` = Maximum 100 packets/second
- `--max-retries 2` = Limit retransmissions
- `--host-timeout 30m` = Give up on host after 30 minutes

### Verbosity & Debugging
- `-v` = Verbose output
- `-vv` = Very verbose
- `-d` = Debug output
- `--reason` = Show reason for port state
- `--packet-trace` = Show packets sent/received

### OS & Service Detection
- `-O` = OS fingerprinting
- `-A` = Aggressive (OS, version, scripts, traceroute)
- `--osscan-guess` = Guess OS when not certain

### NSE Script Categories
- `--script default` = Default scripts (safe)
- `--script vuln` = Vulnerability scripts
- `--script discovery` = Discovery scripts
- `--script auth` = Authentication scripts

## Common Port Numbers
- 21 = FTP
- 22 = SSH
- 23 = Telnet
- 25 = SMTP
- 53 = DNS
- 80 = HTTP
- 110 = POP3
- 135 = MS-RPC
- 139 = NetBIOS
- 143 = IMAP
- 443 = HTTPS
- 445 = SMB
- 1433 = MSSQL
- 3306 = MySQL
- 3389 = RDP
- 5432 = PostgreSQL
- 5900 = VNC
- 8080 = HTTP-Alt
- 8443 = HTTPS-Alt

## OSCP Lab Specific Tips

1. **Always save your scans**: Use `-oA` to save in all formats
2. **Start broad, go narrow**: Network sweep → Top ports → Full scan
3. **Document everything**: Keep notes on which hosts have which services
4. **Use appropriate timing**: `-T4` for most scans, `-T5` for quick discovery
5. **Check both TCP and UDP**: Some services only listen on UDP
6. **Verify with multiple tools**: Don't rely on nmap alone
7. **Watch for IDS/IPS**: If getting blocked, slow down with `-T2`

## Quick Reference Command Chains

### Full TCP Scan Pipeline
```bash
# 1. Discovery
sudo nmap -sn -T4 192.168.229.0/24 -oG - | grep "Up" | cut -d' ' -f2 > targets.txt

# 2. Top ports
sudo nmap -sS --top-ports 100 -T4 -iL targets.txt -oA top100

# 3. Full scan interesting hosts
sudo nmap -sS -p- -T4 192.168.229.149 -oA full_scan

# 4. Service detection on open ports
sudo nmap -sV -sC -p80,443,445 192.168.229.149 -oA service_scan
```

### Quick Web Discovery
```bash
# Find all web servers
sudo nmap -p80,443,8080,8443 192.168.229.0/24 --open -oG - | grep "open"

# Get all titles
sudo nmap -p80,443,8080 --script http-title 192.168.229.0/24 --open
```

---
*Generated during OSCP preparation - $(date)*