# CRACK Usage Guide

Comprehensive guide to using CRACK for penetration testing workflows.

## CLI Quick Reference

### Reconnaissance

```bash
# Port scanning (two-stage: fast discovery + detailed scan)
crack port-scan 10.10.10.100
crack port-scan 10.10.10.100 --top-ports 1000

# Service enumeration with CVE lookup
crack enum-scan 10.10.10.100

# Web enumeration
crack html-enum http://10.10.10.100
crack html-enum http://10.10.10.100 --depth 2
```

### Command Reference

```bash
# Search for commands
crack reference nmap
crack reference "lateral movement"
crack reference kerberos --category active-directory

# Get specific command details
crack reference get nmap-service-scan

# Validate command database
crack reference --validate
crack reference --stats
```

### Cheatsheets

```bash
# Browse available cheatsheets
crack cheatsheets

# View specific cheatsheet
crack cheatsheets linux-privesc
crack cheatsheets ad-kerberoasting

# List all cheatsheet topics
crack cheatsheets --list
```

### Active Directory (BloodTrail)

```bash
# Launch BloodTrail analyzer
crack bloodtrail

# Analyze BloodHound data
crack bloodtrail analyze

# Show attack paths
crack bloodtrail paths --target "Domain Admins"
```

### Post-Exploitation

```bash
# Parse mimikatz output
crack prism mimikatz.txt

# Parse nmap output
crack prism scan.xml --type nmap

# Session management
crack session list
crack session start --type reverse
```

### Configuration

```bash
# List configured variables
crack config list

# Set a variable
crack config set LHOST 10.10.14.5
crack config set TARGET 10.10.10.100

# Auto-detect network settings
crack config auto

# Show current config
crack config show
```

---

## Common Workflows

### 1. Initial Reconnaissance

```bash
# Step 1: Configure target
crack config set TARGET 10.10.10.100

# Step 2: Port scan
crack port-scan $TARGET

# Step 3: Service enumeration
crack enum-scan $TARGET

# Step 4: Look up service-specific commands
crack reference smb
crack reference http enumeration
```

### 2. Web Application Testing

```bash
# Step 1: HTML enumeration
crack html-enum http://10.10.10.100

# Step 2: Parameter discovery
crack reference "parameter fuzzing"

# Step 3: SQLi detection
crack sqli-scan http://10.10.10.100/login.php

# Step 4: Get SQLi cheatsheet
crack cheatsheets sql-injection
```

### 3. Active Directory Attack

```bash
# Step 1: Get AD attack methodology
crack cheatsheets ad-initial-reconnaissance

# Step 2: Look up Kerberos commands
crack reference kerberoasting
crack reference asreproast

# Step 3: Launch BloodTrail for path analysis
crack bloodtrail analyze

# Step 4: Get lateral movement commands
crack reference "pass the hash"
crack reference psexec
```

### 4. Linux Privilege Escalation

```bash
# Step 1: Get privesc cheatsheet
crack cheatsheets linux-privesc

# Step 2: Search for specific techniques
crack reference suid
crack reference capabilities
crack reference sudo

# Step 3: Look up GTFOBins commands
crack reference gtfobins
```

### 5. Windows Privilege Escalation

```bash
# Step 1: Get Windows privesc cheatsheet
crack cheatsheets windows-privesc

# Step 2: Search for techniques
crack reference "service hijacking"
crack reference "token impersonation"
crack reference "always install elevated"
```

---

## GUI Applications

### Crackpedia (Command Encyclopedia)

Launch:
```bash
crackpedia
# or
just crackpedia-dev  # Development mode with hot reload
```

Features:
- **Search**: Find commands by keyword, category, or tags
- **Graph View**: Visualize command relationships and attack paths
- **Command Details**: Full syntax, flags, examples, and alternatives
- **Attack Chains**: Step-by-step workflows for common attacks
- **Cheatsheets**: Educational reference materials

Keyboard Shortcuts:
- `Ctrl+K` or `/`: Focus search
- `Ctrl+G`: Toggle graph view
- `Escape`: Close panels
- Arrow keys: Navigate results

### B.R.E.A.C.H. (Pentesting Workspace)

Launch:
```bash
crack-breach
# or
cd breach && ./start.sh
```

Features:
- **Terminal Multiplexer**: Multiple terminal sessions with tabs
- **Engagement Tracking**: Manage targets, findings, credentials
- **Credential Vault**: Store and quickly use discovered credentials
- **Loot Panel**: Track captured flags, SSH keys, configs
- **Target Sidebar**: Visual status of engagement machines

Tips:
- Use `Ctrl+T` to create new terminal tab
- Right-click terminals for context menu
- Drag tabs to reorder
- Double-click target to filter commands

---

## Configuration

### Environment Variables

Set in `~/.bashrc`, `~/.zshrc`, or use `crack config`:

```bash
# Required for graph features
export NEO4J_URI='bolt://localhost:7687'
export NEO4J_USER='neo4j'
export NEO4J_PASSWORD='your_password'

# Optional
export CRACK_CONFIG_DIR='~/.crack'
export CRACK_ROUTER_BACKEND='auto'  # auto, neo4j, sql, json
```

### User Configuration

Configuration stored in `~/.crack/config.json`:

```json
{
  "variables": {
    "LHOST": "10.10.14.5",
    "TARGET": "10.10.10.100",
    "DOMAIN": "corp.local"
  },
  "preferences": {
    "theme": "dark",
    "verbose": false
  }
}
```

### Variable Placeholders

Commands use placeholders like `<TARGET>`, `<LHOST>`, etc. Set them with:

```bash
# Set individual variables
crack config set TARGET 10.10.10.100
crack config set LHOST 10.10.14.5
crack config set LPORT 4444

# Auto-detect network settings
crack config auto
```

Common variables:
| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET` | Target IP/hostname | `10.10.10.100` |
| `LHOST` | Your IP (for reverse shells) | `10.10.14.5` |
| `LPORT` | Listener port | `4444` |
| `DOMAIN` | AD domain name | `corp.local` |
| `USER` | Username | `administrator` |
| `PASS` | Password | `P@ssw0rd` |
| `HASH` | NTLM hash | `aad3b435...` |

---

## Engagement Tracking

CRACK tracks targets, findings, and credentials for each engagement.

### CLI Commands

```bash
# Create engagement
crack engagement create "Lab Pentest"

# List engagements
crack engagement list

# Activate engagement
crack engagement activate eng-001

# Add target
crack target add 10.10.10.100 --hostname dc01

# Add finding
crack finding add "SQL Injection" --severity high

# Add credential
crack credential add administrator password "P@ssw0rd"
```

### Neo4j Graph

With Neo4j running, engagements are stored as a graph:

```
(:Engagement)─[:TARGETS]→(:Target)─[:HAS_SERVICE]→(:Service)
      │
      ├─[:HAS_CREDENTIAL]→(:Credential)
      ├─[:HAS_FINDING]→(:Finding)
      └─[:HAS_LOOT]→(:Loot)
```

Query in Neo4j Browser:
```cypher
MATCH (e:Engagement)-[:TARGETS]->(t:Target)
RETURN e, t
```

---

## Tips & Best Practices

### 1. Use Config Variables

Instead of typing IPs repeatedly:
```bash
crack config set TARGET 10.10.10.100
crack port-scan $TARGET
crack html-enum http://$TARGET
```

### 2. Explore Cheatsheets First

Before attacking, review methodology:
```bash
crack cheatsheets ad-initial-reconnaissance
crack cheatsheets linux-privesc
```

### 3. Document with Engagement Tracking

Record everything:
```bash
crack target add 10.10.10.100 --hostname dc01 --os "Windows Server 2019"
crack finding add "Anonymous FTP" --severity medium --target t-001
```

### 4. Use MCP with Claude Code

For AI-assisted pentesting:
```bash
just mcp-config  # Get Claude configuration
```

Then in Claude Code, search commands naturally:
> "Find commands for Kerberos lateral movement"

### 5. Check Command Alternatives

Most commands have alternatives:
```bash
crack reference get nmap-service-scan
# Shows: alternatives: ["masscan-fast", "rustscan-quick"]
```

### 6. Validate Before Engagement

Ensure your setup works:
```bash
just verify
just info
```

---

## Integration with Other Tools

### With tmux

```bash
# Create pentesting session
tmux new-session -s pentest

# Split panes for different tasks
# Pane 1: crack reference
# Pane 2: Terminal for commands
# Pane 3: crack bloodtrail
```

### With Metasploit

```bash
# Get Metasploit commands
crack reference metasploit
crack cheatsheets metasploit-basics

# Parse Metasploit output
crack prism meterpreter_output.txt
```

### With BloodHound

```bash
# Analyze BloodHound JSON
crack bloodtrail analyze --file bloodhound.zip

# Get AD attack paths
crack bloodtrail paths
```

---

## Next Steps

- Read [INSTALL.md](../INSTALL.md) for installation details
- Check [FAQ.md](FAQ.md) for troubleshooting
- Explore [ARCHITECTURE.md](../ARCHITECTURE.md) for system design
- See [mcpserver/README.md](../mcpserver/README.md) for Claude integration
