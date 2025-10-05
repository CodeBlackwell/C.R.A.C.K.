# Scan Analyzer - Attack Vector Identification Tool

## Overview
The Scan Analyzer is a dynamic nmap output parser that helps identify and prioritize attack vectors without LLM assistance. It analyzes scan results to highlight unusual services, extract unique banners, and generate specific enumeration commands.

## Purpose
During OSCP exam, you need to quickly identify which services to attack first. This tool:
- Classifies ports as standard vs unusual for the target OS
- Prioritizes services based on multiple factors
- Extracts unique terms from banners for searchsploit
- Generates specific enumeration commands
- Explains the methodology for learning

## Usage

```bash
# Basic usage with nmap text output
crack scan-analyze scan.nmap

# Specify OS type (auto-detects by default)
crack scan-analyze scan.nmap --os windows
crack scan-analyze scan.nmap --os linux

# Works with different nmap formats
crack scan-analyze scan.xml       # XML format
crack scan-analyze scan.gnmap     # Greppable format

# Direct from nmap
nmap -sV -sC target -oA scan && crack scan-analyze scan.nmap
```

## Priority Scoring Algorithm

The tool scores each service based on:
- **Non-standard port** (+3): Not typical for the OS
- **Unknown/custom service** (+3): nmap couldn't identify
- **Unique banner** (+2): Has fingerprint data
- **Non-standard banner** (+1): Not common software
- **Version info** (+1): Specific version available
- **Web service** (+1): Large attack surface
- **Guest access** (+1): Anonymous access indicators

Services are ranked by total score, helping you focus on the most likely vulnerable targets.

## Example Output

```
🎯 SCAN ANALYSIS - 192.168.165.10
Windows 10 Pro

📊 PORT CLASSIFICATION:
✓ Standard windows ports: 135, 139, 445, 49664-49672
⚠️ UNUSUAL PORTS:
  • 1978/tcp (unisql?) - Banner: luminateOK

🚨 ATTACK PRIORITY:
#1 - Port 1978 [CRITICAL - Score: 9/10]
  Service: unisql?
  Banner: luminateOK
  Reasons: non-standard port, unknown service, unique banner

🔍 ENUMERATION COMMANDS:
searchsploit luminateok
nc -nv 192.168.165.10 1978
```

## Key Features

### 1. Dynamic Banner Analysis
- Extracts unique terms from service banners
- Filters out common/generic words
- Identifies product names and versions
- Generates targeted searchsploit queries

### 2. OS-Aware Classification
- Different standard ports for Windows vs Linux
- Auto-detects OS from scan results
- Highlights services unusual for that OS

### 3. Educational Output
- Explains WHY certain ports are prioritized
- Provides mental checklist for exam
- Shows time estimates for planning
- Teaches attack methodology

## Mental Checklist for Exam

When you see scan results:
1. **Circle non-standard ports** - These often run vulnerable custom apps
2. **Highlight unknown services** - nmap couldn't identify = likely custom
3. **Extract banner text** - Unique strings to search for exploits
4. **Note version numbers** - Specific versions may have CVEs
5. **Consider context** - Chapter hints about attack type
6. **Attack unusual first** - Higher success rate than standard services

## Common Patterns

### High Priority Indicators:
- Port not in standard range for OS
- Service shows as "unknown" or has "?"
- Unique banner with product names
- Non-Microsoft software on Windows
- Custom applications on any port

### Lower Priority (but still check):
- Standard services with versions
- Web services (large attack surface)
- Services allowing guest/anonymous access
- Services with known CVE history

## Integration with Workflow

```bash
# Stage 1: Fast port discovery
nmap -p- --min-rate=5000 target -oG ports.gnmap

# Stage 2: Service detection on found ports
nmap -p<ports> -sV -sC target -oA scan

# Stage 3: Analyze for attack vectors
crack scan-analyze scan.nmap

# Stage 4: Research top priorities
searchsploit <banner_terms>
```

## Time Estimates for Exam
- Initial scan analysis: 1-2 minutes
- Research (searchsploit): 5-10 minutes
- Manual service interaction: 5-10 minutes
- Exploit modification/testing: 10-30 minutes
- **Total for initial compromise: 20-50 minutes**

## Why This Approach Works

Custom/unusual services are prioritized because:
1. **Less hardened** - Third-party apps have less security testing
2. **More exploits** - Smaller codebases = more bugs found
3. **Poor patching** - Custom apps updated less frequently
4. **Unique vulns** - Not covered by OS security updates
5. **Chapter context** - OSCP labs hint at attack vectors

## Remember
- The unusual port is usually the path in
- Standard services are hardened, custom ones aren't
- Extract every unique string from banners
- When in doubt, interact manually with nc
- Document what you find for writeups