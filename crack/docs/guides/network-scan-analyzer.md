# Scan Analyzer - Attack Vector Identification Tool

## Overview
The Scan Analyzer is an enhanced nmap output parser that provides comprehensive service analysis, vulnerability assessment, and educational guidance for OSCP exam preparation. It dynamically analyzes scan results to prioritize attack vectors based on multiple risk factors.

## Key Features
During OSCP exam, you need to quickly identify which services to attack first. This tool:
- **Version Cascade Searching** - Generates searches from specific to general (e.g., "apache 2.4.7" → "apache 2.4" → "apache")
- **Software Age Assessment** - Calculates software age and risk level (e.g., "12+ years old (HIGH RISK)")
- **NSE Script Recommendations** - Suggests relevant nmap scripts based on service type
- **Dynamic Banner Analysis** - Extracts unique searchable terms from service banners
- **Enhanced Command Generation** - Provides searchsploit, NSE, manual, and enumeration commands
- **Educational Methodology** - Explains WHY certain ports are prioritized

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

## Enhanced Output Example

```
============================================================
Priority #1 - Port 80
├─ Service: http
├─ Version: Apache httpd 2.4.7 ((Ubuntu))
├─ Software Age: 12+ years old (HIGH RISK)
│
├─ 📚 SearchSploit Commands (Specific → General):
│  searchsploit "apache httpd 2.4.7"
│  searchsploit "apache httpd 2.4"
│  searchsploit "apache httpd 2"
│  searchsploit apache httpd
│
├─ 🔧 NSE Scripts:
│  nmap -p80 --script http-enum TARGET  # Enumerate directories
│  nmap -p80 --script http-methods TARGET  # Check HTTP methods
│  nmap -p80 --script http-shellshock TARGET  # Test Shellshock
│
├─ ✋ Manual Testing:
│  nc -nv TARGET 80
│  # Try: GET / HTTP/1.0, HEAD, OPTIONS
│
└─ 🔍 Enumeration:
   curl -I http://TARGET  # Check headers
   nikto -h http://TARGET  # Web scanner
   dirb http://TARGET  # Directory brute
```

## New Features (v2.0)

### 1. Version Cascade Searching
Generates multiple searchsploit queries from most specific to general:
- Full version: `searchsploit "apache 2.4.7"`
- Minor version: `searchsploit "apache 2.4"`
- Major version: `searchsploit "apache 2"`
- Product only: `searchsploit apache`

### 2. Software Age & Risk Assessment
Automatically calculates software age and assigns risk levels:
- **CRITICAL**: EOL software or known vulnerable versions
- **HIGH**: 10+ years old software
- **MEDIUM**: 5-10 years old
- **LOW**: Recent versions (< 5 years)

### 3. NSE Script Recommendations
Suggests relevant nmap scripts based on service type:
- **SSH**: ssh-auth-methods, ssh2-enum-algos, ssh-brute
- **HTTP**: http-enum, http-methods, http-shellshock
- **SMB**: smb-enum-shares, smb-vuln-*, smb-os-discovery
- **FTP**: ftp-anon, ftp-bounce, ftp-vsftpd-backdoor
- **MySQL**: mysql-empty-password, mysql-enum

### 4. Enhanced Banner Analysis
- Preserves full banner information
- Extracts product names and versions dynamically
- Removes generic terms intelligently
- Generates searches from unique terms only

### 5. Service-Specific Enumeration
Provides tailored commands based on service type:
- **Web**: curl, nikto, dirb, gobuster
- **SMB**: enum4linux, smbclient, crackmapexec
- **SSH**: ssh-audit, hydra
- **FTP**: Anonymous login attempts

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