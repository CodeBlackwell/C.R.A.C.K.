# Enumeration Guide Index

## Overview
Enumeration is the foundation of successful penetration testing. This section contains comprehensive guides for discovering and mapping attack surfaces.

## Categories

### 🌐 [Network Enumeration](network/)
- **[Nmap Reference](network/nmap_reference.md)**: Complete port scanning and service detection guide
- Host discovery techniques
- Port scanning methodologies
- Service version detection

### 🖥️ [Service Enumeration](services/)
- **[SMB Enumeration](services/smb_reference.md)**: Windows file sharing and domain enumeration
- **[SNMP Enumeration](services/snmp-enumeration-guide.md)**: Simple Network Management Protocol exploitation
- FTP enumeration techniques
- SSH enumeration and key discovery

### 🌍 [Web Enumeration](web/)
- **[API Pentesting Guide](web/api-pentesting-guide.md)**: REST API testing methodology
- **[Web API Enumeration](web/web-api-enumeration-guide.md)**: Discovering and mapping APIs
- Directory brute-forcing
- Technology stack identification
- CMS detection and enumeration

## Enumeration Workflow

```
1. Network Discovery
   └── Identify live hosts

2. Port Scanning
   └── Find open services

3. Service Enumeration
   └── Identify versions and configurations

4. Web Application Discovery
   └── Map attack surface

5. Vulnerability Mapping
   └── Match findings to known vulnerabilities
```

## Quick Commands

### Initial Network Sweep
```bash
# Fast ping sweep
sudo nmap -sn -T5 192.168.45.0/24 -oG - | grep "Up"

# Top ports scan
nmap -sV -sC -top-ports 1000 192.168.45.100
```

### Service-Specific
```bash
# SMB enumeration
enum4linux -a 192.168.45.100

# SNMP walk
snmpwalk -c public -v2c 192.168.45.100

# Web enumeration
gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt
```

## Key Principles

1. **Be Thorough**: Don't skip ports or services
2. **Document Everything**: Save all scan outputs
3. **Follow Leads**: Investigate every finding
4. **Stay Organized**: Use consistent naming conventions
5. **Think Like an Attacker**: What would you target?

## OSCP Tips

- Always run full port scans (`-p-`)
- Save outputs in multiple formats (`-oA`)
- Screenshot interesting findings
- Note service versions for exploit research
- Build a personal enumeration checklist