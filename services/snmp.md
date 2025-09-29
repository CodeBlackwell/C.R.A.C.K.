# SNMP Enumeration Reference Guide

## Overview
SNMP (Simple Network Management Protocol) operates on UDP ports 161 (queries) and 162 (traps). Uses community strings as authentication - "public" and "private" are common defaults.

## Quick Discovery

### Fast SNMP Scanner (onesixtyone)
```bash
# Single target, default community
onesixtyone -c public 192.168.229.10

# Multiple targets with wordlist
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -i targets.txt

# Custom community list
echo -e "public\nprivate\nmanager\nadmin" > communities.txt
onesixtyone -c communities.txt -i targets.txt
```

### Nmap UDP Scan
```bash
# Quick SNMP discovery
sudo nmap -sU -p161 --open -T4 192.168.229.0/24 -oG snmp_hosts.txt

# Parallel scanning (faster)
cat targets.txt | xargs -P 5 -I {} sudo nmap -sU {} -p161,162 --open
```

## Detailed Enumeration

### Key Windows MIB OIDs
| OID | Description | Command |
|-----|-------------|---------|
| 1.3.6.1.2.1.25.1.6.0 | System Processes | `snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.1.6.0` |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs | `snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.4.2.1.2` |
| 1.3.6.1.2.1.25.4.2.1.4 | Process Paths | `snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.4.2.1.4` |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units | `snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.2.3.1.4` |
| 1.3.6.1.2.1.25.6.3.1.2 | Installed Software | `snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.6.3.1.2` |
| 1.3.6.1.4.1.77.1.2.25 | User Accounts | `snmpwalk -c public -v1 $IP 1.3.6.1.4.1.77.1.2.25` |
| 1.3.6.1.2.1.6.13.1.3 | TCP Local Ports | `snmpwalk -c public -v1 $IP 1.3.6.1.2.1.6.13.1.3` |
| 1.3.6.1.2.1.2.2.1.2 | Network Interfaces | `snmpwalk -c public -v1 $IP 1.3.6.1.2.1.2.2.1.2` |

### Full Enumeration Commands
```bash
# Get everything (verbose)
snmpwalk -c public -v1 $TARGET

# Translate hex to ASCII
snmpwalk -c public -v1 $TARGET -Oa

# Using snmp-check (automated)
snmp-check $TARGET -c public

# Save output
snmpwalk -c public -v1 $TARGET | tee snmp_full_$TARGET.txt
```

## Practical Workflow

### 1. Discovery Phase
```bash
# Create custom command for network discovery
alias oscp-discover='echo "[*] Running: sudo nmap -sn -T4 192.168.229.0/24" && sudo nmap -sn -T4 192.168.229.0/24 -oG - | grep "Status: Up" | cut -d " " -f2 > targets.txt && echo "[+] Live hosts saved to targets.txt:" && cat targets.txt'
```

### 2. SNMP Identification
```bash
# Fast SNMP discovery
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -i targets.txt -o snmp_found.txt
```

### 3. Deep Enumeration
```bash
# For each confirmed SNMP host
for ip in $(cat snmp_found.txt | cut -d' ' -f1); do
    echo "[*] Enumerating $ip"
    snmpwalk -c public -v1 $ip 1.3.6.1.4.1.77.1.2.25 > users_$ip.txt  # Users
    snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.4.2.1.2 > procs_$ip.txt # Processes
    snmpwalk -c public -v1 $ip 1.3.6.1.2.1.25.6.3.1.2 > soft_$ip.txt  # Software
done
```

## Important Findings to Look For

### High-Value Information
- **Users**: Domain accounts, service accounts, admin users
- **Services**: DNS, LDAP, SMB, WinRM indicate Domain Controller
- **Software**: Anti-virus, vulnerable applications, management tools
- **Network**: Internal IPs, routing tables, connected services
- **Shares**: SYSVOL/NETLOGON indicate Domain Controller

### Example Domain Controller Indicators
```
SYSVOL: C:\Windows\SYSVOL\sysvol
NETLOGON: C:\Windows\SYSVOL\sysvol\domain.com\SCRIPTS
Services: DNS Server, Active Directory Web Services
Ports: 88 (Kerberos), 389 (LDAP), 445 (SMB), 5985 (WinRM)
```

## Security Notes
- **SNMPv1/v2c**: Community strings sent in cleartext
- **SNMPv3**: Supports authentication/encryption but often uses weak DES-56
- **Common strings**: public, private, manager, admin, secret
- **MIB Tree**: Hierarchical database structure for network management data

## Tool Comparison
| Tool | Purpose | Speed | Detail |
|------|---------|--------|---------|
| onesixtyone | Discovery | Fast | Basic |
| nmap -sU | Discovery | Slow | Moderate |
| snmpwalk | Enumeration | Moderate | Detailed |
| snmp-check | Enumeration | Moderate | Formatted |

## Troubleshooting

### No Response
- Firewall blocking UDP 161/162
- Wrong community string
- SNMPv3 requires authentication

### Incomplete Data
- Use `-Oa` flag to decode hex strings
- Try SNMPv2c: `snmpwalk -c public -v2c $IP`
- Some OIDs may be restricted

### Performance
- Use onesixtyone for initial discovery
- Avoid nmap `-A` flag with UDP scans
- Run enumeration in parallel with xargs/parallel

## References
- MIB Tree: IBM Knowledge Center
- Community Lists: /usr/share/seclists/Discovery/SNMP/
- OID Database: http://oid-info.com/