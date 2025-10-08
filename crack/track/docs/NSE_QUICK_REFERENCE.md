# NSE Quick Reference Card

**OSCP-Focused NSE Command Reference**
**Source:** Chapter 9 Part 1 - NSE Basics

---

## Quick NSE Commands

### Discovery Phase
```bash
# Safe enumeration (recommended first)
nmap -sV -sC --script=safe -p- <target>

# Discovery scripts
nmap -sV --script=discovery -p<ports> <target>
```

### Service-Specific Enumeration

**HTTP:**
```bash
nmap --script http-enum,http-methods,http-headers -p80,443 <target>
nmap --script http-wordpress-enum -p80 <target>
```

**SMB:**
```bash
nmap --script smb-enum-shares,smb-enum-users -p445 <target>
nmap --script smb-os-discovery,smb-security-mode -p445 <target>
```

**SSH:**
```bash
nmap --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p22 <target>
nmap --script sshv1 -p22 <target>
```

**FTP:**
```bash
nmap --script ftp-anon -p21 <target>
nmap --script ftp-vsftpd-backdoor -p21 <target>
```

**MySQL:**
```bash
nmap --script mysql-empty-password,mysql-info -p3306 <target>
nmap --script mysql-dump-hashes --script-args username=root,password='' -p3306 <target>
```

**MSSQL:**
```bash
nmap --script ms-sql-empty-password,ms-sql-info,ms-sql-ntlm-info -p1433 <target>
```

**SMTP:**
```bash
nmap --script smtp-enum-users,smtp-open-relay -p25 <target>
```

### Vulnerability Detection
```bash
# All vuln scripts
nmap -sV --script vuln -p<ports> <target>

# Specific vulnerabilities
nmap --script smb-vuln-ms17-010 -p445 <target>
nmap --script http-shellshock --script-args uri=/cgi-bin/status -p80 <target>
nmap --script ssl-heartbleed -p443 <target>
```

### Authentication Testing
```bash
# Auth scripts
nmap --script auth -p<ports> <target>

# Specific tests
nmap --script ftp-anon,mysql-empty-password,ms-sql-empty-password <target>
```

---

## NSE Categories

| Category | Usage | OSCP | Risk |
|----------|-------|------|------|
| `safe` | Non-intrusive enum | HIGH | Low |
| `default` (`-sC`) | Standard scripts | HIGH | Low-Med |
| `discovery` | Active enum | HIGH | Low-Med |
| `vuln` | CVE detection | HIGH | High |
| `auth` | Auth testing | MED | Med |
| `brute` | Credential attacks | LOW | VERY HIGH |
| `intrusive` | Exploitation | LOW | VERY HIGH |

---

## Script Arguments

### Global HTTP
```bash
--script-args http.useragent="Custom"
```

### Brute Force
```bash
--script-args userdb=users.txt,passdb=pass.txt
--script-args brute.firstonly=true
--script-args unpwdb.timelimit=30m
```

### SMB
```bash
--script-args smbuser=admin,smbpass=password
```

### SSH
```bash
--script-args ssh.user=root
--script-args ssh-run.cmd='id',ssh-run.username=user,ssh-run.password=pass
```

### Script-Specific
```bash
--script-args http-enum.basepath=/admin/
--script-args smtp-enum-users.methods={VRFY,EXPN,RCPT}
```

---

## Script Selection

```bash
# Single script
--script http-enum

# Multiple scripts
--script http-enum,http-methods,http-headers

# Wildcard
--script "http-*"

# Category
--script safe
--script vuln

# Logic
--script "safe or intrusive"
--script "(http-* or smb-*) and safe"
--script "not intrusive"
```

---

## Useful Flags

```bash
# Script help
nmap --script-help http-enum
nmap --script-help "http-*"

# Script trace (debug)
nmap --script-trace --script http-enum <target>

# Script timeout
nmap --script http-enum --script-timeout 30s <target>

# Update script DB
nmap --script-updatedb
```

---

## OSCP Workflow

**Phase 1: Safe Discovery**
```bash
nmap -sV -sC -p- <target> -oA safe_scan
```

**Phase 2: Service Enumeration**
```bash
nmap --script discovery -p<ports> <target> -oA discovery_scan
```

**Phase 3: Vulnerability Scanning**
```bash
nmap --script vuln -p<ports> <target> -oA vuln_scan
```

**Phase 4: Auth Testing**
```bash
nmap --script auth -p<ports> <target> -oA auth_scan
```

**Phase 5: Brute Force (LAST RESORT)**
```bash
# Only if all else fails
nmap --script brute --script-args userdb=short.txt -p<port> <target>
```

---

## Common NSE Scripts

### Top 10 OSCP Scripts

1. `http-enum` - Directory brute-force
2. `smb-vuln-ms17-010` - EternalBlue
3. `smb-enum-shares` - SMB share enumeration
4. `ftp-anon` - Anonymous FTP
5. `ssh2-enum-algos` - SSH weak algorithms
6. `http-methods` - Dangerous HTTP methods
7. `smtp-enum-users` - SMTP user enumeration
8. `mysql-empty-password` - MySQL blank password
9. `http-shellshock` - Shellshock vulnerability
10. `ssl-heartbleed` - Heartbleed vulnerability

---

## Warnings

**Avoid:**
- `dos` category - Denial of service
- `fuzzer` category - May crash services
- Extensive brute-forcing - Account lockouts

**Use Caution:**
- `vuln` scripts - May trigger IDS
- `intrusive` scripts - May crash services
- `brute` scripts - Very slow, noisy

---

**Full Reference:** `/home/kali/OSCP/crack/track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md`
**Scan Profiles:** `/home/kali/OSCP/crack/track/data/scan_profiles.json`

