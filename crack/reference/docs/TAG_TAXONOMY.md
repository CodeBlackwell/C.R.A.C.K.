# Tag Taxonomy - CRACK Reference System

**Version:** 2.0
**Last Updated:** 2025-10-12
**Total Tags:** 126
**Total Commands:** 149

## Table of Contents

- [Introduction](#introduction)
- [Tag Categories](#tag-categories)
- [Complete Tag Index](#complete-tag-index)
- [Search Examples](#search-examples)
- [Tag Naming Conventions](#tag-naming-conventions)
- [Common Tag Combinations](#common-tag-combinations)
- [Tag Statistics](#tag-statistics)

## Introduction

Tags enable efficient command discovery in the CRACK reference system. Each command has 4-8 tags describing its functionality, technology, technique, methodology, and associated tools.

**Purpose:**
- Fast search: `crack reference --tag ENUMERATION`
- Category filtering: `crack reference --tag LINUX --tag PRIVESC`
- Discovery: Find commands without knowing exact names
- Learning: Group related techniques together

**Tag Enhancement (v2.0):**
- Added 46 new tags across all categories
- Enhanced all 149 commands with comprehensive tags
- Average tags per command increased from 3.65 to 6.86
- All commands now have minimum 4 tags

## Tag Categories

### 1. Functionality Tags

These describe **what the command does** at a high level.

| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **ENUMERATION** | Discover information about targets (hosts, services, files, directories, users) | 105 | `nmap-ping-sweep`, `gobuster-dir`, `linpeas` |
| **EXPLOITATION** | Execute exploits or attacks to gain access | 132 | `nc-reverse-shell`, `msfvenom-windows-exe`, `sqli-union-select-basic` |
| **POST_EXPLOITATION** | Activities after initial compromise | 84 | `file-transfer-wget`, `linux-privesc-linpeas`, `win-privesc-winpeas` |
| **PRIVILEGE_ESCALATION** | Elevate privileges on compromised systems | 50 | `linux-suid-find`, `windows-unquoted-service`, `linux-kernel-exploit` |
| **CREDENTIAL_ACCESS** | Obtain credentials, hashes, or authentication tokens | 24 | `linux-mysql-udf`, `windows-sam-system-backup`, `smb-null-session-shares` |
| **LATERAL_MOVEMENT** | Pivot from one system to another | 3 | `linux-ssh-keys`, `windows-pass-the-hash` |
| **RECONNAISSANCE** | Information gathering and footprinting | 20 | `nmap-service-scan`, `dns-enum`, `whatweb-technology-detection` |
| **WEAPONIZATION** | Create or prepare exploit payloads | 6 | `msfvenom-windows-reverse-tcp`, `msfvenom-php-webshell` |
| **INITIAL_ACCESS** | Techniques for gaining initial foothold | N/A | (Future use) |
| **DISCOVERY** | Find resources on systems or networks | 67 | `linux-sudo-list`, `windows-whoami-privs`, `curl-header-enum` |

### 2. Technology Tags

These describe **what technologies** the command targets or uses.

#### Web Servers
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **APACHE** | Apache HTTP Server | N/A | (Future use) |
| **NGINX** | Nginx web server | N/A | (Future use) |
| **IIS** | Microsoft Internet Information Services | 2 | `msfvenom-aspx-webshell`, `sqli-union-mssql-info` |

#### Databases
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **MYSQL** | MySQL/MariaDB database | 3 | `linux-mysql-udf`, `linux-mysql-root`, `sqli-detection-error` |
| **POSTGRESQL** | PostgreSQL database | 2 | `sqli-union-postgresql-info`, `sqli-detection-error` |
| **MSSQL** | Microsoft SQL Server | 2 | `sqli-union-mssql-info`, `sqli-detection-error` |
| **ORACLE** | Oracle database | 2 | `sqli-detection-error` |
| **DATABASE** | Generic database operations | 28 | `searchsploit`, `sqlmap-basic`, `sqli-manual-test` |

#### Content Management Systems
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **WORDPRESS** | WordPress CMS | 5 | `wpscan-enumerate-all`, `wpscan-aggressive-detection` |
| **JOOMLA** | Joomla CMS | N/A | (Future use) |
| **DRUPAL** | Drupal CMS | N/A | (Future use) |

#### Directory Services
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **ACTIVE_DIRECTORY** | Active Directory environments | 1 | `windows-kerberoasting` |
| **LDAP** | Lightweight Directory Access Protocol | N/A | (Future use) |

#### File Sharing
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **SAMBA** | SMB/CIFS/Samba file sharing | 13 | `smb-enum4linux-full`, `smb-mount-share`, `file-transfer-smb` |
| **SSH** | Secure Shell protocol | 3 | `hydra-ssh`, `linux-ssh-keys`, `file-transfer-scp` |
| **FTP** | File Transfer Protocol | 2 | `file-transfer-ftp` |
| **RDP** | Remote Desktop Protocol | N/A | (Future use) |
| **VNC** | Virtual Network Computing | 2 | `win-registry-autologon`, `win-password-files` |

### 3. Technique Tags

These describe **attack techniques** used by the command.

#### Injection Attacks
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **INJECTION** | Generic injection attacks | 19 | `linux-wildcard-injection`, `sqli-detection-error`, `sqlmap-basic` |
| **SQL_INJECTION** | SQL injection attacks | 16 | `sqlmap-basic`, `sqli-union-select-basic`, `sqli-detection-error` |
| **COMMAND_INJECTION** | OS command injection | 1 | `linux-wildcard-injection` |
| **CROSS_SITE_SCRIPTING** | XSS attacks | 1 | `xss-test` |

#### Directory/File Operations
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **DIRECTORY_ENUMERATION** | Discover hidden directories/files | 10 | `gobuster-dir`, `wfuzz-params`, `smb-smbmap-recursive` |
| **DIRECTORY_TRAVERSAL** | Path traversal (LFI/RFI) | 2 | `lfi-test` |
| **FILE_INCLUSION** | Local/Remote file inclusion | 4 | `lfi-test`, `rdesktop-disk-share`, `smb-mount-share` |
| **FILE_UPLOAD** | File upload vulnerabilities | 2 | `file-transfer-php`, `curl-upload` |
| **FILE_TRANSFER** | Transfer files between systems | 49 | `wget-download`, `curl-upload`, `python-http-server` |

#### Code Execution
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **REMOTE_CODE_EXECUTION** | Execute code on remote systems | 13 | `nc-reverse-shell`, `msfvenom-windows-exe`, `perl-reverse-shell` |
| **BUFFER_OVERFLOW** | Buffer overflow exploits | N/A | (Future use) |
| **REVERSE_ENGINEERING** | Binary analysis and reverse engineering | 1 | `powershell-reverse-shell` |

### 4. Methodology Phase Tags

These describe **when in the kill chain** the command is used.

| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **STARTER** | First commands to run in new engagements | 4 | `nmap-ping-sweep`, `nmap-quick-scan`, `linux-privesc-linenum` |
| **STEALTHY** | Low-profile, hard-to-detect techniques | 2 | `dns-exfiltration`, `wpscan-aggressive-detection` |
| **NOISY** | High-profile, easily detected techniques | 2 | `gobuster-dir`, `smb-enum4linux-full` |
| **PERSISTENCE** | Maintain access over time | 23 | `linux-cron-enum`, `linux-writable-services`, `windows-scheduled-tasks` |
| **DEFENSE_EVASION** | Bypass security controls | 3 | `file-transfer-base64`, `dns-exfiltration`, `win-privesc-powerup` |
| **NETWORK** | Network-level operations | 46 | `nmap-ping-sweep`, `bash-reverse-shell`, `curl-header-enum` |

### 5. Tool Tags

These indicate **which tool** the command uses.

#### Scanning Tools
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **NMAP** | Network Mapper port scanner | 7 | `nmap-ping-sweep`, `nmap-quick-scan`, `nmap-vuln-scan` |
| **NIKTO** | Web server scanner | 3 | `nikto-scan`, `nikto-comprehensive` |
| **WHATWEB** | Web technology identifier | 4 | `whatweb-enum`, `whatweb-technology-detection` |

#### Web Enumeration
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **GOBUSTER** | Directory/DNS brute forcer | 6 | `gobuster-dir`, `gobuster-dir-common`, `vhost-fuzzing-gobuster` |
| **DIRB** | Web content scanner | 1 | `gobuster-dir-common` |
| **FFUF** | Fast web fuzzer | N/A | (Future use) |
| **WFUZZ** | Web application fuzzer | 2 | `wfuzz-params` |

#### SMB Tools
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **ENUM4LINUX** | SMB enumeration tool | 4 | `smb-enum4linux-full`, `smb-enum` |
| **SMBCLIENT** | SMB client | 3 | `smb-null-session-shares`, `smb-smbclient-connect` |
| **SMBMAP** | SMB share enumerator | 2 | `smb-smbmap-recursive` |
| **CRACKMAPEXEC** | Swiss army knife for SMB/WMI/SSH | 1 | `smb-crackmapexec-shares` |

#### Privilege Escalation Tools
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **LINPEAS** | Linux privilege escalation scanner | 4 | `linux-privesc-linpeas`, `linux-linpeas` |
| **WINPEAS** | Windows privilege escalation scanner | 2 | `win-privesc-winpeas` |
| **PSPY** | Monitor Linux processes without root | 2 | `linux-pspy` |
| **LINENUM** | Linux enumeration script | 2 | `linux-privesc-linenum` |

#### Exploitation Frameworks
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **METASPLOIT** | Metasploit Framework | 9 | `msfvenom-windows-exe`, `msfvenom-linux-reverse-tcp` |
| **SQLMAP** | Automated SQL injection tool | 3 | `sqlmap-basic`, `sqlmap-post-exploitation` |
| **WPSCAN** | WordPress vulnerability scanner | 6 | `wpscan-enumerate-all`, `wpscan-password-attack` |

#### Password Attacks
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **HYDRA** | Network login cracker | 2 | `hydra-ssh` |
| **JOHN** | John the Ripper password cracker | N/A | (Future use) |
| **HASHCAT** | Advanced password recovery | N/A | (Future use) |
| **MIMIKATZ** | Windows credential extractor | 1 | `windows-pass-the-hash` |

#### Utilities
| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **NETCAT** | Network Swiss army knife | 10 | `nc-listener-setup`, `nc-reverse-shell`, `netcat-reverse-shell-mkfifo` |
| **CURL** | Transfer data with URLs | 19 | `curl-post`, `curl-header-enum`, `sqli-detection-error` |
| **WGET** | Network downloader | 4 | `wget-download`, `linux-privesc-linenum` |
| **PYTHON** | Python interpreter/scripts | 7 | `python-shell-upgrade`, `python-http-server`, `win-kernel-exploits` |
| **POWERSHELL** | Windows PowerShell | 4 | `powershell-reverse-shell`, `win-privesc-powerup` |
| **BLOODHOUND** | Active Directory visualizer | N/A | (Future use) |
| **SOCAT** | Multipurpose relay | N/A | (Future use) |

### 6. OSCP-Specific Tags

These indicate **relevance to OSCP exam**.

| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **OSCP:HIGH** | Critical for OSCP exam success | 108 | Majority of commands |
| **OSCP:MEDIUM** | Helpful but not essential | 35 | Alternative techniques |
| **OSCP:LOW** | Optional/advanced techniques | 6 | Specialized scenarios |
| **QUICK_WIN** | Fast, high-value enumeration | 40 | `gobuster-dir`, `linpeas`, `winpeas` |

### 7. Context Tags

These provide **additional context** about command behavior.

| Tag | Description | Commands | Example |
|-----|-------------|----------|---------|
| **MANUAL** | Manual/interactive commands | 30 | `sqli-manual-test`, `lfi-test` |
| **AUTOMATED** | Automated/scripted commands | 5 | `linux-privesc-linpeas`, `win-privesc-winpeas` |
| **LINUX** | Linux-specific commands | 19 | `linux-suid-find`, `linux-sudo-list` |
| **WINDOWS** | Windows-specific commands | 28 | `win-privesc-winpeas`, `windows-sam-system-backup` |
| **WEB** | Web application testing | 32 | `gobuster-dir`, `sqlmap-basic`, `xss-test` |
| **SMB** | SMB/CIFS operations | 7 | `smb-enum`, `smb-null-session-shares` |
| **ENUM** | Enumeration focus | 30 | (Legacy tag, prefer ENUMERATION) |
| **PRIVESC** | Privilege escalation | 22 | (Legacy tag, prefer PRIVILEGE_ESCALATION) |
| **TRANSFER** | File transfer operations | 16 | (Legacy tag, prefer FILE_TRANSFER) |
| **NOISY** | High detection risk | 2 | `gobuster-dir`, `smb-enum4linux-full` |
| **COMPREHENSIVE** | Complete/thorough scans | 1 | `smb-enum4linux-full` |

## Complete Tag Index

**Alphabetical listing of all 126 tags:**

- ACTIVE_DIRECTORY (1)
- APACHE (0)
- AUTOMATED (5)
- BLOODHOUND (0)
- BUFFER_OVERFLOW (0)
- COMMAND_INJECTION (1)
- COMPREHENSIVE (1)
- CRACKMAPEXEC (1)
- CREDENTIAL_ACCESS (24)
- CROSS_SITE_SCRIPTING (1)
- CURL (19)
- DATABASE (28)
- DEFENSE_EVASION (3)
- DIRB (1)
- DIRECTORY_ENUMERATION (10)
- DIRECTORY_TRAVERSAL (2)
- DISCOVERY (67)
- DRUPAL (0)
- ENUM (30) *Legacy*
- ENUM4LINUX (4)
- ENUMERATION (105)
- EXPLOITATION (132)
- FILE_INCLUSION (4)
- FILE_TRANSFER (49)
- FILE_UPLOAD (2)
- FTP (2)
- GOBUSTER (6)
- HASHCAT (0)
- HYDRA (2)
- IIS (2)
- INITIAL_ACCESS (0)
- INJECTION (19)
- JOHN (0)
- JOOMLA (0)
- LATERAL_MOVEMENT (3)
- LDAP (0)
- LINENUM (2)
- LINPEAS (4)
- LINUX (19)
- MANUAL (30)
- METASPLOIT (9)
- MIMIKATZ (1)
- MSSQL (2)
- MYSQL (3)
- NETCAT (10)
- NETWORK (46)
- NGINX (0)
- NIKTO (3)
- NOISY (2)
- ORACLE (2)
- OSCP:HIGH (108)
- OSCP:LOW (6)
- OSCP:MEDIUM (35)
- PERSISTENCE (23)
- POSTGRESQL (2)
- POST_EXPLOITATION (84)
- POWERSHELL (4)
- PRIVILEGE_ESCALATION (50)
- PRIVESC (22) *Legacy*
- PSPY (2)
- PYTHON (7)
- QUICK_WIN (40)
- RDP (0)
- RECONNAISSANCE (20)
- REMOTE_CODE_EXECUTION (13)
- REVERSE_ENGINEERING (1)
- SAMBA (13)
- SMBCLIENT (3)
- SMBMAP (2)
- SMB (7)
- SOCAT (0)
- SQL_INJECTION (16)
- SQLMAP (3)
- SSH (3)
- STARTER (4)
- STEALTHY (2)
- TELNET (0)
- TRANSFER (16) *Legacy*
- VNC (2)
- WEAPONIZATION (6)
- WEB (32)
- WFUZZ (2)
- WGET (4)
- WHATWEB (4)
- WINDOWS (28)
- WINPEAS (2)
- WORDPRESS (5)
- WPSCAN (6)

**Note:** (0) indicates tags added for future use but not yet applied to commands.

## Search Examples

### By Functionality
```bash
# Find all enumeration commands
crack reference --tag ENUMERATION

# Find privilege escalation techniques
crack reference --tag PRIVILEGE_ESCALATION

# Find file transfer methods
crack reference --tag FILE_TRANSFER

# Find exploitation payloads
crack reference --tag EXPLOITATION
```

### By Technology
```bash
# All SMB-related commands
crack reference --tag SAMBA

# All MySQL commands
crack reference --tag MYSQL

# All WordPress commands
crack reference --tag WORDPRESS

# All Active Directory commands
crack reference --tag ACTIVE_DIRECTORY
```

### By Technique
```bash
# SQL injection commands
crack reference --tag SQL_INJECTION

# Directory enumeration commands
crack reference --tag DIRECTORY_ENUMERATION

# Command injection techniques
crack reference --tag COMMAND_INJECTION

# Remote code execution methods
crack reference --tag REMOTE_CODE_EXECUTION
```

### By Tool
```bash
# All nmap commands
crack reference --tag NMAP

# All gobuster commands
crack reference --tag GOBUSTER

# All Metasploit commands
crack reference --tag METASPLOIT

# All LinPEAS commands
crack reference --tag LINPEAS
```

### Combined Searches
```bash
# Linux privilege escalation
crack reference --tag LINUX --tag PRIVILEGE_ESCALATION

# Windows enumeration
crack reference --tag WINDOWS --tag ENUMERATION

# Web SQL injection
crack reference --tag WEB --tag SQL_INJECTION

# SMB enumeration
crack reference --tag SAMBA --tag ENUMERATION

# Quick wins for web testing
crack reference --tag WEB --tag QUICK_WIN

# Stealthy post-exploitation
crack reference --tag POST_EXPLOITATION --tag STEALTHY
```

### OSCP-Focused Searches
```bash
# High-priority OSCP commands
crack reference --tag OSCP:HIGH

# Quick wins (fast enumeration)
crack reference --tag QUICK_WIN

# Starter commands for new targets
crack reference --tag STARTER

# Manual techniques (no automation)
crack reference --tag MANUAL
```

### By Phase/Methodology
```bash
# Reconnaissance phase
crack reference --tag RECONNAISSANCE

# Initial access techniques
crack reference --tag INITIAL_ACCESS

# Post-exploitation activities
crack reference --tag POST_EXPLOITATION

# Lateral movement
crack reference --tag LATERAL_MOVEMENT

# Persistence mechanisms
crack reference --tag PERSISTENCE
```

### Text + Tag Combination
```bash
# Search text AND filter by tag
crack reference nmap --tag STARTER
crack reference shell --tag WINDOWS
crack reference inject --tag SQL_INJECTION
crack reference transfer --tag LINUX
```

## Tag Naming Conventions

### Format Rules

1. **UPPERCASE_WITH_UNDERSCORES**
   - ✓ `SQL_INJECTION`
   - ✗ `SqlInjection`, `sql-injection`

2. **Be Specific**
   - ✓ `MYSQL` (specific database)
   - ✗ `DATABASE` (too generic)
   - Use both: `MYSQL` + `DATABASE`

3. **Self-Documenting**
   - ✓ `DIRECTORY_ENUMERATION` (clear purpose)
   - ✗ `DIR_ENUM` (abbreviation unclear)

4. **Consistent with Existing**
   - Check existing tags before creating new ones
   - Use `ENUMERATION` not `ENUM` (unless legacy)

5. **OSCP Tags Format**
   - `OSCP:HIGH`, `OSCP:MEDIUM`, `OSCP:LOW`
   - Colon separator for hierarchical tags

### Tag Hierarchy

**Prefer specific over generic:**
```
INJECTION (generic)
└── SQL_INJECTION (specific)
└── COMMAND_INJECTION (specific)
└── CROSS_SITE_SCRIPTING (specific)

ENUMERATION (generic)
└── DIRECTORY_ENUMERATION (specific)
└── RECONNAISSANCE (specialized)
```

**Commands should have both:**
- `sqli-union-select-basic`: `INJECTION`, `SQL_INJECTION`, `DATABASE`, `EXPLOITATION`

## Common Tag Combinations

### Reconnaissance
```
ENUMERATION + RECONNAISSANCE + NMAP + NETWORK + STARTER
Example: nmap-ping-sweep
```

### Web Enumeration
```
ENUMERATION + WEB + DIRECTORY_ENUMERATION + GOBUSTER + QUICK_WIN
Example: gobuster-dir
```

### SQL Injection
```
EXPLOITATION + INJECTION + SQL_INJECTION + DATABASE + WEB
Example: sqlmap-basic
```

### Linux Privilege Escalation
```
EXPLOITATION + POST_EXPLOITATION + PRIVILEGE_ESCALATION + LINUX + ENUMERATION
Example: linux-privesc-linpeas
```

### Windows Privilege Escalation
```
EXPLOITATION + POST_EXPLOITATION + PRIVILEGE_ESCALATION + WINDOWS + ENUMERATION
Example: win-privesc-winpeas
```

### File Transfer
```
EXPLOITATION + POST_EXPLOITATION + FILE_TRANSFER + NETWORK
Example: file-transfer-wget
```

### Reverse Shells
```
EXPLOITATION + REMOTE_CODE_EXECUTION + NETWORK
Example: nc-reverse-shell
```

### SMB Enumeration
```
ENUMERATION + RECONNAISSANCE + SAMBA + ENUM4LINUX + CREDENTIAL_ACCESS
Example: smb-enum4linux-full
```

### Payload Generation
```
EXPLOITATION + WEAPONIZATION + METASPLOIT + REMOTE_CODE_EXECUTION
Example: msfvenom-windows-reverse-tcp
```

## Tag Statistics

### Enhancement Results (v2.0)

**Before Enhancement:**
- Total commands: 149
- Total unique tags: 80
- Average tags per command: 3.65
- Commands with <3 tags: 31

**After Enhancement:**
- Total commands: 149
- Total unique tags: 126
- Average tags per command: 6.86
- Commands with <3 tags: 0

**Changes:**
- New tags added: 46
- Total tag instances added: 665
- Files modified: 10
- Commands enhanced: 149 (100%)

### Top 20 Most Common Tags

1. **EXPLOITATION** (132 commands)
2. **OSCP:HIGH** (108 commands)
3. **ENUMERATION** (105 commands)
4. **POST_EXPLOITATION** (84 commands)
5. **DISCOVERY** (67 commands)
6. **PRIVILEGE_ESCALATION** (50 commands)
7. **FILE_TRANSFER** (49 commands)
8. **NETWORK** (46 commands)
9. **QUICK_WIN** (40 commands)
10. **OSCP:MEDIUM** (35 commands)
11. **WEB** (32 commands)
12. **ENUM** (30 commands) *Legacy*
13. **MANUAL** (30 commands)
14. **DATABASE** (28 commands)
15. **WINDOWS** (28 commands)
16. **CREDENTIAL_ACCESS** (24 commands)
17. **PERSISTENCE** (23 commands)
18. **PRIVESC** (22 commands) *Legacy*
19. **RECONNAISSANCE** (20 commands)
20. **LINUX** (19 commands)

### Tags by Category

| Category | Tag Count | Most Common |
|----------|-----------|-------------|
| Functionality | 10 | EXPLOITATION (132) |
| Technology | 23 | DATABASE (28) |
| Technique | 13 | INJECTION (19) |
| Methodology | 6 | NETWORK (46) |
| Tool | 30 | CURL (19) |
| OSCP | 4 | OSCP:HIGH (108) |
| Context | 12 | WEB (32) |

### Tag Coverage by Command Category

| Command Category | Avg Tags | Most Common Tag |
|------------------|----------|-----------------|
| recon | 7.06 | ENUMERATION (17) |
| web | 6.81 | WEB (21) |
| exploitation | 6.74 | EXPLOITATION (27) |
| post-exploit | 6.85 | POST_EXPLOITATION (84) |

## Usage Tips

### For OSCP Students

**Start with these searches:**
```bash
# First commands to run
crack reference --tag STARTER

# Quick enumeration
crack reference --tag QUICK_WIN

# High-priority techniques
crack reference --tag OSCP:HIGH

# Phase-specific commands
crack reference --tag RECONNAISSANCE
crack reference --tag PRIVILEGE_ESCALATION
crack reference --tag POST_EXPLOITATION
```

**Platform-specific:**
```bash
# Linux targets
crack reference --tag LINUX --tag ENUMERATION
crack reference --tag LINUX --tag PRIVILEGE_ESCALATION

# Windows targets
crack reference --tag WINDOWS --tag ENUMERATION
crack reference --tag WINDOWS --tag PRIVILEGE_ESCALATION
```

**By attack surface:**
```bash
# Web applications
crack reference --tag WEB --tag ENUMERATION
crack reference --tag SQL_INJECTION
crack reference --tag DIRECTORY_ENUMERATION

# Network services
crack reference --tag SAMBA
crack reference --tag SSH
crack reference --tag DATABASE
```

### For Command Discovery

**Don't know the exact command name?**
```bash
# Find all nmap commands
crack reference --tag NMAP

# Find all reverse shells
crack reference shell --tag EXPLOITATION

# Find all file transfer methods
crack reference --tag FILE_TRANSFER

# Find all credential dumping techniques
crack reference --tag CREDENTIAL_ACCESS
```

**Need alternatives?**
```bash
# Multiple ways to enumerate SMB
crack reference --tag SAMBA --tag ENUMERATION

# Multiple file transfer techniques
crack reference --tag FILE_TRANSFER --tag LINUX
crack reference --tag FILE_TRANSFER --tag WINDOWS
```

### For Learning

**Study attack techniques:**
```bash
# Learn SQL injection progression
crack reference --tag SQL_INJECTION

# Learn privilege escalation techniques
crack reference --tag PRIVILEGE_ESCALATION --tag LINUX
crack reference --tag PRIVILEGE_ESCALATION --tag WINDOWS

# Learn post-exploitation
crack reference --tag POST_EXPLOITATION
```

**Master specific tools:**
```bash
# Learn all gobuster features
crack reference --tag GOBUSTER

# Learn all nmap techniques
crack reference --tag NMAP

# Learn Metasploit payload generation
crack reference --tag METASPLOIT --tag WEAPONIZATION
```

## Maintenance

### Adding New Tags

**When creating new commands:**
1. Apply at least 4-6 tags
2. Include functionality tag (ENUMERATION, EXPLOITATION, etc.)
3. Include technology tag if applicable (MYSQL, APACHE, etc.)
4. Include technique tag (INJECTION, DIRECTORY_ENUMERATION, etc.)
5. Include tool tag (NMAP, GOBUSTER, etc.)
6. Include OSCP relevance (OSCP:HIGH, OSCP:MEDIUM, OSCP:LOW)
7. Add context tags (LINUX, WINDOWS, WEB, etc.)

**Example:**
```json
{
  "id": "new-command",
  "name": "New Command",
  "tags": [
    "ENUMERATION",           // Functionality
    "MYSQL",                // Technology
    "DIRECTORY_ENUMERATION", // Technique
    "CUSTOM_TOOL",          // Tool
    "OSCP:HIGH",            // OSCP relevance
    "LINUX",                // Context
    "QUICK_WIN"             // Additional
  ]
}
```

### Tag Validation

**Run validation after adding tags:**
```bash
crack reference --validate
```

**Check tag statistics:**
```bash
crack reference --stats
```

### Future Enhancements

**Tags ready for future commands:**
- APACHE, NGINX (web server specific)
- JOOMLA, DRUPAL (CMS)
- LDAP (directory services)
- BUFFER_OVERFLOW (binary exploitation)
- RDP, TELNET (network protocols)
- JOHN, HASHCAT (password cracking)
- BLOODHOUND (AD enumeration)
- SOCAT (advanced networking)

## Version History

### v2.0 (2025-10-12)
- Added 46 new tags across all categories
- Enhanced all 149 commands (100% coverage)
- Increased average tags from 3.65 to 6.86 per command
- Eliminated all commands with <3 tags
- Created comprehensive taxonomy documentation

### v1.0 (Initial)
- 80 tags
- Average 3.65 tags per command
- 31 commands with insufficient tags

---

**For questions or suggestions:**
- Run `crack reference --help` for usage
- Run `crack reference --stats` for current statistics
- Run `crack reference --tag TAG_NAME` to test searches
