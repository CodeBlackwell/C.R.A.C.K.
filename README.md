# OSCP Documentation Index

## Quick Navigation

### 🌐 [Web Exploitation](web/)
Complete web attack guides from discovery to exploitation
- [SQL Injection (Manual)](web/sqli-manual.md)
- [SQL Injection (Code Execution)](web/sqli-code-exec.md)
- [Cross-Site Scripting (XSS)](web/xss.md)
- [Local File Inclusion + Log Poisoning](web/lfi-log-poisoning.md)
- [Remote File Inclusion](web/rfi.md)
- [Command Injection](web/command-injection.md)
- [Python Command Injection](web/command-injection-python.md)
- [Directory Traversal](web/directory-traversal.md)
- [File Upload (FileManager)](web/file-upload-filemanager.md)
- [File Upload (Non-Executable)](web/file-upload-non-exec.md)
- [API Enumeration](web/api-enumeration.md)
- [API Pentesting](web/api-pentesting.md)
- [API Exploitation](web/api-exploitation.md)
- [Grafana Directory Traversal](web/grafana-traversal.md)
- [WordPress XSS Attack Chain](web/wordpress-xss.md)

### 🪟 [Windows Exploitation](windows/)
Windows-specific techniques and post-exploitation
- [Credential Harvesting](windows/credential-harvesting.md)
- [Password Attacks](windows/password-attacks.md)
- [Remote Access Methods](windows/remote-access.md)
- [Pivoting Techniques](windows/pivoting.md)
- [Process Injection](windows/process-injection.md)
- [Office Macro Attacks](windows/office-macros.md)

### 🐧 [Linux Exploitation](linux/)
Linux privilege escalation and lateral movement
- [Privilege Abuse Techniques](linux/privilege-abuse.md)
- [SSH Lateral Movement](linux/ssh-movement.md)

### 🔌 [Service Exploitation](services/)
Network service enumeration and exploitation
- [Nmap Reference](services/nmap.md)
- [SMB Enumeration](services/smb.md)
- [SNMP Enumeration](services/snmp.md)
- [MSSQL Authentication](services/mssql-auth.md)
- [MSSQL Exploitation](services/mssql-exploit.md)

### 🛡️ [Evasion Techniques](evasion/)
Bypassing security controls and defenses
- [AV Evasion Basics](evasion/av-evasion-basics.md)
- [AV Evasion Advanced](evasion/av-evasion-advanced.md)
- [AppLocker Fundamentals](evasion/applocker-fundamentals.md)
- [AppLocker Bypasses](evasion/applocker-bypasses.md)
- [Network Filter Bypasses](evasion/network-filters.md)
- [Deep Packet Inspection](evasion/deep-packet-inspection.md)

### ⚡ [Quick Reference](quick-ref/)
Cheat sheets and fast lookup guides
- [Reverse Shells](quick-ref/reverse-shells.md)
- [PHP Wrappers](quick-ref/php-wrappers.md)
- [Phishing Basics](quick-ref/phishing-basics.md)
- [Phishing & Social Engineering](quick-ref/phishing-social-engineering.md)

### 🏢 [Active Directory](active-directory/)
Active Directory enumeration and attacks
- [AD Enumeration](active-directory/enumeration.md)

### 📝 [Lab Notes](lab-notes/)
Practice machine writeups and exercises
- **[Exercises](lab-notes/exercises/)**
  - [Module 9: Web Application Attacks](lab-notes/exercises/module-09-web-attacks.md)
  - [Module 10: SQL Theory and Databases](lab-notes/exercises/module-10-sql-databases.md)
- **[Proving Grounds](lab-notes/proving-grounds/)**
- **[HackTheBox](lab-notes/hackthebox/)**
- **[VulnHub](lab-notes/vulnhub/)**

---

## Structure Overview

```
OSCP/
├── web/                    # All web exploitation (15 files)
├── windows/                # Windows techniques (6 files)
├── linux/                  # Linux techniques (2 files)
├── services/               # Network services (5 files)
├── evasion/                # Defense bypasses (6 files)
├── quick-ref/              # Fast lookups (4 files)
├── active-directory/       # AD attacks (1 file)
├── lab-notes/              # Practice writeups
│   ├── exercises/
│   ├── proving-grounds/
│   ├── hackthebox/
│   └── vulnhub/
├── scans/                  # Scan outputs
├── exploits/               # Custom scripts
└── CLAUDE.md               # Project configuration
```

---

## Quick Access Examples

```bash
# Web application testing
cat web/sqli-manual.md
cat web/file-upload-filemanager.md

# Windows post-exploitation
cat windows/credential-harvesting.md
cat windows/lateral-movement.md

# Service enumeration
cat services/nmap.md
cat services/smb.md

# Quick reference during engagement
cat quick-ref/reverse-shells.md
cat quick-ref/php-wrappers.md

# Evasion techniques
cat evasion/av-evasion-advanced.md
```

---

## Usage Workflow

1. **Enumeration Phase**: Start with `services/nmap.md`, then specific service guides
2. **Web Testing**: Check `web/` directory for specific vulnerability types
3. **Initial Access**: Reference `quick-ref/reverse-shells.md` for payloads
4. **Post-Exploitation**: Use `windows/` or `linux/` for privilege escalation
5. **Evasion**: Check `evasion/` if encountering AV/AppLocker/filters
6. **Active Directory**: Use `active-directory/enumeration.md` for AD environments

---

## Document Standards

Each document contains:
- **PURPOSE**: What this technique accomplishes
- **COMMANDS**: Full syntax with flag explanations
- **EXPECTED OUTPUT**: What success looks like
- **TROUBLESHOOTING**: Common issues and fixes
- **EXAM TIPS**: OSCP-specific considerations

All guides are end-to-end: discovery → enumeration → exploitation → completion

---

## Contributing

When adding new documentation:
1. Place in appropriate attack vector directory
2. Update this index
3. Include complete command explanations with all flags
4. Add practical examples from labs
5. Include troubleshooting section
6. Focus on OSCP exam applicability