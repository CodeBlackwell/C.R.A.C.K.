# OSCP Documentation Index

## Quick Navigation

### 📋 [00 - Methodology](00-methodology/)
Exam strategy, kill chains, and systematic approaches

### 🔍 [01 - Enumeration](01-enumeration/)
- **[Network](01-enumeration/network/)**: Nmap, port scanning, host discovery
- **[Services](01-enumeration/services/)**: SMB, SNMP, FTP, SSH enumeration
- **[Web](01-enumeration/web/)**: Web apps, APIs, CMS detection

### 🎯 [02 - Vulnerabilities](02-vulnerabilities/)
- **[Web Vulnerabilities](02-vulnerabilities/web/)**
  - [Injections](02-vulnerabilities/web/injections/): LFI, RFI, SQLi, SQLi-to-RCE, Command injection, Python-specific
  - [Access Control](02-vulnerabilities/web/access-control/): Directory/Path traversal
  - [Client-Side](02-vulnerabilities/web/client-side/): XSS, CSRF
  - [File Operations](02-vulnerabilities/web/file-operations/): Upload/Download vulnerabilities
- **[Service Vulnerabilities](02-vulnerabilities/services/)**
- **[Network Vulnerabilities](02-vulnerabilities/network/)**

### 💥 [03 - Exploitation](03-exploitation/)
Web shells, reverse shells, exploitation frameworks, phishing
- [Phishing and Social Engineering](03-exploitation/phishing-social-engineering.md)

### 🔧 [Exploits](exploits/)
Detailed breakdowns of specific exploit techniques and payloads
- [PowerShell Reverse Shell Breakdown](exploits/powershell-reverse-shell-breakdown.md)

### 🔝 [04 - Post-Exploitation](04-post-exploitation/)
- [Linux Privilege Escalation](04-post-exploitation/linux-privesc/)
- [Windows Privilege Escalation](04-post-exploitation/windows-privesc/)
- [Persistence](04-post-exploitation/persistence/)
- [Pivoting](04-post-exploitation/pivoting/)

### 🛠️ [05 - Techniques](05-techniques/)
PHP wrappers, log poisoning, encoding bypasses

### ⚡ [06 - Quick Reference](06-quick-reference/)
Commands cheatsheet, payloads, one-liners

### 🎪 [07 - Specific Exploits](07-specific-exploits/)
- [WordPress](07-specific-exploits/wordpress/)
- [Grafana](07-specific-exploits/grafana/)
- [FileManager](07-specific-exploits/filemanager/)

### 📝 [08 - Lab Notes](08-lab-notes/)
- [OSCP Exercises](08-lab-notes/oscp-exercises/)
  - [Module 9: Web Application Attacks](08-lab-notes/oscp-exercises/module-09-web-attacks.md)
  - [Module 10: SQL Theory and Databases](08-lab-notes/oscp-exercises/module-10-sql-databases.md)
- [Proving Grounds](08-lab-notes/proving-grounds/)
- [HackTheBox](08-lab-notes/hackthebox/)
- [VulnHub](08-lab-notes/vulnhub/)

### 📊 [09 - Reporting](09-reporting/)
Templates and screenshot evidence

---

## File Locations Reference

| Original File | New Location |
|--------------|--------------|
| nmap_reference.md | [01-enumeration/network/](01-enumeration/network/nmap_reference.md) |
| smb_reference.md | [01-enumeration/services/](01-enumeration/services/smb_reference.md) |
| snmp-enumeration-guide.md | [01-enumeration/services/](01-enumeration/services/snmp-enumeration-guide.md) |
| api-pentesting-guide.md | [01-enumeration/web/](01-enumeration/web/api-pentesting-guide.md) |
| web-api-enumeration-guide.md | [01-enumeration/web/](01-enumeration/web/web-api-enumeration-guide.md) |
| web-api-exploitation-guide.md | [02-vulnerabilities/web/](02-vulnerabilities/web/web-api-exploitation-guide.md) |
| lfi-log-poisoning-guide.md | [02-vulnerabilities/web/injections/](02-vulnerabilities/web/injections/lfi-log-poisoning-guide.md) |
| rfi-quick-reference.md | [02-vulnerabilities/web/injections/](02-vulnerabilities/web/injections/rfi-quick-reference.md) |
| sql-injection-manual-exploitation.md | [02-vulnerabilities/web/injections/](02-vulnerabilities/web/injections/sql-injection-manual-exploitation.md) |
| sql-injection-code-execution.md | [02-vulnerabilities/web/injections/](02-vulnerabilities/web/injections/sql-injection-code-execution.md) |
| directory_traversal_guide.md | [02-vulnerabilities/web/access-control/](02-vulnerabilities/web/access-control/directory_traversal_guide.md) |
| xss-privilege-escalation-guide.md | [02-vulnerabilities/web/client-side/](02-vulnerabilities/web/client-side/xss-privilege-escalation-guide.md) |
| file-upload-filemanager-exploitation.md | [02-vulnerabilities/web/file-operations/](02-vulnerabilities/web/file-operations/file-upload-filemanager-exploitation.md) |
| php-wrappers-quick-reference.md | [05-techniques/](05-techniques/php-wrappers-quick-reference.md) |
| wp-xss-attack-chain.md | [07-specific-exploits/wordpress/](07-specific-exploits/wordpress/wp-xss-attack-chain.md) |
| grafana_apache_traversal_reference.md | [07-specific-exploits/grafana/](07-specific-exploits/grafana/grafana_apache_traversal_reference.md) |
| module-09-web-attacks.md | [08-lab-notes/oscp-exercises/](08-lab-notes/oscp-exercises/module-09-web-attacks.md) |
| python-command-injection-guide.md | [02-vulnerabilities/web/injections/](02-vulnerabilities/web/injections/python-command-injection-guide.md) |
| command-injection-quick-reference.md | [02-vulnerabilities/web/injections/](02-vulnerabilities/web/injections/command-injection-quick-reference.md) |
| non-executable-file-upload-quick-reference.md | [02-vulnerabilities/web/file-operations/](02-vulnerabilities/web/file-operations/non-executable-file-upload-quick-reference.md) |
| powershell-reverse-shell-breakdown.md | [exploits/](exploits/powershell-reverse-shell-breakdown.md) |

---

## Usage Tips

1. **During Enumeration**: Start with [01-enumeration/](01-enumeration/)
2. **Found a Vulnerability**: Check [02-vulnerabilities/](02-vulnerabilities/) for exploitation guides
3. **Need Quick Commands**: Reference [06-quick-reference/](06-quick-reference/)
4. **Post-Shell**: Use [04-post-exploitation/](04-post-exploitation/) for privilege escalation
5. **Specific Software**: Check [07-specific-exploits/](07-specific-exploits/) for targeted guides

## Contributing

When adding new documentation:
1. Place it in the appropriate category
2. Update this index
3. Include practical examples
4. Add troubleshooting sections
5. Focus on OSCP exam applicability