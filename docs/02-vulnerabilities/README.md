# Vulnerabilities Reference Index

## Overview
This section contains detailed guides for identifying and exploiting common vulnerabilities found in OSCP environments.

## Categories

### 🌍 [Web Vulnerabilities](web/)

#### [Injection Attacks](web/injections/)
- **[LFI & Log Poisoning](web/injections/lfi-log-poisoning-guide.md)**: Local file inclusion exploitation
- **[RFI Guide](web/injections/rfi-quick-reference.md)**: Remote file inclusion techniques
- SQL injection methodologies
- Command injection exploitation

#### [Access Control](web/access-control/)
- **[Directory Traversal](web/access-control/directory_traversal_guide.md)**: Path traversal exploitation
- Authentication bypass techniques
- Authorization flaws

#### [Client-Side](web/client-side/)
- **[XSS to Privilege Escalation](web/client-side/xss-privilege-escalation-guide.md)**: Cross-site scripting chains
- CSRF exploitation
- DOM-based vulnerabilities

#### [File Operations](web/file-operations/)
- **[File Upload Exploitation](web/file-operations/file-upload-filemanager-exploitation.md)**: Bypassing upload restrictions
- File download vulnerabilities
- Path manipulation attacks

#### [API Vulnerabilities](web/)
- **[Web API Exploitation](web/web-api-exploitation-guide.md)**: REST API attack vectors

### 🖥️ [Service Vulnerabilities](services/)
- SMB exploits and misconfigurations
- SNMP information disclosure
- FTP vulnerabilities
- SSH misconfigurations

### 🌐 [Network Vulnerabilities](network/)
- Buffer overflows
- Network protocol exploits
- Service-specific vulnerabilities

## Vulnerability Assessment Workflow

```
1. Identify Technology
   └── Version, platform, dependencies

2. Research Vulnerabilities
   └── CVEs, exploits, misconfigurations

3. Verify Exploitability
   └── Test for vulnerability presence

4. Develop Exploit
   └── Craft payload or use existing exploit

5. Execute & Document
   └── Exploit and capture evidence
```

## Common Vulnerability Patterns

### Web Applications
- Input validation failures
- Authentication/authorization flaws
- Insecure file operations
- Information disclosure

### Services
- Default credentials
- Unpatched vulnerabilities
- Misconfigurations
- Weak encryption

### Network
- Unencrypted protocols
- Man-in-the-middle opportunities
- Service fingerprinting

## Quick Reference

### Check for Common Web Vulnerabilities
```bash
# Directory traversal test
curl http://target/page.php?file=../../../etc/passwd

# Command injection test
curl http://target/ping.php?ip=127.0.0.1;id

# SQL injection test
sqlmap -u "http://target/page.php?id=1" --batch
```

### Service Vulnerability Checks
```bash
# SMB vulnerability scan
nmap --script smb-vuln* -p445 192.168.45.100

# Check for anonymous FTP
ftp 192.168.45.100 (anonymous:anonymous)
```

## OSCP Focus Areas

1. **File Inclusion**: LFI/RFI leading to RCE
2. **Upload Bypass**: Getting shells through file uploads
3. **SQL Injection**: Database access and shell acquisition
4. **Directory Traversal**: Reading sensitive files
5. **Command Injection**: Direct command execution

## Exploitation Tips

- Always test in safe parameters first
- Understand the vulnerability before exploiting
- Document your exploitation path
- Have multiple exploitation methods ready
- Consider chaining vulnerabilities for greater impact