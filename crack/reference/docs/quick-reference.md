# CRACK Quick Reference Card

## 🚀 Quick Start
```bash
# Initial Setup (run once)
crack reference --config auto                    # Auto-detect network settings
crack reference --set TARGET 192.168.45.100      # Set your target

# Network Enumeration
crack port-scan 192.168.45.100 --full           # Complete port scan
crack enum-scan 192.168.45.100                  # Port scan + CVE lookup
crack scan-analyze scan.nmap                     # Analyze nmap results

# Web Testing
crack html-enum http://target.com                # HTML enumeration
crack param-discover http://target.com/page.php  # Find parameters
crack sqli-scan http://target.com/page.php?id=1  # SQLi detection
```

## 📚 Reference System (70+ Commands)

### Quick Lookups
```bash
crack reference suid                # Find SUID commands
crack reference reverse             # List reverse shells
crack reference transfer            # File transfer methods
crack reference --tag QUICK_WIN     # Find quick wins
crack reference --category web      # Web testing commands
```

### Auto-Fill Commands
```bash
crack reference --fill bash-reverse-shell    # Auto-fills LHOST/LPORT
crack reference --fill nmap-service-scan     # Auto-fills TARGET
crack reference --fill python-http-server    # Auto-fills PORT
```

## 🎯 Common Attack Patterns

### Initial Enumeration
```bash
crack port-scan $TARGET --full
crack scan-analyze scan_output.nmap
crack reference --fill nmap-service-scan
```

### Web Application
```bash
crack html-enum http://$TARGET
crack param-discover http://$TARGET/page.php
crack sqli-scan http://$TARGET/page.php?id=1
crack reference gobuster
```

### Post-Exploitation
```bash
# Linux
crack reference linux-suid
crack reference linux-sudo
crack reference linux-kernel

# Windows
crack reference windows-whoami
crack reference windows-unquoted
crack reference windows-potato
```

### File Transfer
```bash
# Setup server
crack reference python-http-server
crack reference smb-server

# Download commands
crack reference wget
crack reference certutil
crack reference powershell-download
```

## 🔧 Configuration Variables

| Variable | Description | Example |
|----------|------------|---------|
| LHOST | Your IP address | 10.10.14.5 |
| LPORT | Listener port | 4444 |
| TARGET | Target IP | 192.168.45.100 |
| WORDLIST | Default wordlist | /usr/share/wordlists/rockyou.txt |
| INTERFACE | Network interface | tun0 |
| THREADS | Thread count | 10 |

### Manage Config
```bash
crack reference --config list       # Show all variables
crack reference --set LHOST 10.10.14.5
crack reference --get LHOST
crack reference --config edit       # Open in editor
```

## 📊 Command Categories

### Reconnaissance (7)
- Network: `nmap-ping-sweep`, `nmap-quick-scan`, `nmap-service-scan`
- Services: `dns-enum`, `smb-enum`, `snmp-enum`
- Vulnerability: `nmap-vuln-scan`

### Web Testing (9)
- Discovery: `gobuster-dir`, `nikto-scan`, `whatweb-enum`
- SQLi: `sqlmap-basic`, `sqli-manual-test`
- XSS/LFI: `xss-test`, `lfi-test`
- Fuzzing: `wfuzz-params`
- Manual: `curl-post`

### Exploitation (10)
- Linux Shells: `bash-reverse-shell`, `python-reverse-shell`, `nc-reverse-shell`
- Windows Shells: `powershell-reverse-shell`
- Payloads: `msfvenom-linux-elf`, `msfvenom-windows-exe`
- Web Shells: `php-reverse-shell`, `web-shell-php`
- Tools: `searchsploit`, `hydra-ssh`

### Post-Exploitation (29)
**Linux (15)**
- Quick: `linux-suid-find`, `linux-sudo-check`, `linux-capabilities`
- Config: `linux-writable-passwd`, `linux-cron-jobs`, `linux-path-hijack`
- Advanced: `linux-kernel-version`, `linux-linpeas`, `linux-docker-escape`

**Windows (14)**
- Quick: `windows-alwaysinstallelevated`, `windows-unquoted-service`
- Creds: `windows-stored-credentials`, `windows-autologon`, `windows-sam-backup`
- Advanced: `windows-potato-attacks`, `windows-pass-the-hash`, `windows-kerberoasting`

### File Transfer (15)
- Serving: `python-http-server`, `smb-server`, `ftp-transfer`
- Downloading: `wget-download`, `curl-upload`, `certutil-download`
- PowerShell: `powershell-download`
- Advanced: `base64-transfer`, `php-download`, `dns-exfiltration`

## 🏷️ Useful Tags

| Tag | Description | Count |
|-----|------------|-------|
| OSCP:HIGH | High OSCP relevance | 51 |
| QUICK_WIN | Often successful | 16 |
| PRIVESC | Privilege escalation | 27 |
| WINDOWS | Windows specific | 21 |
| LINUX | Linux specific | 19 |
| NOISY | Generates logs/traffic | 9 |
| STEALTH | Low detection | varies |

## 🎓 OSCP Exam Tips

1. **Set config once**: Run `crack reference --config auto` at start
2. **Use quick wins**: `crack reference --tag QUICK_WIN`
3. **Check alternatives**: Every command has manual alternatives
4. **Document everything**: Commands include success/failure indicators
5. **Time estimates**: Plan based on command execution times

## 📖 Interactive Mode

```bash
crack reference --interactive
```

Commands in interactive mode:
- `<query>` - Search for commands
- `cat <category>` - Show category commands
- `tag <tag>` - Show commands with tag
- `fill <command>` - Fill placeholders
- `categories` - List all categories
- `tags` - List all tags
- `help` - Show help
- `quit` - Exit

## 🆘 Need Help?

```bash
crack --help                 # Full help with tree
crack reference --help       # Reference system help
crack <tool> --help          # Tool-specific help
crack reference --stats      # Statistics overview
```

---
*Part of the CRACK Toolkit for OSCP Preparation*