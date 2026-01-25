# BloodTrail Demo - Presenter Notes

## Target Duration: 10 minutes

## Pre-Recording Checklist

- [ ] Forest machine spawned on HTB
- [ ] VPN connected: `sudo openvpn lab.ovpn`
- [ ] Verify: `ping 10.10.10.161`
- [ ] Neo4j running: `sudo neo4j start`
- [ ] Neo4j cleared: `MATCH (n) DETACH DELETE n` (fresh start)
- [ ] BloodHound GUI open and connected
- [ ] tmux layout ready: `./tmux_layout.sh`
- [ ] OBS configured for 1080p capture
- [ ] Font size readable (14pt+ in terminals)

---

## Section Timing

| Marker | Section | Duration | Cumulative |
|--------|---------|----------|------------|
| 0:00 | Hook | 0:30 | 0:30 |
| 0:30 | Problem Statement | 1:00 | 1:30 |
| 1:30 | Phase 1: Anonymous Enum | 1:30 | 3:00 |
| 3:00 | Phase 2: AS-REP | 0:45 | 3:45 |
| 3:45 | Phase 3: Credential Pipeline | 2:00 | 5:45 |
| 5:45 | Phase 4: Attack Path | 2:00 | 7:45 |
| 7:45 | Phase 5: Exploitation | 1:30 | 9:15 |
| 9:15 | Phase 6: Victory | 0:45 | 10:00 |

---

## Section Scripts

### HOOK (0:00 - 0:30)

**Visual:** Split screen - left shows wall of rpcclient/ldapsearch output, right shows BloodTrail clean output

**Script:**
> "You've dumped BloodHound data. You've got a Neo4j graph. Now what?
>
> Manually clicking through BloodHound, googling each edge type, copying commands from cheat sheets...
>
> What if your BloodHound data came with instructions?"

---

### PROBLEM STATEMENT (0:30 - 1:30)

**Visual:** Manual workflow diagram with time estimates

**Script:**
> "The typical Active Directory attack workflow looks like this:
>
> 1. Enumerate users - rpcclient, ldapsearch, kerbrute - 5 minutes
> 2. Find quick wins - GetNPUsers, GetUserSPNs - 5 minutes
> 3. Crack hashes - hashcat - 10 minutes
> 4. Validate credentials - crackmapexec - 2 minutes
> 5. Collect BloodHound - bloodhound-python - 3 minutes
> 6. Import to Neo4j - drag and drop - 2 minutes
> 7. Mark owned users - right-click, mark owned - 1 minute
> 8. Find attack paths - run queries - 5 minutes
> 9. Interpret edges - what does WriteDacl mean? - 10 minutes
> 10. Execute attacks - google each step - 15 minutes
>
> That's 45+ minutes of context switching and manual work.
>
> BloodTrail does this in under 15."

---

### PHASE 1: Anonymous Enumeration (1:30 - 3:00)

**Left pane:** Run manual commands (show complexity)
```bash
rpcclient -U '' -N 10.10.10.161 -c 'enumdomusers'
ldapsearch -x -H ldap://10.10.10.161 -b "DC=htb,DC=local"
```

**Right pane:** Run BloodTrail
```bash
crack bloodtrail 10.10.10.161
```

**Script:**
> "Without any credentials, BloodTrail discovers:
> - Password policy (lockout threshold, complexity)
> - AS-REP roastable users - svc-alfresco
> - Domain users for password spraying
>
> Notice it already has the AS-REP hash and provides the exact hashcat command."

**BloodHound pane:** Empty graph, waiting

---

### PHASE 2: AS-REP Roasting (3:00 - 3:45)

**Script:**
> "BloodTrail already captured the AS-REP hash during enumeration.
>
> The hashcat command is ready to copy-paste.
>
> [Show hashcat running]
>
> Cracked: svc-alfresco:s3rvice"

**Talking point:** Emphasize that BloodTrail does discovery and exploitation setup in one pass.

---

### PHASE 3: Credential Pipeline (3:45 - 5:45)

**Left pane:** Show manual steps (don't run all)
```bash
crackmapexec smb 10.10.10.161 -u svc-alfresco -p 's3rvice'
bloodhound-python -d htb.local -u svc-alfresco -p 's3rvice' -c all
# Then manually import, mark owned, etc.
```

**Right pane:** Run BloodTrail
```bash
crack bloodtrail 10.10.10.161 --creds 'svc-alfresco:s3rvice'
```

**Script:**
> "One command. BloodTrail:
> 1. Validates the credential
> 2. Collects BloodHound data
> 3. Imports to Neo4j
> 4. Marks svc-alfresco as Pwned
> 5. Runs all attack path queries
>
> Watch the BloodHound graph populate..."

**BloodHound pane:** Graph appears with nodes

---

### PHASE 4: Attack Path Discovery (5:45 - 7:45)

**Right pane:**
```bash
crack bloodtrail --pwned-user 'SVC-ALFRESCO@HTB.LOCAL'
```

**Script:**
> "BloodTrail shows us exactly how to get from svc-alfresco to Domain Admin:
>
> svc-alfresco is member of Service Accounts
> which is member of Privileged IT Accounts
> which is member of Account Operators
> which has GenericAll on Exchange Windows Permissions
> which has WriteDacl on the domain
>
> And here are the exact commands to exploit each step."

**BloodHound pane:** Show the same path visually (side-by-side comparison)

**Key moment:** Point out the green copy-paste commands

---

### PHASE 5: Exploitation (7:45 - 9:15)

**Right pane:**
```bash
crack bloodtrail --post-exploit
```

**Script:**
> "Post-exploitation commands are priority-ordered:
>
> 1. Create a computer account (Account Operators can do this)
> 2. Add it to Exchange Windows Permissions (GenericAll)
> 3. Grant DCSync rights (WriteDacl)
> 4. Dump the domain
>
> Each command is ready to copy and run."

**Show:** Highlight the green commands, explain the progression

---

### PHASE 6: Victory (9:15 - 10:00)

**Right pane:**
```bash
crack bloodtrail --pwn 'ADMINISTRATOR@HTB.LOCAL' --cred-type ntlm-hash --cred-value '...'
crack bloodtrail --list-pwned
```

**Script:**
> "We track the full attack chain:
>
> Anonymous → AS-REP → svc-alfresco → Account Operators → Exchange Windows Permissions → DCSync → Administrator
>
> Total time with BloodTrail: about 15 minutes.
> Manual approach: 45+ minutes.
>
> BloodTrail: Where attack paths become attack plans."

**BloodHound pane:** Full path highlighted with owned markers

---

## Key Talking Points

1. **"One command replaces five"** - Emphasize automation
2. **"Copy-paste ready"** - Green highlighted commands
3. **"No more googling edges"** - Commands already researched
4. **"Time savings"** - 45 min → 15 min
5. **"Track your progress"** - --list-pwned shows attack chain

---

## Troubleshooting

**BloodTrail errors:**
- "Neo4j not connected" → `sudo neo4j start`
- "No data found" → Ensure Forest is accessible, creds are correct

**BloodHound not updating:**
- Click refresh button
- Check Neo4j browser for data: `MATCH (n) RETURN count(n)`

**Commands not running:**
- Ensure crack directory is in PYTHONPATH
- Try: `cd ~/Desktop/OSCP/crack && python3 -m crack.tools.post.bloodtrail ...`

---

## Post-Production

- Add chapter markers at each phase
- Add text overlays for key commands
- Speed up hashcat section (or use pre-cracked)
- Add time comparison graphic at end
