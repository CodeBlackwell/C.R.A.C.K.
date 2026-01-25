# Video 02: BloodTrail (AD Attack Paths)

**Duration:** 10 min | **Focus:** Active Directory attack path discovery
**Target Box:** HackTheBox Forest (10.10.10.161)

## 3-Pane Layout

```
+------------------+------------------+
|     MANUAL       |   BLOODTRAIL     |  + BloodHound GUI
| (Raw commands)   | (Guided output)  |    (separate window)
+------------------+------------------+
```

## Attack Path (Forest)

```
Anonymous → AS-REP (svc-alfresco) → Account Operators →
GenericAll → Exchange Windows Permissions → WriteDacl → DCSync → DA
```

## Scripts (Complete)

| File | Purpose |
|------|---------|
| `scripts/demo.sh` | Interactive 6-phase demo with menu |
| `scripts/tmux_layout.sh` | 3-pane tmux session setup |
| `scripts/talking_points.md` | Presenter notes + timing |
| `scripts/commands.txt` | Quick command reference |

## Prerequisites

- [ ] HackTheBox VIP subscription (Forest is retired)
- [ ] Forest machine spawned
- [ ] VPN connected: `sudo openvpn lab.ovpn`
- [ ] Neo4j running: `sudo neo4j start`
- [ ] BloodHound GUI open

## Quick Start

```bash
# 1. Start tmux layout
./scripts/tmux_layout.sh

# 2. Open BloodHound GUI in separate window

# 3. Run interactive demo
./scripts/demo.sh

# Or run specific phase
./scripts/demo.sh 1  # Anonymous Enumeration
./scripts/demo.sh 3  # Credential Pipeline
```

## Demo Phases

| # | Phase | Duration | Key Command |
|---|-------|----------|-------------|
| 1 | Anonymous Enumeration | 1:30 | `crack bloodtrail 10.10.10.161` |
| 2 | AS-REP Roasting | 0:45 | (hash from phase 1) |
| 3 | Credential Pipeline | 2:00 | `--creds 'svc-alfresco:s3rvice'` |
| 4 | Attack Path Discovery | 2:00 | `--pwned-user 'SVC-ALFRESCO@HTB.LOCAL'` |
| 5 | Exploitation | 1:30 | `--post-exploit` |
| 6 | Domain Admin | 0:45 | `--list-pwned` |

## Key Shots

1. Split screen: Manual wall-of-text vs BloodTrail clean output
2. AS-REP discovery with ready hashcat command
3. Credential pipeline auto-stages (validate → collect → import → pwn)
4. Attack path with green copy-paste commands
5. BloodHound graph updating in real-time
6. Time comparison: 45 min manual → 15 min BloodTrail

## Thumbnail Concept

Neo4j graph with glowing red attack path from svc-alfresco to Domain Admins
Text: "Follow the Blood"
