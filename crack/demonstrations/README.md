# Video Production Materials

> This directory is gitignored. Local materials only.

## Directory Structure

```
video-production/
├── 01-prism/           # Credential Parser
├── 02-bloodtrail/      # AD Attack Paths
├── 03-crackpedia/      # GUI Command Encyclopedia
├── 04-breach/          # Pentesting Workspace
├── 05-sessions/        # Reverse Shell Management
├── 06-reference/       # Command Lookup System
└── 07-engagement/      # Target & Finding Tracking
```

## Subdirectory Structure (per video)

```
XX-name/
├── samples/      # Sample input files (mimikatz dumps, nmap output, etc.)
├── scripts/      # Talking points, shot lists, command sequences
├── assets/       # Thumbnails, overlays, graphics
└── recordings/   # Raw and edited video files
```

## Quick Reference

| Video | Duration | Focus |
|-------|----------|-------|
| 01-prism | 8-12 min | Post-exploitation credential parsing |
| 02-bloodtrail | 15-20 min | AD attack path discovery |
| 03-crackpedia | 10-12 min | Visual command encyclopedia |
| 04-breach | 12-15 min | Terminal workspace + tracking |
| 05-sessions | 12-15 min | Shell catching, upgrading, pivoting |
| 06-reference | 6-8 min | CLI command lookup |
| 07-engagement | 8-10 min | Neo4j target/finding management |

## Checklist Location

See: `docs/VIDEO_PRODUCTION_CHECKLIST.md` for full recording checklists.

## Sample File Sources

### PRISM (01)
- Mimikatz: Run `sekurlsa::logonpasswords` on lab DC
- Secretsdump: `secretsdump.py domain/user@target`
- GPP: Extract from `\\DC\SYSVOL\domain\Policies\`
- Kerberoast: `GetUserSPNs.py` output

### BloodTrail (02)
- SharpHound: Run collector on domain-joined machine
- Pre-populate Neo4j with sample AD data

### Sessions (05)
- Need target VM for live shell demo
- Prepare simple exploit (web shell, etc.)

## Recording Tips

1. Terminal font: 16-18pt (Hack or JetBrains Mono)
2. Resolution: 1920x1080 minimum
3. Clear notifications before recording
4. Pre-run commands once to warm up any caches
5. Use `clear` between sections
