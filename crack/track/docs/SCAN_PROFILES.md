# 🎨 Scan Profiles System Documentation

## Overview

The **Scan Profiles System** is a dynamic, extensible framework for managing nmap scanning strategies in CRACK Track. Instead of hardcoded scan commands, profiles are defined in JSON and can be added/modified without changing code.

## Why Scan Profiles?

**Before (Hardcoded):**
```python
# phases/definitions.py - HARDCODED
'command': 'nmap --top-ports 1000 {TARGET} -oN quick_scan.nmap'
```

**After (Dynamic):**
```json
// data/scan_profiles.json - DATA-DRIVEN
{
  "id": "lab-quick",
  "base_command": "nmap --top-ports 1000",
  "timing": "normal",
  "use_case": "OSCP labs, CTF - fast initial discovery"
}
```

**Benefits:**
- ✅ Agent-extensible (CrackPot can mine Nmap cookbook)
- ✅ Environment-aware (lab vs production profiles)
- ✅ Educational (flag explanations, success indicators)
- ✅ Modular (composition vs concatenation)
- ✅ No code changes needed to add scans

---

## Architecture

### Components

```
track/
├── data/
│   └── scan_profiles.json          # Profile definitions (JSON)
│
├── core/
│   ├── scan_profiles.py            # Profile registry and loader
│   │   ├── ScanProfileRegistry     # Central registry
│   │   ├── get_profile()          # Load profile by ID
│   │   └── get_profiles_for_phase() # Filter by phase/env
│   │
│   └── command_builder.py          # Command composition
│       ├── ScanCommandBuilder      # Build nmap commands
│       └── build_discovery_command()
│
├── interactive/
│   ├── prompts.py                  # Dynamic menu generation
│   ├── session.py                  # Profile execution
│   └── decision_trees.py           # Profile-based navigation
│
└── phases/
    └── definitions.py              # Phase task definitions
```

### Data Flow

```
User enters interactive mode
    ↓
PromptBuilder._get_discovery_choices(profile)
    ↓
get_profiles_for_phase('discovery', 'lab')
    ↓
ScanProfileRegistry filters profiles by:
  - Phase compatibility (discovery, service-detection)
  - Environment (lab → show quick/full, production → show stealth)
  - Tags (OSCP:HIGH, QUICK_WIN)
    ↓
Menu displays dynamic options
    ↓
User selects "lab-full"
    ↓
session.execute_scan('lab-full')
    ↓
ScanCommandBuilder.build(target, profile)
    ↓
Command composition:
  base_command + timing + ports + rate + output
  "nmap -p-" + "-T4" + "" + "--min-rate 1000" + "-oA lab_full_scan"
    ↓
Execute: nmap -p- -T4 --min-rate 1000 192.168.45.100 -oA lab_full_scan
    ↓
profile.record_scan('lab-full', command, result)
    ↓
Auto-import results (lab_full_scan.xml)
    ↓
Profile saved with scan history
```

---

## Profile Schema

### Required Fields

```json
{
  "id": "unique-profile-id",
  "name": "Human Readable Name",
  "base_command": "nmap <base flags>"
}
```

### Recommended Fields

```json
{
  "id": "lab-full",
  "name": "Full Port Scan (All 65535)",
  "base_command": "nmap -p-",

  "timing": "aggressive",
  "coverage": "full",
  "use_case": "OSCP labs - comprehensive port discovery",
  "estimated_time": "5-10 minutes",
  "detection_risk": "medium",

  "tags": ["OSCP:HIGH", "LAB", "THOROUGH"],
  "phases": ["discovery"],

  "options": {
    "min_rate": 1000,
    "max_rate": null
  },

  "flag_explanations": {
    "-p-": "Scan all 65535 TCP ports (thorough, finds unusual high ports)",
    "--min-rate 1000": "Send at least 1000 packets/second (speeds up scan)"
  },

  "success_indicators": [
    "All 65535 ports scanned",
    "Unusual high ports discovered"
  ],

  "failure_indicators": [
    "Scan takes >15 minutes (network issue)",
    "Too many ports filtered (firewall)"
  ],

  "next_steps": [
    "Run service version scan on discovered ports",
    "Import results: crack track import <target> lab_full_scan.xml"
  ],

  "alternatives": [
    "nmap -p1-65535 <target>",
    "masscan -p1-65535 <target>"
  ],

  "notes": "OSCP CRITICAL: Always run full port scan. Boxes hide services on unusual ports."
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique identifier (kebab-case) |
| `name` | string | ✅ | Display name for menus |
| `base_command` | string | ✅ | Core nmap command (builder adds flags) |
| `timing` | string | ❌ | `paranoid`, `sneaky`, `polite`, `normal`, `aggressive`, `insane` |
| `coverage` | string | ❌ | `quick`, `full`, `common` |
| `use_case` | string | ❌ | When to use this profile |
| `estimated_time` | string | ❌ | How long scan takes |
| `detection_risk` | string | ❌ | `very-low`, `low`, `medium`, `high`, `very-high` |
| `tags` | array | ❌ | `OSCP:HIGH`, `QUICK_WIN`, `LAB`, `PRODUCTION`, etc. |
| `phases` | array | ❌ | `discovery`, `service-detection` (empty = all phases) |
| `options` | object | ❌ | `min_rate`, `max_rate`, etc. |
| `flag_explanations` | object | ❌ | Map of flag → explanation |
| `success_indicators` | array | ❌ | What success looks like |
| `failure_indicators` | array | ❌ | Common failure modes |
| `next_steps` | array | ❌ | What to do after scan |
| `alternatives` | array | ❌ | Other tools/methods |
| `notes` | string | ❌ | Additional context |

---

## Command Builder

### How It Works

The `ScanCommandBuilder` uses **composition** to build nmap commands from profile components:

```python
from crack.track.core.command_builder import ScanCommandBuilder
from crack.track.core.scan_profiles import get_profile

# Load profile
profile = get_profile('lab-full')

# Build command
builder = ScanCommandBuilder('192.168.45.100', profile)
command = builder.build()

# Result: nmap -p- -T4 --min-rate 1000 192.168.45.100 -oA lab_full_scan
```

### Component Methods

| Method | Purpose | Example Output |
|--------|---------|----------------|
| `_get_timing()` | Convert timing name to flag | `-T4` |
| `_get_port_spec()` | Add port range if needed | `-p-` |
| `_get_rate_limiting()` | Add rate control | `--min-rate 1000` |
| `_get_output()` | Add output format | `-oA lab_full_scan` |

### Deduplication Logic

Builder avoids duplicate flags:

```python
# Profile: {"base_command": "nmap -p- -T4"}
# Builder checks: Is "-T4" already in base_command?
# If yes: Skip _get_timing()
# Result: nmap -p- -T4 192.168.45.100 -oA scan
```

---

## Environment-Aware Filtering

### How It Works

```python
from crack.track.core.scan_profiles import get_profiles_for_phase

# Lab environment
profiles = get_profiles_for_phase('discovery', 'lab')
# Returns: [lab-quick, lab-full, aggressive-full]

# Production environment
profiles = get_profiles_for_phase('discovery', 'production')
# Returns: [stealth-slow, stealth-normal]
```

### Filtering Logic

1. **Phase filter:** Only profiles with `phases: ['discovery']` or empty `phases`
2. **Environment filter:**
   - `lab` → Profiles with `LAB` or `QUICK_WIN` or `OSCP:HIGH` tags
   - `production` → Profiles with `PRODUCTION` or `STEALTH` tags
   - `ctf` → Profiles with `LAB` or `QUICK_WIN` tags
3. **Sort by priority:** `OSCP:HIGH` → `QUICK_WIN` → others

---

## Adding New Profiles

### Method 1: Manual (Quick)

1. Edit `track/data/scan_profiles.json`
2. Add profile to `profiles` array
3. Save file
4. Profiles auto-load next run (no reinstall needed!)

```json
{
  "profiles": [
    {
      "id": "my-custom-scan",
      "name": "My Custom Strategy",
      "base_command": "nmap -sS -f",
      "timing": "polite",
      "use_case": "Fragmented SYN scan for firewall evasion",
      "tags": ["STEALTH", "EVASION"],
      "flag_explanations": {
        "-sS": "SYN stealth scan (half-open)",
        "-f": "Fragment packets (8-byte fragments for evasion)"
      }
    }
  ]
}
```

### Method 2: CrackPot Agent (Automated)

The CrackPot agent can mine the Nmap cookbook and generate profiles:

```bash
# Mine Nmap 6 cookbook Chapter 7 (Scanning Large Networks)
crack agent mine /path/to/Nmap_6_Cookbook.txt \
  --chapter 7 \
  --output track/data/scan_profiles.json \
  --append

# Agent extracts:
# - Timing templates (T0-T5) with use cases
# - Scan types (-sS, -sT, -sF, -sN)
# - Evasion techniques (-f, --mtu, -D)
# - Each technique becomes a profile
```

### Method 3: Programmatic

```python
from crack.track.core.scan_profiles import ScanProfileRegistry

# Add profile at runtime
ScanProfileRegistry.add_profile({
    'id': 'decoy-scan',
    'name': 'Decoy Scan (Hide Source)',
    'base_command': 'nmap -D RND:10',
    'use_case': 'Hide real source IP among 10 decoys',
    'tags': ['EVASION', 'ADVANCED']
})

# Profile immediately available
```

---

## Scan History Tracking

### Recording Scans

Every scan execution is recorded:

```python
# In session.py
profile.record_scan(
    profile_id='lab-full',
    command='nmap -p- --min-rate 1000 192.168.45.100 -oA lab_full_scan',
    result_summary='Completed: Full Port Scan (All 65535)',
    ports_found=5,
    duration_seconds=420
)
```

### Storage

Saved to `~/.crack/targets/TARGET.json`:

```json
{
  "target": "192.168.45.100",
  "metadata": {
    "environment": "lab",
    "preferred_profile": "lab-full"
  },
  "scan_history": [
    {
      "timestamp": "2025-10-08T14:23:00",
      "profile_id": "lab-full",
      "command": "nmap -p- --min-rate 1000 192.168.45.100 -oA lab_full_scan",
      "result_summary": "Completed: Full Port Scan (All 65535)",
      "ports_found": 5,
      "duration_seconds": 420
    }
  ]
}
```

### Resume Capability

```python
# Get last used profile
last_profile = profile.get_last_scan_profile()  # Returns: 'lab-full'

# Offer to repeat scan
print(f"Last scan: {last_profile}. Run again? [Y/n]")
```

---

## Best Practices

### Profile Design

✅ **DO:**
- Use descriptive IDs (`stealth-slow`, not `profile1`)
- Include flag explanations (educational)
- Add success/failure indicators
- Provide manual alternatives
- Tag appropriately (`OSCP:HIGH` for exam-relevant)
- Set realistic time estimates

❌ **DON'T:**
- Duplicate existing profiles
- Use niche flags without explanation
- Forget detection risk warnings
- Skip use_case field

### Timing Templates

| Value | nmap Flag | Use Case | Speed |
|-------|-----------|----------|-------|
| `paranoid` | `-T0` | Maximum stealth (5min between probes) | 🐌🐌🐌 |
| `sneaky` | `-T1` | Stealth (15sec between probes) | 🐌🐌 |
| `polite` | `-T2` | Polite (0.4sec delay) | 🐌 |
| `normal` | `-T3` | Default | ⚡ |
| `aggressive` | `-T4` | Fast (labs, CTF) | ⚡⚡ |
| `insane` | `-T5` | Maximum speed (may miss ports) | ⚡⚡⚡ |

### Detection Risk

| Level | Description | Use When |
|-------|-------------|----------|
| `very-low` | T0, fragmented, decoys | Highly monitored production |
| `low` | T1-T2, stealth scan | Normal production |
| `medium` | T3, standard scans | Labs, testing |
| `high` | T4, aggressive scans | Labs only |
| `very-high` | T5, version detect, scripts | Labs with permission |

---

## API Reference

### scan_profiles.py

```python
# Load profile
profile = get_profile('lab-full')

# Get all profiles
all_profiles = get_all_profiles()

# Filter by phase and environment
discovery_profiles = get_profiles_for_phase('discovery', 'lab')

# Add profile programmatically
ScanProfileRegistry.add_profile(profile_dict)
```

### command_builder.py

```python
# Build discovery command
from crack.track.core.command_builder import build_discovery_command

command = build_discovery_command('192.168.45.100', 'lab-full')
# Result: "nmap -p- -T4 --min-rate 1000 192.168.45.100 -oA lab_full_scan"

# Build service scan command
from crack.track.core.command_builder import build_service_command

command = build_service_command('192.168.45.100', '80,443,8080')
# Result: "nmap -sV -sC -p 80,443,8080 192.168.45.100 -oA service_scan"
```

### state.py

```python
# Record scan
profile.record_scan('lab-full', command, result_summary)

# Get last profile
last_profile_id = profile.get_last_scan_profile()

# Set environment
profile.set_environment('production')  # Changes shown profiles
```

---

## Troubleshooting

### Profile not loading

```bash
# Check if profile exists
python3 -c "from crack.track.core.scan_profiles import get_profile; print(get_profile('lab-full'))"

# Validate JSON syntax
cat track/data/scan_profiles.json | python3 -m json.tool
```

### Wrong profiles shown

```bash
# Check environment setting
crack track show 192.168.45.100 | grep environment

# Change environment
python3 -c "from crack.track.core.state import TargetProfile; p = TargetProfile.load('192.168.45.100'); p.set_environment('lab'); p.save()"
```

### Command not building correctly

```python
# Debug command builder
from crack.track.core.command_builder import ScanCommandBuilder
from crack.track.core.scan_profiles import get_profile

profile = get_profile('lab-full')
builder = ScanCommandBuilder('192.168.45.100', profile)

print("Base:", profile['base_command'])
print("Timing:", builder._get_timing())
print("Ports:", builder._get_port_spec())
print("Rate:", builder._get_rate_limiting())
print("Output:", builder._get_output())
print("Final:", builder.build())
```

---

## Future Enhancements

- [ ] **Scan templates** - Multi-scan workflows (discovery → service → vuln)
- [ ] **Profile dependencies** - Chain profiles (quick → full if ports found)
- [ ] **Adaptive profiles** - Auto-adjust based on results
- [ ] **Profile marketplace** - Community-contributed profiles
- [ ] **Evasion profiles** - Fragmentation, decoys, source port manipulation
- [ ] **Masscan integration** - Ultra-fast discovery profiles

---

## See Also

- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture overview
- [USAGE_GUIDE.md](USAGE_GUIDE.md) - User guide and examples
- [PLUGIN_CONTRIBUTION_GUIDE.md](../PLUGIN_CONTRIBUTION_GUIDE.md) - Service plugin development
- [scan_profiles.json](../data/scan_profiles.json) - Profile definitions
