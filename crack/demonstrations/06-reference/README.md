# Video 06: Reference System (Command Lookup)

**Duration:** 6-8 min | **Focus:** CLI command reference and filling

## Samples Needed

Place in `samples/`:

- [ ] N/A - Uses live command database

## Scripts

Place in `scripts/`:

- [ ] `talking_points.md` - Section-by-section narration
- [ ] `search_demos.txt` - Search queries to demonstrate
- [ ] `config_setup.sh` - Config commands to run before

## Pre-Recording Setup

- [ ] CRACK installed and working
- [ ] Verify: `crack reference --stats` shows 795+ commands
- [ ] Set some config variables for demo:
  ```bash
  crack config set TARGET 10.10.10.5
  crack config set LHOST 10.10.14.5
  ```

## Key Demo Commands

```bash
# Basic search
crack reference nmap
crack reference sqli
crack reference "password spray"

# Detailed lookup
crack reference nmap-service-scan

# Interactive fill
crack fill nmap-service-scan

# Cheatsheets
crack cheatsheets linux-privesc
crack cheatsheets ad-password-spraying

# Config management
crack config list
crack config set TARGET 10.10.10.5
crack config auto  # Auto-detect LHOST
```

## Key Shots

1. Search results with OSCP relevance badges
2. Detailed command output (flags, alternatives)
3. Interactive fill prompts
4. Config defaults auto-filling placeholders
5. Cheatsheet scenario display

## Features to Highlight

- [ ] Ranked search results
- [ ] OSCP relevance indicators
- [ ] Flag explanations (every flag!)
- [ ] Alternatives and prerequisites
- [ ] Next steps suggestions
- [ ] Interactive placeholder filling
- [ ] Config variable inheritance
- [ ] Cheatsheet scenarios

## Thumbnail Concept

Search bar with results dropdown
Text: "Zero Googling"
