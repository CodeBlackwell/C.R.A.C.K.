# SSH Tunneling Cheatsheet Formatting

## Summary

Successfully formatted `ssh-tunneling-linux.json` to improve readability with strategic newlines and command indentation.

## Changes Applied

### 1. Approach Field (5 scenarios, 38 total steps)
- Added `\n` before Step 2+ (Step 1 remains on header line)
- Indented commands 2 spaces after colons (e.g., `: which socat` → `:\n  which socat`)
- Preserved "Traffic:" summaries on same line as context

### 2. Expected Outcome Field (5 scenarios)
- Added paragraph breaks before:
  - "Limitation:"
  - "Alternative:"
  - "Time:"
  - "Success rate:"

### 3. Why This Works Field (5 scenarios)
- Added paragraph breaks before major concept explanations:
  - "SSH", "Socat", "SOCKS", "Firewall", "Multi-hop", "Result:"

### 4. Notes Field (4 sections - Phase 1-4)
- Added paragraph breaks before major topics:
  - "Critical", "Progression", "Prerequisites", "Testing", "Troubleshooting", "sshuttle", "OSCP"

## Validation

- JSON structure: Valid ✓
- ASCII diagrams: Preserved unchanged ✓
- No semantic labels added ✓
- All scenarios processed: 5/5 ✓
- All sections processed: 4/4 ✓

## Files

- **Formatted**: `ssh-tunneling-linux.json`
- **Backup**: `ssh-tunneling-linux.json.bak`
- **Formatter**: `format_ssh_tunneling.py`

## Formatter Usage

```bash
# Run formatter
python3 format_ssh_tunneling.py

# Restore backup if needed
cp ssh-tunneling-linux.json.bak ssh-tunneling-linux.json

# Validate JSON
jq . ssh-tunneling-linux.json > /dev/null
```

## Example Transformation

### Before
```
Step 1: Verify Socat: which socat. Step 2: Listen on port: socat -ddd TCP-LISTEN:2345...
```

### After
```
Step 1: Verify Socat:
  which socat.
Step 2: Listen on port:
  socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432.
```

## Technical Details

- **Regex patterns**: Identify "Step N:" boundaries and ": command" patterns
- **Command detection**: Lowercase tool names, flags (` -`), known tools
- **Whitespace**: `\n` (newline), `  ` (2 spaces for indentation)
- **Preservation**: ASCII diagrams, existing content, inline explanations
