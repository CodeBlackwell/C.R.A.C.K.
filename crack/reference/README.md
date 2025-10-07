# CRACK Reference System

A hybrid command reference system combining human-readable documentation with programmatic command management for OSCP preparation.

## Quick Start

```bash
# Configure common variables (do this first!)
crack reference --config auto                  # Auto-detect LHOST and INTERFACE
crack reference --set TARGET 192.168.45.100    # Set your target

# Search for commands
crack reference nmap
crack reference "sql injection"

# List commands by category
crack reference --category recon
crack reference --category web

# Interactive mode
crack reference --interactive

# Fill command with auto-configured values
crack reference --fill bash-reverse-shell       # Uses configured LHOST, LPORT
crack reference --fill nmap-service-scan        # Uses configured TARGET

# View/manage configuration
crack reference --config list                   # Show all variables
crack reference --set LHOST 10.10.14.5         # Set a variable
crack reference --get LHOST                     # Get a variable value
```

## Directory Structure

```
reference/
├── docs/                   # Human-readable markdown
│   ├── index.md           # Master command index
│   ├── quick-wins.md      # Top commands for quick results
│   ├── placeholders.md    # Variable reference guide
│   ├── tags.md           # Tag explanations
│   ├── 01-recon/         # Reconnaissance commands
│   ├── 02-web/           # Web testing commands
│   ├── 03-exploitation/  # Exploitation commands
│   ├── 04-post-exploitation/  # Post-exploitation
│   ├── 05-pivoting/      # Pivoting & tunneling
│   └── custom/           # Your personal commands
├── core/                  # Core functionality
├── data/                  # Structured command data
│   ├── commands/         # JSON command definitions
│   ├── templates/        # Markdown generation templates
│   └── schemas/          # JSON validation schemas
└── generators/           # Build and sync scripts
```

## Features

### 1. Dual Format Support
- **Markdown**: Human-readable documentation in `docs/`
- **JSON**: Structured data in `data/commands/` for programmatic access
- **Auto-sync**: Changes in either format can be synchronized

### 2. Smart Search
- Search by command name, description, or tags
- Filter by category (recon, web, exploitation, etc.)
- Find commands by OSCP relevance (high, medium, low)

### 3. Variable Substitution
- Standard placeholders like `<TARGET>`, `<LHOST>`, `<LPORT>`
- Interactive filling of variables
- **Auto-fill from central configuration** - Set once, use everywhere
- Context-aware suggestions

### 4. Central Configuration System
- Store commonly used variables (LHOST, TARGET, etc.)
- Auto-detect network settings (IP, interface)
- Variables auto-fill in all commands
- Edit config via CLI or text editor

### 5. OSCP Optimization
- Commands tagged with exam relevance
- Time estimates for planning
- Alternative approaches for tool failures
- Manual methods documented

## Command Categories

### 01 - Reconnaissance
Network discovery, port scanning, service enumeration, DNS enumeration

### 02 - Web Testing
Directory bruteforcing, SQLi payloads, XSS testing, file inclusion

### 03 - Exploitation
Reverse shells, web shells, password attacks, exploit modification

### 04 - Post-Exploitation
Linux privilege escalation, Windows privilege escalation, file transfer, persistence

### 05 - Pivoting
Port forwarding, proxychains configuration, lateral movement

### Custom
Your personal collection of commands and techniques

## Adding Commands

### Method 1: Add to Markdown
Create or edit files in `docs/` directories:

```markdown
## Command Name
\```bash
nmap -sn <TARGET_SUBNET>
\```
Description of what this does
```

### Method 2: Add to JSON
Edit files in `data/commands/`:

```json
{
  "commands": [
    {
      "id": "nmap-ping-sweep",
      "name": "Network Ping Sweep",
      "category": "recon",
      "command": "nmap -sn <TARGET_SUBNET>",
      "description": "Discover live hosts on network",
      "variables": [
        {
          "name": "<TARGET_SUBNET>",
          "description": "Target network",
          "example": "192.168.1.0/24"
        }
      ],
      "tags": ["NOISY", "QUICK_WIN"],
      "oscp_relevance": "high"
    }
  ]
}
```

### Method 3: Interactive Builder
```bash
crack ref --add
```

## Standard Placeholders

| Placeholder | Description | Example |
|------------|-------------|---------|
| `<TARGET>` | Target IP address | 192.168.1.100 |
| `<TARGET_SUBNET>` | Target network | 192.168.1.0/24 |
| `<LHOST>` | Local/attacker IP | 10.10.14.5 |
| `<LPORT>` | Local port for listener | 4444 |
| `<URL>` | Full URL to target | http://target.com/page |
| `<FILE>` | Filename | shell.php |
| `<WORDLIST>` | Path to wordlist | /usr/share/wordlists/... |
| `<USERNAME>` | Username | admin |
| `<PASSWORD>` | Password | password123 |

## Standard Tags

| Tag | Meaning |
|-----|---------|
| `[NOISY]` | Generates significant traffic/logs |
| `[STEALTH]` | Low detection footprint |
| `[REQUIRES_AUTH]` | Needs valid credentials |
| `[LINUX]` | Linux specific |
| `[WINDOWS]` | Windows specific |
| `[OSCP:HIGH]` | Highly relevant for OSCP |
| `[QUICK_WIN]` | Often successful |

## CLI Usage

### Search Commands
```bash
# Find all nmap commands
crack ref nmap

# Search in descriptions
crack ref "directory brute"

# Search by tag
crack ref --tag QUICK_WIN
crack ref --tag WINDOWS
```

### Category Listing
```bash
# List all recon commands
crack ref --category recon

# List all web commands
crack ref --category web
```

### Interactive Mode
```bash
# Enter interactive reference mode
crack ref --interactive

# Interactive mode with category filter
crack ref -i --category exploitation
```

### Variable Substitution
```bash
# Fill placeholders interactively
crack ref --fill "nmap service scan"

# Provide values directly
crack ref --fill "reverse shell bash" --lhost 10.10.14.5 --lport 4444
```

### Export Commands
```bash
# Export category to markdown
crack ref --export recon > my_recon_commands.md

# Export as JSON
crack ref --export web --format json > web_commands.json

# Export for offline use
crack ref --export-all --output reference_backup/
```

## Integration with CRACK

The reference system integrates seamlessly with other CRACK modules:

```bash
# Use with scanner
crack port-scan 192.168.1.100 --ref  # Shows relevant commands

# Get post-exploitation commands after shell
crack ref --context "got shell as www-data"

# Chain with other tools
crack ref "sql injection" | crack sqli-scan --from-ref
```

## Syncing and Validation

```bash
# Validate all JSON files
crack ref --validate

# Sync markdown to JSON
crack ref --sync md-to-json

# Sync JSON to markdown
crack ref --sync json-to-md

# Check for duplicates
crack ref --check-duplicates
```

## Customization

### Personal Commands
Add your own commands to `docs/custom/` or `data/commands/custom.json`

### Custom Tags
Define new tags in `docs/tags.md`

### Custom Placeholders
Add to `docs/placeholders.md` with descriptions

## Best Practices

1. **Use standard placeholders** for consistency
2. **Tag appropriately** for easy filtering
3. **Include success/failure indicators** to verify command output
4. **Document alternatives** for when primary tools fail
5. **Add time estimates** for exam planning
6. **Keep descriptions concise** but informative

## Contributing

1. Follow the JSON schema in `data/schemas/command.schema.json`
2. Use standard placeholders and tags
3. Test commands before adding
4. Include OSCP relevance ratings
5. Document manual alternatives

## Troubleshooting

### Command not found
```bash
# Rebuild index
crack ref --rebuild-index

# Check for syntax errors
crack ref --validate
```

### Sync issues
```bash
# Force sync from JSON (source of truth)
crack ref --sync json-to-md --force

# Check sync status
crack ref --sync-status
```

## Additional Documentation

- [Configuration Management](docs/config.md) - Central variable configuration system
- [Placeholder Reference](docs/placeholders.md) - Complete list of supported placeholders
- [Tag Reference](docs/tags.md) - Understanding command tags
- [Quick Wins](docs/quick-wins.md) - High success rate commands

## Future Enhancements

- [x] Central configuration system for variables
- [ ] Auto-import from tool output (nmap, metasploit)
- [ ] Success detection from command output
- [ ] Command chaining workflows
- [ ] AI-powered command suggestions
- [ ] Community command sharing
- [ ] Version control for command changes

## License

Part of the CRACK toolkit for OSCP preparation.

---

*For more information, see the [CRACK main documentation](../README.md)*