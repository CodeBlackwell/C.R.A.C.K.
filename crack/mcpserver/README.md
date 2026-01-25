# CRACK MCP Server

Claude Code integration for penetration testing workflows. Provides 15 tools for accessing CRACK's command database, managing engagements, and tracking findings.

## Quick Setup

### 1. Install MCP Server

```bash
cd /path/to/crack
just mcp-install

# Or manually:
cd mcpserver
pip install -e .
```

### 2. Configure Claude Code

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "crack": {
      "command": "python",
      "args": ["-m", "mcpserver.server"],
      "cwd": "/path/to/crack/mcpserver"
    }
  }
}
```

Get the exact config with:
```bash
just mcp-config
```

### 3. Restart Claude Code

The MCP server will load automatically when Claude Code starts.

### 4. Verify

```bash
just mcp-test
```

---

## Available Tools (15)

### Knowledge Tools (6)

Query CRACK's command database of 795+ commands, 50+ attack chains, and educational cheatsheets.

| Tool | Purpose |
|------|---------|
| `search_commands` | Search command database by keyword, category, or tags |
| `get_command` | Get full details for a specific command ID |
| `fill_command` | Substitute placeholders with actual values |
| `get_cheatsheet` | Get educational cheatsheet for a topic |
| `get_attack_chain` | Get ordered attack workflow steps |
| `suggest_next_steps` | Get recommended follow-up commands |

#### Examples

**Search for commands:**
```
search_commands("nmap", category="recon")
search_commands("lateral movement", tags="WINDOWS,AD")
```

**Get command details:**
```
get_command("nmap-service-scan")
get_command("impacket-psexec")
```

**Fill command template:**
```
fill_command("nmap-service-scan", '{"TARGET": "10.10.10.50", "PORTS": "22,80,443"}')
```

**Get attack chain:**
```
get_attack_chain("ad-asreproast-full")
get_attack_chain("linux-privesc-suid-basic")
```

### State Tools (7)

Manage engagement data: targets, findings, credentials, and relationships.

| Tool | Purpose |
|------|---------|
| `get_engagement_context` | Get current engagement status and summary |
| `add_target` | Register a target IP with optional hostname/OS |
| `add_finding` | Record a vulnerability finding |
| `add_credential` | Store discovered credentials |
| `get_server_info` | Get MCP server status and capabilities |
| `get_target_graph` | Get all relationships for a target |
| `get_engagement_relationships` | Get cross-node relationship summary |

#### Examples

**Check engagement status:**
```
get_engagement_context()
```

**Add a target:**
```
add_target("10.10.10.50", hostname="dc01.corp.local", os_guess="Windows Server 2019")
```

**Record a finding:**
```
add_finding("SQL Injection in login", severity="high", cve_id="CVE-2024-1234")
```

**Store credentials:**
```
add_credential("administrator", "hash", "aad3b435b51404eeaad3b435b51404ee:...", notes="From LSASS dump")
```

### Config Tools (2)

Inspect CRACK configuration and variable definitions.

| Tool | Purpose |
|------|---------|
| `list_configured_variables` | List all available placeholder variables |
| `describe_variable` | Get details for a specific variable |

#### Examples

**List variables:**
```
list_configured_variables(category="network")
```

**Describe variable:**
```
describe_variable("LHOST")
describe_variable("TARGET")
```

---

## Response Format

All tools return JSON with consistent structure:

**Success:**
```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

**Error:**
```json
{
  "success": false,
  "data": null,
  "error": "Specific error message"
}
```

---

## Use Cases

### Reconnaissance Workflow

1. Search for scanning commands:
   ```
   search_commands("port scan", category="recon")
   ```

2. Get command details:
   ```
   get_command("nmap-service-scan")
   ```

3. Fill with target values:
   ```
   fill_command("nmap-service-scan", '{"TARGET": "10.10.10.50"}')
   ```

4. Get next steps:
   ```
   suggest_next_steps("nmap-service-scan")
   ```

### Active Directory Attack

1. Get AS-REP roasting chain:
   ```
   get_attack_chain("ad-asreproast-full")
   ```

2. Search for Kerberos commands:
   ```
   search_commands("kerberos", tags="AD")
   ```

3. Get cheatsheet:
   ```
   get_cheatsheet("ad-asreproast-methodology")
   ```

### Engagement Tracking

1. Check active engagement:
   ```
   get_engagement_context()
   ```

2. Add discovered target:
   ```
   add_target("10.10.10.50", hostname="dc01")
   ```

3. Record vulnerability:
   ```
   add_finding("MS17-010 EternalBlue", severity="critical", target_id="t-abc123")
   ```

4. View target relationships:
   ```
   get_target_graph("t-abc123", depth=2)
   ```

---

## Architecture

```
mcpserver/
├── server.py           # Entry point, tool registration
├── adapters/
│   └── crack_api.py    # CRACK API wrapper (lazy loading)
└── tools/
    ├── knowledge.py    # 6 knowledge query tools
    ├── state.py        # 7 engagement state tools
    └── config.py       # 2 config introspection tools
```

### Design Principles

- **Knowledge interface, not execution engine** - Provides context for LLM reasoning; Bash handles execution
- **Lazy loading** - CRACK modules imported only when needed
- **Consistent responses** - All tools return `{success, data, error}` JSON
- **No stdout** - All logs go to stderr (required for STDIO transport)

---

## Troubleshooting

### "MCP SDK not installed"

```bash
pip install 'mcp[cli]'
```

### "Connection refused" or tool errors

1. Check if MCP server can import:
   ```bash
   cd mcpserver && python -c "from server import mcp; print('OK')"
   ```

2. Verify CRACK is installed:
   ```bash
   crack --version
   ```

3. Check Claude Code logs for errors

### Tools return empty results

1. Verify Neo4j is running (for engagement/graph tools):
   ```bash
   just neo4j-status
   ```

2. Check if command database is loaded:
   ```bash
   crack reference --stats
   ```

### Changes not taking effect

Restart Claude Code after modifying `~/.claude.json`.

---

## Development

See [CLAUDE.md](CLAUDE.md) for development guidelines.

### Testing

```bash
# Test import
just mcp-test

# Manual testing
python -m mcpserver.server
# (Should start without stdout output)
```

### Adding Tools

1. Add function to appropriate `tools/*.py` file
2. Follow the tool pattern in CLAUDE.md
3. Register in `server.py` if new module
4. Update this README

---

## Requirements

- Python 3.8+
- `mcp[cli]` package
- CRACK installed and configured
- Neo4j (optional, for engagement/graph features)
