# CRACK MCP Server - Development Guidelines

## Philosophy

**Knowledge interface, not execution engine.**
The MCP provides context for LLM reasoning. Bash handles execution.

## Code Principles

### DRY (Don't Repeat Yourself)
- All CRACK imports go through `adapters/crack_api.py`
- Shared response formatting in one place
- Reuse existing CRACK components (registry, config, engagement)

### Minimalist
- One function per tool, max 30 lines
- No wrapper classes where functions suffice
- Zero external dependencies beyond `mcp` and CRACK itself

### Clean
- Type hints on all public functions
- Docstrings follow MCP tool format (Args/Returns)
- Consistent JSON response structure

### High Impact
- Each tool must answer: "What question does this help Claude answer?"
- If a tool duplicates Bash capability, remove it
- Prioritize knowledge retrieval over action execution

## File Responsibilities

| File | Purpose | Max Lines |
|------|---------|-----------|
| `server.py` | Entry point, tool registration | 50 |
| `adapters/crack_api.py` | CRACK imports, lazy loading, adapter methods | 600 |
| `tools/knowledge.py` | 6 knowledge query tools | 200 |
| `tools/state.py` | 7 engagement state tools (4 base + 3 graph) | 220 |
| `tools/config.py` | 2 config introspection tools | 80 |

## Tool Inventory (15 total)

**Knowledge (6):** search_commands, get_command, fill_command, get_cheatsheet, get_attack_chain, suggest_next_steps

**State (7):** get_engagement_context, add_target, add_finding, add_credential, get_server_info, get_target_graph, get_engagement_relationships

**Config (2):** list_configured_variables, describe_variable

## Tool Implementation Pattern

```python
@mcp.tool()
async def tool_name(required_arg: str, optional_arg: str = None) -> str:
    """One-line description for LLM.

    Args:
        required_arg: What this is and why it matters
        optional_arg: What this is (default behavior if omitted)

    Returns:
        JSON with {success, data, error} structure
    """
    try:
        result = api.do_thing(required_arg, optional_arg)
        return json.dumps({"success": True, "data": result, "error": None})
    except Exception as e:
        return json.dumps({"success": False, "data": None, "error": str(e)})
```

## Anti-Patterns (Do NOT)

- Import from `crack.*` directly in tools (use adapter)
- Print to stdout (breaks STDIO transport)
- Create helper classes for single-use logic
- Add tools that wrap single CLI commands
- Return unstructured text (always JSON)
- Catch exceptions silently

## Testing

Manual testing workflow:
1. `python -m crack.mcpserver.server` (verify no stdout on startup)
2. Configure `~/.claude.json`
3. Restart Claude Code
4. Test each tool with realistic queries

## Response Format

All tools return:
```json
{"success": true, "data": {...}, "error": null}
```

Or on error:
```json
{"success": false, "data": null, "error": "Specific error message"}
```

## Dependencies

Only:
- `mcp[cli]` - MCP SDK
- CRACK internal modules (via adapter)
