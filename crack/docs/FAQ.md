# CRACK FAQ & Troubleshooting

Common questions and solutions for CRACK issues.

## Table of Contents

- [Installation Issues](#installation-issues)
- [CLI Issues](#cli-issues)
- [Neo4j Issues](#neo4j-issues)
- [GUI Issues](#gui-issues)
- [MCP Server Issues](#mcp-server-issues)
- [Configuration Issues](#configuration-issues)
- [General Questions](#general-questions)

---

## Installation Issues

### "crack: command not found"

**Cause:** CRACK CLI not in PATH after installation.

**Solutions:**

1. Source your shell config:
   ```bash
   source ~/.bashrc  # or ~/.zshrc
   ```

2. Check installation location:
   ```bash
   pip show crack | grep Location
   python -m crack.cli --version
   ```

3. Reinstall:
   ```bash
   ./reinstall.sh
   ```

4. Add to PATH manually:
   ```bash
   export PATH="$HOME/.local/bin:$PATH"
   ```

---

### "externally-managed-environment" error

**Cause:** Debian/Ubuntu PEP 668 protection on system Python.

**Solutions:**

1. **Use virtual environment (recommended):**
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e .
   ```

2. **Override on Kali:**
   ```bash
   pip install -e . --break-system-packages
   ```

3. **Use pipx:**
   ```bash
   pipx install -e .
   ```

---

### "ModuleNotFoundError: No module named 'crack'"

**Cause:** CRACK not installed in current Python environment.

**Solutions:**

1. Check if installed:
   ```bash
   pip list | grep crack
   ```

2. Install in editable mode:
   ```bash
   pip install -e .
   ```

3. If using venv, ensure it's activated:
   ```bash
   source .venv/bin/activate
   ```

---

### "Permission denied" during installation

**Cause:** Trying to write to system directories without sudo.

**Solutions:**

1. Use `--user` flag:
   ```bash
   pip install -e . --user
   ```

2. Use virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e .
   ```

3. For system-wide (not recommended):
   ```bash
   sudo pip install -e .
   ```

---

### npm install fails in crackpedia/breach

**Cause:** Node.js version too old or missing.

**Solutions:**

1. Check Node version (need 18+):
   ```bash
   node --version
   ```

2. Update Node.js:
   ```bash
   # Using nvm
   nvm install 18
   nvm use 18

   # On Kali
   sudo apt update && sudo apt install nodejs npm
   ```

3. Clear npm cache and retry:
   ```bash
   rm -rf node_modules package-lock.json
   npm cache clean --force
   npm install
   ```

---

## CLI Issues

### "No commands found" or empty search results

**Cause:** Command database not loaded or corrupted.

**Solutions:**

1. Validate database:
   ```bash
   crack reference --validate
   ```

2. Check database stats:
   ```bash
   crack reference --stats
   ```

3. Verify JSON files exist:
   ```bash
   ls db/data/commands/
   ```

---

### Config variables not being substituted

**Cause:** Variables not set or wrong format.

**Solutions:**

1. Check current variables:
   ```bash
   crack config list
   ```

2. Set missing variables:
   ```bash
   crack config set TARGET 10.10.10.100
   crack config set LHOST 10.10.14.5
   ```

3. Auto-detect network settings:
   ```bash
   crack config auto
   ```

---

### Command output is garbled or has wrong colors

**Cause:** Terminal doesn't support Rich library formatting.

**Solutions:**

1. Try different terminal (gnome-terminal, kitty, alacritty)

2. Disable colors:
   ```bash
   export NO_COLOR=1
   crack reference nmap
   ```

3. Check terminal supports 256 colors:
   ```bash
   echo $TERM  # Should be xterm-256color or similar
   ```

---

## Neo4j Issues

### "Connection refused" to Neo4j

**Cause:** Neo4j not running or wrong port.

**Solutions:**

1. Check status:
   ```bash
   just neo4j-status
   ```

2. Start Neo4j:
   ```bash
   just neo4j-start
   ```

3. Verify port is open:
   ```bash
   nc -zv localhost 7687
   ```

4. Check Docker container:
   ```bash
   docker ps | grep neo4j
   docker logs crack-neo4j
   ```

---

### "Authentication failed" to Neo4j

**Cause:** Wrong credentials or password not set.

**Solutions:**

1. Check credentials in `.env`:
   ```bash
   cat .env | grep NEO4J
   ```

2. Reset password (Docker):
   ```bash
   docker-compose down -v
   docker-compose up -d
   # Default password: Neo4j123
   ```

3. Reset password (system package):
   ```bash
   sudo neo4j-admin set-initial-password NewPassword123
   sudo systemctl restart neo4j
   ```

4. Set environment variables:
   ```bash
   export NEO4J_URI='bolt://localhost:7687'
   export NEO4J_USER='neo4j'
   export NEO4J_PASSWORD='Neo4j123'
   ```

---

### Neo4j is slow or uses too much memory

**Cause:** Default memory settings too high for system.

**Solutions:**

1. Reduce memory in `docker-compose.yml`:
   ```yaml
   environment:
     - NEO4J_dbms_memory_heap_initial__size=256m
     - NEO4J_dbms_memory_heap_max__size=512m
     - NEO4J_dbms_memory_pagecache_size=256m
   ```

2. Restart Neo4j:
   ```bash
   docker-compose down && docker-compose up -d
   ```

---

### "Database is empty" after import

**Cause:** Import failed or wrong database selected.

**Solutions:**

1. Run import with health check:
   ```bash
   just db-import
   ```

2. Verify import:
   ```bash
   just db-neo4j-stats
   ```

3. Check import logs:
   ```bash
   python3 db/neo4j-migration/scripts/migrate.py --verbose
   ```

---

## GUI Issues

### Crackpedia won't start

**Cause:** Missing dependencies or Neo4j not running.

**Solutions:**

1. Install dependencies:
   ```bash
   cd crackpedia
   npm install
   ```

2. Check for errors:
   ```bash
   crackpedia --debug
   # or
   cd crackpedia && npm run dev
   ```

3. Ensure Neo4j is running:
   ```bash
   just neo4j-start
   ```

---

### B.R.E.A.C.H. terminal not working

**Cause:** node-pty native module issues.

**Solutions:**

1. Rebuild native modules:
   ```bash
   cd breach
   npm rebuild
   ```

2. If electron-rebuild fails:
   ```bash
   rm -rf node_modules
   npm install
   npx electron-rebuild
   ```

3. Check for errors:
   ```bash
   crack-breach --debug
   ```

---

### GUI is blank or crashes immediately

**Cause:** Electron version mismatch or corrupted cache.

**Solutions:**

1. Clear Electron cache:
   ```bash
   rm -rf ~/.config/crackpedia
   rm -rf ~/.config/crack-breach
   ```

2. Reinstall dependencies:
   ```bash
   cd crackpedia  # or breach
   rm -rf node_modules
   npm install
   ```

3. Run in verbose mode:
   ```bash
   DEBUG=* crackpedia
   ```

---

## MCP Server Issues

### "MCP SDK not installed"

**Cause:** `mcp` package not installed.

**Solution:**
```bash
pip install 'mcp[cli]'
```

---

### MCP tools not appearing in Claude Code

**Cause:** Configuration error or server not starting.

**Solutions:**

1. Verify config syntax in `~/.claude.json`:
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

2. Get correct path:
   ```bash
   just mcp-config
   ```

3. Test server manually:
   ```bash
   just mcp-test
   ```

4. Restart Claude Code completely (quit and reopen)

---

### MCP tools return errors

**Cause:** CRACK not installed or Neo4j not running.

**Solutions:**

1. Verify CRACK works:
   ```bash
   crack --version
   crack reference --stats
   ```

2. Check Neo4j (for engagement tools):
   ```bash
   just neo4j-status
   ```

3. Check MCP server logs in Claude Code terminal

---

## Configuration Issues

### Config file not found

**Cause:** Config directory doesn't exist.

**Solutions:**

1. Create config directory:
   ```bash
   mkdir -p ~/.crack
   ```

2. Initialize config:
   ```bash
   crack config auto
   ```

---

### Environment variables not working

**Cause:** Variables not exported or shell not reloaded.

**Solutions:**

1. Export variables:
   ```bash
   export NEO4J_URI='bolt://localhost:7687'
   ```

2. Add to shell config:
   ```bash
   echo 'export NEO4J_URI="bolt://localhost:7687"' >> ~/.bashrc
   source ~/.bashrc
   ```

3. Use `.env` file:
   ```bash
   cp .env.example .env
   # Edit .env with your values
   ```

---

## General Questions

### Q: Can I use CRACK without Neo4j?

**A:** Yes! Neo4j is optional. The CLI works with JSON fallback:
```bash
just install  # Skips Neo4j setup
```

Features requiring Neo4j:
- Graph-based command relationships
- Engagement tracking
- B.R.E.A.C.H. target management

---

### Q: How do I update CRACK?

**A:**
```bash
cd /path/to/crack
git pull
just install
```

---

### Q: How do I add custom commands?

**A:** Create JSON files in `db/data/commands/`:

```json
{
  "id": "my-custom-command",
  "name": "My Custom Command",
  "command": "my-tool <TARGET>",
  "category": "recon",
  "description": "What this does"
}
```

Validate:
```bash
crack reference --validate
```

---

### Q: Is CRACK safe for production/exam use?

**A:** CRACK is designed for:
- Authorized penetration testing
- CTF competitions
- Educational/lab environments
- OSCP/security certification exams

Always obtain proper authorization before testing systems.

---

### Q: How do I report a bug?

**A:** Open an issue at:
https://github.com/CodeBlackwell/C.R.A.C.K./issues

Include:
- CRACK version (`crack --version`)
- Operating system
- Steps to reproduce
- Error messages

---

### Q: Where are logs stored?

**A:**
- CLI logs: stderr (not persisted by default)
- Neo4j logs: `docker logs crack-neo4j` or `/var/log/neo4j/`
- GUI logs: `~/.config/crackpedia/logs/` or `~/.config/crack-breach/logs/`

---

## Still Need Help?

1. Check [INSTALL.md](../INSTALL.md) for installation details
2. Read [USAGE.md](USAGE.md) for usage examples
3. Review [ARCHITECTURE.md](../ARCHITECTURE.md) for system design
4. Open an issue: https://github.com/CodeBlackwell/C.R.A.C.K./issues
