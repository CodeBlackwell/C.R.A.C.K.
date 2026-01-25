# CRACK Installation Guide

Complete installation instructions for all platforms and configurations.

## Prerequisites Checklist

| Requirement | Version | Required | Purpose |
|-------------|---------|----------|---------|
| Python | 3.8+ | Yes | Core CLI toolkit |
| pip or uv | Latest | Yes | Package installation |
| just | Latest | Recommended | Build automation |
| Node.js | 18+ | For GUIs | Crackpedia, B.R.E.A.C.H. |
| Docker | Latest | Optional | Neo4j container |
| Neo4j | 5.15+ | Optional | Graph database features |

## Quick Install (Recommended)

### One-Command Setup

```bash
# Install just (if not installed)
# Kali/Debian: sudo apt install just
# macOS: brew install just

# Clone and setup
git clone https://github.com/CodeBlackwell/C.R.A.C.K..git crack
cd crack
just setup
```

This will:
1. Check prerequisites
2. Install CRACK CLI and GUI applications
3. Start Neo4j (Docker or systemd)
4. Import command database
5. Verify installation

### CLI Only (No Neo4j)

```bash
git clone https://github.com/CodeBlackwell/C.R.A.C.K..git crack
cd crack
just install
```

---

## Manual Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/CodeBlackwell/C.R.A.C.K..git crack
cd crack
```

### Step 2: Install CLI

**Using pip (virtual environment recommended):**
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

**Using uv (faster):**
```bash
uv pip install -e .
```

**System-wide (Kali/Debian):**
```bash
pip install -e . --break-system-packages
```

**Using reinstall.sh (auto-detects method):**
```bash
./reinstall.sh
```

### Step 3: Verify CLI Installation

```bash
crack --help
crack --version
```

### Step 4: Neo4j Setup (Optional)

Neo4j enables graph-based command relationships and engagement tracking.

**Option A: Docker (Recommended)**
```bash
docker-compose up -d

# Wait for startup
sleep 10

# Verify
curl -s http://localhost:7474 | head -1
```

**Option B: System Package**
```bash
# Kali/Debian
sudo apt install neo4j
sudo systemctl start neo4j
sudo systemctl enable neo4j

# Set password (first time)
sudo neo4j-admin set-initial-password Neo4j123
```

**Option C: Manual Download**
1. Download from https://neo4j.com/download/
2. Extract and run `bin/neo4j start`

**Configure Environment:**
```bash
# Add to ~/.bashrc or ~/.zshrc
export NEO4J_URI='bolt://localhost:7687'
export NEO4J_USER='neo4j'
export NEO4J_PASSWORD='Neo4j123'  # Change this!
```

### Step 5: Import Database

```bash
just db-import
# or manually:
python3 db/neo4j-migration/scripts/migrate.py --check
```

### Step 6: GUI Applications (Optional)

**Crackpedia (Command Encyclopedia):**
```bash
cd crackpedia
npm install
cd ..
```

**B.R.E.A.C.H. (Pentesting Workspace):**
```bash
cd breach
npm install
cd ..
```

The `./reinstall.sh` script creates launchers at `/usr/local/bin/`:
- `crackpedia` - Launch command encyclopedia
- `crack-breach` - Launch pentesting workspace

---

## Platform-Specific Notes

### Kali Linux

Kali is the primary development platform. Everything should work out of the box.

```bash
# Install prerequisites
sudo apt update
sudo apt install python3 python3-pip nodejs npm docker.io docker-compose just

# Enable Docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
# Log out and back in

# Install CRACK
git clone https://github.com/CodeBlackwell/C.R.A.C.K..git crack
cd crack
just setup
```

### Ubuntu/Debian

```bash
# Install prerequisites
sudo apt update
sudo apt install python3 python3-pip python3-venv nodejs npm

# Install just
curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to /usr/local/bin

# Install Docker (optional)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Install CRACK
git clone https://github.com/CodeBlackwell/C.R.A.C.K..git crack
cd crack
just setup
```

### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install prerequisites
brew install python node just

# Install Docker Desktop (optional)
brew install --cask docker

# Install CRACK
git clone https://github.com/CodeBlackwell/C.R.A.C.K..git crack
cd crack
just setup
```

### Windows (WSL2)

CRACK requires WSL2 with a Linux distribution.

```powershell
# In PowerShell (Admin)
wsl --install -d Ubuntu

# Restart, then in WSL:
```

```bash
# In WSL Ubuntu
sudo apt update
sudo apt install python3 python3-pip nodejs npm

# Install just
curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Install CRACK
git clone https://github.com/CodeBlackwell/C.R.A.C.K..git crack
cd crack
just setup
```

---

## MCP Server Setup (Claude Code Integration)

The MCP server enables Claude Code to access CRACK's command database.

### Installation

```bash
just mcp-install
```

### Configuration

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

### Verify

```bash
just mcp-test
```

Restart Claude Code after configuration.

---

## Development Setup

For contributing or modifying CRACK:

```bash
# Full development environment
just dev

# This installs:
# - CRACK CLI in editable mode
# - Dev dependencies (pytest, coverage)
# - Crackpedia npm packages
# - B.R.E.A.C.H. npm packages
```

### Running Tests

```bash
just test          # All tests
just test-v        # Verbose
just test-cov      # With coverage
just test-quick    # Fast smoke test
```

### Development Servers

```bash
just crackpedia-dev  # Crackpedia hot-reload
just breach-dev      # B.R.E.A.C.H. hot-reload
```

---

## Verification

### Check Installation Status

```bash
just info
```

Output:
```
========================================
  CRACK Installation Info
========================================

Components:
  CLI:        /usr/local/bin/crack
  Crackpedia: /usr/local/bin/crackpedia
  B.R.E.A.C.H.: /usr/local/bin/crack-breach

Services:
  Neo4j:      Running (bolt://localhost:7687)

Configuration:
  Config dir: ~/.crack
  Config:     ~/.crack/config.json exists

Knowledge Base:
  Commands:   47 files
  Chains:     28 files
```

### Verify Components

```bash
just verify
```

### Test CLI Commands

```bash
crack reference nmap
crack cheatsheets
crack config list
```

---

## Troubleshooting

### "crack: command not found"

**Cause:** CLI not in PATH

**Solution:**
```bash
# Check where it's installed
pip show crack | grep Location

# Add to PATH or reinstall
./reinstall.sh
source ~/.bashrc
```

### "Neo4j connection refused"

**Cause:** Neo4j not running or wrong credentials

**Solution:**
```bash
# Check status
just neo4j-status

# Start Neo4j
just neo4j-start

# Verify connection
nc -zv localhost 7687
```

### "Permission denied" during install

**Cause:** Writing to system directories without sudo

**Solution:**
```bash
# Use virtual environment
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Or use --user flag
pip install -e . --user
```

### GUI won't start

**Cause:** Missing npm dependencies or Node.js

**Solution:**
```bash
# Check Node.js
node --version  # Should be 18+

# Reinstall dependencies
cd crackpedia && rm -rf node_modules && npm install
cd ../breach && rm -rf node_modules && npm install
```

### "Externally managed environment" error (Debian/Ubuntu)

**Cause:** PEP 668 protection on system Python

**Solution:**
```bash
# Option 1: Use virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Option 2: Override (Kali)
pip install -e . --break-system-packages
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | - | Neo4j password (required) |
| `CRACK_CONFIG_DIR` | `~/.crack` | Configuration directory |

See [.env.example](.env.example) for all options.

---

## Uninstalling

```bash
# Remove CLI
pip uninstall crack

# Remove launchers
sudo rm /usr/local/bin/crack /usr/local/bin/crackpedia /usr/local/bin/crack-breach

# Remove configuration (optional)
rm -rf ~/.crack

# Stop and remove Neo4j (if using Docker)
docker-compose down -v
```

---

## Getting Help

- **Documentation:** See [docs/](docs/) directory
- **Issues:** https://github.com/CodeBlackwell/C.R.A.C.K./issues
- **Quick help:** `crack --help`
