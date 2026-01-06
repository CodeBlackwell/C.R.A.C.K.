# CRACK - Comprehensive Recon & Attack Creation Kit

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/CodeBlackwell/crack)

**C.R.A.C.K.** = **(C)**omprehensive **(R)**econ & **(A)**ttack **(C)**reation **(K)**it

A professional penetration testing toolkit designed for OSCP preparation and real-world engagements. Combines CLI tools, GUI applications, and an extensive knowledge base to streamline security assessments.

## Features

### CLI Toolkit (20+ Commands)
- **Network Reconnaissance**: Port scanning, service enumeration, DNS enumeration
- **Web Application Testing**: HTML enumeration, parameter discovery, SQLi detection
- **Active Directory**: BloodTrail (attack path analysis), credential management
- **Post-Exploitation**: PRISM (output parsing), session management, tunneling

### GUI Applications
- **Crackpedia**: Visual command encyclopedia with graph-based relationships
- **B.R.E.A.C.H.**: Terminal multiplexer with engagement tracking

### Knowledge Base
- 734+ command definitions with flag explanations
- 50+ attack chains (step-by-step workflows)
- Educational cheatsheets and writeups
- Neo4j-powered relationship queries

## Quick Start

### Prerequisites
- Python 3.8+
- Neo4j (optional, for graph features)
- Node.js 18+ (for GUI applications)

### Installation

```bash
# Clone the repository
git clone https://github.com/CodeBlackwell/crack.git
cd crack

# Install in development mode
pip install -e .

# Verify installation
crack --help
```

### Basic Usage

```bash
# Port scanning
crack port-scan 10.10.10.100

# Command reference lookup
crack reference nmap

# Interactive cheatsheets
crack cheatsheets

# BloodTrail AD analysis
crack bloodtrail analyze

# Launch Crackpedia GUI
crackpedia
```

## Architecture

```
crack/
├── cli.py              # Main entry point
├── core/               # Configuration, themes, utilities
├── tools/
│   ├── recon/          # Network, web, SQLi scanning
│   ├── post/           # BloodTrail, PRISM, sessions
│   └── engagement/     # Target and finding management
├── reference/          # Command reference system
├── db/                 # JSON knowledge base + Neo4j migration
├── crackpedia/         # Electron command encyclopedia
└── breach/             # Electron pentesting workspace
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system design.

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/guides/getting-started.md) | First steps and basic usage |
| [CLAUDE.md](CLAUDE.md) | Development philosophy and patterns |
| [Command Schema](db/CLAUDE.md) | Database structure and enrichment |
| [BloodTrail Guide](tools/post/bloodtrail/CLAUDE.md) | AD attack path analysis |

## Configuration

### Environment Variables

```bash
# Neo4j (required for graph features)
export NEO4J_URI='bolt://localhost:7687'
export NEO4J_USER='neo4j'
export NEO4J_PASSWORD='your_secure_password'

# Optional
export CRACK_CONFIG_DIR='~/.crack'
```

See [.env.example](.env.example) for all configuration options.

### Neo4j Setup (Optional)

```bash
# Using Docker
docker-compose up -d

# Or manually
sudo systemctl start neo4j
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `crack port-scan` | Two-stage port scanning |
| `crack enum-scan` | Fast enumeration + CVE lookup |
| `crack html-enum` | HTML/DOM extraction |
| `crack sqli-scan` | SQL injection detection |
| `crack reference` | Command lookup |
| `crack cheatsheets` | Educational collections |
| `crack bloodtrail` | AD attack path analysis |
| `crack prism` | Parse tool output (mimikatz, nmap) |
| `crack session` | Reverse shell management |
| `crack config` | Variable management |

Run `crack <command> --help` for detailed usage.

## Development

### Setup

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

### Adding Commands

Commands are defined in `db/data/commands/` as JSON files. See [db/CLAUDE.md](db/CLAUDE.md) for schema documentation.

```bash
# Validate command definitions
crack reference --validate
```

### GUI Development

```bash
# Crackpedia
cd crackpedia && npm install && npm run dev

# B.R.E.A.C.H.
cd breach && npm install && npm run dev
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

For security issues, see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Philosophy

> "Failed attempts documented well teach more than lucky successes explained poorly."

CRACK focuses on:
- **Manual methodology** over tool memorization
- **Documentation** of failures (critical for learning)
- **Time tracking** for exam planning
- **Tool-independent** exploitation skills

---

**Disclaimer**: This toolkit is intended for authorized security testing, educational purposes, and CTF competitions only. Always obtain proper authorization before testing systems you do not own.
