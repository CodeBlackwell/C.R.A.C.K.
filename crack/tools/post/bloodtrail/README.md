# BloodTrail - BloodHound Attack Path Enhancement

Edge enhancement, credential pipeline, and Cypher query analysis for BloodHound/Neo4j.

## Features

- **Credential Pipeline**: Bridge enumeration and BloodHound with `--creds` integration
- **Anonymous Enumeration**: Auto-detect AS-REP roastable users, Kerberoastable SPNs
- **Edge Enhancement**: Import missing edges (AdminTo, GenericAll, MemberOf, etc.) from SharpHound JSON exports
- **Query Library**: 63+ pre-built Cypher queries for attack path discovery
- **ZIP Support**: Process SharpHound ZIP output directly (no extraction needed)
- **Command Suggestions**: Auto-suggest exploitation commands based on discovered paths
- **Pwned Tracking**: Track compromised users and their access paths in Neo4j

## Quick Start

```bash
# Anonymous enumeration (AS-REP, Kerberoasting detection)
crack bloodtrail 10.10.10.161

# Feed cracked credentials back in (full pipeline)
crack bloodtrail 10.10.10.161 --creds svc-alfresco:s3rvice

# Enhance edges from SharpHound ZIP
crack bloodtrail /path/to/sharphound_output.zip --preset attack-paths

# List available queries
crack bloodtrail --list-queries

# Resume with existing Neo4j data
crack bloodtrail -r
```

## Credential Pipeline (`--creds`)

The credential pipeline bridges anonymous enumeration with authenticated BloodHound collection:

```
Parse → Validate → Collect → Import → Mark Pwned → Query Attack Paths
```

### Usage

```bash
# Inline credential (user:pass)
crack bloodtrail 10.10.10.161 --creds svc-alfresco:s3rvice

# With domain prefix
crack bloodtrail 10.10.10.161 --creds 'htb.local/svc-alfresco:s3rvice'

# From credentials file (one per line)
crack bloodtrail 10.10.10.161 --creds ./creds.txt

# Auto-detect hashcat/john potfile
crack bloodtrail 10.10.10.161 --use-potfile

# NTLM hash (auto-detected by 32 hex chars)
crack bloodtrail 10.10.10.161 --creds 'admin:aad3b435b51404eeaad3b435b51404ee'
```

### Pipeline Options

| Flag | Description |
|------|-------------|
| `--creds CREDS` | Inline credential or path to credentials file |
| `--creds-file FILE` | Explicit credentials file path |
| `--use-potfile` | Auto-detect hashcat/john potfile |
| `--potfile-path FILE` | Custom potfile path |
| `--skip-validate` | Skip credential validation (trust creds) |
| `--no-collect` | Skip BloodHound collection (use existing data) |
| `--no-pwn` | Skip marking users as pwned |
| `--no-import` | Skip Neo4j import |
| `--bh-output DIR` | BloodHound output directory |

### Credential Formats

```
user:password              # Basic
domain/user:password       # Domain prefix (NTLM style)
user@domain:password       # UPN style
user:aad3b435b51404ee...   # NTLM hash (auto-detected)
```

## Anonymous Enumeration

Target an IP to run pre-auth enumeration:

```bash
# Basic enumeration
crack bloodtrail 10.10.10.161

# With verbose output
crack bloodtrail 10.10.10.161 -v

# Specify domain
crack bloodtrail 10.10.10.161 --domain htb.local

# Authenticated enumeration
crack bloodtrail 10.10.10.161 -u admin -p Password123
```

Discovers:
- AS-REP roastable users (DONT_REQ_PREAUTH)
- Kerberoastable accounts (SPNs)
- Password policy
- Domain users and groups

## Presets

- `attack-paths`: High-value attack path edges (AdminTo, DCSync, GenericAll)
- `all`: All available edge types
- `minimal`: Essential edges only

## Neo4j Connection

Default connection: `bolt://localhost:7687`

Configure via environment or `~/.crack/config.json`:
```json
{
  "bloodtrail": {
    "neo4j_uri": "bolt://localhost:7687",
    "neo4j_user": "neo4j",
    "neo4j_password": "your_password"
  }
}
```

## Architecture

```
bloodtrail/
├── cli.py               # CLI interface
├── main.py              # BHEnhancer core logic
├── credential_input.py  # Credential parsing (inline, file, potfile)
├── creds_pipeline.py    # Credential pipeline orchestration
├── extractors.py        # Edge extraction from JSON
├── query_runner.py      # Cypher query execution
├── command_suggester.py # Attack path → command mapping
├── pwned_tracker.py     # Pwned user tracking in Neo4j
├── enumerators/         # Pre-auth enumeration plugins
│   ├── base.py          # Enumerator ABC
│   ├── enum4linux.py    # SMB/RPC enumeration
│   ├── ldapsearch.py    # LDAP enumeration
│   └── kerbrute.py      # Kerberos user enumeration
├── cypher_queries/      # Pre-built query library
└── mappings/            # Edge and credential type mappings
```
