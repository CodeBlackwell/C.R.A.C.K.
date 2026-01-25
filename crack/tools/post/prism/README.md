# PRISM - Parse, Refine, Identify, Summarize, Map

**Distill verbose security tool output into actionable summaries.**

PRISM transforms walls of text from post-exploitation tools into clean, colorized, deduplicated credentials with persistent Neo4j storage.

## Features

- **18 Parsers** - Mimikatz, secretsdump, hashcat, CME, responder, and more
- **Directory Crawl** - Scan entire loot dumps, auto-detect parsable files
- **Neo4j Integration** - Persistent credential storage with relationships
- **Domain Reports** - Query aggregated credentials across sources
- **Dual Hostname Tracking** - Both detected and user-specified hostnames

---

## Quick Start

```bash
# Parse single file (displays + imports to Neo4j)
crack prism mimikatz.txt

# Parse with explicit hostname
crack prism mimikatz.txt --host DC01.CORP.LOCAL

# Crawl entire loot directory
crack prism crawl ./loot_dump/ --host DC01.CORP.LOCAL

# Query domain credentials from Neo4j
crack prism report --domain CORP.LOCAL

# Export report to files
crack prism report --domain CORP.LOCAL  # Creates prism-CORP_LOCAL/*.md + *.json

# Preview purge (dry run)
crack prism purge --domain CORP.LOCAL --dry-run

# JSON output (for piping)
crack prism mimikatz.txt -f json

# Skip Neo4j import
crack prism mimikatz.txt --no-neo4j
```

---

## Supported Parsers (18)

### Windows/AD
| Parser | Description | Signatures |
|--------|-------------|------------|
| **mimikatz** | sekurlsa::logonpasswords, tickets | `mimikatz`, `sekurlsa` |
| **secretsdump** | NTDS.dit, SAM hashes, Kerberos keys | `Dumping local SAM`, `:::` format |
| **kerberoast** | TGS hashes ($krb5tgs$) | `$krb5tgs$23$` |
| **asreproast** | AS-REP hashes ($krb5asrep$) | `$krb5asrep$23$` |
| **ldap** | LDAP enumeration, legacy passwords | `dn:`, `userPassword:` |
| **smbmap** | Share enumeration, high-value files | `Disk`, `READ`, `WRITE` |
| **gpp** | Group Policy Preferences cpassword | `cpassword=` |
| **crackmapexec** | CME spray results | `[+]`, `SMB`, `Pwn3d!` |
| **responder** | NetNTLMv1/v2 captured hashes | `NTLMv2-SSP`, `::` format |
| **kerbrute** | Kerbrute valid users/passwords | `VALID USERNAME`, `VALID LOGIN` |

### Cross-Platform
| Parser | Description | Signatures |
|--------|-------------|------------|
| **hashcat** | Cracked passwords (.potfile) | `hash:password` format |
| **shadow** | Linux /etc/shadow | `$6$`, `$y$`, `$5$` hashes |
| **connstring** | web.config, .env, appsettings.json | `connectionString`, `DB_PASSWORD` |
| **script** | Hardcoded creds in PS1/SH/PY/BAT | `$password=`, `api_key=` |
| **lazagne** | LaZagne JSON output | `"Password"`, software categories |
| **htpasswd** | Apache htpasswd files | `user:$apr1$` format |
| **sshkey** | Private SSH keys | `BEGIN RSA PRIVATE KEY` |
| **aws** | AWS credentials files | `aws_access_key_id` |

---

## CLI Reference

### Parse Single File
```bash
crack prism <file> [options]

Options:
  -f, --format FORMAT   Output: table (default), json, markdown
  --host, --hostname    Source hostname to associate
  -v, --verbose         Include service accounts
  -o, --output FILE     Save to file
  --no-neo4j            Skip Neo4j import
  --no-dedup            Disable deduplication
  --stats-only          Statistics only
  --parser NAME         Force specific parser
  --list-parsers        List available parsers
```

### Crawl Directory
```bash
crack prism crawl <directory> [options]

Options:
  --host, --hostname    Associate all files with this hostname
  -v, --verbose         Show all files including unparsed
  --no-neo4j            Skip Neo4j import

Example:
  crack prism crawl ./loot/ --host DC01.CORP.LOCAL
```

### Domain Report
```bash
crack prism report [options]

Options:
  --list-domains        Show all domains in database
  --domain DOMAIN       Query specific domain
  --section SECTION     Filter: users, credentials, computers, kerberos

Example:
  crack prism report --domain CORP.LOCAL
  crack prism report --domain CORP.LOCAL --section credentials
```

### Purge Data
```bash
crack prism purge [options]

Options:
  --domain DOMAIN       Purge specific domain
  --all                 Purge all PRISM data
  --dry-run             Preview without deleting
  --force               Skip confirmation

Example:
  crack prism purge --domain CORP.LOCAL --dry-run  # Preview first
  crack prism purge --domain CORP.LOCAL            # Then execute
```

---

## Architecture Overview

```
                                   ┌─────────────────┐
                                   │   Input File    │
                                   │ (or directory)  │
                                   └────────┬────────┘
                                            │
                    ┌───────────────────────▼───────────────────────┐
                    │              Parser Registry                   │
                    │  • 18 registered parsers                       │
                    │  • Auto-detection via can_parse()              │
                    │  • Lazy initialization                         │
                    └───────────────────────┬───────────────────────┘
                                            │
    ┌───────────────────┬───────────────────┼───────────────────┬───────────────────┐
    │                   │                   │                   │                   │
┌───▼───┐          ┌────▼────┐         ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
│Mimikatz│         │Secrets- │         │ Hashcat │         │   CME   │         │ Shadow  │
│ Parser │         │  dump   │         │ Potfile │         │  Spray  │         │ Parser  │
└───┬───┘          └────┬────┘         └────┬────┘         └────┬────┘         └────┬────┘
    │                   │                   │                   │                   │
    └───────────────────┴───────────────────┴───────────────────┴───────────────────┘
                                            │
                                            ▼
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                              ParsedSummary                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   │
│  │ Credentials │  │   Tickets   │  │  Sessions   │  │  Metadata   │                   │
│  │ • NTLM      │  │ • TGT       │  │ • Auth ID   │  │ • Hostname  │                   │
│  │ • Cleartext │  │ • TGS       │  │ • Domain    │  │ • Domain    │                   │
│  │ • SHA1      │  │ • .kirbi    │  │ • User      │  │ • specified │                   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘                   │
└───────────────────────────────────────────┬───────────────────────────────────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              │                             │                             │
   ┌──────────▼──────────┐       ┌──────────▼──────────┐       ┌──────────▼──────────┐
   │   Rich Console      │       │     File Export     │       │      Neo4j          │
   │   (PrismFormatter)  │       │   (.json, .md)      │       │   (Credential DB)   │
   │                     │       │                     │       │                     │
   │  Colorized tables   │       │  Portable export    │       │  Graph storage      │
   │  High-value tags    │       │  Untruncated data   │       │  Domain reports     │
   └─────────────────────┘       └─────────────────────┘       └─────────────────────┘
```

---

## Module Structure

```
prism/
├── __init__.py              # Package exports
├── __main__.py              # python -m prism support
├── cli.py                   # CLI: parse, crawl, report, purge
│
├── models/                  # Data structures
│   ├── credential.py        # Credential + CredentialType enum
│   ├── ticket.py            # KerberosTicket
│   ├── session.py           # LogonSession (groups creds)
│   └── summary.py           # ParsedSummary (aggregate)
│
├── parsers/                 # Parser framework (18 parsers)
│   ├── base.py              # Abstract PrismParser + set_hostname()
│   ├── registry.py          # Auto-detection registry
│   ├── mimikatz/            # Windows memory dumps
│   ├── secretsdump/         # NTDS/SAM hashes
│   ├── kerberoast/          # TGS tickets
│   ├── hashcat/             # Cracked passwords
│   ├── shadow/              # Linux shadow files
│   ├── connstring/          # Config file credentials
│   ├── script/              # Hardcoded passwords
│   ├── crackmapexec/        # CME spray results
│   ├── responder/           # NetNTLM captures
│   ├── lazagne/             # Multi-source JSON
│   ├── kerbrute/            # Bruteforce results
│   ├── aws/                 # AWS credentials
│   ├── sshkey/              # Private keys
│   ├── htpasswd/            # Apache auth files
│   ├── gpp/                 # Group Policy Preferences
│   ├── ldap/                # LDAP enumeration
│   └── smbmap/              # Share enumeration
│
├── display/                 # Output formatting
│   └── formatter.py         # Rich tables, JSON, Markdown
│
├── neo4j/                   # Persistence layer
│   └── adapter.py           # Neo4j credential storage + reports
│
└── samples/                 # Demo data for testing
    ├── mimikatz_logonpasswords.txt
    ├── secretsdump_ntds.txt
    ├── hashcat_cracked.potfile
    ├── web.config
    ├── shadow_dump.txt
    └── loot_dump/           # Multi-file crawl demo
```

---

## Data Models

### Credential
```python
@dataclass
class Credential:
    username: str
    domain: str
    cred_type: CredentialType    # CLEARTEXT, NTLM, SHA1, etc.
    value: str
    sid: Optional[str]
    source: Optional[str]        # Tool that extracted it

    # Properties
    is_machine_account   # username ends with $
    is_service_account   # DWM-1, LOCAL SERVICE, etc.
    high_value           # cleartext or real user NTLM
    dedup_key            # tuple for exact-match dedup
```

### CredentialType Enum
```python
class CredentialType(Enum):
    CLEARTEXT = "cleartext"      # Most valuable
    NTLM = "ntlm"                 # Pass-the-hash
    NETNTLMV1 = "netntlmv1"       # Relay/crack
    NETNTLMV2 = "netntlmv2"       # Relay/crack
    SHA1 = "sha1"                 # Less useful
    SHA512 = "sha512"             # Linux shadow
    TGS_HASH = "tgs_hash"         # Kerberoast
    ASREP_HASH = "asrep_hash"     # AS-REP roast
    SSH_KEY = "ssh_key"           # Private keys
    AWS_KEY = "aws_key"           # Cloud access
    CONNECTION_STRING = "connection_string"
    ...
```

### ParsedSummary
```python
@dataclass
class ParsedSummary:
    source_file: str
    source_tool: str
    source_hostname: str         # Auto-detected
    specified_hostname: str      # User-provided --host
    source_domain: str
    credentials: List[Credential]
    tickets: List[KerberosTicket]
    sessions: List[LogonSession]

    # Properties
    effective_hostname     # specified > detected > "Unknown"
    display_hostname       # "DC01 (detected: WIN-ABC)" format
    cleartext_creds        # High value filter
    ntlm_hashes            # NTLM only
    high_value_creds       # Combined high-value

    # Methods
    deduplicate()          # Return deduped copy
    to_dict()              # Serialize
```

---

## Neo4j Integration

### Schema
```cypher
// Credential node
(:Credential {
    id: "user@DOMAIN:ntlm",
    username: "Administrator",
    domain: "CORP",
    cred_type: "ntlm",
    value: "a51493b0b06e5e35f855245e71af1d14",
    high_value: true,
    source_tool: "mimikatz",
    first_seen: datetime(),
    occurrences: 1
})

// Relationships
(:Credential)-[:EXTRACTED_FROM]->(:Computer {name: "DC01"})
(:Credential)-[:BELONGS_TO]->(:Domain {name: "CORP.LOCAL"})
```

### Useful Queries
```cypher
// All cleartext passwords
MATCH (c:Credential {cred_type: "cleartext"})
RETURN c.username, c.domain, c.value

// High-value credentials from specific host
MATCH (c:Credential {high_value: true})-[:EXTRACTED_FROM]->(h:Computer {name: "DC01"})
RETURN c

// Credential reuse across hosts
MATCH (c1:Credential)-[:EXTRACTED_FROM]->(h1:Computer),
      (c2:Credential)-[:EXTRACTED_FROM]->(h2:Computer)
WHERE c1.value = c2.value AND h1 <> h2
RETURN c1.username, c1.value, collect(DISTINCT h1.name) as hosts
```

---

## Display System

### Console Output (Rich)
```
┌──────────────────────────────────────────────────────────────┐
│              PRISM - Mimikatz Credential Summary             │
├──────────────────────────────────────────────────────────────┤
│ Source: DC01.CORP.LOCAL (detected: WIN-ABC123)               │
│ Sessions: 5 | Unique Creds: 8 | High Value: 2                │
└──────────────────────────────────────────────────────────────┘

CLEARTEXT CREDENTIALS (HIGH VALUE)
┌──────────────────────────────────────────────────────────────┐
│ Username │ Domain │ Password    │ Source   │
│ svc_sql  │ CORP   │ Summer2024! │ wdigest  │
└──────────────────────────────────────────────────────────────┘

NTLM HASHES
┌──────────────────────────────────────────────────────────────┐
│ Username      │ Domain │ NTLM                             │ Type    │
│ Administrator │ CORP   │ a51493b0b06e5e35f855245e71af1d14 │ User    │
│ DC01$         │ CORP   │ 983e73c648db56f78e9dfb9698066734 │ Machine │
└──────────────────────────────────────────────────────────────┘
```

### Color Scheme
| Section    | Border Color | Purpose                    |
|------------|--------------|----------------------------|
| Cleartext  | Yellow       | HIGH VALUE - immediate use |
| NTLM       | Blue         | Pass-the-hash potential    |
| NetNTLM    | Cyan         | Relay or crack             |
| TGS Hash   | Magenta      | Kerberoast cracking        |
| SSH Keys   | Red          | Direct access              |

---

## Adding a New Parser

### 1. Create Parser Module
```
prism/parsers/
└── myparser/
    ├── __init__.py      # Export parser class
    └── parser.py        # Main parser with @register
```

### 2. Implement Parser Class
```python
# prism/parsers/myparser/parser.py

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType

@PrismParserRegistry.register
class MyParser(PrismParser):

    @property
    def name(self) -> str:
        return "myparser"

    @property
    def description(self) -> str:
        return "My custom output parser"

    def can_parse(self, filepath: str) -> bool:
        """Detect myparser output"""
        content = self.read_file(filepath)[:2048]
        return 'MY_SIGNATURE' in content

    def parse(self, filepath: str, hostname=None) -> ParsedSummary:
        content = self.read_file(filepath)
        summary = ParsedSummary(
            source_file=filepath,
            source_tool='myparser'
        )

        # Use helper for hostname handling
        detected_host = self._detect_hostname(content)
        self.set_hostname(summary, detected_host, hostname)

        # Parse credentials...
        for match in MY_PATTERN.finditer(content):
            summary.credentials.append(Credential(
                username=match.group('user'),
                domain=summary.effective_hostname,
                cred_type=CredentialType.CLEARTEXT,
                value=match.group('password')
            ))

        return summary.deduplicate()
```

### 3. Register in Init
```python
# prism/parsers/myparser/__init__.py
from .parser import MyParser
```

### 4. Import in Registry
```python
# prism/parsers/registry.py (at bottom)
from . import myparser
```

### 5. Test
```bash
crack prism --list-parsers
# Should show: myparser - My custom output parser
```

---

## Demo System

A 3-terminal tmux demo is available for showcasing PRISM capabilities:

```bash
cd demonstrations/01-prism
./demo.sh
```

Features:
- **Terminal 1 (Main)**: Interactive menu
- **Terminal 2 (RAW)**: Shows raw file content
- **Terminal 3 (PRISM)**: Shows PRISM-processed output

Menu options include all 18 parsers plus features like crawl, report, and purge.

---

## Design Decisions

### Dual Hostname Tracking
- `source_hostname`: Auto-detected from file content
- `specified_hostname`: User-provided via `--host` flag
- `effective_hostname`: Specified takes precedence
- `display_hostname`: Shows both when different

### Conservative Deduplication
- Exact match on `(username, domain, type, value)`
- Never merge credentials that might be different
- Track occurrence count for forensic purposes

### Service Account Filtering
- Hidden by default: DWM-1, UMFD-0, LOCAL SERVICE, etc.
- Machine accounts (ending in $) always shown
- Use `-v` for complete view

### Neo4j Default Import
- Credentials imported by default (single source of truth)
- Use `--no-neo4j` for one-off analysis
- Silent skip if Neo4j unavailable

---

## Version History

| Version | Changes |
|---------|---------|
| 2.0.0   | 11 new parsers (18 total), crawl, report, purge, dual hostname tracking, demo system |
| 1.0.0   | Initial: mimikatz, secretsdump, kerberoast, ldap, smbmap, gpp, Neo4j, Rich display |
