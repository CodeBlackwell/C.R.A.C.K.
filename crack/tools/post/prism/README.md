# PRISM - Parse, Refine, Identify, Summarize, Map

**Distill verbose security tool output into actionable summaries.**

PRISM transforms walls of text from post-exploitation tools (mimikatz, secretsdump, etc.) into clean, colorized, deduplicated credentials with persistent Neo4j storage.

## Quick Start

```bash
# Parse mimikatz output (displays + imports to Neo4j)
crack prism mimikatz.txt

# JSON output (for piping)
crack prism mimikatz.txt -f json

# Skip Neo4j import
crack prism mimikatz.txt --no-neo4j

# Save to file
crack prism mimikatz.txt -o creds.json
```

---

## Architecture Overview

```
                                   ┌─────────────────┐
                                   │   Input File    │
                                   │ (mimikatz.txt)  │
                                   └────────┬────────┘
                                            │
                    ┌───────────────────────▼───────────────────────┐
                    │              Parser Registry                   │
                    │  • Auto-detection via can_parse()              │
                    │  • Lazy initialization                         │
                    │  • @register decorator pattern                 │
                    └───────────────────────┬───────────────────────┘
                                            │
           ┌────────────────────────────────┼────────────────────────────────┐
           │                                │                                │
┌──────────▼──────────┐          ┌──────────▼──────────┐          ┌──────────▼──────────┐
│   MimikatzParser    │          │   SecretsDump       │          │    [Future]         │
│   (logonpasswords   │          │   (NTDS.dit,        │          │    Parser           │
│    + tickets)       │          │    SAM, etc.)       │          │                     │
└──────────┬──────────┘          └─────────────────────┘          └─────────────────────┘
           │
           │ State Machine Parsing
           ▼
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                              ParsedSummary                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                   │
│  │ Credentials │  │   Tickets   │  │  Sessions   │  │  Metadata   │                   │
│  │ • NTLM      │  │ • TGT       │  │ • Auth ID   │  │ • Hostname  │                   │
│  │ • Cleartext │  │ • TGS       │  │ • Domain    │  │ • Domain    │                   │
│  │ • SHA1      │  │ • Saved .kirbi│ │ • User     │  │ • Stats     │                   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘                   │
└───────────────────────────────────────────┬───────────────────────────────────────────┘
                                            │
              ┌─────────────────────────────┼─────────────────────────────┐
              │                             │                             │
   ┌──────────▼──────────┐       ┌──────────▼──────────┐       ┌──────────▼──────────┐
   │   Rich Console      │       │     JSON/Markdown   │       │      Neo4j          │
   │   (PrismFormatter)  │       │     (File Output)   │       │   (Credential DB)   │
   │                     │       │                     │       │                     │
   │  Colorized tables   │       │  Portable export    │       │  Graph storage      │
   │  High-value emphasis│       │  For integration    │       │  Relationships      │
   └─────────────────────┘       └─────────────────────┘       └─────────────────────┘
```

---

## Module Structure

```
prism/
├── __init__.py              # Package exports
├── __main__.py              # python -m prism support
├── cli.py                   # CLI (crack prism ...)
│
├── models/                  # Data structures
│   ├── credential.py        # Credential + CredentialType enum
│   ├── ticket.py            # KerberosTicket
│   ├── session.py           # LogonSession (groups creds)
│   └── summary.py           # ParsedSummary (aggregate)
│
├── parsers/                 # Parser framework
│   ├── base.py              # Abstract PrismParser
│   ├── registry.py          # Auto-detection registry
│   └── mimikatz/            # Mimikatz parser
│       ├── parser.py        # Orchestrator
│       ├── patterns.py      # Compiled regex
│       ├── logonpasswords.py# sekurlsa::logonpasswords
│       └── tickets.py       # sekurlsa::tickets
│
├── display/                 # Output formatting
│   └── formatter.py         # Rich, JSON, Markdown
│
└── neo4j/                   # Persistence layer
    └── adapter.py           # Neo4j credential storage
```

---

## Data Flow

### 1. Parser Selection
```python
# Registry auto-detects based on file content
parser = PrismParserRegistry.get_parser(filepath)
# Returns MimikatzParser if "mimikatz" signatures found
```

### 2. Parsing (State Machine)
```
File Content → Line Iterator → State Machine → LogonSession → ParsedSummary
                                    │
    States: IDLE → IN_SESSION → IN_MSV/WDIGEST/KERBEROS/CREDMAN → IDLE
                                    │
    Each state extracts credentials based on provider context
```

### 3. Deduplication
```python
summary = summary.deduplicate()
# Conservative: exact match on (username, domain, type, value)
# Tracks occurrence count for reporting
```

### 4. Output Routing
```
ParsedSummary
     │
     ├─▶ PrismFormatter.render_summary()  → Rich tables to console
     ├─▶ JSONFormatter.format()           → JSON string
     ├─▶ MarkdownFormatter.format()       → Markdown tables
     └─▶ PrismNeo4jAdapter.import_summary() → Neo4j nodes + relationships
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

    # Properties
    is_machine_account   # username ends with $
    is_service_account   # DWM-1, LOCAL SERVICE, etc.
    high_value           # cleartext or real user NTLM
    dedup_key            # tuple for exact-match dedup
```

### CredentialType Enum
```python
class CredentialType(Enum):
    CLEARTEXT = "cleartext"    # Most valuable
    NTLM = "ntlm"              # Pass-the-hash
    SHA1 = "sha1"              # Less useful
    MACHINE_HEX = "machine_hex"# Machine account blob
    LM = "lm"                  # Legacy
    AES256 = "aes256"          # Kerberos keys
```

### KerberosTicket
```python
@dataclass
class KerberosTicket:
    service_type: str      # krbtgt, cifs, ldap
    service_target: str    # dc01.domain.local
    client_name: str       # HOSTNAME$ or user
    client_realm: str      # DOMAIN.LOCAL
    end_time: datetime
    saved_path: str        # .kirbi file if exported

    # Properties
    is_tgt                 # service_type == krbtgt
    is_tgs                 # not TGT
    is_expired             # end_time < now
    time_remaining         # human-readable
```

### ParsedSummary
```python
@dataclass
class ParsedSummary:
    credentials: List[Credential]
    tickets: List[KerberosTicket]
    sessions: List[LogonSession]

    # Properties
    cleartext_creds        # High value filter
    ntlm_hashes            # NTLM only
    tgt_tickets            # TGT filter
    tgs_tickets            # TGS filter
    high_value_creds       # Combined high-value
    stats                  # Count dictionary

    # Methods
    deduplicate()          # Return deduped copy
    to_dict()              # Serialize
```

---

## Parser Framework

### Abstract Base
```python
class PrismParser(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """e.g., 'mimikatz'"""

    @abstractmethod
    def can_parse(self, filepath: str) -> bool:
        """Return True if this parser handles this file"""

    @abstractmethod
    def parse(self, filepath: str, hostname: Optional[str]) -> ParsedSummary:
        """Parse file, return structured summary"""
```

### Registry Pattern
```python
@PrismParserRegistry.register
class MimikatzParser(PrismParser):
    ...

# Auto-detection:
parser = PrismParserRegistry.get_parser("output.txt")
if parser:
    summary = parser.parse("output.txt")
```

---

## Adding a New Parser

### 1. Create Parser Module
```
prism/parsers/
└── secretsdump/
    ├── __init__.py      # Export parser class
    ├── parser.py        # Main parser with @register
    └── patterns.py      # Regex patterns
```

### 2. Implement Parser Class
```python
# prism/parsers/secretsdump/parser.py

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType

@PrismParserRegistry.register
class SecretsDumpParser(PrismParser):

    @property
    def name(self) -> str:
        return "secretsdump"

    @property
    def description(self) -> str:
        return "Impacket secretsdump output parser"

    def can_parse(self, filepath: str) -> bool:
        """Detect secretsdump output"""
        content = self.read_file(filepath)[:2048]
        return '[*] Dumping local SAM hashes' in content or \
               '[*] Dumping Domain Credentials' in content

    def parse(self, filepath: str, hostname=None) -> ParsedSummary:
        content = self.read_file(filepath)
        summary = ParsedSummary(
            source_file=filepath,
            source_tool='secretsdump'
        )

        # Parse SAM hashes: user:rid:lm:ntlm:::
        for line in content.splitlines():
            if ':::' in line:
                parts = line.split(':')
                if len(parts) >= 4:
                    summary.credentials.append(Credential(
                        username=parts[0],
                        domain=hostname or '',
                        cred_type=CredentialType.NTLM,
                        value=parts[3]
                    ))

        return summary.deduplicate()
```

### 3. Register in Init
```python
# prism/parsers/__init__.py
from . import secretsdump  # Triggers @register decorator
```

### 4. Test Detection
```bash
crack prism --list-parsers
# Should show: secretsdump - Impacket secretsdump output parser
```

---

## Neo4j Integration

### Schema
```cypher
// Credential node
(:Credential {
    id: "user@DOMAIN:ntlm",
    username: "Administrator",
    domain: "SECURE",
    cred_type: "ntlm",
    value: "a51493b0b06e5e35f855245e71af1d14",
    high_value: true,
    is_machine: false,
    first_seen: datetime(),
    occurrences: 1
})

// Relationships
(:Credential)-[:EXTRACTED_FROM]->(:Computer {name: "SECURE"})
(:Credential)-[:BELONGS_TO]->(:Domain {name: "SECURA"})

// Tickets
(:KerberosTicket {
    id: "SECURE$@SECURA.YZX:krbtgt",
    service_type: "krbtgt",
    client_name: "SECURE$",
    is_tgt: true
})-[:EXTRACTED_FROM]->(:Computer)
```

### Queries
```cypher
// All cleartext passwords
MATCH (c:Credential {cred_type: "cleartext"})
RETURN c.username, c.domain, c.value

// High-value credentials from specific host
MATCH (c:Credential {high_value: true})-[:EXTRACTED_FROM]->(h:Computer {name: "SECURE"})
RETURN c

// Credential reuse across hosts
MATCH (c1:Credential)-[:EXTRACTED_FROM]->(h1:Computer),
      (c2:Credential)-[:EXTRACTED_FROM]->(h2:Computer)
WHERE c1.value = c2.value AND h1 <> h2
RETURN c1.username, c1.value, collect(h1.name) as hosts
```

---

## Display System

### Console Output (Rich)
```
┌──────────────────────────────────────────────────────────────┐
│              PRISM - Mimikatz Credential Summary             │
├──────────────────────────────────────────────────────────────┤
│ Source: SECURE.SECURA                                        │
│ Sessions: 5 | Unique Creds: 8 | High Value: 2                │
└──────────────────────────────────────────────────────────────┘

CLEARTEXT CREDENTIALS (HIGH VALUE)
┌──────────────────────────────────────────────────────────────┐
│ Username │ Domain │ Password    │ Source   │
│ apache   │ era... │ New2Era4.!  │ credman  │
└──────────────────────────────────────────────────────────────┘

NTLM HASHES
┌──────────────────────────────────────────────────────────────┐
│ Username      │ Domain │ NTLM                             │ Type    │
│ Administrator │ SECURE │ a51493b0b06e5e35f855245e71af1d14 │ User    │
│ SECURE$       │ SECURA │ 983e73c648db56f78e9dfb9698066734 │ Machine │
└──────────────────────────────────────────────────────────────┘
```

### Color Scheme
| Section    | Border Color | Purpose                    |
|------------|--------------|----------------------------|
| Cleartext  | Yellow       | HIGH VALUE - immediate use |
| NTLM       | Blue         | Pass-the-hash potential    |
| SHA1       | Magenta      | Reference only             |
| TGT        | Magenta      | Golden ticket material     |
| TGS        | Cyan         | Service access             |

---

## CLI Reference

```
crack prism <file> [options]

Positional:
  file                  File to parse

Options:
  -f, --format          Output format: table (default), json, markdown
  --host, --hostname    Override source hostname
  -v, --verbose         Show all creds including service accounts
  -o, --output FILE     Save output to file (.json, .md auto-detected)
  --no-neo4j            Skip Neo4j import (imports by default)
  --no-dedup            Disable deduplication
  --stats-only          Show statistics only
  --parser NAME         Force specific parser
  --list-parsers        List available parsers

Examples:
  crack prism dump.txt                    # Auto-detect, display, import
  crack prism dump.txt -f json            # JSON output (pipe-friendly)
  crack prism dump.txt -o report.json     # Also save to file
  crack prism dump.txt --no-neo4j         # Display only
  crack prism dump.txt -v                 # Include service accounts
```

---

## Design Decisions

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

### Parser Auto-Detection
- Check file content, not extension
- Multiple signature checks for reliability
- Fallback to explicit `--parser` flag

---

## Extending PRISM

### Add New Credential Type
```python
# models/credential.py
class CredentialType(Enum):
    ...
    DPAPI_KEY = "dpapi_key"
```

### Add New Ticket Field
```python
# models/ticket.py
@dataclass
class KerberosTicket:
    ...
    session_key: Optional[str] = None
```

### Custom Display Section
```python
# display/formatter.py
def _render_dpapi_table(self, keys: list) -> None:
    """Render DPAPI master keys"""
    ...
```

---

## Performance Notes

- Regex patterns compiled at module load
- State machine minimizes backtracking
- Lazy parser initialization (only when needed)
- File read with encoding fallback (UTF-8 → Latin-1)
- Neo4j uses batch MERGE for efficiency

---

## Version History

| Version | Changes |
|---------|---------|
| 1.0.0   | Initial: mimikatz (logonpasswords, tickets), Neo4j, Rich display |
