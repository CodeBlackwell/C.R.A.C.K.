# Service Relationship Mapper - Tool Specification

## Executive Summary
A revolutionary penetration testing tool that automatically discovers relationships between services, maps attack chains, and suggests exploitation paths based on discovered service dependencies and trust relationships.

**Problem**: Penetration testers manually piece together how services interact, missing potential attack chains.
**Solution**: Automated service relationship discovery and attack chain generation.
**Innovation**: No existing tool provides holistic service mapping with attack chain intelligence.

---

## Core Concept

The Service Relationship Mapper (SRM) automatically:
1. Discovers relationships between services (web → database → filesystem)
2. Identifies trust relationships and data flows
3. Generates potential attack chains based on discovered relationships
4. Prioritizes exploitation paths by likelihood of success
5. Provides specific exploitation recommendations

---

## Input Sources

### Network Scanning
- Port relationships (80→3306, 443→5432)
- Service banners (Apache/2.4.25 + PHP/7.0.30)
- Backend indicators (X-Powered-By headers)

### Configuration Mining
- Web config files (wp-config.php → MySQL credentials)
- Apache/Nginx configs (proxy_pass → backend services)
- Connection strings (web.config → MSSQL)
- Environment variables (.env files)

### Response Analysis
- Error messages ("MySQL error" → database type)
- Stack traces (reveals framework + dependencies)
- Debug pages (Django debug → Python stack)
- Headers (ASP.NET → IIS → Windows)

---

## Relationship Types

### Direct Dependencies
```
Web → Database (PHP → MySQL)
Web → Cache (Node → Redis)
Web → Queue (Python → RabbitMQ)
Web → Storage (Rails → PostgreSQL)
```

### Authentication Chains
```
Web → LDAP → Active Directory
Web → OAuth → Provider
Web → SAML → IdP
Web → Database → User table
```

### Data Flow Paths
```
User → Web → API → Database
Upload → Web → Filesystem → Process
Form → Web → Queue → Worker → Database
Request → Proxy → Backend → Database
```

### Trust Relationships
- Same server (shared localhost)
- Same network (internal subnet)
- Shared credentials (reused passwords)
- Shared filesystem (mounted volumes)

---

## Attack Chain Generation

### SQL Injection Chains
```
Web SQLi → Database access
    → READ FILES → Web config → More credentials
    → WRITE FILES → Webshell → RCE
    → xp_cmdshell/UDF → System command execution
```

### File Operation Chains
```
LFI → Config files → Database credentials
Directory traversal → SSH keys → Lateral movement
File upload → Web shell → Reverse shell
Template injection → File write → RCE
```

### Credential Chains
```
Web admin → Database admin → System user
Config file → Database → User hashes → Crack
SNMP → Community string → Device access
API key → Backend service → Data access
```

### Protocol Chains
```
HTTP → Redis (unauthenticated) → Write SSH key
HTTP → Memcached → Cache poisoning
HTTP → MongoDB → NoSQL injection
HTTP → Docker API → Container escape
```

---

## Pattern Recognition

### Common Stacks
- **LAMP**: Linux, Apache, MySQL, PHP
- **MEAN**: MongoDB, Express, Angular, Node
- **WAMP**: Windows, Apache, MySQL, PHP
- **Django Stack**: Django + PostgreSQL + Redis + Celery

### Vulnerability Patterns
- Old PHP + MySQL = SQL injection likely
- Struts = Remote code execution vulnerabilities
- WordPress + Plugins = Multiple attack vectors
- Deserialization vulnerabilities (Java, Python, PHP, .NET)

### Default Configurations
- Redis (no auth) → Write to filesystem
- MongoDB (no auth) → Database dump
- Elasticsearch (public) → Data exposure
- Jenkins (no auth) → Script console RCE

---

## Output Formats

### Attack Recommendations
```
"SQLi on port 80 likely yields MySQL access on 3306"
"LFI can read /etc/mysql/debian.cnf for credentials"
"Redis on 6379 allows webshell via SSH key write"
"Upload to /tmp, execute via cron or PHP include"
```

### Priority Rankings
- **Critical**: Direct database access, unauthenticated RCE
- **High**: Authenticated RCE paths
- **Medium**: Authenticated escalation
- **Low**: Information disclosure only

### Export Formats
- JSON (for automation)
- Markdown (for documentation)
- GraphML (for visualization tools)
- MITRE ATT&CK mapping

---

## Example Usage

### Basic Web Application Assessment
```bash
crack service-map https://192.168.45.100

# Output:
[+] Discovered Services:
    - Apache 2.4.25 (port 80/443)
    - PHP 7.0.30
    - MySQL 5.7 (port 3306)

[+] Relationships:
    - Apache serves PHP files
    - PHP connects to MySQL (localhost:3306)
    - Config found: /var/www/config.php

[!] Attack Chains Identified:
    1. SQLi → FILE privilege → Write webshell
       Confidence: 85%
       Command: sqlmap --file-write shell.php --file-dest /var/www/html/

    2. LFI → Read config → Database credentials
       Confidence: 70%
       Path: ../../../../../../etc/mysql/debian.cnf

    3. File upload → PHP execution
       Confidence: 60%
       Target: /uploads/ directory (writable)
```

### Network-Wide Service Discovery
```bash
crack service-map --network 192.168.45.0/24

# Output:
[+] Service Clusters:
    - Web Tier: .100, .101, .102 (Apache + PHP)
    - Database: .200 (MySQL)
    - Cache: .150 (Redis - NO AUTHENTICATION)

[!] Critical Finding:
    Redis instance allows arbitrary file writes

[*] Attack Chain:
    1. Connect to Redis on .150:6379
    2. Write SSH key to /var/www/.ssh/authorized_keys
    3. SSH to all web servers (.100-.102)
    4. Read database credentials from config files
    5. Access MySQL on .200
```

### Configuration-Based Discovery
```bash
crack service-map --config wp-config.php

# Output:
[+] Extracted Relationships:
    - MySQL: db.internal.local:3306
    - Redis cache: 127.0.0.1:6379
    - WordPress admin user: admin

[*] Attack Options:
    1. Local Redis exploitation (same server)
    2. MySQL credential reuse on system
    3. WordPress plugin upload → RCE
```

---

## Implementation Phases

### Phase 1: Core Discovery (MVP)
- Port scanning integration
- Service banner parsing
- Basic relationship mapping
- Simple text output

### Phase 2: Intelligence Layer
- Config file parsing
- Error message analysis
- Attack chain generation
- Confidence scoring

### Phase 3: Advanced Features
- Graph visualization
- Real-time updates
- Integration with other tools
- Machine learning for pattern recognition

---

## Technical Architecture

### Components
```
Input Layer:
├── Scanner Module (nmap integration)
├── Config Parser (regex patterns)
├── Response Analyzer (error detection)
└── Manual Input (known relationships)

Processing Layer:
├── Relationship Engine (graph database)
├── Pattern Matcher (vulnerability signatures)
├── Chain Generator (attack path algorithm)
└── Risk Calculator (CVSS-based scoring)

Output Layer:
├── CLI Interface (text/JSON output)
├── Web Interface (graph visualization)
├── Report Generator (markdown/PDF)
└── API (integration with other tools)
```

### Data Structure
```python
{
    "services": [
        {
            "id": "web-001",
            "type": "Apache",
            "version": "2.4.25",
            "port": 80,
            "host": "192.168.45.100"
        }
    ],
    "relationships": [
        {
            "from": "web-001",
            "to": "db-001",
            "type": "database_connection",
            "confidence": 0.95
        }
    ],
    "attack_chains": [
        {
            "name": "SQLi to RCE",
            "steps": ["sqli", "file_write", "webshell"],
            "confidence": 0.85,
            "commands": ["sqlmap --file-write..."]
        }
    ]
}
```

---

## Unique Value Proposition

### What Makes This Different
1. **Holistic View**: Maps entire service ecosystem, not individual vulnerabilities
2. **Attack Intelligence**: Generates specific attack chains, not just vulnerability lists
3. **Relationship Focus**: Understands how services trust and communicate
4. **Actionable Output**: Provides exact commands and exploitation steps
5. **Learning System**: Improves recommendations based on success/failure feedback

### Gap in Current Tools
- **Nmap**: Discovers services but not relationships
- **Metasploit**: Exploits services but doesn't map dependencies
- **BloodHound**: Maps AD relationships but not general services
- **Nuclei**: Scans for vulnerabilities but doesn't chain them
- **SRM**: Combines all aspects into unified attack chain intelligence

---

## Success Metrics

### Quantifiable Benefits
- Reduce service enumeration time by 70%
- Identify 3x more attack paths than manual analysis
- Decrease time-to-first-shell by 50%
- Document relationships for reporting in seconds vs hours

### OSCP Exam Value
- Quickly understand complex multi-service targets
- Identify non-obvious attack chains
- Prioritize exploitation attempts
- Generate documentation for exam report

---

## Development Roadmap

### Month 1: Foundation
- [ ] Basic service discovery
- [ ] Simple relationship mapping
- [ ] Text-based output

### Month 2: Intelligence
- [ ] Config file parsing
- [ ] Attack chain generation
- [ ] Confidence scoring

### Month 3: Polish
- [ ] Graph visualization
- [ ] Export formats
- [ ] Tool integrations

### Future Enhancements
- Machine learning for pattern recognition
- Cloud service mapping (AWS, Azure)
- Container/Kubernetes relationships
- Real-time monitoring mode
- Collaborative attack chain database

---

## Conclusion

The Service Relationship Mapper fills a critical gap in penetration testing methodology. By automatically discovering and visualizing service relationships, then generating specific attack chains, it transforms how penetration testers approach complex environments.

**This tool doesn't exist today, but it should.**

---

## Contact & Contribution

This specification is open for community input and collaboration.
- **Status**: Concept/Specification
- **Priority**: High
- **Estimated Development**: 3-6 months for MVP
- **Technology Stack**: Python, NetworkX (graphs), SQLite (storage)

---

*Last Updated: October 2024*
*Document Version: 1.0*