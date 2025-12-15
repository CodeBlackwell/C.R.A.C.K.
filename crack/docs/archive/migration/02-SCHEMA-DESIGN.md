# 02 - Schema Design: Neo4j Graph Model

## Prerequisites
- [00-ARCHITECTURE.md](00-ARCHITECTURE.md) - Understanding of dual backend approach
- [01-ENVIRONMENT.md](01-ENVIRONMENT.md) - Neo4j environment running

## Overview

Complete Neo4j graph schema mapping from PostgreSQL relational model to Neo4j labeled property graph.

---

## Design Philosophy

### From Relational to Graph

**PostgreSQL Thinking**: Tables + Foreign Keys + JOIN operations
**Neo4j Thinking**: Nodes + Relationships + MATCH patterns

**Key Transformations**:
1. **Tables → Node Labels**: `commands` table → `(:Command)` nodes
2. **Foreign Keys → Relationships**: `command_tags.command_id` → `(:Command)-[:TAGGED]->(:Tag)`
3. **Junction Tables → Direct Relationships**: `command_relations` → `(:Command)-[:PREREQUISITE]->(:Command)`
4. **Attributes → Properties**: `commands.oscp_relevance` → `command.oscp_relevance`

---

## Node Labels

### Core Entities (11 Node Types)

```cypher
// Command system
(:Command)          // 1200+ nodes from commands table
(:Variable)         // 50+ nodes from variables table
(:Tag)              // 100+ nodes from tags table
(:Flag)             // 500+ nodes (extracted from command_flags)

// Service mapping
(:Service)          // 30+ nodes from services table
(:Port)             // 100+ nodes (extracted from service_ports)

// Attack chains
(:AttackChain)      // 50+ nodes from attack_chains table
(:ChainStep)        // 300+ nodes from chain_steps table
(:Prerequisite)     // 150+ nodes (extracted from chain_prerequisites)

// Findings
(:FindingType)      // 40+ nodes from finding_types table
(:Indicator)        // 200+ nodes (success/failure patterns)
```

### Node Property Schemas

#### (:Command) Node

```cypher
CREATE (cmd:Command {
  id: "nmap-quick-scan",                    // PRIMARY KEY
  name: "Quick Full Port Scan",
  template: "nmap -Pn -p- --min-rate=<RATE> <TARGET> -oA <OUTPUT>",
  description: "Fast scan of all 65535 ports",
  category: "recon",                        // enum: recon|web|exploitation|post-exploit
  subcategory: "enumeration",
  oscp_relevance: "high",                   // enum: low|medium|high
  notes: "Use for initial port discovery",
  created_at: datetime("2025-01-15T10:00:00Z"),
  updated_at: datetime("2025-01-15T10:00:00Z")
})
```

**Constraints**:
```cypher
CREATE CONSTRAINT command_id_unique FOR (c:Command) REQUIRE c.id IS UNIQUE;
CREATE INDEX command_name_fulltext FOR (c:Command) ON (c.name, c.description);
CREATE INDEX command_category FOR (c:Command) ON (c.category);
CREATE INDEX command_oscp FOR (c:Command) ON (c.oscp_relevance);
```

---

#### (:Variable) Node

```cypher
CREATE (var:Variable {
  name: "<TARGET>",                         // Includes angle brackets
  description: "Target IP address or hostname",
  data_type: "ip",                          // enum: string|int|port|ip|path|url|domain
  default_value: "192.168.1.1",
  validation_regex: "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$",
  source: "config"                          // enum: config|env|user|auto
})
```

**Constraints**:
```cypher
CREATE CONSTRAINT variable_name_unique FOR (v:Variable) REQUIRE v.name IS UNIQUE;
```

---

#### (:Tag) Node

```cypher
CREATE (tag:Tag {
  name: "OSCP:HIGH",
  category: "priority",                     // enum: priority|technique|tool|phase
  description: "High priority for OSCP exam",
  color: "#FF0000"                          // Hex color for UI
})
```

**Constraints**:
```cypher
CREATE CONSTRAINT tag_name_unique FOR (t:Tag) REQUIRE t.name IS UNIQUE;
CREATE INDEX tag_category FOR (t:Tag) ON (t.category);
```

---

#### (:Service) Node

```cypher
CREATE (svc:Service {
  id: 1,                                    // AUTO INCREMENT from PostgreSQL
  name: "http",
  protocol: "tcp",                          // enum: tcp|udp
  description: "HTTP Web Server",
  confidence_threshold: 60.0                // Minimum detection confidence (0-100)
})
```

**Constraints**:
```cypher
CREATE CONSTRAINT service_name_unique FOR (s:Service) REQUIRE s.name IS UNIQUE;
```

---

#### (:AttackChain) Node

```cypher
CREATE (chain:AttackChain {
  id: "linux-privesc-sudo",
  name: "Linux Privilege Escalation via Sudo",
  description: "Exploit misconfigured sudo permissions",
  version: "1.0.0",
  category: "privilege_escalation",         // enum: enumeration|privilege_escalation|lateral_movement
  platform: "linux",                        // enum: linux|windows|network|web
  difficulty: "intermediate",               // enum: beginner|intermediate|advanced|expert
  time_estimate: "10 minutes",
  oscp_relevant: true,
  author: "CRACK Team",
  created_at: datetime("2025-01-10T00:00:00Z")
})
```

**Constraints**:
```cypher
CREATE CONSTRAINT chain_id_unique FOR (ac:AttackChain) REQUIRE ac.id IS UNIQUE;
CREATE INDEX chain_category FOR (ac:AttackChain) ON (ac.category);
CREATE INDEX chain_oscp FOR (ac:AttackChain) ON (ac.oscp_relevant);
```

---

#### (:ChainStep) Node

```cypher
CREATE (step:ChainStep {
  id: "check-sudo-privs",
  name: "Check Sudo Privileges",
  step_order: 1,                            // Execution sequence
  objective: "Determine what commands user can run as root",
  description: "Run 'sudo -l' to list allowed commands",
  evidence: ["(ALL : ALL) ALL", "NOPASSWD"],  // JSON array
  success_criteria: ["Output shows allowed commands"],  // JSON array
  failure_conditions: ["Password required", "User not in sudoers"]  // JSON array
})
```

**Constraints**:
```cypher
CREATE CONSTRAINT step_id_unique FOR (cs:ChainStep) REQUIRE cs.id IS UNIQUE;
```

---

## Relationship Types (14 Types)

### Command Relationships

#### 1. PREREQUISITE

**Direction**: `(:Command)-[:PREREQUISITE]->(:Command)`

**Meaning**: Source command must run BEFORE target command

**Properties**:
```cypher
CREATE (cmd1:Command {id: "nc-listener"})-[:PREREQUISITE {
  priority: 1,                              // Order if multiple prerequisites (lower = higher priority)
  condition: "Reverse shell requires listener",
  notes: "Start listener before executing payload"
}]->(cmd2:Command {id: "bash-reverse-shell"})
```

**Query Example**:
```cypher
// Get all prerequisites for a command (transitive)
MATCH path = (prereq:Command)<-[:PREREQUISITE*]-(cmd:Command {id: 'wordpress-sqli'})
RETURN prereq.name, length(path) AS depth
ORDER BY depth DESC
```

---

#### 2. ALTERNATIVE

**Direction**: `(:Command)-[:ALTERNATIVE]->(:Command)`

**Meaning**: If source fails, try target as fallback

**Properties**:
```cypher
CREATE (gobuster:Command {id: 'gobuster-dir'})-[:ALTERNATIVE {
  priority: 1,                              // Try this alternative first
  reason: "Faster enumeration",
  condition: "When wordlist is small (<10k entries)"
}]->(ffuf:Command {id: 'ffuf-dir'})
```

**Query Example**:
```cypher
// Multi-hop alternatives (if A fails → try B → try C)
MATCH path = (start:Command {id: 'gobuster-dir'})-[:ALTERNATIVE*1..3]->(alt)
RETURN alt.name, length(path) AS fallback_depth
ORDER BY fallback_depth
```

---

#### 3. NEXT_STEP

**Direction**: `(:Command)-[:NEXT_STEP]->(:Command)`

**Meaning**: After source succeeds, run target next

**Properties**:
```cypher
CREATE (nmap:Command {id: 'nmap-quick-scan'})-[:NEXT_STEP {
  priority: 1,
  description: "Enumerate services on discovered ports",
  condition: "When open ports found"
}]->(nmap_svc:Command {id: 'nmap-service-enum'})
```

**Query Example**:
```cypher
// Build attack workflow (3 steps forward)
MATCH path = (start:Command {id: 'nmap-ping-sweep'})-[:NEXT_STEP*1..3]->(next)
RETURN [node IN nodes(path) | node.name] AS workflow
```

---

#### 4. USES_VARIABLE

**Direction**: `(:Command)-[:USES_VARIABLE]->(:Variable)`

**Meaning**: Command template contains this variable placeholder

**Properties**:
```cypher
CREATE (cmd:Command {id: 'nmap-quick-scan'})-[:USES_VARIABLE {
  position: 1,                              // Order in template (for display)
  required: true,
  example: "192.168.1.100"                 // Command-specific example (overrides var.default_value)
}]->(var:Variable {name: '<TARGET>'})
```

**Query Example**:
```cypher
// Find all commands using a specific variable
MATCH (cmd:Command)-[u:USES_VARIABLE]->(var:Variable {name: '<LHOST>'})
WHERE u.required = true
RETURN cmd.name, u.example
```

---

#### 5. HAS_FLAG

**Direction**: `(:Command)-[:HAS_FLAG]->(:Flag)`

**Meaning**: Command uses this flag with explanation

**Properties**:
```cypher
CREATE (flag:Flag {
  flag: "-Pn",
  explanation: "Skip ping (assume host is up)"
})

CREATE (cmd:Command {id: 'nmap-quick-scan'})-[:HAS_FLAG {
  required: true,                           // Flag must be used
  position: 1                               // Order in command
}]->(flag)
```

**Query Example**:
```cypher
// Find all commands using a specific flag
MATCH (cmd:Command)-[:HAS_FLAG]->(flag:Flag {flag: '-Pn'})
RETURN cmd.name, cmd.category
```

---

#### 6. TAGGED

**Direction**: `(:Command)-[:TAGGED]->(:Tag)`

**Meaning**: Command has this tag for filtering

**Properties**: None (simple association)

```cypher
CREATE (cmd:Command {id: 'nmap-quick-scan'})-[:TAGGED]->(tag:Tag {name: 'OSCP:HIGH'})
```

**Query Example**:
```cypher
// Find commands matching ALL tags (AND logic)
MATCH (cmd:Command)-[:TAGGED]->(tag:Tag)
WHERE tag.name IN ['OSCP:HIGH', 'QUICK_WIN']
WITH cmd, collect(tag.name) AS tags
WHERE size(tags) = 2
RETURN cmd.name
```

---

### Service Relationships

#### 7. RUNS_ON

**Direction**: `(:Service)-[:RUNS_ON]->(:Port)`

**Meaning**: Service typically runs on this port

**Properties**:
```cypher
CREATE (port:Port {number: 80})
CREATE (svc:Service {name: 'http'})-[:RUNS_ON {
  is_default: true                          // Standard port for this service
}]->(port)
```

**Query Example**:
```cypher
// Find services for detected ports
MATCH (port:Port)<-[:RUNS_ON]-(svc:Service)
WHERE port.number IN [80, 443, 445, 22]
RETURN port.number, collect(svc.name) AS services
```

---

#### 8. ENUMERATED_BY

**Direction**: `(:Service)-[:ENUMERATED_BY]->(:Command)`

**Meaning**: Use this command to enumerate the service

**Properties**:
```cypher
CREATE (svc:Service {name: 'http'})-[:ENUMERATED_BY {
  priority: 1,                              // Run this command first
  context: "enumeration",                   // enum: enumeration|exploitation|post-exploit
  min_confidence: 60.0                      // Only suggest if service detection confidence ≥60%
}]->(cmd:Command {id: 'gobuster-dir'})
```

**Query Example**:
```cypher
// Get recommended commands for a service
MATCH (svc:Service {name: 'http'})-[e:ENUMERATED_BY]->(cmd:Command)
WHERE cmd.oscp_relevance = 'high'
RETURN cmd.name, e.priority
ORDER BY e.priority
```

---

### Attack Chain Relationships

#### 9. HAS_STEP

**Direction**: `(:AttackChain)-[:HAS_STEP]->(:ChainStep)`

**Meaning**: Attack chain contains this step

**Properties**:
```cypher
CREATE (chain:AttackChain {id: 'linux-privesc-sudo'})-[:HAS_STEP {
  order: 1                                  // Step sequence
}]->(step:ChainStep {id: 'check-sudo-privs'})
```

**Query Example**:
```cypher
// Get all steps in execution order
MATCH (chain:AttackChain {id: 'linux-privesc-sudo'})-[h:HAS_STEP]->(step:ChainStep)
RETURN step.name, h.order
ORDER BY h.order
```

---

#### 10. DEPENDS_ON

**Direction**: `(:ChainStep)-[:DEPENDS_ON]->(:ChainStep)`

**Meaning**: Source step requires target step to complete first

**Properties**:
```cypher
CREATE (step2:ChainStep {id: 'exploit-sudo'})-[:DEPENDS_ON {
  reason: "Need to know allowed commands first"
}]->(step1:ChainStep {id: 'check-sudo-privs'})
```

**Query Example**:
```cypher
// Detect parallel-executable steps (no shared dependencies)
MATCH (chain:AttackChain {id: 'linux-privesc-sudo'})-[:HAS_STEP]->(step:ChainStep)
OPTIONAL MATCH (step)-[:DEPENDS_ON]->(dep)
WITH step, collect(dep.id) AS deps
WHERE size(deps) = 0  // No dependencies
RETURN step.name AS parallel_steps
```

---

#### 11. EXECUTES

**Direction**: `(:ChainStep)-[:EXECUTES]->(:Command)`

**Meaning**: This step runs this specific command

**Properties**: None

```cypher
CREATE (step:ChainStep {id: 'check-sudo-privs'})-[:EXECUTES]->(cmd:Command {id: 'sudo-list'})
```

**Query Example**:
```cypher
// Get all commands in an attack chain
MATCH (chain:AttackChain {id: 'linux-privesc-sudo'})-[:HAS_STEP]->(step)-[:EXECUTES]->(cmd)
RETURN step.step_order, cmd.name
ORDER BY step.step_order
```

---

#### 12. REQUIRES

**Direction**: `(:AttackChain)-[:REQUIRES]->(:Prerequisite)`

**Meaning**: Attack chain requires this condition to be met

**Properties**:
```cypher
CREATE (prereq:Prerequisite {
  description: "Shell access as low-privilege user",
  priority: 1
})

CREATE (chain:AttackChain {id: 'linux-privesc-sudo'})-[:REQUIRES]->(prereq)
```

**Query Example**:
```cypher
// Check if attack chain is viable
MATCH (chain:AttackChain {id: 'linux-privesc-sudo'})-[:REQUIRES]->(prereq)
RETURN prereq.description, prereq.priority
ORDER BY prereq.priority
```

---

### Finding Relationships

#### 13. SUCCESS_PATTERN / FAILURE_PATTERN

**Direction**: `(:Command)-[:SUCCESS_PATTERN|FAILURE_PATTERN]->(:Indicator)`

**Meaning**: Command output matching this pattern indicates success/failure

**Properties**:
```cypher
CREATE (indicator:Indicator {
  pattern: "Host is up",
  type: "literal"                           // enum: literal|regex
})

CREATE (cmd:Command {id: 'nmap-ping-sweep'})-[:SUCCESS_PATTERN {
  priority: 1                               // Check high-priority patterns first
}]->(indicator)
```

**Query Example**:
```cypher
// Get all success indicators for a command
MATCH (cmd:Command {id: 'nmap-quick-scan'})-[sp:SUCCESS_PATTERN]->(ind:Indicator)
RETURN ind.pattern, sp.priority
ORDER BY sp.priority
```

---

#### 14. TRIGGERS_TASK

**Direction**: `(:FindingType)-[:TRIGGERS_TASK]->(:Command)`

**Meaning**: When this finding is discovered, automatically queue this command

**Properties**:
```cypher
CREATE (finding:FindingType {name: 'wordpress-detected'})-[:TRIGGERS_TASK {
  priority: 1,
  condition: "version < 5.0"                // Conditional trigger
}]->(cmd:Command {id: 'wpscan-vuln'})
```

**Query Example**:
```cypher
// Get auto-generated tasks for a finding
MATCH (finding:FindingType {name: 'wordpress-detected'})-[tt:TRIGGERS_TASK]->(cmd)
RETURN cmd.name, tt.priority, tt.condition
ORDER BY tt.priority
```

---

## Schema Creation Script

**File**: Reference only (actual script in `scripts/create_schema.cypher`)

```cypher
// === CONSTRAINTS (UNIQUE) ===
CREATE CONSTRAINT command_id_unique IF NOT EXISTS
  FOR (c:Command) REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT variable_name_unique IF NOT EXISTS
  FOR (v:Variable) REQUIRE v.name IS UNIQUE;

CREATE CONSTRAINT tag_name_unique IF NOT EXISTS
  FOR (t:Tag) REQUIRE t.name IS UNIQUE;

CREATE CONSTRAINT service_name_unique IF NOT EXISTS
  FOR (s:Service) REQUIRE s.name IS UNIQUE;

CREATE CONSTRAINT chain_id_unique IF NOT EXISTS
  FOR (ac:AttackChain) REQUIRE ac.id IS UNIQUE;

CREATE CONSTRAINT step_id_unique IF NOT EXISTS
  FOR (cs:ChainStep) REQUIRE cs.id IS UNIQUE;

// === INDEXES (PERFORMANCE) ===
CREATE INDEX command_name_fulltext IF NOT EXISTS
  FOR (c:Command) ON (c.name, c.description);

CREATE INDEX command_category IF NOT EXISTS
  FOR (c:Command) ON (c.category);

CREATE INDEX command_oscp IF NOT EXISTS
  FOR (c:Command) ON (c.oscp_relevance);

CREATE INDEX tag_category IF NOT EXISTS
  FOR (t:Tag) ON (t.category);

CREATE INDEX chain_category IF NOT EXISTS
  FOR (ac:AttackChain) ON (ac.category);

CREATE INDEX chain_oscp IF NOT EXISTS
  FOR (ac:AttackChain) ON (ac.oscp_relevant);

// === FULL-TEXT SEARCH INDEXES ===
CREATE FULLTEXT INDEX command_search IF NOT EXISTS
  FOR (c:Command) ON EACH [c.name, c.description, c.notes];

CREATE FULLTEXT INDEX tag_search IF NOT EXISTS
  FOR (t:Tag) ON EACH [t.name, t.description];
```

**Execution**:
```bash
cypher-shell -u neo4j -p crack_password < scripts/create_schema.cypher
```

---

## Schema Validation Queries

### Count Verification

```cypher
// Expected: 1200+ commands
MATCH (c:Command) RETURN count(c) AS command_count;

// Expected: 50+ variables
MATCH (v:Variable) RETURN count(v) AS variable_count;

// Expected: 100+ tags
MATCH (t:Tag) RETURN count(t) AS tag_count;

// Expected: 30+ services
MATCH (s:Service) RETURN count(s) AS service_count;

// Expected: 50+ attack chains
MATCH (ac:AttackChain) RETURN count(ac) AS chain_count;

// Expected: 300+ chain steps
MATCH (cs:ChainStep) RETURN count(cs) AS step_count;
```

---

### Relationship Integrity

```cypher
// Check for orphaned commands (no relationships)
MATCH (c:Command)
WHERE NOT (c)-[]-()
RETURN c.id, c.name
LIMIT 10;

// Check for circular dependencies in attack chains
MATCH path = (step:ChainStep)-[:DEPENDS_ON*]->(step)
RETURN step.id, length(path) AS cycle_length;

// Check for missing variables in commands
MATCH (c:Command)
WHERE c.template CONTAINS '<'
AND NOT (c)-[:USES_VARIABLE]->()
RETURN c.id, c.template
LIMIT 10;
```

---

## Schema Visualization

**Sample Graph Structure**:

```
(:Command {id: "nmap-quick-scan"})
  ├─[:USES_VARIABLE]→ (:Variable {name: "<TARGET>"})
  ├─[:USES_VARIABLE]→ (:Variable {name: "<RATE>"})
  ├─[:HAS_FLAG]→ (:Flag {flag: "-Pn"})
  ├─[:HAS_FLAG]→ (:Flag {flag: "-p-"})
  ├─[:TAGGED]→ (:Tag {name: "OSCP:HIGH"})
  ├─[:TAGGED]→ (:Tag {name: "NMAP"})
  ├─[:NEXT_STEP]→ (:Command {id: "nmap-service-enum"})
  └─[:ALTERNATIVE]→ (:Command {id: "masscan-quick"})

(:Service {name: "http"})
  ├─[:RUNS_ON]→ (:Port {number: 80})
  ├─[:RUNS_ON]→ (:Port {number: 8080})
  └─[:ENUMERATED_BY]→ (:Command {id: "gobuster-dir"})

(:AttackChain {id: "linux-privesc-sudo"})
  ├─[:HAS_STEP]→ (:ChainStep {id: "check-sudo-privs", order: 1})
  │   └─[:EXECUTES]→ (:Command {id: "sudo-list"})
  ├─[:HAS_STEP]→ (:ChainStep {id: "exploit-sudo", order: 2})
  │   ├─[:DEPENDS_ON]→ (:ChainStep {id: "check-sudo-privs"})
  │   └─[:EXECUTES]→ (:Command {id: "sudo-exploit"})
  └─[:REQUIRES]→ (:Prerequisite {description: "Shell access"})
```

---

## PostgreSQL to Neo4j Mapping Table

| PostgreSQL Table | Neo4j Representation | Transformation |
|-----------------|---------------------|----------------|
| `commands` | `(:Command)` nodes | Direct mapping |
| `command_flags` | `(:Command)-[:HAS_FLAG]->(:Flag)` | Extract flags to nodes |
| `command_vars` | `(:Command)-[:USES_VARIABLE]->(:Variable)` | Many-to-many relationship |
| `command_tags` | `(:Command)-[:TAGGED]->(:Tag)` | Junction → Relationship |
| `command_relations` | `(:Command)-[:PREREQUISITE\|ALTERNATIVE\|NEXT_STEP]->(:Command)` | Self-referential relationships |
| `command_indicators` | `(:Command)-[:SUCCESS_PATTERN\|FAILURE_PATTERN]->(:Indicator)` | Extract patterns to nodes |
| `services` | `(:Service)` nodes | Direct mapping |
| `service_ports` | `(:Service)-[:RUNS_ON]->(:Port)` | Extract ports to nodes |
| `service_commands` | `(:Service)-[:ENUMERATED_BY]->(:Command)` | Junction → Relationship |
| `attack_chains` | `(:AttackChain)` nodes | Direct mapping |
| `chain_steps` | `(:ChainStep)` nodes | Direct mapping |
| `step_dependencies` | `(:ChainStep)-[:DEPENDS_ON]->(:ChainStep)` | Self-referential relationship |
| `chain_prerequisites` | `(:AttackChain)-[:REQUIRES]->(:Prerequisite)` | Extract to nodes |
| `variables` | `(:Variable)` nodes | Direct mapping |
| `tags` | `(:Tag)` nodes | Direct mapping |

---

## Next Steps

1. **Create Schema**: Run Cypher constraints/indexes script
2. **Migrate Data**: [03-MIGRATION-SCRIPTS.md](03-MIGRATION-SCRIPTS.md)
3. **Validate Schema**: Run count and integrity checks above

---

## See Also

- [00-ARCHITECTURE.md](00-ARCHITECTURE.md#proposed-dual-backend-architecture) - Overall design
- [03-MIGRATION-SCRIPTS.md](03-MIGRATION-SCRIPTS.md) - Data import procedures
- [06-ADVANCED-QUERIES.md](06-ADVANCED-QUERIES.md) - Using the schema for complex queries

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-08
**Owner**: Data Modeling Team
**Status**: Ready for Implementation
