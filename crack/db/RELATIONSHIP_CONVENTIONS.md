# Neo4j Relationship Naming Conventions

## Standard Pattern

Neo4j relationships use **UPPERCASE_VERB_OBJECT** format (graph database convention).
PostgreSQL foreign keys use **lowercase_subject_object** format (relational database convention).

## Canonical Relationships

### Command Relationships

| Concept | Neo4j Relationship | PostgreSQL Table | Direction | Semantics |
|---------|-------------------|------------------|-----------|-----------|
| Variable usage | `USES_VARIABLE` | `command_variables` | Command → Variable | Command uses this variable |
| Flag explanation | `HAS_FLAG` | `command_flags` | Command → Flag | Command has this flag option |
| Success/failure indicator | `HAS_INDICATOR` | `command_indicators` | Command → Indicator | Command has this output indicator |
| Tagging | `TAGGED` | `command_tags` | Command → Tag | Command tagged with this tag |
| Alternative | `ALTERNATIVE` | `command_alternatives` | Command → Command | This is alternative to that |
| Prerequisite | `PREREQUISITE` | `command_prerequisites` | Command → Command | This requires that first |

### Attack Chain Relationships

| Concept | Neo4j Relationship | PostgreSQL Table | Direction | Semantics |
|---------|-------------------|------------------|-----------|-----------|
| Chain steps | `HAS_STEP` | `chain_steps` | AttackChain → ChainStep | Chain contains this step |
| Step command | `EXECUTES` | `step_commands` | ChainStep → Command | Step executes this command |
| Chain tagging | `TAGGED` | `chain_tags` | AttackChain → Tag | Chain tagged with this tag |

## Bidirectional Relationship Patterns

For improved graph traversal performance, consider adding inverse relationships:

### Current Unidirectional
- `(a:Command)-[:ALTERNATIVE]->(b:Command)` - "a is alternative to b"
- `(a:Command)-[:PREREQUISITE]->(b:Command)` - "a requires b"

### Proposed Bidirectional Enhancement
- `(a:Command)-[:ALTERNATIVE]->(b:Command)` + `(b)-[:ALTERNATIVE]->(a)` - symmetric alternatives
- `(a:Command)-[:PREREQUISITE]->(b:Command)` + `(b)-[:PREREQUISITE_FOR]->(a)` - inverse dependency

**Benefits:**
- Faster bidirectional traversal without expensive reverse path queries
- Explicit semantic meaning in both directions
- Simplified Cypher queries for "find what depends on this" vs "find what this depends on"

**Implementation:**
See `db/neo4j-migration/scripts/add_bidirectional_relationships.cypher` for migration script.

## Relationship Properties

### USES_VARIABLE
- `position`: Integer order in command
- `example`: Example value
- `required`: Boolean (true/false as string)

### HAS_FLAG
- `position`: Integer order in flag list

### HAS_INDICATOR
- `type`: 'success' or 'failure'

### HAS_STEP
- `order`: Integer step sequence in chain

### TAGGED
No properties (pure classification)

### ALTERNATIVE / PREREQUISITE
No properties (pure relationship)

## Naming Guidelines

### DO
- Use UPPERCASE for relationship types
- Use active verbs (EXECUTES, USES, HAS)
- Be specific (HAS_FLAG vs HAS)
- Match domain semantics

### DON'T
- Use lowercase in relationship types
- Use passive voice (USED_BY - prefer USES with reversed direction)
- Use generic names (RELATED_TO, LINKED_TO)
- Mix PostgreSQL and Neo4j conventions in same context

## Future Domain Relationships

Consider adding semantic relationships for enhanced queries:

### Service/Port Targeting
```cypher
(c:Command)-[:TARGETS_SERVICE]->(s:Service {name: 'SMB', port: 445})
```

### Platform Support
```cypher
(c:Command)-[:WORKS_ON_PLATFORM]->(p:Platform {name: 'Windows'})
(c:Command)-[:WORKS_ON_PLATFORM]->(p:Platform {name: 'Linux'})
```

### Category Hierarchy
```cypher
(c:Command)-[:BELONGS_TO_CATEGORY]->(cat:Category {name: 'enumeration'})
(cat)-[:SUBCATEGORY_OF]->(parent:Category {name: 'reconnaissance'})
```

### Mitigation/Detection
```cypher
(c:Command)-[:DETECTED_BY]->(detection:Detection)
(c:Command)-[:MITIGATED_BY]->(mitigation:Mitigation)
```

## Migration Notes

### From PostgreSQL Junction Tables
PostgreSQL junction tables map directly to Neo4j relationships:

```sql
-- PostgreSQL
CREATE TABLE command_tags (
    command_id TEXT,
    tag_name TEXT
);
```

```cypher
// Neo4j
(c:Command {id: 'cmd_123'})-[:TAGGED]->(t:Tag {name: 'oscp'})
```

### Relationship vs Property
Use relationships when:
- The target is a first-class entity (Tag, Variable, Flag)
- Many-to-many associations exist
- Traversal queries are needed

Use properties when:
- Simple scalar values (category, difficulty)
- One-to-one attributes
- No need for independent entity lifecycle

## Query Pattern Examples

### Find all alternatives to a command
```cypher
MATCH (c:Command {id: $cmd_id})-[:ALTERNATIVE]->(alt:Command)
RETURN alt
```

### With bidirectional relationships (faster)
```cypher
// Find what alternatives exist FOR this command
MATCH (alt:Command)-[:ALTERNATIVE]->(c:Command {id: $cmd_id})
RETURN alt
```

### Find all commands that depend on a command
```cypher
// Without inverse relationship (slow)
MATCH (dependent:Command)-[:PREREQUISITE]->(c:Command {id: $cmd_id})
RETURN dependent

// With inverse relationship (fast)
MATCH (c:Command {id: $cmd_id})-[:PREREQUISITE_FOR]->(dependent:Command)
RETURN dependent
```

### Find attack chains using specific command
```cypher
MATCH (chain:AttackChain)-[:HAS_STEP]->(step:ChainStep)-[:EXECUTES]->(c:Command {id: $cmd_id})
RETURN DISTINCT chain
```

## References
- Neo4j Relationship Naming: https://neo4j.com/docs/cypher-manual/current/syntax/naming/
- Graph Modeling Best Practices: https://neo4j.com/developer/guide-data-modeling/
