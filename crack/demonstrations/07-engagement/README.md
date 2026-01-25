# Video 07: Engagement Tracking

**Duration:** 8-10 min | **Focus:** Neo4j-based target and finding management

## Samples Needed

Place in `samples/`:

- [ ] N/A - Creates data live

## Scripts

Place in `scripts/`:

- [ ] `talking_points.md` - Section-by-section narration
- [ ] `cypher_queries.md` - Neo4j queries to demonstrate
- [ ] `demo_data.sh` - Commands to populate sample data

## Pre-Recording Setup

- [ ] Neo4j running and accessible
- [ ] Clean state (or create fresh engagement)
- [ ] Neo4j Browser open for graph visualization

## Key Demo Commands

```bash
# Create and activate engagement
crack engagement create "Lab Pentest"
crack engagement list
crack engagement activate <id>
crack engagement status

# Add targets
crack target add 10.10.10.5 --hostname dc01
crack target add 10.10.10.10 --hostname web01
crack target list

# Add services
crack target services <target_id>
crack target service-add <target_id> 445 --name smb
crack target service-add <target_id> 88 --name kerberos

# Add findings
crack finding add "SQL Injection in login" --severity critical
crack finding add "Weak password policy" --severity medium
crack finding list
crack finding link <finding_id> --target <target_id>
```

## Neo4j Queries to Show

```cypher
# Show engagement graph
MATCH (e:Engagement)-[r]->(n)
WHERE e.name = "Lab Pentest"
RETURN e, r, n

# Show target with all services
MATCH (t:Target)-[:HAS_SERVICE]->(s:Service)
RETURN t, s

# Show findings by severity
MATCH (f:Finding)
RETURN f.title, f.severity
ORDER BY f.severity
```

## Key Shots

1. Engagement creation and activation
2. Target list with status
3. Service discovery output
4. Finding list with severity badges
5. Neo4j Browser graph visualization
6. Relationship traversal query

## Features to Highlight

- [ ] Engagement scoping (data isolation)
- [ ] Target status tracking
- [ ] Service discovery integration
- [ ] Finding severity levels
- [ ] Neo4j graph relationships
- [ ] Tool auto-logging (mention PRISM, port scanner)

## Thumbnail Concept

Neo4j graph with interconnected nodes (targets, services, findings)
Text: "Track Everything"
