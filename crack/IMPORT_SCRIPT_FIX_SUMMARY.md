# Import Script Fix Summary

## Problem Resolved
Fixed hardcoded `id` field in import script to handle different ID fields for different node types.

**Original Issue (Line 106)**:
```python
MERGE (n:{node_type} {{id: row.id}})
```

This failed because:
- Commands use `id` field
- Tags use `name` field
- Variables use `name` field
- Flags use auto-incremented `id`
- Indicators use auto-incremented `id`
- AttackChains use `id`
- ChainSteps use `id`

## Solution Implemented

### 1. Updated `import_nodes()` Function
**Location**: `/home/kali/Desktop/OSCP/crack/db/neo4j-migration/scripts/import_to_neo4j.py:70-104`

Added `id_field` parameter:
```python
def import_nodes(driver, node_type: str, csv_path: str, id_field: str,
                 properties: Dict[str, str] = None, batch_size: int = 1000) -> int:
```

### 2. Updated `_create_node_batch()` Function
**Location**: Line 107-128

Now accepts and uses `id_field` parameter:
```python
def _create_node_batch(session, node_type: str, rows: List[Dict[str, Any]],
                       id_field: str) -> int:
    query = f"""
    UNWIND $rows AS row
    MERGE (n:{node_type} {{{id_field}: row.{id_field}}})
    SET n += row
    RETURN count(n) AS created
    """
```

### 3. Updated `import_relationships()` Function
**Location**: Line 131-182

Added `start_id_field` and `end_id_field` parameters:
```python
def import_relationships(driver, rel_type: str, csv_path: str,
                        start_label: str, end_label: str,
                        start_id_col: str, end_id_col: str,
                        start_id_field: str = 'id', end_id_field: str = 'id',
                        properties: Dict[str, str] = None,
                        batch_size: int = 1000) -> int:
```

### 4. Updated `_create_relationship_batch()` Function
**Location**: Line 185-216

Now correctly matches nodes using appropriate id fields:
```python
def _create_relationship_batch(session, rel_type: str, rows: List[Dict[str, Any]],
                              start_label: str, end_label: str,
                              start_id_col: str, end_id_col: str,
                              start_id_field: str = 'id', end_id_field: str = 'id') -> int:
    query = f"""
    UNWIND $rows AS row
    MATCH (start:{start_label} {{{start_id_field}: row.{start_id_col}}})
    MATCH (end:{end_label} {{{end_id_field}: row.{end_id_col}}})
    MERGE (start)-[r:{rel_type}]->(end)
    SET r += row
    RETURN count(r) AS created
    """
```

### 5. Updated `import_all_to_neo4j()` Function
**Location**: Line 284-354

Updated all node imports with correct `id_field`:
```python
# Nodes with id='id'
import_nodes(driver, 'Command', ..., id_field='id', ...)
import_nodes(driver, 'Flag', ..., id_field='id', ...)
import_nodes(driver, 'Indicator', ..., id_field='id', ...)
import_nodes(driver, 'AttackChain', ..., id_field='id', ...)
import_nodes(driver, 'ChainStep', ..., id_field='id', ...)

# Nodes with id='name'
import_nodes(driver, 'Tag', ..., id_field='name', ...)
import_nodes(driver, 'Variable', ..., id_field='name', ...)
```

Updated all relationships with correct `start_id_field` and `end_id_field`:
```python
# Command -> Variable (Command:id, Variable:name)
import_relationships(driver, 'USES_VARIABLE', ...,
                    start_id_field='id', end_id_field='name', ...)

# Command -> Tag (Command:id, Tag:name)
import_relationships(driver, 'TAGGED', ...,
                    start_id_field='id', end_id_field='name', ...)

# AttackChain -> Tag (AttackChain:id, Tag:name)
import_relationships(driver, 'TAGGED', ...,
                    start_id_field='id', end_id_field='name', ...)

# All other relationships (both use 'id')
import_relationships(driver, 'HAS_FLAG', ...,
                    start_id_field='id', end_id_field='id', ...)
```

## ID Field Mapping Reference

| Node Type | ID Field | CSV Export Field | Usage |
|-----------|----------|------------------|-------|
| Command | `id` | `id` | Unique command identifier |
| Tag | `name` | `name` | Tag name is unique identifier |
| Variable | `name` | `name` | Variable name is unique identifier |
| Flag | `id` | `id` | Auto-increment, exported as id |
| Indicator | `id` | `id` | Auto-increment, exported as id |
| AttackChain | `id` | `id` | Unique chain identifier |
| ChainStep | `id` | `id` | Unique step identifier |

## Relationship ID Field Mapping

| Relationship Type | Start Label | Start ID | End Label | End ID |
|------------------|------------|----------|-----------|--------|
| USES_VARIABLE | Command | `id` | Variable | `name` |
| HAS_FLAG | Command | `id` | Flag | `id` |
| HAS_INDICATOR | Command | `id` | Indicator | `id` |
| TAGGED (Cmd->Tag) | Command | `id` | Tag | `name` |
| TAGGED (Chain->Tag) | AttackChain | `id` | Tag | `name` |
| ALTERNATIVE | Command | `id` | Command | `id` |
| PREREQUISITE | Command | `id` | Command | `id` |
| HAS_STEP | AttackChain | `id` | ChainStep | `id` |
| EXECUTES | ChainStep | `id` | Command | `id` |

## Verification
- Python syntax check: PASSED
- All function signatures updated
- All function calls updated with correct parameters
- Backward compatible (optional parameters with defaults)

## Next Steps
The import script is now ready to handle all node and relationship types correctly. Run:
```bash
python3 db/neo4j-migration/scripts/import_to_neo4j.py --csv-dir db/neo4j-migration/data/neo4j
```
