#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../../.." && pwd )"

cd "$PROJECT_ROOT"

echo "=== CRACK Neo4j Migration Pipeline ==="
echo ""
echo "Step 1: Transform existing JSON to Neo4j CSV format"
python3 db/neo4j-migration/scripts/transform_to_neo4j.py --validate --verbose

echo ""
echo "Step 2: Import CSVs to Neo4j"
python3 db/neo4j-migration/scripts/import_to_neo4j.py

echo ""
echo "=== Migration Complete ==="
echo "Verify in Neo4j Browser: http://localhost:7474"
echo "Example query: MATCH (c:Command) RETURN count(c)"
