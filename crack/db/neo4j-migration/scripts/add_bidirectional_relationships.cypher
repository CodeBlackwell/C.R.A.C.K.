// Add Bidirectional Relationships to Neo4j Graph
// Run this script after initial import to enhance graph traversal performance

// ============================================================================
// ALTERNATIVE Relationships (Symmetric)
// ============================================================================
// Make ALTERNATIVE relationships bidirectional for symmetric alternatives
// If (a)-[:ALTERNATIVE]->(b) exists, ensure (b)-[:ALTERNATIVE]->(a) also exists

MATCH (a:Command)-[r:ALTERNATIVE]->(b:Command)
WHERE NOT EXISTS((b)-[:ALTERNATIVE]->(a))
WITH a, b
CREATE (b)-[:ALTERNATIVE]->(a);

// Verify ALTERNATIVE relationship count
MATCH ()-[r:ALTERNATIVE]->()
WITH count(r) as total
RETURN 'ALTERNATIVE relationships: ' + total AS result;


// ============================================================================
// PREREQUISITE_FOR Relationships (Inverse)
// ============================================================================
// Add inverse PREREQUISITE_FOR relationships
// If (a)-[:PREREQUISITE]->(b), create (b)-[:PREREQUISITE_FOR]->(a)
// Semantics: "a requires b" <=> "b is prerequisite for a"

MATCH (a:Command)-[r:PREREQUISITE]->(b:Command)
WHERE NOT EXISTS((b)-[:PREREQUISITE_FOR]->(a))
WITH a, b
CREATE (b)-[:PREREQUISITE_FOR]->(a);

// Verify PREREQUISITE_FOR relationship count
MATCH ()-[r:PREREQUISITE_FOR]->()
WITH count(r) as total
RETURN 'PREREQUISITE_FOR relationships: ' + total AS result;


// ============================================================================
// Verification Queries
// ============================================================================

// Show example bidirectional ALTERNATIVE relationships
MATCH (a:Command)-[:ALTERNATIVE]->(b:Command)-[:ALTERNATIVE]->(a)
RETURN a.id AS cmd1_id, a.name AS cmd1_name,
       b.id AS cmd2_id, b.name AS cmd2_name
LIMIT 5;

// Show example PREREQUISITE/PREREQUISITE_FOR pairs
MATCH (a:Command)-[:PREREQUISITE]->(b:Command)<-[:PREREQUISITE_FOR]-(a)
RETURN a.id AS dependent_id, a.name AS dependent_name,
       b.id AS prerequisite_id, b.name AS prerequisite_name
LIMIT 5;


// ============================================================================
// Index Creation for Performance
// ============================================================================

// Create indexes on Command.id for faster relationship lookups
CREATE INDEX command_id_index IF NOT EXISTS FOR (c:Command) ON (c.id);

// Create indexes on relationship endpoints for traversal queries
// Note: Neo4j automatically indexes relationship start/end nodes,
// but explicit property indexes help with filtered traversals


// ============================================================================
// Statistics
// ============================================================================

// Final relationship counts
CALL {
    MATCH ()-[r:ALTERNATIVE]->()
    RETURN count(r) AS alternative_count
}
CALL {
    MATCH ()-[r:PREREQUISITE]->()
    RETURN count(r) AS prerequisite_count
}
CALL {
    MATCH ()-[r:PREREQUISITE_FOR]->()
    RETURN count(r) AS prerequisite_for_count
}
CALL {
    MATCH ()-[r:USES_VARIABLE]->()
    RETURN count(r) AS uses_variable_count
}
CALL {
    MATCH ()-[r:HAS_FLAG]->()
    RETURN count(r) AS has_flag_count
}
CALL {
    MATCH ()-[r:TAGGED]->()
    RETURN count(r) AS tagged_count
}
RETURN
    alternative_count,
    prerequisite_count,
    prerequisite_for_count,
    uses_variable_count,
    has_flag_count,
    tagged_count;


// ============================================================================
// Performance Comparison Queries
// ============================================================================

// Before: Find commands that depend on a specific command (slow reverse traversal)
// MATCH (dependent:Command)-[:PREREQUISITE]->(c:Command {id: 'some_id'})
// RETURN dependent

// After: Find commands that depend on a specific command (fast forward traversal)
// MATCH (c:Command {id: 'some_id'})-[:PREREQUISITE_FOR]->(dependent:Command)
// RETURN dependent


// ============================================================================
// Cleanup (Optional - only if you need to remove inverse relationships)
// ============================================================================

// Remove all PREREQUISITE_FOR relationships
// MATCH ()-[r:PREREQUISITE_FOR]->() DELETE r;

// Make ALTERNATIVE relationships unidirectional again
// MATCH (a:Command)-[r:ALTERNATIVE]->(b:Command)
// WHERE id(a) > id(b)  // Keep only one direction based on node ID
// DELETE r;
