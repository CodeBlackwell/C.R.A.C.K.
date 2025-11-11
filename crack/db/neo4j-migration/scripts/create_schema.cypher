// Neo4j Schema Creation Script for CRACK Toolkit
// Creates constraints and indexes for the dual-backend graph database
// Execute with: cypher-shell -u neo4j -p Neo4j123 < create_schema.cypher

// ============================================================
// CONSTRAINTS (UNIQUE NODE IDENTIFIERS)
// ============================================================

// Core command entities
CREATE CONSTRAINT command_id_unique IF NOT EXISTS
  FOR (c:Command) REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT variable_name_unique IF NOT EXISTS
  FOR (v:Variable) REQUIRE v.name IS UNIQUE;

CREATE CONSTRAINT tag_name_unique IF NOT EXISTS
  FOR (t:Tag) REQUIRE t.name IS UNIQUE;

CREATE CONSTRAINT flag_id_unique IF NOT EXISTS
  FOR (f:Flag) REQUIRE (f.flag, f.explanation) IS UNIQUE;

// Service mapping entities
CREATE CONSTRAINT service_name_unique IF NOT EXISTS
  FOR (s:Service) REQUIRE s.name IS UNIQUE;

CREATE CONSTRAINT port_number_unique IF NOT EXISTS
  FOR (p:Port) REQUIRE p.number IS UNIQUE;

// Attack chain entities
CREATE CONSTRAINT chain_id_unique IF NOT EXISTS
  FOR (ac:AttackChain) REQUIRE ac.id IS UNIQUE;

CREATE CONSTRAINT step_id_unique IF NOT EXISTS
  FOR (cs:ChainStep) REQUIRE cs.id IS UNIQUE;

CREATE CONSTRAINT prerequisite_id_unique IF NOT EXISTS
  FOR (pr:Prerequisite) REQUIRE pr.description IS UNIQUE;

// Finding entities
CREATE CONSTRAINT finding_type_unique IF NOT EXISTS
  FOR (ft:FindingType) REQUIRE ft.name IS UNIQUE;

CREATE CONSTRAINT indicator_id_unique IF NOT EXISTS
  FOR (i:Indicator) REQUIRE (i.pattern, i.type) IS UNIQUE;

// ============================================================
// STANDARD INDEXES (PERFORMANCE OPTIMIZATION)
// ============================================================

// Command search and filtering
CREATE INDEX command_category IF NOT EXISTS
  FOR (c:Command) ON (c.category);

CREATE INDEX command_subcategory IF NOT EXISTS
  FOR (c:Command) ON (c.subcategory);

CREATE INDEX command_oscp IF NOT EXISTS
  FOR (c:Command) ON (c.oscp_relevance);

CREATE INDEX command_created IF NOT EXISTS
  FOR (c:Command) ON (c.created_at);

CREATE INDEX command_updated IF NOT EXISTS
  FOR (c:Command) ON (c.updated_at);

// Tag categorization
CREATE INDEX tag_category IF NOT EXISTS
  FOR (t:Tag) ON (t.category);

// Service filtering
CREATE INDEX service_protocol IF NOT EXISTS
  FOR (s:Service) ON (s.protocol);

// Attack chain filtering
CREATE INDEX chain_category IF NOT EXISTS
  FOR (ac:AttackChain) ON (ac.category);

CREATE INDEX chain_platform IF NOT EXISTS
  FOR (ac:AttackChain) ON (ac.platform);

CREATE INDEX chain_difficulty IF NOT EXISTS
  FOR (ac:AttackChain) ON (ac.difficulty);

CREATE INDEX chain_oscp IF NOT EXISTS
  FOR (ac:AttackChain) ON (ac.oscp_relevant);

// Chain step ordering
CREATE INDEX step_order IF NOT EXISTS
  FOR (cs:ChainStep) ON (cs.step_order);

// Variable data types
CREATE INDEX variable_type IF NOT EXISTS
  FOR (v:Variable) ON (v.data_type);

CREATE INDEX variable_source IF NOT EXISTS
  FOR (v:Variable) ON (v.source);

// Indicator types
CREATE INDEX indicator_type IF NOT EXISTS
  FOR (i:Indicator) ON (i.type);

// ============================================================
// FULL-TEXT SEARCH INDEXES
// ============================================================

// Command full-text search (name, description, notes)
CREATE FULLTEXT INDEX command_search IF NOT EXISTS
  FOR (c:Command) ON EACH [c.name, c.description, c.notes, c.template];

// Tag full-text search
CREATE FULLTEXT INDEX tag_search IF NOT EXISTS
  FOR (t:Tag) ON EACH [t.name, t.description];

// Service full-text search
CREATE FULLTEXT INDEX service_search IF NOT EXISTS
  FOR (s:Service) ON EACH [s.name, s.description];

// Attack chain full-text search
CREATE FULLTEXT INDEX chain_search IF NOT EXISTS
  FOR (ac:AttackChain) ON EACH [ac.name, ac.description];

// Chain step full-text search
CREATE FULLTEXT INDEX step_search IF NOT EXISTS
  FOR (cs:ChainStep) ON EACH [cs.name, cs.objective, cs.description];

// Variable full-text search
CREATE FULLTEXT INDEX variable_search IF NOT EXISTS
  FOR (v:Variable) ON EACH [v.name, v.description];

// ============================================================
// RELATIONSHIP INDEXES (GRAPH TRAVERSAL OPTIMIZATION)
// ============================================================

// Command relationship indexes for fast traversal
CREATE INDEX rel_prerequisite_priority IF NOT EXISTS
  FOR ()-[r:PREREQUISITE]-() ON (r.priority);

CREATE INDEX rel_alternative_priority IF NOT EXISTS
  FOR ()-[r:ALTERNATIVE]-() ON (r.priority);

CREATE INDEX rel_next_step_priority IF NOT EXISTS
  FOR ()-[r:NEXT_STEP]-() ON (r.priority);

CREATE INDEX rel_has_flag_required IF NOT EXISTS
  FOR ()-[r:HAS_FLAG]-() ON (r.required);

CREATE INDEX rel_enumerated_by_priority IF NOT EXISTS
  FOR ()-[r:ENUMERATED_BY]-() ON (r.priority);

CREATE INDEX rel_has_step_order IF NOT EXISTS
  FOR ()-[r:HAS_STEP]-() ON (r.order);

// ============================================================
// VERIFICATION QUERY
// ============================================================

// Return all constraints and indexes for verification
SHOW CONSTRAINTS;
SHOW INDEXES;
