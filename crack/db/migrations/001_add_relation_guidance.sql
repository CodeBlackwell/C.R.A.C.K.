-- ============================================================================
-- Migration 001: Add command_relation_guidance table
-- ============================================================================
-- Purpose: Store descriptive/procedural guidance relations that don't map
--          to specific command IDs (e.g., "Check for specific services")
--
-- Context: During migration, 580 relations were classified as "guidance text"
--          rather than command ID references. These need to be preserved
--          for pedagogical value in OSCP learning.
--
-- Example Data:
--   source: 'nmap-service-scan'
--   type: 'next_steps'
--   guidance: 'Check for specific services (SMB, HTTP, SSH)'
--   order: 1
-- ============================================================================

CREATE TABLE IF NOT EXISTS command_relation_guidance (
    id SERIAL PRIMARY KEY,
    source_command_id VARCHAR(255) NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    relation_type VARCHAR(20) NOT NULL,             -- 'prerequisite'|'alternative'|'next_step'
    guidance_text TEXT NOT NULL,                    -- Descriptive procedural guidance
    display_order INT DEFAULT 1,                    -- Order for display (lower = shown first)
    category VARCHAR(50),                           -- Optional: 'conditional'|'best-practice'|'troubleshooting'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CHECK (relation_type IN ('prerequisite', 'alternative', 'next_step'))
);

CREATE INDEX IF NOT EXISTS idx_guidance_source ON command_relation_guidance(source_command_id);
CREATE INDEX IF NOT EXISTS idx_guidance_type ON command_relation_guidance(relation_type);
CREATE INDEX IF NOT EXISTS idx_guidance_category ON command_relation_guidance(category);

-- ============================================================================
-- Update schema version
-- ============================================================================
INSERT INTO schema_version (version, description) VALUES
('1.1.0', 'Added command_relation_guidance table for descriptive relations')
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- Example Queries
-- ============================================================================

-- Get all guidance for a command
-- SELECT guidance_text, relation_type, display_order
-- FROM command_relation_guidance
-- WHERE source_command_id = 'nmap-service-scan'
-- ORDER BY relation_type, display_order;

-- Get next_steps guidance only
-- SELECT c.name, g.guidance_text
-- FROM command_relation_guidance g
-- JOIN commands c ON g.source_command_id = c.id
-- WHERE g.relation_type = 'next_step'
-- ORDER BY c.name, g.display_order;

-- Count guidance by type
-- SELECT relation_type, COUNT(*) as count
-- FROM command_relation_guidance
-- GROUP BY relation_type
-- ORDER BY count DESC;
