-- ============================================================================
-- CRACK SQL Database Schema v1.0.0
-- ============================================================================
-- Comprehensive normalized schema for penetration testing toolkit
-- Compatible with: SQLite 3.x, PostgreSQL 10+
-- Purpose: Replace JSON-based storage with queryable relational model
-- ============================================================================

-- ============================================================================
-- COMMANDS: Command definitions and metadata
-- ============================================================================
CREATE TABLE IF NOT EXISTS commands (
    id VARCHAR(255) PRIMARY KEY,                    -- e.g., 'nmap-quick-scan'
    name VARCHAR(255) NOT NULL,                     -- 'Quick Full Port Scan'
    command_template TEXT NOT NULL,                 -- 'nmap -Pn -p- --min-rate=<RATE> <TARGET> -oA <OUTPUT>'
    description TEXT NOT NULL,
    category VARCHAR(50) NOT NULL,                  -- recon|web|exploitation|post-exploit|file-transfer
    subcategory VARCHAR(50),                        -- shells|enumeration|brute-force
    notes TEXT,
    oscp_relevance VARCHAR(10) DEFAULT 'medium',    -- low|medium|high
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CHECK (category IN ('recon', 'web', 'exploitation', 'post-exploit', 'file-transfer', 'pivoting', 'custom')),
    CHECK (oscp_relevance IN ('low', 'medium', 'high'))
);

CREATE INDEX IF NOT EXISTS idx_commands_category ON commands(category);
CREATE INDEX IF NOT EXISTS idx_commands_oscp ON commands(oscp_relevance);

-- ============================================================================
-- COMMAND_FLAGS: Reusable flag definitions
-- ============================================================================
CREATE TABLE IF NOT EXISTS command_flags (
    id SERIAL PRIMARY KEY,
    command_id VARCHAR(255) NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    flag VARCHAR(50) NOT NULL,                      -- '-Pn', '--min-rate', '-v'
    explanation TEXT NOT NULL,
    is_required BOOLEAN DEFAULT FALSE,

    UNIQUE(command_id, flag)
);

CREATE INDEX IF NOT EXISTS idx_flags_command ON command_flags(command_id);

-- ============================================================================
-- VARIABLES: Global variable definitions
-- ============================================================================
CREATE TABLE IF NOT EXISTS variables (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,               -- '<TARGET>', '<LHOST>', '<LPORT>'
    description TEXT NOT NULL,
    data_type VARCHAR(20) DEFAULT 'string',         -- string|int|port|ip|path|url
    default_value VARCHAR(255),                     -- Default if not in config
    validation_regex VARCHAR(500),                  -- Optional validation pattern
    source VARCHAR(50),                             -- 'config'|'env'|'user'|'auto'

    CHECK (data_type IN ('string', 'int', 'port', 'ip', 'path', 'url', 'domain'))
);

CREATE INDEX IF NOT EXISTS idx_variables_name ON variables(name);

-- ============================================================================
-- COMMAND_VARS: Command-specific variable usage
-- ============================================================================
CREATE TABLE IF NOT EXISTS command_vars (
    id SERIAL PRIMARY KEY,
    command_id VARCHAR(255) NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    variable_id INT NOT NULL REFERENCES variables(id) ON DELETE CASCADE,
    position INT NOT NULL,                          -- Order in command template
    is_required BOOLEAN DEFAULT TRUE,
    example_value VARCHAR(255),                     -- Command-specific example (overrides variable default)

    UNIQUE(command_id, variable_id)
);

CREATE INDEX IF NOT EXISTS idx_command_vars_cmd ON command_vars(command_id);
CREATE INDEX IF NOT EXISTS idx_command_vars_var ON command_vars(variable_id);

-- ============================================================================
-- TAGS: Categorization and filtering
-- ============================================================================
CREATE TABLE IF NOT EXISTS tags (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,               -- 'OSCP:HIGH', 'QUICK_WIN', 'ENUM'
    category VARCHAR(50),                           -- 'priority'|'technique'|'tool'|'phase'
    description TEXT,
    color VARCHAR(7)                                -- Hex color for UI: '#00FF00'
);

CREATE INDEX IF NOT EXISTS idx_tags_category ON tags(category);

CREATE TABLE IF NOT EXISTS command_tags (
    command_id VARCHAR(255) NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    tag_id INT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,

    PRIMARY KEY (command_id, tag_id)
);

CREATE INDEX IF NOT EXISTS idx_command_tags_cmd ON command_tags(command_id);
CREATE INDEX IF NOT EXISTS idx_command_tags_tag ON command_tags(tag_id);

-- ============================================================================
-- COMMAND_RELATIONS: Prerequisites, Alternatives, Next Steps
-- ============================================================================
CREATE TABLE IF NOT EXISTS command_relations (
    id SERIAL PRIMARY KEY,
    source_command_id VARCHAR(255) NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    target_command_id VARCHAR(255) NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    relation_type VARCHAR(20) NOT NULL,             -- 'prerequisite'|'alternative'|'next_step'
    priority INT DEFAULT 1,                         -- Order for display (lower = higher priority)
    condition TEXT,                                 -- Optional: when this relation applies
    notes TEXT,

    CHECK (relation_type IN ('prerequisite', 'alternative', 'next_step')),
    CHECK (source_command_id != target_command_id), -- Prevent self-reference
    UNIQUE(source_command_id, target_command_id, relation_type)
);

CREATE INDEX IF NOT EXISTS idx_relations_source ON command_relations(source_command_id);
CREATE INDEX IF NOT EXISTS idx_relations_target ON command_relations(target_command_id);
CREATE INDEX IF NOT EXISTS idx_relations_type ON command_relations(relation_type);

-- ============================================================================
-- COMMAND_INDICATORS: Success/Failure Patterns
-- ============================================================================
CREATE TABLE IF NOT EXISTS command_indicators (
    id SERIAL PRIMARY KEY,
    command_id VARCHAR(255) NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    indicator_type VARCHAR(10) NOT NULL,            -- 'success'|'failure'
    pattern TEXT NOT NULL,                          -- Regex or literal string
    pattern_type VARCHAR(10) DEFAULT 'literal',     -- 'literal'|'regex'
    priority INT DEFAULT 1,
    description TEXT,

    CHECK (indicator_type IN ('success', 'failure')),
    CHECK (pattern_type IN ('literal', 'regex'))
);

CREATE INDEX IF NOT EXISTS idx_indicators_command ON command_indicators(command_id);
CREATE INDEX IF NOT EXISTS idx_indicators_type ON command_indicators(indicator_type);

-- ============================================================================
-- SERVICES: Service types and metadata
-- ============================================================================
CREATE TABLE IF NOT EXISTS services (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,               -- 'http', 'smb', 'ssh'
    protocol VARCHAR(20),                           -- 'tcp'|'udp'
    description TEXT,
    confidence_threshold REAL DEFAULT 60.0          -- Minimum detection confidence (0-100)
);

CREATE INDEX IF NOT EXISTS idx_services_name ON services(name);

CREATE TABLE IF NOT EXISTS service_ports (
    id SERIAL PRIMARY KEY,
    service_id INT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    port INT NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,                   -- Standard port (e.g., 80 for HTTP)

    UNIQUE(service_id, port),
    CHECK (port > 0 AND port <= 65535)
);

CREATE INDEX IF NOT EXISTS idx_service_ports_service ON service_ports(service_id);
CREATE INDEX IF NOT EXISTS idx_service_ports_port ON service_ports(port);

CREATE TABLE IF NOT EXISTS service_aliases (
    id SERIAL PRIMARY KEY,
    service_id INT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    alias VARCHAR(50) NOT NULL,                     -- 'https', 'web', 'www' all map to 'http'

    UNIQUE(alias)
);

CREATE INDEX IF NOT EXISTS idx_service_aliases_service ON service_aliases(service_id);

-- ============================================================================
-- SERVICE_COMMANDS: Service → Command Mappings
-- ============================================================================
CREATE TABLE IF NOT EXISTS service_commands (
    id SERIAL PRIMARY KEY,
    service_id INT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    command_id VARCHAR(255) NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    priority INT DEFAULT 1,                         -- Execution order (1 = run first)
    context VARCHAR(50),                            -- 'enumeration'|'exploitation'|'post-exploit'
    required_confidence REAL DEFAULT 60.0,          -- Min confidence to suggest command

    UNIQUE(service_id, command_id)
);

CREATE INDEX IF NOT EXISTS idx_service_commands_service ON service_commands(service_id);
CREATE INDEX IF NOT EXISTS idx_service_commands_command ON service_commands(command_id);

-- ============================================================================
-- ATTACK_CHAINS: Multi-step attack sequences
-- ============================================================================
CREATE TABLE IF NOT EXISTS attack_chains (
    id VARCHAR(255) PRIMARY KEY,                    -- 'linux-privesc-sudo-nopasswd'
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    version VARCHAR(20) NOT NULL,                   -- Semantic versioning: '1.0.0'
    category VARCHAR(50) NOT NULL,                  -- 'enumeration'|'privilege_escalation'|'lateral_movement'
    platform VARCHAR(50),                           -- 'linux'|'windows'|'network'|'web'
    difficulty VARCHAR(20) DEFAULT 'intermediate',  -- 'beginner'|'intermediate'|'advanced'|'expert'
    time_estimate VARCHAR(50),                      -- '5 minutes', '1 hour'
    oscp_relevant BOOLEAN DEFAULT FALSE,
    author VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,

    CHECK (difficulty IN ('beginner', 'intermediate', 'advanced', 'expert')),
    CHECK (category IN ('enumeration', 'privilege_escalation', 'lateral_movement', 'persistence', 'custom'))
);

CREATE INDEX IF NOT EXISTS idx_chains_category ON attack_chains(category);
CREATE INDEX IF NOT EXISTS idx_chains_oscp ON attack_chains(oscp_relevant);
CREATE INDEX IF NOT EXISTS idx_chains_difficulty ON attack_chains(difficulty);

CREATE TABLE IF NOT EXISTS chain_prerequisites (
    id SERIAL PRIMARY KEY,
    chain_id VARCHAR(255) NOT NULL REFERENCES attack_chains(id) ON DELETE CASCADE,
    description TEXT NOT NULL,                      -- 'Shell access as low-privilege user'
    priority INT DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_chain_prereqs_chain ON chain_prerequisites(chain_id);

-- ============================================================================
-- CHAIN_STEPS: Ordered steps in attack chains
-- ============================================================================
CREATE TABLE IF NOT EXISTS chain_steps (
    id VARCHAR(255) PRIMARY KEY,                    -- 'check-sudo-privs'
    chain_id VARCHAR(255) NOT NULL REFERENCES attack_chains(id) ON DELETE CASCADE,
    command_id VARCHAR(255) REFERENCES commands(id) ON DELETE SET NULL,  -- Optional: may be manual step
    step_order INT NOT NULL,                        -- Execution order (1, 2, 3...)
    name VARCHAR(255) NOT NULL,
    objective TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT,                                  -- JSON array of expected evidence
    success_criteria TEXT,                          -- JSON array of success conditions
    failure_conditions TEXT,                        -- JSON array of failure indicators

    UNIQUE(chain_id, step_order)
);

CREATE INDEX IF NOT EXISTS idx_chain_steps_chain ON chain_steps(chain_id);
CREATE INDEX IF NOT EXISTS idx_chain_steps_command ON chain_steps(command_id);

CREATE TABLE IF NOT EXISTS step_dependencies (
    step_id VARCHAR(255) NOT NULL REFERENCES chain_steps(id) ON DELETE CASCADE,
    depends_on_step_id VARCHAR(255) NOT NULL REFERENCES chain_steps(id) ON DELETE CASCADE,

    PRIMARY KEY (step_id, depends_on_step_id),
    CHECK (step_id != depends_on_step_id)           -- Prevent self-dependency
);

CREATE INDEX IF NOT EXISTS idx_step_deps_step ON step_dependencies(step_id);
CREATE INDEX IF NOT EXISTS idx_step_deps_depends ON step_dependencies(depends_on_step_id);

-- ============================================================================
-- FINDING TYPES: Classification of enumeration findings
-- ============================================================================
CREATE TABLE IF NOT EXISTS finding_types (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,               -- 'directory', 'vulnerability', 'credential'
    category VARCHAR(50),                           -- 'web'|'network'|'auth'|'file'
    description TEXT,
    severity VARCHAR(20),                           -- 'info'|'low'|'medium'|'high'|'critical'

    CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_finding_types_category ON finding_types(category);

-- ============================================================================
-- FINDING_PATTERNS: Output parsing patterns
-- ============================================================================
CREATE TABLE IF NOT EXISTS finding_patterns (
    id SERIAL PRIMARY KEY,
    finding_type_id INT NOT NULL REFERENCES finding_types(id) ON DELETE CASCADE,
    source_command_id VARCHAR(255) REFERENCES commands(id) ON DELETE SET NULL,  -- NULL = generic pattern
    regex_pattern TEXT NOT NULL,
    description TEXT,
    priority INT DEFAULT 1,                         -- Higher priority patterns checked first
    extraction_groups TEXT,                         -- JSON: {"1": "path", "2": "status_code"}

    UNIQUE(finding_type_id, source_command_id, regex_pattern)
);

CREATE INDEX IF NOT EXISTS idx_patterns_type ON finding_patterns(finding_type_id);
CREATE INDEX IF NOT EXISTS idx_patterns_command ON finding_patterns(source_command_id);

-- ============================================================================
-- FINDING_TO_TASK: Automatic task generation rules
-- ============================================================================
CREATE TABLE IF NOT EXISTS finding_to_task (
    id SERIAL PRIMARY KEY,
    finding_type_id INT NOT NULL REFERENCES finding_types(id) ON DELETE CASCADE,
    task_command_id VARCHAR(255) NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
    condition TEXT,                                 -- SQL-like condition: "severity = 'high'"
    priority INT DEFAULT 1,

    UNIQUE(finding_type_id, task_command_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_tasks_type ON finding_to_task(finding_type_id);
CREATE INDEX IF NOT EXISTS idx_finding_tasks_command ON finding_to_task(task_command_id);

-- ============================================================================
-- TARGET SESSIONS: Enumeration session tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS target_sessions (
    id SERIAL PRIMARY KEY,
    target_ip VARCHAR(45) NOT NULL,                 -- IPv4 or IPv6
    target_name VARCHAR(255),                       -- Friendly name or hostname
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    phase VARCHAR(50) DEFAULT 'discovery',          -- discovery|enumeration|exploitation|post-exploit
    status VARCHAR(20) DEFAULT 'new',               -- new|in-progress|completed|archived
    environment VARCHAR(20) DEFAULT 'lab',          -- lab|production|ctf
    metadata TEXT,                                  -- JSON: scan preferences, confirmation mode

    CHECK (status IN ('new', 'in-progress', 'completed', 'archived')),
    UNIQUE(target_ip)
);

CREATE INDEX IF NOT EXISTS idx_sessions_target ON target_sessions(target_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON target_sessions(status);

CREATE TABLE IF NOT EXISTS session_ports (
    id SERIAL PRIMARY KEY,
    session_id INT NOT NULL REFERENCES target_sessions(id) ON DELETE CASCADE,
    port INT NOT NULL,
    state VARCHAR(20) DEFAULT 'open',               -- open|closed|filtered
    service VARCHAR(100),
    version VARCHAR(255),
    source VARCHAR(100),                            -- 'nmap', 'masscan', 'manual'
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(session_id, port),
    CHECK (port > 0 AND port <= 65535)
);

CREATE INDEX IF NOT EXISTS idx_session_ports_session ON session_ports(session_id);

CREATE TABLE IF NOT EXISTS session_findings (
    id SERIAL PRIMARY KEY,
    session_id INT NOT NULL REFERENCES target_sessions(id) ON DELETE CASCADE,
    finding_type_id INT NOT NULL REFERENCES finding_types(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    source_command VARCHAR(255),                    -- Command that found this
    metadata TEXT,                                  -- JSON: additional context
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_session_findings_session ON session_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_session_findings_type ON session_findings(finding_type_id);

CREATE TABLE IF NOT EXISTS session_credentials (
    id SERIAL PRIMARY KEY,
    session_id INT NOT NULL REFERENCES target_sessions(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    password TEXT,
    password_hash TEXT,
    service VARCHAR(50),                            -- 'ssh', 'http', 'smb'
    port INT,
    source VARCHAR(255),                            -- How discovered
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CHECK ((password IS NOT NULL) OR (password_hash IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_session_creds_session ON session_credentials(session_id);

-- ============================================================================
-- COMMAND_HISTORY: Execution tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS command_history (
    id SERIAL PRIMARY KEY,
    session_id INT NOT NULL REFERENCES target_sessions(id) ON DELETE CASCADE,
    command_id VARCHAR(255) REFERENCES commands(id) ON DELETE SET NULL,
    executed_command TEXT NOT NULL,                 -- Full command with variables filled
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    exit_code INT,
    duration_ms INT,                                -- Execution time in milliseconds
    output_file TEXT,                               -- Path to saved output
    findings_count INT DEFAULT 0,
    success BOOLEAN,                                -- Determined by success_indicators
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_history_session ON command_history(session_id);
CREATE INDEX IF NOT EXISTS idx_history_command ON command_history(command_id);
CREATE INDEX IF NOT EXISTS idx_history_executed ON command_history(executed_at DESC);

-- ============================================================================
-- CHAIN_REFERENCES: External documentation links
-- ============================================================================
CREATE TABLE IF NOT EXISTS chain_references (
    id SERIAL PRIMARY KEY,
    chain_id VARCHAR(255) NOT NULL REFERENCES attack_chains(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    description TEXT,
    priority INT DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_chain_refs_chain ON chain_references(chain_id);

-- ============================================================================
-- Schema Metadata
-- ============================================================================
CREATE TABLE IF NOT EXISTS schema_version (
    version VARCHAR(20) PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

INSERT INTO schema_version (version, description) VALUES
('1.0.0', 'Initial schema: 17 tables for commands, services, chains, findings, sessions')
ON CONFLICT (version) DO NOTHING;
