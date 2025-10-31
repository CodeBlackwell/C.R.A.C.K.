-- Migration 002: Service Plugin Integration
-- Extends the command registry to support service plugin task generation
--
-- Purpose: Enable service plugins to reference commands from SQL instead of hardcoding
-- Approach: Unified registry - both reference and plugin commands in same tables
--
-- Tables Added:
-- 1. service_plugins - Plugin registry (name, class, description)
-- 2. plugin_task_templates - Reusable task structures per plugin
-- 3. plugin_task_variables - Variable substitutions for task templates
--
-- Migration Date: 2025-10-29
-- Status: Initial pilot for 5 plugins (ftp, nfs, smtp, mysql, ssh)

-- =============================================================================
-- Table 1: Service Plugins Registry
-- =============================================================================

CREATE TABLE IF NOT EXISTS service_plugins (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,              -- Plugin name (e.g., 'ftp', 'mysql')
    python_class VARCHAR(255) NOT NULL,             -- Python class name (e.g., 'FTPPlugin')
    python_module VARCHAR(255) NOT NULL,            -- Module path (e.g., 'track.services.ftp')
    description TEXT,                               -- Plugin purpose
    service_patterns TEXT,                          -- JSON array of service name patterns
    default_ports TEXT,                             -- JSON array of default ports
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast plugin lookup by name
CREATE INDEX IF NOT EXISTS idx_service_plugins_name ON service_plugins(name);

-- =============================================================================
-- Table 2: Plugin Task Templates
-- =============================================================================

CREATE TABLE IF NOT EXISTS plugin_task_templates (
    id SERIAL PRIMARY KEY,
    plugin_id INTEGER NOT NULL,                     -- FK to service_plugins
    task_id VARCHAR(255) NOT NULL,                  -- Task identifier (without port suffix)
    task_name VARCHAR(500) NOT NULL,                -- Human-readable task name
    task_type VARCHAR(50) NOT NULL,                 -- 'parent', 'command', 'manual', 'research'
    parent_task_id INTEGER,                         -- FK to parent task (for hierarchy)
    command_id VARCHAR(255),                        -- FK to commands.id (unified registry)
    priority INTEGER DEFAULT 0,                     -- Execution order within parent
    description TEXT,                               -- Task purpose/notes
    tags TEXT,                                      -- JSON array of tags
    requires_auth BOOLEAN DEFAULT FALSE,                -- Task requires authentication
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plugin_id) REFERENCES service_plugins(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_task_id) REFERENCES plugin_task_templates(id) ON DELETE CASCADE,
    FOREIGN KEY (command_id) REFERENCES commands(id) ON DELETE SET NULL,
    CHECK (task_type IN ('parent', 'command', 'manual', 'research', 'finding'))
);

-- Indexes for task lookup
CREATE INDEX IF NOT EXISTS idx_plugin_tasks_plugin ON plugin_task_templates(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_tasks_parent ON plugin_task_templates(parent_task_id);
CREATE INDEX IF NOT EXISTS idx_plugin_tasks_command ON plugin_task_templates(command_id);
CREATE INDEX IF NOT EXISTS idx_plugin_tasks_type ON plugin_task_templates(task_type);

-- =============================================================================
-- Table 3: Plugin Task Variable Substitutions
-- =============================================================================

CREATE TABLE IF NOT EXISTS plugin_task_variables (
    id SERIAL PRIMARY KEY,
    task_template_id INTEGER NOT NULL,              -- FK to plugin_task_templates
    variable_name VARCHAR(50) NOT NULL,             -- Variable name (e.g., 'target', 'port')
    variable_source VARCHAR(50) NOT NULL,           -- Source: 'target', 'port', 'service_info', 'config', 'prompt'
    default_value TEXT,                             -- Default value if not provided
    required BOOLEAN DEFAULT TRUE,                     -- Is this variable required?
    description TEXT,                               -- Variable purpose
    FOREIGN KEY (task_template_id) REFERENCES plugin_task_templates(id) ON DELETE CASCADE,
    CHECK (variable_source IN ('target', 'port', 'service_info', 'config', 'prompt', 'static'))
);

-- Index for variable lookup
CREATE INDEX IF NOT EXISTS idx_plugin_vars_template ON plugin_task_variables(task_template_id);

-- =============================================================================
-- Table 4: Plugin Output Patterns (for future on_task_complete support)
-- =============================================================================
-- Note: Not used in Phase 4 Task 2 (deferred to Phase 5)
-- Included in schema for completeness

CREATE TABLE IF NOT EXISTS plugin_output_patterns (
    id SERIAL PRIMARY KEY,
    plugin_id INTEGER NOT NULL,                     -- FK to service_plugins
    task_template_id INTEGER,                       -- Optional: specific task this pattern applies to
    pattern_type VARCHAR(50) NOT NULL,              -- 'regex', 'substring', 'json_path', 'xml_path'
    pattern TEXT NOT NULL,                          -- The actual pattern
    description TEXT,                               -- What this pattern detects
    action_type VARCHAR(50),                        -- 'create_task', 'add_finding', 'set_variable'
    action_data TEXT,                               -- JSON: action-specific data
    priority INTEGER DEFAULT 0,                     -- Match priority (higher = check first)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plugin_id) REFERENCES service_plugins(id) ON DELETE CASCADE,
    FOREIGN KEY (task_template_id) REFERENCES plugin_task_templates(id) ON DELETE CASCADE,
    CHECK (pattern_type IN ('regex', 'substring', 'json_path', 'xml_path', 'startswith', 'contains')),
    CHECK (action_type IN ('create_task', 'add_finding', 'set_variable', 'emit_event'))
);

-- Index for pattern matching
CREATE INDEX IF NOT EXISTS idx_plugin_patterns_plugin ON plugin_output_patterns(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_patterns_task ON plugin_output_patterns(task_template_id);

-- =============================================================================
-- Sample Data: Pilot Plugins (5 plugins)
-- =============================================================================

-- Plugin 1: FTP
INSERT INTO service_plugins (name, python_class, python_module, description, service_patterns, default_ports)
VALUES (
    'ftp',
    'FTPPlugin',
    'track.services.ftp',
    'File Transfer Protocol enumeration and exploitation',
    '["ftp", "vsftpd", "proftpd"]',
    '[21, 2121]'
);

-- Plugin 2: NFS
INSERT INTO service_plugins (name, python_class, python_module, description, service_patterns, default_ports)
VALUES (
    'nfs',
    'NFSPlugin',
    'track.services.nfs',
    'Network File System enumeration and mounting',
    '["nfs", "nfsd", "rpc.nfsd"]',
    '[2049, 111]'
);

-- Plugin 3: SMTP
INSERT INTO service_plugins (name, python_class, python_module, description, service_patterns, default_ports)
VALUES (
    'smtp',
    'SMTPPlugin',
    'track.services.smtp',
    'Simple Mail Transfer Protocol enumeration',
    '["smtp", "smtpd", "postfix", "sendmail", "exim"]',
    '[25, 465, 587]'
);

-- Plugin 4: MySQL
INSERT INTO service_plugins (name, python_class, python_module, description, service_patterns, default_ports)
VALUES (
    'mysql',
    'MySQLPlugin',
    'track.services.mysql',
    'MySQL/MariaDB database enumeration and exploitation',
    '["mysql", "mariadb", "mysql-server"]',
    '[3306]'
);

-- Plugin 5: SSH
INSERT INTO service_plugins (name, python_class, python_module, description, service_patterns, default_ports)
VALUES (
    'ssh',
    'SSHPlugin',
    'track.services.ssh',
    'Secure Shell enumeration and exploitation',
    '["ssh", "openssh", "dropbear"]',
    '[22, 2222]'
);

-- =============================================================================
-- Schema Version Update
-- =============================================================================

UPDATE schema_version SET version = '2', description = 'Service plugin integration'
WHERE version = '1';

-- If no version exists, insert it
INSERT INTO schema_version (version, description) VALUES ('2', 'Service plugin integration') ON CONFLICT DO NOTHING;

-- =============================================================================
-- Migration Complete
-- =============================================================================

-- Validation Queries:
-- SELECT COUNT(*) FROM service_plugins;              -- Should show 5
-- SELECT COUNT(*) FROM plugin_task_templates;        -- Will be populated by plugin migration
-- SELECT * FROM service_plugins;                     -- List all registered plugins
