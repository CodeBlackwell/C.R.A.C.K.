-- Migration 004: NFS Plugin Command Definitions
-- Populates commands and task templates for NFS service plugin
-- SCHEMA-ALIGNED with actual database structure
--
-- Date: 2025-10-28
-- Plugin: nfs (2049/tcp, 111/tcp RPC)
-- Commands: 8 core NFS enumeration commands
--
-- Tables populated:
--   - variables (common placeholders)
--   - commands (command definitions)
--   - command_vars (command-variable links)
--   - command_flags (flag explanations)
--   - command_indicators (success/failure patterns)
--   - command_tags (tag assignments)
--   - plugin_task_templates (task definitions)

BEGIN TRANSACTION;

-- =============================================================================
-- Step 1: Ensure Common Variables Exist
-- =============================================================================

INSERT INTO variables (name, description, data_type, default_value, source)
VALUES
    ('<TARGET>', 'Target IP address or hostname', 'ip', NULL, 'user'),
    ('<PORT>', 'Service port number', 'port', NULL, 'user'),
    ('<LHOST>', 'Local attacker IP (for reverse shells, listeners)', 'ip', NULL, 'config'),
    ('<LPORT>', 'Local attacker port (for reverse shells, listeners)', 'port', '4444', 'config'),
    ('<EXPORT_PATH>', 'NFS export path from showmount output', 'string', NULL, 'user')
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    data_type = EXCLUDED.data_type,
    default_value = EXCLUDED.default_value,
    source = EXCLUDED.source
WHERE (
    variables.description IS DISTINCT FROM EXCLUDED.description OR
    variables.data_type IS DISTINCT FROM EXCLUDED.data_type OR
    variables.default_value IS DISTINCT FROM EXCLUDED.default_value OR
    variables.source IS DISTINCT FROM EXCLUDED.source
);

-- =============================================================================
-- Step 2: Insert NFS Commands (8 commands)
-- =============================================================================

-- Command 1: RPC Service Information
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'nfs-rpcinfo',
    'RPC Service Information',
    'rpcinfo -p <TARGET>',
    'Query RPC portmapper to discover NFS-related services and ports',
    'recon',
    'nfs',
    'high',
    'RPC portmapper (port 111) must be open. NFSv4 may not require portmapper. Time: ~5 seconds. Manual alternative: nmap -sV -p 111,<PORT> --script=rpcinfo <TARGET>'
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    command_template = EXCLUDED.command_template,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    subcategory = EXCLUDED.subcategory,
    oscp_relevance = EXCLUDED.oscp_relevance,
    notes = EXCLUDED.notes
WHERE (
    commands.name IS DISTINCT FROM EXCLUDED.name OR
    commands.command_template IS DISTINCT FROM EXCLUDED.command_template OR
    commands.description IS DISTINCT FROM EXCLUDED.description OR
    commands.category IS DISTINCT FROM EXCLUDED.category OR
    commands.subcategory IS DISTINCT FROM EXCLUDED.subcategory OR
    commands.oscp_relevance IS DISTINCT FROM EXCLUDED.oscp_relevance OR
    commands.notes IS DISTINCT FROM EXCLUDED.notes
);

-- Link variables
INSERT INTO command_vars (command_id, variable_id, position, is_required, example_value)
VALUES
    ('nfs-rpcinfo', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.45.100') ON CONFLICT (command_id, variable_id) DO NOTHING;

-- Add flags
INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('nfs-rpcinfo', '-p', 'Probe RPC portmapper on target and display all registered programs') ON CONFLICT (command_id, flag) DO NOTHING;

-- Add indicators
INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('nfs-rpcinfo', 'success', 'mountd', 'literal', 'NFS mount daemon detected'),
    ('nfs-rpcinfo', 'success', 'nfs', 'literal', 'NFS service found'),
    ('nfs-rpcinfo', 'success', 'nlockmgr', 'literal', 'NFS lock manager detected'),
    ('nfs-rpcinfo', 'failure', 'Connection refused', 'literal', 'Port 111/tcp closed'),
    ('nfs-rpcinfo', 'failure', 'RPC: Program not registered', 'literal', 'RPC service not available') ON CONFLICT DO NOTHING;

-- Add tags
INSERT INTO tags (name) VALUES ('OSCP:HIGH'), ('OSCP:MEDIUM'), ('OSCP:LOW'), ('QUICK_WIN'), ('MANUAL'), ('AUTOMATED'), ('CRITICAL'), ('ENUM'), ('EXPLOIT'), ('LINUX'), ('WINDOWS'), ('NOISY'), ('NSE'), ('POST_ACCESS'), ('REQUIRES_AUTH'), ('REQUIRES_SHELL'), ('RESEARCH'), ('QUICK_WIN'), ('MANUAL'), ('ENUM')
ON CONFLICT (name) DO UPDATE SET
    category = EXCLUDED.category,
    description = EXCLUDED.description,
    color = EXCLUDED.color
WHERE (
    tags.category IS DISTINCT FROM EXCLUDED.category OR
    tags.description IS DISTINCT FROM EXCLUDED.description OR
    tags.color IS DISTINCT FROM EXCLUDED.color
);
INSERT INTO command_tags (command_id, tag_id) VALUES
    ('nfs-rpcinfo', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('nfs-rpcinfo', (SELECT id FROM tags WHERE name = 'QUICK_WIN')),
    ('nfs-rpcinfo', (SELECT id FROM tags WHERE name = 'MANUAL')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 2: NFS Share Discovery (showmount)
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'nfs-showmount',
    'NFS Share Discovery',
    'showmount -e <TARGET>',
    'List all NFS exports and their access controls (NFSv3)',
    'recon',
    'nfs',
    'high',
    'showmount only works with NFSv3. NFSv4 requires direct mount attempts. May be disabled even if NFS is running. Time: 5-10 seconds. Alternative: nmap -p <PORT> --script nfs-showmount <TARGET>'
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    command_template = EXCLUDED.command_template,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    subcategory = EXCLUDED.subcategory,
    oscp_relevance = EXCLUDED.oscp_relevance,
    notes = EXCLUDED.notes
WHERE (
    commands.name IS DISTINCT FROM EXCLUDED.name OR
    commands.command_template IS DISTINCT FROM EXCLUDED.command_template OR
    commands.description IS DISTINCT FROM EXCLUDED.description OR
    commands.category IS DISTINCT FROM EXCLUDED.category OR
    commands.subcategory IS DISTINCT FROM EXCLUDED.subcategory OR
    commands.oscp_relevance IS DISTINCT FROM EXCLUDED.oscp_relevance OR
    commands.notes IS DISTINCT FROM EXCLUDED.notes
);

INSERT INTO command_vars (command_id, variable_id, position, is_required, example_value)
VALUES
    ('nfs-showmount', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.45.100') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('nfs-showmount', '-e', 'Show export list (directories available for mounting)') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('nfs-showmount', 'success', 'Export list', 'literal', 'NFS exports discovered'),
    ('nfs-showmount', 'success', '/home', 'literal', 'Home directory export found'),
    ('nfs-showmount', 'success', 'everyone', 'literal', 'Export allows universal access'),
    ('nfs-showmount', 'failure', 'clnt_create: RPC: Program not registered', 'literal', 'NFSv4 or showmount disabled'),
    ('nfs-showmount', 'failure', 'Export list is empty', 'literal', 'No shares exported'),
    ('nfs-showmount', 'failure', 'Permission denied', 'literal', 'IP-based restrictions active') ON CONFLICT DO NOTHING;

INSERT INTO command_tags (command_id, tag_id) VALUES
    ('nfs-showmount', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('nfs-showmount', (SELECT id FROM tags WHERE name = 'QUICK_WIN')),
    ('nfs-showmount', (SELECT id FROM tags WHERE name = 'ENUM')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 3: Nmap NFS-LS Script
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'nfs-nmap-ls',
    'NFS Directory Listing (Nmap)',
    'nmap -p <PORT> --script nfs-ls <TARGET>',
    'List NFS exports and enumerate directory contents remotely',
    'recon',
    'nfs',
    'high',
    'Requires successful export discovery. May reveal sensitive file paths without mounting. Time: 30-60 seconds. Manual alternative: showmount -e <TARGET> && mount -t nfs <TARGET>:/export /mnt/nfs && ls -la /mnt/nfs'
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    command_template = EXCLUDED.command_template,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    subcategory = EXCLUDED.subcategory,
    oscp_relevance = EXCLUDED.oscp_relevance,
    notes = EXCLUDED.notes
WHERE (
    commands.name IS DISTINCT FROM EXCLUDED.name OR
    commands.command_template IS DISTINCT FROM EXCLUDED.command_template OR
    commands.description IS DISTINCT FROM EXCLUDED.description OR
    commands.category IS DISTINCT FROM EXCLUDED.category OR
    commands.subcategory IS DISTINCT FROM EXCLUDED.subcategory OR
    commands.oscp_relevance IS DISTINCT FROM EXCLUDED.oscp_relevance OR
    commands.notes IS DISTINCT FROM EXCLUDED.notes
);

INSERT INTO command_vars (command_id, variable_id, position, is_required, example_value)
VALUES
    ('nfs-nmap-ls', (SELECT id FROM variables WHERE name = '<TARGET>'), 2, TRUE, '192.168.45.100'),
    ('nfs-nmap-ls', (SELECT id FROM variables WHERE name = '<PORT>'), 1, TRUE, '2049') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('nfs-nmap-ls', '-p', 'Target NFS port (usually 2049)'),
    ('nfs-nmap-ls', '--script nfs-ls', 'NSE script to list NFS exports and directory contents') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('nfs-nmap-ls', 'success', 'Directory structure', 'literal', 'Files and directories enumerated'),
    ('nfs-nmap-ls', 'success', 'UID', 'literal', 'File ownership visible'),
    ('nfs-nmap-ls', 'failure', 'Access denied', 'literal', 'IP restrictions prevent access'),
    ('nfs-nmap-ls', 'failure', 'No exports found', 'literal', 'No accessible exports'),
    ('nfs-nmap-ls', 'failure', 'Script timeout', 'literal', 'Firewall or filtering blocking') ON CONFLICT DO NOTHING;

INSERT INTO command_tags (command_id, tag_id) VALUES
    ('nfs-nmap-ls', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('nfs-nmap-ls', (SELECT id FROM tags WHERE name = 'ENUM')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 4: Nmap NFS-Showmount Script
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'nfs-nmap-showmount',
    'NFS Showmount (Nmap NSE)',
    'nmap -p <PORT> --script nfs-showmount <TARGET>',
    'NSE alternative to showmount command for export discovery',
    'recon',
    'nfs',
    'medium',
    'Same functionality as showmount -e but through Nmap. Use if showmount not available. Time: 10-15 seconds'
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    command_template = EXCLUDED.command_template,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    subcategory = EXCLUDED.subcategory,
    oscp_relevance = EXCLUDED.oscp_relevance,
    notes = EXCLUDED.notes
WHERE (
    commands.name IS DISTINCT FROM EXCLUDED.name OR
    commands.command_template IS DISTINCT FROM EXCLUDED.command_template OR
    commands.description IS DISTINCT FROM EXCLUDED.description OR
    commands.category IS DISTINCT FROM EXCLUDED.category OR
    commands.subcategory IS DISTINCT FROM EXCLUDED.subcategory OR
    commands.oscp_relevance IS DISTINCT FROM EXCLUDED.oscp_relevance OR
    commands.notes IS DISTINCT FROM EXCLUDED.notes
);

INSERT INTO command_vars (command_id, variable_id, position, is_required, example_value)
VALUES
    ('nfs-nmap-showmount', (SELECT id FROM variables WHERE name = '<TARGET>'), 2, TRUE, '192.168.45.100'),
    ('nfs-nmap-showmount', (SELECT id FROM variables WHERE name = '<PORT>'), 1, TRUE, '2049') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('nfs-nmap-showmount', '--script nfs-showmount', 'Emulates showmount -e functionality via Nmap') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('nfs-nmap-showmount', 'success', 'Exports', 'literal', 'Export list discovered'),
    ('nfs-nmap-showmount', 'success', 'mount points', 'literal', 'Mount points listed'),
    ('nfs-nmap-showmount', 'failure', 'No exports found', 'literal', 'No accessible exports'),
    ('nfs-nmap-showmount', 'failure', 'RPC timeout', 'literal', 'RPC service not responding') ON CONFLICT DO NOTHING;

INSERT INTO tags (name) VALUES ('OSCP:MEDIUM'), ('AUTOMATED')
ON CONFLICT (name) DO UPDATE SET
    category = EXCLUDED.category,
    description = EXCLUDED.description,
    color = EXCLUDED.color
WHERE (
    tags.category IS DISTINCT FROM EXCLUDED.category OR
    tags.description IS DISTINCT FROM EXCLUDED.description OR
    tags.color IS DISTINCT FROM EXCLUDED.color
);
INSERT INTO command_tags (command_id, tag_id) VALUES
    ('nfs-nmap-showmount', (SELECT id FROM tags WHERE name = 'OSCP:MEDIUM')),
    ('nfs-nmap-showmount', (SELECT id FROM tags WHERE name = 'ENUM')),
    ('nfs-nmap-showmount', (SELECT id FROM tags WHERE name = 'AUTOMATED')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 5: Nmap NFS-Statfs Script
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'nfs-nmap-statfs',
    'NFS Filesystem Statistics',
    'nmap -p <PORT> --script nfs-statfs <TARGET>',
    'Gather NFS filesystem statistics (disk space, free space, block size)',
    'recon',
    'nfs',
    'low',
    'Low priority for OSCP. Useful for data exfiltration planning or identifying storage capacity. Time: 10-15 seconds. Manual: mount -t nfs <TARGET>:/export /mnt && df -h /mnt'
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    command_template = EXCLUDED.command_template,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    subcategory = EXCLUDED.subcategory,
    oscp_relevance = EXCLUDED.oscp_relevance,
    notes = EXCLUDED.notes
WHERE (
    commands.name IS DISTINCT FROM EXCLUDED.name OR
    commands.command_template IS DISTINCT FROM EXCLUDED.command_template OR
    commands.description IS DISTINCT FROM EXCLUDED.description OR
    commands.category IS DISTINCT FROM EXCLUDED.category OR
    commands.subcategory IS DISTINCT FROM EXCLUDED.subcategory OR
    commands.oscp_relevance IS DISTINCT FROM EXCLUDED.oscp_relevance OR
    commands.notes IS DISTINCT FROM EXCLUDED.notes
);

INSERT INTO command_vars (command_id, variable_id, position, is_required, example_value)
VALUES
    ('nfs-nmap-statfs', (SELECT id FROM variables WHERE name = '<TARGET>'), 2, TRUE, '192.168.45.100'),
    ('nfs-nmap-statfs', (SELECT id FROM variables WHERE name = '<PORT>'), 1, TRUE, '2049') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('nfs-nmap-statfs', '--script nfs-statfs', 'Retrieve filesystem statistics from NFS shares') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('nfs-nmap-statfs', 'success', 'Disk space', 'literal', 'Filesystem statistics retrieved'),
    ('nfs-nmap-statfs', 'success', 'Available space', 'literal', 'Free space information obtained'),
    ('nfs-nmap-statfs', 'failure', 'Access denied', 'literal', 'Statistics unavailable'),
    ('nfs-nmap-statfs', 'failure', 'Script timeout', 'literal', 'No response from NFS service') ON CONFLICT DO NOTHING;

INSERT INTO tags (name) VALUES ('OSCP:LOW')
ON CONFLICT (name) DO UPDATE SET
    category = EXCLUDED.category,
    description = EXCLUDED.description,
    color = EXCLUDED.color
WHERE (
    tags.category IS DISTINCT FROM EXCLUDED.category OR
    tags.description IS DISTINCT FROM EXCLUDED.description OR
    tags.color IS DISTINCT FROM EXCLUDED.color
);
INSERT INTO command_tags (command_id, tag_id) VALUES
    ('nfs-nmap-statfs', (SELECT id FROM tags WHERE name = 'OSCP:LOW')),
    ('nfs-nmap-statfs', (SELECT id FROM tags WHERE name = 'ENUM')),
    ('nfs-nmap-statfs', (SELECT id FROM tags WHERE name = 'AUTOMATED')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 6: Metasploit NFS Mount Scanner
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'nfs-msf-nfsmount',
    'Metasploit NFS Mount Scanner',
    'msfconsole -q -x "use auxiliary/scanner/nfs/nfsmount; set RHOSTS <TARGET>; set RPORT <PORT>; run; exit"',
    'Scan and enumerate NFS mounts with permission analysis using Metasploit',
    'recon',
    'nfs',
    'medium',
    'Metasploit alternative to showmount. Useful if standard tools unavailable or for consistent output format. Time: 20-30 seconds. Alternative: showmount -e <TARGET>'
);

INSERT INTO command_vars (command_id, variable_id, position, is_required, example_value)
VALUES
    ('nfs-msf-nfsmount', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.45.100'),
    ('nfs-msf-nfsmount', (SELECT id FROM variables WHERE name = '<PORT>'), 2, TRUE, '2049') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('nfs-msf-nfsmount', '-q', 'Quiet mode (suppress Metasploit banner)'),
    ('nfs-msf-nfsmount', '-x', 'Execute commands and exit'),
    ('nfs-msf-nfsmount', 'use auxiliary/scanner/nfs/nfsmount', 'Load NFS mount scanner module'),
    ('nfs-msf-nfsmount', 'set RHOSTS', 'Set target IP address'),
    ('nfs-msf-nfsmount', 'set RPORT', 'Set NFS port (usually 2049)') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('nfs-msf-nfsmount', 'success', 'Exports discovered', 'literal', 'NFS exports found'),
    ('nfs-msf-nfsmount', 'success', 'READ', 'literal', 'Read permissions identified'),
    ('nfs-msf-nfsmount', 'success', 'WRITE', 'literal', 'Write permissions identified'),
    ('nfs-msf-nfsmount', 'failure', 'No exports found', 'literal', 'No accessible exports'),
    ('nfs-msf-nfsmount', 'failure', 'Connection refused', 'literal', 'NFS service unavailable'),
    ('nfs-msf-nfsmount', 'failure', 'RPC error', 'literal', 'Version incompatibility') ON CONFLICT DO NOTHING;

INSERT INTO command_tags (command_id, tag_id) VALUES
    ('nfs-msf-nfsmount', (SELECT id FROM tags WHERE name = 'OSCP:MEDIUM')),
    ('nfs-msf-nfsmount', (SELECT id FROM tags WHERE name = 'ENUM')),
    ('nfs-msf-nfsmount', (SELECT id FROM tags WHERE name = 'AUTOMATED')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 7: Mount NFS Share (NFSv2 - No Auth)
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'nfs-mount-nfsv2',
    'Mount NFS Share (NFSv2)',
    'mkdir -p /mnt/nfs_<TARGET> && mount -t nfs -o vers=2,nolock <TARGET>:<EXPORT_PATH> /mnt/nfs_<TARGET>',
    'Mount NFS export using version 2 (no authentication) for maximum access',
    'exploitation',
    'nfs',
    'high',
    'NFSv2 bypasses most authentication. Replace <EXPORT_PATH> with actual export from showmount. Create mount point first. Always unmount when done: umount /mnt/nfs_<TARGET>. Time: 10-15 seconds'
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    command_template = EXCLUDED.command_template,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    subcategory = EXCLUDED.subcategory,
    oscp_relevance = EXCLUDED.oscp_relevance,
    notes = EXCLUDED.notes
WHERE (
    commands.name IS DISTINCT FROM EXCLUDED.name OR
    commands.command_template IS DISTINCT FROM EXCLUDED.command_template OR
    commands.description IS DISTINCT FROM EXCLUDED.description OR
    commands.category IS DISTINCT FROM EXCLUDED.category OR
    commands.subcategory IS DISTINCT FROM EXCLUDED.subcategory OR
    commands.oscp_relevance IS DISTINCT FROM EXCLUDED.oscp_relevance OR
    commands.notes IS DISTINCT FROM EXCLUDED.notes
);

INSERT INTO command_vars (command_id, variable_id, position, is_required, example_value)
VALUES
    ('nfs-mount-nfsv2', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.45.100'),
    ('nfs-mount-nfsv2', (SELECT id FROM variables WHERE name = '<EXPORT_PATH>'), 2, TRUE, '/home') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('nfs-mount-nfsv2', '-t nfs', 'Filesystem type is NFS'),
    ('nfs-mount-nfsv2', '-o vers=2', 'Force NFSv2 (no authentication or authorization)'),
    ('nfs-mount-nfsv2', '-o nolock', 'Disable file locking (avoids lock manager issues)'),
    ('nfs-mount-nfsv2', 'mkdir -p', 'Create mount point directory if it does not exist') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('nfs-mount-nfsv2', 'success', 'Mount succeeds', 'literal', 'NFS share successfully mounted'),
    ('nfs-mount-nfsv2', 'success', 'ls command shows', 'literal', 'Directory contents accessible'),
    ('nfs-mount-nfsv2', 'failure', 'mount.nfs: access denied', 'literal', 'IP restrictions prevent mounting'),
    ('nfs-mount-nfsv2', 'failure', 'mount.nfs: Protocol not supported', 'literal', 'NFSv2 disabled on server'),
    ('nfs-mount-nfsv2', 'failure', 'mount.nfs: No such file or directory', 'literal', 'Invalid export path') ON CONFLICT DO NOTHING;

INSERT INTO tags (name) VALUES ('CRITICAL'), ('EXPLOIT')
ON CONFLICT (name) DO UPDATE SET
    category = EXCLUDED.category,
    description = EXCLUDED.description,
    color = EXCLUDED.color
WHERE (
    tags.category IS DISTINCT FROM EXCLUDED.category OR
    tags.description IS DISTINCT FROM EXCLUDED.description OR
    tags.color IS DISTINCT FROM EXCLUDED.color
);
INSERT INTO command_tags (command_id, tag_id) VALUES
    ('nfs-mount-nfsv2', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('nfs-mount-nfsv2', (SELECT id FROM tags WHERE name = 'MANUAL')),
    ('nfs-mount-nfsv2', (SELECT id FROM tags WHERE name = 'CRITICAL')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 8: Detect no_root_squash Misconfiguration
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'nfs-detect-norootsquash',
    'Detect no_root_squash Misconfiguration',
    'sudo touch /mnt/nfs_<TARGET>/root_test 2>/dev/null && sudo ls -l /mnt/nfs_<TARGET>/root_test',
    'Test if NFS share allows root UID (0) access without squashing to nobody',
    'exploitation',
    'nfs',
    'high',
    'no_root_squash is a CRITICAL misconfiguration allowing root-level exploitation. Default Linux configuration is root_squash (secure). This is a high-value OSCP target. Time: 30 seconds'
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    command_template = EXCLUDED.command_template,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    subcategory = EXCLUDED.subcategory,
    oscp_relevance = EXCLUDED.oscp_relevance,
    notes = EXCLUDED.notes
WHERE (
    commands.name IS DISTINCT FROM EXCLUDED.name OR
    commands.command_template IS DISTINCT FROM EXCLUDED.command_template OR
    commands.description IS DISTINCT FROM EXCLUDED.description OR
    commands.category IS DISTINCT FROM EXCLUDED.category OR
    commands.subcategory IS DISTINCT FROM EXCLUDED.subcategory OR
    commands.oscp_relevance IS DISTINCT FROM EXCLUDED.oscp_relevance OR
    commands.notes IS DISTINCT FROM EXCLUDED.notes
);

INSERT INTO command_vars (command_id, variable_id, position, is_required, example_value)
VALUES
    ('nfs-detect-norootsquash', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.45.100') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('nfs-detect-norootsquash', 'sudo', 'Execute command as root (UID 0)'),
    ('nfs-detect-norootsquash', 'touch', 'Create empty file (tests write permission)'),
    ('nfs-detect-norootsquash', 'ls -l', 'Long listing showing ownership'),
    ('nfs-detect-norootsquash', '2>/dev/null', 'Suppress errors if permission denied') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('nfs-detect-norootsquash', 'success', 'root root', 'literal', 'no_root_squash confirmed (CRITICAL VULNERABILITY)'),
    ('nfs-detect-norootsquash', 'success', 'File created', 'literal', 'Write access as root successful'),
    ('nfs-detect-norootsquash', 'failure', 'Permission denied', 'literal', 'root_squash enabled (secure)'),
    ('nfs-detect-norootsquash', 'failure', 'nobody', 'literal', 'Root UID squashed to nobody (secure)'),
    ('nfs-detect-norootsquash', 'failure', '65534', 'literal', 'Root UID squashed (GID 65534 = nobody)') ON CONFLICT DO NOTHING;

INSERT INTO tags (name) VALUES ('PRIVESC')
ON CONFLICT (name) DO UPDATE SET
    category = EXCLUDED.category,
    description = EXCLUDED.description,
    color = EXCLUDED.color
WHERE (
    tags.category IS DISTINCT FROM EXCLUDED.category OR
    tags.description IS DISTINCT FROM EXCLUDED.description OR
    tags.color IS DISTINCT FROM EXCLUDED.color
);
INSERT INTO command_tags (command_id, tag_id) VALUES
    ('nfs-detect-norootsquash', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('nfs-detect-norootsquash', (SELECT id FROM tags WHERE name = 'QUICK_WIN')),
    ('nfs-detect-norootsquash', (SELECT id FROM tags WHERE name = 'CRITICAL')),
    ('nfs-detect-norootsquash', (SELECT id FROM tags WHERE name = 'EXPLOIT')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================
-- Step 3: Insert NFS Plugin Task Templates (8 tasks)
-- =============================================================================

-- Task 1: RPC Service Information
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'nfs'),
    'nfs-rpcinfo',
    'RPC Service Information',
    'command',
    'nfs-rpcinfo',
    1,
    'Query RPC portmapper to discover NFS-related services',
    '["OSCP:HIGH", "QUICK_WIN", "MANUAL"]'
) ON CONFLICT DO NOTHING;

-- Task 2: NFS Share Discovery
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'nfs'),
    'nfs-showmount',
    'NFS Share Discovery',
    'command',
    'nfs-showmount',
    2,
    'List all NFS exports with showmount',
    '["OSCP:HIGH", "QUICK_WIN", "ENUM"]'
) ON CONFLICT DO NOTHING;

-- Task 3: Nmap NFS Directory Listing
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'nfs'),
    'nfs-nmap-ls',
    'NFS Directory Listing (Nmap)',
    'command',
    'nfs-nmap-ls',
    3,
    'List NFS exports and directory contents with Nmap',
    '["OSCP:HIGH", "ENUM", "AUTOMATED"]'
) ON CONFLICT DO NOTHING;

-- Task 4: Nmap NFS Showmount
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'nfs'),
    'nfs-nmap-showmount',
    'NFS Showmount (Nmap)',
    'command',
    'nfs-nmap-showmount',
    4,
    'Nmap NSE alternative to showmount',
    '["OSCP:MEDIUM", "ENUM", "AUTOMATED"]'
) ON CONFLICT DO NOTHING;

-- Task 5: Nmap NFS Filesystem Stats
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'nfs'),
    'nfs-nmap-statfs',
    'NFS Filesystem Statistics',
    'command',
    'nfs-nmap-statfs',
    5,
    'Gather NFS filesystem statistics with Nmap',
    '["OSCP:LOW", "ENUM", "AUTOMATED"]'
) ON CONFLICT DO NOTHING;

-- Task 6: Metasploit NFS Scanner
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'nfs'),
    'nfs-msf-nfsmount',
    'Metasploit NFS Mount Scanner',
    'command',
    'nfs-msf-nfsmount',
    6,
    'Scan and enumerate NFS mounts with Metasploit',
    '["OSCP:MEDIUM", "ENUM", "AUTOMATED"]'
) ON CONFLICT DO NOTHING;

-- Task 7: Mount NFS Share
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'nfs'),
    'nfs-mount',
    'Mount NFS Share (NFSv2)',
    'command',
    'nfs-mount-nfsv2',
    7,
    'Mount NFS export for direct file access',
    '["OSCP:HIGH", "MANUAL", "CRITICAL"]'
) ON CONFLICT DO NOTHING;

-- Task 8: Detect no_root_squash
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'nfs'),
    'nfs-detect-norootsquash',
    'Detect no_root_squash',
    'command',
    'nfs-detect-norootsquash',
    8,
    'Test for no_root_squash misconfiguration (privilege escalation)',
    '["OSCP:HIGH", "QUICK_WIN", "CRITICAL", "EXPLOIT"]'
) ON CONFLICT DO NOTHING;

COMMIT;

-- =============================================================================
-- Validation Queries
-- =============================================================================

-- Check NFS commands
-- SELECT COUNT(*) FROM commands WHERE subcategory = 'nfs';
-- Expected: 8

-- Check NFS task templates
-- SELECT COUNT(*) FROM plugin_task_templates
-- WHERE plugin_id = (SELECT id FROM service_plugins WHERE name = 'nfs');
-- Expected: 8

-- View NFS plugin tasks with commands
-- SELECT
--     t.priority,
--     t.task_id,
--     t.task_name,
--     c.name as command_name,
--     c.command_template
-- FROM plugin_task_templates t
-- LEFT JOIN commands c ON t.command_id = c.id
-- WHERE t.plugin_id = (SELECT id FROM service_plugins WHERE name = 'nfs')
-- ORDER BY t.priority;

-- Test task instance creation
-- python3 -c "
-- from db.repositories import PluginRepository
-- repo = PluginRepository()
-- instance = repo.create_task_instance('nfs', '192.168.45.100', 2049, {'service': 'nfs'})
-- import json
-- print(json.dumps(instance, indent=2))
-- "
