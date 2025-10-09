"""
Anti-Forensics Alternative Commands

Manual alternatives for log clearing, timestamp manipulation, and covering tracks.
Focus: OSCP-viable manual techniques without specialized tools.

Extracted from: HackTricks anti-forensics plugin
Quality: 5 HIGH IMPACT alternatives (manual alternatives to automated tools)
"""

from ..models import AlternativeCommand, Variable


ALTERNATIVES = [
    # ============================================================================
    # LOG CLEARING (Linux)
    # ============================================================================

    AlternativeCommand(
        id='alt-clear-bash-history',
        name='Clear Bash History',
        command_template='history -c && rm -f ~/.bash_history ~/.zsh_history ~/.python_history',
        description='Clear shell command history (immediate + persistent)',
        category='anti-forensics',
        subcategory='log-clearing',
        variables=[],
        tags=['OSCP:HIGH', 'POST_EXPLOIT', 'LINUX', 'NOISY', 'QUICK_WIN'],
        os_type='linux',
        flag_explanations={
            'history -c': 'Clear in-memory command history for current shell session',
            'rm -f': 'Force remove files without prompting (ignore if files do not exist)',
            '~/.bash_history': 'Bash shell persistent history file',
            '~/.zsh_history': 'Zsh shell persistent history file',
            '~/.python_history': 'Python REPL interactive history file'
        },
        success_indicators=[
            'History files deleted',
            'history command shows no entries',
            'No command trail visible on logout'
        ],
        failure_indicators=[
            'Files recreated on next command',
            'History still visible in /proc or ps output'
        ],
        next_steps=[
            'Prevent future logging: unset HISTFILE',
            'Disable for session: set +o history'
        ],
        notes='OSCP Exam: Clear before disconnecting. Document in writeup with timestamp. Extremely suspicious to defenders.',
        parent_task_pattern='*post-exploit*'
    ),

    # ============================================================================
    # TIMESTAMP MANIPULATION (Linux)
    # ============================================================================

    AlternativeCommand(
        id='alt-touch-timestamps',
        name='Copy File Timestamps',
        command_template='touch -r <REFERENCE_FILE> <TARGET_FILE>',
        description='Copy timestamps from legitimate file to malicious file (blend in with system files)',
        category='anti-forensics',
        subcategory='timestamp-manipulation',
        variables=[
            Variable('REFERENCE_FILE', 'Legitimate system file to copy timestamps from', '/bin/ls', auto_resolve=False),
            Variable('TARGET_FILE', 'Malicious file to modify timestamps on', '/tmp/malicious.sh', auto_resolve=False)
        ],
        tags=['OSCP:HIGH', 'POST_EXPLOIT', 'LINUX', 'STEALTH'],
        os_type='linux',
        flag_explanations={
            'touch': 'Change file access and modification times',
            '-r': 'Use timestamps from reference file instead of current time (copy mode)'
        },
        success_indicators=[
            'Timestamps match reference file exactly',
            'ls -la shows modified time matching reference',
            'stat command shows all timestamps aligned'
        ],
        failure_indicators=[
            'Permission denied on target file',
            'Filesystem mounted with noatime (access time updates disabled)'
        ],
        next_steps=[
            'Verify with: stat <TARGET_FILE>',
            'Check filesystem mount options: grep -E \'(noatime|relatime)\' /proc/mounts'
        ],
        notes='Blends malicious files into legitimate timestamp timeline. Makes forensic timeline analysis harder. Choose reference files from same directory for authenticity.',
        parent_task_pattern='*post-exploit*'
    ),

    # ============================================================================
    # SECURE DELETION (Linux)
    # ============================================================================

    AlternativeCommand(
        id='alt-shred-file',
        name='Shred File (Secure Deletion)',
        command_template='shred -vfz -n 10 <FILE>',
        description='Overwrite file multiple times before deletion (prevents recovery)',
        category='anti-forensics',
        subcategory='secure-deletion',
        variables=[
            Variable('FILE', 'File to securely delete', '/tmp/sensitive.txt', auto_resolve=False)
        ],
        tags=['OSCP:HIGH', 'POST_EXPLOIT', 'LINUX', 'MANUAL'],
        os_type='linux',
        flag_explanations={
            'shred': 'Overwrite file contents to hide original data',
            '-v': 'Verbose output showing progress of each overwrite pass',
            '-f': 'Force operation - change permissions if needed to allow writing',
            '-z': 'Add final overwrite with zeros to hide that shredding occurred',
            '-n 10': 'Number of overwrite passes (10 is thorough, default is 3)'
        },
        success_indicators=[
            'File overwritten 10 times',
            'Original data unrecoverable',
            'File deleted after final overwrite'
        ],
        failure_indicators=[
            'Journaling filesystem may retain data in journal (ext3/ext4)',
            'SSD wear leveling defeats overwriting (data may persist on unmapped blocks)',
            'File was copied elsewhere before shredding'
        ],
        next_steps=[
            'Verify deletion: ls -la <FILE>',
            'Check for copies: find / -name <filename> 2>/dev/null'
        ],
        notes='Best-effort secure deletion. SSDs and journaling filesystems may retain data. For exams: document that file was shredded and verification steps taken.',
        parent_task_pattern='*post-exploit*'
    ),

    # ============================================================================
    # SSL/TLS CERTIFICATE ANALYSIS (Manual Alternative to Automated Tools)
    # ============================================================================

    AlternativeCommand(
        id='alt-openssl-cert-extract',
        name='Extract SSL Certificate',
        command_template='echo | openssl s_client -connect <TARGET>:<PORT> -showcerts 2>/dev/null | openssl x509 -outform PEM > cert.pem',
        description='Download and save server certificate for manual analysis (reveals hostnames, SANs, org details)',
        category='anti-forensics',
        subcategory='crypto-analysis',
        variables=[
            Variable('TARGET', 'Target hostname or IP address', '192.168.45.100', auto_resolve=True),
            Variable('PORT', 'HTTPS/TLS port', '443', auto_resolve=True)
        ],
        tags=['OSCP:MEDIUM', 'RECON', 'QUICK_WIN', 'MANUAL'],
        os_type='both',
        flag_explanations={
            'echo |': 'Send empty input to openssl (non-interactive mode)',
            's_client': 'OpenSSL SSL/TLS client program for establishing connections',
            '-connect': 'Specify target host:port to connect to',
            '-showcerts': 'Display full certificate chain (not just server cert)',
            'x509': 'X.509 certificate manipulation utility',
            '-outform PEM': 'Output certificate in PEM format (Base64-encoded)',
            '2>/dev/null': 'Suppress stderr error messages'
        },
        success_indicators=[
            'cert.pem file created',
            'BEGIN CERTIFICATE block visible in file',
            'Certificate downloaded successfully'
        ],
        failure_indicators=[
            'Connection refused (port not open)',
            'SSL handshake failure (protocol mismatch)',
            'Empty cert.pem file'
        ],
        next_steps=[
            'Parse certificate: openssl x509 -in cert.pem -text -noout',
            'Extract SANs for subdomain discovery',
            'Check validity dates (expired certs = potential vulnerability)'
        ],
        notes='Certificates reveal internal hostnames, subdomains, and organization details. Check Subject Alternative Names (SANs) for additional targets.',
        parent_task_pattern='http*'
    ),

    # ============================================================================
    # ECB MODE DETECTION (Manual Crypto Analysis)
    # ============================================================================

    AlternativeCommand(
        id='alt-ecb-mode-detect',
        name='Detect ECB Mode Encryption',
        command_template='echo "<COOKIE>" | base64 -d | xxd',
        description='Manual detection of ECB mode (identical plaintext blocks = identical ciphertext blocks)',
        category='anti-forensics',
        subcategory='crypto-analysis',
        variables=[
            Variable('COOKIE', 'Base64-encoded cookie or ciphertext to analyze', 'aGVsbG93b3JsZA==', auto_resolve=False)
        ],
        tags=['OSCP:MEDIUM', 'EXPLOIT', 'MANUAL', 'WEB'],
        os_type='both',
        flag_explanations={
            'echo': 'Output the cookie value',
            'base64 -d': 'Decode base64-encoded data to raw binary',
            'xxd': 'Create hex dump of binary data (visualize byte patterns)'
        },
        success_indicators=[
            'Repeating hex patterns visible (indicates ECB mode)',
            'Identical blocks for repeated plaintext',
            'Block-level patterns in hex dump'
        ],
        failure_indicators=[
            'No repeating patterns (likely CBC/CTR mode)',
            'Random-looking output (strong encryption or IV in use)'
        ],
        next_steps=[
            'Create test users with controlled usernames (e.g., "aaaaaaaa")',
            'Identify block size (8 bytes for DES/Blowfish, 16 bytes for AES)',
            'Attempt block removal/reordering attacks'
        ],
        notes='ECB mode vulnerability: Allows block removal and reordering attacks. Example: username "aaaaaaaaadmin" -> remove first block -> "admin". Test with CyberChef or Python.',
        parent_task_pattern='http*'
    )
]
