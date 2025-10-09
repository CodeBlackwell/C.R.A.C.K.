"""
Proxychains configuration generator and manager.

Proxychains routes TCP connections through proxy chains (SOCKS4/SOCKS5/HTTP).
Essential for routing tools through pivots during internal network enumeration.
"""

from pathlib import Path
from typing import Optional, List, Dict, Any

from .models import Tunnel, TunnelConfig


class ProxychainsManager:
    """Proxychains configuration generation and management.

    Generates proxychains configuration files to route tools through
    SOCKS proxies created by SSH (-D), chisel, or other tunnels.

    Use Case:
        Route offensive tools through compromised hosts to access internal networks:
        - nmap scanning (proxychains nmap -sT 192.168.1.0/24)
        - Web enumeration (proxychains gobuster)
        - Exploitation (proxychains msfconsole)
        - Any TCP-based tool

    Important:
        - Use -sT for nmap (TCP connect, no SYN scan through proxy)
        - Some tools don't work with proxychains (ping, raw sockets)
        - DNS resolution happens through proxy (proxy_dns)

    Example:
        >>> from sessions.tunnel.proxychains import ProxychainsManager
        >>>
        >>> manager = ProxychainsManager()
        >>>
        >>> # Create proxychains config for SSH SOCKS proxy
        >>> config_path = manager.create_config(
        ...     proxy_host='127.0.0.1',
        ...     proxy_port=1080,
        ...     config_path='/tmp/proxychains.conf'
        ... )
        >>>
        >>> # Run nmap through proxy
        >>> cmd = manager.run_through_proxy(
        ...     command='nmap -sT -Pn 192.168.1.0/24',
        ...     config_path=config_path
        ... )
        >>> print(cmd)
        'proxychains -f /tmp/proxychains.conf nmap -sT -Pn 192.168.1.0/24'
    """

    DEFAULT_CONFIG_PATH = Path('/tmp/proxychains.conf')

    def __init__(self):
        """Initialize ProxychainsManager."""
        pass

    def create_config(self, proxy_host: str, proxy_port: int,
                     proxy_type: str = 'socks5',
                     config_path: Path = None,
                     chain_type: str = 'strict',
                     proxy_dns: bool = True,
                     tcp_read_timeout: int = 15000,
                     tcp_connect_timeout: int = 8000,
                     additional_proxies: List[Dict[str, Any]] = None) -> Path:
        """Generate proxychains configuration file.

        Creates a proxychains config file with specified proxy settings.

        Config Structure:
            [ProxyList]
            socks5 127.0.0.1 1080
            socks5 192.168.1.10 1080  (if chaining through multiple proxies)

        Args:
            proxy_host: Proxy server host (usually 127.0.0.1 for local SSH/chisel)
            proxy_port: Proxy server port (e.g., 1080 for SSH -D)
            proxy_type: Proxy type ('socks4', 'socks5', 'http') [default: socks5]
            config_path: Output config path (default: /tmp/proxychains.conf)
            chain_type: Chain type ('strict', 'dynamic', 'random') [default: strict]
            proxy_dns: Resolve DNS through proxy (default: True)
            tcp_read_timeout: TCP read timeout in ms (default: 15000)
            tcp_connect_timeout: TCP connect timeout in ms (default: 8000)
            additional_proxies: List of additional proxies for chaining

        Returns:
            Path to generated config file

        Raises:
            IOError: If config file cannot be written

        Example:
            >>> # Simple SOCKS5 proxy config
            >>> config_path = manager.create_config(
            ...     proxy_host='127.0.0.1',
            ...     proxy_port=1080
            ... )
            >>>
            >>> # SOCKS4 proxy with custom timeouts
            >>> config_path = manager.create_config(
            ...     proxy_host='127.0.0.1',
            ...     proxy_port=1080,
            ...     proxy_type='socks4',
            ...     tcp_read_timeout=30000
            ... )
            >>>
            >>> # Multiple proxy chain (pivot through multiple hosts)
            >>> config_path = manager.create_config(
            ...     proxy_host='127.0.0.1',
            ...     proxy_port=1080,
            ...     additional_proxies=[
            ...         {'type': 'socks5', 'host': '192.168.1.10', 'port': 1080}
            ...     ]
            ... )

        Chain Types:
            strict:  All proxies must work (fails if any proxy down)
            dynamic: Skips dead proxies, continues with alive ones
            random:  Selects random proxy from list for each connection
        """
        if config_path is None:
            config_path = self.DEFAULT_CONFIG_PATH

        config_path = Path(config_path)

        # Validate proxy type
        if proxy_type not in ['socks4', 'socks5', 'http']:
            raise ValueError(f"Invalid proxy type: {proxy_type}. Valid types: socks4, socks5, http")

        # Validate chain type
        if chain_type not in ['strict', 'dynamic', 'random']:
            raise ValueError(f"Invalid chain type: {chain_type}. Valid types: strict, dynamic, random")

        # Build configuration content
        config_lines = [
            "# Proxychains configuration generated by CRACK",
            f"# Primary proxy: {proxy_type}://{proxy_host}:{proxy_port}",
            "",
            "# Chain type (strict, dynamic, random)",
            f"{chain_type}_chain",
            ""
        ]

        # Add proxy DNS if enabled
        if proxy_dns:
            config_lines.extend([
                "# Proxy DNS requests through proxy (recommended)",
                "proxy_dns",
                ""
            ])

        # Add timeouts
        config_lines.extend([
            "# Timeout settings (milliseconds)",
            f"tcp_read_time_out {tcp_read_timeout}",
            f"tcp_connect_time_out {tcp_connect_timeout}",
            ""
        ])

        # Add quiet mode (suppress proxychains output)
        config_lines.extend([
            "# Quiet mode (suppress proxychains messages)",
            "# quiet_mode",
            ""
        ])

        # Add proxy list section
        config_lines.extend([
            "# Proxy list",
            "[ProxyList]",
            f"{proxy_type} {proxy_host} {proxy_port}"
        ])

        # Add additional proxies if specified (for multi-hop pivoting)
        if additional_proxies:
            for proxy in additional_proxies:
                ptype = proxy.get('type', 'socks5')
                phost = proxy.get('host')
                pport = proxy.get('port')
                if phost and pport:
                    config_lines.append(f"{ptype} {phost} {pport}")

        # Write config file
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                f.write('\n'.join(config_lines) + '\n')

            print(f"[+] Proxychains config written to: {config_path}")
            return config_path

        except IOError as e:
            raise IOError(f"Failed to write proxychains config: {e}")

    def run_through_proxy(self, command: str, config_path: Path = None,
                         quiet: bool = False) -> str:
        """Generate proxychains command wrapper.

        Wraps a command with proxychains to route it through proxy.

        Args:
            command: Command to run through proxy
            config_path: Path to proxychains config (default: /tmp/proxychains.conf)
            quiet: Suppress proxychains output (default: False)

        Returns:
            Full command string with proxychains wrapper

        Example:
            >>> # Run nmap through proxy
            >>> cmd = manager.run_through_proxy('nmap -sT -Pn 192.168.1.0/24')
            >>> print(cmd)
            'proxychains -f /tmp/proxychains.conf nmap -sT -Pn 192.168.1.0/24'
            >>>
            >>> # Run msfconsole through proxy (quiet mode)
            >>> cmd = manager.run_through_proxy('msfconsole', quiet=True)
            >>> print(cmd)
            'proxychains -q -f /tmp/proxychains.conf msfconsole'

        OSCP Tool Examples:
            nmap:       proxychains nmap -sT -Pn 192.168.1.0/24
            gobuster:   proxychains gobuster dir -u http://192.168.1.10 -w wordlist.txt
            curl:       proxychains curl http://192.168.1.10
            msfconsole: proxychains msfconsole
            nikto:      proxychains nikto -h 192.168.1.10
            sqlmap:     proxychains sqlmap -u http://192.168.1.10/?id=1

        Important Notes:
            - Use nmap -sT (TCP connect scan, not SYN scan)
            - Use -Pn (skip ping, hosts may not respond to ICMP)
            - Some tools require -q flag for quiet mode
            - Raw socket tools (ping, traceroute) won't work
        """
        if config_path is None:
            config_path = self.DEFAULT_CONFIG_PATH

        cmd_parts = ['proxychains']

        if quiet:
            cmd_parts.append('-q')

        cmd_parts.extend(['-f', str(config_path)])
        cmd_parts.append(command)

        return ' '.join(cmd_parts)

    def create_tunnel_config(self, tunnel: Tunnel, config_path: Path = None) -> Path:
        """Create proxychains config from existing tunnel.

        Convenience method to generate proxychains config from an active tunnel
        (SSH -D, chisel SOCKS, etc.).

        Args:
            tunnel: Active tunnel instance
            config_path: Output config path (optional)

        Returns:
            Path to generated config file

        Raises:
            ValueError: If tunnel doesn't have SOCKS configuration

        Example:
            >>> # Create SSH SOCKS tunnel
            >>> ssh_tunnel = ssh.dynamic_socks(local_port=1080)
            >>>
            >>> # Generate proxychains config from tunnel
            >>> config_path = manager.create_tunnel_config(ssh_tunnel)
            >>>
            >>> # Run tools through tunnel
            >>> cmd = manager.run_through_proxy('nmap -sT 192.168.1.0/24', config_path)
        """
        # Extract SOCKS configuration from tunnel
        if tunnel.type == 'ssh-dynamic':
            proxy_host = '127.0.0.1'
            proxy_port = tunnel.config.socks_port
            proxy_type = 'socks5'

        elif tunnel.type == 'chisel' and 'socks' in str(tunnel.config.tunnel_spec):
            # Chisel SOCKS proxy
            proxy_host = '127.0.0.1'
            proxy_port = tunnel.config.server_port
            proxy_type = 'socks5'

        else:
            raise ValueError(f"Tunnel type {tunnel.type} does not provide SOCKS proxy")

        if not proxy_port:
            raise ValueError("Tunnel does not have SOCKS port configured")

        return self.create_config(
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            proxy_type=proxy_type,
            config_path=config_path
        )

    def get_usage_examples(self) -> str:
        """Get common proxychains usage examples.

        Returns:
            Formatted string with usage examples

        Example:
            >>> print(manager.get_usage_examples())
        """
        return """
=== Proxychains Usage Examples ===

1. Network Scanning:
   proxychains nmap -sT -Pn -p- 192.168.1.10
   proxychains nmap -sT -Pn -sV -sC 192.168.1.0/24

   Flags:
   -sT: TCP connect scan (required for proxychains, no SYN scan)
   -Pn: Skip ping (ICMP doesn't work through SOCKS)
   -p-: Scan all ports
   -sV: Version detection
   -sC: Default scripts

2. Web Enumeration:
   proxychains gobuster dir -u http://192.168.1.10 -w /usr/share/wordlists/dirb/common.txt
   proxychains nikto -h http://192.168.1.10
   proxychains curl http://192.168.1.10/admin

3. Web Application Testing:
   proxychains sqlmap -u http://192.168.1.10/?id=1 --batch
   proxychains wfuzz -u http://192.168.1.10/FUZZ -w wordlist.txt
   proxychains burpsuite

4. Exploitation:
   proxychains msfconsole
   proxychains use exploit/multi/handler
   proxychains searchsploit Apache 2.4

5. File Transfer:
   proxychains wget http://192.168.1.10/file.txt
   proxychains curl -O http://192.168.1.10/file.txt

6. Database Access:
   proxychains mysql -h 192.168.1.10 -u root -p
   proxychains psql -h 192.168.1.10 -U postgres

7. SMB Enumeration:
   proxychains smbclient -L //192.168.1.10
   proxychains enum4linux 192.168.1.10

Important Notes:
- Use -sT for nmap (TCP connect, not SYN)
- Use -Pn for nmap (skip ping check)
- ICMP tools (ping, traceroute) won't work
- UDP scanning won't work (SOCKS is TCP-only)
- DNS resolution happens through proxy (use proxy_dns)

Multi-Hop Pivoting:
1. Create SSH tunnel from Kali -> Host1:
   ssh -D 1080 user@host1.com

2. Create SSH tunnel from Host1 -> Host2:
   host1$ ssh -D 1081 user@host2.internal

3. Create proxychains config with both:
   [ProxyList]
   socks5 127.0.0.1 1080
   socks5 127.0.0.1 1081

4. Use tools:
   proxychains nmap -sT host3.internal
"""

    def __repr__(self):
        return "<ProxychainsManager>"
