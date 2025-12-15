#!/usr/bin/env python3
"""
CRACK Ports - Quick port reference for pentesting

Displays colorized chart of common ports with attack vectors.
"""

import sys
from typing import Optional

# Port data: (port, protocol, service, description, tools)
PORT_DATA = [
    # Critical AD/Domain Services
    (21, "TCP", "FTP", "File Transfer", "hydra, ftp-anon"),
    (22, "TCP", "SSH", "Secure Shell", "hydra, ssh-audit"),
    (23, "TCP", "Telnet", "Remote Login", "hydra, telnet"),
    (25, "TCP", "SMTP", "Mail Transfer", "smtp-user-enum, swaks"),
    (53, "TCP/UDP", "DNS", "Domain Service", "dig, dnsenum"),
    (69, "UDP", "TFTP", "Trivial FTP", "tftp, nmap"),
    (80, "TCP", "HTTP", "Web Server", "gobuster, nikto"),
    (88, "TCP", "Kerberos", "AD Auth", "kerbrute, GetNPUsers"),
    (110, "TCP", "POP3", "Mail Retrieval", "hydra, nc"),
    (111, "TCP/UDP", "RPC", "Remote Procedure", "rpcinfo, showmount"),
    (135, "TCP", "MSRPC", "Windows RPC", "rpcclient, impacket"),
    (137, "UDP", "NetBIOS-NS", "Name Service", "nbtscan, nmblookup"),
    (138, "UDP", "NetBIOS-DGM", "Datagram", "nbtscan"),
    (139, "TCP", "NetBIOS-SSN", "Session Service", "smbclient, enum4linux"),
    (143, "TCP", "IMAP", "Mail Access", "hydra, nc"),
    (161, "UDP", "SNMP", "Network Mgmt", "snmpwalk, onesixtyone"),
    (389, "TCP", "LDAP", "Directory Service", "ldapsearch, windapsearch"),
    (443, "TCP", "HTTPS", "Secure Web", "gobuster, sslscan"),
    (445, "TCP", "SMB", "File Sharing", "smbclient, crackmapexec"),
    (464, "TCP", "Kpasswd", "Kerberos Passwd", "kpasswd, impacket"),
    (512, "TCP", "rexec", "Remote Exec", "rlogin, rsh"),
    (513, "TCP", "rlogin", "Remote Login", "rlogin"),
    (514, "TCP/UDP", "RSH/Syslog", "Remote Shell", "rsh, nc"),
    (515, "TCP", "LPD", "Printer", "lpr"),
    (548, "TCP", "AFP", "Apple Filing", "nmap"),
    (554, "TCP", "RTSP", "Streaming", "nmap"),
    (587, "TCP", "SMTP-Sub", "Mail Submission", "swaks, hydra"),
    (593, "TCP", "HTTP-RPC", "RPC over HTTP", "rpcclient"),
    (623, "UDP", "IPMI", "Server Mgmt", "ipmitool, metasploit"),
    (636, "TCP", "LDAPS", "Secure LDAP", "ldapsearch"),
    (873, "TCP", "Rsync", "File Sync", "rsync, nmap"),
    (993, "TCP", "IMAPS", "Secure IMAP", "hydra, openssl"),
    (995, "TCP", "POP3S", "Secure POP3", "hydra, openssl"),
    (1080, "TCP", "SOCKS", "Proxy", "proxychains, curl"),
    (1099, "TCP", "RMI", "Java RMI", "rmg, ysoserial"),
    (1433, "TCP", "MSSQL", "MS SQL Server", "sqsh, impacket-mssqlclient"),
    (1521, "TCP", "Oracle", "Oracle DB", "odat, sqlplus"),
    (2049, "TCP/UDP", "NFS", "Network FS", "showmount, nfspy"),
    (2121, "TCP", "FTP-Alt", "Alt FTP", "hydra, ftp"),
    (2375, "TCP", "Docker", "Docker API", "docker, curl"),
    (3268, "TCP", "GC", "Global Catalog", "ldapsearch"),
    (3269, "TCP", "GC-SSL", "GC over SSL", "ldapsearch"),
    (3306, "TCP", "MySQL", "MySQL DB", "mysql, hydra"),
    (3389, "TCP", "RDP", "Remote Desktop", "xfreerdp, hydra"),
    (4369, "TCP", "EPMD", "Erlang Port", "nmap"),
    (5432, "TCP", "PostgreSQL", "Postgres DB", "psql, hydra"),
    (5900, "TCP", "VNC", "Remote Desktop", "vncviewer, hydra"),
    (5985, "TCP", "WinRM", "WinRM HTTP", "evil-winrm, crackmapexec"),
    (5986, "TCP", "WinRM-S", "WinRM HTTPS", "evil-winrm"),
    (6379, "TCP", "Redis", "Redis DB", "redis-cli, hydra"),
    (8000, "TCP", "HTTP-Alt", "Alt Web", "gobuster, curl"),
    (8080, "TCP", "HTTP-Proxy", "Proxy/Web", "gobuster, burp"),
    (8443, "TCP", "HTTPS-Alt", "Alt HTTPS", "gobuster, sslscan"),
    (8888, "TCP", "HTTP-Alt", "Alt Web/Jupyter", "gobuster, curl"),
    (9000, "TCP", "PHP-FPM", "FastCGI", "curl, nmap"),
    (9200, "TCP", "Elastic", "Elasticsearch", "curl, searchsploit"),
    (11211, "TCP", "Memcached", "Cache Server", "nc, memcstat"),
    (27017, "TCP", "MongoDB", "Mongo DB", "mongosh, nmap"),
]

# Color codes
class C:
    """ANSI color codes"""
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'


def colorize_port(port: int) -> str:
    """Color port based on category"""
    if port in (21, 22, 23, 25, 110, 143, 993, 995):  # Auth/Mail
        return f"{C.GREEN}{port:>5}{C.END}"
    elif port in (53, 88, 135, 137, 138, 139, 389, 445, 464, 636, 3268, 3269):  # AD/SMB
        return f"{C.RED}{port:>5}{C.END}"
    elif port in (80, 443, 8000, 8080, 8443, 8888, 9000):  # Web
        return f"{C.CYAN}{port:>5}{C.END}"
    elif port in (1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017):  # DB
        return f"{C.YELLOW}{port:>5}{C.END}"
    elif port in (3389, 5900, 5985, 5986):  # Remote Access
        return f"{C.MAGENTA}{port:>5}{C.END}"
    else:
        return f"{C.WHITE}{port:>5}{C.END}"


def print_header():
    """Print table header"""
    print(f"\n{C.BOLD}{C.CYAN}{'='*78}{C.END}")
    print(f"{C.BOLD}{C.WHITE}  CRACK Port Reference - Common Attack Vectors{C.END}")
    print(f"{C.BOLD}{C.CYAN}{'='*78}{C.END}\n")

    header = f"{C.BOLD}{'PORT':>5}  {'PROTO':<7} {'SERVICE':<12} {'DESCRIPTION':<16} {'TOOLS'}{C.END}"
    print(header)
    print(f"{C.DIM}{'-'*78}{C.END}")


def print_legend():
    """Print color legend"""
    print(f"\n{C.DIM}{'-'*78}{C.END}")
    print(f"{C.BOLD}Legend:{C.END} ", end="")
    print(f"{C.RED}AD/SMB{C.END}  ", end="")
    print(f"{C.CYAN}Web{C.END}  ", end="")
    print(f"{C.YELLOW}Database{C.END}  ", end="")
    print(f"{C.MAGENTA}Remote{C.END}  ", end="")
    print(f"{C.GREEN}Auth/Mail{C.END}  ", end="")
    print(f"{C.WHITE}Other{C.END}")
    print()


def filter_ports(ports: list, query: Optional[str] = None) -> list:
    """Filter ports by query (port number, service name, or protocol)"""
    if not query:
        return ports

    query = query.lower()
    filtered = []

    for port, proto, service, desc, tools in ports:
        if (query in str(port) or
            query in proto.lower() or
            query in service.lower() or
            query in desc.lower() or
            query in tools.lower()):
            filtered.append((port, proto, service, desc, tools))

    return filtered


def display_ports(limit: int = 50, query: Optional[str] = None, show_all: bool = False):
    """Display port reference chart"""
    ports = PORT_DATA if show_all else PORT_DATA[:limit]

    if query:
        ports = filter_ports(PORT_DATA, query)
        if not ports:
            print(f"\n{C.YELLOW}No ports found matching '{query}'{C.END}\n")
            return

    print_header()

    for port, proto, service, desc, tools in ports:
        port_col = colorize_port(port)
        print(f"{port_col}  {C.GRAY}{proto:<7}{C.END} {C.WHITE}{service:<12}{C.END} {C.DIM}{desc:<16}{C.END} {C.GREEN}{tools}{C.END}")

    print_legend()

    if query:
        print(f"{C.DIM}Showing {len(ports)} result(s) for '{query}'{C.END}\n")
    elif not show_all and len(PORT_DATA) > limit:
        print(f"{C.DIM}Showing top {limit} ports. Use --all for full list ({len(PORT_DATA)} total){C.END}\n")


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='CRACK Ports - Quick port reference for pentesting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  crack ports              Show top 50 common ports
  crack ports --all        Show all ports
  crack ports smb          Filter by 'smb'
  crack ports 445          Filter by port number
  crack ports kerberos     Filter by service name
"""
    )

    parser.add_argument('query', nargs='?', help='Filter by port, service, or description')
    parser.add_argument('-a', '--all', action='store_true', help='Show all ports')
    parser.add_argument('-n', '--limit', type=int, default=50, help='Number of ports to show (default: 50)')

    args = parser.parse_args()

    display_ports(limit=args.limit, query=args.query, show_all=args.all)


if __name__ == '__main__':
    main()
