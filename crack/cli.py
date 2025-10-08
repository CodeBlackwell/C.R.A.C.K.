#!/usr/bin/env python3
"""
C.R.A.C.K. - Comprehensive Recon & Attack Creation Kit
(C)omprehensive (R)econ & (A)ttack (C)reation (K)it

Main CLI interface for all penetration testing tools
"""

import argparse
import sys
import subprocess
import os
from pathlib import Path

from crack.utils.colors import Colors

def print_banner():
    """Display the C.R.A.C.K. banner"""
    banner = f"""
{Colors.BOLD}{Colors.RED}
 ░▒▓██████▓▒░       ░▒▓███████▓▒░        ░▒▓██████▓▒░        ░▒▓██████▓▒░       ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓████████▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░     
░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░     
░▒▓█▓▒░             ░▒▓███████▓▒░       ░▒▓████████▓▒░      ░▒▓█▓▒░             ░▒▓███████▓▒░░▒▓█▓▒░  ░▒▓█▓▒░     
░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░     
░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░     
 ░▒▓██████▓▒░░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██▓▒░░▒▓██████▓▒░░▒▓██▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░  ░▒▓█▓▒░     
                                                                                                                  

{Colors.END}
{Colors.CYAN}  (C)omprehensive (R)econ & (A)ttack (C)reation (K)it{Colors.END}
{Colors.YELLOW}  Professional OSCP Pentesting Toolkit{Colors.END}
    """
    print(banner)

def html_enum_command(args):
    """Execute the HTML enumeration tool"""
    from crack.web import html_enum
    # Pass arguments to the original main function
    sys.argv = ['html_enum'] + args
    html_enum.main()

def param_discover_command(args):
    """Execute the parameter discovery tool"""
    from crack.web import param_discover
    # Pass arguments to the original main function
    sys.argv = ['param_discover'] + args
    param_discover.main()

def sqli_scan_command(args):
    """Execute the SQLi scanner tool"""
    from crack.sqli import sqli_scanner
    # Pass arguments to the original main function
    sys.argv = ['sqli_scanner'] + args
    sqli_scanner.main()

def sqli_fu_command(args):
    """Execute the SQLi follow-up enumeration reference tool"""
    from crack.sqli import reference
    # Pass arguments to the original main function
    sys.argv = ['sqli_fu'] + args
    reference.main()

def param_extract_command(args):
    """Execute the parameter extraction tool"""
    from crack.web import param_extract
    # Pass arguments to the original main function
    sys.argv = ['param_extract'] + args
    param_extract.main()

def enum_scan_command(args):
    """Execute the enumeration scanner tool"""
    from crack.network import enum_scan
    # Pass arguments to the original main function
    sys.argv = ['enum_scan'] + args
    enum_scan.main()

def scan_analyze_command(args):
    """Execute the scan analyzer tool"""
    from crack.network import scan_analyzer
    # Pass arguments to the original main function
    sys.argv = ['scan_analyzer'] + args
    scan_analyzer.main()

def reference_command(args):
    """Execute the reference system"""
    from crack.reference import cli as ref_cli
    # Pass arguments to the reference CLI
    sys.argv = ['crack-reference'] + args
    ref_cli.main()

def track_command(args):
    """Execute CRACK Track - enumeration tracking and task management"""
    from crack.track import cli as track_cli
    # Pass arguments to the track CLI
    sys.argv = ['crack-track'] + args
    track_cli.main()

def checklist_command(args):
    """Execute the enumeration checklist system (backward compatibility alias)"""
    # Redirect to track command for backward compatibility
    track_command(args)

def port_scan_command(args):
    """Execute the two-stage port scanner"""
    from crack.network import port_scanner
    # Pass arguments to the original main function
    sys.argv = ['port_scanner'] + args
    port_scanner.main()

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='C.R.A.C.K. - (C)omprehensive (R)econ & (A)ttack (C)reation (K)it',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.CYAN}══════════════════════════ AVAILABLE TOOLS ══════════════════════════{Colors.END}

{Colors.YELLOW}▶ Network & Enumeration{Colors.END}
  ├─ port-scan       Two-stage port scanner with service detection
  ├─ enum-scan       Fast port scan + automatic CVE lookup
  ├─ scan-analyze    Parse nmap output to identify attack vectors
  └─ track           CRACK Track - Enumeration tracking & task management

{Colors.YELLOW}▶ Web Application{Colors.END}
  ├─ html-enum       Find forms, comments, endpoints in HTML
  ├─ param-discover  Discover hidden GET/POST parameters
  ├─ param-extract   Extract form values as variables
  ├─ sqli-scan       Detect SQL injection vulnerabilities
  └─ sqli-fu         SQLi post-exploitation reference

{Colors.YELLOW}▶ Reference System{Colors.END}
  └─ reference       Command lookup with 70+ OSCP commands

{Colors.CYAN}═══════════════════════ REFERENCE CATEGORIES ════════════════════════{Colors.END}

{Colors.GREEN}📚 Available Reference Commands (70+ total):{Colors.END}

{Colors.YELLOW}▶ Reconnaissance (7 commands){Colors.END}
  ├─ Network Discovery: nmap-ping-sweep, nmap-quick-scan
  ├─ Service Enum: nmap-service-scan, nmap-vuln-scan
  └─ Protocol Specific: dns-enum, smb-enum, snmp-enum

{Colors.YELLOW}▶ Web Testing (9 commands){Colors.END}
  ├─ Directory/File: gobuster-dir, nikto-scan, whatweb-enum
  ├─ SQL Injection: sqlmap-basic, sqli-manual-test
  └─ Other Vulns: xss-test, lfi-test, wfuzz-params

{Colors.YELLOW}▶ Exploitation (10 commands){Colors.END}
  ├─ Reverse Shells: bash-reverse-shell, python-reverse-shell, nc-reverse-shell
  ├─ Payloads: msfvenom-linux-elf, msfvenom-windows-exe, php-reverse-shell
  └─ Tools: searchsploit, hydra-ssh, web-shell-php

{Colors.YELLOW}▶ Post-Exploitation (29 commands){Colors.END}
  ├─ {Colors.CYAN}Linux PrivEsc (15){Colors.END}
  │   ├─ Quick Wins: linux-suid-find, linux-sudo-check, linux-capabilities
  │   ├─ Config Issues: linux-writable-passwd, linux-cron-jobs
  │   └─ Advanced: linux-kernel-version, linux-linpeas, linux-pspy
  │
  └─ {Colors.CYAN}Windows PrivEsc (14){Colors.END}
      ├─ Quick Wins: windows-alwaysinstallelevated, windows-unquoted-service
      ├─ Credentials: windows-stored-credentials, windows-autologon
      └─ Advanced: windows-potato-attacks, windows-pass-the-hash

{Colors.YELLOW}▶ File Transfer (15 commands){Colors.END}
  ├─ HTTP: python-http-server, wget-download, curl-upload, certutil-download
  ├─ SMB/FTP: smb-server, ftp-transfer, scp-transfer
  └─ Advanced: base64-transfer, php-download, dns-exfiltration

{Colors.CYAN}════════════════════════════ EXAMPLES ═══════════════════════════════{Colors.END}

{Colors.GREEN}Network Scanning:{Colors.END}
  crack port-scan 192.168.45.100 --full
  crack enum-scan 192.168.45.100 --top-ports 1000
  crack scan-analyze scan.nmap --verbose

{Colors.GREEN}Web Testing:{Colors.END}
  crack html-enum http://target.com
  crack param-discover http://target.com/page.php
  crack sqli-scan http://target.com/page.php?id=1

{Colors.GREEN}Reference System:{Colors.END}
  crack reference --fill bash-reverse-shell    # Auto-fills LHOST/LPORT
  crack reference --category post-exploit      # List privesc commands
  crack reference --tag QUICK_WIN              # Find quick wins
  crack reference --config auto                # Auto-detect settings
  crack reference --set TARGET 192.168.45.100  # Set config variable

{Colors.CYAN}══════════════════════════ CONFIGURATION ════════════════════════════{Colors.END}

{Colors.GREEN}Config Variables:{Colors.END} (~/.crack/config.json)
  LHOST, LPORT, TARGET, WORDLIST, INTERFACE, THREADS

{Colors.GREEN}Quick Setup:{Colors.END}
  crack reference --config auto                # Auto-detect network
  crack reference --set TARGET 192.168.45.100  # Set target IP

{Colors.CYAN}══════════════════════════════════════════════════════════════════════{Colors.END}
        """
    )

    parser.add_argument('-v', '--version', action='version',
                       version='C.R.A.C.K. v1.0.0')
    parser.add_argument('--no-banner', action='store_true',
                       help='Suppress the banner')

    subparsers = parser.add_subparsers(dest='tool', help='Tool to run')

    # Port Scanner subcommand
    port_scan_parser = subparsers.add_parser('port-scan',
                                             help='Two-stage Port Scanner',
                                             add_help=False)
    port_scan_parser.set_defaults(func=port_scan_command)

    # Enumeration Scanner subcommand
    enum_scan_parser = subparsers.add_parser('enum-scan',
                                             help='Enumeration Scanner',
                                             add_help=False)
    enum_scan_parser.set_defaults(func=enum_scan_command)

    # Scan Analyzer subcommand
    scan_analyze_parser = subparsers.add_parser('scan-analyze',
                                                help='Scan Analyzer - Parse nmap output',
                                                add_help=False)
    scan_analyze_parser.set_defaults(func=scan_analyze_command)

    # HTML Enumeration subcommand
    html_parser = subparsers.add_parser('html-enum',
                                        help='HTML Enumeration Tool',
                                        add_help=False)
    html_parser.set_defaults(func=html_enum_command)

    # Parameter Discovery subcommand
    param_parser = subparsers.add_parser('param-discover',
                                         help='Parameter Discovery Tool',
                                         add_help=False)
    param_parser.set_defaults(func=param_discover_command)

    # SQLi Scanner subcommand
    sqli_parser = subparsers.add_parser('sqli-scan',
                                        help='SQL Injection Scanner',
                                        add_help=False)
    sqli_parser.set_defaults(func=sqli_scan_command)

    # SQLi Fu subcommand
    sqli_fu_parser = subparsers.add_parser('sqli-fu',
                                           help='SQLi Follow-up Enumeration Reference',
                                           add_help=False)
    sqli_fu_parser.set_defaults(func=sqli_fu_command)

    # Parameter Extraction subcommand
    param_extract_parser = subparsers.add_parser('param-extract',
                                                 help='Parameter Extraction Tool',
                                                 add_help=False)
    param_extract_parser.set_defaults(func=param_extract_command)

    # Reference System subcommand
    reference_parser = subparsers.add_parser('reference',
                                            help='Reference System - Command lookup and management',
                                            add_help=False)
    reference_parser.set_defaults(func=reference_command)

    # CRACK Track subcommand (primary)
    track_parser = subparsers.add_parser('track',
                                        help='CRACK Track - Enumeration tracking & task management',
                                        add_help=False)
    track_parser.set_defaults(func=track_command)

    # Enumeration Checklist subcommand (backward compatibility alias)
    checklist_parser = subparsers.add_parser('checklist',
                                             help='Alias for "track" (backward compatibility)',
                                             add_help=False)
    checklist_parser.set_defaults(func=checklist_command)

    # Parse known args to allow passing through tool-specific args
    args, remaining = parser.parse_known_args()

    # Show banner unless suppressed
    if not args.no_banner and args.tool:
        print_banner()

    # Execute the selected tool
    if hasattr(args, 'func'):
        args.func(remaining)
    else:
        if not args.no_banner:
            print_banner()
        parser.print_help()

if __name__ == '__main__':
    main()