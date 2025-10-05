#!/usr/bin/env python3
"""
C.R.A.C.K. - Comprehensive Recon & Attack Creation Kit
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
  ██████╗    ██████╗     █████╗     ██████╗    ██╗  ██╗
 ██╔════╝    ██╔══██╗   ██╔══██╗   ██╔════╝    ██║ ██╔╝
 ██║         ██████╔╝   ███████║   ██║         █████╔╝
 ██║         ██╔══██╗   ██╔══██║   ██║         ██╔═██╗
 ╚██████╗    ██║  ██║   ██║  ██║   ╚██████╗    ██║  ██╗
  ╚═════╝    ╚═╝  ╚═╝   ╚═╝  ╚═╝    ╚═════╝    ╚═╝  ╚═╝
{Colors.END}
{Colors.CYAN}  Comprehensive Recon & Attack Creation Kit{Colors.END}
{Colors.YELLOW}  OSCP Pentesting Toolkit v1.0.0{Colors.END}
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
    from crack.sqli import scanner
    # Pass arguments to the original main function
    sys.argv = ['sqli_scanner'] + args
    scanner.main()

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

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='C.R.A.C.K. - Comprehensive Recon & Attack Creation Kit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tool Categories:
  enumeration     Web enumeration tools

Available Tools:
  enum-scan       Enumeration Scanner - Fast two-stage port scan + CVE lookup
  scan-analyze    Scan Analyzer - Parse nmap output to identify attack vectors
  html-enum       HTML Enumeration Tool - Find forms, comments, endpoints
  param-discover  Parameter Discovery Tool - Find hidden GET/POST parameters
  param-extract   Parameter Extraction Tool - Extract form values as variables
  sqli-scan       SQLi Scanner - Detect SQL injection vulnerabilities
  sqli-fu         SQLi Follow-up - Post-exploitation enumeration reference

Examples:
  crack enum-scan 192.168.45.100
  crack enum-scan 192.168.45.100 --full
  crack scan-analyze targeted_scan.nmap
  crack scan-analyze scan.xml --os windows
  crack html-enum http://target.com
  crack param-discover http://target.com/page.php
  crack param-extract http://target.com/login.aspx
  crack sqli-scan http://target.com/page.php?id=1
  crack sqli-fu mysql
  crack sqli-fu mysql -c privileges
  crack sqli-fu postgresql -t http://target.com/vuln.php -p id
        """
    )

    parser.add_argument('-v', '--version', action='version',
                       version='C.R.A.C.K. v1.0.0')
    parser.add_argument('--no-banner', action='store_true',
                       help='Suppress the banner')

    subparsers = parser.add_subparsers(dest='tool', help='Tool to run')

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