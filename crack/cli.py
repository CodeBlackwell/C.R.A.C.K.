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
    from crack.enumeration import html_enum
    # Pass arguments to the original main function
    sys.argv = ['html_enum'] + args
    html_enum.main()

def param_discover_command(args):
    """Execute the parameter discovery tool"""
    from crack.enumeration import param_discover
    # Pass arguments to the original main function
    sys.argv = ['param_discover'] + args
    param_discover.main()

def sqli_scan_command(args):
    """Execute the SQLi scanner tool"""
    from crack.enumeration import sqli_scanner
    # Pass arguments to the original main function
    sys.argv = ['sqli_scanner'] + args
    sqli_scanner.main()

def sqli_fu_command(args):
    """Execute the SQLi follow-up enumeration reference tool"""
    from crack.enumeration import sqli_fu
    # Pass arguments to the original main function
    sys.argv = ['sqli_fu'] + args
    sqli_fu.main()

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='C.R.A.C.K. - Comprehensive Recon & Attack Creation Kit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tool Categories:
  enumeration     Web enumeration tools

Available Tools:
  html-enum       HTML Enumeration Tool - Find forms, comments, endpoints
  param-discover  Parameter Discovery Tool - Find hidden GET/POST parameters
  sqli-scan       SQLi Scanner - Detect SQL injection vulnerabilities
  sqli-fu         SQLi Follow-up - Post-exploitation enumeration reference

Examples:
  crack html-enum http://target.com
  crack param-discover http://target.com/page.php
  crack sqli-scan http://target.com/page.php?id=1
  crack sqli-fu -d mysql -c privileges

Quick Access:
  You can also use direct shortcuts:
    crack-html http://target.com
    crack-param http://target.com/page.php
    crack-sqli http://target.com/page.php?id=1
    crack-sqli-fu -d postgresql
        """
    )

    parser.add_argument('-v', '--version', action='version',
                       version='C.R.A.C.K. v1.0.0')
    parser.add_argument('--no-banner', action='store_true',
                       help='Suppress the banner')

    subparsers = parser.add_subparsers(dest='tool', help='Tool to run')

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

def html_enum_entry():
    """Direct entry point for crack-html command"""
    print_banner()
    from crack.enumeration import html_enum
    html_enum.main()

def param_discover_entry():
    """Direct entry point for crack-param command"""
    print_banner()
    from crack.enumeration import param_discover
    param_discover.main()

def sqli_scan_entry():
    """Direct entry point for crack-sqli command"""
    print_banner()
    from crack.enumeration import sqli_scanner
    sqli_scanner.main()

def sqli_fu_entry():
    """Direct entry point for crack-sqli-fu command"""
    print_banner()
    from crack.enumeration import sqli_fu
    sqli_fu.main()

if __name__ == '__main__':
    main()