#!/usr/bin/env python3
"""
SQL Injection Follow-Up Commands Reference
Displays all follow-up enumeration commands organized by database type
"""

import sys
import argparse

try:
    from ..utils.colors import Colors
except ImportError:
    # Fallback for standalone execution
    class Colors:
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        CYAN = '\033[96m'
        END = '\033[0m'

from .sqli.databases import DatabaseEnumeration


def print_banner():
    """Display the tool banner"""
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("""
 ███████╗ ██████╗ ██╗     ██╗      ███████╗ ██████╗ ██╗     ██╗      ██████╗ ██╗    ██╗      ██╗   ██╗██████╗
 ██╔════╝██╔═══██╗██║     ██║      ██╔════╝██╔═══██╗██║     ██║     ██╔═══██╗██║    ██║      ██║   ██║██╔══██╗
 ███████╗██║   ██║██║     ██║█████╗█████╗  ██║   ██║██║     ██║     ██║   ██║██║ █╗ ██║█████╗██║   ██║██████╔╝
 ╚════██║██║▄▄ ██║██║     ██║╚════╝██╔══╝  ██║   ██║██║     ██║     ██║   ██║██║███╗██║╚════╝██║   ██║██╔═══╝
 ███████║╚██████╔╝███████╗██║      ██║     ╚██████╔╝███████╗███████╗╚██████╔╝╚███╔███╔╝      ╚██████╔╝██║
 ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝      ╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═════╝  ╚══╝╚══╝        ╚═════╝ ╚═╝""")
    print(f"{Colors.END}")
    print(f"{Colors.YELLOW}SQL Injection Follow-Up Commands Reference Guide{Colors.END}")
    print(f"{Colors.BLUE}Educational enumeration techniques for OSCP preparation{Colors.END}")
    print("═" * 80)


def display_commands_for_db(db_type, param='PARAM', target='http://TARGET/page.php', verbose=False):
    """Display follow-up commands for a specific database type"""

    # Get the follow-up commands
    commands = DatabaseEnumeration.get_followup_commands(db_type, param, 'GET', target)

    if not commands:
        print(f"{Colors.RED}No commands available for database type: {db_type}{Colors.END}")
        return

    # Database header
    print(f"\n{Colors.BOLD}{Colors.HEADER}╔{'═' * 78}╗{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}║{db_type.upper():^78}║{Colors.END}")
    print(f"{Colors.BOLD}{Colors.HEADER}╚{'═' * 78}╝{Colors.END}")

    for category, cmd_list in commands.items():
        print(f"\n{Colors.CYAN}▶ {category}{Colors.END}")
        print(f"  {'─' * 76