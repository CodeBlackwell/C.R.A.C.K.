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
import random
from pathlib import Path

try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False

from crack.core.themes import ReferenceTheme, Colors

def print_banner():
    """Display the C.R.A.C.K. banner with themed colors and random font"""
    theme = ReferenceTheme()

    if PYFIGLET_AVAILABLE:
        # Curated list of fonts that work well for "CRACK"
        fonts = [
            'slant', 'banner3', 'big', 'doom', 'speed',
            'starwars', 'colossal', 'standard', 'epic', 'isometric1',
            'larry3d', 'cyberlarge', 'graffiti', 'block', 'shadow'
        ]

        # Randomly select a font
        selected_font = random.choice(fonts)

        try:
            # Generate ASCII art with pyfiglet
            ascii_art = pyfiglet.figlet_format("CRACK", font=selected_font)

            # Display with themed colors
            print(theme.banner_title(ascii_art))
            print(theme.banner_subtitle("  (C)omprehensive (R)econ & (A)ttack (C)reation (K)it"))
            print(theme.banner_tagline("  Professional OSCP Pentesting Toolkit\n"))
        except pyfiglet.FontNotFound:
            # Fallback to standard if selected font not found
            ascii_art = pyfiglet.figlet_format("CRACK", font="standard")
            print(theme.banner_title(ascii_art))
            print(theme.banner_subtitle("  (C)omprehensive (R)econ & (A)ttack (C)reation (K)it"))
            print(theme.banner_tagline("  Professional OSCP Pentesting Toolkit\n"))
    else:
        # Simple text fallback if pyfiglet not available
        print(f"\n{theme.banner_title('C.R.A.C.K.')}")
        print(theme.banner_subtitle("  (C)omprehensive (R)econ & (A)ttack (C)reation (K)it"))
        print(theme.banner_tagline("  Professional OSCP Pentesting Toolkit\n"))

def html_enum_command(args):
    """Execute the HTML enumeration tool"""
    from crack.tools.recon.web import html_enum
    # Pass arguments to the original main function
    sys.argv = ['html_enum'] + args
    html_enum.main()

def param_discover_command(args):
    """Execute the parameter discovery tool"""
    from crack.tools.recon.web import param_discover
    # Pass arguments to the original main function
    sys.argv = ['param_discover'] + args
    param_discover.main()

def sqli_scan_command(args):
    """Execute the SQLi scanner tool"""
    from crack.tools.recon.sqli import sqli_scanner
    # Pass arguments to the original main function
    sys.argv = ['sqli_scanner'] + args
    sqli_scanner.main()

def sqli_fu_command(args):
    """Execute the SQLi follow-up enumeration reference tool"""
    from crack.tools.recon.sqli import reference
    # Pass arguments to the original main function
    sys.argv = ['sqli_fu'] + args
    reference.main()

def param_extract_command(args):
    """Execute the parameter extraction tool"""
    from crack.tools.recon.web import param_extract
    # Pass arguments to the original main function
    sys.argv = ['param_extract'] + args
    param_extract.main()

def enum_scan_command(args):
    """Execute the enumeration scanner tool"""
    from crack.tools.recon.network import enum_scan
    # Pass arguments to the original main function
    sys.argv = ['enum_scan'] + args
    enum_scan.main()

def scan_analyze_command(args):
    """Execute the scan analyzer tool"""
    from crack.tools.recon.network import scan_analyzer
    # Pass arguments to the original main function
    sys.argv = ['scan_analyzer'] + args
    scan_analyzer.main()

def dns_enum_command(args):
    """Execute the recursive DNS enumeration tool"""
    from crack.tools.recon.network import dns_enum
    # Pass arguments to the original main function
    sys.argv = ['dns_enum'] + args
    dns_enum.main()

def reference_command(args):
    """Execute the reference system"""
    from crack.reference.cli import main as ref_main
    # Pass arguments to the reference CLI
    # Add --no-banner by default unless --banner is explicitly requested
    if '--banner' not in args:
        args = ['--no-banner'] + args
    sys.argv = ['crack-reference'] + args
    ref_main()

def cheatsheets_command(args):
    """Execute the cheatsheets system"""
    from crack.reference.core import HybridCommandRegistry, ConfigManager, ReferenceTheme
    from crack.reference.core.cheatsheet_registry import CheatsheetRegistry
    from crack.reference.cli.cheatsheet import CheatsheetCLI
    from crack.core.themes import Colors

    # Initialize registries
    theme = ReferenceTheme()
    config = ConfigManager()
    crack_root = Path(__file__).parent
    command_registry = HybridCommandRegistry(base_path=crack_root, config_manager=config, theme=theme)
    cheatsheet_registry = CheatsheetRegistry(base_path=crack_root, command_registry=command_registry, theme=theme)
    cli = CheatsheetCLI(
        cheatsheet_registry=cheatsheet_registry,
        command_registry=command_registry,
        theme=theme
    )

    # Parse --list-subjects flag
    if args and args[0] == '--list-subjects':
        _list_subjects(cheatsheet_registry)
        return

    # Parse --subject/-s flag
    subject_filter = None
    filtered_args = []
    i = 0
    while i < len(args):
        if args[i] in ['--subject', '-s']:
            if i + 1 < len(args):
                subject_filter = args[i + 1]
                i += 2  # Skip flag and value
            else:
                print(f"{Colors.RED}Error: --subject requires a category name{Colors.END}")
                print(f"\nUsage: crack cheatsheets --subject <category>")
                print(f"   or: crack cheatsheets -s <category>")
                print(f"\nTo see available subjects: crack cheatsheets --list-subjects")
                return
        else:
            filtered_args.append(args[i])
            i += 1

    # Handle subject filtering
    if subject_filter:
        _filter_by_subject(cli, cheatsheet_registry, subject_filter, filtered_args)
        return

    # Parse arguments (original logic)
    if not filtered_args:
        # No args - list all cheatsheets
        cli.list_cheatsheets()
        return

    # Join args for pattern matching (e.g., "metasploit 2" → "metasploit 2")
    cheatsheet_query = ' '.join(filtered_args) if filtered_args else ''

    # Check for flags
    if '--fill-all' in filtered_args:
        # Fill all commands sequentially
        cheatsheet_id = filtered_args[0]
        cli.fill_all_commands(cheatsheet_id)
    elif len(filtered_args) >= 2 and filtered_args[1].isdigit():
        # Could be either:
        # 1. "metasploit 2" = Select cheatsheet #2 from "metasploit" search
        # 2. "log-poisoning 3" = Fill command #3 from exact cheatsheet ID
        # Determine by checking if first arg is exact cheatsheet ID
        exact_sheet = cli.cheatsheet_registry.get_cheatsheet(filtered_args[0])
        if exact_sheet:
            # Exact ID + number = fill command
            command_number = int(filtered_args[1])
            cli.fill_command(filtered_args[0], command_number)
        else:
            # Search query + number = select cheatsheet
            cli.show_cheatsheet(cheatsheet_query)
    else:
        # Show cheatsheet
        cli.show_cheatsheet(cheatsheet_query)


def _list_subjects(cheatsheet_registry):
    """List all available cheatsheet subjects/categories"""
    from crack.core.themes import Colors
    from pathlib import Path

    # Get cheatsheet base directory
    cheatsheet_path = Path(cheatsheet_registry.base_path) / 'data' / 'cheatsheets'

    # Find all subdirectories (categories)
    categories = {}
    for subdir in sorted(cheatsheet_path.iterdir()):
        if subdir.is_dir() and not subdir.name.startswith('.'):
            # Count JSON files in each category
            count = len(list(subdir.glob('*.json')))
            if count > 0:
                categories[subdir.name] = count

    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BRIGHT_WHITE}AVAILABLE CHEATSHEET CATEGORIES{Colors.END}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.END}\n")

    # Display usage
    print(f"{Colors.BRIGHT_BLACK}Use with: crack cheatsheets --subject <category>{Colors.END}")
    print(f"{Colors.BRIGHT_BLACK}      or: crack cheatsheets -s <category>{Colors.END}\n")

    # Sort by name alphabetically
    for category, count in sorted(categories.items()):
        # Format category name for display (replace dashes with spaces, title case)
        display_name = category.replace('-', ' ').replace('_', ' ').title()
        print(f"  {Colors.CYAN}•{Colors.END} {Colors.BOLD}{category}{Colors.END} "
              f"{Colors.BRIGHT_BLACK}({count} cheatsheet{'s' if count > 1 else ''}){Colors.END} "
              f"{Colors.BRIGHT_BLACK}- {display_name}{Colors.END}")

    print(f"\n{Colors.BRIGHT_BLACK}Total: {len(categories)} categories, "
          f"{sum(categories.values())} cheatsheets{Colors.END}\n")


def _filter_by_subject(cli, cheatsheet_registry, subject, remaining_args):
    """Filter cheatsheets by subject (directory) and optionally select by number"""
    from pathlib import Path

    theme = cheatsheet_registry.theme

    # Get cheatsheets from specific subdirectory
    base_path = Path(cheatsheet_registry.base_path) / 'data' / 'cheatsheets'
    cheatsheet_path = base_path / subject

    # Check if category directory exists
    if not cheatsheet_path.exists() or not cheatsheet_path.is_dir():
        print(f"\n{theme.error('No category found:')} {theme.primary(subject)}\n")
        print(f"{theme.hint('To see available categories:')}")
        print(f"  crack cheatsheets --list-subjects\n")
        return

    # Load cheatsheets from this category directory
    matching_sheets = []
    for json_file in sorted(cheatsheet_path.glob('*.json')):
        try:
            with open(json_file, 'r') as f:
                import json
                data = json.load(f)
                from crack.reference.core.cheatsheet_registry import Cheatsheet
                sheet = Cheatsheet.from_dict(data)
                matching_sheets.append(sheet)
        except Exception as e:
            # Skip invalid files
            pass

    if not matching_sheets:
        print(f"\n{theme.error('No cheatsheets found in category:')} {theme.primary(subject)}\n")
        return

    # Check if numeric selection provided
    selection_num = None
    if remaining_args and remaining_args[0].isdigit():
        selection_num = int(remaining_args[0]) - 1  # Convert to 0-indexed

    # If selection provided, show that specific cheatsheet
    if selection_num is not None:
        if 0 <= selection_num < len(matching_sheets):
            cli.show_cheatsheet(matching_sheets[selection_num].id)
        else:
            print(f"\n{theme.error(f'Invalid selection: {selection_num + 1}')}")
            print(f"Only {len(matching_sheets)} cheatsheet(s) available for subject '{subject}'\n")
            _display_subject_results(matching_sheets, subject, theme)
        return

    # No selection - display numbered list
    _display_subject_results(matching_sheets, subject, theme)


def _display_subject_results(sheets, subject, theme):
    """Display numbered list of cheatsheets for a subject"""
    # Format category name for display
    display_name = subject.replace('-', ' ').replace('_', ' ').title()

    print(f"{theme.hint(f'Found {len(sheets)} match(es) for:')} {theme.primary(display_name)}\n")

    print(f"{theme.command_name('ID Matches:')}")
    for i, sheet in enumerate(sheets, 1):
        # Display numbered result (matching search format from cheatsheet.py:356-360)
        print(f"  {theme.bold_white(f'{i}.')} {theme.primary(sheet.id)}")
        print(f"     {theme.hint(sheet.name)}")

        # Truncate description
        if sheet.description:
            desc = sheet.description[:80] + "..." if len(sheet.description) > 80 else sheet.description
            print(f"     {theme.muted(desc)}")

    print()
    print(f"{theme.hint('To view full cheatsheet:')}")
    print(f"  {theme.secondary('crack cheatsheets <id>')}")
    print(f"  {theme.secondary(f'crack cheatsheets {subject} <number>')}")
    print(f"\n{theme.hint('Example:')} {theme.primary(f'crack cheatsheets {subject} 1')}")
    print()

def chain_builder_command(args):
    """Execute the chain builder wizard"""
    from crack.reference.cli.chain_builder import ChainBuilderCLI

    # Parse action
    if not args or args[0] not in ['create', 'clone']:
        print(f"{Colors.CYAN}CRACK Chain Builder{Colors.END}\n")
        print(f"{Colors.YELLOW}Usage:{Colors.END}")
        print("  crack chain-builder create           - Create new chain from scratch")
        print("  crack chain-builder clone <chain-id> - Clone existing chain")
        print(f"\n{Colors.YELLOW}Examples:{Colors.END}")
        print("  crack chain-builder create")
        print("  crack chain-builder clone linux-privesc-suid-basic")
        return

    action = args[0]
    cli = ChainBuilderCLI()

    if action == 'create':
        sys.exit(cli.create())
    elif action == 'clone':
        if len(args) < 2:
            print(f"{Colors.RED}Error: clone requires a chain ID{Colors.END}")
            print("Usage: crack chain-builder clone <chain-id>")
            sys.exit(1)
        chain_id = args[1]
        sys.exit(cli.clone(chain_id))

def port_scan_command(args):
    """Execute the two-stage port scanner"""
    from crack.tools.recon.network import port_scanner
    # Pass arguments to the original main function
    sys.argv = ['port_scanner'] + args
    port_scanner.main()

def session_command(args):
    """Execute session management commands via unified CLI"""
    from crack.tools.post.sessions.unified_cli import UnifiedSessionCLI

    cli = UnifiedSessionCLI()
    cli.run(args)

def db_command(args):
    """Execute database management commands"""
    from crack.db.cli import main as db_main
    # Pass arguments to the db CLI
    sys.argv = ['crack-db'] + args
    sys.exit(db_main())

def ports_command(args):
    """Execute the port reference tool"""
    from crack.core.utils import ports
    # Pass arguments to the original main function
    sys.argv = ['ports'] + args
    ports.main()

def blood_trail_command(args):
    """Execute BloodHound Trail - Edge enhancement and Neo4j query analysis"""
    from crack.tools.post.bloodtrail.cli import main as bt_main
    sys.argv = ['crack-bloodtrail'] + args
    bt_main()

def prism_command(args):
    """Execute PRISM - Parse and distill security tool output"""
    from crack.tools.post.prism.cli import main as prism_main
    sys.argv = ['crack-prism'] + args
    prism_main()

def config_command(args):
    """Execute configuration management"""
    from crack.core.config import ConfigManager
    from crack.core.config.variables import get_all_categories, get_by_category

    config = ConfigManager()

    # Parse config-specific arguments
    if not args:
        # No args - show help
        print(f"{Colors.CYAN}CRACK Configuration Management{Colors.END}\n")
        print(f"{Colors.YELLOW}Usage:{Colors.END}")
        print("  crack config list [category]      - List configured variables")
        print("  crack config set VAR VALUE        - Set a variable")
        print("  crack config get VAR              - Get a variable value")
        print("  crack config delete VAR           - Delete a variable")
        print("  crack config clear [--keep-defaults] - Clear all variables")
        print("  crack config auto                 - Auto-detect network settings")
        print("  crack config validate             - Validate all configured values")
        print("  crack config categories           - List all variable categories")
        print("  crack config setup                - Interactive setup wizard")
        print("  crack config theme                - Interactive theme selector")
        print("  crack config edit                 - Open config file in editor")
        print("  crack config export FILE          - Export config to file")
        print("  crack config import FILE [--merge] - Import config from file")
        print(f"\n{Colors.YELLOW}Examples:{Colors.END}")
        print("  crack config auto")
        print("  crack config set LHOST 10.10.14.5")
        print("  crack config set TARGET 192.168.45.100")
        print("  crack config list network")
        print("  crack config setup")
        return

    subcommand = args[0]

    if subcommand == 'list':
        category = args[1] if len(args) > 1 else None
        variables = config.list_variables(category)

        if category:
            print(f"\n{Colors.CYAN}Variables in category: {category}{Colors.END}\n")
        else:
            print(f"\n{Colors.CYAN}All Configured Variables{Colors.END}\n")

        if not variables:
            print("No variables configured")
            if category:
                print(f"\nUse 'crack config categories' to see all categories")
        else:
            for name, var_data in sorted(variables.items()):
                if isinstance(var_data, dict):
                    value = var_data.get('value', '')
                    source = var_data.get('source', 'manual')
                    description = var_data.get('description', '')

                    if value:
                        print(f"  {Colors.GREEN}{name:20}{Colors.END} = {Colors.YELLOW}{value:30}{Colors.END} [{source}]")
                    else:
                        print(f"  {Colors.GREEN}{name:20}{Colors.END} = \033[2m(not set)\033[0m                   [{source}]")

                    if description:
                        print(f"  \033[2m{' ':20}   {description}\033[0m")
                else:
                    print(f"  {Colors.GREEN}{name:20}{Colors.END} = {Colors.YELLOW}{var_data}{Colors.END}")

        print(f"\n{Colors.CYAN}Config file:{Colors.END} {config.config_path}")

    elif subcommand == 'set':
        if len(args) < 3:
            print(f"{Colors.RED}Error:{Colors.END} Usage: crack config set VAR VALUE")
            return

        var_name = args[1]
        value = args[2]

        success, error = config.set_variable(var_name, value, validate=True)
        if success:
            print(f"{Colors.GREEN}✓{Colors.END} Set {Colors.CYAN}{var_name}{Colors.END} = {Colors.YELLOW}{value}{Colors.END}")
            print(f"Config saved to: {config.config_path}")
        else:
            print(f"{Colors.RED}✗ Error:{Colors.END} {error}")

    elif subcommand == 'get':
        if len(args) < 2:
            print(f"{Colors.RED}Error:{Colors.END} Usage: crack config get VAR")
            return

        var_name = args[1]
        value = config.get_variable(var_name)

        if value:
            print(f"{Colors.CYAN}{var_name}{Colors.END} = {Colors.YELLOW}{value}{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END} {var_name} is not set")

    elif subcommand == 'delete':
        if len(args) < 2:
            print(f"{Colors.RED}Error:{Colors.END} Usage: crack config delete VAR")
            return

        var_name = args[1]
        if config.delete_variable(var_name):
            print(f"{Colors.GREEN}✓{Colors.END} Deleted {Colors.CYAN}{var_name}{Colors.END}")
        else:
            print(f"{Colors.RED}✗{Colors.END} Variable not found: {var_name}")

    elif subcommand == 'clear':
        keep_defaults = '--keep-defaults' in args
        confirm = input(f"{Colors.YELLOW}Clear all variables? (y/N):{Colors.END} ").strip().lower()

        if confirm == 'y':
            if config.clear_variables(keep_defaults=keep_defaults):
                print(f"{Colors.GREEN}✓{Colors.END} Variables cleared")
            else:
                print(f"{Colors.RED}✗{Colors.END} Failed to clear variables")

    elif subcommand == 'auto':
        print("Auto-detecting network settings...")
        updates = config.auto_configure()

        if updates:
            print(f"\n{Colors.GREEN}✓ Auto-configured:{Colors.END}")
            for var, value in updates.items():
                print(f"  {Colors.CYAN}{var}{Colors.END} = {Colors.YELLOW}{value}{Colors.END}")
            print(f"\nConfig saved to: {config.config_path}")
        else:
            print(f"{Colors.YELLOW}No values auto-detected{Colors.END}")

    elif subcommand == 'validate':
        print("Validating all configured variables...")
        errors = config.validate_all()

        if not errors:
            print(f"{Colors.GREEN}✓ All variables are valid{Colors.END}")
        else:
            print(f"{Colors.RED}✗ Validation errors found:{Colors.END}\n")
            for var_name, error_list in errors.items():
                print(f"  {Colors.CYAN}{var_name}{Colors.END}:")
                for error in error_list:
                    print(f"    {Colors.RED}•{Colors.END} {error}")

    elif subcommand == 'categories':
        categories = config.get_all_categories()
        print(f"\n{Colors.CYAN}Variable Categories{Colors.END}\n")

        for category in categories:
            vars_in_cat = config.get_variables_by_category(category)
            print(f"  {Colors.YELLOW}{category:20}{Colors.END} ({len(vars_in_cat)} variables)")

        print(f"\nUse 'crack config list <category>' to see variables in a category")

    elif subcommand == 'setup':
        print(f"{Colors.CYAN}CRACK Configuration Setup Wizard{Colors.END}\n")
        print("This wizard will help you configure common variables.\n")

        # Auto-detect first
        print(f"{Colors.YELLOW}[1/4] Auto-detecting network settings...{Colors.END}")
        updates = config.auto_configure()
        if updates:
            for var, value in updates.items():
                print(f"  {Colors.GREEN}✓{Colors.END} {var} = {value}")

        # Network variables
        print(f"\n{Colors.YELLOW}[2/4] Network Configuration{Colors.END}")
        target = input(f"  TARGET IP address [\033[2m192.168.45.100\033[0m]: ").strip()
        if target:
            config.set_variable('TARGET', target, validate=True)

        lport = input(f"  LPORT [\033[2m4444\033[0m]: ").strip()
        if lport:
            config.set_variable('LPORT', lport, validate=True)

        # Web variables
        print(f"\n{Colors.YELLOW}[3/4] Web Testing Configuration{Colors.END}")
        wordlist = input(f"  WORDLIST path [\033[2m/usr/share/wordlists/dirb/common.txt\033[0m]: ").strip()
        if wordlist:
            config.set_variable('WORDLIST', wordlist, validate=False)

        threads = input(f"  THREADS [\033[2m10\033[0m]: ").strip()
        if threads:
            config.set_variable('THREADS', threads, validate=True)

        # Optional: API tokens
        print(f"\n{Colors.YELLOW}[4/4] Optional API Tokens{Colors.END}")
        wpscan = input(f"  WPSCAN_API_TOKEN [\033[2mskip\033[0m]: ").strip()
        if wpscan:
            config.set_variable('WPSCAN_API_TOKEN', wpscan, validate=False)

        print(f"\n{Colors.GREEN}✓ Setup complete!{Colors.END}")
        print(f"Config saved to: {config.config_path}")
        print(f"\nUse 'crack config list' to review your configuration")

    elif subcommand == 'edit':
        print(f"Opening config file: {config.config_path}")
        if config.open_editor():
            print("Config reloaded")
        else:
            print(f"{Colors.RED}✗{Colors.END} Failed to open editor")

    elif subcommand == 'export':
        if len(args) < 2:
            print(f"{Colors.RED}Error:{Colors.END} Usage: crack config export FILE")
            return

        filepath = args[1]
        if config.export_config(filepath):
            print(f"{Colors.GREEN}✓{Colors.END} Config exported to: {filepath}")
        else:
            print(f"{Colors.RED}✗{Colors.END} Failed to export config")

    elif subcommand == 'import':
        if len(args) < 2:
            print(f"{Colors.RED}Error:{Colors.END} Usage: crack config import FILE [--merge]")
            return

        filepath = args[1]
        merge = '--merge' in args

        if config.import_config(filepath, merge=merge):
            mode = "merged" if merge else "imported"
            print(f"{Colors.GREEN}✓{Colors.END} Config {mode} from: {filepath}")
        else:
            print(f"{Colors.RED}✗{Colors.END} Failed to import config")

    elif subcommand == 'theme':
        # Launch interactive theme selector
        from themes import interactive_theme_selector
        interactive_theme_selector()

    else:
        print(f"{Colors.RED}Error:{Colors.END} Unknown subcommand: {subcommand}")
        print("Use 'crack config' to see available commands")

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
  └─ scan-analyze    Parse nmap output to identify attack vectors

{Colors.YELLOW}▶ Web Application{Colors.END}
  ├─ html-enum       Find forms, comments, endpoints in HTML
  ├─ param-discover  Discover hidden GET/POST parameters
  ├─ param-extract   Extract form values as variables
  ├─ sqli-scan       Detect SQL injection vulnerabilities
  └─ sqli-fu         SQLi post-exploitation reference

{Colors.YELLOW}▶ Active Directory{Colors.END}
  └─ bloodtrail     BloodHound Trail - Edge enhancement and Neo4j query analysis

{Colors.YELLOW}▶ Session Management{Colors.END}
  └─ session         Reverse shell session management (TCP/HTTP/DNS)

{Colors.YELLOW}▶ Reference System{Colors.END}
  └─ reference       Command lookup with 70+ OSCP commands

{Colors.YELLOW}▶ Configuration Management{Colors.END}
  └─ config          Shared variable management (77 variables, 8 categories)

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

{Colors.GREEN}Session Management:{Colors.END}
  crack session start tcp --port 4444          # Start TCP listener
  crack session start http --port 8080         # Start HTTP beacon listener
  crack session start dns --domain tunnel.com  # Start DNS tunnel (root)
  crack session start icmp                     # Start ICMP tunnel (root)
  crack session list --filter active           # List active sessions
  crack session upgrade abc123 --method auto   # Upgrade shell to TTY
  crack session beacon-gen bash http://IP:8080 # Generate beacon script
  crack session tunnel-create abc123 --type ssh-dynamic --socks-port 1080
  crack session kill abc123                    # Kill session

{Colors.CYAN}══════════════════════════ CONFIGURATION ════════════════════════════{Colors.END}

{Colors.GREEN}Config System:{Colors.END} (~/.crack/config.json)
  77 variables across 8 categories (network, web, credentials, etc.)
  Shared across all modules (reference, track, sessions)

{Colors.GREEN}Quick Setup:{Colors.END}
  crack config setup                           # Interactive wizard (30 seconds)
  crack config auto                            # Auto-detect network settings
  crack config set LHOST 10.10.14.5           # Set variables manually
  crack config set TARGET 192.168.45.100
  crack config list                            # View all configured variables
  crack config list network                    # View by category
  crack config validate                        # Validate all values

{Colors.GREEN}Variable Categories:{Colors.END}
  network (12)      - LHOST, LPORT, TARGET, INTERFACE, IP, SUBNET, etc.
  web (11)          - URL, WORDLIST, WPSCAN_API_TOKEN, THREADS, etc.
  credentials (6)   - USERNAME, PASSWORD, LM_HASH, NTLM_HASH, etc.
  enumeration (7)   - SNMP_COMMUNITY, SERVICE, VERSION, SHARE, etc.
  exploitation (4)  - PAYLOAD, CVE_ID, EDB_ID, SEARCH_TERM
  file-transfer (8) - FILE, LOCAL_PATH, OUTPUT_DIR, MOUNT_POINT, etc.
  sql-injection (4) - DATABASE, NULL_COLUMNS, MAX_COLS, etc.
  misc (16)         - OUTPUT, DIR, SCRIPT, THEME, DATE, etc.

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

    # DNS Enumeration subcommand
    dns_enum_parser = subparsers.add_parser('dns-enum',
                                            help='Recursive DNS Enumeration',
                                            add_help=False)
    dns_enum_parser.set_defaults(func=dns_enum_command)

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

    # Cheatsheets subcommand
    cheatsheets_parser = subparsers.add_parser('cheatsheets', aliases=['cs'],
                                               help='Cheatsheets - Educational command collections',
                                               add_help=False)
    cheatsheets_parser.set_defaults(func=cheatsheets_command)

    # Chain Builder subcommand
    chain_builder_parser = subparsers.add_parser('chain-builder',
                                                 help='Chain Builder - Create attack chains',
                                                 add_help=False)
    chain_builder_parser.set_defaults(func=chain_builder_command)

    # Session Management subcommand
    session_parser = subparsers.add_parser('session',
                                           help='Session Management - Reverse shell handler',
                                           add_help=False)
    session_parser.set_defaults(func=session_command)

    # Configuration Management subcommand
    config_parser = subparsers.add_parser('config',
                                         help='Configuration Management - Variable management',
                                         add_help=False)
    config_parser.set_defaults(func=config_command)

    # Database Management subcommand
    db_parser = subparsers.add_parser('db',
                                     help='Database Management - Setup and manage PostgreSQL backend',
                                     add_help=False)
    db_parser.set_defaults(func=db_command)

    # Port Reference subcommand
    ports_parser = subparsers.add_parser('ports',
                                         help='Port Reference - Quick lookup of common ports and attack tools',
                                         add_help=False)
    ports_parser.set_defaults(func=ports_command)

    # BloodHound Trail subcommand
    blood_trail_parser = subparsers.add_parser('bloodtrail',
                                               help='BloodHound Trail - Edge enhancement and Neo4j query analysis',
                                               add_help=False)
    blood_trail_parser.set_defaults(func=blood_trail_command)

    # BloodHound Trail alias (bt)
    bt_parser = subparsers.add_parser('bt',
                                       help='Alias for bloodtrail',
                                       add_help=False)
    bt_parser.set_defaults(func=blood_trail_command)

    # PRISM - Security tool output parser
    prism_parser = subparsers.add_parser('prism',
                                         help='PRISM - Parse and distill security tool output (mimikatz, etc.)',
                                         add_help=False)
    prism_parser.set_defaults(func=prism_command)

    # Parse known args to allow passing through tool-specific args
    args, remaining = parser.parse_known_args()

    # Show banner unless suppressed
    # Note: reference, db, ports, and prism commands have no banner by default
    if not args.no_banner and args.tool:
        if args.tool not in ['reference', 'db', 'ports', 'prism'] or '--banner' in remaining:
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