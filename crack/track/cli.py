"""
C.R.A.C.K. T.R.A.C.K. CLI

Main command-line interface for CRACK Track:
- (C)omprehensive (R)econ & (A)ttack (C)reation (K)it
- (T)argeted (R)econnaissance (A)nd (C)ommand (K)onsole

Enumeration tracking and task management system for OSCP preparation.
"""

import sys
import argparse
import logging
from pathlib import Path

# Configure logging early to suppress noisy plugin registration
# This must be done BEFORE importing ServiceRegistry
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logging.getLogger('crack.track.services.registry').setLevel(logging.WARNING)

from .core.state import TargetProfile
from .core.storage import Storage
from .core.events import EventBus
from .phases.registry import PhaseManager
from .services.registry import ServiceRegistry
from .parsers.registry import ParserRegistry
from .recommendations.engine import RecommendationEngine
from .formatters.console import ConsoleFormatter
from .formatters.markdown import MarkdownFormatter
from .interactive.debug_cli import create_config_from_args


def _resolve_wordlist_arg(wordlist_arg: str) -> str:
    """
    Resolve wordlist argument to absolute path

    Tries multiple resolution strategies:
    1. Direct path (if exists)
    2. Fuzzy search using WordlistManager
    3. User disambiguation if multiple matches

    Args:
        wordlist_arg: User-provided wordlist path or fuzzy name

    Returns:
        Absolute path to wordlist

    Raises:
        ValueError: If wordlist cannot be resolved
    """
    # Try as direct path first
    if Path(wordlist_arg).exists():
        return str(Path(wordlist_arg).resolve())

    # Try fuzzy matching with WordlistManager
    try:
        from .wordlists import WordlistManager

        # Initialize manager (will load cache or scan)
        manager = WordlistManager()

        # Ensure cache is populated
        if not manager.cache:
            print("Scanning wordlists directory (first time may take a few seconds)...")
            manager.scan_directory()

        # Search for matches
        matches = manager.search(wordlist_arg)

        if not matches:
            # No matches found - show suggestions
            all_wordlists = manager.get_all()
            if all_wordlists:
                print(f"\nError: No wordlist found matching '{wordlist_arg}'")
                print("\nAvailable wordlists (top 10):")
                for entry in all_wordlists[:10]:
                    print(f"  - {entry.name} ({entry.path})")
                print(f"\nTotal: {len(all_wordlists)} wordlists available")
                raise ValueError(f"No wordlist found: {wordlist_arg}")
            else:
                print(f"\nError: No wordlist found matching '{wordlist_arg}'")
                print("No wordlists discovered. Check wordlists directory.")
                raise ValueError(f"No wordlist found: {wordlist_arg}")

        elif len(matches) == 1:
            # Single match - use it
            return matches[0].path

        else:
            # Multiple matches - prompt user to disambiguate
            print(f"\nMultiple wordlists match '{wordlist_arg}':")
            for i, entry in enumerate(matches, 1):
                size_kb = entry.size_bytes / 1024
                print(f"  {i}. {entry.name}")
                print(f"     Path: {entry.path}")
                print(f"     Category: {entry.category} | Size: {size_kb:.1f} KB | Lines: {entry.line_count:,}")
                print()

            # Get user selection
            while True:
                try:
                    choice = input(f"Select wordlist [1-{len(matches)}] or 'q' to quit: ").strip()
                    if choice.lower() == 'q':
                        raise ValueError("User cancelled wordlist selection")

                    idx = int(choice) - 1
                    if 0 <= idx < len(matches):
                        return matches[idx].path
                    else:
                        print(f"Invalid selection. Enter 1-{len(matches)}")
                except ValueError as e:
                    if "User cancelled" in str(e):
                        raise
                    print(f"Invalid input. Enter a number 1-{len(matches)} or 'q'")

    except ImportError:
        # WordlistManager not available - fall back to direct path only
        raise ValueError(f"No wordlist found: {wordlist_arg}")
    except Exception as e:
        # Graceful degradation - try direct path before failing
        if "User cancelled" in str(e):
            # Re-raise user cancellation immediately
            raise
        print(f"Warning: Wordlist resolution failed: {e}")
        print(f"Trying direct path: {wordlist_arg}")
        if Path(wordlist_arg).exists():
            return str(Path(wordlist_arg).resolve())
        raise ValueError(f"No wordlist found: {wordlist_arg}")


def _should_use_tui(args) -> bool:
    """
    Determine if TUI should be used as default

    TUI is default UNLESS:
    - Already specified --tui or --interactive
    - Using non-interactive flags (--import, --export, --mark-done, etc.)
    - Not in a TTY (piped/scripted)

    Args:
        args: Parsed command-line arguments

    Returns:
        True if TUI should be used as default
    """
    # Already specified interactive mode - respect user choice
    if args.interactive or args.tui:
        return False  # Let existing logic handle it

    # Check for non-interactive operation flags
    non_interactive_flags = [
        args.import_file,
        args.mark_done,
        args.skip_task,
        args.finding,
        args.cred,
        args.note,
        args.export,
        args.export_commands,
        args.show_findings,
        args.show_creds,
        args.show_all,
        args.reset,
        args.stats
    ]

    if any(non_interactive_flags):
        return False  # User wants non-interactive operation

    # Check if stdin is a TTY (not piped/scripted)
    if not sys.stdin.isatty():
        return False  # Piped input, use non-interactive mode

    # Default to TUI for interactive work
    return True


def main():
    """Main CLI entry point for CRACK Track"""
    parser = argparse.ArgumentParser(
        description='C.R.A.C.K. T.R.A.C.K.\n(C)omprehensive (R)econ & (A)ttack (C)reation (K)it\n(T)argeted (R)econnaissance (A)nd (C)ommand (K)onsole\n\nEnumeration tracking and task management for OSCP preparation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (TUI is now DEFAULT)
  crack track                                         # Quick test with google-gruyere.appspot.com (default)
  crack track 192.168.45.100                          # Launches TUI interface for specific target
  crack track -i 192.168.45.100                       # Terminal-based interactive mode
  crack track 192.168.45.100 --resume                 # Resume TUI session

  # Start tracking a new target
  crack track new 192.168.45.100

  # Import nmap scan results (auto-generates service tasks)
  crack track import 192.168.45.100 port_scan.xml
  crack track import 192.168.45.100 service_scan.xml

  # View current status and recommendations
  crack track show 192.168.45.100
  crack track recommend 192.168.45.100

  # Mark tasks complete
  crack track done 192.168.45.100 whatweb-80
  crack track done 192.168.45.100 gobuster-80

  # Document findings (source required for OSCP!)
  crack track finding 192.168.45.100 \\
    --type vulnerability \\
    --description "SQLi in id parameter" \\
    --source "Manual testing with sqlmap"

  crack track note 192.168.45.100 "Apache 2.4.41 has CVE-2021-41773"

  # Add discovered credentials
  crack track creds 192.168.45.100 \\
    --username admin \\
    --password password123 \\
    --service mysql \\
    --port 3306 \\
    --source "Found in config.php"

  # Export OSCP writeup
  crack track export 192.168.45.100 > writeup.md
  crack track timeline 192.168.45.100

  # Visualize architecture and flows
  crack track --visualize architecture
  crack track --viz plugin-flow --viz-color
  crack track --viz plugin-graph                      # Phased plugin dependencies
  crack track --viz plugin-graph --viz-style compact  # Show trigger matrix
  crack track --viz master                            # NEW: Comprehensive master view
  crack track --viz master --viz-style compact        # Summary only
  crack track --viz master --viz-focus chains         # Focus on attack chains
  crack track 192.168.45.100 --viz task-tree
  crack track 192.168.45.100 --viz progress --viz-color
  crack track --viz decision-tree --viz-phase discovery

  # List all tracked targets
  crack track list

  # Migrate profiles from legacy location
  crack track --migrate                              # Migrate all profiles
  crack track --migrate --migrate-target 192.168.45.100  # Migrate specific target

  # Delete target profile
  crack track delete 192.168.45.100

Debug Options (Precision Logging):
  # Developer mode (auto-reset + debug enabled, perfect for QA from step 0)
  crack track --dev 192.168.45.100
  crack track --dev                                   # Uses default target

  # Basic debug logging to file (.debug_logs/)
  crack track --tui 192.168.45.100 --debug

  # Debug specific categories (UI, STATE, EXECUTION, etc.)
  crack track --tui 192.168.45.100 --debug --debug-categories=UI:VERBOSE,STATE:NORMAL
  crack track --tui 192.168.45.100 --debug --debug-categories=UI.INPUT:TRACE

  # Debug with console output (see logs in real-time)
  crack track --tui 192.168.45.100 --debug --debug-output=both

  # Debug with performance timing
  crack track --tui 192.168.45.100 --debug --debug-timing --debug-categories=PERFORMANCE

  # Available categories: UI, STATE, EXECUTION, DATA, NETWORK, PERFORMANCE, SYSTEM
  # Verbosity levels: MINIMAL, NORMAL, VERBOSE, TRACE
  # Output targets: file (default), console, both, json

For full documentation: See track/README.md or https://github.com/CodeBlackwell/Phantom-Protocol
        """
    )

    parser.add_argument('target', nargs='?',
                        default='google-gruyere.appspot.com',
                        help='Target IP or hostname (default: google-gruyere.appspot.com for testing)')

    # Interactive mode
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Use terminal-based interactive mode instead of TUI (TUI is default)')
    parser.add_argument('--tui', action='store_true',
                        help='Explicitly launch TUI interface (now the default for interactive work)')
    parser.add_argument('-D', '--tui-debug', action='store_true', dest='tui_debug',
                        help='Enable TUI debug mode (shows detailed execution flow in output panel)')
    parser.add_argument('--resume', action='store_true',
                        help='Resume existing interactive session')
    parser.add_argument('-X', '--screened', action='store_true',
                        help='Screened mode: persistent terminal with auto-parsing (use with -i)')

    # Import actions
    parser.add_argument('--import', dest='import_file', metavar='FILE',
                        help='Import scan results (nmap XML/gnmap)')

    # Task management
    parser.add_argument('--mark-done', dest='mark_done', metavar='TASK_ID',
                        help='Mark task as completed')
    parser.add_argument('--skip', dest='skip_task', metavar='TASK_ID',
                        help='Skip task with optional reason')
    parser.add_argument('--skip-reason', dest='skip_reason',
                        help='Reason for skipping task')

    # Data entry
    parser.add_argument('--finding', help='Add finding description')
    parser.add_argument('--finding-type', default='general',
                        help='Finding type (vulnerability, directory, user, etc.)')
    parser.add_argument('--source', help='Source of information (required for findings/creds)')

    parser.add_argument('--cred', metavar='USER:PASS',
                        help='Add credential (format: username:password)')
    parser.add_argument('--service', help='Service name for credential')
    parser.add_argument('--port', type=int, help='Port number for credential')

    parser.add_argument('--note', help='Add freeform note')

    # Display options
    parser.add_argument('--show-all', action='store_true',
                        help='Show all tasks (including completed)')
    parser.add_argument('--show-findings', action='store_true',
                        help='Show only findings')
    parser.add_argument('--show-creds', action='store_true',
                        help='Show only credentials')
    parser.add_argument('--phase', help='Show only tasks for specific phase')

    # Export options
    parser.add_argument('--export', metavar='FILE',
                        help='Export full report to markdown')
    parser.add_argument('--export-commands', metavar='FILE',
                        help='Export command reference to markdown')

    # Management
    parser.add_argument('--list', action='store_true',
                        help='List all tracked targets')
    parser.add_argument('--reset', action='store_true',
                        help='Reset target (delete profile)')
    parser.add_argument('--migrate', action='store_true',
                        help='Migrate profiles from ~/.crack/targets/ to ./CRACK_targets/')
    parser.add_argument('--migrate-target', metavar='TARGET',
                        help='Specific target to migrate (default: all)')
    parser.add_argument('--stats', action='store_true',
                        help='Show statistics')

    # Visualization
    parser.add_argument('--visualize', '--viz', '-v', metavar='VIEW',
                        choices=['architecture', 'plugin-flow', 'plugin-graph', 'master', 'task-tree', 'progress',
                                'phase-flow', 'decision-tree', 'plugins', 'themes'],
                        help='Visualize architecture/flow (architecture, plugin-flow, plugin-graph, master, task-tree, progress, phase-flow, decision-tree, plugins, themes)')
    parser.add_argument('--viz-style', default='tree',
                        choices=['tree', 'columnar', 'compact'],
                        help='Visualization style (default: tree)')
    parser.add_argument('--viz-color', action='store_true',
                        help='Enable colored output')
    parser.add_argument('--viz-theme', default='oscp',
                        choices=['oscp', 'dark', 'light', 'mono'],
                        help='Color theme (default: oscp)')
    parser.add_argument('--viz-phase', default='discovery',
                        help='Phase for decision-tree view (default: discovery)')
    parser.add_argument('--viz-focus',
                        choices=['summary', 'phases', 'ports', 'chains', 'tags', 'overlaps', 'tasks', 'graph'],
                        help='Focus on specific section of master view')
    parser.add_argument('--viz-output', '-o', metavar='FILE',
                        help='Export visualization to markdown file (untruncated)')

    # Wordlist selection
    parser.add_argument('--wordlist',
                        help='Wordlist path or fuzzy name (e.g., common, rockyou)')

    # Advanced / Developer mode
    parser.add_argument('--dev', nargs='?', const=True, metavar='FIXTURE',
                        help='Developer mode: auto-reset profile OR load fixture (e.g., --dev=web-enum)')

    # Fixture management (dev mode extensions)
    dev_group = parser.add_argument_group('fixture management (dev mode)')
    dev_group.add_argument('--dev-save', metavar='NAME',
                          help='Save current profile as dev fixture')
    dev_group.add_argument('--dev-list', action='store_true',
                          help='List available dev fixtures')
    dev_group.add_argument('--dev-show', metavar='NAME',
                          help='Show fixture details')
    dev_group.add_argument('--dev-delete', metavar='NAME',
                          help='Delete dev fixture')
    dev_group.add_argument('--dev-description', metavar='TEXT',
                          help='Description for --dev-save (optional)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable precision debug logging to .debug_logs/ (combine with --debug-categories for filtering)')

    # Precision debug logging arguments (skip --debug as it's already defined above)
    debug_group = parser.add_argument_group('precision debug logging options')

    debug_group.add_argument(
        '--debug-categories',
        type=str,
        metavar='SPECS',
        help='Comma-separated category specs (e.g., "UI.INPUT:VERBOSE,STATE:NORMAL")'
    )

    debug_group.add_argument(
        '--debug-modules',
        type=str,
        metavar='MODULES',
        help='Comma-separated module names to log (prefix with ! to disable)'
    )

    debug_group.add_argument(
        '--debug-level',
        type=str,
        choices=['MINIMAL', 'NORMAL', 'VERBOSE', 'TRACE'],
        metavar='LEVEL',
        help='Global log level (MINIMAL, NORMAL, VERBOSE, TRACE)'
    )

    debug_group.add_argument(
        '--debug-output',
        type=str,
        choices=['file', 'console', 'both', 'json'],
        metavar='TARGET',
        help='Output target: file, console, both, or json'
    )

    debug_group.add_argument(
        '--debug-format',
        type=str,
        choices=['text', 'json', 'compact'],
        metavar='FORMAT',
        help='Log format: text, json, or compact'
    )

    debug_group.add_argument(
        '--debug-config',
        type=str,
        metavar='PATH',
        help='Path to debug configuration JSON file'
    )

    debug_group.add_argument(
        '--debug-timing',
        action='store_true',
        help='Include performance timing in logs'
    )

    args = parser.parse_args()

    # Handle fixture management commands (early exit)
    if args.dev_list:
        handle_dev_list()
        return

    if args.dev_show:
        handle_dev_show(args.dev_show)
        return

    if args.dev_delete:
        handle_dev_delete(args.dev_delete)
        return

    if args.dev_save:
        handle_dev_save(args.target, args.dev_save, args.dev_description)
        return

    # Handle developer mode (auto-reset OR fixture load)
    dev_mode = args.dev
    dev_fixture = None

    if dev_mode:
        args.debug = True  # Auto-enable debug mode
        args.tui = True    # Auto-enable TUI mode

        # Check if dev_mode is a string (fixture name)
        if isinstance(dev_mode, str):
            dev_fixture = dev_mode

    # Enable debug mode if requested (re-enable INFO logs)
    if args.debug:
        logging.getLogger('crack.track.services.registry').setLevel(logging.INFO)
        EventBus.set_debug(True)

    # Initialize plugins and parsers
    ServiceRegistry.initialize_plugins()
    ParserRegistry.initialize_parsers()

    # Print dev mode banner AFTER plugin initialization (for visibility)
    if dev_mode:
        from .core.fixtures import FixtureStorage

        print(f"\n{'='*50}")
        print(f"[DEV MODE] Enabled for {args.target}")
        print(f"{'='*50}")

        if dev_fixture:
            # Load fixture mode
            print(f"  • Fixture: {dev_fixture}")
            print("  • Debug logging: ON (.debug_logs/)")
            print("  • TUI mode: ON")

            try:
                FixtureStorage.load_fixture(dev_fixture, args.target)
                print(f"\n  ✓ Fixture '{dev_fixture}' loaded successfully")

                # Show fixture summary
                details = FixtureStorage.get_fixture_details(dev_fixture)
                profile_info = details['profile']
                print(f"  ✓ Phase: {profile_info['phase']}")
                print(f"  ✓ Ports: {profile_info['port_summary']}")
                print(f"  ✓ Tasks: {profile_info['task_count']}")

            except ValueError as e:
                print(f"\n  ✗ Error: {e}")
                print(f"\nAvailable fixtures:")
                for fixture in FixtureStorage.list_fixtures():
                    print(f"  - {fixture['name']}: {fixture['description']}")
                sys.exit(1)

        else:
            # Reset mode (original behavior)
            print("  • Auto-reset: ON")
            print("  • Debug logging: ON (.debug_logs/)")
            print("  • TUI mode: ON")

            # Auto-reset profile without confirmation
            if TargetProfile.exists(args.target):
                Storage.delete(args.target)
                print(f"\n  ✓ Profile reset (clean slate for QA)")

        print(f"{'='*50}\n")

    # Handle list command
    if args.list:
        handle_list()
        return

    # Handle migration command
    if args.migrate:
        handle_migrate(args.migrate_target)
        return

    # Handle visualization (may not need target)
    if args.visualize:
        handle_visualize(args)
        return

    # Target now has a default (google-gruyere.appspot.com) for easy testing
    # No need to check if target is provided

    # Check if TUI should be default (new behavior)
    # TUI becomes the default interactive mode unless user specifies otherwise
    if _should_use_tui(args):
        # Auto-enable TUI mode for interactive work
        args.tui = True

    # Handle interactive mode (before loading profile)
    # --tui flag automatically enables interactive mode
    if args.interactive or args.tui:
        # Create debug config from CLI args
        debug_config = create_config_from_args(args)
        handle_interactive(args.target, args.resume, args.screened, args.wordlist, args.tui, args.tui_debug, debug_config)
        return

    # Load or create profile
    profile = load_or_create_profile(args.target)

    # Handle reset
    if args.reset:
        handle_reset(args.target)
        return

    # Handle import
    if args.import_file:
        handle_import(profile, args.import_file)

    # Handle task completion
    if args.mark_done:
        handle_mark_done(profile, args.mark_done)

    if args.skip_task:
        handle_skip(profile, args.skip_task, args.skip_reason)

    # Handle data entry
    if args.finding:
        handle_finding(profile, args.finding, args.finding_type, args.source)

    if args.cred:
        handle_credential(profile, args.cred, args.service, args.port, args.source)

    if args.note:
        handle_note(profile, args.note, args.source)

    # Handle export
    if args.export:
        handle_export(profile, args.export)
        return

    if args.export_commands:
        handle_export_commands(profile, args.export_commands)
        return

    # Handle display modes
    if args.show_findings:
        print(ConsoleFormatter.format_findings(profile))
        return

    if args.show_creds:
        print(ConsoleFormatter.format_credentials(profile))
        return

    # Default: Show checklist with recommendations
    handle_display(profile)


def load_or_create_profile(target: str) -> TargetProfile:
    """Load existing profile or create new one"""
    if TargetProfile.exists(target):
        profile = TargetProfile.load(target)
        print(f"Loaded existing profile for {target}")
    else:
        profile = TargetProfile(target)
        print(f"Created new profile for {target}")
        # Tasks are auto-initialized in __init__
        profile.save()

    return profile


def handle_interactive(target: str, resume: bool = False, screened: bool = False, wordlist: str = None, tui: bool = False, tui_debug: bool = False, debug_config=None):
    """Handle interactive mode

    Args:
        target: Target IP/hostname
        resume: Resume existing session
        screened: Screened mode with auto-parsing
        wordlist: Wordlist argument (raw, not resolved yet)
        tui: Use TUI windowed interface
        tui_debug: Enable TUI debug mode (legacy flag, use --debug for precision logging)
        debug_config: LogConfig instance for precision debug logging
    """
    # Choose session type based on TUI flag
    if tui:
        from .interactive.tui_session_v2 import TUISessionV2
        session = TUISessionV2(target, resume=resume, screened=screened, debug=tui_debug, debug_config=debug_config)
    else:
        from .interactive import InteractiveSession
        session = InteractiveSession(target, resume=resume, screened=screened, debug_config=debug_config)

    try:

        # If wordlist provided, store in session context for task creation
        if wordlist:
            # Resolve wordlist path
            try:
                resolved_path = _resolve_wordlist_arg(wordlist)
                print(f"Using wordlist: {resolved_path}")
                # Store in session for task metadata
                if hasattr(session, 'default_wordlist'):
                    session.default_wordlist = resolved_path
                else:
                    # Create attribute if doesn't exist
                    session.default_wordlist = resolved_path
            except ValueError as e:
                print(f"Error resolving wordlist: {e}")
                print("Continuing without pre-selected wordlist")

        session.run()
    except KeyboardInterrupt:
        print("\n\nInteractive mode interrupted.")
    except Exception as e:
        print(f"Error in interactive mode: {e}")
        import traceback
        traceback.print_exc()


def handle_import(profile: TargetProfile, filepath: str):
    """Handle file import"""
    print(f"Importing {filepath}...")

    try:
        # Parse file and update profile
        data = ParserRegistry.parse_file(filepath, profile.target, profile)

        # Display summary
        print()
        print(ConsoleFormatter.format_import_summary(data))
        print()

        # Check for phase advancement
        PhaseManager.advance_phase(profile.phase, profile)

        # Save profile
        profile.save()
        print(f"✓ Profile saved")

    except Exception as e:
        print(f"Error importing file: {e}")
        sys.exit(1)


def handle_mark_done(profile: TargetProfile, task_id: str):
    """Mark task as completed"""
    try:
        profile.mark_task_done(task_id)
        profile.save()
        print(f"✓ Marked task '{task_id}' as completed")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


def handle_skip(profile: TargetProfile, task_id: str, reason: str = None):
    """Skip task"""
    task = profile.get_task(task_id)
    if not task:
        print(f"Error: Task '{task_id}' not found")
        sys.exit(1)

    task.mark_skipped(reason)
    profile.save()
    print(f"✓ Skipped task '{task_id}'")


def handle_finding(profile: TargetProfile, description: str, finding_type: str, source: str):
    """Add finding"""
    if not source:
        print("Error: --source is required for findings")
        sys.exit(1)

    profile.add_finding(finding_type, description, source=source)
    profile.save()
    print(f"✓ Added finding: {description}")


def handle_credential(profile: TargetProfile, cred_str: str, service: str, port: int, source: str):
    """Add credential"""
    if not source:
        print("Error: --source is required for credentials")
        sys.exit(1)

    # Parse credential string
    if ':' in cred_str:
        username, password = cred_str.split(':', 1)
    else:
        username = cred_str
        password = None

    profile.add_credential(
        username=username,
        password=password,
        service=service,
        port=port,
        source=source
    )
    profile.save()
    print(f"✓ Added credential: {username}")


def handle_note(profile: TargetProfile, note: str, source: str):
    """Add note"""
    profile.add_note(note, source=source or 'manual')
    profile.save()
    print(f"✓ Added note")


def handle_display(profile: TargetProfile):
    """Display interactive checklist"""
    # Get recommendations
    recommendations = RecommendationEngine.get_recommendations(profile)

    # Format and display
    output = ConsoleFormatter.format_profile(profile, recommendations)
    print(output)


def handle_export(profile: TargetProfile, filepath: str):
    """Export markdown report"""
    report = MarkdownFormatter.export_full_report(profile)

    with open(filepath, 'w') as f:
        f.write(report)

    print(f"✓ Exported report to {filepath}")


def handle_export_commands(profile: TargetProfile, filepath: str):
    """Export command reference"""
    reference = MarkdownFormatter.export_task_reference(profile)

    with open(filepath, 'w') as f:
        f.write(reference)

    print(f"✓ Exported command reference to {filepath}")


def handle_list():
    """List all tracked targets"""
    targets = Storage.list_targets()

    if not targets:
        print("No targets tracked yet")
        return

    print(f"Tracked targets ({len(targets)}):")
    print()

    for target in targets:
        profile = TargetProfile.load(target)
        if profile:
            progress = profile.get_progress()
            pct = (progress['completed'] / progress['total'] * 100) if progress['total'] > 0 else 0

            print(f"  • {target}")
            print(f"    Phase: {profile.phase} | Progress: {progress['completed']}/{progress['total']} ({pct:.0f}%)")
            print(f"    Ports: {len(profile.ports)} | Findings: {len(profile.findings)}")
            print()


def handle_reset(target: str):
    """Reset target profile"""
    if not TargetProfile.exists(target):
        print(f"Target {target} not found")
        return

    confirm = input(f"Reset profile for {target}? This will delete all data. (yes/no): ")
    if confirm.lower() == 'yes':
        Storage.delete(target)
        print(f"✓ Deleted profile for {target}")
    else:
        print("Cancelled")


def handle_migrate(target: str = None):
    """Migrate profiles from legacy location to project-local

    Args:
        target: Specific target to migrate (None = migrate all)
    """
    from pathlib import Path

    legacy_dir = Path.home() / ".crack" / "targets"
    new_dir = Path.cwd() / "CRACK_targets"

    print("=" * 60)
    print("Profile Migration: ~/.crack/targets/ → ./CRACK_targets/")
    print("=" * 60)
    print()

    # Check if legacy directory exists
    if not legacy_dir.exists():
        print("✓ No legacy profiles found")
        print(f"  Legacy directory does not exist: {legacy_dir}")
        return

    # Count profiles to migrate
    if target:
        count = 1 if (legacy_dir / f"{target.replace('/', '_').replace(':', '_')}.json").exists() else 0
    else:
        count = len(list(legacy_dir.glob("*.json")))

    if count == 0:
        print("✓ No profiles to migrate")
        return

    print(f"Found {count} profile(s) to migrate")
    print(f"  From: {legacy_dir}")
    print(f"  To:   {new_dir}")
    print()

    # Confirm migration
    if target:
        confirm = input(f"Migrate profile for {target}? (yes/no): ")
    else:
        confirm = input(f"Migrate all {count} profiles? (yes/no): ")

    if confirm.lower() != 'yes':
        print("Cancelled")
        return

    # Perform migration
    stats = Storage.migrate_from_legacy(target)

    print()
    print("Migration Results:")
    print(f"  ✓ Migrated: {stats['migrated']}")
    if stats['skipped'] > 0:
        print(f"  • Skipped (already exists): {stats['skipped']}")
    if stats['errors'] > 0:
        print(f"  ✗ Errors: {stats['errors']}")

    if stats['migrated'] > 0:
        print()
        print("Profiles are now stored in ./CRACK_targets/")
        print("Original files remain in ~/.crack/targets/ (backup)")


def handle_visualize(args):
    """Handle visualization command"""
    from .visualizer import visualize

    view = args.visualize
    target = args.target
    output_file = args.viz_output

    # Check if target is required for this view
    target_required = view in ['task-tree', 'progress']
    if target_required and not target:
        print(f"Error: View '{view}' requires a target")
        print(f"Usage: crack track {view} <target>")
        sys.exit(1)

    # Build options
    opts = {
        'style': args.viz_style,
        'color': args.viz_color,
        'theme': args.viz_theme,
        'phase': args.viz_phase,
        'focus': args.viz_focus,  # focus option for master view
        'output_file': output_file  # NEW: output file for markdown export
    }

    # Render visualization
    output = visualize(view, target, **opts)

    # Write to file if output file specified
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(output)
            print(f"✓ Exported visualization to {output_file}")
            # Also show file size
            import os
            size = os.path.getsize(output_file)
            print(f"  File size: {size:,} bytes")
        except IOError as e:
            print(f"Error writing to {output_file}: {e}")
            sys.exit(1)
    else:
        # Print to terminal
        print(output)


def handle_dev_save(target: str, fixture_name: str, description: str = None):
    """Save current profile as dev fixture"""
    from .core.fixtures import FixtureStorage

    try:
        # Check if profile exists
        if not TargetProfile.exists(target):
            print(f"Error: No profile found for {target}")
            print(f"Create a profile first: crack track {target}")
            sys.exit(1)

        # Save fixture
        fixture_path = FixtureStorage.save_fixture(target, fixture_name, description)
        print(f"✓ Saved fixture '{fixture_name}' from {target}")
        print(f"  Location: {fixture_path}")

        # Show fixture details
        details = FixtureStorage.get_fixture_details(fixture_name)
        profile_info = details['profile']
        print(f"\nFixture Summary:")
        print(f"  Phase: {profile_info['phase']}")
        print(f"  Ports: {profile_info['port_summary']}")
        print(f"  Findings: {profile_info['finding_summary'] or 'None'}")
        print(f"  Tasks: {profile_info['task_count']}")
        print(f"\nLoad with: crack track --dev={fixture_name} <target>")

    except Exception as e:
        print(f"Error saving fixture: {e}")
        sys.exit(1)


def handle_dev_list():
    """List available dev fixtures"""
    from .core.fixtures import FixtureStorage

    fixtures = FixtureStorage.list_fixtures()

    if not fixtures:
        print("No dev fixtures available")
        print("\nCreate a fixture:")
        print("  crack track --dev-save <name> <target>")
        return

    print(f"Available Dev Fixtures ({len(fixtures)}):\n")

    for fixture in fixtures:
        print(f"  • {fixture['name']}")
        print(f"    Description: {fixture['description']}")
        print(f"    Phase: {fixture['phase']} | Ports: {fixture['ports']} | Findings: {fixture['findings']} | Tasks: {fixture['tasks']}")
        print(f"    Source: {fixture['source_target']} | Created: {fixture['created'][:10]}")
        print()

    print("Load a fixture:")
    print(f"  crack track --dev=<fixture-name> <target>")


def handle_dev_show(fixture_name: str):
    """Show detailed fixture info"""
    from .core.fixtures import FixtureStorage

    try:
        details = FixtureStorage.get_fixture_details(fixture_name)

        metadata = details['metadata']
        profile = details['profile']

        print(f"\nFixture: {fixture_name}")
        print("=" * 60)
        print(f"\nDescription: {metadata.get('description', 'No description')}")
        print(f"Created: {metadata.get('created', 'Unknown')}")
        print(f"Source Target: {metadata.get('source_target', 'Unknown')}")

        print(f"\nProfile State:")
        print(f"  Target: {profile['target']}")
        print(f"  Phase: {profile['phase']}")
        print(f"  Status: {profile['status']}")

        print(f"\nEnumeration Summary:")
        print(f"  Ports: {profile['port_summary']}")
        print(f"  Findings: {profile['finding_summary'] or 'None'}")
        print(f"  Credentials: {profile['credential_count']}")
        print(f"  Notes: {profile['note_count']}")
        print(f"  Tasks: {profile['task_count']}")

        print(f"\nLoad this fixture:")
        print(f"  crack track --dev={fixture_name} <target>")

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


def handle_dev_delete(fixture_name: str):
    """Delete dev fixture"""
    from .core.fixtures import FixtureStorage

    try:
        # Show what will be deleted
        details = FixtureStorage.get_fixture_details(fixture_name)
        print(f"\nFixture to delete: {fixture_name}")
        print(f"  Description: {details['metadata'].get('description', 'No description')}")

        # Confirm deletion
        confirm = input(f"\nDelete fixture '{fixture_name}'? (yes/no): ")
        if confirm.lower() == 'yes':
            FixtureStorage.delete_fixture(fixture_name)
            print(f"✓ Deleted fixture '{fixture_name}'")
        else:
            print("Cancelled")

    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
