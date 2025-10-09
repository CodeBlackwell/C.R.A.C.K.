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


def main():
    """Main CLI entry point for CRACK Track"""
    parser = argparse.ArgumentParser(
        description='C.R.A.C.K. T.R.A.C.K.\n(C)omprehensive (R)econ & (A)ttack (C)reation (K)it\n(T)argeted (R)econnaissance (A)nd (C)ommand (K)onsole\n\nEnumeration tracking and task management for OSCP preparation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (recommended for beginners)
  crack track interactive 192.168.45.100
  crack track -i 192.168.45.100
  crack track interactive 192.168.45.100 --resume

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

  # Delete target profile
  crack track delete 192.168.45.100

For full documentation: See track/README.md or https://github.com/CodeBlackwell/Phantom-Protocol
        """
    )

    parser.add_argument('target', nargs='?', help='Target IP or hostname')

    # Interactive mode
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Start interactive mode with progressive prompting')
    parser.add_argument('--tui', action='store_true',
                        help='Use windowed TUI interface (rich panels, no flooding)')
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

    # Advanced
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')

    args = parser.parse_args()

    # Enable debug mode if requested (re-enable INFO logs)
    if args.debug:
        logging.getLogger('crack.track.services.registry').setLevel(logging.INFO)
        EventBus.set_debug(True)

    # Initialize plugins and parsers
    ServiceRegistry.initialize_plugins()
    ParserRegistry.initialize_parsers()

    # Handle list command
    if args.list:
        handle_list()
        return

    # Handle visualization (may not need target)
    if args.visualize:
        handle_visualize(args)
        return

    # Target is required for all other commands
    if not args.target:
        parser.print_help()
        return

    # Handle interactive mode (before loading profile)
    if args.interactive:
        handle_interactive(args.target, args.resume, args.screened, args.wordlist, args.tui, args.tui_debug)
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


def handle_interactive(target: str, resume: bool = False, screened: bool = False, wordlist: str = None, tui: bool = False, tui_debug: bool = False):
    """Handle interactive mode

    Args:
        target: Target IP/hostname
        resume: Resume existing session
        screened: Screened mode with auto-parsing
        wordlist: Wordlist argument (raw, not resolved yet)
        tui: Use TUI windowed interface
        tui_debug: Enable TUI debug mode
    """
    # Choose session type based on TUI flag
    if tui:
        from .interactive.tui_session import TUISession
        session = TUISession(target, resume=resume, screened=screened, debug=tui_debug)
    else:
        from .interactive import InteractiveSession
        session = InteractiveSession(target, resume=resume, screened=screened)

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


if __name__ == '__main__':
    main()
