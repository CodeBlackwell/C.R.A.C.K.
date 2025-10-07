"""
CRACK Track CLI

Main command-line interface for CRACK Track - the enumeration tracking and task management system.
"""

import sys
import argparse
from pathlib import Path

from .core.state import TargetProfile
from .core.storage import Storage
from .core.events import EventBus
from .phases.registry import PhaseManager
from .services.registry import ServiceRegistry
from .parsers.registry import ParserRegistry
from .recommendations.engine import RecommendationEngine
from .formatters.console import ConsoleFormatter
from .formatters.markdown import MarkdownFormatter


def main():
    """Main CLI entry point for CRACK Track"""
    parser = argparse.ArgumentParser(
        description='CRACK Track - Enumeration tracking and task management for OSCP preparation',
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
    parser.add_argument('--resume', action='store_true',
                        help='Resume existing interactive session')

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
                        choices=['architecture', 'plugin-flow', 'task-tree', 'progress',
                                'phase-flow', 'decision-tree', 'plugins'],
                        help='Visualize architecture/flow (architecture, plugin-flow, task-tree, progress, phase-flow, decision-tree, plugins)')
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

    # Advanced
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug output')

    args = parser.parse_args()

    # Initialize plugins and parsers
    ServiceRegistry.initialize_plugins()
    ParserRegistry.initialize_parsers()

    # Enable debug if requested
    if args.debug:
        EventBus.set_debug(True)

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
        handle_interactive(args.target, args.resume)
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


def handle_interactive(target: str, resume: bool = False):
    """Handle interactive mode"""
    from .interactive import InteractiveSession

    try:
        session = InteractiveSession(target, resume=resume)
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
        'phase': args.viz_phase
    }

    # Render visualization
    output = visualize(view, target, **opts)
    print(output)


if __name__ == '__main__':
    main()
