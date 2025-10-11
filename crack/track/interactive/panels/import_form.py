"""
Import Form Panel - Wizard for importing scan results

Features:
- Multi-stage import wizard (file path → detect type → preview → merge → confirm)
- Auto-detect file format (Nmap XML, greppable, JSON)
- Parse preview showing what will be imported
- Merge strategy selection (replace, append, smart-merge)
- Graceful error handling (file not found, parse errors)
- Integration with existing parsers (track/parsers/)

Follows hub-spoke navigation - this is a spoke panel.
"""

from typing import Dict, Any, Optional, Tuple, List
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text
from rich.console import Console
from pathlib import Path
import os

from ..themes.helpers import format_menu_number, format_hotkey


class ImportForm:
    """Import wizard for scan results"""

    # Import stages
    STAGE_FILE_PATH = 1
    STAGE_PREVIEW = 2
    STAGE_MERGE_STRATEGY = 3
    STAGE_CONFIRM = 4
    STAGE_COMPLETE = 5

    # Merge strategies
    MERGE_REPLACE = 'replace'       # Clear existing, use new data only
    MERGE_APPEND = 'append'         # Keep existing, add new data
    MERGE_SMART = 'smart-merge'     # Deduplicate, merge intelligently

    # Common scan file patterns
    COMMON_PATHS = [
        './nmap.xml',
        './scan.xml',
        './nmap.gnmap',
        './scan.gnmap',
        './ports.txt',
        './output.xml'
    ]

    def __init__(self, profile=None, validator=None, error_handler=None, console=None, debug_logger=None, theme=None):
        """
        Initialize import form

        Args:
            profile: TargetProfile instance (optional, for validation)
            validator: InputValidator instance (optional, created if None)
            error_handler: ErrorHandler instance (optional, created if None)
            console: Rich Console instance (optional, created if None)
            debug_logger: DebugLogger instance (optional, for logging validation)
            theme: ThemeManager instance (optional, created if None)
        """
        self.profile = profile
        self.console = console or Console()
        self.debug_logger = debug_logger

        # Initialize theme (fallback for backward compatibility)
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()
        self.theme = theme

        # Initialize validation components (create if not provided)
        if validator:
            self.validator = validator
        else:
            from ..components.input_validator import InputValidator
            self.validator = InputValidator()

        if error_handler:
            self.error_handler = error_handler
        else:
            from ..components.error_handler import ErrorHandler, ErrorType
            self.error_handler = ErrorHandler(console=self.console)

        self.reset()

    def reset(self):
        """Clear form state and start fresh"""
        self.stage = self.STAGE_FILE_PATH
        self.file_path: Optional[str] = None
        self.file_type: Optional[str] = None
        self.parse_results: Optional[Dict[str, Any]] = None
        self.merge_strategy: str = self.MERGE_SMART
        self.error_message: Optional[str] = None
        self.import_success = False
        self.import_summary: Optional[Dict[str, Any]] = None

    def render(self) -> Tuple[Panel, List[Dict]]:
        """
        Render import wizard based on current stage

        Returns:
            Tuple of (Rich Panel, choices list for input processing)
        """
        if self.stage == self.STAGE_FILE_PATH:
            return self._render_file_path_stage()
        elif self.stage == self.STAGE_PREVIEW:
            return self._render_preview_stage()
        elif self.stage == self.STAGE_MERGE_STRATEGY:
            return self._render_merge_strategy_stage()
        elif self.stage == self.STAGE_CONFIRM:
            return self._render_confirm_stage()
        elif self.stage == self.STAGE_COMPLETE:
            return self._render_complete_stage()
        else:
            # Fallback - should never happen
            return self._render_file_path_stage()

    def _render_file_path_stage(self) -> Tuple[Panel, List[Dict]]:
        """
        Render file path input stage

        Returns:
            Tuple of (Panel, choices)
        """
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Section", style="white", width=80)

        # Header
        table.add_row(f"[bold {self.theme.get_color('primary')}]📥 IMPORT SCAN RESULTS[/]")
        table.add_row(self.theme.muted("Step 1/4: Select file to import"))
        table.add_row("")

        # Show current file path if set
        if self.file_path:
            status = self._check_file_exists(self.file_path)
            if status['exists']:
                table.add_row(f"{self.theme.primary('File:')} {self.file_path}")
                table.add_row(self.theme.success(f"✓ File found ({status['size']})"))
            else:
                table.add_row(f"{self.theme.primary('File:')} {self.file_path}")
                table.add_row(self.theme.danger("✗ File not found"))
        else:
            table.add_row(self.theme.muted("No file selected yet"))

        # Show error if any
        if self.error_message:
            table.add_row("")
            table.add_row(f"[bold {self.theme.get_color('danger')}]Error:[/] {self.error_message}")

        table.add_row("")

        # Common paths suggestions
        table.add_row(f"[bold {self.theme.get_color('text')}]Common Paths:[/]")
        table.add_row("")

        existing_paths = []
        for path in self.COMMON_PATHS:
            if os.path.exists(path):
                file_size = self._format_file_size(os.path.getsize(path))
                table.add_row(f"  {self.theme.success('✓')} {path} {self.theme.muted(f'({file_size})')}")
                existing_paths.append(path)
            else:
                table.add_row(f"  {self.theme.muted(f'✗ {path}')}")

        table.add_row("")

        # Build action menu
        choices = []

        table.add_row(f"[bold {self.theme.get_color('text')}]Actions:[/]")
        table.add_row("")

        table.add_row(f"{format_menu_number(self.theme, '1')} Enter custom file path")
        choices.append({
            'id': 'enter-path',
            'label': 'Enter custom file path',
            'action': 'enter_path'
        })

        # Quick select for existing common paths
        if existing_paths:
            for idx, path in enumerate(existing_paths, 2):
                table.add_row(f"{format_menu_number(self.theme, str(idx))} Use {path}")
                choices.append({
                    'id': f'use-{idx}',
                    'label': f'Use {path}',
                    'action': 'use_path',
                    'path': path
                })

        table.add_row("")

        if self.file_path and self._check_file_exists(self.file_path)['exists']:
            table.add_row(f"{format_hotkey(self.theme, 'n')} Next (detect file type)")
            choices.append({
                'id': 'next',
                'label': 'Next (detect file type)',
                'action': 'next_stage'
            })
            table.add_row("")

        table.add_row(f"{format_hotkey(self.theme, 'b')} Back to dashboard")
        choices.append({
            'id': 'back',
            'label': 'Back to dashboard',
            'action': 'back'
        })

        # Build panel
        breadcrumb = "Dashboard > Import Scan"
        title = f"[bold {self.theme.get_color('primary')}]{breadcrumb}[/]"
        target_info = f"Target: {self.profile.target}" if self.profile else "Standalone Mode"
        subtitle = f"{self.theme.muted(target_info + ' | Step 1: File Selection')}"

        return Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style=self.theme.panel_border(),
            box=box.ROUNDED
        ), choices

    def _render_preview_stage(self) -> Tuple[Panel, List[Dict]]:
        """
        Render parse preview stage

        Returns:
            Tuple of (Panel, choices)
        """
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Section", style="white", width=80)

        # Header
        table.add_row(f"[bold {self.theme.get_color('primary')}]📥 IMPORT SCAN RESULTS[/]")
        table.add_row(self.theme.muted("Step 2/4: Preview parsed data"))
        table.add_row("")

        # File info
        table.add_row(f"{self.theme.primary('File:')} {self.file_path}")
        table.add_row(f"{self.theme.primary('Type:')} {self.file_type or 'Unknown'}")
        table.add_row("")

        # Parse results summary
        if self.parse_results:
            table.add_row(f"[bold {self.theme.get_color('text')}]PARSE RESULTS:[/]")
            table.add_row("")

            target = self.parse_results.get('target', 'N/A')
            ports = self.parse_results.get('ports', [])
            hostnames = self.parse_results.get('hostnames', [])
            os_guess = self.parse_results.get('os_guess')

            table.add_row(f"  {self.theme.primary('Target:')} {target}")
            table.add_row(f"  {self.theme.primary('Open Ports:')} {len(ports)}")

            if hostnames:
                table.add_row(f"  {self.theme.primary('Hostnames:')} {', '.join(hostnames[:3])}")

            if os_guess:
                table.add_row(f"  {self.theme.primary('OS Detection:')} {os_guess}")

            # Show port preview (first 5)
            if ports:
                table.add_row("")
                table.add_row(f"[bold {self.theme.get_color('text')}]Port Preview:[/]")
                table.add_row("")

                port_table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
                port_table.add_column("Port", style=self.theme.get_color('primary'), width=8)
                port_table.add_column("Service", style="white", width=15)
                port_table.add_column("Version", style=self.theme.get_color('muted'), width=45)

                for port_data in ports[:5]:
                    port_num = str(port_data.get('port', 'N/A'))
                    service = port_data.get('service', 'unknown')
                    version = port_data.get('version', '')[:43] + '...' if len(port_data.get('version', '')) > 45 else port_data.get('version', '-')

                    port_table.add_row(port_num, service, version)

                if len(ports) > 5:
                    port_table.add_row(self.theme.muted("..."), self.theme.muted(f"({len(ports) - 5} more)"), "")

                table.add_row(port_table)

        elif self.error_message:
            table.add_row(f"[bold {self.theme.get_color('danger')}]Parse Error:[/] {self.error_message}")

        table.add_row("")

        # Build action menu
        choices = []

        table.add_row(f"[bold {self.theme.get_color('text')}]Actions:[/]")
        table.add_row("")

        if self.parse_results:
            table.add_row(f"{format_hotkey(self.theme, 'n')} Next (select merge strategy)")
            choices.append({
                'id': 'next',
                'label': 'Next (select merge strategy)',
                'action': 'next_stage'
            })
        else:
            table.add_row(self.theme.muted("Fix errors before continuing"))

        table.add_row("")
        table.add_row(f"{format_hotkey(self.theme, 'b')} Back (change file)")
        choices.append({
            'id': 'back',
            'label': 'Back (change file)',
            'action': 'prev_stage'
        })

        # Build panel
        breadcrumb = "Dashboard > Import Scan > Preview"
        title = f"[bold {self.theme.get_color('primary')}]{breadcrumb}[/]"
        subtitle = self.theme.muted("Step 2: Preview parsed data")

        return Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style=self.theme.panel_border(),
            box=box.ROUNDED
        ), choices

    def _render_merge_strategy_stage(self) -> Tuple[Panel, List[Dict]]:
        """
        Render merge strategy selection stage

        Returns:
            Tuple of (Panel, choices)
        """
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Section", style="white", width=80)

        # Header
        table.add_row(f"[bold {self.theme.get_color('primary')}]📥 IMPORT SCAN RESULTS[/]")
        table.add_row(self.theme.muted("Step 3/4: Select merge strategy"))
        table.add_row("")

        # Current profile stats (if available)
        if self.profile:
            existing_ports = len(self.profile.ports)
            existing_findings = len(self.profile.findings)
            table.add_row(f"{self.theme.primary('Current Profile:')} {existing_ports} ports, {existing_findings} findings")
            table.add_row("")

        # Merge strategy options
        table.add_row(f"[bold {self.theme.get_color('text')}]MERGE STRATEGIES:[/]")
        table.add_row("")

        strategies = [
            (self.MERGE_SMART, "Smart Merge (Recommended)", "Intelligently merge new data, deduplicate ports, preserve findings"),
            (self.MERGE_APPEND, "Append Only", "Add all new data, keep existing (may create duplicates)"),
            (self.MERGE_REPLACE, "Replace All", "Clear existing data, use imported data only")
        ]

        for strategy_id, label, description in strategies:
            selected = "✓ " if self.merge_strategy == strategy_id else "  "
            style = f"bold {self.theme.get_color('text')}" if self.merge_strategy == strategy_id else "white"
            table.add_row(f"[{style}]{selected}{label}[/]")
            table.add_row(f"  {self.theme.muted(description)}")
            table.add_row("")

        # Build action menu
        choices = []

        table.add_row(f"[bold {self.theme.get_color('text')}]Actions:[/]")
        table.add_row("")

        table.add_row(f"{format_menu_number(self.theme, '1')} Smart Merge (recommended)")
        choices.append({
            'id': 'smart',
            'label': 'Smart Merge',
            'action': 'select_strategy',
            'strategy': self.MERGE_SMART
        })

        table.add_row(f"{format_menu_number(self.theme, '2')} Append Only")
        choices.append({
            'id': 'append',
            'label': 'Append Only',
            'action': 'select_strategy',
            'strategy': self.MERGE_APPEND
        })

        table.add_row(f"{format_menu_number(self.theme, '3')} Replace All")
        choices.append({
            'id': 'replace',
            'label': 'Replace All',
            'action': 'select_strategy',
            'strategy': self.MERGE_REPLACE
        })

        table.add_row("")
        table.add_row(f"{format_hotkey(self.theme, 'n')} Next (confirm import)")
        choices.append({
            'id': 'next',
            'label': 'Next (confirm import)',
            'action': 'next_stage'
        })

        table.add_row("")
        table.add_row(f"{format_hotkey(self.theme, 'b')} Back (change file)")
        choices.append({
            'id': 'back',
            'label': 'Back (change file)',
            'action': 'prev_stage'
        })

        # Build panel
        breadcrumb = "Dashboard > Import Scan > Merge Strategy"
        title = f"[bold {self.theme.get_color('primary')}]{breadcrumb}[/]"
        subtitle = self.theme.muted("Step 3: Choose how to merge data")

        return Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style=self.theme.panel_border(),
            box=box.ROUNDED
        ), choices

    def _render_confirm_stage(self) -> Tuple[Panel, List[Dict]]:
        """
        Render confirmation stage

        Returns:
            Tuple of (Panel, choices)
        """
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Section", style="white", width=80)

        # Header
        table.add_row(f"[bold {self.theme.get_color('primary')}]📥 IMPORT SCAN RESULTS[/]")
        table.add_row(self.theme.muted("Step 4/4: Confirm import"))
        table.add_row("")

        # Import summary
        table.add_row(f"[bold {self.theme.get_color('text')}]IMPORT SUMMARY:[/]")
        table.add_row("")
        table.add_row(f"  {self.theme.primary('File:')} {self.file_path}")
        table.add_row(f"  {self.theme.primary('Type:')} {self.file_type}")
        table.add_row(f"  {self.theme.primary('Merge Strategy:')} {self._get_strategy_label(self.merge_strategy)}")
        table.add_row("")

        if self.parse_results:
            ports_count = len(self.parse_results.get('ports', []))
            target = self.parse_results.get('target', 'N/A')
            table.add_row(f"  {self.theme.primary('Target:')} {target}")
            table.add_row(f"  {self.theme.primary('Ports to Import:')} {ports_count}")

        table.add_row("")

        # Warning for replace strategy
        if self.merge_strategy == self.MERGE_REPLACE:
            table.add_row(f"[bold {self.theme.get_color('danger')}]⚠ WARNING:[/] This will delete all existing data!")
            table.add_row("")

        # Build action menu
        choices = []

        table.add_row(f"[bold {self.theme.get_color('text')}]Actions:[/]")
        table.add_row("")

        table.add_row(f"{format_hotkey(self.theme, 'c')} Confirm and Import")
        choices.append({
            'id': 'confirm',
            'label': 'Confirm and Import',
            'action': 'import'
        })

        table.add_row("")
        table.add_row(f"{format_hotkey(self.theme, 'b')} Back (change settings)")
        choices.append({
            'id': 'back',
            'label': 'Back (change settings)',
            'action': 'prev_stage'
        })

        table.add_row("")
        table.add_row(f"{format_hotkey(self.theme, 'x')} Cancel import")
        choices.append({
            'id': 'cancel',
            'label': 'Cancel import',
            'action': 'cancel'
        })

        # Build panel
        breadcrumb = "Dashboard > Import Scan > Confirm"
        title = f"[bold {self.theme.get_color('primary')}]{breadcrumb}[/]"
        subtitle = self.theme.muted("Step 4: Review and confirm")

        return Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style=self.theme.panel_border(),
            box=box.ROUNDED
        ), choices

    def _render_complete_stage(self) -> Tuple[Panel, List[Dict]]:
        """
        Render import complete stage

        Returns:
            Tuple of (Panel, choices)
        """
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Section", style="white", width=80)

        # Header
        if self.import_success:
            table.add_row(f"[bold {self.theme.get_color('success')}]✓ IMPORT COMPLETE[/]")
            table.add_row("")

            # Import summary
            if self.import_summary:
                table.add_row(f"[bold {self.theme.get_color('text')}]Import Summary:[/]")
                table.add_row("")
                table.add_row(f"  {self.theme.primary('Ports Added:')} {self.import_summary.get('ports_added', 0)}")
                table.add_row(f"  {self.theme.primary('Notes Added:')} {self.import_summary.get('notes_added', 0)}")
                table.add_row(f"  {self.theme.primary('Tasks Generated:')} {self.import_summary.get('tasks_generated', 'N/A')}")
        else:
            table.add_row(f"[bold {self.theme.get_color('danger')}]✗ IMPORT FAILED[/]")
            table.add_row("")
            if self.error_message:
                table.add_row(f"{self.theme.danger('Error:')} {self.error_message}")

        table.add_row("")

        # Build action menu
        choices = []

        table.add_row(f"[bold {self.theme.get_color('text')}]Actions:[/]")
        table.add_row("")

        table.add_row(f"{format_hotkey(self.theme, 'i')} Import another file")
        choices.append({
            'id': 'import-another',
            'label': 'Import another file',
            'action': 'reset'
        })

        table.add_row(f"{format_hotkey(self.theme, 'b')} Back to dashboard")
        choices.append({
            'id': 'back',
            'label': 'Back to dashboard',
            'action': 'back'
        })

        # Build panel
        breadcrumb = "Dashboard > Import Scan > Complete"
        title = f"[bold {self.theme.get_color('primary')}]{breadcrumb}[/]"
        subtitle = self.theme.muted("Import finished")

        return Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style=self.theme.panel_border(),
            box=box.ROUNDED
        ), choices

    # Stage progression methods

    def next_stage(self):
        """Move to next stage"""
        if self.stage == self.STAGE_FILE_PATH:
            # Validate file exists before proceeding
            if self.file_path and self._check_file_exists(self.file_path)['exists']:
                self.stage = self.STAGE_PREVIEW
                # Auto-detect and parse
                self._detect_and_parse()
            else:
                self.error_message = "Please select a valid file first"
        elif self.stage == self.STAGE_PREVIEW:
            if self.parse_results:
                self.stage = self.STAGE_MERGE_STRATEGY
            else:
                self.error_message = "Cannot proceed with parse errors"
        elif self.stage == self.STAGE_MERGE_STRATEGY:
            self.stage = self.STAGE_CONFIRM
        elif self.stage == self.STAGE_CONFIRM:
            # This shouldn't be called - use import_to_profile instead
            pass

    def prev_stage(self):
        """Move to previous stage"""
        if self.stage == self.STAGE_PREVIEW:
            self.stage = self.STAGE_FILE_PATH
            self.error_message = None
        elif self.stage == self.STAGE_MERGE_STRATEGY:
            self.stage = self.STAGE_PREVIEW
        elif self.stage == self.STAGE_CONFIRM:
            self.stage = self.STAGE_MERGE_STRATEGY

    # Form processing methods

    def set_file_path(self, file_path: str) -> bool:
        """
        Set file path and validate with InputValidator

        Args:
            file_path: Path to file

        Returns:
            True if file exists and is valid
        """
        # Expand user home directory
        expanded_path = os.path.expanduser(file_path)

        # Log validation attempt
        if self.debug_logger:
            self.debug_logger.debug(f"Validating file path: {expanded_path}")

        # Validate file path using InputValidator
        is_valid, error_msg = self.validator.validate_file_path(
            expanded_path,
            mode='r',
            must_exist=True
        )

        if is_valid:
            self.file_path = expanded_path
            self.error_message = None
            if self.debug_logger:
                self.debug_logger.info(f"✓ File path valid: {expanded_path}")
            return True
        else:
            # Validation failed - set inline error (no blocking popup)
            self.file_path = expanded_path
            self.error_message = error_msg
            if self.debug_logger:
                self.debug_logger.warning(f"✗ File validation failed: {error_msg}")
            return False

    def _detect_and_parse(self):
        """
        Auto-detect file type and parse

        Sets self.file_type and self.parse_results
        """
        if not self.file_path:
            self.error_message = "No file path set"
            return

        try:
            # Import parser registry
            from crack.track.parsers.registry import ParserRegistry

            if self.debug_logger:
                self.debug_logger.info(f"Detecting file type: {self.file_path}")

            # Get appropriate parser
            parser = ParserRegistry.get_parser(self.file_path)

            if not parser:
                # Set inline error (no blocking popup - user sees it in form)
                error_msg = "Unsupported file format (expected Nmap XML or greppable)"
                self.error_message = error_msg
                self.file_type = "Unknown"
                if self.debug_logger:
                    self.debug_logger.warning(f"✗ Format detection failed: {error_msg}")
                return

            # Set file type
            self.file_type = parser.name
            if self.debug_logger:
                self.debug_logger.info(f"✓ Detected format: {parser.name}")
                self.debug_logger.info(f"Parsing file...")

            # Parse file
            target_hint = self.profile.target if self.profile else None
            self.parse_results = parser.parse(self.file_path, target=target_hint)

            self.error_message = None

            # Log parse results
            if self.debug_logger and self.parse_results:
                ports_count = len(self.parse_results.get('ports', []))
                target = self.parse_results.get('target', 'N/A')
                self.debug_logger.info(f"✓ Parse successful: {ports_count} ports found for {target}")

        except Exception as e:
            # Set inline error (no blocking popup - user sees it in form)
            error_msg = f"Parse error: {str(e)}"
            self.error_message = error_msg
            self.parse_results = None
            if self.debug_logger:
                self.debug_logger.error(f"✗ Parse exception: {str(e)}")

    def validate(self) -> bool:
        """
        Validate form is ready for import

        Returns:
            True if all stages are complete and valid
        """
        if not self.file_path:
            self.error_message = "No file selected"
            return False

        if not self._check_file_exists(self.file_path)['exists']:
            self.error_message = "File does not exist"
            return False

        if not self.parse_results:
            self.error_message = "File not parsed successfully"
            return False

        if not self.merge_strategy:
            self.error_message = "No merge strategy selected"
            return False

        return True

    def import_to_profile(self, profile) -> bool:
        """
        Execute import with selected merge strategy

        Args:
            profile: TargetProfile to import into

        Returns:
            True if import successful
        """
        if not self.validate():
            return False

        try:
            # Import parser registry
            from crack.track.parsers.registry import ParserRegistry

            # Track what we're adding
            ports_before = len(profile.ports)
            notes_before = len(profile.notes)

            # Handle merge strategy
            if self.merge_strategy == self.MERGE_REPLACE:
                # Clear existing data
                profile.ports = []
                profile.findings = []
                profile.credentials = []
                profile.notes = []
                profile.task_tree.root.children = []

            # Use ParserRegistry to import (handles events and task generation)
            ParserRegistry.parse_file(self.file_path, target=profile.target, profile=profile)

            # Calculate what was added
            ports_added = len(profile.ports) - ports_before
            notes_added = len(profile.notes) - notes_before

            # Get pending tasks count
            tasks_generated = len(profile.task_tree.get_all_pending())

            # Save profile
            profile.save()

            # Mark success
            self.import_success = True
            self.import_summary = {
                'ports_added': ports_added,
                'notes_added': notes_added,
                'tasks_generated': tasks_generated
            }

            # Move to complete stage
            self.stage = self.STAGE_COMPLETE

            return True

        except Exception as e:
            self.import_success = False
            self.error_message = f"Import failed: {str(e)}"
            self.stage = self.STAGE_COMPLETE
            return False

    # Helper methods

    def _check_file_exists(self, file_path: str) -> Dict[str, Any]:
        """
        Check if file exists and get metadata

        Args:
            file_path: Path to file

        Returns:
            Dict with exists, size, formatted_size
        """
        if not file_path:
            return {'exists': False, 'size': 0, 'formatted_size': 'N/A'}

        path = Path(file_path)

        if path.exists() and path.is_file():
            size = path.stat().st_size
            return {
                'exists': True,
                'size': size,
                'formatted_size': self._format_file_size(size)
            }
        else:
            return {'exists': False, 'size': 0, 'formatted_size': 'N/A'}

    def _format_file_size(self, size_bytes: int) -> str:
        """
        Format file size in human-readable format

        Args:
            size_bytes: File size in bytes

        Returns:
            Formatted string (e.g., "1.5 KB", "2.3 MB")
        """
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"

    def _get_strategy_label(self, strategy: str) -> str:
        """
        Get display label for merge strategy

        Args:
            strategy: Strategy ID

        Returns:
            Display label
        """
        labels = {
            self.MERGE_SMART: "Smart Merge",
            self.MERGE_APPEND: "Append Only",
            self.MERGE_REPLACE: "Replace All"
        }
        return labels.get(strategy, "Unknown")

    # Input processing helper

    def process_input(self, key: str) -> str:
        """
        Process user input for form navigation

        Args:
            key: User input key/choice

        Returns:
            Action code ('continue', 'back', 'next', 'import')
        """
        # This method provides a simple interface for TUI integration
        # The actual routing should be handled by the session using the choices list
        # This is just a convenience method for standalone testing
        pass
