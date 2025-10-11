"""
Output Overlay - Full-screen command output viewer with context cycling

Features:
- View complete command output (no line limits)
- Cycle between multiple execution contexts
- Search within output (vim-style /)
- Export to file
- Scrollable with keyboard navigation

Usage:
    Press 'o' from any panel to open output overlay
    Navigate between contexts with n/p
    Search with /pattern
    Export with e
"""

from typing import List, Dict, Any, Optional, Tuple
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box


class OutputOverlay:
    """Full-screen output viewer with context management"""

    @classmethod
    def render_and_navigate(
        cls,
        console: Console,
        profile: 'TargetProfile',
        initial_task_id: str = None,
        theme=None
    ):
        """
        Interactive output viewer with navigation

        Args:
            console: Rich Console instance
            profile: TargetProfile with task execution history
            initial_task_id: Optional task ID to start with
            theme: ThemeManager instance (optional for backward compat)

        Controls:
            n/p: Next/Previous context
            j/k or ↑/↓: Scroll output
            g/G: Top/Bottom
            /: Search (not yet implemented)
            e: Export to file (not yet implemented)
            q: Close overlay
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Collect all execution contexts from all tasks
        contexts = cls._collect_contexts(profile)

        if not contexts:
            console.print(theme.warning("No execution history available"))
            console.print(theme.muted("Execute tasks to build output history"))
            input("\nPress Enter to continue...")
            return

        # Find initial context index
        current_index = 0
        if initial_task_id:
            for i, ctx in enumerate(contexts):
                if ctx['task_id'] == initial_task_id:
                    current_index = i
                    break

        # State for scrolling
        scroll_offset = 0
        display_lines = 40  # Lines to show at once (terminal height - header/footer)

        running = True
        while running:
            # Get current context
            context = contexts[current_index]

            # Render overlay
            overlay_panel = cls._render_context(
                context,
                current_index + 1,
                len(contexts),
                scroll_offset,
                display_lines,
                theme=theme
            )

            # Clear screen and display
            console.clear()
            console.print(overlay_panel)

            # Show controls
            hotkey_color = theme.get_component_color('hotkey')
            controls = (
                f"[{hotkey_color}]n[/]:Next Context | [{hotkey_color}]p[/]:Prev | "
                f"[{hotkey_color}]j/k[/]:Scroll | [{hotkey_color}]g/G[/]:Top/Bottom | "
                f"[{hotkey_color}]e[/]:Export | [{hotkey_color}]q[/]:Close"
            )
            console.print(f"\n{controls}")

            # Get user input
            console.print("\n" + theme.muted("Command: "), end="")
            try:
                user_input = input().strip().lower()
            except (EOFError, KeyboardInterrupt):
                break

            # Process commands
            if user_input == 'q':
                running = False

            elif user_input == 'n':
                # Next context
                current_index = (current_index + 1) % len(contexts)
                scroll_offset = 0  # Reset scroll

            elif user_input == 'p':
                # Previous context
                current_index = (current_index - 1) % len(contexts)
                scroll_offset = 0  # Reset scroll

            elif user_input == 'j':
                # Scroll down
                max_offset = max(0, len(context['output_lines']) - display_lines)
                scroll_offset = min(scroll_offset + 5, max_offset)

            elif user_input == 'k':
                # Scroll up
                scroll_offset = max(0, scroll_offset - 5)

            elif user_input == 'g':
                # Go to top
                scroll_offset = 0

            elif user_input.upper() == 'G':
                # Go to bottom
                max_offset = max(0, len(context['output_lines']) - display_lines)
                scroll_offset = max_offset

            elif user_input == 'e':
                # Export context to file
                cls._export_context(console, context, theme=theme)

            elif user_input.startswith('/'):
                # Search (future feature)
                console.print(theme.warning("Search not yet implemented"))
                input("Press Enter...")

    @classmethod
    def _collect_contexts(cls, profile: 'TargetProfile') -> List[Dict[str, Any]]:
        """
        Collect all execution contexts from profile

        Args:
            profile: TargetProfile instance

        Returns:
            List of context dictionaries sorted by timestamp (most recent first)
        """
        contexts = []

        # Get all tasks
        all_tasks = profile.task_tree.get_all_tasks()

        for task in all_tasks:
            # Get execution history for this task
            executions = task.get_execution_history()

            for execution in executions:
                context = {
                    'task_id': task.id,
                    'task_name': task.name,
                    'context_label': execution['context_label'],
                    'timestamp': execution['timestamp'],
                    'command': execution['command'],
                    'output_lines': execution['output_lines'],
                    'exit_code': execution['exit_code'],
                    'duration': execution['duration'],
                    'output_line_count': execution['output_line_count']
                }
                contexts.append(context)

        # Sort by timestamp (most recent first)
        contexts.sort(key=lambda x: x['timestamp'], reverse=True)

        return contexts

    @classmethod
    def _render_context(
        cls,
        context: Dict[str, Any],
        context_num: int,
        total_contexts: int,
        scroll_offset: int,
        display_lines: int,
        theme=None
    ) -> Panel:
        """
        Render a single context for display

        Args:
            context: Context dictionary
            context_num: Current context number (1-indexed)
            total_contexts: Total number of contexts
            scroll_offset: Current scroll position
            display_lines: Number of lines to display
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Rich Panel with context information and output
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Build header table
        header = Table(show_header=False, box=None, padding=(0, 1))
        label_color = theme.get_color('primary')
        text_color = theme.get_color('text')
        header.add_column("Label", style=f"bold {label_color}", width=15)
        header.add_column("Value", style=text_color)

        header.add_row("Context", f"{context_num}/{total_contexts}: {context['context_label']}")
        header.add_row("Task", context['task_name'][:60])
        header.add_row("Command", context['command'][:80] + "..." if len(context['command']) > 80 else context['command'])
        header.add_row("Timestamp", context['timestamp'][:19])  # Strip microseconds
        header.add_row("Duration", f"{context['duration']:.2f}s")

        # Exit code with color
        exit_code = context['exit_code']
        exit_color = theme.get_color('success') if exit_code == 0 else theme.get_color('danger')
        header.add_row("Exit Code", f"[{exit_color}]{exit_code}[/]")

        # Output stats
        total_lines = len(context['output_lines'])
        header.add_row("Output Lines", f"{total_lines} lines")

        # Get output slice for current scroll position
        start_line = scroll_offset
        end_line = min(scroll_offset + display_lines, total_lines)
        output_slice = context['output_lines'][start_line:end_line]

        # Build output text
        output_text = Text()
        muted_color = theme.get_color('muted')
        output_text.append("\n" + "─" * 80 + "\n", style=muted_color)

        if not output_slice:
            output_text.append("[No output]\n", style=muted_color)
        else:
            for i, line in enumerate(output_slice):
                line_num = start_line + i + 1
                # Show line numbers in muted style
                output_text.append(f"{line_num:5d} │ ", style=muted_color)
                output_text.append(line + "\n")

        output_text.append("\n" + "─" * 80 + "\n", style=muted_color)

        # Scroll indicator
        if total_lines > display_lines:
            percent = int((scroll_offset / (total_lines - display_lines)) * 100) if total_lines > display_lines else 0
            scroll_info = f"[Lines {start_line + 1}-{end_line} of {total_lines}] {percent}%"
        else:
            scroll_info = f"[All {total_lines} lines shown]"

        info_color = theme.get_color('info')
        output_text.append(scroll_info, style=f"{info_color} {muted_color}")

        # Combine header and output using Group (allows mixed renderable types)
        full_content = Group(
            header,
            Text("\n"),
            output_text
        )

        # Create panel
        title = f"[bold {theme.get_color('info')}]Command Output Viewer[/]"
        return Panel(
            full_content,
            title=title,
            border_style=theme.overlay_border(),
            box=box.DOUBLE
        )

    @classmethod
    def _export_context(cls, console: Console, context: Dict[str, Any], theme=None):
        """
        Export context to file

        Args:
            console: Rich Console instance
            context: Context to export
            theme: ThemeManager instance (optional for backward compat)
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        import os
        from datetime import datetime

        # Generate filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_label = context['context_label'].replace('/', '_').replace(' ', '_')
        filename = f"output_{safe_label}_{timestamp}.txt"

        # Get user confirmation
        console.print("\n" + theme.primary(f"Export to: {filename}"))
        response = input("Confirm? [Y/n]: ").strip().lower()

        if response and response != 'y':
            console.print(theme.muted("Export cancelled"))
            input("Press Enter...")
            return

        # Write to file
        try:
            export_path = os.path.expanduser(f"~/.crack/{filename}")

            with open(export_path, 'w') as f:
                # Write header
                f.write("=" * 80 + "\n")
                f.write(f"Context: {context['context_label']}\n")
                f.write(f"Task: {context['task_name']}\n")
                f.write(f"Command: {context['command']}\n")
                f.write(f"Timestamp: {context['timestamp']}\n")
                f.write(f"Duration: {context['duration']:.2f}s\n")
                f.write(f"Exit Code: {context['exit_code']}\n")
                f.write("=" * 80 + "\n\n")

                # Write output
                for i, line in enumerate(context['output_lines'], 1):
                    f.write(f"{i:5d} │ {line}\n")

                f.write("\n" + "=" * 80 + "\n")
                f.write(f"Total Lines: {len(context['output_lines'])}\n")

            console.print(theme.success(f"✓ Exported to: {export_path}"))
            input("\nPress Enter...")

        except Exception as e:
            console.print(theme.danger(f"✗ Export failed: {str(e)}"))
            input("\nPress Enter...")
