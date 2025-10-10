"""
Quick Note Form Panel - Fast note-taking during enumeration

Minimal form designed for speed:
- Single multi-line text input
- Auto-timestamp (ISO 8601)
- Optional tag selection (idea, todo, warning, success, info)
- Auto-save to TargetProfile.notes

Follows hub-spoke navigation - this is a spoke panel.
"""

from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box


class NoteFormPanel:
    """Quick note form for fast enumeration notes"""

    # Available note tags
    NOTE_TAGS = {
        '1': ('idea', '💡', 'bright_cyan'),
        '2': ('todo', '✓', 'yellow'),
        '3': ('warning', '⚠', 'bright_red'),
        '4': ('success', '✓', 'bright_green'),
        '5': ('info', 'ℹ', 'bright_blue')
    }

    @classmethod
    def render(
        cls,
        profile,  # TargetProfile instance
        note_text: Optional[str] = None,
        selected_tag: Optional[str] = None
    ) -> Tuple[Panel, List[Dict]]:
        """
        Render quick note form panel

        Args:
            profile: TargetProfile instance
            note_text: Current note text (for preview during tag selection)
            selected_tag: Selected tag (idea, todo, warning, success, info)

        Returns:
            Tuple of (Panel, action choices list)
        """
        # Build main table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Section", style="white", width=80)

        # Header
        table.add_row("[bold bright_cyan]📝 QUICK NOTE[/]")
        table.add_row("[dim]Fast note-taking during enumeration[/]")
        table.add_row("")

        # Show current state
        if note_text:
            # Show note preview
            preview = cls._truncate(note_text, 70)
            table.add_row(f"[cyan]Note:[/] {preview}")

            if selected_tag:
                tag_name, icon, color = cls._get_tag_display(selected_tag)
                table.add_row(f"[cyan]Tag:[/] [{color}]{icon} {tag_name.upper()}[/]")
            else:
                table.add_row(f"[cyan]Tag:[/] [dim]None (optional)[/]")

            table.add_row("")
            table.add_row("[bold bright_green]✓ Note ready to save[/]")
        else:
            # Initial instructions
            table.add_row("[dim]Enter your note text when prompted.[/]")
            table.add_row("[dim]Supports multi-line input (Ctrl+D or empty line to finish)[/]")

        table.add_row("")

        # Build action menu
        choices = cls._build_action_menu(table, note_text, selected_tag)

        # Build breadcrumb
        breadcrumb = "Dashboard > Quick Note"

        # Build panel
        panel = Panel(
            table,
            title=f"[bold cyan]{breadcrumb}[/]",
            subtitle=f"[dim]Target: {profile.target} | Auto-timestamped notes[/]",
            border_style="cyan",
            box=box.ROUNDED
        )

        return panel, choices

    @classmethod
    def _build_action_menu(
        cls,
        table: Table,
        note_text: Optional[str],
        selected_tag: Optional[str]
    ) -> List[Dict]:
        """
        Build context-aware action menu

        Args:
            table: Table to add menu items to
            note_text: Current note text
            selected_tag: Selected tag

        Returns:
            List of choice dictionaries
        """
        choices = []

        # If no note text yet, show entry option
        if not note_text:
            table.add_row("[bold bright_white]1.[/] Enter note text")
            choices.append({
                'id': 'enter',
                'label': 'Enter note text',
                'action': 'enter_text'
            })

        # If note exists, show save/tag/edit options
        else:
            table.add_row("[bold bright_white]1.[/] Save note (with current tag)")
            choices.append({
                'id': 'save',
                'label': 'Save note',
                'action': 'save_note',
                'note_text': note_text,
                'tag': selected_tag
            })

            table.add_row("[bold bright_white]2.[/] Select tag (optional)")
            choices.append({
                'id': 'tag',
                'label': 'Select tag',
                'action': 'select_tag'
            })

            table.add_row("[bold bright_white]3.[/] Edit note text")
            choices.append({
                'id': 'edit',
                'label': 'Edit note text',
                'action': 'enter_text'
            })

        # Always show back option
        table.add_row("")
        table.add_row("[bold bright_white]b.[/] Back to dashboard (discard)")
        choices.append({
            'id': 'b',
            'label': 'Back to dashboard',
            'action': 'back'
        })

        return choices

    @classmethod
    def render_tag_selector(cls) -> Tuple[Panel, List[Dict]]:
        """
        Render tag selection panel

        Returns:
            Tuple of (Panel, tag choices list)
        """
        # Build tag table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Section", style="white", width=80)

        table.add_row("[bold bright_cyan]🏷 SELECT TAG[/]")
        table.add_row("")

        # Build choices
        choices = []

        # Add tag options
        for key, (tag_name, icon, color) in cls.NOTE_TAGS.items():
            table.add_row(f"[bold bright_white]{key}.[/] [{color}]{icon} {tag_name.upper()}[/]")
            choices.append({
                'id': key,
                'label': f'{tag_name.upper()}',
                'action': 'tag_selected',
                'tag': tag_name
            })

        # No tag option
        table.add_row("")
        table.add_row("[bold bright_white]n.[/] No tag (skip)")
        choices.append({
            'id': 'n',
            'label': 'No tag',
            'action': 'tag_selected',
            'tag': None
        })

        # Back option
        table.add_row("")
        table.add_row("[bold bright_white]b.[/] Back")
        choices.append({
            'id': 'b',
            'label': 'Back',
            'action': 'back'
        })

        # Build panel
        panel = Panel(
            table,
            title="[bold cyan]Quick Note > Select Tag[/]",
            subtitle="[dim]Optional: Add context to your note[/]",
            border_style="cyan",
            box=box.ROUNDED
        )

        return panel, choices

    @classmethod
    def save_note_to_profile(
        cls,
        profile,
        note_text: str,
        tag: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Save note to TargetProfile with auto-timestamp

        Args:
            profile: TargetProfile instance
            note_text: Note text content
            tag: Optional tag (idea, todo, warning, success, info)

        Returns:
            The saved note dictionary
        """
        # Build note entry
        note_entry = {
            'timestamp': datetime.now().isoformat(),
            'note': note_text.strip(),
            'type': 'quick_note'  # Distinguish from other note types
        }

        # Add tag if provided
        if tag:
            note_entry['tag'] = tag

        # Add to profile
        profile.notes.append(note_entry)

        # Update profile timestamp
        profile._update_timestamp()

        # Save to disk
        profile.save()

        return note_entry

    @classmethod
    def _get_tag_display(cls, tag: str) -> Tuple[str, str, str]:
        """
        Get display info for tag

        Args:
            tag: Tag name

        Returns:
            Tuple of (tag_name, icon, color)
        """
        # Find matching tag
        for key, (tag_name, icon, color) in cls.NOTE_TAGS.items():
            if tag_name == tag:
                return (tag_name, icon, color)

        # Default if not found
        return (tag, '•', 'white')

    @classmethod
    def _truncate(cls, text: str, max_len: int) -> str:
        """
        Truncate long text with ellipsis

        Args:
            text: Text to truncate
            max_len: Maximum length

        Returns:
            Truncated text
        """
        # Handle multi-line text - show first line only
        first_line = text.split('\n')[0]

        if len(first_line) <= max_len:
            return first_line
        return first_line[:max_len-3] + "..."

    @classmethod
    def prompt_for_note_text(cls, console) -> Optional[str]:
        """
        Prompt user for multi-line note text

        Args:
            console: Rich Console instance for output

        Returns:
            Note text or None if cancelled
        """
        console.print("\n[cyan]Enter note text:[/]")
        console.print("[dim](Multi-line supported - press Ctrl+D or enter empty line twice to finish)[/]")
        console.print("[dim]> [/]", end="")

        lines = []
        empty_count = 0

        try:
            while True:
                line = input()

                # Check for empty line (finish trigger)
                if not line.strip():
                    empty_count += 1
                    # Two consecutive empty lines = done
                    if empty_count >= 2:
                        break
                    # Single empty line = add blank line to note
                    lines.append(line)
                else:
                    empty_count = 0
                    lines.append(line)

                # Visual continuation indicator
                console.print("[dim]> [/]", end="")

        except EOFError:
            # Ctrl+D pressed - finish input
            pass
        except KeyboardInterrupt:
            # Ctrl+C pressed - cancel
            console.print("\n[yellow]Cancelled[/]")
            return None

        # Join lines and strip trailing empty lines
        note_text = '\n'.join(lines).rstrip()

        if not note_text.strip():
            console.print("[yellow]Empty note - cancelled[/]")
            return None

        return note_text
