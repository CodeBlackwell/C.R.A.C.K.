#!/usr/bin/env python3
"""
Quick test script for command editor TUI integration
"""

from track.interactive.components.command_editor.tui_integration import CommandEditorTUI
from rich.console import Console

def test_quick_editor():
    """Test QuickEditor with a gobuster command"""
    console = Console()

    console.print("\n[cyan]Testing Command Editor TUI Integration[/cyan]\n")

    # Test command
    command = "gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt"
    metadata = {'tool': 'gobuster'}

    console.print(f"[yellow]Original command:[/yellow] {command}\n")

    # Create editor
    editor = CommandEditorTUI(
        command=command,
        metadata=metadata,
        console=console
    )

    # Run editor (will prompt for user input)
    result = editor.edit()

    if result:
        console.print(f"\n[green]Result:[/green]")
        console.print(f"  Action: {result.action}")
        console.print(f"  Command: {result.command}")
    else:
        console.print("\n[yellow]Cancelled[/yellow]")

if __name__ == "__main__":
    test_quick_editor()
