"""
Console Injection - Vim-style :! command execution

Allows quick ad-hoc command execution without task tracking overhead.
Triggered by ':!' from any panel.

Features:
- Direct shell execution
- Output capture and display
- Optional save to context
- Quick iteration testing

Usage:
    :! curl -I http://target
    :! nc -nv 192.168.45.100 80
    :! cat /etc/passwd
"""

import subprocess
import time
from typing import Optional, Tuple, List
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box


class ConsoleInjection:
    """Vim-style :! command execution"""

    @classmethod
    def execute(
        cls,
        console: Console,
        command: str,
        profile: 'TargetProfile' = None
    ) -> Optional[Tuple[List[str], int, float]]:
        """
        Execute command and display results

        Args:
            console: Rich Console instance
            command: Command to execute (without :! prefix)
            profile: Optional TargetProfile for context saving

        Returns:
            Tuple of (output_lines, exit_code, duration) or None if execution failed
        """
        if not command or not command.strip():
            console.print("[yellow]No command specified[/]")
            return None

        # Clean command
        command = command.strip()

        # Display execution banner
        console.print()
        console.print("=" * 80, style="dim")
        console.print(f"[bold cyan]Console Injection[/] [dim](:! mode)[/]")
        console.print(f"[white]>[/] [cyan]{command}[/]")
        console.print("=" * 80, style="dim")
        console.print()

        # Execute command
        output_lines, exit_code, duration = cls._execute_command(command)

        # Display output
        if output_lines:
            for line in output_lines:
                console.print(line)
        else:
            console.print("[dim](no output)[/]", style="dim")

        # Display footer
        console.print()
        console.print("=" * 80, style="dim")

        # Status with color
        if exit_code == 0:
            status_text = f"[green]✓ Success[/]"
        else:
            status_text = f"[red]✗ Failed (exit code: {exit_code})[/]"

        console.print(f"{status_text} | [cyan]Duration: {duration:.2f}s[/] | [white]Lines: {len(output_lines)}[/]")

        # Offer to save to context (if profile provided)
        if profile and len(output_lines) > 0:
            console.print()
            response = input("Save to output history? [y/N]: ").strip().lower()

            if response == 'y':
                # Find or create a general task for console injection commands
                task = cls._get_or_create_injection_task(profile)

                # Save execution to task history
                task.add_execution(
                    command=command,
                    output_lines=output_lines,
                    exit_code=exit_code,
                    duration=duration,
                    context_label=f"console-injection-{int(time.time())}"
                )

                # Save profile
                profile.save()

                console.print("[green]✓ Saved to output history[/]")
                console.print(f"[dim]View with 'o' (Output overlay)[/]")

        console.print("=" * 80, style="dim")
        console.print()
        console.print("[dim]Press Enter to continue...[/]", end="")
        input()

        return (output_lines, exit_code, duration)

    @classmethod
    def _execute_command(cls, command: str) -> Tuple[List[str], int, float]:
        """
        Execute shell command and capture output

        Args:
            command: Shell command to execute

        Returns:
            Tuple of (output_lines, exit_code, duration)
        """
        start_time = time.time()
        output_lines = []
        exit_code = 1

        try:
            # Execute with shell
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Combine stderr with stdout
                text=True,
                timeout=60  # 60 second timeout
            )

            # Capture output
            if result.stdout:
                output_lines = result.stdout.strip().split('\n')

            exit_code = result.returncode

        except subprocess.TimeoutExpired:
            output_lines = ["[ERROR] Command timed out after 60 seconds"]
            exit_code = 124

        except Exception as e:
            output_lines = [f"[ERROR] Execution failed: {str(e)}"]
            exit_code = 1

        duration = time.time() - start_time

        return (output_lines, exit_code, duration)

    @classmethod
    def _get_or_create_injection_task(cls, profile: 'TargetProfile') -> 'TaskNode':
        """
        Get or create a special task for console injection commands

        Args:
            profile: TargetProfile instance

        Returns:
            TaskNode for console injection commands
        """
        # Look for existing task
        task = profile.get_task('console-injection')

        if not task:
            # Create new task for console injections
            from ..core.task_tree import TaskNode

            task = TaskNode(
                task_id='console-injection',
                name='Console Injection Commands',
                task_type='manual'
            )

            task.metadata['description'] = 'Ad-hoc commands executed via :! console injection'
            task.metadata['command'] = None  # No fixed command
            task.status = 'completed'  # Always marked complete (not a real task)

            # Add to profile
            profile.task_tree.add_child(task)

        return task
