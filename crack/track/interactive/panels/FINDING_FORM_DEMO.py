#!/usr/bin/env python3
"""
Finding Entry Form Panel - Demonstration Script

This script demonstrates how to use the FindingFormPanel standalone.
For integration into the TUI, see the integration examples below.

Usage:
    python track/interactive/panels/FINDING_FORM_DEMO.py
"""

from crack.track.core.state import TargetProfile
from crack.track.interactive.panels.finding_form import FindingFormPanel
from crack.track.interactive.themes import ThemeManager
from rich.console import Console


def demo_basic_usage():
    """Demonstrate basic form usage"""
    console = Console()

    # Create or load profile
    profile = TargetProfile('192.168.1.100')
    theme = ThemeManager()

    # Create form instance
    form = FindingFormPanel.create(profile, theme)

    # Render panel (returns Panel and choices)
    panel, choices = form.render()

    # Display panel
    console.print(panel)

    # Show available choices
    console.print("\n[cyan]Available choices:[/]")
    for choice in choices:
        console.print(f"  {choice['id']}: {choice['label']}")


def demo_field_editing():
    """Demonstrate field editing workflow"""
    console = Console()

    # Create profile and form
    profile = TargetProfile('192.168.1.100')
    theme = ThemeManager()
    form = FindingFormPanel.create(profile, theme)

    # Simulate user filling out form
    console.print("[cyan]Simulating form entry...[/]\n")

    # Field 0: Type
    form.current_field = 0
    form.edit_current_field('vulnerability')
    console.print(f"✓ Type: {form.form_data['type']}")

    # Field 1: Description
    form.current_field = 1
    form.edit_current_field('SQL injection in login form parameter')
    console.print(f"✓ Description: {form.form_data['description']}")

    # Field 2: Source (REQUIRED)
    form.current_field = 2
    form.edit_current_field('sqlmap --batch --dump')
    console.print(f"✓ Source: {form.form_data['source']}")

    # Field 3: Port (optional)
    form.current_field = 3
    form.edit_current_field('443')
    console.print(f"✓ Port: {form.form_data['port']}")

    # Field 4: Severity (optional)
    form.current_field = 4
    form.edit_current_field('high')
    console.print(f"✓ Severity: {form.form_data['severity']}")

    # Field 5: Impact (optional)
    form.current_field = 5
    form.edit_current_field('Database compromise, credential extraction')
    console.print(f"✓ Impact: {form.form_data['impact']}")

    # Validate
    console.print("\n[cyan]Validating form...[/]")
    if form.validate():
        console.print("[green]✓ Validation passed![/]")
    else:
        console.print("[red]✗ Validation failed:[/]")
        for field, error in form.validation_errors.items():
            console.print(f"  {field}: {error}")

    # Save to profile
    console.print("\n[cyan]Saving to profile...[/]")
    if form.save_to_profile():
        console.print("[green]✓ Finding saved successfully![/]")
        console.print(f"\nTotal findings in profile: {len(profile.findings)}")
        console.print(f"Latest finding: {profile.findings[-1]}")
    else:
        console.print("[red]✗ Save failed[/]")


def demo_type_selector():
    """Demonstrate type selection dropdown"""
    console = Console()
    theme = ThemeManager()

    # Render type selector
    panel, choices = FindingFormPanel.render_type_selector(theme=theme)

    console.print(panel)

    console.print("\n[cyan]Type selector choices:[/]")
    for choice in choices[:6]:  # Show first 6
        console.print(f"  {choice['id']}: {choice.get('type', 'N/A')}")


def demo_severity_selector():
    """Demonstrate severity selection dropdown"""
    console = Console()
    theme = ThemeManager()

    # Render severity selector with current selection
    panel, choices = FindingFormPanel.render_severity_selector('high', theme=theme)

    console.print(panel)

    console.print("\n[cyan]Severity selector choices:[/]")
    for choice in choices[:5]:  # Show severities
        console.print(f"  {choice['id']}: {choice.get('severity', 'N/A')}")


def demo_validation_errors():
    """Demonstrate validation error handling"""
    console = Console()

    profile = TargetProfile('192.168.1.100')
    theme = ThemeManager()
    form = FindingFormPanel.create(profile, theme)

    # Try to save without filling required fields
    console.print("[cyan]Attempting to save empty form...[/]\n")

    if not form.save_to_profile():
        console.print("[yellow]Save blocked by validation:[/]")
        for field, error in form.validation_errors.items():
            console.print(f"  [red]✗[/] {field}: {error}")

    # Render form with errors
    console.print("\n[cyan]Form with validation errors:[/]\n")
    panel, choices = form.render()
    console.print(panel)


def demo_integration_example():
    """Show TUI integration pattern"""
    console = Console()

    console.print("""
[bold cyan]TUI Integration Pattern[/]

[white]# In TUISessionV2 class:[/]

[dim]def _finding_form_loop(self):
    '''Finding entry form panel loop'''
    form = FindingFormPanel.create(self.profile, self.theme)

    while True:
        # Render panel
        panel, choices = form.render()
        self.layout['menu'].update(panel)

        # Get user input
        self._live.stop()
        choice = input("Choice: ").strip()
        self._live.start()

        # Process input
        action = form.process_input(choice)

        if action == 'edit-field':
            # Get field info
            field_info = form.get_current_field_info()

            # Stop live for input
            self._live.stop()

            if field_info['type'] == 'dropdown':
                # Show dropdown selector
                if field_info['field_name'] == 'type':
                    panel, choices = FindingFormPanel.render_type_selector(theme=self.theme)
                    # ... handle selection
                elif field_info['field_name'] == 'severity':
                    panel, choices = FindingFormPanel.render_severity_selector(theme=self.theme)
                    # ... handle selection
            else:
                # Text/numeric input
                new_value = input(f"{field_info['label']}: ").strip()
                form.edit_current_field(new_value)

            self._live.start()

        elif action == 'save':
            self._live.stop()
            if form.save_to_profile():
                print("✓ Finding saved!")
                input("Press Enter to continue...")
            else:
                print("✗ Validation failed")
                input("Press Enter to continue...")
            self._live.start()

        elif action == 'back':
            return  # Back to hub

        elif action == 'continue':
            continue  # Re-render[/]
    """)


if __name__ == '__main__':
    console = Console()

    console.print("\n[bold cyan]═══ Finding Entry Form Panel Demo ═══[/]\n")

    demos = [
        ("1. Basic Usage", demo_basic_usage),
        ("2. Field Editing Workflow", demo_field_editing),
        ("3. Type Selector", demo_type_selector),
        ("4. Severity Selector", demo_severity_selector),
        ("5. Validation Errors", demo_validation_errors),
        ("6. TUI Integration Pattern", demo_integration_example)
    ]

    for idx, (title, demo_func) in enumerate(demos, 1):
        console.print(f"\n[bold white]{title}[/]")
        console.print("─" * 60)

        try:
            demo_func()
        except Exception as e:
            console.print(f"[red]Error in demo: {e}[/]")

        if idx < len(demos):
            console.print("\n")

    console.print("\n[bold green]✓ Demo complete![/]\n")
