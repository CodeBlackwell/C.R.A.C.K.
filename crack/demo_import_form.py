#!/usr/bin/env python3
"""
Standalone demonstration of Import Form Panel

This shows how to use the ImportForm panel independently
of the main TUI session.
"""

from crack.track.interactive.panels.import_form import ImportForm
from crack.track.core.state import TargetProfile
from rich.console import Console
import sys
import tempfile
from pathlib import Path

console = Console()


def create_sample_nmap_xml(path: str):
    """Create a sample Nmap XML for testing"""
    xml_content = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC 192.168.45.100" start="1234567890" version="7.94">
    <host>
        <address addr="192.168.45.100" addrtype="ipv4"/>
        <hostnames>
            <hostname name="oscp-target.local" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open" reason="syn-ack"/>
                <service name="http" product="Apache httpd" version="2.4.41 ((Ubuntu))"/>
            </port>
            <port protocol="tcp" portid="22">
                <state state="open" reason="syn-ack"/>
                <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.1"/>
            </port>
            <port protocol="tcp" portid="445">
                <state state="open" reason="syn-ack"/>
                <service name="microsoft-ds" product="Samba smbd" version="4.11.6-Ubuntu"/>
            </port>
        </ports>
    </host>
</nmaprun>"""

    Path(path).write_text(xml_content)
    console.print(f"[green]Created sample Nmap XML at:[/] {path}")


def demo_basic_usage():
    """Demonstrate basic Import Form usage"""
    console.rule("[bold cyan]Import Form - Basic Usage Demo")
    console.print()

    # Create a target profile
    profile = TargetProfile(target="192.168.45.100")
    console.print(f"[cyan]Created profile for target:[/] {profile.target}")
    console.print()

    # Create sample XML file
    with tempfile.TemporaryDirectory() as tmpdir:
        xml_file = Path(tmpdir) / "nmap.xml"
        create_sample_nmap_xml(str(xml_file))
        console.print()

        # Initialize import form
        form = ImportForm(profile=profile)
        console.print("[green]✓ Import form initialized[/]")
        console.print()

        # Stage 1: File path selection
        console.rule("[cyan]Stage 1: File Path")
        panel, choices = form.render()
        console.print(panel)
        console.print(f"[dim]Available choices: {len(choices)}[/]")
        console.print()

        # Set file path
        form.set_file_path(str(xml_file))
        console.print(f"[green]✓ File path set:[/] {xml_file}")
        console.print()

        # Stage 2: Preview parsed data
        console.rule("[cyan]Stage 2: Parse Preview")
        form.next_stage()
        panel, choices = form.render()
        console.print(panel)
        console.print()

        # Show parse results
        if form.parse_results:
            console.print("[bold green]Parse Results:[/]")
            console.print(f"  • File type: [cyan]{form.file_type}[/]")
            console.print(f"  • Target: [cyan]{form.parse_results.get('target')}[/]")
            console.print(f"  • Ports found: [cyan]{len(form.parse_results.get('ports', []))}[/]")

            for port_data in form.parse_results.get('ports', [])[:3]:
                port = port_data.get('port')
                service = port_data.get('service', 'unknown')
                version = port_data.get('version', '-')
                console.print(f"    - Port {port}: {service} ({version})")
        console.print()

        # Stage 3: Merge strategy
        console.rule("[cyan]Stage 3: Merge Strategy")
        form.next_stage()
        panel, choices = form.render()
        console.print(panel)
        console.print(f"[dim]Current strategy: {form.merge_strategy}[/]")
        console.print()

        # Stage 4: Confirmation
        console.rule("[cyan]Stage 4: Confirmation")
        form.next_stage()
        panel, choices = form.render()
        console.print(panel)
        console.print()

        # Validate before import
        if form.validate():
            console.print("[bold green]✓ Form validation passed[/]")
        else:
            console.print(f"[bold red]✗ Validation failed:[/] {form.error_message}")
        console.print()

        # Execute import (dry run - we won't actually save)
        console.rule("[cyan]Import Execution")
        console.print("[yellow]Simulating import...[/]")

        # Show what would be imported
        console.print("[bold]Import Summary:[/]")
        console.print(f"  • File: {form.file_path}")
        console.print(f"  • Type: {form.file_type}")
        console.print(f"  • Strategy: {form._get_strategy_label(form.merge_strategy)}")
        console.print(f"  • Ports to add: {len(form.parse_results.get('ports', []))}")
        console.print()

        # Actually do the import
        result = form.import_to_profile(profile)

        if result:
            console.print("[bold green]✓ Import successful![/]")
            if form.import_summary:
                console.print(f"  • Ports added: {form.import_summary.get('ports_added', 0)}")
                console.print(f"  • Notes added: {form.import_summary.get('notes_added', 0)}")
                console.print(f"  • Tasks generated: {form.import_summary.get('tasks_generated', 0)}")
        else:
            console.print(f"[bold red]✗ Import failed:[/] {form.error_message}")
        console.print()

        # Stage 5: Complete
        console.rule("[cyan]Stage 5: Complete")
        panel, choices = form.render()
        console.print(panel)


def demo_error_handling():
    """Demonstrate error handling"""
    console.rule("[bold cyan]Import Form - Error Handling Demo")
    console.print()

    form = ImportForm()

    # Test 1: Invalid file
    console.print("[yellow]Test: Invalid file path[/]")
    result = form.set_file_path("/nonexistent/file.xml")
    if not result:
        console.print(f"[green]✓ Error caught:[/] {form.error_message}")
    console.print()

    # Test 2: Validation without data
    console.print("[yellow]Test: Validation without parse results[/]")
    form.reset()
    result = form.validate()
    if not result:
        console.print(f"[green]✓ Validation failed:[/] {form.error_message}")
    console.print()

    # Test 3: Unsupported file format
    console.print("[yellow]Test: Unsupported file format[/]")
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode='w') as f:
        f.write("This is not a scan file")
        txt_file = f.name

    form.reset()
    form.file_path = txt_file
    form._detect_and_parse()

    if form.error_message:
        console.print(f"[green]✓ Parse error caught:[/] {form.error_message}")

    Path(txt_file).unlink()  # Cleanup


def demo_merge_strategies():
    """Demonstrate different merge strategies"""
    console.rule("[bold cyan]Import Form - Merge Strategies Demo")
    console.print()

    strategies = [
        (ImportForm.MERGE_SMART, "Smart Merge (deduplicate, intelligent merge)"),
        (ImportForm.MERGE_APPEND, "Append Only (keep all, may duplicate)"),
        (ImportForm.MERGE_REPLACE, "Replace All (clear existing data)"),
    ]

    for strategy_id, description in strategies:
        console.print(f"[bold cyan]{strategy_id}:[/] {description}")

    console.print()
    console.print("[dim]The form starts with Smart Merge as the default strategy.[/]")
    console.print("[dim]Users can change strategy at Stage 3 before import.[/]")


def main():
    """Run all demonstrations"""
    console.print()
    console.print("[bold bright_white]CRACK Track - Import Form Panel Demonstration[/]")
    console.print("[dim]Standalone panel for importing scan results (Nmap XML, greppable, JSON)[/]")
    console.print()

    try:
        demo_basic_usage()
        console.print()

        demo_error_handling()
        console.print()

        demo_merge_strategies()
        console.print()

        console.rule("[bold green]Demo Complete")
        console.print()
        console.print("[green]✓ Import Form panel is fully functional and standalone![/]")
        console.print()
        console.print("[bold]Key Features:[/]")
        console.print("  • Multi-stage wizard (file → preview → merge → confirm)")
        console.print("  • Auto-detection of file formats (XML, greppable)")
        console.print("  • Parse preview with port/service summary")
        console.print("  • Merge strategies (smart/append/replace)")
        console.print("  • Integration with existing parsers")
        console.print("  • Graceful error handling")
        console.print()
        console.print("[bold]Integration Pattern:[/]")
        console.print("  [dim]form = ImportForm(profile)[/]")
        console.print("  [dim]panel, choices = form.render()[/]")
        console.print("  [dim]if form.validate(): form.import_to_profile(profile)[/]")

    except Exception as e:
        console.print(f"[bold red]Error during demo:[/] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
