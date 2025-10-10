#!/usr/bin/env python3
"""
Standalone example of Credential Entry Form Panel

Demonstrates:
- Creating a credential form instance
- Rendering the form panel
- Field navigation and editing
- Validation
- Saving to profile

Run with: python3 examples/credential_form_standalone.py
"""

from crack.track.core.state import TargetProfile
from crack.track.interactive.panels.credential_form import CredentialFormPanel
from rich.console import Console
from rich.panel import Panel


def main():
    """Demonstrate credential form usage"""
    console = Console()

    # 1. Create or load target profile
    console.print("[bold cyan]Creating target profile...[/]")
    profile = TargetProfile('192.168.45.100')
    console.print(f"[green]✓[/] Profile created: {profile.target}\n")

    # 2. Create credential form instance
    console.print("[bold cyan]Creating credential form...[/]")
    form = CredentialFormPanel.create(profile)
    console.print(f"[green]✓[/] Form initialized with {len(form.FIELDS)} fields\n")

    # 3. Render the form (shows empty state)
    console.print("[bold cyan]Rendering empty form...[/]")
    panel, choices = form.render()
    console.print(panel)
    console.print(f"\n[dim]Available choices: {len(choices)}[/]\n")

    # 4. Simulate filling out the form
    console.print("[bold cyan]Filling out form programmatically...[/]")

    # Navigate to username field (field 0)
    form.current_field = 0
    form.edit_current_field('admin')
    console.print("[green]✓[/] Username: admin")

    # Navigate to password field (field 1)
    form.current_field = 1
    form.edit_current_field('P@ssw0rd123!')
    console.print("[green]✓[/] Password: *********** (masked)")

    # Navigate to service field (field 2)
    form.current_field = 2
    form.edit_current_field('SSH')
    console.print("[green]✓[/] Service: SSH")

    # Navigate to source field (field 3) - REQUIRED
    form.current_field = 3
    form.edit_current_field('hydra brute force attack')
    console.print("[green]✓[/] Source: hydra brute force attack")

    # Navigate to port field (field 4)
    form.current_field = 4
    form.edit_current_field('22')
    console.print("[green]✓[/] Port: 22")

    # Navigate to notes field (field 5)
    form.current_field = 5
    form.edit_current_field('Default credentials found during enumeration')
    console.print("[green]✓[/] Notes: Default credentials found during enumeration\n")

    # 5. Render filled form
    console.print("[bold cyan]Rendering filled form...[/]")
    panel, choices = form.render()
    console.print(panel)
    console.print()

    # 6. Validate the form
    console.print("[bold cyan]Validating form...[/]")
    is_valid = form.validate()
    if is_valid:
        console.print("[bold green]✓ Form validation passed![/]\n")
    else:
        console.print("[bold red]✗ Form validation failed![/]")
        for field, error in form.validation_errors.items():
            console.print(f"  [red]• {field}: {error}[/]")
        console.print()

    # 7. Save to profile
    if is_valid:
        console.print("[bold cyan]Saving credential to profile...[/]")
        success = form.save_to_profile()

        if success:
            console.print("[bold green]✓ Credential saved successfully![/]\n")

            # 8. Verify saved credential
            console.print("[bold cyan]Verifying saved credential...[/]")
            cred = profile.credentials[0]

            info_table = Panel(
                f"""[white]Username:[/] {cred['username']}
[white]Password:[/] {cred['password']}
[white]Service:[/] {cred['service']}
[white]Source:[/] {cred['source']}
[white]Port:[/] {cred['port']}
[white]Notes:[/] {cred['notes']}
[white]Timestamp:[/] {cred['timestamp']}""",
                title="[bold green]Saved Credential[/]",
                border_style="green"
            )
            console.print(info_table)
            console.print()
        else:
            console.print("[bold red]✗ Failed to save credential[/]\n")

    # 9. Demonstrate validation errors
    console.print("[bold cyan]Demonstrating validation errors...[/]")
    form2 = CredentialFormPanel.create(profile)

    # Try to save empty form
    success = form2.save_to_profile()
    console.print(f"[yellow]Empty form save attempt: {success}[/]")
    console.print(f"[yellow]Validation errors: {list(form2.validation_errors.keys())}[/]\n")

    # 10. Demonstrate field-level validation
    console.print("[bold cyan]Demonstrating field-level validation...[/]")
    form3 = CredentialFormPanel.create(profile)

    # Try invalid port
    form3.current_field = 4  # Port field
    valid = form3.edit_current_field('99999')
    console.print(f"[yellow]Invalid port (99999): Valid={valid}[/]")
    console.print(f"[yellow]Error: {form3.validation_errors.get('port')}[/]\n")

    # Try invalid service
    form3.current_field = 2  # Service field
    valid = form3.edit_current_field('INVALID_SERVICE')
    console.print(f"[yellow]Invalid service: Valid={valid}[/]")
    console.print(f"[yellow]Error: {form3.validation_errors.get('service')}[/]\n")

    # 11. Demonstrate password masking
    console.print("[bold cyan]Demonstrating password masking...[/]")
    form4 = CredentialFormPanel.create(profile)
    form4.form_data['password'] = 'secret123'

    console.print(f"[white]Password visible:[/] {form4.show_password}")
    console.print(f"[white]Raw password:[/] {form4.form_data['password']}")

    form4._toggle_password_visibility()
    console.print(f"[white]After toggle - visible:[/] {form4.show_password}")

    form4._toggle_password_visibility()
    console.print(f"[white]After toggle - visible:[/] {form4.show_password}\n")

    # 12. Demonstrate service selector
    console.print("[bold cyan]Demonstrating service selector...[/]")
    selector_panel, selector_choices = CredentialFormPanel.render_service_selector()
    console.print(selector_panel)
    console.print(f"\n[dim]Service choices: {len([c for c in selector_choices if c['id'].startswith('select-')])}[/]\n")

    # 13. Demonstrate clear form
    console.print("[bold cyan]Demonstrating form clear...[/]")
    form5 = CredentialFormPanel.create(profile)
    form5.form_data['username'] = 'test'
    form5.form_data['password'] = 'test123'
    console.print(f"[white]Before clear - username:[/] '{form5.form_data['username']}'")

    form5._clear_form()
    console.print(f"[white]After clear - username:[/] '{form5.form_data['username']}'")
    console.print(f"[white]After clear - current field:[/] {form5.current_field}\n")

    # 14. Summary
    console.print("[bold cyan]Summary[/]")
    console.print(f"[white]Total credentials in profile:[/] {len(profile.credentials)}")
    console.print(f"[white]Profile target:[/] {profile.target}")
    console.print(f"[white]Profile status:[/] {profile.status}")

    console.print("\n[bold green]✓ Credential form demonstration complete![/]")


if __name__ == '__main__':
    main()
