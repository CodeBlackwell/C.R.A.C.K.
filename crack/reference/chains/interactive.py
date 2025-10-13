"""Interactive chain execution with step-by-step guidance.

MVP implementation:
- Linear progression through chain steps
- Manual confirmation at each stage
- Command resolution and variable filling
- Session persistence for resume
"""

import subprocess
from typing import Any, Dict, Optional

from .registry import ChainRegistry
from .command_resolver import CommandResolver
from .session_storage import ChainSession
from crack.reference.core.registry import HybridCommandRegistry
from crack.config import ConfigManager
from crack.reference.core.colors import ReferenceTheme


class ChainInteractive:
    """Main interactive loop for chain execution"""

    def __init__(self, chain_id: str, target: Optional[str] = None, resume: bool = False):
        """Initialize interactive chain executor

        Args:
            chain_id: Unique chain identifier
            target: Target IP/hostname (prompts if None)
            resume: Resume from saved session
        """
        self.theme = ReferenceTheme()
        self.chain_registry = ChainRegistry()
        self.command_resolver = CommandResolver()
        self.command_registry = HybridCommandRegistry(
            config_manager=ConfigManager(),
            theme=self.theme
        )

        # Load chain
        self.chain = self.chain_registry.get_chain(chain_id)
        if not self.chain:
            raise ValueError(f"Chain not found: {chain_id}")

        # Get or prompt for target
        if target is None:
            target = input(self.theme.prompt("Target IP/hostname (press Enter for '.'): ")).strip()
            if not target:
                target = "."
                print(self.theme.hint("→ Using '.' (local system)\n"))

        self.target = target

        # Load or create session
        if resume:
            self.session = ChainSession.load(chain_id, target)
            if self.session:
                print(self.theme.success(
                    f"Resuming session from step {self.session.current_step_index + 1}"
                ))
            else:
                print(self.theme.warning("No saved session found, starting fresh"))
                self.session = ChainSession(chain_id, target)
        else:
            # Check if session exists
            if ChainSession.exists(chain_id, target):
                print(self.theme.warning(
                    f"Existing session found for {chain_id} on {target}"
                ))
                resume_confirm = input("Resume from saved progress? (y/N): ").strip().lower()
                if resume_confirm == 'y':
                    self.session = ChainSession.load(chain_id, target)
                    print(self.theme.success(
                        f"Resuming from step {self.session.current_step_index + 1}"
                    ))
                else:
                    self.session = ChainSession(chain_id, target)
            else:
                self.session = ChainSession(chain_id, target)

        # Add target to session variables (auto-fill for commands)
        self.session.variables['<TARGET>'] = target

    def run(self):
        """Main loop: show step → fill → execute → next"""
        total_steps = len(self.chain['steps'])

        # Show chain header
        self._show_chain_header(total_steps)

        while self.session.current_step_index < total_steps:
            step = self.chain['steps'][self.session.current_step_index]
            step_num = self.session.current_step_index + 1

            # Show step details
            self._show_step(step, step_num, total_steps)

            # Resolve command reference
            cmd = self._resolve_command(step['command_ref'])
            if not cmd:
                print(self.theme.error(
                    f"Command reference not found: {step['command_ref']}"
                ))
                if self._confirm("Skip this step?"):
                    self._mark_complete(step)
                    self._advance_step()
                    continue
                else:
                    print("Paused. Run with --resume to continue.")
                    self.session.save()
                    return

            # Fill placeholders (reuse existing registry logic)
            print(f"\n{self.theme.primary('Filling command variables...')}\n")
            filled = self._fill_command(cmd)

            # Show final command
            print(f"\n{self.theme.primary('Final command:')}")
            print(f"  {self.theme.command_name(filled)}\n")

            # Execute
            if self._confirm("Run this command?"):
                output = self._execute(filled, step)
                self.session.step_outputs[step['id']] = output if output else ""
            else:
                print("Skipped execution.")

            # Progress
            print()
            if self._confirm("Mark complete and continue?"):
                self._mark_complete(step)
                self._advance_step()
                self.session.save()
                print(self.theme.success("Progress saved.\n"))
            else:
                print(self.theme.info("Paused. Run with --resume to continue from this step."))
                self.session.save()
                return

        # Chain complete
        print("\n" + "=" * 70)
        print(self.theme.success("🎉 Chain complete!"))
        print("=" * 70)
        self.session.delete()  # Clean up completed session

    def _show_chain_header(self, total_steps: int):
        """Display chain metadata with prerequisites and notes"""
        import textwrap

        print("\n" + "=" * 70)
        print(self.theme.command_name(self.chain['name']))
        print("=" * 70)

        # Basic metadata
        print(f"{self.theme.primary('Target:')} {self.target}")
        print(f"{self.theme.primary('Steps:')} {total_steps}")
        print(f"{self.theme.primary('Difficulty:')} {self.chain.get('difficulty', 'Unknown')}")
        print(f"{self.theme.primary('Time Estimate:')} {self.chain.get('time_estimate', 'Unknown')}")

        # OSCP relevance
        oscp = 'Yes' if self.chain.get('oscp_relevant', False) else 'No'
        oscp_color = self.theme.success if oscp == 'Yes' else self.theme.muted
        print(f"{self.theme.primary('OSCP Relevant:')} {oscp_color(oscp)}")

        # Description
        if self.chain.get('description'):
            print(f"\n{self.theme.hint(self.chain['description'])}")

        # Prerequisites
        prereqs = self.chain.get('prerequisites', [])
        if prereqs:
            print(f"\n{self.theme.primary('Prerequisites:')}")
            for prereq in prereqs:
                print(f"  {self.theme.hint('•')} {prereq}")

        # Notes (OSCP tips, common pitfalls)
        notes = self.chain.get('notes')
        if notes:
            print(f"\n{self.theme.primary('Notes:')}")
            # Word wrap long notes
            wrapped = textwrap.fill(notes, width=68, initial_indent='  ', subsequent_indent='  ')
            print(self.theme.hint(wrapped))

        print("=" * 70 + "\n")

    def _show_step(self, step: Dict[str, Any], step_num: int, total_steps: int):
        """Display current step details with success/failure criteria"""
        import textwrap

        print("=" * 70)
        print(self.theme.command_name(f"Step {step_num} of {total_steps}: {step['name']}"))
        print("=" * 70)

        # Objective
        print(f"\n{self.theme.primary('Objective:')} {step['objective']}")

        # Description (formatted better)
        if step.get('description'):
            print(f"\n{self.theme.primary('Description:')}")
            wrapped = textwrap.fill(step['description'], width=68, initial_indent='  ', subsequent_indent='  ')
            print(self.theme.hint(wrapped))

        # Command reference and preview
        print(f"\n{self.theme.primary('Command Reference:')} {step['command_ref']}")

        try:
            cmd_preview = self._resolve_command_preview(step['command_ref'])
            if cmd_preview:
                print(f"{self.theme.hint('Resolved Command:')} {self.theme.muted(cmd_preview.command)}")
        except Exception:
            pass

        # Success criteria (what to look for)
        success_criteria = step.get('success_criteria', [])
        if success_criteria:
            print(f"\n{self.theme.primary('Expected Evidence (Success Indicators):')}")
            for criteria in success_criteria:
                print(f"  {self.theme.success('✓')} {criteria}")

        # Failure conditions (troubleshooting)
        failure_conditions = step.get('failure_conditions', [])
        if failure_conditions:
            print(f"\n{self.theme.primary('Common Failures:')}")
            for condition in failure_conditions:
                print(f"  {self.theme.error('✗')} {condition}")

        # Evidence to collect (if different from success_criteria)
        evidence = step.get('evidence', [])
        if evidence and not success_criteria:  # Don't duplicate if success_criteria exists
            print(f"\n{self.theme.primary('Evidence to Collect:')}")
            for item in evidence:
                print(f"  {self.theme.hint('•')} {item}")

    def _resolve_command_preview(self, command_ref: str) -> Optional[Any]:
        """Preview command without failing (for display only)

        Args:
            command_ref: Command ID to resolve

        Returns:
            Command object or None (silent failure)
        """
        try:
            # Try CommandResolver first
            resolved = self.command_resolver.resolve_command_ref(command_ref)
            if resolved:
                cmd = self.command_registry.get_command(command_ref)
                if cmd:
                    return cmd

            # Fallback: direct lookup
            return self.command_registry.get_command(command_ref)
        except Exception:
            return None

    def _resolve_command(self, command_ref: str) -> Optional[Any]:
        """Resolve command reference to Command object

        Args:
            command_ref: Command ID to resolve

        Returns:
            Command object or None
        """
        # Try to resolve via CommandResolver first
        resolved = self.command_resolver.resolve_command_ref(command_ref)
        if resolved:
            # CommandResolver returns dict, convert to Command
            cmd = self.command_registry.get_command(command_ref)
            if cmd:
                return cmd

        # Fallback: direct lookup in registry
        return self.command_registry.get_command(command_ref)

    def _fill_command(self, cmd: Any) -> str:
        """Fill command placeholders with flag explanations

        Args:
            cmd: Command object

        Returns:
            Filled command string
        """
        print(f"\n{self.theme.primary('Filling command variables...')}\n")

        # Show command name and template
        print(f"{self.theme.primary('[*] Command:')} {self.theme.command_name(cmd.name)}")
        print(f"{self.theme.hint('[*] Template:')} {self.theme.muted(cmd.command)}")

        # Check if command has placeholders
        placeholders = cmd.extract_placeholders()
        if not placeholders or not any(p not in ['<TARGET>'] for p in placeholders):
            print(self.theme.hint("\nNo variables to fill (command ready to execute)\n"))

        # Show flag explanations
        if cmd.flag_explanations:
            print(f"\n{self.theme.primary('Flag Explanations:')}")
            for flag, explanation in cmd.flag_explanations.items():
                # Format nicely with proper spacing
                print(f"  {self.theme.primary(flag.ljust(15))} → {self.theme.hint(explanation)}")

        # Use registry's interactive fill (handles config auto-fill)
        try:
            print()  # Blank line before prompts
            filled = self.command_registry.interactive_fill(cmd)

            # Show final command
            print(f"\n{self.theme.success('[+] Final command:')} {self.theme.command_name(filled)}")

            return filled
        except KeyboardInterrupt:
            print(self.theme.warning("\nFilling cancelled"))
            raise

    def _execute(self, command: str, step: Dict[str, Any]) -> Optional[str]:
        """Execute command and show verification checklist

        Args:
            command: Filled command string
            step: Current step metadata

        Returns:
            Command output or None
        """
        print(f"\n{self.theme.primary('Executing...')}\n")

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            # Show output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(self.theme.hint(result.stderr))

            # Show return code
            if result.returncode == 0:
                print(f"\n{self.theme.success('✓ Command completed successfully')}")
            else:
                print(f"\n{self.theme.warning(f'⚠ Command exited with code {result.returncode}')}")

            # Verification checklist
            success_criteria = step.get('success_criteria', [])
            if success_criteria:
                print(f"\n{self.theme.primary('Verify Your Results:')}")
                print(self.theme.hint("Review the output above and check:"))
                for criteria in success_criteria:
                    print(f"  [{self.theme.success('✓')}] {criteria}")

            # Next steps preview
            next_steps = step.get('next_steps', [])
            if next_steps:
                print(f"\n{self.theme.primary('Next Step:')}")
                print(f"  {self.theme.hint('→ ' + next_steps[0])}")
            elif self.session.current_step_index + 1 < len(self.chain['steps']):
                # Show next step's objective as preview
                next_step = self.chain['steps'][self.session.current_step_index + 1]
                print(f"\n{self.theme.primary('Next Step:')}")
                print(f"  {self.theme.hint('→ ' + next_step.get('objective', next_step.get('name')))}")

            return result.stdout if result.stdout else result.stderr

        except subprocess.TimeoutExpired:
            print(self.theme.error("⚠ Command timed out (5 minute limit)"))
            return None
        except Exception as e:
            print(self.theme.error(f"⚠ Execution failed: {str(e)}"))
            return None

    def _mark_complete(self, step: Dict[str, Any]):
        """Mark step as complete"""
        step_id = step.get('id', f"step_{self.session.current_step_index}")
        output = self.session.step_outputs.get(step_id, "")
        self.session.mark_step_complete(step_id, output)

    def _advance_step(self):
        """Move to next step"""
        self.session.advance_step()

    def _confirm(self, message: str, default: str = 'y') -> bool:
        """Get user confirmation

        Args:
            message: Prompt message
            default: Default choice ('y' or 'n')

        Returns:
            True if confirmed
        """
        prompt_suffix = " (Y/n): " if default == 'y' else " (y/N): "
        response = input(self.theme.prompt(message + prompt_suffix)).strip().lower()

        if not response:
            return default == 'y'

        return response in ['y', 'yes']
