"""Interactive chain execution with step-by-step guidance.

MVP implementation:
- Linear progression through chain steps
- Manual confirmation at each stage
- Command resolution and variable filling
- Session persistence for resume
"""

import subprocess
import sys
import tty
import termios
from typing import Any, Dict, Optional

from pathlib import Path
from .registry import ChainRegistry
from .loader import ChainLoader
from .command_resolver import CommandResolver
from .session_storage import ChainSession
from .core.step_processor import StepProcessor
from .variables.context import VariableContext
from .filtering.selector import FindingSelector
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
        self.chain_loader = ChainLoader()
        self.command_resolver = CommandResolver()
        self.config_manager = ConfigManager()
        self.command_registry = HybridCommandRegistry(
            config_manager=self.config_manager,
            theme=self.theme
        )

        # Load chains from data directory
        self._ensure_chains_loaded()

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
                print(self.theme.prompt("Resume from saved progress? (y/N): "), end='', flush=True)
                resume_key = self._read_single_key()
                print(resume_key)  # Echo key

                if resume_key == 'y':
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

        # Initialize new parsing/variable systems
        self.var_context = VariableContext(self.session, self.config_manager)
        self.selector = FindingSelector(self.theme)
        self.step_processor = StepProcessor(self.var_context, self.selector)

    def _ensure_chains_loaded(self):
        """Load chains from data directory (same pattern as CLI)"""
        # Check if already loaded (registry is singleton)
        if self.chain_registry.get_chain('linux-privesc-suid-basic'):
            return  # Already loaded

        data_dir = Path(__file__).parent.parent / 'data' / 'attack_chains'
        if not data_dir.exists():
            print(self.theme.warning(f"Chain data directory not found: {data_dir}"))
            return

        try:
            chains = self.chain_loader.load_all_chains([data_dir])
            loaded_count = 0
            skipped_count = 0

            for chain_id, chain_data in chains.items():
                # Check if already registered (registry is singleton)
                if self.chain_registry.get_chain(chain_id):
                    print(self.theme.warning(
                        f"Chain '{chain_id}' already registered - skipping duplicate"
                    ))
                    skipped_count += 1
                else:
                    self.chain_registry.register_chain(chain_id, chain_data)
                    loaded_count += 1

            if loaded_count > 0:
                print(self.theme.hint(f"Loaded {loaded_count} attack chain(s)"))
            if skipped_count > 0:
                print(self.theme.hint(f"Skipped {skipped_count} duplicate(s)"))

        except ValueError as e:
            # Don't silently fail - show the error
            print(self.theme.error(f"Failed to load chains: {e}"))
            raise  # Re-raise so user knows something went wrong

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

            # Fill placeholders (with variable context)
            filled = self._fill_command(cmd, step)

            # Show final command
            print(f"\n{self.theme.primary('Final command:')}")
            print(f"  {self.theme.command_name(filled)}\n")

            # Execute
            if self._confirm("Run this command?"):
                output = self._execute(filled, step)

                # Store raw output
                self.session.step_outputs[step['id']] = output if output else ""

                # Parse output and extract findings/variables
                parse_result = None
                if output:
                    parse_result = self.step_processor.process_output(
                        step=step,
                        command=filled,
                        output=output,
                        step_id=step['id']
                    )

                    # Store findings and variables
                    self.session.store_step_findings(step['id'], parse_result.get('findings', {}))
                    self.session.store_step_variables(step['id'], parse_result.get('variables', {}))

                    # Show parsing summary
                    if parse_result.get('parser'):
                        print(f"\n{self.theme.hint('─' * 70)}")
                        print(f"{self.theme.primary('Parsing Results:')}")
                        print(self.step_processor.get_step_summary(step['id'], parse_result))

                # Store parse result for verification
                self._last_parse_result = parse_result
            else:
                print("Skipped execution.")
                self._last_parse_result = None

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

    def _fill_command(self, cmd: Any, step: Dict[str, Any]) -> str:
        """Fill command placeholders with variable context and user input

        Args:
            cmd: Command object
            step: Current step metadata

        Returns:
            Filled command string
        """
        print(f"\n{self.theme.primary('Filling command variables...')}\n")

        # Show command name and template
        print(f"{self.theme.primary('[*] Command:')} {self.theme.command_name(cmd.name)}")
        print(f"{self.theme.hint('[*] Template:')} {self.theme.muted(cmd.command)}")

        # Check if command has placeholders
        placeholders = cmd.extract_placeholders()

        # Get all available variables from context
        step_id = step.get('id', '')

        # Check which variables we can auto-fill
        auto_filled = {}
        needs_input = []

        for placeholder in placeholders:
            resolved = self.var_context.resolve(placeholder, step_id)
            if resolved:
                auto_filled[placeholder] = resolved
                source = self.var_context.get_variable_source(placeholder, step_id)
                print(f"{self.theme.hint(f'[*] Auto-filled {placeholder} from {source.value}:')} {resolved}")
            else:
                needs_input.append(placeholder)

        if not needs_input:
            # All variables auto-filled - use them directly
            print(self.theme.hint("\nAll variables auto-filled (no user input needed)\n"))
            filled = cmd.fill_placeholders(auto_filled)
        else:
            # Some variables need user input - use interactive fill
            print(f"\n{self.theme.hint(f'Need to fill {len(needs_input)} remaining variables')}\n")

            # Temporarily add auto-filled values to config so interactive_fill uses them
            if self.config_manager and auto_filled:
                original_config = {}
                for placeholder, value in auto_filled.items():
                    # Save original value
                    original_config[placeholder] = self.config_manager.get_placeholder(placeholder)
                    # Set our auto-filled value
                    self.config_manager.set_placeholder(placeholder, value)

            # Show flag explanations
            if cmd.flag_explanations:
                print(f"{self.theme.primary('Flag Explanations:')}")
                for flag, explanation in cmd.flag_explanations.items():
                    print(f"  {self.theme.primary(flag.ljust(15))} → {self.theme.hint(explanation)}")

            try:
                print()  # Blank line before prompts
                filled = self.command_registry.interactive_fill(cmd)

                # Restore original config values
                if self.config_manager and auto_filled:
                    for placeholder, value in original_config.items():
                        if value is not None:
                            self.config_manager.set_placeholder(placeholder, value)
                        else:
                            # Was not in config before, remove it
                            self.config_manager.placeholders.pop(placeholder, None)

            except KeyboardInterrupt:
                # Restore config on cancel
                if self.config_manager and auto_filled:
                    for placeholder, value in original_config.items():
                        if value is not None:
                            self.config_manager.set_placeholder(placeholder, value)
                        else:
                            self.config_manager.placeholders.pop(placeholder, None)
                print(self.theme.warning("\nFilling cancelled"))
                raise

        # Show final command
        print(f"\n{self.theme.success('[+] Final command:')} {self.theme.command_name(filled)}")

        return filled

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

            # Verification checklist - intelligent based on parsing results
            self._show_verification_checklist(step, result)

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

    def _show_verification_checklist(self, step: Dict[str, Any], execution_result):
        """Show intelligent verification checklist based on parsing results

        Args:
            step: Current step metadata
            execution_result: subprocess.CompletedProcess result
        """
        success_criteria = step.get('success_criteria', [])
        if not success_criteria:
            return

        print(f"\n{self.theme.primary('Verification Checklist:')}")

        # Get parsed findings if available
        parse_result = getattr(self, '_last_parse_result', None)
        findings = parse_result.get('findings', {}) if parse_result else {}

        # Intelligent verification based on parsed data
        for criteria in success_criteria:
            criteria_lower = criteria.lower()
            checked = False

            # Check based on parsing results
            if 'command executes without errors' in criteria_lower:
                checked = execution_result.returncode == 0
            elif 'binaries discovered' in criteria_lower or 'binaries found' in criteria_lower:
                # Extract number from criteria (e.g., "At least 10-20 SUID binaries")
                total = findings.get('total_count', 0)
                checked = total >= 10
            elif 'exploitable' in criteria_lower or 'interesting' in criteria_lower:
                exploitable = findings.get('exploitable_count', 0)
                checked = exploitable > 0
            elif 'non-standard binaries' in criteria_lower:
                exploitable = findings.get('exploitable_count', 0)
                checked = exploitable > 0

            # Show checkbox with status
            if checked:
                checkbox = self.theme.success('✓')
            else:
                checkbox = self.theme.muted('□')

            print(f"  [{checkbox}] {criteria}")

        # Show parsed evidence summary with exact/fuzzy counts
        if parse_result and parse_result.get('parser'):
            print(f"\n{self.theme.hint('Parsed Evidence:')}")

            total = findings.get('total_count', 0)
            exploitable = findings.get('exploitable_count', 0)
            standard = findings.get('standard_count', 0)
            unknown = findings.get('unknown_count', 0)

            print(f"  • Total binaries: {total}")

            if exploitable > 0:
                # Count exact vs fuzzy matches
                exploitable_list = findings.get('exploitable_binaries', [])
                exact = 0
                fuzzy = 0

                if exploitable_list and isinstance(exploitable_list[0], dict):
                    exact = sum(1 for b in exploitable_list if b.get('match_type') == 'exact')
                    fuzzy = sum(1 for b in exploitable_list if b.get('match_type') == 'fuzzy')

                if exact > 0 or fuzzy > 0:
                    print(f"  • {self.theme.success(f'Exploitable: {exploitable} ({exact} exact, {fuzzy} fuzzy)')}")
                else:
                    print(f"  • {self.theme.success(f'Exploitable: {exploitable}')}")
            else:
                print(f"  • {self.theme.warning(f'Exploitable: 0')}")

            print(f"  • Standard system: {standard}")

            if unknown > 0:
                print(f"  • {self.theme.warning(f'Unknown: {unknown} (manual review)')}")

    def _mark_complete(self, step: Dict[str, Any]):
        """Mark step as complete"""
        step_id = step.get('id', f"step_{self.session.current_step_index}")
        output = self.session.step_outputs.get(step_id, "")
        self.session.mark_step_complete(step_id, output)

    def _advance_step(self):
        """Move to next step"""
        self.session.advance_step()

    def _read_single_key(self) -> str:
        """Read single keystroke without requiring Enter

        Returns:
            Single character (lowercase)
        """
        if not sys.stdin.isatty():
            # Fallback for non-TTY (pipes, redirects)
            return input().strip().lower()

        try:
            # Save terminal settings
            original_settings = termios.tcgetattr(sys.stdin)

            try:
                # Set raw mode (no echo, no line buffering)
                tty.setraw(sys.stdin.fileno())

                # Read single character
                key = sys.stdin.read(1).lower()

                # Handle Ctrl+C
                if key == '\x03':
                    raise KeyboardInterrupt

                return key

            finally:
                # Always restore terminal settings
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, original_settings)

        except Exception:
            # Fallback on any error
            return input().strip().lower()

    def _confirm(self, message: str, default: str = 'y') -> bool:
        """Get user confirmation with single keystroke

        Args:
            message: Prompt message
            default: Default choice ('y' or 'n')

        Returns:
            True if confirmed
        """
        prompt_suffix = " (Y/n): " if default == 'y' else " (y/N): "
        print(self.theme.prompt(message + prompt_suffix), end='', flush=True)

        key = self._read_single_key()

        # Echo the key for user feedback
        print(key)

        # Empty key (just Enter) = use default
        if key in ['\r', '\n', '']:
            return default == 'y'

        return key == 'y'
