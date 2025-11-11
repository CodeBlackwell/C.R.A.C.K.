"""
CLI handler for cheatsheet display and interaction
"""

from typing import Optional, List
from crack.reference.cli.base import BaseCLIHandler
from crack.reference.core.cheatsheet_registry import Cheatsheet, CheatsheetRegistry
from crack.reference.core.registry import Command


class CheatsheetCLI(BaseCLIHandler):
    """Handler for cheatsheet operations"""

    def __init__(self, cheatsheet_registry: CheatsheetRegistry, command_registry=None, theme=None):
        """
        Initialize cheatsheet CLI handler

        Args:
            cheatsheet_registry: CheatsheetRegistry instance
            command_registry: HybridCommandRegistry or SQLCommandRegistryAdapter for resolving commands
            theme: ReferenceTheme instance
        """
        super().__init__(theme)
        self.cheatsheet_registry = cheatsheet_registry
        self.command_registry = command_registry

    def list_cheatsheets(self, numbered=False):
        """
        List all available cheatsheets grouped by category

        Args:
            numbered: If True, number each cheatsheet for selection
        """
        sheets = self.cheatsheet_registry.list_cheatsheets()

        if not sheets:
            print(f"{self.theme.warning('No cheatsheets available.')}")
            return []

        # Group cheatsheets by primary tag/category
        categories = {}
        for sheet in sheets:
            # Use first tag as category, or 'general' if no tags
            primary_tag = sheet.tags[0].upper() if sheet.tags else 'GENERAL'

            # Clean up category names for display
            if primary_tag in ['OSCP:HIGH', 'QUICK_WIN']:
                category = 'OSCP PRIORITY'
            elif primary_tag == 'METASPLOIT':
                category = 'METASPLOIT FRAMEWORK'
            elif primary_tag in ['WEB', 'SSH', 'WINDOWS', 'LINUX']:
                category = primary_tag + ' TECHNIQUES'
            elif primary_tag in ['ACTIVE_DIRECTORY', 'AD']:
                category = 'ACTIVE DIRECTORY'
            elif primary_tag.startswith('HASH'):
                category = 'PASSWORD ATTACKS'
            else:
                category = primary_tag.replace('_', ' ')

            if category not in categories:
                categories[category] = []
            categories[category].append(sheet)

        # Display header
        print(f"\n{self.theme.command_name('═' * 70)}")
        print(f"{self.theme.command_name('AVAILABLE CHEATSHEETS')}")
        print(f"{self.theme.command_name('═' * 70)}\n")

        # Display each category
        counter = 1
        all_sheets_ordered = []

        # Sort categories: OSCP PRIORITY first, then alphabetically
        sorted_categories = sorted(categories.keys(),
                                  key=lambda x: (x != 'OSCP PRIORITY', x))

        for category in sorted_categories:
            sheets_in_cat = sorted(categories[category], key=lambda s: s.name)

            # Category header
            print(f"{self.theme.primary(f'┌─ {category} ({len(sheets_in_cat)})')}")
            print(f"{self.theme.muted('│')}")

            # List sheets in category
            for sheet in sheets_in_cat:
                all_sheets_ordered.append(sheet)

                if numbered:
                    number_str = f"{self.theme.bold_white(f'{counter}.')}"
                    print(f"{self.theme.muted('│')}  {number_str} {self.theme.primary(sheet.id)}")
                else:
                    print(f"{self.theme.muted('│')}  • {self.theme.primary(sheet.id)}")

                # Name and description
                print(f"{self.theme.muted('│')}     {sheet.name}")

                # Show truncated description
                if sheet.description:
                    desc = sheet.description[:70] + "..." if len(sheet.description) > 70 else sheet.description
                    print(f"{self.theme.muted('│')}     {self.theme.hint(desc)}")

                print(f"{self.theme.muted('│')}")
                counter += 1

            print()  # Spacing between categories

        # Footer with usage hints
        print(f"{self.theme.muted('─' * 70)}")
        if numbered:
            print(f"{self.theme.hint('Select:')} crack cheatsheets <query> <number>")
            print(f"{self.theme.hint('Example:')} crack cheatsheets metasploit 2")
        else:
            print(f"{self.theme.hint('Usage:')} crack cheatsheets <id>")
            print(f"{self.theme.hint('Example:')} crack cheatsheets log-poisoning")
        print()

        return all_sheets_ordered  # Return for numeric selection

    def show_cheatsheet(self, cheatsheet_id: str):
        """
        Display a cheatsheet with full educational formatting

        Args:
            cheatsheet_id: Cheatsheet ID, search query, or "query number" for selection
        """
        # Check for numeric selection pattern: "query 1", "metasploit 2", etc.
        selection_number = None
        if cheatsheet_id and ' ' in cheatsheet_id:
            parts = cheatsheet_id.rsplit(None, 1)
            if parts[-1].isdigit():
                actual_query = parts[0] if len(parts) > 1 else None
                selection_number = int(parts[-1]) - 1  # Convert to 0-indexed
                cheatsheet_id = actual_query

        # If numeric selection was specified, resolve and select
        if selection_number is not None:
            sheet = self._resolve_with_selection(cheatsheet_id, selection_number)
            if not sheet:
                return
        else:
            sheet = self._resolve_cheatsheet_id(cheatsheet_id)
            if not sheet:
                return

        # Header
        self._render_header(sheet)

        # Educational Context
        self._render_educational_header(sheet)

        # Scenarios
        self._render_scenarios(sheet)

        # Command Sections
        self._render_sections(sheet)

        # Footer with usage hints
        self._render_footer(len(self._collect_all_commands(sheet)))

    def fill_command(self, cheatsheet_id: str, command_number: int):
        """
        Fill a specific command from a cheatsheet

        Args:
            cheatsheet_id: Cheatsheet ID (exact or partial match)
            command_number: 1-indexed command number
        """
        sheet = self._resolve_cheatsheet_id(cheatsheet_id)
        if not sheet:
            return

        # Collect all commands in order
        commands = self._collect_all_commands(sheet)

        if command_number < 1 or command_number > len(commands):
            print(f"{self.theme.error('Invalid command number.')} Valid range: 1-{len(commands)}")
            return

        cmd_id = commands[command_number - 1]
        cmd = self.command_registry.get_command(cmd_id)

        if not cmd:
            print(f"{self.theme.error('Command not found in registry:')} {cmd_id}")
            return

        # Use interactive fill from command registry
        try:
            filled = self.command_registry.interactive_fill(cmd)
            print(f"\n{self.theme.primary('✓ Ready to copy:')}")
            print(f"  {self.theme.command_name(filled)}\n")
        except KeyboardInterrupt:
            print(f"\n{self.theme.warning('[Cancelled]')}\n")
        except AttributeError:
            print(f"{self.theme.error('Command registry does not support interactive fill.')}")

    def fill_all_commands(self, cheatsheet_id: str):
        """
        Fill all commands in a cheatsheet sequentially

        Args:
            cheatsheet_id: Cheatsheet ID (exact or partial match)
        """
        sheet = self._resolve_cheatsheet_id(cheatsheet_id)
        if not sheet:
            return

        commands = self._collect_all_commands(sheet)
        filled_commands = []

        print(f"\n{self.theme.command_name(f'Filling {len(commands)} commands from: {sheet.name}')}")
        print(f"{self.theme.muted('━' * 70)}\n")

        for i, cmd_id in enumerate(commands, 1):
            cmd = self.command_registry.get_command(cmd_id)

            if not cmd:
                print(f"{self.theme.warning(f'[{i}/{len(commands)}] Command not found:')} {cmd_id}")
                continue

            print(f"\n{self.theme.primary(f'[{i}/{len(commands)}]')} {cmd.name}")
            print(f"{self.theme.hint(cmd.command)}\n")

            try:
                filled = self.command_registry.interactive_fill(cmd)
                filled_commands.append(filled)
                print(f"{self.theme.success('✓ Added')}\n")
            except KeyboardInterrupt:
                print(f"\n{self.theme.warning('[Cancelled by user]')}\n")
                break
            except AttributeError:
                print(f"{self.theme.error('Command registry does not support interactive fill.')}")
                return

        # Display all filled commands at the end
        if filled_commands:
            print(f"\n{self.theme.command_name('═' * 70)}")
            print(f"{self.theme.command_name('ALL COMMANDS (copy-paste ready):')}")
            print(f"{self.theme.command_name('═' * 70)}\n")

            for i, filled in enumerate(filled_commands, 1):
                print(f"# Command {i}")
                print(filled)
                print()

    def _resolve_with_selection(self, query: str, selection: int):
        """
        Resolve cheatsheet using query + numeric selection

        Args:
            query: Search query (can be None for "just number" like "2")
            selection: 0-indexed selection number

        Returns:
            Cheatsheet object or None
        """
        # If no query (user just typed a number), show all cheatsheets with numbers
        if not query:
            all_sheets = self.list_cheatsheets(numbered=True)
            if 0 <= selection < len(all_sheets):
                return all_sheets[selection]
            else:
                print(f"{self.theme.error('Invalid selection:')} {selection + 1} (only {len(all_sheets)} cheatsheet(s) available)")
                return None

        # Otherwise, search and filter
        query_lower = query.lower()
        matches = []

        # Find matching cheatsheets (ID or content)
        for sheet_id, sheet in self.cheatsheet_registry.cheatsheets.items():
            # ID match
            if query_lower in sheet_id.lower():
                matches.append(sheet)
                continue

            # Content match (name, description, tags)
            if (query_lower in sheet.name.lower() or
                query_lower in sheet.description.lower() or
                any(query_lower in tag.lower() for tag in sheet.tags)):
                matches.append(sheet)

        # Sort matches for consistency
        matches.sort(key=lambda s: s.name)

        if not matches:
            print(f"{self.theme.error('No cheatsheets found for:')} {query}")
            return None

        if 0 <= selection < len(matches):
            selected = matches[selection]
            print(f"{self.theme.hint('Selected:')} {self.theme.primary(selected.id)}\n")
            return selected
        else:
            print(f"{self.theme.error('Invalid selection:')} {selection + 1} (only {len(matches)} match(es) for \"{query}\")")
            print(f"\n{self.theme.hint('Available matches:')}")
            for i, sheet in enumerate(matches, 1):
                print(f"  {i}. {self.theme.primary(sheet.id)} - {sheet.name}")
            print()
            return None

    def _resolve_cheatsheet_id(self, query: str):
        """
        Resolve cheatsheet ID with intelligent multi-tier search

        Priority matching:
        1. Exact ID match (highest confidence) - Shows full cheatsheet
        2. Partial ID match - Shows list (requires exact ID to display full sheet)
        3. Content search - name/description/tags - Shows list

        Args:
            query: Exact ID, partial ID, or search term

        Returns:
            Cheatsheet object or None if not found/ambiguous
        """
        # Tier 1: Exact ID match ONLY (instant return with full display)
        sheet = self.cheatsheet_registry.get_cheatsheet(query)
        if sheet:
            # Exact match - show full cheatsheet immediately
            return sheet

        # Tier 2: Partial ID match - ALWAYS show list, never auto-display
        query_lower = query.lower()
        id_matches = []

        for sheet_id, sheet in self.cheatsheet_registry.cheatsheets.items():
            if query_lower in sheet_id.lower():
                id_matches.append(sheet)

        # Tier 3: Content search (name, description, tags)
        content_matches = self.cheatsheet_registry.search_cheatsheets(query)

        # Combine results: ID matches prioritized, then content matches (deduplicated)
        all_matches = id_matches + [s for s in content_matches if s not in id_matches]

        # Handle results - NEVER auto-display full sheet for partial matches
        if len(all_matches) == 0:
            print(f"{self.theme.error('No cheatsheets found for:')} {query}")
            print(f"\n{self.theme.hint('Available cheatsheets:')}")
            # Dynamic list with descriptions (sorted alphabetically)
            for sheet_id in sorted(self.cheatsheet_registry.cheatsheets.keys()):
                sheet = self.cheatsheet_registry.cheatsheets[sheet_id]
                print(f"  {self.theme.primary(sheet_id)}")
                if sheet.description:
                    print(f"    {self.theme.hint(sheet.description)}")
            print(f"\n{self.theme.hint('Usage:')} crack cheatsheets <id>")
            return None

        # Show list for ANY partial/content matches (even single results)
        # User must provide exact ID to see full cheatsheet
        print(f"{self.theme.hint(f'Found {len(all_matches)} match(es) for:')} {self.theme.primary(query)}\n")

        if id_matches:
            print(f"{self.theme.command_name('ID Matches:')}")
            for i, sheet in enumerate(id_matches, 1):
                print(f"  {self.theme.bold_white(f'{i}.')} {self.theme.primary(sheet.id)}")
                print(f"     {self.theme.hint(sheet.name)}")
                if sheet.description:
                    desc_preview = sheet.description[:80] + "..." if len(sheet.description) > 80 else sheet.description
                    print(f"     {self.theme.muted(desc_preview)}")
            print()

        content_only = [s for s in content_matches if s not in id_matches]
        if content_only:
            print(f"{self.theme.command_name('Content Matches:')}")
            offset = len(id_matches)
            for i, sheet in enumerate(content_only, offset + 1):
                print(f"  {self.theme.bold_white(f'{i}.')} {self.theme.primary(sheet.id)}")
                print(f"     {self.theme.hint(sheet.name)}")

                # Show WHY it matched
                match_reasons = []
                if query_lower in sheet.name.lower():
                    match_reasons.append("name")
                if query_lower in sheet.description.lower():
                    match_reasons.append("description")
                matching_tags = [t for t in sheet.tags if query_lower in t.lower()]
                if matching_tags:
                    match_reasons.append(f"tags: {', '.join(matching_tags)}")

                if match_reasons:
                    print(f"     {self.theme.muted('→ matched in: ' + ', '.join(match_reasons))}")
            print()

        print(f"{self.theme.hint('To view full cheatsheet:')}")
        print(f"  {self.theme.secondary('crack cheatsheets <id>')}")
        print(f"  {self.theme.secondary(f'crack cheatsheets {query} <number>')}")
        if len(all_matches) == 1:
            print(f"\n{self.theme.hint('Example:')} {self.theme.primary(f'crack cheatsheets {all_matches[0].id}')}")
        else:
            print(f"\n{self.theme.hint('Example:')} {self.theme.primary(f'crack cheatsheets {query} 1')}")
        print()
        return None

    def _render_header(self, sheet: Cheatsheet):
        """Render cheatsheet header"""
        border = '═' * 70
        print(f"\n{self.theme.command_name(border)}")
        print(f"{self.theme.command_name(sheet.name.center(70))}")
        print(f"{self.theme.command_name(border)}")
        print(f"\n{self.theme.info(sheet.description)}\n")

    def _render_educational_header(self, sheet: Cheatsheet):
        """Render educational context section"""
        header = sheet.educational_header

        print(f"{self.theme.primary('═══ HOW TO RECOGNIZE ═══')}\n")
        for item in header.how_to_recognize:
            print(f"  {self.theme.success('✓')} {self.theme.info(item)}")

        print(f"\n{self.theme.primary('═══ WHEN TO LOOK FOR ═══')}\n")
        for item in header.when_to_look_for:
            print(f"  {self.theme.prompt('→')} {self.theme.info(item)}")

        print()

    def _render_scenarios(self, sheet: Cheatsheet):
        """Render detailed scenarios"""
        print(f"{self.theme.primary('═══ REAL-WORLD SCENARIOS ═══')}\n")

        for scenario in sheet.scenarios:
            # Scenario box
            border = '─' * 70
            print(f"{self.theme.muted('┌' + border + '┐')}")
            print(f"{self.theme.muted('│')} {self.theme.command_name(scenario.title.ljust(68))} {self.theme.muted('│')}")
            print(f"{self.theme.muted('├' + border + '┤')}")

            # Context
            print(f"{self.theme.muted('│')} {self.theme.bold_white('Context:').ljust(76)} {self.theme.muted('│')}")
            for line in self._wrap_text(scenario.context, 66):
                print(f"{self.theme.muted('│')}   {line.ljust(66)} {self.theme.muted('│')}")

            # Approach
            print(f"{self.theme.muted('│')}{' ' * 70}{self.theme.muted('│')}")
            print(f"{self.theme.muted('│')} {self.theme.bold_white('Approach:').ljust(76)} {self.theme.muted('│')}")
            for line in self._wrap_text(scenario.approach, 66):
                print(f"{self.theme.muted('│')}   {line.ljust(66)} {self.theme.muted('│')}")

            # Expected Outcome
            print(f"{self.theme.muted('│')}{' ' * 70}{self.theme.muted('│')}")
            print(f"{self.theme.muted('│')} {self.theme.bold_white('Expected Outcome:').ljust(76)} {self.theme.muted('│')}")
            for line in self._wrap_text(scenario.expected_outcome, 66):
                print(f"{self.theme.muted('│')}   {line.ljust(66)} {self.theme.muted('│')}")

            # Why This Works
            print(f"{self.theme.muted('│')}{' ' * 70}{self.theme.muted('│')}")
            print(f"{self.theme.muted('│')} {self.theme.bold_white('Why This Works:').ljust(76)} {self.theme.muted('│')}")
            for line in self._wrap_text(scenario.why_this_works, 66):
                print(f"{self.theme.muted('│')}   {line.ljust(66)} {self.theme.muted('│')}")

            print(f"{self.theme.muted('└' + border + '┘')}\n")

    def _render_sections(self, sheet: Cheatsheet):
        """Render command sections"""
        command_counter = 1

        for section in sheet.sections:
            # Section header
            print(f"{self.theme.primary(f'═══ {section.title.upper()} ═══')}\n")
            print(f"{self.theme.info(section.notes)}\n")

            # Commands in this section
            for cmd_id in section.commands:
                cmd = self.command_registry.get_command(cmd_id)
                if not cmd:
                    print(f"  {self.theme.warning(f'{command_counter}. [Command not found: {cmd_id}]')}\n")
                    command_counter += 1
                    continue

                # Command header
                print(f"  {self.theme.bold_white(f'{command_counter}.')} {self.theme.command_name(cmd.name)}")
                print(f"     {self.theme.secondary(cmd.command)}")

                # Brief description
                if cmd.description:
                    print(f"     {self.theme.hint(cmd.description)}")

                # Success/failure indicators (brief)
                if cmd.success_indicators:
                    success_str = ', '.join(cmd.success_indicators[:2])
                    print(f"     {self.theme.success('✓ Success:')} {self.theme.info(success_str)}")

                if cmd.failure_indicators:
                    failure_str = ', '.join(cmd.failure_indicators[:2])
                    print(f"     {self.theme.error('✗ Failure:')} {self.theme.info(failure_str)}")

                print()
                command_counter += 1

    def _render_footer(self, total_commands: int):
        """Render usage footer"""
        border = '═' * 70
        print(f"{self.theme.muted(border)}")
        print(f"{self.theme.hint('Press number to fill command, or:')}")
        print(f"  {self.theme.primary('crack cheatsheets <id> <number>')} - Fill specific command")
        print(f"  {self.theme.primary('crack cheatsheets <id> --fill-all')} - Fill all commands\n")

    def _collect_all_commands(self, sheet: Cheatsheet) -> List[str]:
        """
        Collect all command IDs in order from sections

        Args:
            sheet: Cheatsheet object

        Returns:
            List of command IDs in display order
        """
        commands = []
        for section in sheet.sections:
            commands.extend(section.commands)
        return commands

    def _wrap_text(self, text: str, width: int) -> List[str]:
        """
        Wrap text to specified width while preserving newlines and applying theme colors

        Handles:
        - Newline preservation (\n creates new lines)
        - Indentation detection and preservation (leading spaces)
        - Theme colorization for steps, commands, traffic flows

        Args:
            text: Text to wrap (may contain \n for intentional breaks)
            width: Maximum line width

        Returns:
            List of wrapped lines with theme colors applied
        """
        import re

        result_lines = []
        paragraphs = text.split('\n')

        for para in paragraphs:
            # Empty line - preserve as spacing
            if not para.strip():
                result_lines.append('')
                continue

            # Detect indentation (leading spaces)
            indent_match = re.match(r'^(\s+)', para)
            indent = indent_match.group(1) if indent_match else ''
            indent_len = len(indent)
            content = para[indent_len:]  # Strip indent for processing

            # Detect line type and apply theme color
            colored_content = content
            effective_width = width - indent_len

            # WARNING/CRITICAL/PITFALL markers - Use notes_warning for high visibility
            if re.match(r'^(WARNING|CRITICAL|PITFALL):', content, re.IGNORECASE):
                marker_match = re.match(r'^([A-Z]+:)(.*)$', content)
                if marker_match:
                    label = self.theme.notes_warning(marker_match.group(1))
                    rest = self.theme.info(marker_match.group(2)) if marker_match.group(2).strip() else ''
                    colored_content = label + rest

            # TIP/EXAM TIP markers - Use notes_tip for helpful info
            elif re.match(r'^(TIP|EXAM TIP):', content, re.IGNORECASE):
                tip_match = re.match(r'^([^:]+:)(.*)$', content)
                if tip_match:
                    label = self.theme.notes_tip(tip_match.group(1))
                    rest = self.theme.info(tip_match.group(2)) if tip_match.group(2).strip() else ''
                    colored_content = label + rest

            # SUCCESS/EXPECTED OUTPUT markers - Use notes_success
            elif re.match(r'^(SUCCESS|EXPECTED OUTPUT|EXPECTED):', content, re.IGNORECASE):
                success_match = re.match(r'^([^:]+:)(.*)$', content)
                if success_match:
                    label = self.theme.notes_success(success_match.group(1))
                    rest = self.theme.info(success_match.group(2)) if success_match.group(2).strip() else ''
                    colored_content = label + rest

            # FAILURE/ERROR markers - Use notes_failure
            elif re.match(r'^(FAILURE|ERROR|FAILED):', content, re.IGNORECASE):
                failure_match = re.match(r'^([^:]+:)(.*)$', content)
                if failure_match:
                    label = self.theme.notes_failure(failure_match.group(1))
                    rest = self.theme.info(failure_match.group(2)) if failure_match.group(2).strip() else ''
                    colored_content = label + rest

            # Section headers (all caps words followed by colon) - Use notes_section
            elif re.match(r'^[A-Z][A-Z\s]+:', content):
                section_match = re.match(r'^([A-Z][A-Z\s]+:)(.*)$', content)
                if section_match:
                    label = self.theme.notes_section(section_match.group(1))
                    rest = self.theme.info(section_match.group(2)) if section_match.group(2).strip() else ''
                    colored_content = label + rest

            # Step labels: "Step N:" or "Step (N):" - Use notes_step for prominence
            elif re.match(r'^Step (\d+|\(\d+\)):', content):
                step_match = re.match(r'^(Step (?:\d+|\(\d+\)):)(.*)$', content)
                if step_match:
                    label = self.theme.notes_step(step_match.group(1))
                    rest = self.theme.info(step_match.group(2)) if step_match.group(2).strip() else ''
                    colored_content = label + rest

            # Numbered steps: "(1)", "(2)", "1.", "2." at start of line - Use notes_step
            elif re.match(r'^(\(\d+\)|\d+\.)\s', content):
                num_match = re.match(r'^((?:\(\d+\)|\d+\.))\s(.*)$', content)
                if num_match:
                    label = self.theme.notes_step(num_match.group(1))
                    rest = self.theme.info(num_match.group(2)) if num_match.group(2).strip() else ''
                    colored_content = label + ' ' + rest

            # Traffic flow summary - Use info/muted for less emphasis
            elif content.startswith('Traffic:'):
                traffic_match = re.match(r'^(Traffic:)(.*)$', content)
                if traffic_match:
                    label = self.theme.info('Traffic:')
                    rest = self.theme.info(traffic_match.group(2)) if traffic_match.group(2).strip() else ''
                    colored_content = label + rest

            # Indented lines (commands) - Use notes_code for code-like appearance
            elif indent_len >= 2:
                colored_content = self.theme.notes_code(content)

            # Limitation/Alternative markers - Use warning for attention
            elif content.startswith('Limitation:') or content.startswith('Alternative:'):
                marker_match = re.match(r'^(Limitation:|Alternative:)(.*)$', content)
                if marker_match:
                    label = self.theme.warning(marker_match.group(1))
                    rest = self.theme.info(marker_match.group(2)) if marker_match.group(2).strip() else ''
                    colored_content = label + rest

            # Timing markers - Use hint for muted emphasis
            elif re.match(r'^Time:', content):
                time_match = re.match(r'^(Time:)(.*)$', content)
                if time_match:
                    label = self.theme.hint('Time:')
                    rest = self.theme.info(time_match.group(2)) if time_match.group(2).strip() else ''
                    colored_content = label + rest

            # Default: regular paragraph text - Use info color for theme consistency
            else:
                # Don't color here - will be done after word wrap
                pass  # Keep colored_content as plain content

            # Word wrap the content (may already have colors from pattern matching)
            wrapped = self._word_wrap(colored_content, effective_width)

            # Apply theme color to each wrapped line (for non-patterned text)
            # Check if content was already colored by pattern matching
            has_ansi = '\033[' in colored_content or colored_content != content

            for line in wrapped:
                # If no pattern matched and this is regular text, color it now
                if not has_ansi and content.strip():
                    colored_line = self.theme.info(line)
                else:
                    colored_line = line
                result_lines.append(indent + colored_line)

        return result_lines if result_lines else ['']

    def _word_wrap(self, text: str, width: int) -> List[str]:
        """
        Word-wrap text to specified width, preserving ANSI color codes

        Args:
            text: Text to wrap (may contain ANSI codes)
            width: Maximum line width (excluding ANSI codes)

        Returns:
            List of wrapped lines
        """
        # Strip ANSI codes for length calculation
        from crack.themes import Colors
        plain_text = Colors.strip(text)

        # If line fits, return as-is
        if len(plain_text) <= width:
            return [text]

        # Simple word wrapping (preserves ANSI codes in original text)
        words = text.split()
        lines = []
        current_line = []
        current_length = 0

        for word in words:
            plain_word = Colors.strip(word)
            word_length = len(plain_word)

            # Check if adding word exceeds width
            space_needed = 1 if current_line else 0
            if current_length + word_length + space_needed <= width:
                current_line.append(word)
                current_length += word_length + space_needed
            else:
                # Start new line
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
                current_length = word_length

        # Add remaining words
        if current_line:
            lines.append(' '.join(current_line))

        return lines if lines else ['']
