"""
CLI handler for attack chains management
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from crack.reference.cli.base import BaseCLIHandler
from crack.reference.chains.loader import ChainLoader
from crack.reference.chains.registry import ChainRegistry
from crack.reference.chains.command_resolver import CommandResolver


class ChainsCLI(BaseCLIHandler):
    """CLI for attack chains management"""

    def __init__(self, chain_loader=None, chain_registry=None, command_resolver=None, theme=None):
        """Initialize chains CLI

        Args:
            chain_loader: ChainLoader instance
            chain_registry: ChainRegistry instance
            command_resolver: CommandResolver instance
            theme: ReferenceTheme instance
        """
        super().__init__(theme)
        self.loader = chain_loader or ChainLoader()
        self.registry = chain_registry or ChainRegistry()
        self.resolver = command_resolver or CommandResolver()
        self._loaded = False

    def _ensure_loaded(self):
        """Lazy load chains from data directory"""
        if self._loaded:
            return

        # Load chains from data directory
        data_dir = Path(__file__).parent.parent / 'data' / 'attack_chains'
        if data_dir.exists():
            try:
                chains = self.loader.load_all_chains([data_dir])
                for chain_id, chain_data in chains.items():
                    self.registry.register_chain(chain_id, chain_data)
                self._loaded = True
            except ValueError as e:
                print(self.format_error(f"Failed to load chains: {e}"))

    def list_or_show(self, query: Optional[str] = None,
                     format: str = 'text', verbose: bool = False) -> int:
        """Unified handler for chain listing/searching/showing

        Args:
            query: None (list all), keyword (search), chain ID (show), or keyword + number (select)
            format: Output format (text, json, yaml)
            verbose: Show detailed info

        Behavior:
            - No query: List all chains
            - Query ends with number: Search/list + auto-select by number
            - Valid ID: Show specific chain details
            - Keyword: Search chains by name/tags/description

        Returns:
            Exit code (0 for success)

        Examples:
            chains.list_or_show()  # List all
            chains.list_or_show('sqli')  # Search
            chains.list_or_show('sqli 1')  # Search + select first result
            chains.list_or_show('linux-privesc-suid-basic')  # Show specific
        """
        self._ensure_loaded()

        selection = None

        # Check if query ends with a number (for numbered selection)
        if query and query.split()[-1].isdigit():
            parts = query.rsplit(None, 1)
            actual_query = parts[0] if len(parts) > 1 else None
            selection = int(parts[-1]) - 1  # Convert to 0-indexed
            query = actual_query

        # No query - list all
        if not query:
            chains = list(self.registry.filter_chains())
            if selection is not None:
                return self._handle_selection(chains, selection)
            return self.list(format=format)

        # Check if query matches a chain ID (exact match)
        chain = self.registry.get_chain(query)
        if chain:
            return self.show(query, format=format)

        # Otherwise treat as search keyword
        chains = self._search_chains(query)

        if selection is not None:
            # User wants to select by number from search results
            if not chains:
                print("No attack chains found matching criteria")
                return 1
            return self._handle_selection(chains, selection)

        # Display search results
        if not chains:
            print("No attack chains found matching criteria")
            return 0

        # Format output
        if format == 'json':
            import json
            print(json.dumps(chains, indent=2))
        elif format == 'yaml':
            try:
                import yaml
                print(yaml.dump(chains, default_flow_style=False))
            except ImportError:
                print(self.format_error("PyYAML not installed. Use 'pip install pyyaml'"))
                return 1
        else:  # text format
            if verbose:
                # Show detailed view for each chain
                for i, chain in enumerate(chains):
                    if i > 0:
                        print('\n' + '─' * 80 + '\n')
                    self._format_chain_details_text(chain)
            else:
                # Show summary list
                self._format_chain_list_text(chains)

        return 0

    def search(self, query: Optional[str] = None,
               oscp_relevant: Optional[bool] = None,
               format: str = 'text',
               verbose: bool = False) -> int:
        """Search attack chains by keyword

        Args:
            query: Search term to filter chains (searches name, description, tags, steps)
            oscp_relevant: Filter by OSCP relevance
            format: Output format (text, json, yaml)
            verbose: Show detailed information

        Returns:
            Exit code (0 for success)

        Examples:
            chains.search('sqli')
            chains.search('privesc', oscp_relevant=True)
            chains.search(format='json')
        """
        self._ensure_loaded()

        # Build filter criteria
        criteria = {}
        if oscp_relevant is not None:
            criteria['oscp_relevant'] = oscp_relevant

        # Get all chains matching criteria
        chains = list(self.registry.filter_chains(**criteria))

        # Apply keyword search if query provided
        if query:
            query_lower = query.lower()
            filtered_chains = []

            for chain in chains:
                # Search in multiple fields
                searchable_text = ' '.join([
                    chain.get('id', ''),
                    chain.get('name', ''),
                    chain.get('description', ''),
                    ' '.join(chain.get('metadata', {}).get('tags', [])),
                    chain.get('metadata', {}).get('category', ''),
                    chain.get('metadata', {}).get('platform', ''),
                    # Also search step names and descriptions
                    ' '.join([step.get('name', '') + ' ' + step.get('description', '')
                             for step in chain.get('steps', [])])
                ]).lower()

                if query_lower in searchable_text:
                    filtered_chains.append(chain)

            chains = filtered_chains

        if not chains:
            print("No attack chains found matching criteria")
            return 0

        # Format output
        if format == 'json':
            import json
            print(json.dumps(chains, indent=2))
        elif format == 'yaml':
            try:
                import yaml
                print(yaml.dump(chains, default_flow_style=False))
            except ImportError:
                print(self.format_error("PyYAML not installed. Use 'pip install pyyaml'"))
                return 1
        else:  # text format
            if verbose:
                # Show detailed view for each chain
                for i, chain in enumerate(chains):
                    if i > 0:
                        print('\n' + '─' * 80 + '\n')
                    self._format_chain_details_text(chain)
            else:
                # Show summary list
                self._format_chain_list_text(chains)

        return 0

    def list(self, category: Optional[str] = None,
             platform: Optional[str] = None,
             difficulty: Optional[str] = None,
             oscp_relevant: Optional[bool] = None,
             format: str = 'text') -> int:
        """List attack chains with filtering

        Args:
            category: Filter by category (enumeration, privilege_escalation, etc.)
            platform: Filter by platform (linux, windows, web, etc.)
            difficulty: Filter by difficulty (beginner, intermediate, advanced, expert)
            oscp_relevant: Filter by OSCP relevance
            format: Output format (text, json, yaml)

        Returns:
            Exit code (0 for success)

        Examples:
            chains.list(category='privilege_escalation')
            chains.list(platform='linux', difficulty='beginner')
            chains.list(oscp_relevant=True, format='json')
        """
        self._ensure_loaded()

        # Build filter criteria
        criteria = {}
        if category:
            criteria['metadata.category'] = category
        if platform:
            criteria['metadata.platform'] = platform
        if difficulty:
            criteria['difficulty'] = difficulty
        if oscp_relevant is not None:
            criteria['oscp_relevant'] = oscp_relevant

        # Query registry
        chains = list(self.registry.filter_chains(**criteria))

        if not chains:
            print("No attack chains found matching criteria")
            return 0

        # Format output
        if format == 'json':
            print(json.dumps(chains, indent=2))
        elif format == 'yaml':
            try:
                import yaml
                print(yaml.dump(chains, default_flow_style=False))
            except ImportError:
                print(self.format_error("PyYAML not installed. Use 'pip install pyyaml'"))
                return 1
        else:  # text format
            self._format_chain_list_text(chains)

        return 0

    def show(self, chain_id: str, format: str = 'text') -> int:
        """Show full chain details with resolved commands

        Args:
            chain_id: Unique chain identifier
            format: Output format (text, json, yaml)

        Returns:
            Exit code (0 for success, 1 for not found)

        Examples:
            chains.show('linux-privesc-suid-basic')
            chains.show('web-sqli-union-dump', format='json')
        """
        self._ensure_loaded()

        # Load chain
        chain = self.registry.get_chain(chain_id)
        if not chain:
            print(self.format_error(f"Chain not found: {chain_id}"))
            return 1

        # Format output
        if format == 'json':
            print(json.dumps(chain, indent=2))
        elif format == 'yaml':
            try:
                import yaml
                print(yaml.dump(chain, default_flow_style=False))
            except ImportError:
                print(self.format_error("PyYAML not installed. Use 'pip install pyyaml'"))
                return 1
        else:  # text format
            self._format_chain_details_text(chain)

        return 0

    def validate(self, chain_path: Optional[str] = None, strict: bool = False) -> int:
        """Validate attack chain files

        Args:
            chain_path: Specific chain file to validate (validates all if None)
            strict: Enable strict validation (circular dependency checks)

        Returns:
            Exit code (0 for success, 1 for validation errors)

        Examples:
            chains.validate()  # Validate all
            chains.validate(chain_path='linux-privesc.json')
            chains.validate(strict=True)
        """
        print("Validating attack chains...")

        # Determine what to validate
        if chain_path:
            paths = [Path(chain_path)]
        else:
            data_dir = Path(__file__).parent.parent / 'data' / 'attack_chains'
            paths = [data_dir]

        # Load and validate
        errors: Dict[Path, str] = {}
        try:
            chains = self.loader.load_all_chains(paths)
            print(self.format_success(f"Successfully validated {len(chains)} chain(s)"))

            # Print summary
            for chain_id, chain_data in chains.items():
                print(f"  {self.theme.primary('✓')} {chain_id}: {chain_data.get('name', 'Unknown')}")

            return 0
        except ValueError as e:
            # Parse error message to extract individual errors
            error_msg = str(e)
            print(self.format_error("Validation failed:"))
            print(f"\n{error_msg}\n")
            return 1

    def _search_chains(self, query: Optional[str] = None,
                      oscp_relevant: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Search and filter chains (extracted helper method)

        Args:
            query: Search term to filter chains
            oscp_relevant: Filter by OSCP relevance

        Returns:
            List of matching chain dictionaries
        """
        # Build filter criteria
        criteria = {}
        if oscp_relevant is not None:
            criteria['oscp_relevant'] = oscp_relevant

        # Get all chains matching criteria
        chains = list(self.registry.filter_chains(**criteria))

        # Apply keyword search if query provided
        if query:
            query_lower = query.lower()
            filtered_chains = []

            for chain in chains:
                # Search in multiple fields
                searchable_text = ' '.join([
                    chain.get('id', ''),
                    chain.get('name', ''),
                    chain.get('description', ''),
                    ' '.join(chain.get('metadata', {}).get('tags', [])),
                    chain.get('metadata', {}).get('category', ''),
                    chain.get('metadata', {}).get('platform', ''),
                    # Also search step names and descriptions
                    ' '.join([step.get('name', '') + ' ' + step.get('description', '')
                             for step in chain.get('steps', [])])
                ]).lower()

                if query_lower in searchable_text:
                    filtered_chains.append(chain)

            chains = filtered_chains

        return chains

    def _handle_selection(self, chains: List[Dict[str, Any]], selection: int) -> int:
        """Handle numeric selection from chain list

        Args:
            chains: List of chain dictionaries
            selection: 0-indexed selection number

        Returns:
            Exit code (0 for success, 1 for error)
        """
        if 0 <= selection < len(chains):
            chain = chains[selection]
            chain_id = chain.get('id', 'Unknown')
            # Show full details for selected chain
            return self.show(chain_id, format='text')
        else:
            print(self.format_error(f"Invalid selection: {selection + 1} (only {len(chains)} chain(s) found)"))
            return 1

    def _format_chain_list_text(self, chains: List[Dict[str, Any]]):
        """Format chain list in text format (numbered for selection)

        Args:
            chains: List of chain dictionaries
        """
        self.print_banner("ATTACK CHAINS")

        # Numbered list format (like normal commands)
        for i, chain in enumerate(chains, 1):
            chain_id = chain.get('id', 'Unknown')
            name = chain.get('name', 'Unknown')
            category = chain.get('metadata', {}).get('category', 'Unknown')
            difficulty = chain.get('difficulty', 'Unknown')
            time_est = chain.get('time_estimate', 'Unknown')
            oscp = 'OSCP' if chain.get('oscp_relevant', False) else ''

            # Number + ID + Name (color-coded)
            print(f"\n{self.theme.muted(f'{i}.')} [{self.theme.primary(chain_id)}] {self.theme.command_name(name)}")

            # Metadata line
            tags = f"{self.theme.secondary(category)} • {difficulty}"
            if time_est and time_est != 'Unknown':
                tags += f" • {time_est}"
            if oscp:
                tags += f" • {self.theme.success(oscp)}"
            print(f"   {tags}")

        print(f"\n{self.theme.hint(f'Total: {len(chains)} chain(s)')}")
        print(f"{self.theme.hint('Use: crack reference --chains <id> to view details')}")
        print(f"{self.theme.hint('Use: crack reference --chains <query> <number> to select')}")

    def execute_interactive(self, chain_id: str, target: Optional[str] = None, resume: bool = False) -> int:
        """Launch interactive chain execution

        Args:
            chain_id: Unique chain identifier
            target: Target IP/hostname (prompts if None)
            resume: Resume from saved session

        Returns:
            Exit code (0 for success)
        """
        try:
            from crack.reference.chains.interactive import ChainInteractive

            executor = ChainInteractive(chain_id, target, resume)
            executor.run()
            return 0

        except ValueError as e:
            print(self.format_error(str(e)))
            return 1
        except KeyboardInterrupt:
            print(f"\n{self.theme.warning('Interrupted by user')}")
            return 1
        except Exception as e:
            print(self.format_error(f"Interactive execution failed: {str(e)}"))
            return 1

    def _format_chain_details_text(self, chain: Dict[str, Any]):
        """Format chain details in text format

        Args:
            chain: Chain dictionary
        """
        # Header
        self.print_banner(chain.get('name', 'Unknown Chain'))

        # Basic info
        print(f"{self.theme.primary('ID:')} {self.theme.secondary(chain.get('id', 'Unknown'))}")
        print(f"{self.theme.primary('Version:')} {chain.get('version', 'Unknown')}")

        # Metadata
        metadata = chain.get('metadata', {})
        category = metadata.get('category', 'Unknown')
        platform = metadata.get('platform', 'Not specified')
        print(f"{self.theme.primary('Category:')} {self.theme.secondary(category)}")
        print(f"{self.theme.primary('Platform:')} {platform}")

        # Difficulty and time
        difficulty = chain.get('difficulty', 'Unknown')
        time_est = chain.get('time_estimate', 'Unknown')
        oscp = 'Yes' if chain.get('oscp_relevant', False) else 'No'

        difficulty_color = (
            self.theme.success if difficulty == 'beginner' else
            self.theme.warning if difficulty == 'intermediate' else
            self.theme.error
        )
        print(f"{self.theme.primary('Difficulty:')} {difficulty_color(difficulty.upper())}")
        print(f"{self.theme.primary('Time Estimate:')} {time_est}")
        print(f"{self.theme.primary('OSCP Relevant:')} {self.theme.success(oscp) if oscp == 'Yes' else self.theme.muted(oscp)}")

        # Description
        print(f"\n{self.theme.primary('Description:')}")
        print(f"  {chain.get('description', 'No description available')}")

        # Tags
        tags = metadata.get('tags', [])
        if tags:
            print(f"\n{self.theme.primary('Tags:')} {', '.join([self.theme.secondary(tag) for tag in tags])}")

        # Prerequisites
        prereqs = chain.get('prerequisites', [])
        if prereqs:
            print(f"\n{self.theme.primary('Prerequisites:')}")
            for prereq in prereqs:
                print(f"  {self.theme.hint('•')} {prereq}")

        # Steps
        steps = chain.get('steps', [])
        if steps:
            print(f"\n{self.theme.primary('Steps:')}")
            for i, step in enumerate(steps, 1):
                step_name = step.get('name', 'Unknown')
                objective = step.get('objective', 'No objective specified')
                command_ref = step.get('command_ref', 'Unknown')

                print(f"\n  {self.theme.command_name(f'{i}. {step_name}')}")
                print(f"     {self.theme.hint('Objective:')} {objective}")
                print(f"     {self.theme.hint('Command Ref:')} {self.theme.primary(command_ref)}")

                # Try to resolve command reference and show raw command
                try:
                    resolved = self.resolver.resolve_command_ref(command_ref)
                    if resolved:
                        # Show raw command with placeholders
                        raw_command = resolved.command if hasattr(resolved, 'command') else resolved.get('command', 'Unknown')
                        print(f"     {self.theme.hint('Raw Command:')} {self.theme.secondary(raw_command)}")
                    else:
                        print(f"     {self.theme.error('(Command not found in registry)')}")
                except Exception as e:
                    print(f"     {self.theme.error(f'(Failed to resolve: {e})')}")

                # Description
                desc = step.get('description')
                if desc:
                    print(f"     {self.theme.muted(desc)}")

        # Notes
        notes = chain.get('notes')
        if notes:
            print(f"\n{self.theme.primary('Notes:')}")
            print(f"  {notes}")

        # Footer
        self.print_separator()
        print(self.theme.hint(f"Use 'crack reference --chains {chain.get('id', 'CHAIN_ID')} -i' for interactive execution"))
        print(self.theme.hint(f"Use 'crack reference --chains {chain.get('id', 'CHAIN_ID')} --format json' for machine-readable output"))
        print()
