"""
Attack Chain Visualizer CLI

Command-line interface for dynamic chain visualization with search/filter integration.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Dict, Optional

# Import visualizer components
from .filters import ChainFilter
from .graph_builder import ChainGraphBuilder
from .renderers import AsciiRenderer, DotRenderer
from .models import Graph

# ANSI colors
CYAN = '\033[36m'
YELLOW = '\033[33m'
GREEN = '\033[32m'
RED = '\033[31m'
DIM = '\033[2m'
BOLD = '\033[1m'
RESET = '\033[0m'


class VisualizerCLI:
    """CLI interface for attack chain visualization"""

    def __init__(self):
        """Initialize CLI"""
        # Import chain components
        try:
            from crack.reference.chains import ChainRegistry
            from crack.reference.chains.loader import ChainLoader
            from pathlib import Path

            self.registry = ChainRegistry()

            # Load all chains from data directory
            loader = ChainLoader()
            chains_dir = Path(__file__).parent.parent / 'reference' / 'data' / 'attack_chains'

            if chains_dir.exists():
                chains = loader.load_all_chains([chains_dir])
                for chain_id, chain in chains.items():
                    self.registry.register_chain(chain_id, chain)
            else:
                print(f"{YELLOW}Warning: Attack chains directory not found: {chains_dir}{RESET}")

        except ImportError as e:
            print(f"{RED}Error: Chain registry not available{RESET}")
            print(f"Import error: {e}")
            print("Ensure crack.reference.chains is installed")
            sys.exit(1)
        except Exception as e:
            print(f"{RED}Error loading attack chains: {e}{RESET}")
            sys.exit(1)

        self.filter = ChainFilter(self.registry)
        self.builder = ChainGraphBuilder()

    def run(self, args: List[str]) -> int:
        """
        Main CLI entry point

        Args:
            args: Command-line arguments

        Returns:
            Exit code (0 = success)
        """
        # Strip "chains" subcommand if present
        if args and args[0] == 'chains':
            args = args[1:]

        parser = self._build_parser()
        parsed_args = parser.parse_args(args)

        # Handle no arguments - show interactive menu
        if not any([parsed_args.chain_query,
                   parsed_args.all,
                   parsed_args.category,
                   parsed_args.tags,
                   parsed_args.search]):
            return self._interactive_menu()

        # Filter chains based on arguments
        chains = self._filter_chains(parsed_args)

        if not chains:
            print(f"{RED}No chains match criteria{RESET}")
            return 1

        # Handle single chain selection if multiple results
        if len(chains) > 1 and not parsed_args.all and parsed_args.interactive:
            chain = self._select_chain(chains)
            if not chain:
                return 0  # User cancelled
            chains = [chain]

        # Build graph
        mode = parsed_args.mode
        if not mode:
            # Auto-detect mode
            if len(chains) == 1:
                mode = 'detail'
            elif len(chains) <= 10:
                mode = 'relationships'
            else:
                mode = 'overview'

        if mode == 'detail' and len(chains) > 1:
            print(f"{YELLOW}Warning: Multiple chains found, showing first match in detail mode{RESET}")
            graph = self.builder.build_single_chain(chains[0])
        elif mode == 'detail':
            graph = self.builder.build_single_chain(chains[0])
        elif mode == 'relationships':
            graph = self.builder.build_multi_chain(chains)
        else:  # overview
            graph = self.builder.build_ecosystem(chains)

        # Render graph
        output_format = parsed_args.format
        use_colors = not parsed_args.no_color and sys.stdout.isatty()

        if output_format == 'ascii':
            renderer = AsciiRenderer(use_colors=use_colors)
        elif output_format == 'dot':
            renderer = DotRenderer()
        else:
            print(f"{RED}Error: Unknown format '{output_format}'{RESET}")
            return 1

        output = renderer.render(graph)

        # Output
        if parsed_args.output:
            Path(parsed_args.output).write_text(output)
            print(f"{GREEN}✓{RESET} Graph exported to: {parsed_args.output}")

            # Suggest next steps for DOT format
            if output_format == 'dot':
                print(f"\n{DIM}Generate PNG:{RESET}")
                print(f"  dot -Tpng {parsed_args.output} -o graph.png")
                print(f"\n{DIM}Generate SVG:{RESET}")
                print(f"  dot -Tsvg {parsed_args.output} -o graph.svg")
        else:
            print(output)

        return 0

    def _build_parser(self) -> argparse.ArgumentParser:
        """Build argument parser"""
        parser = argparse.ArgumentParser(
            prog='crack visualize chains',
            description='Dynamic attack chain visualization with search/filter integration',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f"""{CYAN}Examples:{RESET}

  # Visualize specific chain
  crack visualize chains linux-privesc-sudo

  # Search and visualize
  crack visualize chains "docker privilege"

  # Filter by multiple tags
  crack visualize chains --tag OSCP QUICK_WIN

  # View entire ecosystem
  crack visualize chains --all

  # Export to DOT format
  crack visualize chains linux-privesc-sudo --format dot -o graph.dot

  # Generate PNG (requires graphviz)
  dot -Tpng graph.dot -o graph.png
            """
        )

        # Positional argument
        parser.add_argument(
            'chain_query',
            nargs='?',
            help='Chain ID or search query'
        )

        # Filtering options
        filter_group = parser.add_argument_group('Filtering Options')
        filter_group.add_argument(
            '--all',
            action='store_true',
            help='Visualize entire ecosystem'
        )
        filter_group.add_argument(
            '--category',
            help='Filter by category (enumeration, privilege_escalation, etc.)'
        )
        filter_group.add_argument(
            '--tag',
            nargs='+',
            dest='tags',
            help='Filter by tag(s) - space-separated (e.g., --tag OSCP QUICK_WIN)'
        )
        filter_group.add_argument(
            '--difficulty',
            choices=['beginner', 'intermediate', 'advanced'],
            help='Filter by difficulty level'
        )
        filter_group.add_argument(
            '--oscp-only',
            action='store_true',
            help='Only OSCP-relevant chains'
        )
        filter_group.add_argument(
            '--search',
            help='Search chain names/descriptions'
        )

        # Display options
        display_group = parser.add_argument_group('Display Options')
        display_group.add_argument(
            '--mode',
            choices=['detail', 'relationships', 'overview'],
            help='Visualization mode (auto-detect by default)'
        )
        display_group.add_argument(
            '--related',
            action='store_true',
            help='Show chains that activate from result'
        )
        display_group.add_argument(
            '--show-activations',
            action='store_true',
            help='Include activation edges'
        )

        # Output options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument(
            '--format',
            choices=['ascii', 'dot'],
            default='ascii',
            help='Output format (default: ascii)'
        )
        output_group.add_argument(
            '-o', '--output',
            help='Export to file'
        )
        output_group.add_argument(
            '--no-color',
            action='store_true',
            help='Disable colors'
        )

        # Interactive options
        parser.add_argument(
            '-i', '--interactive',
            action='store_true',
            help='Show selection menu if multiple results'
        )

        return parser

    def _filter_chains(self, args) -> List[Dict]:
        """Filter chains based on parsed arguments"""
        if args.all:
            return self.filter.get_all_chains()

        # Build filter parameters
        filter_params = {}

        if args.chain_query:
            # Try exact ID match first
            chain = self.registry.get_chain(args.chain_query)
            if chain:
                chains = [chain]
            else:
                # Fuzzy search
                filter_params['search_term'] = args.chain_query
                chains = self.filter.filter_chains(**filter_params)
        else:
            chains = None

        # Apply additional filters
        if args.category:
            filter_params['category'] = args.category
        if args.tags:
            filter_params['tags'] = args.tags
        if args.difficulty:
            filter_params['difficulty'] = args.difficulty
        if args.oscp_only:
            filter_params['oscp_relevant'] = True
        if args.search:
            filter_params['search_term'] = args.search

        # Apply filters
        if chains and filter_params:
            # Filter already-found chains
            chains = self.filter.filter_chains(
                chain_ids=[c['id'] for c in chains],
                **filter_params
            )
        elif filter_params:
            chains = self.filter.filter_chains(**filter_params)
        elif not chains:
            chains = []

        return chains

    def _select_chain(self, chains: List[Dict]) -> Optional[Dict]:
        """
        Interactive chain selection

        Args:
            chains: List of matching chains

        Returns:
            Selected chain or None if cancelled
        """
        print(f"\n{YELLOW}Found {len(chains)} matching chains:{RESET}\n")

        for i, chain in enumerate(chains[:10], 1):
            name = chain.get('name', chain['id'])
            category = chain.get('metadata', {}).get('category', 'N/A')
            tags = chain.get('metadata', {}).get('tags', [])

            # Highlight OSCP/QUICK_WIN
            tag_str = ""
            oscp_tags = [t for t in tags if 'OSCP' in t or t == 'QUICK_WIN']
            if oscp_tags:
                tag_str = f" [{GREEN}{', '.join(oscp_tags[:2])}{RESET}]"

            print(f"  {BOLD}[{i}]{RESET} {CYAN}{name}{RESET}")
            print(f"      Category: {category}{tag_str}")

        if len(chains) > 10:
            print(f"\n  {DIM}... and {len(chains) - 10} more{RESET}")

        print(f"\n{YELLOW}Options:{RESET}")
        print(f"  [1-{min(10, len(chains))}] Select specific chain")
        print(f"  [a] Visualize all results")
        print(f"  [q] Cancel")

        try:
            choice = input(f"\n{YELLOW}Select:{RESET} ").strip().lower()

            if choice == 'q':
                return None
            elif choice == 'a':
                # Return None to signal "show all"
                return None
            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(chains):
                    return chains[idx]
        except (KeyboardInterrupt, EOFError):
            print()
            return None

        print(f"{RED}Invalid selection{RESET}")
        return None

    def _interactive_menu(self) -> int:
        """
        Interactive menu when no arguments provided

        Returns:
            Exit code
        """
        print(f"\n{CYAN}{'=' * 70}{RESET}")
        print(f"{BOLD}CRACK Attack Chain Visualizer{RESET}".center(70))
        print(f"{CYAN}{'=' * 70}{RESET}\n")

        print("What would you like to visualize?\n")
        print(f"  {BOLD}[1]{RESET} Specific chain (by ID or name)")
        print(f"  {BOLD}[2]{RESET} Filter by category")
        print(f"  {BOLD}[3]{RESET} Filter by tags")
        print(f"  {BOLD}[4]{RESET} Search chains")
        print(f"  {BOLD}[5]{RESET} View all chains (ecosystem)")
        print(f"  {BOLD}[q]{RESET} Quit\n")

        try:
            choice = input(f"{YELLOW}Select option:{RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return 0

        if choice == '1':
            query = input(f"{YELLOW}Enter chain ID or name:{RESET} ").strip()
            return self.run([query, '-i'])

        elif choice == '2':
            categories = self.filter.get_categories()
            print(f"\n{CYAN}Available categories:{RESET}")
            for i, cat in enumerate(categories, 1):
                print(f"  {i}. {cat}")
            cat_choice = input(f"{YELLOW}Select category number:{RESET} ").strip()
            if cat_choice.isdigit() and 1 <= int(cat_choice) <= len(categories):
                return self.run(['--category', categories[int(cat_choice) - 1], '-i'])

        elif choice == '3':
            tags = self.filter.get_all_tags()
            print(f"\n{CYAN}Available tags:{RESET}")
            common_tags = ['OSCP', 'OSCP:HIGH', 'QUICK_WIN', 'AUTOMATED', 'LINUX', 'WINDOWS']
            display_tags = [t for t in common_tags if t in tags]
            for i, tag in enumerate(display_tags[:10], 1):
                print(f"  {i}. {tag}")
            tag_choice = input(f"{YELLOW}Select tag number:{RESET} ").strip()
            if tag_choice.isdigit() and 1 <= int(tag_choice) <= len(display_tags):
                return self.run(['--tag', display_tags[int(tag_choice) - 1], '-i'])

        elif choice == '4':
            query = input(f"{YELLOW}Search query:{RESET} ").strip()
            return self.run(['--search', query, '-i'])

        elif choice == '5':
            return self.run(['--all'])

        elif choice.lower() == 'q':
            return 0

        print(f"{RED}Invalid choice{RESET}")
        return 1


def main():
    """CLI entry point"""
    cli = VisualizerCLI()
    sys.exit(cli.run(sys.argv[1:]))


if __name__ == '__main__':
    main()
