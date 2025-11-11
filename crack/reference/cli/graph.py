"""
Graph Pattern CLI - Neo4j Graph Query Interface

Minimalist CLI handler for Neo4j graph primitives and pattern library.
"""

import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class GraphCLI:
    """Handler for Neo4j graph pattern operations (minimalist)"""

    def __init__(self, registry, theme):
        """Initialize graph CLI

        Args:
            registry: Command registry (should be Neo4jCommandRegistryAdapter)
            theme: ReferenceTheme instance
        """
        self.registry = registry
        self.theme = theme
        self.patterns = None

        # Initialize pattern helper if Neo4j available
        self._initialize_patterns()

    def _initialize_patterns(self):
        """Initialize pattern library if Neo4j backend available"""
        try:
            from reference.core import Neo4jCommandRegistryAdapter
            from reference.patterns.advanced_queries import create_pattern_helper

            if isinstance(self.registry, Neo4jCommandRegistryAdapter):
                self.patterns = create_pattern_helper(self.registry)
                logger.debug("Pattern library initialized")
            else:
                logger.debug("Registry is not Neo4j, patterns unavailable")

        except ImportError as e:
            logger.debug(f"Pattern library unavailable: {e}")

    def execute_pattern(self, pattern_name: str, args) -> int:
        """Execute named graph pattern

        Args:
            pattern_name: Pattern identifier (multi-hop, service-rec, etc.)
            args: Parsed CLI arguments

        Returns:
            Exit code (0 for success, 1 for error)
        """
        # Check Neo4j availability
        if not self.patterns:
            print(self.theme.error("✗ Neo4j backend not available"))
            print(self.theme.hint("Graph patterns require Neo4j connection"))
            print(self.theme.hint("Check status: crack reference --status"))
            return 1

        # Route to appropriate handler
        handlers = {
            'multi-hop': self._multi_hop,
            'shortest-path': self._shortest_path,
            'prereqs': self._prerequisites,
            'parallel': self._parallel_execution,
            'service-rec': self._service_recommendations,
            'tag-hierarchy': self._tag_hierarchy,
            'success-corr': self._success_correlation,
            'coverage-gaps': self._coverage_gaps,
            'circular-deps': self._circular_dependencies,
            'var-usage': self._variable_usage
        }

        handler = handlers.get(pattern_name)
        if not handler:
            print(self.theme.error(f"Unknown pattern: {pattern_name}"))
            return 1

        return handler(args)

    def _multi_hop(self, args) -> int:
        """Pattern 1: Multi-hop alternative chains"""
        if not args.args:
            print(self.theme.error("Usage: crack reference --graph multi-hop <command_id> [positional_args...]"))
            print(self.theme.hint("Example: crack reference --graph multi-hop gobuster-dir"))
            return 1

        command_id = args.args[0]
        depth = 3  # Default depth

        # Check for depth in remaining args
        for i, arg in enumerate(args.args[1:], 1):
            if arg.isdigit():
                depth = int(arg)
                break

        results = self.patterns.multi_hop_alternatives(command_id, depth=depth)

        if not results:
            print(self.theme.hint(f"No alternative chains found for: {command_id}"))
            return 0

        print(f"\n{self.theme.command_name('Alternative Command Chains')}")
        print(f"{self.theme.hint(f'(depth: {depth}, found: {len(results)})')}\n")

        for i, alt in enumerate(results, 1):
            chain = ' → '.join([c['name'] for c in alt['command_chain']])
            print(f"{i}. {self.theme.primary(chain)}")
            print(f"   Depth: {alt['depth']}, Priority: {alt.get('cumulative_priority', 'N/A')}")

            if alt.get('metadata') and alt['metadata']:
                reason = alt['metadata'][0].get('reason', 'N/A')
                print(f"   {self.theme.hint(f'Reason: {reason}')}")
            print()

        return 0

    def _shortest_path(self, args) -> int:
        """Pattern 2: Shortest attack path"""
        if len(args.args) < 2:
            print(self.theme.error("Usage: crack reference --graph shortest-path <start_tag> <end_tag>"))
            print(self.theme.hint("Example: crack reference --graph shortest-path STARTER PRIVESC"))
            return 1

        start_tag = args.args[0]
        end_tag = args.args[1]

        results = self.patterns.shortest_attack_path(start_tag, end_tag)

        if not results:
            print(self.theme.hint(f"No path found from {start_tag} to {end_tag}"))
            return 0

        print(f"\n{self.theme.command_name('Shortest Attack Path')}")
        print(f"{self.theme.hint(f'{start_tag} → {end_tag}')}\n")

        for i, path_data in enumerate(results, 1):
            print(f"{i}. {self.theme.primary('Path')} (length: {path_data.get('step_count', 'N/A')})")
            if 'path' in path_data:
                print(f"   {path_data['path']}")
            print()

        return 0

    def _prerequisites(self, args) -> int:
        """Pattern 3: Prerequisite closure with execution order"""
        if not args.args:
            print(self.theme.error("Usage: crack reference --graph prereqs <command_id>"))
            print(self.theme.hint("Example: crack reference --graph prereqs wordpress-sqli"))
            return 1

        command_id = args.args[0]
        results = self.patterns.prerequisite_closure(command_id, with_execution_order=True)

        if not results:
            print(self.theme.hint(f"No prerequisites found for: {command_id}"))
            return 0

        print(f"\n{self.theme.command_name('Prerequisites (Execution Order)')}\n")

        for prereq in results:
            depth = prereq.get('dependency_count', 0)
            name = prereq.get('command_name', prereq.get('command_id', 'N/A'))
            print(f"{depth}. {self.theme.primary(name)}")

        print(f"\n{self.theme.hint('Run commands in order from 0 upward')}")
        return 0

    def _parallel_execution(self, args) -> int:
        """Pattern 4: Parallel execution planning"""
        if not args.args:
            print(self.theme.error("Usage: crack reference --graph parallel <chain_id>"))
            print(self.theme.hint("Example: crack reference --graph parallel web-to-root"))
            return 1

        chain_id = args.args[0]
        results = self.patterns.parallel_execution_plan(chain_id)

        if not results or not results.get('parallel_groups'):
            print(self.theme.hint(f"No parallel execution plan for: {chain_id}"))
            return 0

        print(f"\n{self.theme.command_name('Parallel Execution Plan')}\n")

        for i, group in enumerate(results['parallel_groups'], 1):
            print(f"Wave {i}: {self.theme.primary(', '.join(group))}")

        print(f"\n{self.theme.hint('Commands in same wave can run simultaneously')}")
        return 0

    def _service_recommendations(self, args) -> int:
        """Pattern 5: Service-based command recommendations"""
        if not args.args:
            print(self.theme.error("Usage: crack reference --graph service-rec <port1> <port2> ..."))
            print(self.theme.hint("Example: crack reference --graph service-rec 80 445 22"))
            return 1

        # Parse port numbers
        try:
            ports = [int(p) for p in args.args]
        except ValueError:
            print(self.theme.error("All arguments must be valid port numbers"))
            return 1

        results = self.patterns.service_recommendations(ports, oscp_only=True)

        if not results:
            print(self.theme.hint(f"No command recommendations for ports: {ports}"))
            return 0

        print(f"\n{self.theme.command_name('Service Recommendations')}")
        print(f"{self.theme.hint(f'Ports: {ports}')}\n")

        for i, rec in enumerate(results, 1):
            name = rec.get('command_name', 'N/A')
            services = rec.get('services', [])
            count = rec.get('service_count', 0)

            print(f"{i}. {self.theme.primary(name)}")
            print(f"   Services: {', '.join(services)} ({count} services)")
            print()

        return 0

    def _tag_hierarchy(self, args) -> int:
        """Pattern 6: Tag hierarchy filtering"""
        if not args.args:
            print(self.theme.error("Usage: crack reference --graph tag-hierarchy <tag>"))
            print(self.theme.hint("Example: crack reference --graph tag-hierarchy OSCP"))
            return 1

        tags = args.args  # Can provide multiple tags
        results = self.patterns.filter_by_tag_hierarchy(tags)

        if not results:
            print(self.theme.hint(f"No commands found with tags: {tags}"))
            return 0

        print(f"\n{self.theme.command_name('Commands by Tag Hierarchy')}")
        print(f"{self.theme.hint(f'Tags: {tags} (includes child tags)')}\n")

        for i, cmd in enumerate(results, 1):
            print(f"{i}. {self.theme.primary(cmd.name)} ({cmd.id})")
            print(f"   Category: {cmd.category}")
            if cmd.tags:
                print(f"   Tags: {', '.join(cmd.tags)}")
            print()

        return 0

    def _success_correlation(self, args) -> int:
        """Pattern 7: Command success correlation"""
        min_count = 5  # Default

        if args.args and args.args[0].isdigit():
            min_count = int(args.args[0])

        results = self.patterns.success_correlation(min_co_occurrence=min_count)

        if not results:
            print(self.theme.hint("No success correlation data available"))
            print(self.theme.hint("(Requires session execution history)"))
            return 0

        print(f"\n{self.theme.command_name('Command Success Correlation')}\n")

        for i, corr in enumerate(results, 1):
            cmd_a = corr.get('command_a', 'N/A')
            cmd_b = corr.get('command_b', 'N/A')
            count = corr.get('co_occurrence', 0)

            print(f"{i}. {self.theme.primary(cmd_a)} ↔ {cmd_b}")
            print(f"   Co-occurrence: {count}")
            print()

        return 0

    def _coverage_gaps(self, args) -> int:
        """Pattern 8: Coverage gap detection"""
        results = self.patterns.find_coverage_gaps(oscp_only=True)

        if not results:
            print(self.theme.success("✓ No coverage gaps found!"))
            print(self.theme.hint("All services have high-OSCP enumeration commands"))
            return 0

        print(f"\n{self.theme.command_name('Coverage Gaps')}")
        print(f"{self.theme.hint('Services lacking high-OSCP commands')}\n")

        for i, gap in enumerate(results, 1):
            service = gap.get('service_name', 'N/A')
            protocol = gap.get('protocol', 'N/A')
            ports = gap.get('ports', [])

            print(f"{i}. {self.theme.error(service)} ({protocol})")
            print(f"   Ports: {', '.join(map(str, ports))}")
            print()

        return 0

    def _circular_dependencies(self, args) -> int:
        """Pattern 9: Circular dependency detection"""
        results = self.patterns.detect_circular_dependencies()

        if not results:
            print(self.theme.success("✓ No circular dependencies detected!"))
            return 0

        print(f"\n{self.theme.command_name('Circular Dependencies')}")
        print(f"{self.theme.error(f'Found {len(results)} cycles')}\n")

        for i, cycle in enumerate(results, 1):
            steps = cycle.get('circular_steps', [])
            length = cycle.get('cycle_length', 0)

            print(f"{i}. {self.theme.error('Cycle')} (length: {length})")
            print(f"   {' → '.join(steps)}")
            print()

        return 1  # Return error code if cycles found

    def _variable_usage(self, args) -> int:
        """Pattern 10: Variable usage analysis"""
        results = self.patterns.variable_usage_analysis()

        if not results:
            print(self.theme.hint("No variable usage data available"))
            return 0

        print(f"\n{self.theme.command_name('Variable Usage Analysis')}\n")

        for i, var in enumerate(results, 1):
            name = var.get('variable_name', 'N/A')
            count = var.get('usage_count', 0)
            samples = var.get('sample_commands', [])

            print(f"{i}. {self.theme.primary(name)} (used in {count} commands)")
            if samples:
                print(f"   Examples: {', '.join(samples[:3])}")
            print()

        return 0
