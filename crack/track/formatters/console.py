"""
Console formatter for rich terminal output

Displays enumeration checklists with color-coded sections,
progress indicators, and formatted task lists.
"""

from typing import Dict, Any, List
from ..core.task_tree import TaskNode

# Try to import Colors from crack utils
try:
    from crack.utils.colors import Colors
except ImportError:
    # Fallback if running standalone
    class Colors:
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        END = '\033[0m'
        # Bright variants
        BRIGHT_BLACK = '\033[90m'
        BRIGHT_RED = '\033[91m'
        BRIGHT_GREEN = '\033[92m'
        BRIGHT_YELLOW = '\033[93m'
        BRIGHT_BLUE = '\033[94m'
        BRIGHT_MAGENTA = '\033[95m'
        BRIGHT_CYAN = '\033[96m'
        BRIGHT_WHITE = '\033[97m'
        # Combinations
        BOLD_GREEN = '\033[1m\033[92m'
        BOLD_YELLOW = '\033[1m\033[93m'
        BOLD_RED = '\033[1m\033[91m'
        BOLD_CYAN = '\033[1m\033[96m'
        BOLD_WHITE = '\033[1m\033[97m'


class ConsoleFormatter:
    """Format checklist output for terminal display"""

    # Status symbols
    SYMBOLS = {
        'pending': '[ ]',
        'in-progress': '[~]',
        'completed': '[✓]',
        'skipped': '[✗]',
        'failed': '[✗]'
    }

    # Status colors - using bright variants for better visibility
    STATUS_COLORS = {
        'pending': Colors.BRIGHT_YELLOW,
        'in-progress': Colors.BRIGHT_CYAN,
        'completed': Colors.BRIGHT_GREEN,
        'skipped': Colors.BRIGHT_RED,
        'failed': Colors.BRIGHT_RED
    }

    @classmethod
    def format_profile(cls, profile, recommendations: Dict[str, Any] = None) -> str:
        """Format complete profile for display

        Args:
            profile: TargetProfile instance
            recommendations: Optional recommendations dict

        Returns:
            Formatted string for terminal output
        """
        output = []

        # Header
        output.append(cls._format_header(profile))
        output.append("")

        # Progress
        output.append(cls._format_progress(profile))
        output.append("")

        # Discovered information
        if profile.ports:
            output.append(cls._format_ports(profile))
            output.append("")

        # Recommendations
        if recommendations:
            output.append(cls._format_recommendations(recommendations, profile))
            output.append("")

        # Task tree
        output.append(cls._format_task_tree(profile.task_tree))

        return "\n".join(output)

    @classmethod
    def _format_header(cls, profile) -> str:
        """Format header with target info"""
        lines = []
        lines.append(f"{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.END}")
        lines.append(f"{Colors.BOLD}{Colors.HEADER}TARGET: {profile.target}{Colors.END}")
        lines.append(f"{Colors.BOLD}PHASE: {profile.phase.upper()}{Colors.END}")
        lines.append(f"{Colors.BOLD}STATUS: {profile.status.upper()}{Colors.END}")
        lines.append(f"{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.END}")
        return "\n".join(lines)

    @classmethod
    def _format_progress(cls, profile) -> str:
        """Format progress statistics"""
        progress = profile.get_progress()
        total = progress['total']
        completed = progress['completed']
        in_progress = progress['in_progress']
        pending = progress['pending']
        failed = progress.get('failed', 0)

        if total == 0:
            return f"{Colors.YELLOW}No tasks yet{Colors.END}"

        pct = (completed / total * 100) if total > 0 else 0

        # Progress bar
        bar_width = 40
        filled = int(bar_width * completed / total) if total > 0 else 0
        bar = '█' * filled + '░' * (bar_width - filled)

        lines = []
        lines.append(f"{Colors.BOLD}PROGRESS:{Colors.END}")
        lines.append(f"  [{Colors.GREEN}{bar}{Colors.END}] {pct:.0f}%")
        status_line = f"  {Colors.GREEN}✓ {completed}{Colors.END} completed | {Colors.CYAN}~ {in_progress}{Colors.END} in progress | {Colors.YELLOW}• {pending}{Colors.END} pending"
        if failed > 0:
            status_line += f" | {Colors.RED}✗ {failed}{Colors.END} failed"
        lines.append(status_line)

        return "\n".join(lines)

    @classmethod
    def _format_ports(cls, profile) -> str:
        """Format discovered ports"""
        lines = []
        lines.append(f"{Colors.BOLD}DISCOVERED PORTS:{Colors.END}")

        for port, info in sorted(profile.ports.items()):
            service = info.get('service', 'unknown')
            version = info.get('version', '')

            line = f"  {Colors.BLUE}{port:5d}/tcp{Colors.END} - "
            line += f"{Colors.BOLD}{service}{Colors.END}"

            if version:
                line += f" {Colors.CYAN}({version}){Colors.END}"

            lines.append(line)

        return "\n".join(lines)

    @classmethod
    def _format_recommendations(cls, recommendations: Dict[str, Any], profile) -> str:
        """Format recommendations section"""
        lines = []
        lines.append(f"{Colors.BOLD}{Colors.GREEN}RECOMMENDED ACTIONS:{Colors.END}")
        lines.append("")

        # Quick wins
        if recommendations.get('quick_wins'):
            lines.append(f"{Colors.BOLD}⚡ Quick Wins:{Colors.END}")
            for task in recommendations['quick_wins'][:3]:
                lines.append(f"  • {task.name}")
                if task.metadata.get('command'):
                    lines.append(f"    {Colors.CYAN}{task.metadata['command']}{Colors.END}")
            lines.append("")

        # Next task
        next_task = recommendations.get('next')
        if next_task:
            lines.append(f"{Colors.BOLD}Next Task: {next_task.name}{Colors.END}")
            if next_task.metadata.get('command'):
                lines.append(f"  Command: {Colors.GREEN}{next_task.metadata['command']}{Colors.END}")

                # Show flag explanations if available
                flag_explanations = next_task.metadata.get('flag_explanations', {})
                if flag_explanations:
                    lines.append(f"  Flags:")
                    for flag, explanation in flag_explanations.items():
                        lines.append(f"    {flag}: {explanation}")

            if next_task.metadata.get('description'):
                lines.append(f"  {next_task.metadata['description']}")

            lines.append("")

        # Parallel tasks
        if recommendations.get('parallel'):
            lines.append(f"{Colors.BOLD}Can Run in Parallel:{Colors.END}")
            for task in recommendations['parallel'][:3]:
                lines.append(f"  • {task.name}")
            lines.append("")

        # Phase suggestions
        from ..recommendations.engine import RecommendationEngine
        phase_suggestions = RecommendationEngine.get_phase_suggestions(profile)
        if phase_suggestions:
            lines.append(f"{Colors.BOLD}Phase Guidance:{Colors.END}")
            for suggestion in phase_suggestions:
                lines.append(f"  • {suggestion}")

        return "\n".join(lines)

    @classmethod
    def format_task_tree(cls, root: TaskNode) -> str:
        """Public interface for formatting task tree

        Args:
            root: Root task node

        Returns:
            Formatted task tree string
        """
        return cls._format_task_tree(root, indent=0)

    @classmethod
    def _format_task_tree(cls, root: TaskNode, indent: int = 0) -> str:
        """Format task tree recursively (internal)

        Args:
            root: Root task node
            indent: Current indentation level

        Returns:
            Formatted task tree string
        """
        lines = []

        # Don't show root task itself
        if indent == 0:
            lines.append(f"{Colors.BOLD}TASK CHECKLIST:{Colors.END}")
            for child in root.children:
                lines.append(cls._format_task_node(child, 0))
        else:
            lines.append(cls._format_task_node(root, indent))

        return "\n".join(lines)

    @classmethod
    def _format_task_node(cls, task: TaskNode, indent: int) -> str:
        """Format a single task node

        Args:
            task: Task node
            indent: Indentation level

        Returns:
            Formatted task string
        """
        lines = []
        prefix = "  " * indent

        # Get status symbol and color
        symbol = cls.SYMBOLS.get(task.status, '[ ]')
        color = cls.STATUS_COLORS.get(task.status, '')

        # Format task line
        task_line = f"{prefix}{color}{symbol}{Colors.END} {task.name}"

        # Add tags if present
        tags = task.metadata.get('tags', [])
        if tags:
            tag_str = ' '.join(f"[{tag}]" for tag in tags[:2])  # Show first 2 tags
            task_line += f" {Colors.CYAN}{tag_str}{Colors.END}"

        # Add alternative count badge (Phase 6.4)
        alternative_ids = task.metadata.get('alternative_ids', [])
        if alternative_ids:
            alt_count = len(alternative_ids)
            task_line += f" {Colors.YELLOW}[{alt_count} alt]{Colors.END}"

        lines.append(task_line)

        # Show command for pending/in-progress tasks
        if task.status in ['pending', 'in-progress'] and task.metadata.get('command'):
            lines.append(f"{prefix}  → {Colors.CYAN}{task.metadata['command']}{Colors.END}")

        # Recursively format children
        for child in task.children:
            child_output = cls._format_task_node(child, indent + 1)
            lines.append(child_output)

        return "\n".join(lines)

    @classmethod
    def format_findings(cls, profile) -> str:
        """Format findings section

        Args:
            profile: TargetProfile instance

        Returns:
            Formatted findings string
        """
        if not profile.findings:
            return f"{Colors.YELLOW}No findings yet{Colors.END}"

        lines = []
        lines.append(f"{Colors.BOLD}{Colors.GREEN}FINDINGS:{Colors.END}")
        lines.append("")

        for finding in profile.findings:
            lines.append(f"  {Colors.BOLD}[{finding['type']}]{Colors.END} {finding['description']}")
            lines.append(f"    Source: {Colors.CYAN}{finding.get('source', 'N/A')}{Colors.END}")
            lines.append(f"    Time: {finding.get('timestamp', 'N/A')}")
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def format_credentials(cls, profile) -> str:
        """Format credentials section

        Args:
            profile: TargetProfile instance

        Returns:
            Formatted credentials string
        """
        if not profile.credentials:
            return f"{Colors.YELLOW}No credentials found yet{Colors.END}"

        lines = []
        lines.append(f"{Colors.BOLD}{Colors.GREEN}DISCOVERED CREDENTIALS:{Colors.END}")
        lines.append("")

        for cred in profile.credentials:
            lines.append(f"  {Colors.BOLD}User:{Colors.END} {cred['username']}")
            if cred.get('password'):
                lines.append(f"  {Colors.BOLD}Pass:{Colors.END} {cred['password']}")
            if cred.get('hash'):
                lines.append(f"  {Colors.BOLD}Hash:{Colors.END} {cred['hash']}")
            if cred.get('service'):
                lines.append(f"  {Colors.BOLD}Service:{Colors.END} {cred.get('service')} (port {cred.get('port', 'N/A')})")
            lines.append(f"    Source: {Colors.CYAN}{cred.get('source', 'N/A')}{Colors.END}")
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def format_import_summary(cls, data: Dict[str, Any]) -> str:
        """Format import summary

        Args:
            data: Parsed data from parser

        Returns:
            Formatted summary string
        """
        lines = []
        lines.append(f"{Colors.GREEN}✓ Import successful!{Colors.END}")
        lines.append("")

        if data.get('target'):
            lines.append(f"Target: {Colors.BOLD}{data['target']}{Colors.END}")

        if data.get('ports'):
            lines.append(f"Discovered {Colors.BOLD}{len(data['ports'])}{Colors.END} open ports:")
            for port_data in data['ports'][:10]:  # Show first 10
                service = port_data.get('service', 'unknown')
                version = port_data.get('version', '')
                line = f"  • {port_data['port']}/tcp - {service}"
                if version:
                    line += f" ({version})"
                lines.append(line)

            if len(data['ports']) > 10:
                lines.append(f"  ... and {len(data['ports']) - 10} more")

        return "\n".join(lines)

    @classmethod
    def format_task_details(cls, task: TaskNode) -> str:
        """Format detailed task information including alternatives (Phase 6.4)

        Args:
            task: Task node to display

        Returns:
            Formatted task details string
        """
        lines = []

        # Header
        lines.append(f"{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.END}")
        lines.append(f"{Colors.BOLD}Task: {task.name}{Colors.END}")
        lines.append(f"{Colors.BOLD}{Colors.HEADER}{'='*60}{Colors.END}")
        lines.append("")

        # Status
        status_color = cls.STATUS_COLORS.get(task.status, '')
        lines.append(f"Status: {status_color}{task.status.upper()}{Colors.END}")

        # Command
        if task.metadata.get('command'):
            lines.append(f"Command: {Colors.CYAN}{task.metadata['command']}{Colors.END}")

        # Description
        if task.metadata.get('description'):
            lines.append(f"Description: {task.metadata['description']}")

        # Tags
        tags = task.metadata.get('tags', [])
        if tags:
            tag_str = ' '.join(f"[{tag}]" for tag in tags)
            lines.append(f"Tags: {Colors.CYAN}{tag_str}{Colors.END}")

        # Show linked alternatives (Phase 6.4)
        alternative_ids = task.metadata.get('alternative_ids', [])
        if alternative_ids:
            lines.append("")
            lines.append(f"{Colors.BOLD}{Colors.YELLOW}Alternative Commands ({len(alternative_ids)}):{Colors.END}")

            # Import here to avoid circular dependency
            try:
                from ..alternatives.registry import AlternativeCommandRegistry
                AlternativeCommandRegistry.load_all()

                for i, alt_id in enumerate(alternative_ids, 1):
                    alt = AlternativeCommandRegistry.get(alt_id)
                    if alt:
                        lines.append(f"  {i}. {Colors.BOLD}{alt.name}{Colors.END}")
                        lines.append(f"     {alt.description}")
                        if alt.tags:
                            tag_str = ' '.join(f"[{tag}]" for tag in alt.tags[:3])
                            lines.append(f"     {Colors.CYAN}{tag_str}{Colors.END}")
                    else:
                        lines.append(f"  {i}. {Colors.RED}[Unknown: {alt_id}]{Colors.END}")

                lines.append("")
                lines.append(f"{Colors.YELLOW}Press 'alt' in interactive mode to execute alternatives{Colors.END}")

            except ImportError:
                lines.append(f"  {Colors.RED}[Alternative commands not available]{Colors.END}")

        # Children count
        if task.children:
            lines.append("")
            lines.append(f"Subtasks: {len(task.children)}")

        return "\n".join(lines)
