"""
Markdown export formatter for OSCP writeups

Generates comprehensive markdown reports suitable for
educational documentation and OSCP lab writeups.
"""

from datetime import datetime
from typing import Dict, Any, List
from ..core.task_tree import TaskNode


class MarkdownFormatter:
    """Export enumeration data to markdown format"""

    @classmethod
    def export_full_report(cls, profile) -> str:
        """Generate complete enumeration report

        Args:
            profile: TargetProfile instance

        Returns:
            Markdown-formatted report string
        """
        sections = []

        # Title and metadata
        sections.append(cls._format_title(profile))
        sections.append(cls._format_metadata(profile))

        # Executive summary
        sections.append(cls._format_summary(profile))

        # Discovered information
        sections.append(cls._format_ports_section(profile))

        if profile.findings:
            sections.append(cls._format_findings_section(profile))

        if profile.credentials:
            sections.append(cls._format_credentials_section(profile))

        # Task completion
        sections.append(cls._format_tasks_section(profile))

        # Timeline
        sections.append(cls._format_timeline(profile))

        # Imported files
        if profile.imported_files:
            sections.append(cls._format_imported_files(profile))

        return "\n\n".join(sections)

    @classmethod
    def _format_title(cls, profile) -> str:
        """Format report title"""
        return f"# Enumeration Report: {profile.target}\n"

    @classmethod
    def _format_metadata(cls, profile) -> str:
        """Format metadata section"""
        lines = []
        lines.append("## Metadata")
        lines.append("")
        lines.append(f"- **Target**: {profile.target}")
        lines.append(f"- **Status**: {profile.status}")
        lines.append(f"- **Phase**: {profile.phase}")
        lines.append(f"- **Started**: {profile.created}")
        lines.append(f"- **Last Updated**: {profile.updated}")
        lines.append(f"- **Generated**: {datetime.now().isoformat()}")

        return "\n".join(lines)

    @classmethod
    def _format_summary(cls, profile) -> str:
        """Format executive summary"""
        progress = profile.get_progress()

        lines = []
        lines.append("## Summary")
        lines.append("")
        lines.append(f"Enumeration of **{profile.target}** is currently in the **{profile.phase}** phase.")
        lines.append("")
        lines.append(f"- **Open Ports**: {len(profile.ports)}")
        lines.append(f"- **Findings**: {len(profile.findings)}")
        lines.append(f"- **Credentials**: {len(profile.credentials)}")
        lines.append(f"- **Tasks Completed**: {progress['completed']}/{progress['total']}")

        return "\n".join(lines)

    @classmethod
    def _format_ports_section(cls, profile) -> str:
        """Format ports section"""
        if not profile.ports:
            return "## Discovered Ports\n\nNo ports discovered yet."

        lines = []
        lines.append("## Discovered Ports")
        lines.append("")
        lines.append("| Port | State | Service | Version | Source |")
        lines.append("|------|-------|---------|---------|--------|")

        for port, info in sorted(profile.ports.items()):
            service = info.get('service', 'unknown')
            version = info.get('version', 'N/A')
            state = info.get('state', 'open')
            source = info.get('source', 'N/A')

            # Escape pipes in version strings
            version = version.replace('|', '\\|') if version else 'N/A'

            lines.append(f"| {port} | {state} | {service} | {version} | {source} |")

        return "\n".join(lines)

    @classmethod
    def _format_findings_section(cls, profile) -> str:
        """Format findings section"""
        lines = []
        lines.append("## Findings")
        lines.append("")

        for i, finding in enumerate(profile.findings, 1):
            lines.append(f"### Finding #{i}: {finding['type']}")
            lines.append("")
            lines.append(f"**Description**: {finding['description']}")
            lines.append("")
            lines.append(f"**Source**: `{finding.get('source', 'N/A')}`")
            lines.append("")
            lines.append(f"**Timestamp**: {finding.get('timestamp', 'N/A')}")
            lines.append("")

            # Add additional metadata
            for key, value in finding.items():
                if key not in ['type', 'description', 'source', 'timestamp']:
                    lines.append(f"**{key.title()}**: {value}")
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def _format_credentials_section(cls, profile) -> str:
        """Format credentials section"""
        lines = []
        lines.append("## Discovered Credentials")
        lines.append("")
        lines.append("| Username | Password | Hash | Service | Port | Source |")
        lines.append("|----------|----------|------|---------|------|--------|")

        for cred in profile.credentials:
            username = cred.get('username', 'N/A')
            password = cred.get('password', 'N/A')
            hash_val = cred.get('hash', 'N/A')
            service = cred.get('service', 'N/A')
            port = cred.get('port', 'N/A')
            source = cred.get('source', 'N/A')

            # Truncate long hashes
            if hash_val and len(hash_val) > 20:
                hash_val = hash_val[:17] + "..."

            lines.append(f"| {username} | {password} | {hash_val} | {service} | {port} | {source} |")

        return "\n".join(lines)

    @classmethod
    def _format_tasks_section(cls, profile) -> str:
        """Format tasks section"""
        lines = []
        lines.append("## Enumeration Tasks")
        lines.append("")

        # Completed tasks
        completed = profile.task_tree.get_all_completed()
        if completed:
            lines.append("### Completed Tasks")
            lines.append("")
            for task in completed:
                lines.append(f"- **{task.name}**")
                if task.metadata.get('command'):
                    lines.append(f"  ```bash")
                    lines.append(f"  {task.metadata['command']}")
                    lines.append(f"  ```")
                lines.append("")

        # Pending tasks
        pending = profile.task_tree.get_all_pending()
        if pending:
            lines.append("### Pending Tasks")
            lines.append("")
            for task in pending:
                lines.append(f"- [ ] {task.name}")
                if task.metadata.get('description'):
                    lines.append(f"  - {task.metadata['description']}")

        return "\n".join(lines)

    @classmethod
    def _format_timeline(cls, profile) -> str:
        """Format timeline of events"""
        lines = []
        lines.append("## Timeline")
        lines.append("")

        # Collect all timestamped events
        events = []

        # Add task completions
        for task in profile.task_tree._get_all_descendants():
            if task.status == 'completed' and task.metadata.get('completed_at'):
                events.append({
                    'timestamp': task.metadata['completed_at'],
                    'event': f"Completed: {task.name}",
                    'type': 'task'
                })

        # Add findings
        for finding in profile.findings:
            events.append({
                'timestamp': finding.get('timestamp', ''),
                'event': f"Finding: {finding['description']}",
                'type': 'finding'
            })

        # Add credentials
        for cred in profile.credentials:
            events.append({
                'timestamp': cred.get('timestamp', ''),
                'event': f"Credential: {cred['username']}",
                'type': 'credential'
            })

        # Sort by timestamp
        events.sort(key=lambda e: e['timestamp'])

        # Format as list
        for event in events:
            lines.append(f"- **{event['timestamp']}**: {event['event']}")

        if not events:
            lines.append("No timeline events yet.")

        return "\n".join(lines)

    @classmethod
    def _format_imported_files(cls, profile) -> str:
        """Format imported files section"""
        lines = []
        lines.append("## Imported Files")
        lines.append("")
        lines.append("| File | Type | Timestamp |")
        lines.append("|------|------|-----------|")

        for file_info in profile.imported_files:
            filename = file_info.get('file', 'N/A')
            file_type = file_info.get('type', 'N/A')
            timestamp = file_info.get('timestamp', 'N/A')

            lines.append(f"| `{filename}` | {file_type} | {timestamp} |")

        return "\n".join(lines)

    @classmethod
    def export_task_reference(cls, profile) -> str:
        """Export task reference with all commands

        Args:
            profile: TargetProfile instance

        Returns:
            Markdown-formatted command reference
        """
        lines = []
        lines.append(f"# Command Reference: {profile.target}")
        lines.append("")
        lines.append("Complete list of enumeration commands for this target.")
        lines.append("")

        cls._format_task_commands(profile.task_tree, lines)

        return "\n".join(lines)

    @classmethod
    def _format_task_commands(cls, task: TaskNode, lines: List[str], level: int = 0):
        """Recursively format task commands

        Args:
            task: Task node
            lines: Output lines list
            level: Heading level
        """
        # Skip root
        if level == 0:
            for child in task.children:
                cls._format_task_commands(child, lines, level + 1)
            return

        # Format task
        heading = "#" * min(level + 1, 6)
        lines.append(f"{heading} {task.name}")
        lines.append("")

        if task.metadata.get('description'):
            lines.append(task.metadata['description'])
            lines.append("")

        if task.metadata.get('command'):
            lines.append("**Command**:")
            lines.append("```bash")
            lines.append(task.metadata['command'])
            lines.append("```")
            lines.append("")

        # Flag explanations
        flag_explanations = task.metadata.get('flag_explanations', {})
        if flag_explanations:
            lines.append("**Flags**:")
            for flag, explanation in flag_explanations.items():
                lines.append(f"- `{flag}`: {explanation}")
            lines.append("")

        # Success/failure indicators
        if task.metadata.get('success_indicators'):
            lines.append("**Success Indicators**:")
            for indicator in task.metadata['success_indicators']:
                lines.append(f"- {indicator}")
            lines.append("")

        if task.metadata.get('failure_indicators'):
            lines.append("**Failure Indicators**:")
            for indicator in task.metadata['failure_indicators']:
                lines.append(f"- {indicator}")
            lines.append("")

        # Next steps
        if task.metadata.get('next_steps'):
            lines.append("**Next Steps**:")
            for step in task.metadata['next_steps']:
                lines.append(f"- {step}")
            lines.append("")

        # Alternatives
        if task.metadata.get('alternatives'):
            lines.append("**Alternatives**:")
            for alt in task.metadata['alternatives']:
                lines.append(f"- `{alt}`")
            lines.append("")

        # Recurse to children
        for child in task.children:
            cls._format_task_commands(child, lines, level + 1)
