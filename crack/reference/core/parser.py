"""
Markdown command parser for extracting commands from documentation
"""

import re
from pathlib import Path
from typing import List, Dict, Optional
from .registry import Command, CommandVariable


class MarkdownCommandParser:
    """Parse commands from markdown documentation"""

    def __init__(self):
        self.commands = []

    def parse_file(self, filepath: Path) -> List[Command]:
        """Parse a single markdown file for commands"""
        with open(filepath, 'r') as f:
            content = f.read()

        return self.parse_content(content, filepath.stem)

    def parse_content(self, content: str, default_category: str = 'custom') -> List[Command]:
        """Parse markdown content for commands"""
        commands = []

        # Find all code blocks with bash/shell
        code_blocks = re.findall(r'```(?:bash|shell|sh)?\n(.*?)\n```', content, re.DOTALL)

        for i, block in enumerate(code_blocks):
            # Skip if block is too long (likely not a command)
            if len(block.split('\n')) > 10:
                continue

            # Look for command-like patterns
            lines = block.strip().split('\n')
            for line in lines:
                if self._looks_like_command(line):
                    cmd = self._extract_command_from_line(line, default_category, i)
                    if cmd:
                        commands.append(cmd)

        return commands

    def _looks_like_command(self, line: str) -> bool:
        """Check if a line looks like a command"""
        # Skip comments
        if line.strip().startswith('#'):
            return False

        # Common command prefixes
        command_prefixes = [
            'nmap', 'gobuster', 'sqlmap', 'curl', 'wget', 'nc', 'netcat',
            'python', 'bash', 'powershell', 'hydra', 'john', 'hashcat',
            'msfvenom', 'searchsploit', 'enum4linux', 'smbclient', 'rpcclient',
            'nikto', 'dirb', 'wfuzz', 'ffuf', 'burpsuite'
        ]

        line_lower = line.strip().lower()
        return any(line_lower.startswith(prefix) for prefix in command_prefixes)

    def _extract_command_from_line(self, line: str, category: str, index: int) -> Optional[Command]:
        """Extract a Command object from a command line"""
        # Extract placeholders
        placeholders = re.findall(r'<[A-Z_]+>', line)

        # Generate ID from command
        cmd_parts = line.split()
        if not cmd_parts:
            return None

        tool = cmd_parts[0]
        cmd_id = f"{tool}_{category}_{index}"

        # Create variables from placeholders
        variables = []
        for placeholder in placeholders:
            var = CommandVariable(
                name=placeholder,
                description=self._guess_placeholder_description(placeholder),
                example=self._guess_placeholder_example(placeholder),
                required=True
            )
            variables.append(var)

        # Create command
        return Command(
            id=cmd_id,
            name=f"{tool.title()} Command",
            category=category,
            command=line.strip(),
            description=f"Execute {tool} command",
            variables=variables,
            tags=self._guess_tags_from_command(line)
        )

    def _guess_placeholder_description(self, placeholder: str) -> str:
        """Guess description for common placeholders"""
        descriptions = {
            '<TARGET>': 'Target IP address or hostname',
            '<LHOST>': 'Local/attacker IP address',
            '<LPORT>': 'Local port for listener',
            '<PORT>': 'Target port number',
            '<URL>': 'Target URL',
            '<FILE>': 'File path',
            '<WORDLIST>': 'Path to wordlist file',
            '<USERNAME>': 'Username for authentication',
            '<PASSWORD>': 'Password for authentication'
        }
        return descriptions.get(placeholder, f"Value for {placeholder}")

    def _guess_placeholder_example(self, placeholder: str) -> str:
        """Provide example values for placeholders"""
        examples = {
            '<TARGET>': '192.168.1.100',
            '<LHOST>': '10.10.14.5',
            '<LPORT>': '4444',
            '<PORT>': '80',
            '<URL>': 'http://target.com',
            '<FILE>': 'shell.php',
            '<WORDLIST>': '/usr/share/wordlists/rockyou.txt',
            '<USERNAME>': 'admin',
            '<PASSWORD>': 'password123'
        }
        return examples.get(placeholder, '')

    def _guess_tags_from_command(self, command: str) -> List[str]:
        """Guess appropriate tags from command content"""
        tags = []
        cmd_lower = command.lower()

        # Tool-specific tags
        if 'nmap' in cmd_lower:
            tags.extend(['ENUM', 'NOISY'])
        if 'gobuster' in cmd_lower or 'dirb' in cmd_lower:
            tags.extend(['WEB', 'NOISY', 'ENUM'])
        if 'sqlmap' in cmd_lower:
            tags.extend(['SQLI', 'NOISY', 'AUTOMATED'])
        if 'hydra' in cmd_lower:
            tags.extend(['BRUTEFORCE', 'NOISY'])
        if 'nc' in cmd_lower or 'netcat' in cmd_lower:
            tags.extend(['TRANSFER', 'REVERSE_SHELL'])

        # Stealth considerations
        if '-sS' in cmd_lower or '-sF' in cmd_lower:
            tags.append('STEALTH')

        return list(set(tags))  # Remove duplicates

    def parse_directory(self, directory: Path) -> Dict[str, List[Command]]:
        """Parse all markdown files in a directory"""
        results = {}

        for md_file in directory.glob('**/*.md'):
            # Determine category from path
            if '01-recon' in str(md_file):
                category = 'recon'
            elif '02-web' in str(md_file):
                category = 'web'
            elif '03-exploitation' in str(md_file):
                category = 'exploitation'
            elif '04-post-exploitation' in str(md_file):
                category = 'post-exploit'
            elif '05-pivoting' in str(md_file):
                category = 'pivoting'
            else:
                category = 'custom'

            commands = self.parse_file(md_file)
            if commands:
                results[str(md_file)] = commands

        return results


class MarkdownGenerator:
    """Generate markdown documentation from commands"""

    def __init__(self):
        self.template_path = Path(__file__).parent.parent.parent / 'db' / 'data' / 'templates'

    def generate_command_md(self, command: Command) -> str:
        """Generate markdown for a single command"""
        md = f"## {command.name}\n\n"
        md += f"```bash\n{command.command}\n```\n\n"
        md += f"**Description**: {command.description}\n\n"

        if command.variables:
            md += "### Variables\n"
            for var in command.variables:
                md += f"- **{var.name}**: {var.description}"
                if var.example:
                    md += f" (e.g., `{var.example}`)"
                md += "\n"
            md += "\n"

        if command.tags:
            md += f"**Tags**: {' '.join([f'`{tag}`' for tag in command.tags])}\n\n"

        if command.success_indicators:
            md += f"**Success Indicators**: {command.success_indicators}\n\n"

        if command.failure_indicators:
            md += f"**Failure Indicators**: {command.failure_indicators}\n\n"

        if command.alternatives:
            md += "### Alternative Commands\n"
            for alt in command.alternatives:
                md += f"- `{alt}`\n"
            md += "\n"

        if command.notes:
            md += f"**Notes**: {command.notes}\n\n"

        if command.oscp_relevance:
            md += f"**OSCP Relevance**: {command.oscp_relevance.upper()}\n\n"

        return md

    def generate_category_md(self, category: str, commands: List[Command]) -> str:
        """Generate markdown for a category of commands"""
        md = f"# {category.title()} Commands\n\n"
        md += f"Total commands in category: {len(commands)}\n\n"

        # Group by relevance
        high_relevance = [c for c in commands if c.oscp_relevance == 'high']
        medium_relevance = [c for c in commands if c.oscp_relevance == 'medium']
        low_relevance = [c for c in commands if c.oscp_relevance == 'low']

        if high_relevance:
            md += "## High OSCP Relevance\n\n"
            for cmd in high_relevance:
                md += self._generate_command_summary(cmd)

        if medium_relevance:
            md += "## Medium OSCP Relevance\n\n"
            for cmd in medium_relevance:
                md += self._generate_command_summary(cmd)

        if low_relevance:
            md += "## Low OSCP Relevance\n\n"
            for cmd in low_relevance:
                md += self._generate_command_summary(cmd)

        return md

    def _generate_command_summary(self, command: Command) -> str:
        """Generate a summary for a command"""
        md = f"### {command.name}\n"
        md += f"```bash\n{command.command}\n```\n"
        md += f"{command.description}\n\n"
        return md