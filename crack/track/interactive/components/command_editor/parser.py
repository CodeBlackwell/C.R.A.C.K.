"""
CommandParser - Tool-Specific Command Parsing

Parses pentesting tool commands into structured format.
Supports: gobuster, nmap, nikto, hydra, sqlmap
"""

import re
import shlex
from dataclasses import dataclass, field
from typing import Optional, Dict, List


@dataclass
class ParsedCommand:
    """Structured representation of a parsed command"""
    tool: str
    subcommand: Optional[str] = None
    flags: Dict[str, bool] = field(default_factory=dict)  # Boolean flags (-v, -f)
    parameters: Dict[str, str] = field(default_factory=dict)  # Value params (-u URL, -w PATH)
    arguments: List[str] = field(default_factory=list)  # Positional args


class CommandParser:
    """Parse pentesting tool commands into structured format"""

    # Tool-specific flag definitions
    TOOL_FLAGS = {
        'gobuster': {
            'value_flags': ['-u', '-w', '-t', '-x', '-o', '-p', '-c', '-k', '-r', '-a'],
            'bool_flags': ['-v', '-f', '-e', '-q', '-n', '-i', '-s']
        },
        'nmap': {
            'value_flags': ['-p', '-oA', '-oN', '-oX', '-oG', '-T', '--script', '--exclude'],
            'bool_flags': ['-sS', '-sT', '-sV', '-sC', '-O', '-A', '-Pn', '-n', '-6', '-v']
        },
        'nikto': {
            'value_flags': ['-h', '-p', '-ssl', '-Tuning', '-output', '-Format', '-id'],
            'bool_flags': ['-nossl', '-nolookup', '-nocache', '-nointeractive']
        },
        'hydra': {
            'value_flags': ['-l', '-L', '-p', '-P', '-t', '-o', '-s', '-e', '-f'],
            'bool_flags': ['-v', '-V', '-d', '-q', '-F', '-M', '-S']
        },
        'sqlmap': {
            'value_flags': ['-u', '--url', '--data', '--cookie', '--dbs', '--tables', '--dump',
                           '-D', '-T', '-C', '--level', '--risk', '--threads', '--batch'],
            'bool_flags': ['--random-agent', '--crawl', '--forms', '--all']
        }
    }

    @staticmethod
    def extract_tool(command: str) -> str:
        """
        Extract tool name (first word) from command.

        Args:
            command: Full command string

        Returns:
            Tool name (e.g., "gobuster", "nmap")
        """
        if not command or not command.strip():
            return ""

        # Handle multi-line commands (join lines)
        normalized = ' '.join(command.split('\n')).strip()

        # Extract first word (tool name)
        parts = normalized.split()
        if not parts:
            return ""

        tool = parts[0].strip()

        # Handle sudo prefix
        if tool == 'sudo':
            return parts[1] if len(parts) > 1 else ""

        return tool

    @staticmethod
    def parse(command: str) -> ParsedCommand:
        """
        Parse command into structured format.

        Supports:
        - gobuster: -u, -w, -t, -x, -o
        - nmap: -sS, -sV, -p, -A, -oA
        - nikto: -h, -p, -ssl, -Tuning
        - hydra: -l, -L, -p, -P, -t
        - sqlmap: -u, --dbs, --tables, --dump

        Args:
            command: Full command string (may be multi-line)

        Returns:
            ParsedCommand with structured fields
        """
        if not command or not command.strip():
            return ParsedCommand(tool="", subcommand=None, flags={}, parameters={}, arguments=[])

        # Normalize multi-line commands (remove backslash continuations)
        normalized = command.replace('\\\n', ' ').replace('\\', '')
        normalized = ' '.join(normalized.split('\n')).strip()

        # Extract tool name
        tool = CommandParser.extract_tool(normalized)

        # Parse based on tool type
        if tool in ['gobuster', 'nmap', 'nikto', 'hydra', 'sqlmap']:
            return CommandParser._parse_tool_specific(normalized, tool)
        else:
            # Generic fallback parser
            return CommandParser._parse_generic(normalized)

    @staticmethod
    def _parse_tool_specific(command: str, tool: str) -> ParsedCommand:
        """Parse tool-specific command with known flag patterns"""

        # Split command into tokens (handle quotes)
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Fallback if quote parsing fails
            tokens = command.split()

        if not tokens:
            return ParsedCommand(tool=tool)

        # Skip tool name (and sudo if present)
        idx = 1
        if tokens[0] == 'sudo':
            idx = 2

        # Detect subcommand (for gobuster)
        subcommand = None
        if tool == 'gobuster' and idx < len(tokens) and not tokens[idx].startswith('-'):
            subcommand = tokens[idx]
            idx += 1

        flags = {}
        parameters = {}
        arguments = []

        tool_config = CommandParser.TOOL_FLAGS.get(tool, {'value_flags': [], 'bool_flags': []})
        value_flags = tool_config['value_flags']
        bool_flags = tool_config['bool_flags']

        while idx < len(tokens):
            token = tokens[idx]

            # Boolean flag
            if token in bool_flags:
                flag_name = token.lstrip('-')
                flags[flag_name] = True
                idx += 1

            # Value flag
            elif token in value_flags or token.startswith('--'):
                flag_name = token.lstrip('-')

                # Get next token as value
                if idx + 1 < len(tokens) and not tokens[idx + 1].startswith('-'):
                    parameters[flag_name] = tokens[idx + 1]
                    idx += 2
                else:
                    # Flag without value (treat as boolean)
                    flags[flag_name] = True
                    idx += 1

            # Check for compound flags (e.g., -T4 -> -T with value 4)
            elif token.startswith('-') and len(token) > 2 and not token.startswith('--'):
                # Extract flag and potential value (e.g., -T4 -> flag=T, value=4)
                flag_part = '-' + token[1]
                value_part = token[2:]

                if flag_part in value_flags:
                    # Compound flag with value (e.g., -T4)
                    flag_name = flag_part.lstrip('-')
                    parameters[flag_name] = value_part
                    idx += 1
                else:
                    # Unknown flag or compound boolean (treat as positional)
                    arguments.append(token)
                    idx += 1

            # Positional argument
            else:
                arguments.append(token)
                idx += 1

        return ParsedCommand(
            tool=tool,
            subcommand=subcommand,
            flags=flags,
            parameters=parameters,
            arguments=arguments
        )

    @staticmethod
    def _parse_generic(command: str) -> ParsedCommand:
        """
        Generic fallback parser for unknown tools.
        Uses regex patterns to extract flags and parameters.
        """

        # Extract tool name
        tool = CommandParser.extract_tool(command)

        # Try to parse with shlex
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()

        if not tokens:
            return ParsedCommand(tool=tool)

        # Skip tool name
        idx = 1
        if tokens[0] == 'sudo':
            idx = 2

        flags = {}
        parameters = {}
        arguments = []

        # Generic pattern: -X or --XXX for flags, -X value for parameters
        while idx < len(tokens):
            token = tokens[idx]

            if token.startswith('-'):
                flag_name = token.lstrip('-')

                # Check if next token is a value (not a flag)
                if idx + 1 < len(tokens) and not tokens[idx + 1].startswith('-'):
                    parameters[flag_name] = tokens[idx + 1]
                    idx += 2
                else:
                    # Boolean flag
                    flags[flag_name] = True
                    idx += 1
            else:
                # Positional argument
                arguments.append(token)
                idx += 1

        return ParsedCommand(
            tool=tool,
            subcommand=None,
            flags=flags,
            parameters=parameters,
            arguments=arguments
        )
