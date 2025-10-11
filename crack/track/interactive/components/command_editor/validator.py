"""
Command Validator - Safety and syntax checks for commands

Validates command syntax, checks file paths, validates tool-specific flags,
estimates runtime, and performs security checks.
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional


@dataclass
class ValidationResult:
    """Result of validation check"""
    is_valid: bool
    errors: List[str]  # Blocking issues
    warnings: List[str]  # Non-blocking suggestions


@dataclass
class ValidationWarning:
    """Detailed warning with context"""
    type: str  # "missing_file", "slow_operation", "security_risk"
    message: str
    severity: str  # "info", "warning", "error"


@dataclass
class ParsedCommand:
    """Parsed command structure (for validate_flags compatibility)"""
    tool: str
    subcommand: Optional[str]
    flags: Dict[str, bool]  # Boolean flags (-v, -f)
    parameters: Dict[str, str]  # Value params (-u URL, -w PATH)
    arguments: List[str]  # Positional args


class CommandValidator:
    """Validates commands for safety and correctness"""

    # Dangerous command patterns
    DANGEROUS_PATTERNS = [
        r'\brm\s+-rf\s+/',
        r'\brm\s+-rf\s+\*',
        r'/etc/.*',
        r'\bdd\s+.*of=/dev/',
        r':\(\)\{.*\};:',  # Fork bomb
        r'chmod\s+777\s+/',
        r'chown\s+.*\s+/',
    ]

    # Tool-specific incompatible flags
    FLAG_CONFLICTS = {
        'nmap': [
            ('-sS', '-sT'),  # SYN scan vs Connect scan
            ('-sU', '-sT'),  # UDP vs TCP
            ('-sn', '-p'),   # No port scan vs port specification
        ],
        'gobuster': [
            ('-q', '-v'),    # Quiet vs Verbose
        ],
    }

    # Runtime estimation rules (seconds)
    RUNTIME_ESTIMATES = {
        'gobuster': {
            'base': 60,
            'wordlist_multiplier': 0.001,  # Per word
            'threads_divisor': 10,
        },
        'nmap': {
            'base': 30,
            'port_multiplier': 0.5,  # Per 1000 ports
            'timing_factors': {
                '0': 10.0,
                '1': 5.0,
                '2': 2.0,
                '3': 1.0,
                '4': 0.5,
                '5': 0.2,
            }
        },
        'hydra': {
            'base': 120,
            'user_multiplier': 1.0,
            'password_multiplier': 0.1,
        }
    }

    @staticmethod
    def validate_syntax(command: str) -> ValidationResult:
        """Check basic syntax validity

        Validates:
        - Balanced quotes (single and double)
        - Balanced parentheses
        - Line continuation validity
        - Basic shell syntax

        Args:
            command: Command string to validate

        Returns:
            ValidationResult with errors for syntax issues
        """
        errors = []
        warnings = []

        # Check for empty command
        if not command or not command.strip():
            errors.append("Command is empty")
            return ValidationResult(is_valid=False, errors=errors, warnings=warnings)

        # Check balanced quotes
        single_quotes = command.count("'") - command.count("\\'")
        double_quotes = command.count('"') - command.count('\\"')

        if single_quotes % 2 != 0:
            errors.append("Unbalanced single quotes")

        if double_quotes % 2 != 0:
            errors.append("Unbalanced double quotes")

        # Check balanced parentheses
        paren_count = 0
        for char in command:
            if char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
            if paren_count < 0:
                errors.append("Unbalanced parentheses (closing before opening)")
                break

        if paren_count > 0:
            errors.append("Unbalanced parentheses (unclosed)")

        # Check line continuations
        lines = command.split('\n')
        for i, line in enumerate(lines[:-1]):  # Skip last line
            stripped = line.rstrip()
            if stripped and not stripped.endswith('\\'):
                warnings.append(f"Line {i+1} may need continuation backslash")

        # Check for trailing backslash with nothing after
        if command.rstrip().endswith('\\') and not command.endswith('\\\n'):
            warnings.append("Trailing backslash with no continuation")

        is_valid = len(errors) == 0
        return ValidationResult(is_valid=is_valid, errors=errors, warnings=warnings)

    @staticmethod
    def validate_paths(command: str) -> List[ValidationWarning]:
        """Check if file paths exist

        Extracts potential file paths from command and checks their existence.
        Handles:
        - Absolute paths (/path/to/file)
        - Relative paths (./file, ../file)
        - Wordlists, output files, config files
        - Symbolic links

        Args:
            command: Command string containing file paths

        Returns:
            List of ValidationWarning for missing or problematic paths
        """
        warnings = []

        # Extract potential file paths (after common flags)
        path_patterns = [
            r'-w\s+([^\s]+)',      # Wordlist
            r'-o\s+([^\s]+)',      # Output
            r'-oA\s+([^\s]+)',     # Output (nmap)
            r'-i\s+([^\s]+)',      # Input file
            r'-c\s+([^\s]+)',      # Config
            r'-L\s+([^\s]+)',      # List file (hydra)
            r'-P\s+([^\s]+)',      # Password file
            r'--wordlist[=\s]+([^\s]+)',
            r'--output[=\s]+([^\s]+)',
        ]

        checked_paths = set()
        for pattern in path_patterns:
            matches = re.finditer(pattern, command)
            for match in matches:
                path_str = match.group(1)

                # Skip if already checked
                if path_str in checked_paths:
                    continue
                checked_paths.add(path_str)

                # Expand ~ and environment variables
                expanded_path = os.path.expanduser(os.path.expandvars(path_str))
                path = Path(expanded_path)

                # Check if path exists
                if not path.exists():
                    # Check if it's likely an output file (will be created)
                    if '-o' in command or '--output' in command:
                        # Verify parent directory exists
                        if path.parent != Path('.') and not path.parent.exists():
                            warnings.append(ValidationWarning(
                                type="missing_file",
                                message=f"Output directory does not exist: {path.parent}",
                                severity="error"
                            ))
                        else:
                            warnings.append(ValidationWarning(
                                type="missing_file",
                                message=f"Output file will be created: {path_str}",
                                severity="info"
                            ))
                    else:
                        warnings.append(ValidationWarning(
                            type="missing_file",
                            message=f"File does not exist: {path_str}",
                            severity="warning"
                        ))
                elif path.is_symlink():
                    target = path.resolve()
                    if not target.exists():
                        warnings.append(ValidationWarning(
                            type="missing_file",
                            message=f"Symbolic link points to non-existent target: {path_str} -> {target}",
                            severity="error"
                        ))
                    else:
                        warnings.append(ValidationWarning(
                            type="missing_file",
                            message=f"Path is symbolic link: {path_str} -> {target}",
                            severity="info"
                        ))

        return warnings

    @staticmethod
    def validate_flags(parsed: ParsedCommand) -> ValidationResult:
        """Check tool-specific flag compatibility

        Validates that flags don't conflict with each other based on
        tool-specific rules (e.g., nmap -sS and -sT are incompatible).

        Args:
            parsed: ParsedCommand with extracted flags

        Returns:
            ValidationResult with errors for flag conflicts
        """
        errors = []
        warnings = []

        tool = parsed.tool.lower()

        # Check for tool-specific conflicts
        if tool in CommandValidator.FLAG_CONFLICTS:
            conflicts = CommandValidator.FLAG_CONFLICTS[tool]

            for flag1, flag2 in conflicts:
                # Check both in flags dict and in command reconstruction
                has_flag1 = flag1.lstrip('-') in parsed.flags or flag1 in str(parsed.parameters)
                has_flag2 = flag2.lstrip('-') in parsed.flags or flag2 in str(parsed.parameters)

                if has_flag1 and has_flag2:
                    errors.append(f"{tool}: Incompatible flags {flag1} and {flag2}")

        # Tool-specific validations
        if tool == 'nmap':
            # Check for required target
            if not parsed.arguments and 'target' not in parsed.parameters:
                errors.append("nmap: No target specified")

            # Warn about aggressive scan without sudo
            if 'sS' in parsed.flags or 'O' in parsed.flags:
                warnings.append("SYN scan (-sS) or OS detection (-O) requires root privileges")

        elif tool == 'gobuster':
            # Check required flags
            if 'u' not in parsed.parameters and 'url' not in parsed.parameters:
                errors.append("gobuster: Missing required flag -u (URL)")
            if 'w' not in parsed.parameters and 'wordlist' not in parsed.parameters:
                errors.append("gobuster: Missing required flag -w (wordlist)")

        elif tool == 'hydra':
            # Check for username/password specification
            has_user = 'l' in parsed.parameters or 'L' in parsed.parameters
            has_pass = 'p' in parsed.parameters or 'P' in parsed.parameters

            if not has_user:
                errors.append("hydra: No username specified (-l or -L)")
            if not has_pass:
                errors.append("hydra: No password specified (-p or -P)")

        is_valid = len(errors) == 0
        return ValidationResult(is_valid=is_valid, errors=errors, warnings=warnings)

    @staticmethod
    def estimate_runtime(command: str, tool: str) -> int:
        """Estimate execution time in seconds

        Estimates based on:
        - Gobuster: Wordlist size, threads
        - Nmap: Port range, timing template
        - Hydra: Username/password list sizes

        Args:
            command: Full command string
            tool: Tool name (gobuster, nmap, hydra, etc.)

        Returns:
            Estimated runtime in seconds (0 if unknown)
        """
        tool = tool.lower()

        if tool not in CommandValidator.RUNTIME_ESTIMATES:
            return 0  # Unknown tool

        estimate_rules = CommandValidator.RUNTIME_ESTIMATES[tool]
        base_time = estimate_rules['base']

        if tool == 'gobuster':
            # Extract wordlist size
            wordlist_match = re.search(r'-w\s+([^\s]+)', command)
            if wordlist_match:
                wordlist_path = wordlist_match.group(1)
                try:
                    with open(os.path.expanduser(wordlist_path), 'r') as f:
                        word_count = sum(1 for _ in f)
                    base_time += word_count * estimate_rules['wordlist_multiplier']
                except (FileNotFoundError, PermissionError):
                    pass  # Use base time

            # Extract threads
            threads_match = re.search(r'-t\s+(\d+)', command)
            if threads_match:
                threads = int(threads_match.group(1))
                base_time /= (threads / estimate_rules['threads_divisor'])

        elif tool == 'nmap':
            # Extract port range
            ports_match = re.search(r'-p\s+([^\s]+)', command)
            if ports_match:
                ports_str = ports_match.group(1)
                if ports_str == '-':
                    port_count = 65535
                elif '-' in ports_str and ',' not in ports_str:
                    parts = ports_str.split('-')
                    if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                        port_count = int(parts[1]) - int(parts[0]) + 1
                    else:
                        port_count = 1000  # Default
                else:
                    port_count = len(ports_str.split(','))

                base_time += (port_count / 1000) * estimate_rules['port_multiplier']
            else:
                base_time += estimate_rules['port_multiplier']  # Default 1000 ports

            # Extract timing template
            timing_match = re.search(r'-T([0-5])', command)
            if timing_match:
                timing = timing_match.group(1)
                factor = estimate_rules['timing_factors'].get(timing, 1.0)
                base_time *= factor

        elif tool == 'hydra':
            # Estimate based on user/password list sizes
            user_count = 1
            pass_count = 1

            # Check for user list
            user_list_match = re.search(r'-L\s+([^\s]+)', command)
            if user_list_match:
                try:
                    with open(os.path.expanduser(user_list_match.group(1)), 'r') as f:
                        user_count = sum(1 for _ in f)
                except (FileNotFoundError, PermissionError):
                    user_count = 10  # Estimate

            # Check for password list
            pass_list_match = re.search(r'-P\s+([^\s]+)', command)
            if pass_list_match:
                try:
                    with open(os.path.expanduser(pass_list_match.group(1)), 'r') as f:
                        pass_count = sum(1 for _ in f)
                except (FileNotFoundError, PermissionError):
                    pass_count = 100  # Estimate

            base_time += (user_count * estimate_rules['user_multiplier'] +
                         pass_count * estimate_rules['password_multiplier'])

        return int(base_time)

    @staticmethod
    def validate_security(command: str) -> List[ValidationWarning]:
        """Perform security checks on command

        Checks for:
        - Dangerous rm -rf patterns
        - /etc writes
        - dd to /dev devices
        - Fork bombs
        - Suspicious chmod/chown

        Args:
            command: Command string to check

        Returns:
            List of ValidationWarning for security issues
        """
        warnings = []

        for pattern in CommandValidator.DANGEROUS_PATTERNS:
            if re.search(pattern, command):
                warnings.append(ValidationWarning(
                    type="security_risk",
                    message=f"Dangerous pattern detected: {pattern}",
                    severity="error"
                ))

        # Check for /etc writes
        if '/etc/' in command and any(op in command for op in ['>', '>>', 'tee']):
            warnings.append(ValidationWarning(
                type="security_risk",
                message="Command attempts to write to /etc",
                severity="error"
            ))

        return warnings
