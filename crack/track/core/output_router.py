"""
Output Router - Centralized output path management for CRACK commands

Automatically injects output flags into commands to ensure all tool outputs
are saved to target-specific directories (CRACK_targets/<target>/scans/).

Key Features:
- Tool-agnostic: Works with nmap, gobuster, nikto, hydra, enum4linux, etc.
- Non-invasive: Only adds output flags when not already present
- Fallback safe: Captures stdout for tools without native output flags
- OSCP compliant: All outputs systematically organized per target
"""

import os
import re
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
from datetime import datetime


class OutputRouter:
    """Centralized output path management for all CRACK commands"""

    # Tool-specific output flag patterns
    OUTPUT_PATTERNS = {
        'nmap': {
            'detect': r'\bnmap\b',
            'has_output': r'-o[ANXG]',  # -oA, -oN, -oX, -oG
            'inject_template': '-oA {scans_dir}/nmap_{timestamp}',
            'position': 'before_target',  # Insert before target IP
            'file_extension': '.nmap',  # Primary output file
        },
        'gobuster': {
            'detect': r'\bgobuster\b',
            'has_output': r'-o\s+\S+',
            'inject_template': '-o {scans_dir}/gobuster_{port}_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'nikto': {
            'detect': r'\bnikto\b',
            'has_output': r'-output\s+\S+',
            'inject_template': '-output {scans_dir}/nikto_{port}_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'hydra': {
            'detect': r'\bhydra\b',
            'has_output': r'-o\s+\S+',
            'inject_template': '-o {scans_dir}/hydra_{timestamp}.txt',
            'position': 'before_target',
            'file_extension': '.txt',
        },
        'enum4linux': {
            'detect': r'\benum4linux\b',
            'has_output': r'\|\s*tee',  # Check for existing tee
            'inject_template': '| tee {scans_dir}/enum4linux_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'wpscan': {
            'detect': r'\bwpscan\b',
            'has_output': r'--output\s+\S+',
            'inject_template': '--output {scans_dir}/wpscan_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'feroxbuster': {
            'detect': r'\bferoxbuster\b',
            'has_output': r'-o\s+\S+',
            'inject_template': '-o {scans_dir}/feroxbuster_{port}_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'dirb': {
            'detect': r'\bdirb\b',
            'has_output': r'-o\s+\S+',
            'inject_template': '-o {scans_dir}/dirb_{port}_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'wfuzz': {
            'detect': r'\bwfuzz\b',
            'has_output': r'-f\s+\S+',
            'inject_template': '-f {scans_dir}/wfuzz_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'sqlmap': {
            'detect': r'\bsqlmap\b',
            'has_output': r'--output-dir\s+\S+',
            'inject_template': '--output-dir={scans_dir}/sqlmap_{timestamp}',
            'position': 'end',
            'file_extension': '/log',  # Directory-based output
        },
        'searchsploit': {
            'detect': r'\bsearchsploit\b',
            'has_output': r'>\s*\S+\.txt',  # Check for redirect
            'inject_template': '> {scans_dir}/searchsploit_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'smbclient': {
            'detect': r'\bsmbclient\b',
            'has_output': r'\|\s*tee',
            'inject_template': '| tee {scans_dir}/smbclient_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'smbmap': {
            'detect': r'\bsmbmap\b',
            'has_output': r'-o\s+\S+',
            'inject_template': '| tee {scans_dir}/smbmap_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'rpcclient': {
            'detect': r'\brpcclient\b',
            'has_output': r'\|\s*tee',
            'inject_template': '| tee {scans_dir}/rpcclient_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'ldapsearch': {
            'detect': r'\bldapsearch\b',
            'has_output': r'>\s*\S+\.txt',
            'inject_template': '> {scans_dir}/ldapsearch_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'snmpwalk': {
            'detect': r'\bsnmpwalk\b',
            'has_output': r'>\s*\S+\.txt',
            'inject_template': '> {scans_dir}/snmpwalk_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'crackmapexec': {
            'detect': r'\bcrackmapexec\b',
            'has_output': r'\|\s*tee',
            'inject_template': '| tee {scans_dir}/crackmapexec_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
        'john': {
            'detect': r'\bjohn\b',
            'has_output': r'--pot=\S+',
            'inject_template': '--pot={scans_dir}/john_{timestamp}.pot',
            'position': 'before_hash_file',
            'file_extension': '.pot',
        },
        'hashcat': {
            'detect': r'\bhashcat\b',
            'has_output': r'-o\s+\S+|--outfile\s+\S+',
            'inject_template': '-o {scans_dir}/hashcat_{timestamp}.txt',
            'position': 'end',
            'file_extension': '.txt',
        },
    }

    @staticmethod
    def get_scans_dir(target: str) -> Path:
        """
        Get target-specific scans directory

        Priority order:
        1. CRACK_OUTPUT_DIR environment variable (if set)
        2. CRACK_targets/<target>/scans/ (project-local, default)
        3. ~/.crack/targets/<target>/scans/ (legacy fallback)

        Args:
            target: Target IP or hostname

        Returns:
            Path to scans directory (created if doesn't exist)
        """
        # Sanitize target for directory name
        safe_target = target.replace('/', '_')
        safe_target = re.sub(r'[<>:"|?*]', '_', safe_target)
        safe_target = safe_target.strip('. ') or 'target'

        # Check environment variable override
        env_dir = os.environ.get('CRACK_OUTPUT_DIR')
        if env_dir:
            scans_dir = Path(env_dir) / safe_target / 'scans'
            scans_dir.mkdir(parents=True, exist_ok=True)
            return scans_dir

        # Check project-local directory (new default)
        local_dir = Path.cwd() / 'CRACK_targets' / safe_target / 'scans'
        if local_dir.parent.parent.exists() or not (Path.home() / '.crack' / 'targets' / safe_target).exists():
            # Use local if CRACK_targets exists, or legacy doesn't exist
            local_dir.mkdir(parents=True, exist_ok=True)
            return local_dir

        # Fallback to legacy directory
        legacy_dir = Path.home() / '.crack' / 'targets' / safe_target / 'scans'
        legacy_dir.mkdir(parents=True, exist_ok=True)
        return legacy_dir

    @staticmethod
    def inject_output_flags(
        command: str,
        target: str,
        task_metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, Optional[Path]]:
        """
        Inject tool-specific output flags into command

        Args:
            command: Original command string
            target: Target IP/hostname (for directory path)
            task_metadata: Optional task metadata (port, task_id, etc.)

        Returns:
            Tuple of (modified_command, expected_output_file_path)
            If no injection performed, returns (original_command, None)
        """
        if not command or not target:
            return (command, None)

        task_metadata = task_metadata or {}

        # Get scans directory
        scans_dir = OutputRouter.get_scans_dir(target)

        # Generate timestamp for unique filenames
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Extract port from metadata if available
        port = task_metadata.get('port', '')

        # Detect tool and check if output flag already present
        for tool_name, pattern_config in OutputRouter.OUTPUT_PATTERNS.items():
            detect_pattern = pattern_config['detect']
            has_output_pattern = pattern_config.get('has_output')

            # Check if command uses this tool
            if not re.search(detect_pattern, command):
                continue

            # Check if output flag already present
            if has_output_pattern and re.search(has_output_pattern, command):
                # Output already specified, don't override
                # Try to extract existing output path
                existing_path = OutputRouter._extract_existing_output_path(
                    command, has_output_pattern
                )
                return (command, existing_path)

            # Inject output flag
            inject_template = pattern_config['inject_template']
            position = pattern_config.get('position', 'end')
            file_extension = pattern_config.get('file_extension', '.txt')

            # Format injection string
            injection = inject_template.format(
                scans_dir=scans_dir,
                timestamp=timestamp,
                port=port or 'unknown',
                target=target.replace('/', '_')
            )

            # Determine expected output file
            if file_extension.startswith('/'):
                # Directory-based output (e.g., sqlmap)
                output_file = Path(injection.split('=')[1] if '=' in injection else injection.split()[-1]) / 'log'
            else:
                # File-based output
                output_file = Path(injection.split()[-1])

            # Inject based on position
            if position == 'end':
                modified_command = f"{command} {injection}"
            elif position == 'before_target':
                # Insert before target IP pattern
                target_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
                match = re.search(target_pattern, command)
                if match:
                    insert_pos = match.start()
                    modified_command = command[:insert_pos] + injection + ' ' + command[insert_pos:]
                else:
                    # Fallback to end if no target IP found
                    modified_command = f"{command} {injection}"
            else:
                # Unknown position, append to end
                modified_command = f"{command} {injection}"

            return (modified_command, output_file)

        # No tool matched, return original command
        return (command, None)

    @staticmethod
    def _extract_existing_output_path(command: str, output_pattern: str) -> Optional[Path]:
        """
        Extract existing output path from command if present

        Args:
            command: Command string
            output_pattern: Regex pattern for output flag (e.g., r'-o\s+\S+')

        Returns:
            Path to output file if found, None otherwise
        """
        # The pattern already includes the filename part like '-o\s+\S+'
        # So we match the whole thing and extract just the filename
        match = re.search(output_pattern, command)
        if match:
            # Extract the filename part from the matched string
            matched_str = match.group(0)
            # Split on whitespace to get the filename (last part)
            parts = matched_str.split()
            if len(parts) >= 2:
                path_str = parts[-1]
                # Remove quotes if present
                path_str = path_str.strip('"\'')
                return Path(path_str)
        return None

    @staticmethod
    def save_captured_output(
        output: str,
        target: str,
        task_id: str,
        timestamp: Optional[str] = None
    ) -> Path:
        """
        Fallback: Save captured stdout for tools without native output flags

        Args:
            output: Captured stdout/stderr content
            target: Target IP/hostname
            task_id: Task identifier
            timestamp: Optional timestamp (generated if not provided)

        Returns:
            Path to saved output file
        """
        scans_dir = OutputRouter.get_scans_dir(target)

        if timestamp is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Sanitize task_id for filename
        safe_task_id = re.sub(r'[<>:"|?*]', '_', task_id)

        output_file = scans_dir / f"fallback_{safe_task_id}_{timestamp}.stdout"

        with open(output_file, 'w') as f:
            f.write(output)

        return output_file

    @staticmethod
    def get_output_file_for_task(task_metadata: Dict[str, Any], target: str) -> Optional[Path]:
        """
        Get expected output file path for a task (without executing)

        Args:
            task_metadata: Task metadata dict
            target: Target IP/hostname

        Returns:
            Expected output file path if determinable, None otherwise
        """
        command = task_metadata.get('command', '')
        if not command:
            return None

        _, output_file = OutputRouter.inject_output_flags(command, target, task_metadata)
        return output_file
