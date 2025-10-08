"""
Scan Command Builder - Modular nmap command composition

Builds nmap commands from scan profiles using composition pattern.
Supports:
- Timing template selection (-T0 through -T5)
- Port range specification
- Output format selection
- Rate limiting
- Evasion techniques (future)
"""

from typing import Dict, Any, Optional


class ScanCommandBuilder:
    """Build nmap commands from scan profiles"""

    def __init__(self, target: str, profile: Dict[str, Any]):
        """
        Args:
            target: Target IP or hostname
            profile: Scan profile dict from ScanProfileRegistry
        """
        self.target = target
        self.profile = profile
        self.components = []

    def build(self) -> str:
        """Compose final nmap command

        Returns:
            Complete nmap command string
        """
        cmd_parts = [
            self.profile.get('base_command', 'nmap'),
            self._get_timing(),
            self._get_port_spec(),
            self._get_rate_limiting(),
            self._get_evasion(),
            self._get_output(),
            self.target
        ]

        # Filter out None/empty strings
        return ' '.join(filter(None, cmd_parts))

    def _get_timing(self) -> str:
        """Get timing template flag

        Returns:
            Timing flag (-T0 through -T5) or empty string
        """
        timing = self.profile.get('timing', '').lower()

        timing_map = {
            'paranoid': '-T0',
            'sneaky': '-T1',
            'polite': '-T2',
            'normal': '-T3',
            'aggressive': '-T4',
            'insane': '-T5'
        }

        # Only add if not already in base_command
        base_cmd = self.profile.get('base_command', '')
        flag = timing_map.get(timing, '')

        if flag and flag not in base_cmd:
            return flag

        return ''

    def _get_port_spec(self) -> str:
        """Get port range specification

        Returns:
            Port spec flag or empty string
        """
        coverage = self.profile.get('coverage', '')

        # Check if already specified in base_command
        base_cmd = self.profile.get('base_command', '')

        if '-p' in base_cmd or '--top-ports' in base_cmd:
            # Already specified
            return ''

        if coverage == 'full':
            return '-p-'
        elif coverage == 'quick':
            return '--top-ports 1000'
        elif coverage == 'common':
            return '--top-ports 100'

        return ''

    def _get_rate_limiting(self) -> str:
        """Get rate limiting flags

        Returns:
            Rate limiting flags or empty string
        """
        options = self.profile.get('options', {})
        base_cmd = self.profile.get('base_command', '')

        parts = []

        # Min rate
        if 'min_rate' in options and '--min-rate' not in base_cmd:
            parts.append(f"--min-rate {options['min_rate']}")

        # Max rate
        if 'max_rate' in options and '--max-rate' not in base_cmd:
            parts.append(f"--max-rate {options['max_rate']}")

        # Max retries
        if 'max_retries' in options and '--max-retries' not in base_cmd:
            parts.append(f"--max-retries {options['max_retries']}")

        # Host timeout
        if 'host_timeout' in options and '--host-timeout' not in base_cmd:
            parts.append(f"--host-timeout {options['host_timeout']}")

        # Min/Max hostgroup (parallelism for multi-target scans)
        if 'min_hostgroup' in options and '--min-hostgroup' not in base_cmd:
            parts.append(f"--min-hostgroup {options['min_hostgroup']}")

        if 'max_hostgroup' in options and '--max-hostgroup' not in base_cmd:
            parts.append(f"--max-hostgroup {options['max_hostgroup']}")

        # Probe parallelism control
        if 'min_parallelism' in options and '--min-parallelism' not in base_cmd:
            parts.append(f"--min-parallelism {options['min_parallelism']}")

        if 'max_parallelism' in options and '--max-parallelism' not in base_cmd:
            parts.append(f"--max-parallelism {options['max_parallelism']}")

        # RTT timeout tuning
        if 'initial_rtt_timeout' in options and '--initial-rtt-timeout' not in base_cmd:
            parts.append(f"--initial-rtt-timeout {options['initial_rtt_timeout']}")

        if 'max_rtt_timeout' in options and '--max-rtt-timeout' not in base_cmd:
            parts.append(f"--max-rtt-timeout {options['max_rtt_timeout']}")

        if 'min_rtt_timeout' in options and '--min-rtt-timeout' not in base_cmd:
            parts.append(f"--min-rtt-timeout {options['min_rtt_timeout']}")

        # Scan delay (IDS evasion)
        if 'scan_delay' in options and '--scan-delay' not in base_cmd:
            parts.append(f"--scan-delay {options['scan_delay']}")

        if 'max_scan_delay' in options and '--max-scan-delay' not in base_cmd:
            parts.append(f"--max-scan-delay {options['max_scan_delay']}")

        return ' '.join(parts)

    def _get_evasion(self) -> str:
        """Get firewall evasion flags (Chapter 2 techniques)

        Returns:
            Evasion flags or empty string
        """
        options = self.profile.get('options', {})
        base_cmd = self.profile.get('base_command', '')

        parts = []

        # Packet padding (random data evasion)
        if 'data_length' in options and '--data-length' not in base_cmd:
            parts.append(f"--data-length {options['data_length']}")

        # MAC address spoofing (ARP-level evasion)
        if 'spoof_mac' in options and '--spoof-mac' not in base_cmd:
            parts.append(f"--spoof-mac {options['spoof_mac']}")

        # Decoy scanning (hide among decoys)
        if 'decoys' in options and '-D' not in base_cmd:
            parts.append(f"-D {options['decoys']}")

        # Source port spoofing (bypass simple firewalls)
        if 'source_port' in options and '--source-port' not in base_cmd:
            parts.append(f"--source-port {options['source_port']}")

        # Packet fragmentation (split packets to evade signatures)
        if options.get('fragment') and '-f' not in base_cmd:
            parts.append('-f')

        # MTU specification (custom fragmentation size)
        if 'mtu' in options and '--mtu' not in base_cmd:
            parts.append(f"--mtu {options['mtu']}")

        return ' '.join(parts)

    def _get_output(self) -> str:
        """Get output format specification

        Returns:
            Output flags
        """
        base_cmd = self.profile.get('base_command', '')

        # Check if output already specified
        if '-oA' in base_cmd or '-oN' in base_cmd or '-oX' in base_cmd:
            return ''

        # Default output format based on coverage
        coverage = self.profile.get('coverage', '')
        profile_id = self.profile.get('id', 'scan')

        if coverage == 'full':
            # Full scans get all formats for import
            return f'-oA {profile_id}_scan'
        else:
            # Quick scans get normal format only
            return f'-oN {profile_id}_scan.nmap'


class ServiceScanCommandBuilder(ScanCommandBuilder):
    """Build service version detection commands"""

    def __init__(self, target: str, ports: str, profile: Optional[Dict[str, Any]] = None):
        """
        Args:
            target: Target IP or hostname
            ports: Port specification (e.g., "80,443" or "22,80,445")
            profile: Optional scan profile (uses default if not provided)
        """
        if profile is None:
            # Default service scan profile
            profile = {
                'id': 'service-detect',
                'base_command': 'nmap -sV -sC',
                'timing': 'normal',
                'use_case': 'Service version detection with default scripts'
            }

        super().__init__(target, profile)
        self.ports = ports

    def _get_port_spec(self) -> str:
        """Override to use provided ports"""
        if self.ports:
            return f'-p {self.ports}'
        return ''

    def _get_output(self) -> str:
        """Service scans always use XML for import"""
        return '-oA service_scan'


def build_discovery_command(target: str, profile_id: str) -> str:
    """Build port discovery command

    Args:
        target: Target IP/hostname
        profile_id: Scan profile ID

    Returns:
        Complete nmap command
    """
    from .scan_profiles import get_profile

    profile = get_profile(profile_id)
    if not profile:
        raise ValueError(f"Unknown scan profile: {profile_id}")

    builder = ScanCommandBuilder(target, profile)
    return builder.build()


def build_service_command(target: str, ports: str, profile_id: Optional[str] = None) -> str:
    """Build service version detection command

    Args:
        target: Target IP/hostname
        ports: Comma-separated port list
        profile_id: Optional service scan profile ID

    Returns:
        Complete nmap command
    """
    from .scan_profiles import get_profile

    profile = None
    if profile_id:
        profile = get_profile(profile_id)

    builder = ServiceScanCommandBuilder(target, ports, profile)
    return builder.build()
