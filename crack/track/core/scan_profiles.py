"""
Scan Profile Registry - Dynamic scan strategy management

Profiles define scan strategies (stealth, aggressive, quick, etc.) that can be:
- Loaded from JSON files
- Selected dynamically in interactive mode
- Mined/extended by CrackPot agent from Nmap cookbook

Separates scan strategy (data) from execution logic (code)
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class ScanProfileRegistry:
    """Central registry for scan profiles"""

    _profiles: Dict[str, Dict[str, Any]] = {}
    _initialized: bool = False

    @classmethod
    def initialize(cls):
        """Load scan profiles from data files"""
        if cls._initialized:
            return

        # Load built-in profiles
        profiles_file = Path(__file__).parent.parent / 'data' / 'scan_profiles.json'

        if profiles_file.exists():
            try:
                with open(profiles_file, 'r') as f:
                    data = json.load(f)
                    for profile in data.get('profiles', []):
                        cls._profiles[profile['id']] = profile
                logger.info(f"Loaded {len(cls._profiles)} scan profiles")
            except Exception as e:
                logger.error(f"Failed to load scan profiles: {e}")
                cls._load_defaults()
        else:
            logger.warning("No scan profiles file found, using defaults")
            cls._load_defaults()

        cls._initialized = True

    @classmethod
    def _load_defaults(cls):
        """Load default hardcoded profiles (fallback)"""
        defaults = [
            {
                'id': 'lab-quick',
                'name': 'Quick Scan (Top 1000 Ports)',
                'base_command': 'nmap --top-ports 1000',
                'timing': 'normal',
                'coverage': 'quick',
                'use_case': 'OSCP labs, CTF - fast initial discovery',
                'estimated_time': '1-2 minutes',
                'detection_risk': 'medium',
                'tags': ['QUICK_WIN', 'OSCP:HIGH', 'LAB'],
                'phases': ['discovery']
            },
            {
                'id': 'lab-full',
                'name': 'Full Port Scan (All 65535)',
                'base_command': 'nmap -p-',
                'timing': 'aggressive',
                'coverage': 'full',
                'use_case': 'OSCP labs - comprehensive port discovery',
                'estimated_time': '5-10 minutes',
                'detection_risk': 'medium',
                'tags': ['OSCP:HIGH', 'LAB', 'THOROUGH'],
                'phases': ['discovery'],
                'options': {
                    'min_rate': 1000
                }
            },
            {
                'id': 'stealth-slow',
                'name': 'Stealth Scan (Paranoid)',
                'base_command': 'nmap -sS -T0',
                'timing': 'paranoid',
                'coverage': 'full',
                'use_case': 'Production systems with IDS/IPS',
                'estimated_time': '30+ minutes',
                'detection_risk': 'very-low',
                'tags': ['STEALTH', 'PRODUCTION', 'SLOW'],
                'phases': ['discovery'],
                'notes': 'Extremely slow but very stealthy. Use for sensitive targets.'
            },
            {
                'id': 'stealth-normal',
                'name': 'Stealth Scan (Polite)',
                'base_command': 'nmap -sS -T2',
                'timing': 'polite',
                'coverage': 'full',
                'use_case': 'Production systems, moderate stealth',
                'estimated_time': '15-20 minutes',
                'detection_risk': 'low',
                'tags': ['STEALTH', 'PRODUCTION'],
                'phases': ['discovery']
            },
            {
                'id': 'aggressive-full',
                'name': 'Aggressive Full Scan',
                'base_command': 'nmap -sV -sC -A -T4 -p-',
                'timing': 'aggressive',
                'coverage': 'full',
                'use_case': 'Labs, time-critical pentests',
                'estimated_time': '10-15 minutes',
                'detection_risk': 'high',
                'tags': ['AGGRESSIVE', 'NOISY', 'LAB'],
                'phases': ['discovery', 'service-detection']
            }
        ]

        for profile in defaults:
            cls._profiles[profile['id']] = profile

    @classmethod
    def get_profile(cls, profile_id: str) -> Optional[Dict[str, Any]]:
        """Get profile by ID

        Args:
            profile_id: Profile identifier

        Returns:
            Profile dict or None if not found
        """
        if not cls._initialized:
            cls.initialize()

        return cls._profiles.get(profile_id)

    @classmethod
    def get_all_profiles(cls) -> List[Dict[str, Any]]:
        """Get all registered profiles

        Returns:
            List of profile dicts
        """
        if not cls._initialized:
            cls.initialize()

        return list(cls._profiles.values())

    @classmethod
    def get_profiles_for_phase(cls, phase: str, environment: str = 'lab') -> List[Dict[str, Any]]:
        """Get profiles suitable for a specific phase and environment

        Args:
            phase: Phase name (discovery, service-detection, etc.)
            environment: Target environment (lab, production, ctf)

        Returns:
            List of matching profiles
        """
        if not cls._initialized:
            cls.initialize()

        matches = []

        for profile in cls._profiles.values():
            # Check phase compatibility
            phases = profile.get('phases', [])
            if phases and phase not in phases:
                continue

            # Check environment compatibility
            tags = profile.get('tags', [])
            env_upper = environment.upper()

            # Environment-specific filtering
            if environment == 'production':
                # Prefer stealth profiles for production
                if 'PRODUCTION' in tags or 'STEALTH' in tags:
                    matches.append(profile)
            elif environment in ['lab', 'ctf']:
                # Prefer speed profiles for labs
                if 'LAB' in tags or 'QUICK_WIN' in tags or 'OSCP:HIGH' in tags:
                    matches.append(profile)
            else:
                # Unknown environment - show all applicable
                matches.append(profile)

        # Sort by priority (OSCP:HIGH first, then QUICK_WIN)
        def sort_key(p):
            tags = p.get('tags', [])
            if 'OSCP:HIGH' in tags:
                return 0
            elif 'QUICK_WIN' in tags:
                return 1
            else:
                return 2

        matches.sort(key=sort_key)

        return matches

    @classmethod
    def add_profile(cls, profile: Dict[str, Any]):
        """Add or update a profile

        Args:
            profile: Profile dict with required fields (id, name, base_command)
        """
        if not cls._initialized:
            cls.initialize()

        # Validate required fields
        required = ['id', 'name', 'base_command']
        for field in required:
            if field not in profile:
                raise ValueError(f"Profile missing required field: {field}")

        cls._profiles[profile['id']] = profile
        logger.info(f"Registered scan profile: {profile['id']}")

    @classmethod
    def clear(cls):
        """Clear all profiles (mainly for testing)"""
        cls._profiles.clear()
        cls._initialized = False


# Convenience functions
def get_profile(profile_id: str) -> Optional[Dict[str, Any]]:
    """Get scan profile by ID"""
    return ScanProfileRegistry.get_profile(profile_id)


def get_all_profiles() -> List[Dict[str, Any]]:
    """Get all scan profiles"""
    return ScanProfileRegistry.get_all_profiles()


def get_profiles_for_phase(phase: str, environment: str = 'lab') -> List[Dict[str, Any]]:
    """Get profiles for specific phase and environment"""
    return ScanProfileRegistry.get_profiles_for_phase(phase, environment)


def get_output_format_recommendation(use_case: str = 'oscp_exam') -> Dict[str, Any]:
    """Get output format best practices

    Chapter 8: Nmap output format recommendations for different use cases

    Args:
        use_case: Use case type ('oscp_exam', 'lab', 'production')

    Returns:
        Dictionary with output format recommendations
    """
    ScanProfileRegistry.initialize()

    # Load profiles to get metadata
    profiles_file = Path(__file__).parent.parent / 'data' / 'scan_profiles.json'

    if not profiles_file.exists():
        return _get_default_output_recommendations(use_case)

    try:
        with open(profiles_file, 'r') as f:
            data = json.load(f)
            meta = data.get('meta', {})
            best_practices = meta.get('output_format_best_practices', {})

            if use_case in best_practices:
                return best_practices[use_case]
            elif 'oscp_exam' in best_practices:
                return best_practices['oscp_exam']
            else:
                return _get_default_output_recommendations(use_case)

    except Exception as e:
        logger.error(f"Failed to load output recommendations: {e}")
        return _get_default_output_recommendations(use_case)


def _get_default_output_recommendations(use_case: str) -> Dict[str, Any]:
    """Get default output format recommendations (fallback)

    Args:
        use_case: Use case type

    Returns:
        Default recommendations dictionary
    """
    return {
        'recommended': '-oA',
        'explanation': 'Save all formats (normal, XML, greppable) simultaneously',
        'example': f'nmap -p- -oA scan_name <target>',
        'benefits': [
            'XML for automated parsing and tool imports',
            'Normal format for human-readable review',
            'Greppable for command-line filtering',
            'Complete documentation'
        ]
    }


def build_nmap_command(profile_id: str, target: str, output_basename: str = None,
                       add_reason: bool = True, add_traceroute: bool = False) -> str:
    """Build complete nmap command from profile with OSCP best practices

    Chapter 8: Automated command construction with output formats

    Args:
        profile_id: Scan profile ID
        target: Target IP or hostname
        output_basename: Output file basename (uses -oA)
        add_reason: Add --reason flag (recommended for OSCP)
        add_traceroute: Add --traceroute flag

    Returns:
        Complete nmap command string
    """
    profile = get_profile(profile_id)

    if not profile:
        raise ValueError(f"Unknown profile: {profile_id}")

    # Start with base command
    cmd_parts = [profile['base_command']]

    # Add target
    cmd_parts.append(target)

    # Add output (Chapter 8: Always use -oA for OSCP)
    if output_basename:
        cmd_parts.append(f'-oA {output_basename}')
    else:
        # Use profile ID as basename
        cmd_parts.append(f'-oA {profile_id}_{target.replace(".", "_")}')

    # Add --reason for troubleshooting (Chapter 8)
    if add_reason:
        cmd_parts.append('--reason')

    # Add traceroute if requested
    if add_traceroute:
        cmd_parts.append('--traceroute')

    # Add any profile-specific options
    options = profile.get('options', {})
    if options:
        if options.get('min_rate'):
            cmd_parts.append(f'--min-rate {options["min_rate"]}')

    return ' '.join(cmd_parts)


def validate_output_completeness(scan_dir: Path, basename: str) -> Dict[str, bool]:
    """Validate that all expected output files exist

    Chapter 8: OSCP documentation completeness check

    Args:
        scan_dir: Directory containing scan outputs
        basename: Output file basename (from -oA)

    Returns:
        Dictionary showing which formats are present
    """
    formats = {
        'normal': scan_dir / f'{basename}.nmap',
        'xml': scan_dir / f'{basename}.xml',
        'greppable': scan_dir / f'{basename}.gnmap'
    }

    return {
        format_name: filepath.exists()
        for format_name, filepath in formats.items()
    }
