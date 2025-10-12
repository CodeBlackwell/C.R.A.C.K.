#!/usr/bin/env python3
"""
Generate QA profile packages for testing plugin priority and event handler fixes

Creates pre-configured profiles for each test story to enable zero-setup testing.
Profiles are generated in ../CRACK_targets/ with qa-* prefix for easy identification.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path to import track modules
sys.path.insert(0, str(Path(__file__).parent.parent))


def generate_base_profile(target: str, phase: str = 'discovery') -> dict:
    """Generate base profile structure

    Args:
        target: Target hostname
        phase: Enumeration phase

    Returns:
        Base profile dictionary
    """
    now = datetime.now().isoformat()

    return {
        'target': target,
        'created': now,
        'updated': now,
        'phase': phase,
        'status': 'in-progress',
        'ports': {},
        'findings': [],
        'credentials': [],
        'notes': [],
        'imported_files': [],
        'metadata': {
            'environment': 'lab',
            'default_timing': 'normal',
            'preferred_profile': None,
            'evasion_enabled': False,
            'confirmation_mode': 'smart'
        },
        'scan_history': [],
        'task_tree': {
            'id': 'root',
            'name': f'Enumeration: {target}',
            'type': 'parent',
            'status': 'pending',
            'metadata': {
                'command': None,
                'description': None,
                'spawned_by': None,
                'depends_on': [],
                'tags': [],
                'created_at': now,
                'completed_at': None,
                'notes': [],
                'alternatives': [],
                'alternative_ids': [],
                'alternative_context': {},
                'wordlist': None,
                'wordlist_purpose': None,
                'wordlist_variant': 'default',
                'execution_history': []
            },
            'children': [
                {
                    'id': 'ping-check',
                    'name': 'Verify host is alive',
                    'type': 'command',
                    'status': 'pending',
                    'metadata': {
                        'command': f'ping -c 3 {target}',
                        'description': 'Quick ICMP ping to verify host responds',
                        'spawned_by': None,
                        'depends_on': [],
                        'tags': ['QUICK_WIN', 'OSCP:HIGH'],
                        'created_at': now,
                        'completed_at': None,
                        'notes': [],
                        'alternatives': [],
                        'alternative_ids': [],
                        'alternative_context': {},
                        'wordlist': None,
                        'wordlist_purpose': None,
                        'wordlist_variant': 'default',
                        'execution_history': [],
                        'flag_explanations': {
                            '-c 3': 'Send 3 ICMP echo requests'
                        }
                    },
                    'children': []
                },
                {
                    'id': 'port-discovery',
                    'name': 'Port Discovery',
                    'type': 'scan',
                    'status': 'pending',
                    'metadata': {
                        'command': None,
                        'description': 'Discover open ports on target',
                        'spawned_by': None,
                        'depends_on': [],
                        'tags': ['OSCP:HIGH'],
                        'created_at': now,
                        'completed_at': None,
                        'notes': [
                            'Choose scan strategy based on environment',
                            'Labs: use lab-quick or lab-full',
                            'Production: use stealth-normal',
                            'Full scan critical for OSCP - finds unusual high ports'
                        ],
                        'alternatives': [],
                        'alternative_ids': [],
                        'alternative_context': {},
                        'wordlist': None,
                        'wordlist_purpose': None,
                        'wordlist_variant': 'default',
                        'execution_history': [],
                        'allow_custom': True
                    },
                    'children': []
                }
            ]
        }
    }


def story_1_generic_http():
    """Story 1: Generic HTTP service (PHP-Bypass should NOT activate)

    Starting State:
    - Port 80: service='http', no PHP indicators
    - Expected: HTTP Plugin wins (100 > 0)
    - Tasks: gobuster, nikto, whatweb
    - NO PHP-Bypass tasks
    """
    profile = generate_base_profile('qa-story-1-generic-http')

    # Add HTTP port (no PHP)
    profile['ports']['80'] = {
        'state': 'open',
        'service': 'http',
        'version': None,
        'source': 'qa-profile-generator',
        'updated_at': datetime.now().isoformat(),
        'protocol': 'tcp'
    }

    return profile


def story_2_http_with_php():
    """Story 2: HTTP with PHP in version (both plugins should activate)

    Starting State:
    - Port 80: service='http', version='Apache/2.4.41 PHP/7.4.3'
    - Expected: HTTP Plugin wins (100), PHP-Bypass also activates (95)
    - Tasks: Both HTTP + PHP tasks
    """
    profile = generate_base_profile('qa-story-2-http-with-php')

    # Add HTTP port with PHP in version
    profile['ports']['80'] = {
        'state': 'open',
        'service': 'http',
        'version': 'Apache/2.4.41 (Ubuntu) PHP/7.4.3',
        'source': 'qa-profile-generator',
        'updated_at': datetime.now().isoformat(),
        'protocol': 'tcp',
        'product': 'Apache httpd'
    }

    return profile


def story_3_progressive_discovery():
    """Story 3: Progressive discovery (finding-based activation)

    Starting State:
    - Port 80: service='http', no PHP
    - Test Steps:
      1. Load profile → See only HTTP tasks
      2. Add PHP finding → PHP-Bypass tasks appear
    """
    profile = generate_base_profile('qa-story-3-progressive')

    # Add generic HTTP port
    profile['ports']['80'] = {
        'state': 'open',
        'service': 'http',
        'version': None,
        'source': 'qa-profile-generator',
        'updated_at': datetime.now().isoformat(),
        'protocol': 'tcp'
    }

    return profile


def story_4_profile_load():
    """Story 4: Profile load from disk (event handler fix)

    Starting State:
    - Ports: 80, 443 (both http/https)
    - Findings: Directory finding
    - Some tasks completed
    - Tests event handler registration on load
    """
    profile = generate_base_profile('qa-story-4-profile-load')

    # Add HTTP and HTTPS ports
    profile['ports']['80'] = {
        'state': 'open',
        'service': 'http',
        'version': None,
        'source': 'qa-profile-generator',
        'updated_at': datetime.now().isoformat(),
        'protocol': 'tcp'
    }

    profile['ports']['443'] = {
        'state': 'open',
        'service': 'https',
        'version': None,
        'source': 'qa-profile-generator',
        'updated_at': datetime.now().isoformat(),
        'protocol': 'tcp'
    }

    # Add finding
    profile['findings'].append({
        'timestamp': datetime.now().isoformat(),
        'type': 'directory',
        'description': '/admin',
        'source': 'gobuster'
    })

    return profile


def story_5_webshell():
    """Story 5: Webshell finding (highest priority)

    Starting State:
    - Port 80: service='http'
    - Test Steps:
      1. Load profile → See HTTP tasks
      2. Add webshell finding → PHP-Bypass high-priority tasks
    """
    profile = generate_base_profile('qa-story-5-webshell')

    # Add HTTP port
    profile['ports']['80'] = {
        'state': 'open',
        'service': 'http',
        'version': None,
        'source': 'qa-profile-generator',
        'updated_at': datetime.now().isoformat(),
        'protocol': 'tcp'
    }

    return profile


def story_6_nmap_import():
    """Story 6: Nmap import (full integration)

    Starting State:
    - Fresh profile (no ports)
    - Includes test-scan.xml with ports 22, 80, 443
    - Tests full Nmap import workflow
    """
    profile = generate_base_profile('qa-story-6-nmap-import')

    # Start with empty ports (will be populated by import)
    # Profile is fresh for testing import workflow

    return profile


def story_7_multistage():
    """Story 7: Multi-stage discovery (cascading plugins)

    Starting State:
    - Port 80: service='http'
    - Test Steps:
      1. Load → HTTP tasks only
      2. Add PHP finding → PHP tasks
      3. Add login form finding → Auth/SQLi tasks
      4. Add SQLi vuln finding → Exploitation tasks
    """
    profile = generate_base_profile('qa-story-7-multistage')

    # Add HTTP port
    profile['ports']['80'] = {
        'state': 'open',
        'service': 'http',
        'version': None,
        'source': 'qa-profile-generator',
        'updated_at': datetime.now().isoformat(),
        'protocol': 'tcp'
    }

    return profile


def main():
    """Generate all QA profiles"""
    # Define output directory
    output_dir = Path(__file__).parent.parent / "CRACK_targets"
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("QA Profile Generator")
    print("=" * 70)
    print()

    # Profile generators
    profiles = {
        'qa-story-1-generic-http': story_1_generic_http,
        'qa-story-2-http-with-php': story_2_http_with_php,
        'qa-story-3-progressive': story_3_progressive_discovery,
        'qa-story-4-profile-load': story_4_profile_load,
        'qa-story-5-webshell': story_5_webshell,
        'qa-story-6-nmap-import': story_6_nmap_import,
        'qa-story-7-multistage': story_7_multistage
    }

    # Generate each profile
    for target, generator in profiles.items():
        profile_data = generator()
        output_path = output_dir / f"{target}.json"

        with open(output_path, 'w') as f:
            json.dump(profile_data, f, indent=2)

        print(f"✅ Generated: {target}")
        print(f"   Path: {output_path}")
        print(f"   Ports: {len(profile_data['ports'])}")
        print(f"   Findings: {len(profile_data['findings'])}")
        print()

    print("=" * 70)
    print(f"✅ Generated {len(profiles)} QA profiles")
    print(f"   Location: {output_dir}")
    print()
    print("Load profiles with:")
    print("  crack track --tui qa-story-1-generic-http --debug")
    print("  crack track --tui qa-story-2-http-with-php --debug")
    print("  ... etc")
    print()


if __name__ == '__main__':
    main()
