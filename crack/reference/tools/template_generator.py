#!/usr/bin/env python3
"""
Command Template Generator
Generates smart field templates based on command analysis
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional


class TemplateGenerator:
    """Generates field templates for commands"""

    # Common patterns for generating smart defaults
    TOOL_PATTERNS = {
        'nmap': {
            'use_cases': [
                "Network reconnaissance and port discovery",
                "Service version detection",
                "Operating system fingerprinting"
            ],
            'advantages': [
                "Industry-standard reconnaissance tool",
                "Comprehensive scanning capabilities",
                "Scriptable with NSE (Nmap Scripting Engine)"
            ],
            'disadvantages': [
                "Can be noisy and easily detected by IDS/IPS",
                "Requires root privileges for SYN scans",
                "Slow on large networks without tuning"
            ]
        },
        'nc|netcat': {
            'use_cases': [
                "Creating reverse shells",
                "Port scanning",
                "File transfer",
                "Banner grabbing"
            ],
            'advantages': [
                "Lightweight and ubiquitous",
                "Simple syntax",
                "Available on most systems"
            ],
            'disadvantages': [
                "No encryption support",
                "Limited features in some variants",
                "Requires manual protocol handling"
            ]
        },
        'curl': {
            'use_cases': [
                "Testing web application endpoints",
                "Downloading files",
                "API interaction",
                "Banner grabbing"
            ],
            'advantages': [
                "Supports many protocols (HTTP, FTP, etc.)",
                "Detailed debugging output available",
                "Scriptable and automatable"
            ],
            'disadvantages': [
                "Limited rendering of JavaScript content",
                "No browser-like session handling",
                "May miss client-side protections"
            ]
        },
        'ssh': {
            'use_cases': [
                "Secure remote access",
                "Port forwarding and tunneling",
                "File transfer via SCP/SFTP",
                "Command execution on remote systems"
            ],
            'advantages': [
                "Encrypted communication",
                "Strong authentication mechanisms",
                "Built-in tunneling capabilities"
            ],
            'disadvantages': [
                "Requires valid credentials or keys",
                "Restricted by firewall rules",
                "Can be blocked by network policies"
            ]
        },
        'python': {
            'use_cases': [
                "Quick web server for file transfer",
                "Script execution and automation",
                "Exploit development",
                "Data processing"
            ],
            'advantages': [
                "Widely available on Linux systems",
                "Simple one-liner servers",
                "Rich library ecosystem"
            ],
            'disadvantages': [
                "Version differences (Python 2 vs 3)",
                "May not be installed on minimal systems",
                "No encryption by default"
            ]
        }
    }

    CATEGORY_TEMPLATES = {
        'enumeration': {
            'output_analysis': [
                "Look for service versions in output",
                "Identify potential vulnerabilities based on detected versions",
                "Note unusual or non-standard ports"
            ],
            'common_uses': [
                "Initial reconnaissance phase",
                "Service identification",
                "Attack surface mapping"
            ]
        },
        'exploitation': {
            'output_analysis': [
                "Verify exploitation success indicators",
                "Check for shell access or code execution",
                "Confirm payload delivery"
            ],
            'common_uses': [
                "Gaining initial access",
                "Exploiting identified vulnerabilities",
                "Testing exploit reliability"
            ]
        },
        'post-exploit': {
            'output_analysis': [
                "Identify privilege level",
                "Note sensitive files or credentials",
                "Map internal network topology"
            ],
            'common_uses': [
                "Privilege escalation",
                "Credential harvesting",
                "Lateral movement preparation"
            ]
        },
        'pivoting': {
            'output_analysis': [
                "Verify tunnel connectivity",
                "Confirm port accessibility",
                "Check routing table entries"
            ],
            'common_uses': [
                "Accessing internal networks",
                "Bypassing network segmentation",
                "Multi-hop exploitation"
            ]
        },
        'file-transfer': {
            'output_analysis': [
                "Confirm successful file transfer",
                "Verify file integrity (size/hash)",
                "Check file permissions on destination"
            ],
            'common_uses': [
                "Uploading exploits to target",
                "Downloading data from compromised systems",
                "Tool deployment"
            ]
        }
    }

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def analyze_command(self, cmd: Dict) -> Dict[str, any]:
        """Analyze command and extract metadata for template generation"""
        command_text = cmd.get('command', '').lower()
        category = cmd.get('category', '').lower()
        name = cmd.get('name', '').lower()
        description = cmd.get('description', '').lower()

        # Detect primary tool
        tool = self._detect_tool(command_text, name)

        # Detect flags
        flags = self._extract_flags(command_text)

        # Detect variables
        variables = self._extract_variables(cmd.get('command', ''))

        return {
            'tool': tool,
            'category': category,
            'flags': flags,
            'variables': variables,
            'has_sudo': 'sudo' in command_text,
            'has_pipe': '|' in command_text,
            'is_oneiner': '\n' not in cmd.get('command', '')
        }

    def _detect_tool(self, command_text: str, name: str) -> Optional[str]:
        """Detect primary tool being used"""
        for tool_pattern in self.TOOL_PATTERNS.keys():
            if re.search(r'\b(' + tool_pattern + r')\b', command_text):
                return tool_pattern
            if re.search(r'\b(' + tool_pattern + r')\b', name):
                return tool_pattern
        return None

    def _extract_flags(self, command_text: str) -> List[str]:
        """Extract command-line flags"""
        # Match -x or --xxx style flags
        flags = re.findall(r'\s(-[\w-]+)', command_text)
        return list(set(flags))

    def _extract_variables(self, command_text: str) -> List[str]:
        """Extract <PLACEHOLDER> variables"""
        return re.findall(r'<([A-Z_]+)>', command_text)

    def generate_template(self, cmd_id: str) -> Optional[Dict]:
        """Generate complete field template for command"""
        # Find command
        result = self._find_command(cmd_id)
        if not result:
            print(f"Error: Command '{cmd_id}' not found")
            return None

        cmd, json_file = result
        analysis = self.analyze_command(cmd)

        template = {}

        # Generate use_cases
        if not cmd.get('use_cases'):
            template['use_cases'] = self._generate_use_cases(cmd, analysis)

        # Generate advantages
        if not cmd.get('advantages'):
            template['advantages'] = self._generate_advantages(cmd, analysis)

        # Generate disadvantages
        if not cmd.get('disadvantages'):
            template['disadvantages'] = self._generate_disadvantages(cmd, analysis)

        # Generate output_analysis
        if not cmd.get('output_analysis'):
            template['output_analysis'] = self._generate_output_analysis(cmd, analysis)

        # Generate common_uses
        if not cmd.get('common_uses'):
            template['common_uses'] = self._generate_common_uses(cmd, analysis)

        # Generate troubleshooting
        if not cmd.get('troubleshooting'):
            template['troubleshooting'] = self._generate_troubleshooting(cmd, analysis)

        # Generate prerequisites
        if not cmd.get('prerequisites'):
            template['prerequisites'] = self._generate_prerequisites(cmd, analysis)

        # Generate success/failure indicators
        if not cmd.get('success_indicators'):
            template['success_indicators'] = self._generate_success_indicators(cmd, analysis)

        if not cmd.get('failure_indicators'):
            template['failure_indicators'] = self._generate_failure_indicators(cmd, analysis)

        # Generate next_steps
        if not cmd.get('next_steps'):
            template['next_steps'] = self._generate_next_steps(cmd, analysis)

        return template

    def _generate_use_cases(self, cmd: Dict, analysis: Dict) -> List[str]:
        """Generate use cases based on tool and category"""
        use_cases = []

        # Tool-specific use cases
        if analysis['tool'] and analysis['tool'] in self.TOOL_PATTERNS:
            use_cases.extend(self.TOOL_PATTERNS[analysis['tool']].get('use_cases', []))

        # Category-specific use cases
        if analysis['category'] in self.CATEGORY_TEMPLATES:
            use_cases.extend(self.CATEGORY_TEMPLATES[analysis['category']].get('common_uses', []))

        # Generic fallbacks
        if not use_cases:
            category = analysis['category']
            use_cases = [
                f"During {category} phase of penetration testing",
                f"When manual {category} is required",
                "In OSCP lab exercises"
            ]

        return use_cases[:4]  # Limit to 4

    def _generate_advantages(self, cmd: Dict, analysis: Dict) -> List[str]:
        """Generate advantages"""
        if analysis['tool'] and analysis['tool'] in self.TOOL_PATTERNS:
            return self.TOOL_PATTERNS[analysis['tool']].get('advantages', [])

        return [
            "Lightweight and fast",
            "Available in OSCP lab environment",
            "Simple syntax"
        ]

    def _generate_disadvantages(self, cmd: Dict, analysis: Dict) -> List[str]:
        """Generate disadvantages"""
        if analysis['tool'] and analysis['tool'] in self.TOOL_PATTERNS:
            return self.TOOL_PATTERNS[analysis['tool']].get('disadvantages', [])

        disadvantages = []

        if analysis['has_sudo']:
            disadvantages.append("Requires elevated privileges (sudo/root)")

        if not analysis['is_oneiner']:
            disadvantages.append("Multi-step command prone to syntax errors")

        if not disadvantages:
            disadvantages = [
                "May require specific system configuration",
                "Results depend on target environment"
            ]

        return disadvantages

    def _generate_output_analysis(self, cmd: Dict, analysis: Dict) -> List[str]:
        """Generate output analysis guidelines"""
        if analysis['category'] in self.CATEGORY_TEMPLATES:
            return self.CATEGORY_TEMPLATES[analysis['category']].get('output_analysis', [])

        return [
            "Review output for expected patterns",
            "Note any error messages for troubleshooting",
            "Verify command executed successfully"
        ]

    def _generate_common_uses(self, cmd: Dict, analysis: Dict) -> List[str]:
        """Generate common use scenarios"""
        if analysis['category'] in self.CATEGORY_TEMPLATES:
            return self.CATEGORY_TEMPLATES[analysis['category']].get('common_uses', [])

        return [
            "During penetration testing engagements",
            "In OSCP exam scenarios",
            "For security assessments"
        ]

    def _generate_troubleshooting(self, cmd: Dict, analysis: Dict) -> Dict[str, str]:
        """Generate troubleshooting guide"""
        troubleshooting = {}

        if analysis['has_sudo']:
            troubleshooting["Permission denied"] = "Run command with sudo or as root user"

        if 'TARGET' in analysis['variables']:
            troubleshooting["Connection timeout"] = "Verify target IP is reachable and correct"
            troubleshooting["Connection refused"] = "Check if target service is running on specified port"

        if not troubleshooting:
            troubleshooting = {
                "Command not found": "Verify tool is installed on system",
                "Unexpected output": "Check command syntax and variable values"
            }

        return troubleshooting

    def _generate_prerequisites(self, cmd: Dict, analysis: Dict) -> List[str]:
        """Generate prerequisites"""
        prereqs = []

        if analysis['has_sudo']:
            prereqs.append("Root or sudo privileges required")

        if 'PORT' in analysis['variables']:
            prereqs.append("Target port must be accessible")

        if 'WORDLIST' in analysis['variables']:
            prereqs.append("Wordlist file must exist (e.g., /usr/share/wordlists/...)")

        return prereqs if prereqs else []

    def _generate_success_indicators(self, cmd: Dict, analysis: Dict) -> List[str]:
        """Generate success indicators"""
        category = analysis['category']

        if category == 'enumeration':
            return ["Output shows discovered services/ports", "No errors in output"]
        elif category == 'exploitation':
            return ["Shell access obtained", "Payload executed successfully"]
        elif category == 'file-transfer':
            return ["File transferred successfully", "No transfer errors"]
        elif category == 'pivoting':
            return ["Tunnel established", "Connection successful"]

        return ["Command exits with status 0", "Expected output received"]

    def _generate_failure_indicators(self, cmd: Dict, analysis: Dict) -> List[str]:
        """Generate failure indicators"""
        return [
            "Connection refused or timeout",
            "Permission denied errors",
            "Command not found",
            "Syntax error in output"
        ]

    def _generate_next_steps(self, cmd: Dict, analysis: Dict) -> List[str]:
        """Generate next steps"""
        category = analysis['category']

        if category == 'enumeration':
            return ["Analyze discovered services for vulnerabilities", "Research identified versions for exploits"]
        elif category == 'exploitation':
            return ["Stabilize shell", "Begin privilege escalation"]
        elif category == 'pivoting':
            return ["Enumerate internal network", "Identify additional targets"]

        return ["Review output", "Proceed to next phase"]

    def _find_command(self, cmd_id: str) -> Optional[tuple]:
        """Find command by ID"""
        for json_file in self.data_dir.rglob("*.json"):
            if 'auto-generated' not in json_file.name:
                continue

            with open(json_file) as f:
                data = json.load(f)
                for cmd in data.get('commands', []):
                    if cmd.get('id') == cmd_id:
                        return cmd, json_file

        return None

    def apply_template(self, cmd_id: str, dry_run: bool = False) -> bool:
        """Generate and apply template to command"""
        template = self.generate_template(cmd_id)
        if not template:
            return False

        print(f"\nGenerated template for: {cmd_id}\n")
        print(json.dumps(template, indent=2))

        if dry_run:
            print("\n(Dry run - no changes made)")
            return True

        # Apply template
        result = self._find_command(cmd_id)
        if not result:
            return False

        cmd, json_file = result

        # Update command with template fields
        for field, value in template.items():
            if not cmd.get(field):  # Only add if field is empty
                cmd[field] = value

        # Save changes
        with open(json_file) as f:
            data = json.load(f)

        # Update command in data
        for i, c in enumerate(data['commands']):
            if c.get('id') == cmd_id:
                data['commands'][i] = cmd
                break

        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\n✓ Applied template to {json_file.name}")
        return True


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Generate command field templates')
    parser.add_argument('command_id', help='Command ID to generate template for')
    parser.add_argument('--data-dir', type=Path,
                       default=Path(__file__).parent.parent / 'data' / 'commands',
                       help='Directory containing command JSON files')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show template without applying changes')
    parser.add_argument('--apply', action='store_true',
                       help='Apply template to command JSON')

    args = parser.parse_args()

    generator = TemplateGenerator(args.data_dir)

    if args.apply:
        generator.apply_template(args.command_id, dry_run=args.dry_run)
    else:
        template = generator.generate_template(args.command_id)
        if template:
            print(json.dumps(template, indent=2))


if __name__ == '__main__':
    main()
