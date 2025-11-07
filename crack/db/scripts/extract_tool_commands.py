#!/usr/bin/env python3
"""
Extract tool commands from the 963 'unresolved' relations.

This script parses all relation fields (alternatives, prerequisites, next_steps)
and identifies executable tool commands that should be converted to proper
command definitions.

Strategy:
1. Parse all JSON files for relations
2. Classify each relation as:
   - Command ID (already in database)
   - Tool command (extractable: curl, fping, searchsploit, etc.)
   - Descriptive guidance (keep as text: "Check for...", "Verify...", etc.)
3. Extract tool commands and generate template definitions
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict


# Tool patterns to identify extractable commands
TOOL_PATTERNS = {
    'curl': r'^curl\s+',
    'searchsploit': r'^searchsploit\s+',
    'fping': r'^fping\s+',
    'arp-scan': r'^arp-scan\s+',
    'masscan': r'^masscan\s+',
    'john': r'^john\s+',
    'hashcat': r'^hashcat\s+',
    'hydra': r'^hydra\s+',
    'msfconsole': r'^msfconsole\s+',
    'msfvenom': r'^msfvenom\s+',
    'chisel': r'^chisel\s+',
    'socat': r'^socat\s+',
    'evil-winrm': r'^evil-winrm\s+',
    'crackmapexec': r'^crackmapexec\s+',
    'impacket-': r'^impacket-\w+\s+',
    'bloodhound': r'^bloodhound',
    'rpcclient': r'^rpcclient\s+',
    'smbmap': r'^smbmap\s+',
    'ldapsearch': r'^ldapsearch\s+',
    'kerbrute': r'^kerbrute\s+',
    'enum4linux-ng': r'^enum4linux-ng\s+',
    'sqlmap': r'^sqlmap\s+',
    'wfuzz': r'^wfuzz\s+',
    'ffuf': r'^ffuf\s+',
    'burpsuite': r'burp\s+suite',
    'metasploit': r'metasploit|msfconsole',
    'nc': r'^nc\s+-',
    'netcat': r'^netcat\s+',
    'ssh': r'^ssh\s+-',
    'scp': r'^scp\s+',
    'wget': r'^wget\s+',
    'tar': r'^tar\s+',
    'zip': r'^(zip|unzip)\s+',
    'gzip': r'^g(zip|unzip)\s+',
    'base64': r'^base64\s+',
    'certutil': r'^certutil\s+',
    'powershell': r'^powershell\s+',
    'python': r'^python[23]?\s+-',
    'php': r'^php\s+-',
    'perl': r'^perl\s+-',
    'ruby': r'^ruby\s+-',
}

# Guidance patterns (NOT tool commands - keep as text)
GUIDANCE_PATTERNS = [
    r'^Check\s+',
    r'^Verify\s+',
    r'^Test\s+',
    r'^Try\s+',
    r'^Ensure\s+',
    r'^If\s+',
    r'^Manual\s+',
    r'^Research\s+',
    r'^Look\s+for\s+',
    r'^Review\s+',
    r'^Examine\s+',
    r'^Inspect\s+',
    r'^Monitor\s+',
    r'^Document\s+',
    r'^Analyze\s+',
]


class RelationExtractor:
    """Extract and classify relations from JSON command files."""

    def __init__(self):
        self.command_ids: Set[str] = set()
        self.tool_commands: Dict[str, List[Tuple[str, str, str]]] = defaultdict(list)
        self.guidance_text: List[Tuple[str, str, str]] = []
        self.stats = {
            'total_relations': 0,
            'command_id_refs': 0,
            'tool_commands': 0,
            'guidance_text': 0,
        }

    def load_json_files(self, json_dir: Path) -> None:
        """Load all JSON files and extract command IDs + relations."""
        print(f"Loading JSON files from: {json_dir}\n")

        for json_file in json_dir.rglob("*.json"):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                # Handle both formats
                commands = data.get('commands', [data] if 'id' in data else [])

                for cmd in commands:
                    cmd_id = cmd.get('id')
                    if cmd_id:
                        self.command_ids.add(cmd_id)

                    # Extract relations
                    for rel_type in ['alternatives', 'prerequisites', 'next_steps']:
                        relations = cmd.get(rel_type, [])
                        for relation in relations:
                            self._classify_relation(cmd_id, relation, rel_type)

            except Exception as e:
                print(f"  ✗ Error reading {json_file.name}: {e}")

    def _classify_relation(self, source_id: str, relation: str, rel_type: str) -> None:
        """Classify a relation as: command ID, tool command, or guidance text."""
        self.stats['total_relations'] += 1

        # Check if it's a command ID reference
        if relation in self.command_ids or '-' in relation and not relation.startswith('-'):
            # Looks like a command ID (contains hyphens, structured)
            # Check if it's likely a command ID vs a command string
            if not any(relation.startswith(tool) for tool in ['curl', 'nmap', 'gobuster']):
                if relation in self.command_ids:
                    self.stats['command_id_refs'] += 1
                    return

        # Check if it's a tool command
        for tool, pattern in TOOL_PATTERNS.items():
            if re.search(pattern, relation, re.IGNORECASE):
                self.tool_commands[tool].append((source_id, rel_type, relation))
                self.stats['tool_commands'] += 1
                return

        # Check if it's guidance text
        for pattern in GUIDANCE_PATTERNS:
            if re.match(pattern, relation, re.IGNORECASE):
                self.guidance_text.append((source_id, rel_type, relation))
                self.stats['guidance_text'] += 1
                return

        # Default: if it contains a command-like structure, it might be a tool
        # Otherwise, treat as guidance
        if self._looks_like_command(relation):
            # Unrecognized tool command
            self.tool_commands['unknown'].append((source_id, rel_type, relation))
            self.stats['tool_commands'] += 1
        else:
            self.guidance_text.append((source_id, rel_type, relation))
            self.stats['guidance_text'] += 1

    def _looks_like_command(self, text: str) -> bool:
        """Heuristic: does this look like a command vs guidance?"""
        # Contains command-like flags
        if re.search(r'\s+-[a-zA-Z]', text):
            return True
        # Contains redirects or pipes
        if re.search(r'[|><&]', text):
            return True
        # Contains file paths
        if re.search(r'(/[\w/.-]+|[A-Z]:\\)', text):
            return True
        # Starts with common command verbs (but not guidance verbs)
        command_verbs = ['run', 'execute', 'use', 'start', 'launch']
        if any(text.lower().startswith(verb) for verb in command_verbs):
            return True
        return False

    def print_report(self) -> None:
        """Print extraction report."""
        print("=" * 80)
        print("RELATION EXTRACTION REPORT")
        print("=" * 80)
        print(f"\nTotal Relations Analyzed: {self.stats['total_relations']}")
        print(f"  - Command ID References:  {self.stats['command_id_refs']} (already in database)")
        print(f"  - Tool Commands:          {self.stats['tool_commands']} (extractable)")
        print(f"  - Guidance Text:          {self.stats['guidance_text']} (keep as text)")

        print("\n" + "=" * 80)
        print("EXTRACTABLE TOOL COMMANDS BY TOOL")
        print("=" * 80)

        for tool in sorted(self.tool_commands.keys(), key=lambda t: len(self.tool_commands[t]), reverse=True):
            count = len(self.tool_commands[tool])
            print(f"\n{tool.upper()}: {count} commands")
            # Show first 3 examples
            for source, rel_type, cmd in self.tool_commands[tool][:3]:
                preview = cmd[:70] + '...' if len(cmd) > 70 else cmd
                print(f"  - [{rel_type}] {preview}")

        print("\n" + "=" * 80)
        print("GUIDANCE TEXT EXAMPLES (NOT EXTRACTABLE)")
        print("=" * 80)
        # Show first 10 guidance examples
        for source, rel_type, text in self.guidance_text[:10]:
            preview = text[:70] + '...' if len(text) > 70 else text
            print(f"  - [{rel_type}] {preview}")

        print("\n" + "=" * 80)
        print("EXTRACTION CANDIDATES")
        print("=" * 80)
        print(f"\nTotal Commands to Extract: {self.stats['tool_commands']}")
        print("\nRecommended Approach:")
        print("1. Create command definitions for recognized tools (~40-50 commands)")
        print("2. Review 'unknown' category for additional tools")
        print("3. Keep guidance text as descriptive relations in new database table")

    def export_candidates(self, output_file: Path) -> None:
        """Export tool command candidates to JSON for review."""
        candidates = []

        for tool, commands in self.tool_commands.items():
            for source_id, rel_type, cmd_text in commands:
                candidates.append({
                    'tool': tool,
                    'source_command': source_id,
                    'relation_type': rel_type,
                    'command_text': cmd_text,
                })

        with open(output_file, 'w') as f:
            json.dump({
                'total_candidates': len(candidates),
                'by_tool': {tool: len(cmds) for tool, cmds in self.tool_commands.items()},
                'candidates': candidates
            }, f, indent=2)

        print(f"\n✓ Exported {len(candidates)} candidates to: {output_file}")


def main():
    """Run extraction analysis."""
    extractor = RelationExtractor()

    # Load JSON files
    json_dir = Path(__file__).parent.parent.parent / "reference" / "data" / "commands"
    extractor.load_json_files(json_dir)

    # Print report
    extractor.print_report()

    # Export candidates
    output_file = Path(__file__).parent / "tool_command_candidates.json"
    extractor.export_candidates(output_file)


if __name__ == "__main__":
    main()
