#!/usr/bin/env python3
"""
Script 02: Build Command Index

Purpose: Create searchable index of all command IDs from JSON files
Input: reference/data/commands/**/*.json
Output: db/neo4j-migration/data/command_index.json

This index enables text-to-ID mapping for schema violation fixes.
"""

import json
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict
import re

# ANSI colors
class Colors:
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    BLUE = '\033[36m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


class CommandIndexBuilder:
    """Build searchable index from JSON command files"""

    def __init__(self, commands_dir: Path, output_file: Path):
        self.commands_dir = commands_dir
        self.output_file = output_file
        self.index = {}
        self.stats = {
            'files_scanned': 0,
            'commands_indexed': 0,
            'duplicates_found': 0,
            'parse_errors': 0
        }
        self.duplicates = defaultdict(list)

    def extract_primary_tool(self, command: str) -> str:
        """Extract primary tool name from command string"""
        # Handle sudo prefix
        cmd = command.strip()
        if cmd.startswith('sudo '):
            cmd = cmd[5:].strip()

        # Extract first word (tool name)
        parts = cmd.split()
        if parts:
            # Remove common prefixes like python3, python, bash, sh
            tool = parts[0]
            if tool in ['python3', 'python', 'bash', 'sh', 'perl', 'ruby'] and len(parts) > 1:
                # Next part might be script name or -c flag
                if parts[1] == '-c' and len(parts) > 2:
                    return parts[2].split()[0] if ' ' in parts[2] else tool
                return parts[1].split('.')[0] if '.' in parts[1] else tool
            return tool
        return 'unknown'

    def extract_keywords(self, cmd_data: Dict) -> List[str]:
        """Extract searchable keywords from command data"""
        keywords = set()

        # Add ID parts
        if cmd_data.get('id'):
            keywords.update(cmd_data['id'].split('-'))

        # Add name words
        if cmd_data.get('name'):
            keywords.update(cmd_data['name'].lower().split())

        # Add description words (first 50 chars to avoid bloat)
        if cmd_data.get('description'):
            desc_words = cmd_data['description'][:50].lower().split()
            keywords.update(desc_words)

        # Add category
        if cmd_data.get('category'):
            keywords.add(cmd_data['category'])

        # Add tags
        if cmd_data.get('tags'):
            keywords.update(tag.lower() for tag in cmd_data['tags'])

        # Add primary tool
        if cmd_data.get('command'):
            tool = self.extract_primary_tool(cmd_data['command'])
            keywords.add(tool)

        # Clean up keywords
        cleaned = {
            kw.strip('.,!?;:()[]{}')
            for kw in keywords
            if len(kw) > 2  # Skip short words
        }

        return sorted(cleaned)

    def normalize_command_template(self, command: str) -> str:
        """Normalize command by replacing variables with placeholders"""
        # Replace common variable patterns with generic placeholders
        normalized = command

        # Replace <VAR_NAME> patterns
        normalized = re.sub(r'<[A-Z_]+>', '<VAR>', normalized)

        # Replace $VAR patterns
        normalized = re.sub(r'\$[A-Z_]+', '<VAR>', normalized)

        # Replace common paths
        normalized = re.sub(r'/tmp/[^\s]+', '/tmp/<FILE>', normalized)
        normalized = re.sub(r'/home/[^\s]+', '/home/<PATH>', normalized)

        # Normalize whitespace
        normalized = ' '.join(normalized.split())

        return normalized

    def build_index(self) -> Dict:
        """Build complete command index"""
        print(f"\n{Colors.BOLD}Building Command Index...{Colors.RESET}\n")

        # Scan all JSON files
        for json_file in self.commands_dir.rglob('*.json'):
            self.stats['files_scanned'] += 1

            try:
                with open(json_file) as f:
                    data = json.load(f)

                # Process each command in file
                for cmd in data.get('commands', []):
                    cmd_id = cmd.get('id')

                    if not cmd_id:
                        print(f"{Colors.YELLOW}⚠ Command missing ID in {json_file.name}{Colors.RESET}")
                        continue

                    # Check for duplicates
                    if cmd_id in self.index:
                        self.stats['duplicates_found'] += 1
                        self.duplicates[cmd_id].append(str(json_file))
                        print(f"{Colors.RED}✗ Duplicate ID: {cmd_id}{Colors.RESET}")
                        print(f"  First: {self.index[cmd_id]['file']}")
                        print(f"  Also:  {json_file}")
                        continue

                    # Build index entry
                    command_str = cmd.get('command', '')

                    self.index[cmd_id] = {
                        'id': cmd_id,
                        'name': cmd.get('name', ''),
                        'command': command_str,
                        'command_normalized': self.normalize_command_template(command_str),
                        'primary_tool': self.extract_primary_tool(command_str),
                        'category': cmd.get('category', ''),
                        'tags': cmd.get('tags', []),
                        'keywords': self.extract_keywords(cmd),
                        'oscp_relevance': cmd.get('oscp_relevance', 'unknown'),
                        'file': str(json_file.relative_to(self.commands_dir.parent.parent))
                    }

                    self.stats['commands_indexed'] += 1

            except json.JSONDecodeError as e:
                self.stats['parse_errors'] += 1
                print(f"{Colors.RED}✗ JSON parse error in {json_file.name}: {e}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}✗ Error processing {json_file.name}: {e}{Colors.RESET}")

        return self.index

    def save_index(self):
        """Save index to JSON file"""
        # Create output directory if needed
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        # Save main index
        with open(self.output_file, 'w') as f:
            json.dump(self.index, f, indent=2, sort_keys=True)

        print(f"\n{Colors.GREEN}✓ Index saved to: {self.output_file}{Colors.RESET}")
        print(f"  File size: {self.output_file.stat().st_size:,} bytes")

        # Save duplicate report if needed
        if self.duplicates:
            dup_file = self.output_file.parent / 'duplicate_ids_report.json'
            with open(dup_file, 'w') as f:
                json.dump(dict(self.duplicates), f, indent=2)
            print(f"{Colors.YELLOW}⚠ Duplicate IDs report: {dup_file}{Colors.RESET}")

    def print_stats(self):
        """Print indexing statistics"""
        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}COMMAND INDEX STATISTICS{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

        print(f"{Colors.BOLD}Files and Commands:{Colors.RESET}")
        print(f"  Files scanned:      {self.stats['files_scanned']:4d}")
        print(f"  Commands indexed:   {Colors.GREEN}{self.stats['commands_indexed']:4d}{Colors.RESET}")

        if self.stats['duplicates_found'] > 0:
            print(f"  {Colors.RED}Duplicate IDs:      {self.stats['duplicates_found']:4d}{Colors.RESET}")

        if self.stats['parse_errors'] > 0:
            print(f"  {Colors.RED}Parse errors:       {self.stats['parse_errors']:4d}{Colors.RESET}")

        # Tool distribution
        print(f"\n{Colors.BOLD}Top 10 Primary Tools:{Colors.RESET}")
        tool_counts = defaultdict(int)
        for cmd_data in self.index.values():
            tool_counts[cmd_data['primary_tool']] += 1

        for tool, count in sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            pct = count / self.stats['commands_indexed'] * 100
            print(f"  {tool:20s} {count:4d} ({pct:5.1f}%)")

        # Category distribution
        print(f"\n{Colors.BOLD}Top 10 Categories:{Colors.RESET}")
        cat_counts = defaultdict(int)
        for cmd_data in self.index.values():
            cat_counts[cmd_data['category']] += 1

        for category, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            pct = count / self.stats['commands_indexed'] * 100
            print(f"  {category:25s} {count:4d} ({pct:5.1f}%)")

        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")

        if self.stats['duplicates_found'] == 0 and self.stats['parse_errors'] == 0:
            print(f"{Colors.GREEN}✓ Index built successfully - ready for mapping{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}⚠ Index built with issues - review warnings above{Colors.RESET}")

        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")


def main():
    """Main execution"""
    # Paths
    project_root = Path('/home/kali/Desktop/OSCP/crack')
    commands_dir = project_root / 'reference' / 'data' / 'commands'
    output_file = project_root / 'db' / 'neo4j-migration' / 'data' / 'command_index.json'

    # Verify commands directory exists
    if not commands_dir.exists():
        print(f"{Colors.RED}✗ Commands directory not found: {commands_dir}{Colors.RESET}")
        return 1

    # Build index
    builder = CommandIndexBuilder(commands_dir, output_file)
    builder.build_index()
    builder.save_index()
    builder.print_stats()

    return 0


if __name__ == '__main__':
    exit(main())
