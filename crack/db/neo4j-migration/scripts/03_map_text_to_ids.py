#!/usr/bin/env python3
"""
Script 03: Map Text to IDs

Purpose: Map text-based alternatives/prerequisites to command IDs
Input:
  - db/data/commands/**/*.json (JSON files with violations)
  - db/neo4j-migration/data/command_index.json (command index)
Output: db/neo4j-migration/data/mapping_report.json

Uses fuzzy matching and heuristics to convert command text to IDs.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from difflib import SequenceMatcher
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


class TextToIDMapper:
    """Map command text to IDs using fuzzy matching"""

    def __init__(self, index_file: Path, commands_dir: Path, output_file: Path):
        self.index_file = index_file
        self.commands_dir = commands_dir
        self.output_file = output_file

        # Load index
        with open(index_file) as f:
            self.index = json.load(f)

        # Build reverse indexes for fast lookup
        self.command_to_id = {}  # normalized command → id
        self.tool_to_ids = defaultdict(list)  # tool name → [ids]

        for cmd_id, cmd_data in self.index.items():
            # Map normalized command
            if cmd_data.get('command_normalized'):
                self.command_to_id[cmd_data['command_normalized']] = cmd_id

            # Map tool name
            if cmd_data.get('primary_tool'):
                self.tool_to_ids[cmd_data['primary_tool']].append(cmd_id)

        # Mapping results
        self.mappings = {
            'successful': [],
            'failed': [],
            'stats': defaultdict(int)
        }

    def normalize_text(self, text: str) -> str:
        """Normalize command text for matching"""
        normalized = text.strip()

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

    def extract_tool_name(self, text: str) -> str:
        """Extract primary tool from command text"""
        text = text.strip()

        # Handle sudo
        if text.startswith('sudo '):
            text = text[5:].strip()

        # Extract first word
        parts = text.split()
        if parts:
            tool = parts[0]

            # Handle script interpreters
            if tool in ['python3', 'python', 'bash', 'sh', 'perl', 'ruby'] and len(parts) > 1:
                if parts[1] == '-c' and len(parts) > 2:
                    return parts[2].split()[0] if ' ' in parts[2] else tool
                return parts[1].split('.')[0] if '.' in parts[1] else tool

            return tool

        return 'unknown'

    def similarity_score(self, text1: str, text2: str) -> float:
        """Calculate similarity between two strings (0-1)"""
        return SequenceMatcher(None, text1.lower(), text2.lower()).ratio()

    def map_text_to_id(self, text: str, field: str, command_id: str) -> Tuple[Optional[str], str, float]:
        """
        Map text to command ID using multiple strategies

        Returns: (mapped_id, confidence_level, confidence_score)
        """
        self.mappings['stats']['total_attempts'] += 1

        # Strategy 1: Exact normalized match (highest confidence)
        normalized = self.normalize_text(text)
        if normalized in self.command_to_id:
            mapped_id = self.command_to_id[normalized]
            self.mappings['stats']['exact_match'] += 1
            return mapped_id, 'exact_match', 1.0

        # Strategy 2: Check if text is already an ID
        if text in self.index:
            self.mappings['stats']['already_id'] += 1
            return text, 'already_id', 1.0

        # Strategy 3: Tool name + fuzzy match
        tool = self.extract_tool_name(text)
        if tool in self.tool_to_ids:
            candidate_ids = self.tool_to_ids[tool]

            # Find best match by comparing full commands
            best_match = None
            best_score = 0.0

            for candidate_id in candidate_ids:
                candidate_cmd = self.index[candidate_id]['command']
                score = self.similarity_score(text, candidate_cmd)

                if score > best_score:
                    best_score = score
                    best_match = candidate_id

            # Accept if similarity > 70%
            if best_score >= 0.70:
                self.mappings['stats']['fuzzy_match'] += 1
                return best_match, 'fuzzy_match', best_score

        # Strategy 4: Keyword matching
        keywords = set(re.findall(r'\w+', text.lower()))

        best_match = None
        best_score = 0.0

        for cmd_id, cmd_data in self.index.items():
            cmd_keywords = set(cmd_data['keywords'])

            # Calculate keyword overlap
            if cmd_keywords and keywords:
                overlap = len(keywords & cmd_keywords)
                score = overlap / max(len(keywords), len(cmd_keywords))

                if score > best_score:
                    best_score = score
                    best_match = cmd_id

        # Accept if keyword overlap > 60%
        if best_score >= 0.60:
            self.mappings['stats']['keyword_match'] += 1
            return best_match, 'keyword_match', best_score

        # No match found
        self.mappings['stats']['no_match'] += 1
        return None, 'no_match', 0.0

    def process_commands(self):
        """Process all command files and map text to IDs"""
        print(f"\n{Colors.BOLD}Mapping Text to IDs...{Colors.RESET}\n")

        files_processed = 0
        commands_processed = 0

        for json_file in self.commands_dir.rglob('*.json'):
            try:
                with open(json_file) as f:
                    data = json.load(f)

                files_processed += 1

                for cmd in data.get('commands', []):
                    cmd_id = cmd.get('id')
                    if not cmd_id:
                        continue

                    commands_processed += 1

                    # Process alternatives
                    if cmd.get('alternatives'):
                        for alt_text in cmd['alternatives']:
                            # Check if it's text (not ID)
                            if not self._looks_like_id(alt_text):
                                mapped_id, confidence, score = self.map_text_to_id(
                                    alt_text, 'alternatives', cmd_id
                                )

                                mapping_entry = {
                                    'command_id': cmd_id,
                                    'command_name': cmd.get('name', ''),
                                    'field': 'alternatives',
                                    'old_value': alt_text,
                                    'new_value': mapped_id,
                                    'confidence': confidence,
                                    'confidence_score': round(score, 3),
                                    'file': str(json_file.relative_to(self.commands_dir.parent.parent))
                                }

                                if mapped_id:
                                    self.mappings['successful'].append(mapping_entry)
                                else:
                                    mapping_entry['suggestion'] = self._suggest_new_id(alt_text)
                                    self.mappings['failed'].append(mapping_entry)

                    # Process prerequisites
                    if cmd.get('prerequisites'):
                        for prereq_text in cmd['prerequisites']:
                            # Check if it's text (not ID)
                            if not self._looks_like_id(prereq_text):
                                mapped_id, confidence, score = self.map_text_to_id(
                                    prereq_text, 'prerequisites', cmd_id
                                )

                                mapping_entry = {
                                    'command_id': cmd_id,
                                    'command_name': cmd.get('name', ''),
                                    'field': 'prerequisites',
                                    'old_value': prereq_text,
                                    'new_value': mapped_id,
                                    'confidence': confidence,
                                    'confidence_score': round(score, 3),
                                    'file': str(json_file.relative_to(self.commands_dir.parent.parent))
                                }

                                if mapped_id:
                                    self.mappings['successful'].append(mapping_entry)
                                else:
                                    mapping_entry['suggestion'] = self._suggest_new_id(prereq_text)
                                    self.mappings['failed'].append(mapping_entry)

            except Exception as e:
                print(f"{Colors.RED}✗ Error processing {json_file.name}: {e}{Colors.RESET}")

        print(f"{Colors.GREEN}✓ Processed {files_processed} files, {commands_processed} commands{Colors.RESET}\n")

    def _looks_like_id(self, text: str) -> bool:
        """Check if text looks like a command ID"""
        # IDs are lowercase with hyphens, no spaces, no special chars
        return bool(re.match(r'^[a-z0-9-]+$', text))

    def _suggest_new_id(self, text: str) -> str:
        """Suggest a new ID based on command text"""
        # Extract tool name
        tool = self.extract_tool_name(text)

        # Extract action keywords
        action_words = []
        text_lower = text.lower()

        # Common action patterns
        if 'list' in text_lower or '-l' in text:
            action_words.append('list')
        elif 'show' in text_lower:
            action_words.append('show')
        elif 'add' in text_lower:
            action_words.append('add')
        elif 'delete' in text_lower or 'remove' in text_lower or 'rm' in text:
            action_words.append('delete')
        elif 'create' in text_lower or 'mkdir' in text:
            action_words.append('create')
        elif 'check' in text_lower or 'test' in text:
            action_words.append('check')

        # Build suggested ID
        parts = [tool] + action_words
        suggested_id = '-'.join(parts)

        return suggested_id

    def save_mappings(self):
        """Save mapping results to JSON"""
        # Create output directory
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

        # Prepare output
        output = {
            'successful_mappings': self.mappings['successful'],
            'failed_mappings': self.mappings['failed'],
            'stats': dict(self.mappings['stats'])
        }

        # Save to file
        with open(self.output_file, 'w') as f:
            json.dump(output, f, indent=2)

        print(f"{Colors.GREEN}✓ Mapping report saved to: {self.output_file}{Colors.RESET}")
        print(f"  File size: {self.output_file.stat().st_size:,} bytes\n")

    def print_stats(self):
        """Print mapping statistics"""
        stats = self.mappings['stats']
        successful_count = len(self.mappings['successful'])
        failed_count = len(self.mappings['failed'])
        total = successful_count + failed_count

        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}MAPPING STATISTICS{Colors.RESET}")
        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

        print(f"{Colors.BOLD}Overall Results:{Colors.RESET}")
        print(f"  Total mappings attempted:  {total:4d}")
        print(f"  {Colors.GREEN}Successful mappings:       {successful_count:4d} ({successful_count/total*100:.1f}%){Colors.RESET}")
        print(f"  {Colors.RED}Failed mappings:           {failed_count:4d} ({failed_count/total*100:.1f}%){Colors.RESET}")

        print(f"\n{Colors.BOLD}Confidence Breakdown:{Colors.RESET}")
        print(f"  Exact match:               {stats.get('exact_match', 0):4d}")
        print(f"  Already ID:                {stats.get('already_id', 0):4d}")
        print(f"  Fuzzy match:               {stats.get('fuzzy_match', 0):4d}")
        print(f"  Keyword match:             {stats.get('keyword_match', 0):4d}")
        print(f"  No match:                  {stats.get('no_match', 0):4d}")

        # Show sample successful mappings
        if self.mappings['successful']:
            print(f"\n{Colors.BOLD}Sample Successful Mappings (first 5):{Colors.RESET}")
            for mapping in self.mappings['successful'][:5]:
                print(f"  {Colors.DIM}{mapping['command_id']}{Colors.RESET}")
                print(f"    Text: {mapping['old_value'][:60]}")
                print(f"    → ID: {Colors.GREEN}{mapping['new_value']}{Colors.RESET}")
                print(f"    Confidence: {mapping['confidence']} ({mapping['confidence_score']})")

        # Show sample failed mappings
        if self.mappings['failed']:
            print(f"\n{Colors.BOLD}{Colors.YELLOW}Sample Failed Mappings (first 5):{Colors.RESET}")
            for mapping in self.mappings['failed'][:5]:
                print(f"  {Colors.DIM}{mapping['command_id']}{Colors.RESET}")
                print(f"    Text: {mapping['old_value'][:60]}")
                print(f"    {Colors.RED}No match found{Colors.RESET}")
                print(f"    Suggestion: {mapping['suggestion']}")

        print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")

        if successful_count / total >= 0.80:
            print(f"{Colors.GREEN}✓ High mapping success rate ({successful_count/total*100:.1f}%){Colors.RESET}")
        elif successful_count / total >= 0.60:
            print(f"{Colors.YELLOW}⚠ Moderate mapping success rate ({successful_count/total*100:.1f}%){Colors.RESET}")
        else:
            print(f"{Colors.RED}✗ Low mapping success rate ({successful_count/total*100:.1f}%){Colors.RESET}")

        print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")


def main():
    """Main execution"""
    # Paths
    project_root = Path('/home/kali/Desktop/OSCP/crack')
    index_file = project_root / 'db' / 'neo4j-migration' / 'data' / 'command_index.json'
    commands_dir = project_root / 'db' / 'data' / 'commands'
    output_file = project_root / 'db' / 'neo4j-migration' / 'data' / 'mapping_report.json'

    # Verify files exist
    if not index_file.exists():
        print(f"{Colors.RED}✗ Index file not found: {index_file}{Colors.RESET}")
        print(f"{Colors.YELLOW}  Run: python3 02_build_command_index.py{Colors.RESET}")
        return 1

    if not commands_dir.exists():
        print(f"{Colors.RED}✗ Commands directory not found: {commands_dir}{Colors.RESET}")
        return 1

    # Map text to IDs
    mapper = TextToIDMapper(index_file, commands_dir, output_file)
    mapper.process_commands()
    mapper.save_mappings()
    mapper.print_stats()

    return 0


if __name__ == '__main__':
    exit(main())
