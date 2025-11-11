#!/usr/bin/env python3
"""
Command Quality Validation Tool
Audits field completeness and generates enrichment priorities
"""

import json
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class FieldStats:
    total: int = 0
    populated: int = 0
    empty: int = 0

    @property
    def coverage(self) -> float:
        return (self.populated / self.total * 100) if self.total > 0 else 0.0


class CommandValidator:
    """Validates command quality and generates enrichment reports"""

    CRITICAL_FIELDS = [
        'flag_explanations',
        'variables',
        'prerequisites',
        'success_indicators',
        'failure_indicators',
        'next_steps',
        'alternatives'
    ]

    EDUCATIONAL_FIELDS = [
        'use_cases',
        'advantages',
        'disadvantages',
        'output_analysis',
        'common_uses',
        'references',
        'troubleshooting'
    ]

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.commands = []
        self.field_stats = defaultdict(FieldStats)
        self.category_stats = defaultdict(lambda: defaultdict(FieldStats))

    def load_commands(self):
        """Load all commands from JSON files"""
        for json_file in self.data_dir.rglob("*.json"):
            if 'auto-generated' in json_file.name and 'full-syntax' in json_file.name:
                with open(json_file) as f:
                    data = json.load(f)
                    category = data.get('metadata', {}).get('category', 'unknown')
                    for cmd in data.get('commands', []):
                        cmd['_file'] = json_file.name
                        cmd['_category'] = category
                        self.commands.append(cmd)

        print(f"Loaded {len(self.commands)} commands from {len(set(c['_file'] for c in self.commands))} files")

    def validate_field(self, cmd: Dict, field: str) -> bool:
        """Check if field is populated with meaningful content"""
        if field not in cmd:
            return False

        value = cmd[field]

        # Empty checks
        if value is None:
            return False
        if isinstance(value, str) and not value.strip():
            return False
        if isinstance(value, (list, dict)) and not value:
            return False

        return True

    def analyze_commands(self):
        """Analyze all commands and build statistics"""
        all_fields = self.CRITICAL_FIELDS + self.EDUCATIONAL_FIELDS

        for cmd in self.commands:
            category = cmd['_category']

            for field in all_fields:
                is_populated = self.validate_field(cmd, field)

                # Global stats
                self.field_stats[field].total += 1
                if is_populated:
                    self.field_stats[field].populated += 1
                else:
                    self.field_stats[field].empty += 1

                # Category stats
                self.category_stats[category][field].total += 1
                if is_populated:
                    self.category_stats[category][field].populated += 1
                else:
                    self.category_stats[category][field].empty += 1

    def get_worst_commands(self, limit: int = 20) -> List[Dict]:
        """Find commands with lowest field coverage"""
        scored = []
        all_fields = self.CRITICAL_FIELDS + self.EDUCATIONAL_FIELDS

        for cmd in self.commands:
            populated = sum(1 for f in all_fields if self.validate_field(cmd, f))
            score = populated / len(all_fields) * 100
            scored.append({
                'id': cmd.get('id', 'unknown'),
                'name': cmd.get('name', 'unknown'),
                'category': cmd['_category'],
                'file': cmd['_file'],
                'score': score,
                'populated': populated,
                'total': len(all_fields),
                'missing': [f for f in all_fields if not self.validate_field(cmd, f)]
            })

        scored.sort(key=lambda x: x['score'])
        return scored[:limit]

    def report_global_stats(self):
        """Print global field coverage statistics"""
        print("\n=== GLOBAL FIELD COVERAGE ===\n")

        print("Critical Fields:")
        for field in self.CRITICAL_FIELDS:
            stats = self.field_stats[field]
            bar = self._progress_bar(stats.coverage)
            print(f"  {field:25} {bar} {stats.coverage:5.1f}% ({stats.populated}/{stats.total})")

        print("\nEducational Fields:")
        for field in self.EDUCATIONAL_FIELDS:
            stats = self.field_stats[field]
            bar = self._progress_bar(stats.coverage)
            print(f"  {field:25} {bar} {stats.coverage:5.1f}% ({stats.populated}/{stats.total})")

    def report_category_stats(self):
        """Print per-category field coverage"""
        print("\n=== CATEGORY BREAKDOWN ===\n")

        for category in sorted(self.category_stats.keys()):
            stats = self.category_stats[category]
            total_cmds = stats[self.CRITICAL_FIELDS[0]].total

            # Calculate average coverage for critical fields
            avg_coverage = sum(stats[f].coverage for f in self.CRITICAL_FIELDS) / len(self.CRITICAL_FIELDS)

            print(f"\n{category.upper()} ({total_cmds} commands) - Avg Critical Coverage: {avg_coverage:.1f}%")

            for field in self.CRITICAL_FIELDS:
                fstats = stats[field]
                bar = self._progress_bar(fstats.coverage, width=20)
                print(f"  {field:25} {bar} {fstats.coverage:5.1f}%")

    def report_worst_commands(self, limit: int = 20):
        """Print commands needing most enrichment"""
        print(f"\n=== TOP {limit} COMMANDS NEEDING ENRICHMENT ===\n")

        worst = self.get_worst_commands(limit)

        for i, cmd in enumerate(worst, 1):
            print(f"\n{i}. {cmd['name']}")
            print(f"   ID: {cmd['id']}")
            print(f"   Category: {cmd['category']}")
            print(f"   Coverage: {cmd['score']:.1f}% ({cmd['populated']}/{cmd['total']} fields)")
            print(f"   Missing: {', '.join(cmd['missing'][:5])}")
            if len(cmd['missing']) > 5:
                print(f"            ... and {len(cmd['missing']) - 5} more")

    def export_enrichment_list(self, output_file: Path, limit: int = None):
        """Export prioritized enrichment list as JSON"""
        worst = self.get_worst_commands(limit or len(self.commands))

        with open(output_file, 'w') as f:
            json.dump(worst, f, indent=2)

        print(f"\nExported enrichment list to: {output_file}")

    def _progress_bar(self, percentage: float, width: int = 30) -> str:
        """Generate ASCII progress bar"""
        filled = int(width * percentage / 100)
        bar = '█' * filled + '░' * (width - filled)
        return f"[{bar}]"


def main():
    """Run validation and generate reports"""
    import argparse

    parser = argparse.ArgumentParser(description='Validate command quality')
    parser.add_argument('--data-dir', type=Path,
                       default=Path(__file__).parent.parent / 'data' / 'commands',
                       help='Directory containing command JSON files')
    parser.add_argument('--export', type=Path,
                       help='Export enrichment list to JSON file')
    parser.add_argument('--limit', type=int, default=20,
                       help='Number of worst commands to show')

    args = parser.parse_args()

    validator = CommandValidator(args.data_dir)
    validator.load_commands()
    validator.analyze_commands()

    validator.report_global_stats()
    validator.report_category_stats()
    validator.report_worst_commands(args.limit)

    if args.export:
        validator.export_enrichment_list(args.export)


if __name__ == '__main__':
    main()
