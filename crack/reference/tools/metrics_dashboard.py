#!/usr/bin/env python3
"""
Command Quality Metrics Dashboard
Visual progress tracking for command enrichment
"""

import json
from pathlib import Path
from typing import Dict, List
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime


@dataclass
class QualityScore:
    """Overall quality scoring for a command"""
    critical_score: float  # 0-100
    educational_score: float  # 0-100
    overall_score: float  # 0-100
    grade: str  # A, B, C, D, F


class MetricsDashboard:
    """Command quality metrics and progress tracking"""

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

    CRITICAL_WEIGHT = 0.7  # 70% of overall score
    EDUCATIONAL_WEIGHT = 0.3  # 30% of overall score

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.commands = []
        self.scores = {}
        self.category_scores = defaultdict(list)

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

    def validate_field(self, cmd: Dict, field: str) -> bool:
        """Check if field is populated with meaningful content"""
        if field not in cmd:
            return False
        value = cmd[field]
        if value is None:
            return False
        if isinstance(value, str) and not value.strip():
            return False
        if isinstance(value, (list, dict)) and not value:
            return False
        return True

    def calculate_score(self, cmd: Dict) -> QualityScore:
        """Calculate quality score for command"""
        # Critical fields score
        critical_filled = sum(1 for f in self.CRITICAL_FIELDS if self.validate_field(cmd, f))
        critical_score = (critical_filled / len(self.CRITICAL_FIELDS)) * 100

        # Educational fields score
        educational_filled = sum(1 for f in self.EDUCATIONAL_FIELDS if self.validate_field(cmd, f))
        educational_score = (educational_filled / len(self.EDUCATIONAL_FIELDS)) * 100

        # Overall weighted score
        overall_score = (critical_score * self.CRITICAL_WEIGHT) + (educational_score * self.EDUCATIONAL_WEIGHT)

        # Letter grade
        if overall_score >= 90:
            grade = 'A'
        elif overall_score >= 80:
            grade = 'B'
        elif overall_score >= 70:
            grade = 'C'
        elif overall_score >= 60:
            grade = 'D'
        else:
            grade = 'F'

        return QualityScore(
            critical_score=critical_score,
            educational_score=educational_score,
            overall_score=overall_score,
            grade=grade
        )

    def analyze_commands(self):
        """Analyze all commands and calculate scores"""
        for cmd in self.commands:
            cmd_id = cmd.get('id', 'unknown')
            score = self.calculate_score(cmd)
            self.scores[cmd_id] = score
            self.category_scores[cmd['_category']].append(score)

    def show_dashboard(self):
        """Display comprehensive metrics dashboard"""
        print("\n" + "="*70)
        print("CRACK COMMAND QUALITY DASHBOARD".center(70))
        print("="*70)

        self._show_overview()
        self._show_category_breakdown()
        self._show_grade_distribution()
        self._show_field_coverage()
        self._show_recommendations()

    def _show_overview(self):
        """Display overall metrics"""
        print("\n📊 OVERALL METRICS\n")

        total = len(self.commands)
        avg_overall = sum(s.overall_score for s in self.scores.values()) / total if total > 0 else 0
        avg_critical = sum(s.critical_score for s in self.scores.values()) / total if total > 0 else 0
        avg_educational = sum(s.educational_score for s in self.scores.values()) / total if total > 0 else 0

        # Grade counts
        grade_counts = defaultdict(int)
        for score in self.scores.values():
            grade_counts[score.grade] += 1

        print(f"  Total Commands:        {total}")
        print(f"  Average Overall Score: {avg_overall:.1f}%  {self._score_emoji(avg_overall)}")
        print(f"  Average Critical:      {avg_critical:.1f}%  {self._progress_bar(avg_critical, 40)}")
        print(f"  Average Educational:   {avg_educational:.1f}%  {self._progress_bar(avg_educational, 40)}")
        print(f"\n  Grade Distribution:")
        for grade in ['A', 'B', 'C', 'D', 'F']:
            count = grade_counts[grade]
            pct = (count / total * 100) if total > 0 else 0
            bar = self._grade_bar(grade, count, total)
            print(f"    {grade}: {bar} {count:3} ({pct:4.1f}%)")

    def _show_category_breakdown(self):
        """Display per-category metrics"""
        print("\n📁 CATEGORY BREAKDOWN\n")

        for category in sorted(self.category_scores.keys()):
            scores = self.category_scores[category]
            if not scores:
                continue

            count = len(scores)
            avg_overall = sum(s.overall_score for s in scores) / count
            avg_critical = sum(s.critical_score for s in scores) / count
            avg_educational = sum(s.educational_score for s in scores) / count

            print(f"  {category.upper()} ({count} commands)")
            print(f"    Overall:     {avg_overall:5.1f}% {self._progress_bar(avg_overall, 30)}")
            print(f"    Critical:    {avg_critical:5.1f}% {self._progress_bar(avg_critical, 30)}")
            print(f"    Educational: {avg_educational:5.1f}% {self._progress_bar(avg_educational, 30)}")
            print()

    def _show_grade_distribution(self):
        """Display grade distribution graph"""
        print("📈 QUALITY DISTRIBUTION\n")

        # Count commands by score ranges
        ranges = {
            '90-100 (A)': 0,
            '80-89 (B)': 0,
            '70-79 (C)': 0,
            '60-69 (D)': 0,
            '0-59 (F)': 0
        }

        for score in self.scores.values():
            s = score.overall_score
            if s >= 90:
                ranges['90-100 (A)'] += 1
            elif s >= 80:
                ranges['80-89 (B)'] += 1
            elif s >= 70:
                ranges['70-79 (C)'] += 1
            elif s >= 60:
                ranges['60-69 (D)'] += 1
            else:
                ranges['0-59 (F)'] += 1

        max_count = max(ranges.values()) if ranges.values() else 1

        for range_label, count in ranges.items():
            bar_length = int((count / max_count * 40)) if max_count > 0 else 0
            bar = '█' * bar_length
            print(f"  {range_label:15} {bar:40} {count:3}")

    def _show_field_coverage(self):
        """Display field-by-field coverage"""
        print("\n📋 FIELD COVERAGE\n")

        print("  Critical Fields:")
        for field in self.CRITICAL_FIELDS:
            filled = sum(1 for cmd in self.commands if self.validate_field(cmd, field))
            pct = (filled / len(self.commands) * 100) if self.commands else 0
            bar = self._progress_bar(pct, 35)
            status = self._field_status(pct)
            print(f"    {field:25} {bar} {pct:5.1f}% {status}")

        print("\n  Educational Fields:")
        for field in self.EDUCATIONAL_FIELDS:
            filled = sum(1 for cmd in self.commands if self.validate_field(cmd, field))
            pct = (filled / len(self.commands) * 100) if self.commands else 0
            bar = self._progress_bar(pct, 35)
            status = self._field_status(pct)
            print(f"    {field:25} {bar} {pct:5.1f}% {status}")

    def _show_recommendations(self):
        """Display actionable recommendations"""
        print("\n💡 RECOMMENDATIONS\n")

        # Find worst-scoring commands
        worst = sorted(self.scores.items(), key=lambda x: x[1].overall_score)[:5]

        print("  Top Priority Commands (lowest scores):")
        for i, (cmd_id, score) in enumerate(worst, 1):
            cmd = next((c for c in self.commands if c.get('id') == cmd_id), None)
            if cmd:
                print(f"    {i}. {cmd.get('name', 'Unknown'):40} Score: {score.overall_score:5.1f}% (Grade {score.grade})")

        # Identify weakest fields
        field_coverage = {}
        for field in self.CRITICAL_FIELDS + self.EDUCATIONAL_FIELDS:
            filled = sum(1 for cmd in self.commands if self.validate_field(cmd, field))
            pct = (filled / len(self.commands) * 100) if self.commands else 0
            field_coverage[field] = pct

        weakest_fields = sorted(field_coverage.items(), key=lambda x: x[1])[:3]

        print("\n  Weakest Fields (focus enrichment here):")
        for i, (field, pct) in enumerate(weakest_fields, 1):
            missing = len(self.commands) - int((pct / 100) * len(self.commands))
            print(f"    {i}. {field:25} {pct:5.1f}% coverage ({missing} commands missing)")

        # Category recommendations
        category_avgs = {cat: sum(s.overall_score for s in scores) / len(scores)
                        for cat, scores in self.category_scores.items() if scores}
        weakest_categories = sorted(category_avgs.items(), key=lambda x: x[1])[:2]

        print("\n  Weakest Categories:")
        for i, (cat, avg) in enumerate(weakest_categories, 1):
            count = len(self.category_scores[cat])
            print(f"    {i}. {cat:25} {avg:5.1f}% average ({count} commands)")

    def _progress_bar(self, percentage: float, width: int = 30) -> str:
        """Generate ASCII progress bar with color"""
        filled = int(width * percentage / 100)
        bar = '█' * filled + '░' * (width - filled)
        return f"[{bar}]"

    def _grade_bar(self, grade: str, count: int, total: int) -> str:
        """Generate grade distribution bar"""
        width = 40
        filled = int((count / total * width)) if total > 0 else 0
        bar = '█' * filled + '░' * (width - filled)
        return f"[{bar}]"

    def _score_emoji(self, score: float) -> str:
        """Return emoji based on score"""
        if score >= 90:
            return "🌟"
        elif score >= 80:
            return "✅"
        elif score >= 70:
            return "👍"
        elif score >= 60:
            return "⚠️"
        else:
            return "❌"

    def _field_status(self, percentage: float) -> str:
        """Return status emoji for field coverage"""
        if percentage >= 80:
            return "✅"
        elif percentage >= 50:
            return "⚠️"
        else:
            return "❌"

    def export_report(self, output_file: Path):
        """Export detailed metrics report as JSON"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_commands': len(self.commands),
                'average_overall_score': sum(s.overall_score for s in self.scores.values()) / len(self.commands),
                'average_critical_score': sum(s.critical_score for s in self.scores.values()) / len(self.commands),
                'average_educational_score': sum(s.educational_score for s in self.scores.values()) / len(self.commands),
            },
            'commands': {
                cmd_id: {
                    'name': next((c.get('name') for c in self.commands if c.get('id') == cmd_id), 'Unknown'),
                    'category': next((c.get('_category') for c in self.commands if c.get('id') == cmd_id), 'unknown'),
                    'critical_score': score.critical_score,
                    'educational_score': score.educational_score,
                    'overall_score': score.overall_score,
                    'grade': score.grade
                }
                for cmd_id, score in self.scores.items()
            }
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n✓ Exported report to: {output_file}")


def main():
    """Run metrics dashboard"""
    import argparse

    parser = argparse.ArgumentParser(description='Command quality metrics dashboard')
    parser.add_argument('--data-dir', type=Path,
                       default=Path(__file__).parent.parent / 'data' / 'commands',
                       help='Directory containing command JSON files')
    parser.add_argument('--export', type=Path,
                       help='Export detailed report to JSON file')

    args = parser.parse_args()

    dashboard = MetricsDashboard(args.data_dir)
    dashboard.load_commands()
    dashboard.analyze_commands()
    dashboard.show_dashboard()

    if args.export:
        dashboard.export_report(args.export)


if __name__ == '__main__':
    main()
