#!/usr/bin/env python3
"""
Similarity Analysis Tool for Copyright Audit

Compares db/data content against reference text to identify
entries that may need modification.

Techniques:
1. N-gram matching (3-5 word phrases)
2. Fuzzy description matching
3. Exact phrase detection
4. Command syntax similarity
"""

import json
import re
import os
import sys
from pathlib import Path
from collections import defaultdict
from difflib import SequenceMatcher

# Minimum similarity threshold (0-1)
SIMILARITY_THRESHOLD = 0.7
NGRAM_MIN_LENGTH = 4  # Minimum words in matching phrase


def load_reference_text(filepath: str) -> str:
    """Load and clean reference text."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).lower()
    return text


def extract_ngrams(text: str, n: int) -> set:
    """Extract n-grams from text."""
    words = re.findall(r'\b[a-z]{3,}\b', text.lower())
    return set(' '.join(words[i:i+n]) for i in range(len(words) - n + 1))


def load_json_entries(db_path: str) -> list:
    """Load all JSON entries from db/data."""
    entries = []

    for root, _, files in os.walk(db_path):
        for file in files:
            if not file.endswith('.json'):
                continue

            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, db_path)

            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
            except (json.JSONDecodeError, IOError):
                continue

            # Extract entries based on structure
            if isinstance(data, dict):
                # Commands file with 'commands' array
                if 'commands' in data:
                    for cmd in data['commands']:
                        entries.append({
                            'file': rel_path,
                            'id': cmd.get('id', 'unknown'),
                            'type': 'command',
                            'name': cmd.get('name', ''),
                            'description': cmd.get('description', ''),
                            'notes': cmd.get('notes', ''),
                            'syntax': cmd.get('syntax', ''),
                        })
                # Cheatsheet with 'sections'
                elif 'sections' in data:
                    for section in data.get('sections', []):
                        for cmd in section.get('commands', []):
                            entries.append({
                                'file': rel_path,
                                'id': cmd.get('id', section.get('name', 'unknown')),
                                'type': 'cheatsheet',
                                'name': cmd.get('name', ''),
                                'description': cmd.get('description', ''),
                                'notes': cmd.get('notes', ''),
                                'syntax': cmd.get('syntax', ''),
                            })
                # Chain with 'steps'
                elif 'steps' in data:
                    entries.append({
                        'file': rel_path,
                        'id': data.get('id', 'unknown'),
                        'type': 'chain',
                        'name': data.get('name', ''),
                        'description': data.get('description', ''),
                        'notes': '\n'.join(s.get('notes', '') for s in data.get('steps', [])),
                        'syntax': '',
                    })
                # Writeup
                elif 'machine' in data or 'platform' in data:
                    entries.append({
                        'file': rel_path,
                        'id': data.get('id', data.get('machine', 'unknown')),
                        'type': 'writeup',
                        'name': data.get('machine', data.get('name', '')),
                        'description': data.get('summary', ''),
                        'notes': '\n'.join(data.get('key_learnings', [])),
                        'syntax': '',
                    })

    return entries


def calculate_similarity(text1: str, text2: str) -> float:
    """Calculate similarity ratio between two texts."""
    if not text1 or not text2:
        return 0.0
    return SequenceMatcher(None, text1.lower(), text2.lower()).ratio()


def find_matching_phrases(entry_text: str, reference_ngrams: dict, min_words: int = 4) -> list:
    """Find phrases in entry that match reference n-grams."""
    matches = []
    entry_lower = entry_text.lower()

    for n in range(min_words, 8):
        entry_ngrams = extract_ngrams(entry_lower, n)
        if n in reference_ngrams:
            common = entry_ngrams & reference_ngrams[n]
            for phrase in common:
                # Filter out generic phrases
                if not is_generic_phrase(phrase):
                    matches.append((n, phrase))

    return matches


def is_generic_phrase(phrase: str) -> bool:
    """Check if phrase is too generic to be meaningful."""
    generic_patterns = [
        r'^the .* is$',
        r'^this .* the$',
        r'^we can use$',
        r'^you can use$',
        r'^to do this$',
        r'^in order to$',
        r'^we need to$',
        r'^the following$',
        r'^for example$',
    ]

    # Very common tech terms that appear everywhere
    generic_terms = {
        'the command will', 'this will allow', 'we can see',
        'the output shows', 'run the following', 'use the following',
        'the next step', 'in this case', 'as shown below',
    }

    if phrase in generic_terms:
        return True

    for pattern in generic_patterns:
        if re.match(pattern, phrase):
            return True

    return False


def analyze_entry(entry: dict, reference_text: str, reference_ngrams: dict) -> dict:
    """Analyze a single entry for similarity."""
    results = {
        'file': entry['file'],
        'id': entry['id'],
        'type': entry['type'],
        'name': entry['name'],
        'issues': [],
        'severity': 'low',
        'matching_phrases': [],
    }

    # Combine all text fields
    full_text = ' '.join(filter(None, [
        entry.get('description', ''),
        entry.get('notes', ''),
    ]))

    if not full_text.strip():
        return results

    # Check description similarity
    desc = entry.get('description', '')
    if len(desc) > 50:
        # Look for exact substring matches (50+ chars)
        desc_lower = desc.lower()
        if desc_lower in reference_text:
            results['issues'].append('EXACT_MATCH: Description found verbatim in reference')
            results['severity'] = 'critical'

    # Find matching n-gram phrases
    matching_phrases = find_matching_phrases(full_text, reference_ngrams)
    if matching_phrases:
        results['matching_phrases'] = matching_phrases

        # Score based on longest match
        max_words = max(m[0] for m in matching_phrases)
        if max_words >= 7:
            results['issues'].append(f'LONG_PHRASE_MATCH: {max_words}-word phrase matches reference')
            results['severity'] = 'high'
        elif max_words >= 5:
            results['issues'].append(f'PHRASE_MATCH: {max_words}-word phrase matches reference')
            if results['severity'] != 'high':
                results['severity'] = 'medium'

    # Check for specific course-related terms
    course_markers = [
        'medtech', 'relia', 'secura', 'skylark', 'oscp lab',
        'pen-200', 'pwk', 'offsec', 'offensive security',
        '192.168.119', '192.168.120', '192.168.121',  # Common lab ranges
    ]

    text_lower = full_text.lower()
    for marker in course_markers:
        if marker in text_lower:
            results['issues'].append(f'COURSE_MARKER: Contains "{marker}"')
            results['severity'] = 'critical'

    return results


def main():
    # Paths
    script_dir = Path(__file__).parent.parent
    db_path = script_dir / 'db' / 'data'
    reference_path = Path('/tmp/pen200_text.txt')

    if not reference_path.exists():
        print(f"[!] Reference text not found: {reference_path}")
        print("    Run: pdftotext /path/to/pen-200.pdf /tmp/pen200_text.txt")
        sys.exit(1)

    print("[*] Loading reference text...")
    reference_text = load_reference_text(str(reference_path))
    print(f"    Loaded {len(reference_text):,} characters")

    print("[*] Building n-gram index...")
    reference_ngrams = {}
    for n in range(NGRAM_MIN_LENGTH, 8):
        reference_ngrams[n] = extract_ngrams(reference_text, n)
        print(f"    {n}-grams: {len(reference_ngrams[n]):,}")

    print(f"[*] Loading entries from {db_path}...")
    entries = load_json_entries(str(db_path))
    print(f"    Found {len(entries)} entries")

    print("[*] Analyzing entries...")
    results = []
    for entry in entries:
        result = analyze_entry(entry, reference_text, reference_ngrams)
        if result['issues']:
            results.append(result)

    # Sort by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    results.sort(key=lambda x: severity_order.get(x['severity'], 4))

    # Output report
    print("\n" + "="*80)
    print("SIMILARITY AUDIT REPORT")
    print("="*80)

    stats = defaultdict(int)
    for r in results:
        stats[r['severity']] += 1

    print(f"\nSummary:")
    print(f"  Critical: {stats['critical']}")
    print(f"  High:     {stats['high']}")
    print(f"  Medium:   {stats['medium']}")
    print(f"  Low:      {stats['low']}")
    print(f"  Total:    {len(results)} entries flagged\n")

    # Detailed output
    for severity in ['critical', 'high', 'medium']:
        items = [r for r in results if r['severity'] == severity]
        if not items:
            continue

        print(f"\n{'='*40}")
        print(f"[{severity.upper()}] - {len(items)} items")
        print(f"{'='*40}")

        for r in items:
            print(f"\n  File: {r['file']}")
            print(f"  ID:   {r['id']}")
            print(f"  Name: {r['name'][:60]}..." if len(r['name']) > 60 else f"  Name: {r['name']}")
            print(f"  Issues:")
            for issue in r['issues']:
                print(f"    - {issue}")
            if r['matching_phrases']:
                print(f"  Matching phrases:")
                for n, phrase in r['matching_phrases'][:3]:
                    print(f"    - [{n}w] \"{phrase[:50]}...\"" if len(phrase) > 50 else f"    - [{n}w] \"{phrase}\"")

    # Export checklist
    checklist_path = script_dir / 'SIMILARITY_CHECKLIST.md'
    with open(checklist_path, 'w') as f:
        f.write("# Similarity Audit Checklist\n\n")
        f.write("Items flagged for potential modification based on similarity to reference material.\n\n")
        f.write(f"**Generated:** {__import__('datetime').datetime.now().isoformat()}\n\n")

        f.write("## Summary\n\n")
        f.write(f"| Severity | Count |\n")
        f.write(f"|----------|-------|\n")
        f.write(f"| Critical | {stats['critical']} |\n")
        f.write(f"| High | {stats['high']} |\n")
        f.write(f"| Medium | {stats['medium']} |\n")
        f.write(f"| Low | {stats['low']} |\n\n")

        for severity in ['critical', 'high', 'medium']:
            items = [r for r in results if r['severity'] == severity]
            if not items:
                continue

            f.write(f"\n## {severity.upper()} Priority\n\n")

            for r in items:
                f.write(f"### [ ] `{r['id']}`\n\n")
                f.write(f"- **File:** `{r['file']}`\n")
                f.write(f"- **Type:** {r['type']}\n")
                f.write(f"- **Name:** {r['name']}\n")
                f.write(f"- **Issues:**\n")
                for issue in r['issues']:
                    f.write(f"  - {issue}\n")
                if r['matching_phrases']:
                    f.write(f"- **Matching phrases:**\n")
                    for n, phrase in r['matching_phrases'][:5]:
                        f.write(f"  - `{phrase}`\n")
                f.write(f"\n**Action:** Rewrite description/notes to be original\n\n")
                f.write("---\n\n")

    print(f"\n[+] Checklist exported to: {checklist_path}")


if __name__ == '__main__':
    main()
