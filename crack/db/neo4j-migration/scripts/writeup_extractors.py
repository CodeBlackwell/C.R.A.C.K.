#!/usr/bin/env python3
"""
Writeup Extractors for Neo4j CSV Generation

Extracts nodes and relationships from writeup JSON files:
- Writeup nodes
- CVE nodes
- Technique nodes
- Platform nodes
- Skill nodes
- Failed Attempt data
- Relationships to commands, chains, techniques, CVEs, etc.
"""

from typing import List, Dict, Any, Set
import hashlib


def generate_id(text: str) -> str:
    """Generate consistent ID from text"""
    return hashlib.md5(text.encode()).hexdigest()[:16]


class WriteupNodesExtractor:
    """Extract writeup nodes for CSV"""

    def extract_nodes(self, writeups: List[Dict]) -> List[Dict]:
        """
        Extract writeup node data

        Returns list of dicts with fields:
        - id, name, platform, machine_type, difficulty, os, os_version
        - ip_address, oscp_relevance, exam_applicable, synopsis
        - total_duration_minutes, release_date, retire_date
        - writeup_author, writeup_date, tags, attack_phases
        """
        import json

        nodes = []

        for writeup in writeups:
            source = writeup.get('source', {})
            metadata = writeup.get('metadata', {})
            oscp = writeup.get('oscp_relevance', {})
            time_breakdown = writeup.get('time_breakdown', {})

            # Serialize attack_phases as JSON string for Neo4j storage
            attack_phases = writeup.get('attack_phases', [])
            attack_phases_json = json.dumps(attack_phases) if attack_phases else '[]'

            node = {
                'id': writeup.get('id', ''),
                'name': writeup.get('name', ''),
                'platform': source.get('platform', ''),
                'machine_type': source.get('type', ''),
                'difficulty': metadata.get('difficulty', ''),
                'os': metadata.get('os', ''),
                'os_version': metadata.get('os_version', ''),
                'ip_address': metadata.get('ip_address', ''),
                'oscp_relevance': oscp.get('score', ''),
                'oscp_reasoning': oscp.get('reasoning', ''),
                'exam_applicable': str(oscp.get('exam_applicable', False)),
                'synopsis': writeup.get('synopsis', ''),
                'total_duration_minutes': time_breakdown.get('total_minutes', 0),
                'release_date': source.get('release_date', ''),
                'retire_date': source.get('retire_date', ''),
                'writeup_author': metadata.get('writeup_author', ''),
                'writeup_date': metadata.get('writeup_date', ''),
                'tags': '|'.join(writeup.get('tags', [])),  # Pipe-separated for Neo4j
                'machine_author': metadata.get('machine_author', ''),
                'points': metadata.get('points', 0),
                'attack_phases': attack_phases_json  # JSON string for Neo4j
            }

            nodes.append(node)

        return nodes


class WriteupDemonstratesCommandExtractor:
    """Extract DEMONSTRATES relationships (Writeup -> Command)"""

    def extract_relationships(self, writeups: List[Dict]) -> List[Dict]:
        """
        Extract Writeup -[:DEMONSTRATES]-> Command relationships

        Returns list of dicts with fields:
        - writeup_id, command_id, phase, step_number, context
        - command_executed, success, notes, flags_used
        """
        relationships = []

        for writeup in writeups:
            writeup_id = writeup.get('id', '')

            for phase_data in writeup.get('attack_phases', []):
                phase_name = phase_data.get('phase', '')

                for cmd_usage in phase_data.get('commands_used', []):
                    rel = {
                        'writeup_id': writeup_id,
                        'command_id': cmd_usage.get('command_id', ''),
                        'phase': phase_name,
                        'step_number': cmd_usage.get('step_number', 0),
                        'context': cmd_usage.get('context', ''),
                        'command_executed': cmd_usage.get('command_executed', ''),
                        'success': str(cmd_usage.get('success', False)),
                        'notes': cmd_usage.get('notes', ''),
                        'flags_used': str(cmd_usage.get('flags_used', {})),  # Convert dict to string
                        'output_snippet': cmd_usage.get('output_snippet', ''),
                        'url_visited': cmd_usage.get('url_visited', '')
                    }

                    relationships.append(rel)

        return relationships


class WriteupFailedAttemptExtractor:
    """Extract failed attempt relationships (Writeup -> Command)"""

    def extract_relationships(self, writeups: List[Dict]) -> List[Dict]:
        """
        Extract Writeup -[:FAILED_ATTEMPT]-> Command relationships

        Returns list of dicts with fields:
        - writeup_id, command_id, phase, attempt, expected, actual
        - reason, solution, lesson_learned, time_wasted_minutes, importance
        """
        relationships = []

        for writeup in writeups:
            writeup_id = writeup.get('id', '')

            for phase_data in writeup.get('attack_phases', []):
                phase_name = phase_data.get('phase', '')

                for failed in phase_data.get('failed_attempts', []):
                    # Try to extract command_id from command_executed string
                    # This is a heuristic - ideally it should be in the JSON
                    command_id = self._infer_command_id(failed.get('command_executed', ''))

                    rel = {
                        'writeup_id': writeup_id,
                        'command_id': command_id,
                        'phase': phase_name,
                        'attempt': failed.get('attempt', ''),
                        'command_executed': failed.get('command_executed', ''),
                        'expected': failed.get('expected', ''),
                        'actual': failed.get('actual', ''),
                        'reason': failed.get('reason', ''),
                        'solution': failed.get('solution', ''),
                        'lesson_learned': failed.get('lesson_learned', ''),
                        'time_wasted_minutes': failed.get('time_wasted_minutes', 0),
                        'importance': failed.get('documentation_importance', 'medium')
                    }

                    relationships.append(rel)

        return relationships

    def _infer_command_id(self, command_str: str) -> str:
        """Infer command ID from command string (heuristic)"""
        if not command_str:
            return 'unknown-command'

        # Extract first word (usually the tool name)
        first_word = command_str.split()[0] if command_str.split() else 'unknown'

        # Create simple ID
        return f"{first_word}-command"


class CVENodesExtractor:
    """Extract unique CVE nodes from writeups"""

    def extract_nodes(self, writeups: List[Dict]) -> List[Dict]:
        """
        Extract CVE nodes from all writeups

        Returns list of dicts with fields:
        - cve_id, name, description, severity, component, versions
        """
        cves = {}  # Use dict to deduplicate by cve_id

        for writeup in writeups:
            for phase_data in writeup.get('attack_phases', []):
                for vuln in phase_data.get('vulnerabilities', []):
                    cve_id = vuln.get('cve')

                    if not cve_id or cve_id == 'null':
                        continue  # Skip non-CVE vulnerabilities

                    if cve_id not in cves:
                        cves[cve_id] = {
                            'cve_id': cve_id,
                            'name': vuln.get('name', ''),
                            'description': vuln.get('notes', vuln.get('description', '')),
                            'severity': vuln.get('severity', ''),
                            'component': vuln.get('component', ''),
                            'version': vuln.get('version', ''),
                            'exploitability': vuln.get('exploitability', ''),
                            'type': vuln.get('type', '')
                        }

        return list(cves.values())


class WriteupExploitsCVEExtractor:
    """Extract EXPLOITS_CVE relationships (Writeup -> CVE)"""

    def extract_relationships(self, writeups: List[Dict]) -> List[Dict]:
        """
        Extract Writeup -[:EXPLOITS_CVE]-> CVE relationships

        Returns list of dicts with fields:
        - writeup_id, cve_id, phase, exploitation_method, severity, impact
        """
        relationships = []

        for writeup in writeups:
            writeup_id = writeup.get('id', '')

            for phase_data in writeup.get('attack_phases', []):
                phase_name = phase_data.get('phase', '')

                for vuln in phase_data.get('vulnerabilities', []):
                    cve_id = vuln.get('cve')

                    if not cve_id or cve_id == 'null':
                        continue

                    rel = {
                        'writeup_id': writeup_id,
                        'cve_id': cve_id,
                        'phase': phase_name,
                        'exploitation_method': vuln.get('technique', ''),
                        'severity': vuln.get('severity', ''),
                        'location': vuln.get('location', ''),
                        'parameter': vuln.get('parameter', '')
                    }

                    relationships.append(rel)

        return relationships


class TechniqueNodesExtractor:
    """Extract unique Technique nodes from writeups"""

    def extract_nodes(self, writeups: List[Dict]) -> List[Dict]:
        """
        Extract technique nodes from writeup attack phases

        Returns list of dicts with fields:
        - name, category, difficulty, description, oscp_applicable, steps
        """
        techniques = {}  # Deduplicate by name

        for writeup in writeups:
            for phase_data in writeup.get('attack_phases', []):
                for tech in phase_data.get('techniques', []):
                    name = tech.get('name', '')

                    if not name or name in techniques:
                        continue

                    techniques[name] = {
                        'name': name,
                        'category': tech.get('category', ''),
                        'difficulty': tech.get('difficulty', ''),
                        'description': tech.get('why_this_works', tech.get('description', '')),
                        'oscp_applicable': str(tech.get('oscp_applicable', True)),
                        'steps': '|'.join(tech.get('steps', [])),  # Pipe-separated
                        'detection_difficulty': tech.get('detection_difficulty', ''),
                        'references': '|'.join(tech.get('references', []))
                    }

        return list(techniques.values())


class WriteupTeachesTechniqueExtractor:
    """Extract TEACHES_TECHNIQUE relationships (Writeup -> Technique)"""

    def extract_relationships(self, writeups: List[Dict]) -> List[Dict]:
        """
        Extract Writeup -[:TEACHES_TECHNIQUE]-> Technique relationships
        """
        relationships = []

        for writeup in writeups:
            writeup_id = writeup.get('id', '')

            for phase_data in writeup.get('attack_phases', []):
                phase_name = phase_data.get('phase', '')

                for tech in phase_data.get('techniques', []):
                    rel = {
                        'writeup_id': writeup_id,
                        'technique_name': tech.get('name', ''),
                        'phase': phase_name,
                        'difficulty': tech.get('difficulty', ''),
                        'oscp_applicable': str(tech.get('oscp_applicable', True))
                    }

                    relationships.append(rel)

        return relationships


class PlatformNodesExtractor:
    """Extract unique Platform nodes"""

    def extract_nodes(self, writeups: List[Dict]) -> List[Dict]:
        """Extract platform nodes from writeup sources"""
        platforms = {}  # Deduplicate by name

        for writeup in writeups:
            source = writeup.get('source', {})
            platform_name = source.get('platform', '')

            if not platform_name or platform_name in platforms:
                continue

            platforms[platform_name] = {
                'name': platform_name,
                'url': source.get('url', ''),
                'type': self._infer_platform_type(platform_name)
            }

        return list(platforms.values())

    def _infer_platform_type(self, name: str) -> str:
        """Infer platform type from name"""
        name_lower = name.lower()

        if 'hackthebox' in name_lower or 'htb' in name_lower:
            return 'commercial'
        elif 'provinggrounds' in name_lower or 'offsec' in name_lower:
            return 'official'
        elif 'tryhackme' in name_lower:
            return 'commercial'
        elif 'vulnhub' in name_lower:
            return 'community'
        elif 'oscp' in name_lower:
            return 'official'
        else:
            return 'custom'


class WriteupFromPlatformExtractor:
    """Extract FROM_PLATFORM relationships (Writeup -> Platform)"""

    def extract_relationships(self, writeups: List[Dict]) -> List[Dict]:
        """Extract Writeup -[:FROM_PLATFORM]-> Platform relationships"""
        relationships = []

        for writeup in writeups:
            source = writeup.get('source', {})

            rel = {
                'writeup_id': writeup.get('id', ''),
                'platform_name': source.get('platform', ''),
                'machine_type': source.get('type', ''),
                'release_date': source.get('release_date', ''),
                'retire_date': source.get('retire_date', '')
            }

            relationships.append(rel)

        return relationships


class SkillNodesExtractor:
    """Extract unique Skill nodes from writeups"""

    def extract_nodes(self, writeups: List[Dict]) -> List[Dict]:
        """Extract skill nodes from required/learned skills"""
        skills = {}  # Deduplicate by name

        for writeup in writeups:
            skills_data = writeup.get('skills', {})

            # Required skills
            for skill_name in skills_data.get('required', []):
                if skill_name not in skills:
                    skills[skill_name] = {
                        'name': skill_name,
                        'category': self._infer_category(skill_name),
                        'oscp_importance': 'medium'  # Default
                    }

            # Learned skills
            for skill_name in skills_data.get('learned', []):
                if skill_name not in skills:
                    skills[skill_name] = {
                        'name': skill_name,
                        'category': self._infer_category(skill_name),
                        'oscp_importance': 'medium'
                    }

        return list(skills.values())

    def _infer_category(self, skill_name: str) -> str:
        """Infer skill category from name"""
        name_lower = skill_name.lower()

        if any(x in name_lower for x in ['web', 'http', 'sql', 'xss', 'file upload']):
            return 'web_exploitation'
        elif any(x in name_lower for x in ['priv', 'escalation', 'sudo', 'suid']):
            return 'privilege_escalation'
        elif any(x in name_lower for x in ['binary', 'analysis', 'reverse']):
            return 'binary_analysis'
        elif any(x in name_lower for x in ['enum', 'recon', 'scanning']):
            return 'enumeration'
        elif any(x in name_lower for x in ['lateral', 'movement', 'pivot']):
            return 'lateral_movement'
        else:
            return 'general'


class WriteupRequiresSkillExtractor:
    """Extract REQUIRES_SKILL relationships"""

    def extract_relationships(self, writeups: List[Dict]) -> List[Dict]:
        """Extract Writeup -[:REQUIRES_SKILL]-> Skill relationships"""
        relationships = []

        for writeup in writeups:
            writeup_id = writeup.get('id', '')
            skills_data = writeup.get('skills', {})

            for skill_name in skills_data.get('required', []):
                rel = {
                    'writeup_id': writeup_id,
                    'skill_name': skill_name,
                    'importance': 'medium'  # Could be enhanced with more detail
                }

                relationships.append(rel)

        return relationships


class WriteupTeachesSkillExtractor:
    """Extract TEACHES_SKILL relationships"""

    def extract_relationships(self, writeups: List[Dict]) -> List[Dict]:
        """Extract Writeup -[:TEACHES_SKILL]-> Skill relationships"""
        relationships = []

        for writeup in writeups:
            writeup_id = writeup.get('id', '')
            skills_data = writeup.get('skills', {})

            for skill_name in skills_data.get('learned', []):
                rel = {
                    'writeup_id': writeup_id,
                    'skill_name': skill_name,
                    'proficiency_level': 'intermediate',  # Default
                    'practice_value': 'high'
                }

                relationships.append(rel)

        return relationships


# ============================================================================
# Extractor Registry
# ============================================================================

WRITEUP_EXTRACTORS = {
    # Nodes
    'writeups_nodes': WriteupNodesExtractor(),
    'cve_nodes': CVENodesExtractor(),
    'technique_nodes': TechniqueNodesExtractor(),
    'platform_nodes': PlatformNodesExtractor(),
    'skill_nodes': SkillNodesExtractor(),

    # Relationships
    'writeup_demonstrates_command': WriteupDemonstratesCommandExtractor(),
    'writeup_failed_attempt': WriteupFailedAttemptExtractor(),
    'writeup_exploits_cve': WriteupExploitsCVEExtractor(),
    'writeup_teaches_technique': WriteupTeachesTechniqueExtractor(),
    'writeup_from_platform': WriteupFromPlatformExtractor(),
    'writeup_requires_skill': WriteupRequiresSkillExtractor(),
    'writeup_teaches_skill': WriteupTeachesSkillExtractor()
}
