"""
Finding Quality Classification

Determines if a finding is "actionable" (would trigger task generation).
Mirrors FindingsProcessor logic to ensure consistency between:
- FindingsProcessor (converts findings to tasks)
- Smart detection plugins (decide when to activate based on findings)

This ensures smart detection doesn't suppress when only boring/passive findings exist.
"""

import re
from typing import Dict, Any, List


class FindingClassifier:
    """Classify findings as actionable vs non-actionable

    Actionable findings = Would trigger task generation in FindingsProcessor
    Non-actionable findings = Logged but don't generate tasks

    This classification mirrors FindingsProcessor logic exactly to ensure:
    - Smart detection activates when needed (no actionable findings)
    - Smart detection deactivates when appropriate (actionable findings exist)
    """

    # From findings_processor.py:119 - Directories that trigger inspection tasks
    INTERESTING_DIRS = [
        '/admin', '/login', '/dashboard', '/config', '/backup',
        '/upload', '/uploads', '/api', '/console', '/manager'
    ]

    # From findings_processor.py:171 - Files that trigger download/analysis tasks
    INTERESTING_FILES = [
        '.config', '.backup', '.bak', '.sql', '.db',
        '.env', 'config.php', 'web.config', '.git'
    ]

    @classmethod
    def is_actionable(cls, finding: Dict[str, Any]) -> bool:
        """
        Check if finding would trigger task generation in FindingsProcessor

        Args:
            finding: Finding dict with keys: type, description, source

        Returns:
            True if finding is actionable (generates tasks)
            False if finding is passive (no tasks generated)

        Examples:
            Actionable:
            - {'type': 'directory', 'description': '/admin'} → True
            - {'type': 'vulnerability', 'description': 'CVE-2021-44228'} → True
            - {'type': 'user', 'description': 'admin'} → True

            Non-actionable:
            - {'type': 'directory', 'description': '/images'} → False
            - {'type': 'credential', 'description': 'admin:password'} → False
            - {'type': 'service', 'description': 'Apache 2.4.41'} → False
        """
        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '')

        # ACTIONABLE: Interesting directories
        # FindingsProcessor._convert_directory_finding() checks if path matches interesting_dirs
        # Only interesting directories generate "Inspect {path}" tasks
        if finding_type in ['directory', 'directories']:
            return any(
                interesting in description.lower()
                for interesting in cls.INTERESTING_DIRS
            )

        # ACTIONABLE: Interesting files
        # FindingsProcessor._convert_file_finding() checks if path contains interesting extensions
        # Only interesting files generate "Fetch {path}" tasks
        elif finding_type in ['file', 'files']:
            return any(
                ext in description.lower()
                for ext in cls.INTERESTING_FILES
            )

        # ACTIONABLE: CVE vulnerabilities (if CVE ID present)
        # FindingsProcessor._convert_vuln_finding() extracts CVE ID and generates searchsploit task
        # Only vulnerabilities with CVE-YYYY-NNNNN format are actionable
        elif finding_type in ['vulnerability', 'vulnerabilities']:
            return bool(re.search(r'CVE-\d{4}-\d{4,}', description, re.IGNORECASE))

        # ACTIONABLE: User findings (password testing)
        # FindingsProcessor._convert_user_finding() generates password guessing task
        # All user findings are actionable
        elif finding_type in ['user', 'users']:
            return True

        # NON-ACTIONABLE: Credentials (logged only)
        # FindingsProcessor._convert_credential_finding() returns empty list
        # Credentials are valuable but don't automatically generate tasks
        # Stored in profile.credentials for manual use
        elif finding_type in ['credential', 'credentials']:
            return False

        # NON-ACTIONABLE: Services (handled by ServicePlugins)
        # FindingsProcessor._convert_service_finding() returns empty list
        # Service detection triggers ServicePlugin activation, not FindingsProcessor tasks
        # Prevents duplicate task generation
        elif finding_type in ['service', 'services']:
            return False

        # UNKNOWN: Treat as non-actionable (conservative)
        # Unknown finding types shouldn't suppress smart detection
        # Better to over-generate tasks than under-generate
        else:
            return False

    @classmethod
    def count_actionable(cls, findings: List[Dict[str, Any]]) -> int:
        """
        Count actionable findings in list

        Args:
            findings: List of finding dicts

        Returns:
            Number of actionable findings

        Example:
            findings = [
                {'type': 'directory', 'description': '/admin'},       # Actionable
                {'type': 'directory', 'description': '/images'},      # Not actionable
                {'type': 'credential', 'description': 'admin:pass'},  # Not actionable
                {'type': 'user', 'description': 'admin'}              # Actionable
            ]
            count_actionable(findings) → 2
        """
        return sum(1 for f in findings if cls.is_actionable(f))

    @classmethod
    def has_actionable(cls, findings: List[Dict[str, Any]]) -> bool:
        """
        Check if ANY findings are actionable

        Args:
            findings: List of finding dicts

        Returns:
            True if at least one finding is actionable
            False if all findings are non-actionable

        Usage in smart detection:
            if FindingClassifier.has_actionable(profile.findings):
                return 0  # Defer to finding-based activation
            else:
                # Activate smart detection (no actionable findings yet)
                return 25
        """
        return any(cls.is_actionable(f) for f in findings)

    @classmethod
    def filter_actionable(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter list to only actionable findings

        Args:
            findings: List of finding dicts

        Returns:
            List containing only actionable findings

        Example:
            findings = [
                {'type': 'directory', 'description': '/admin'},
                {'type': 'directory', 'description': '/images'},
                {'type': 'credential', 'description': 'admin:pass'}
            ]
            filter_actionable(findings) → [
                {'type': 'directory', 'description': '/admin'}
            ]
        """
        return [f for f in findings if cls.is_actionable(f)]

    @classmethod
    def filter_non_actionable(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter list to only non-actionable findings

        Args:
            findings: List of finding dicts

        Returns:
            List containing only non-actionable findings

        Example:
            findings = [
                {'type': 'directory', 'description': '/admin'},
                {'type': 'directory', 'description': '/images'},
                {'type': 'credential', 'description': 'admin:pass'}
            ]
            filter_non_actionable(findings) → [
                {'type': 'directory', 'description': '/images'},
                {'type': 'credential', 'description': 'admin:pass'}
            ]
        """
        return [f for f in findings if not cls.is_actionable(f)]

    @classmethod
    def get_actionability_report(cls, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate detailed report on finding actionability

        Args:
            findings: List of finding dicts

        Returns:
            Report dict with statistics and categorization

        Example:
            report = get_actionability_report(findings)
            {
                'total': 5,
                'actionable': 2,
                'non_actionable': 3,
                'actionable_findings': [...],
                'non_actionable_findings': [...],
                'by_type': {
                    'directory': {'total': 3, 'actionable': 1},
                    'credential': {'total': 1, 'actionable': 0},
                    ...
                }
            }
        """
        actionable = cls.filter_actionable(findings)
        non_actionable = cls.filter_non_actionable(findings)

        # Count by type
        by_type = {}
        for finding in findings:
            ftype = finding.get('type', 'unknown')
            if ftype not in by_type:
                by_type[ftype] = {'total': 0, 'actionable': 0}
            by_type[ftype]['total'] += 1
            if cls.is_actionable(finding):
                by_type[ftype]['actionable'] += 1

        return {
            'total': len(findings),
            'actionable': len(actionable),
            'non_actionable': len(non_actionable),
            'actionable_findings': actionable,
            'non_actionable_findings': non_actionable,
            'by_type': by_type
        }
