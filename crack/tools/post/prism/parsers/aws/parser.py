"""
AWS Credentials Parser

Extracts AWS access keys and secrets from credentials files.

Supported formats:
- AWS credentials file (~/.aws/credentials) - INI format
- Environment variable exports (export AWS_ACCESS_KEY_ID=...)
- Config files containing aws_access_key_id entries
- Inline AKIA patterns in various file formats

Detection:
- Filename: credentials in .aws path, aws_credentials, .aws_credentials
- Content: aws_access_key_id/aws_secret_access_key patterns
- Content: AKIA prefix pattern (AWS access key format)

AWS Key Format:
- Access Key ID: AKIA + 16 alphanumeric chars (20 total)
- Secret Access Key: 40 chars base64-like
"""

import re
import configparser
from typing import Optional, List, Dict
from pathlib import Path
from io import StringIO

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType


# AWS credential file patterns
AWS_FILENAMES = frozenset([
    'credentials',
    'aws_credentials',
    '.aws_credentials',
    'config',  # AWS config file (if in .aws directory)
])

# AWS Access Key ID pattern (starts with AKIA, ASIA, AIDA, AROA, ANPA, ANVA, AGPA)
# AKIA = regular access key, ASIA = STS temporary credentials
ACCESS_KEY_PATTERN = re.compile(
    r'(?:A(?:KIA|SIA|IDA|ROA|NPA|NVA|GPA)[A-Z0-9]{16})'
)

# AWS Secret pattern (40 chars, mixed case alphanumeric with +/)
SECRET_KEY_PATTERN = re.compile(
    r'[A-Za-z0-9+/]{40}'
)

# INI-style key-value patterns
INI_KEY_PATTERNS = {
    'access_key': re.compile(
        r'^\s*(?:aws_)?access_key_id\s*[=:]\s*([A-Z0-9]{20})\s*$',
        re.MULTILINE | re.IGNORECASE
    ),
    'secret_key': re.compile(
        r'^\s*(?:aws_)?secret_access_key\s*[=:]\s*([A-Za-z0-9+/]{40})\s*$',
        re.MULTILINE | re.IGNORECASE
    ),
    'session_token': re.compile(
        r'^\s*(?:aws_)?session_token\s*[=:]\s*([A-Za-z0-9+/=]+)\s*$',
        re.MULTILINE | re.IGNORECASE
    ),
    'region': re.compile(
        r'^\s*(?:aws_)?(?:default_)?region\s*[=:]\s*([a-z]{2}-[a-z]+-\d+)\s*$',
        re.MULTILINE | re.IGNORECASE
    ),
}

# Export pattern (shell scripts, .env files)
EXPORT_PATTERNS = {
    'access_key': re.compile(
        r'(?:export\s+)?AWS_ACCESS_KEY_ID\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?',
        re.IGNORECASE
    ),
    'secret_key': re.compile(
        r'(?:export\s+)?AWS_SECRET_ACCESS_KEY\s*[=:]\s*["\']?([A-Za-z0-9+/]{40})["\']?',
        re.IGNORECASE
    ),
}


@PrismParserRegistry.register
class AWSCredentialsParser(PrismParser):
    """Parser for AWS credentials files"""

    @property
    def name(self) -> str:
        return "aws"

    @property
    def description(self) -> str:
        return "AWS credentials parser (access keys, secrets from ~/.aws/credentials)"

    def can_parse(self, filepath: str) -> bool:
        """Detect AWS credentials files by path, filename, or content"""
        if not self.validate_file(filepath):
            return False

        path = Path(filepath)
        filename = path.name.lower()

        # Check for .aws directory in path
        if '.aws' in path.parts:
            if filename in ['credentials', 'config']:
                return True

        # Check by filename
        if filename in AWS_FILENAMES:
            # Verify content
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read(4096)
                return self._has_aws_patterns(content)
            except Exception:
                return False

        # Check content for AWS patterns in any file
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(4096)
            return self._has_aws_patterns(content)
        except Exception:
            return False

    def _has_aws_patterns(self, content: str) -> bool:
        """Check if content contains AWS credential patterns"""
        # Check for AKIA/ASIA access key prefix
        if ACCESS_KEY_PATTERN.search(content):
            return True

        # Check for aws_access_key_id pattern
        if INI_KEY_PATTERNS['access_key'].search(content):
            return True

        # Check for export patterns
        if EXPORT_PATTERNS['access_key'].search(content):
            return True

        return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse AWS credentials file

        Args:
            filepath: Path to credentials file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted AWS credentials
        """
        content = self.read_file(filepath)
        path = Path(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='aws',
            lines_parsed=len(content.splitlines()),
        )

        # Try INI parsing first (standard AWS credentials format)
        credentials = self._parse_ini_format(content, filepath)

        # If no INI credentials, try regex extraction
        if not credentials:
            credentials = self._extract_regex(content, filepath)

        summary.credentials.extend(credentials)
        summary.source_hostname = hostname or self._infer_host_from_path(filepath)

        return summary.deduplicate()

    def _parse_ini_format(self, content: str, filepath: str) -> List[Credential]:
        """Parse AWS credentials in INI format

        Format:
        [profile_name]
        aws_access_key_id = AKIA...
        aws_secret_access_key = ...
        """
        credentials = []

        try:
            # ConfigParser for INI parsing
            config = configparser.ConfigParser()
            config.read_string(content)

            for section in config.sections():
                profile_name = section

                # Extract access key
                access_key = None
                secret_key = None
                region = None

                for key in ['aws_access_key_id', 'access_key_id', 'aws_access_key']:
                    if config.has_option(section, key):
                        access_key = config.get(section, key).strip()
                        break

                for key in ['aws_secret_access_key', 'secret_access_key', 'aws_secret_key']:
                    if config.has_option(section, key):
                        secret_key = config.get(section, key).strip()
                        break

                for key in ['region', 'aws_default_region']:
                    if config.has_option(section, key):
                        region = config.get(section, key).strip()
                        break

                # Validate and create credential
                if access_key and self._validate_access_key(access_key):
                    # Use access key as username, secret as value
                    # Profile name as domain for organization
                    credential = Credential(
                        username=access_key,
                        domain=profile_name if profile_name != 'default' else '',
                        cred_type=CredentialType.AWS_ACCESS_KEY,
                        value=secret_key or '[SECRET NOT FOUND]',
                    )
                    credentials.append(credential)

        except configparser.Error:
            # Not valid INI, will fall back to regex
            pass

        return credentials

    def _extract_regex(self, content: str, filepath: str) -> List[Credential]:
        """Extract AWS credentials via regex (fallback)"""
        credentials = []
        found_pairs: Dict[str, str] = {}

        # Find all access keys
        access_keys = ACCESS_KEY_PATTERN.findall(content)

        # Try to find corresponding secrets near each access key
        for access_key in access_keys:
            if access_key in found_pairs:
                continue

            # Look for secret key near the access key
            # Find position of access key
            pos = content.find(access_key)
            if pos == -1:
                continue

            # Search in surrounding context (500 chars before and after)
            context_start = max(0, pos - 500)
            context_end = min(len(content), pos + 500)
            context = content[context_start:context_end]

            # Look for secret key pattern in context
            secret_match = INI_KEY_PATTERNS['secret_key'].search(context)
            if not secret_match:
                secret_match = EXPORT_PATTERNS['secret_key'].search(context)

            secret_key = secret_match.group(1) if secret_match else None

            # Look for profile name
            profile_name = self._find_profile_near(content, pos)

            credential = Credential(
                username=access_key,
                domain=profile_name,
                cred_type=CredentialType.AWS_ACCESS_KEY,
                value=secret_key or '[SECRET NOT FOUND]',
            )
            credentials.append(credential)
            found_pairs[access_key] = secret_key or ''

        return credentials

    def _validate_access_key(self, key: str) -> bool:
        """Validate AWS access key format"""
        if not key or len(key) != 20:
            return False

        # Valid prefixes
        valid_prefixes = ['AKIA', 'ASIA', 'AIDA', 'AROA', 'ANPA', 'ANVA', 'AGPA']
        return any(key.startswith(prefix) for prefix in valid_prefixes)

    def _find_profile_near(self, content: str, pos: int) -> str:
        """Find INI section header near a position"""
        # Look backwards for [section] pattern
        search_start = max(0, pos - 200)
        context = content[search_start:pos]

        # Find last section header
        section_pattern = re.compile(r'\[([^\]]+)\]')
        matches = list(section_pattern.finditer(context))

        if matches:
            profile = matches[-1].group(1).strip()
            if profile != 'default':
                return profile

        return ""

    def _infer_host_from_path(self, filepath: str) -> str:
        """Try to infer hostname from file path"""
        path = Path(filepath)

        # Check for hostname patterns in path
        for part in path.parts:
            # IP address pattern
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', part):
                return part
            # Hostname pattern
            if re.match(r'^[a-zA-Z][a-zA-Z0-9-]+[a-zA-Z0-9]$', part):
                if part.lower() not in ['home', 'root', 'aws', 'users', 'tmp', 'var', 'loot']:
                    return part

        # Check for username in path
        for i, part in enumerate(path.parts):
            if part == 'home' and i + 1 < len(path.parts):
                return path.parts[i + 1]
            if part == 'Users' and i + 1 < len(path.parts):
                return path.parts[i + 1]

        return ""
