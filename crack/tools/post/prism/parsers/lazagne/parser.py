"""
LaZagne Credential Parser

Parses LaZagne JSON output files to extract credentials from various sources:
- Browsers (Chrome, Firefox, Edge, etc.)
- Wi-Fi networks
- Windows Credential Manager
- Database clients
- Email clients
- Git credentials
- And many more...

LaZagne JSON structure:
{
  "Software": {
    "browsers": {
      "chrome": [
        {"URL": "https://example.com", "Login": "user", "Password": "pass"}
      ]
    },
    "wifi": [
      {"SSID": "NetworkName", "Password": "wifipass"}
    ],
    "windows": {
      "credman": [
        {"Target": "server", "Username": "user", "Password": "pass"}
      ]
    }
  }
}

Usage:
    crack prism lazagne_output.json
    python lazagne.py all > lazagne_output.json && crack prism lazagne_output.json
"""

import json
import logging
from typing import Optional, List, Dict, Any
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary
from ...models.credential import Credential, CredentialType

logger = logging.getLogger(__name__)


# Keys that contain username values
USERNAME_KEYS = frozenset([
    'login', 'username', 'user', 'email', 'account',
    'name', 'id', 'uid', 'userid', 'user_name',
])

# Keys that contain password values
PASSWORD_KEYS = frozenset([
    'password', 'pass', 'pwd', 'secret', 'key',
    'credential', 'token', 'passphrase',
])

# Keys that provide context (URL, target, etc.)
CONTEXT_KEYS = frozenset([
    'url', 'target', 'ssid', 'host', 'hostname',
    'server', 'site', 'domain', 'path', 'service',
])


@PrismParserRegistry.register
class LaZagneParser(PrismParser):
    """Parser for LaZagne JSON credential dump output"""

    @property
    def name(self) -> str:
        return "lazagne"

    @property
    def description(self) -> str:
        return "LaZagne credential extraction JSON output parser"

    def can_parse(self, filepath: str) -> bool:
        """Detect LaZagne JSON output by structure"""
        if not self.validate_file(filepath):
            return False

        path = Path(filepath)

        # Must be JSON file
        if path.suffix.lower() != '.json':
            return False

        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(8192)

            # Try to parse as JSON
            try:
                # For partial reads, try to detect structure from beginning
                data = json.loads(content)
            except json.JSONDecodeError:
                # Partial content - check for LaZagne markers
                return self._detect_lazagne_markers(content)

            # Check for LaZagne structure
            return self._is_lazagne_structure(data)

        except Exception as e:
            logger.debug(f"LaZagne detection failed: {e}")
            return False

    def _detect_lazagne_markers(self, content: str) -> bool:
        """Detect LaZagne output from partial content using string markers"""
        lazagne_markers = [
            '"Software"',
            '"browsers"',
            '"wifi"',
            '"credman"',
            '"Login"',
            '"Password"',
            '"SSID"',
            # LaZagne category names
            '"chats"',
            '"databases"',
            '"games"',
            '"git"',
            '"mails"',
            '"memory"',
            '"multimedia"',
            '"php"',
            '"svn"',
            '"sysadmin"',
            '"windows"',
        ]
        matches = sum(1 for marker in lazagne_markers if marker in content)
        # Need at least 3 markers to be confident
        return matches >= 3

    def _is_lazagne_structure(self, data: Any) -> bool:
        """Check if JSON data matches LaZagne output structure"""
        if not isinstance(data, dict):
            return False

        # Primary marker: "Software" key at top level
        if 'Software' in data:
            return True

        # Alternative: check for known LaZagne category structure
        lazagne_categories = {
            'browsers', 'wifi', 'windows', 'chats', 'databases',
            'games', 'git', 'mails', 'memory', 'multimedia',
            'php', 'svn', 'sysadmin',
        }

        # Check if top-level keys match LaZagne categories
        top_keys = set(k.lower() for k in data.keys())
        if top_keys & lazagne_categories:
            return True

        return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse LaZagne JSON file and extract credentials

        Args:
            filepath: Path to LaZagne JSON output
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted credentials
        """
        content = self.read_file(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='lazagne',
            lines_parsed=len(content.splitlines()),
        )

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LaZagne JSON: {e}")
            return summary

        # Extract credentials from structure
        credentials = self._extract_credentials(data)
        summary.credentials.extend(credentials)

        # Set user-specified hostname (lazagne doesn't detect hostname)
        self.set_hostname(summary, None, hostname)

        return summary.deduplicate()

    def _extract_credentials(self, data: Any) -> List[Credential]:
        """Extract credentials from LaZagne JSON structure recursively

        Args:
            data: Parsed JSON data

        Returns:
            List of extracted Credential objects
        """
        credentials: List[Credential] = []

        if not isinstance(data, dict):
            return credentials

        # Handle "Software" wrapper
        if 'Software' in data:
            data = data['Software']

        # Process each category
        for category, category_data in data.items():
            creds = self._process_category(category, category_data)
            credentials.extend(creds)

        return credentials

    def _process_category(
        self,
        category: str,
        category_data: Any,
        parent_source: str = ""
    ) -> List[Credential]:
        """Process a LaZagne category (browsers, wifi, etc.)

        Args:
            category: Category name (e.g., 'browsers', 'wifi')
            category_data: Data for this category
            parent_source: Parent context for nested categories

        Returns:
            List of Credential objects
        """
        credentials: List[Credential] = []
        source = f"{parent_source}/{category}" if parent_source else category

        if isinstance(category_data, dict):
            # Nested structure (e.g., browsers -> chrome -> [entries])
            for subcategory, subdata in category_data.items():
                creds = self._process_category(subcategory, subdata, source)
                credentials.extend(creds)

        elif isinstance(category_data, list):
            # List of credential entries
            for entry in category_data:
                if isinstance(entry, dict):
                    cred = self._parse_credential_entry(entry, source)
                    if cred:
                        credentials.append(cred)

        return credentials

    def _parse_credential_entry(
        self,
        entry: Dict[str, Any],
        source: str
    ) -> Optional[Credential]:
        """Parse a single credential entry from LaZagne output

        Args:
            entry: Credential entry dictionary
            source: Source category path (e.g., 'browsers/chrome')

        Returns:
            Credential object or None if no valid credentials found
        """
        # Normalize keys to lowercase for matching
        entry_lower = {k.lower(): v for k, v in entry.items()}

        # Find username
        username = self._find_value(entry_lower, USERNAME_KEYS)

        # Find password
        password = self._find_value(entry_lower, PASSWORD_KEYS)

        # Skip entries without meaningful credentials
        if not password:
            return None

        # Use 'unknown' for missing username
        if not username:
            username = 'unknown'

        # Find context (URL, target, SSID, etc.)
        context = self._find_value(entry_lower, CONTEXT_KEYS)

        # Parse domain from username if present
        domain = ""
        clean_username = username

        if '\\' in username:
            domain, clean_username = username.split('\\', 1)
        elif '@' in username:
            clean_username, domain = username.split('@', 1)

        # Build session_type from source and context
        session_type = source
        if context:
            session_type = f"{source}: {context}"

        return Credential(
            username=clean_username,
            domain=domain,
            cred_type=CredentialType.CLEARTEXT,
            value=password,
            session_type=session_type,
        )

    def _find_value(
        self,
        entry: Dict[str, Any],
        keys: frozenset
    ) -> str:
        """Find a value from entry matching one of the given keys

        Args:
            entry: Entry dictionary with lowercase keys
            keys: Set of keys to search for

        Returns:
            Found value as string, or empty string
        """
        for key in keys:
            if key in entry:
                value = entry[key]
                if value is not None and str(value).strip():
                    return str(value).strip()
        return ""
