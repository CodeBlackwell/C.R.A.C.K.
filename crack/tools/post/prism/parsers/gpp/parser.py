"""
GPP (Group Policy Preferences) Password Parser

Parses GPP XML files and decrypts cpassword values using the known Microsoft AES key.

Supported files:
- Groups.xml - Local group membership
- ScheduledTasks.xml - Scheduled tasks
- Services.xml - Service accounts
- DataSources.xml - Data source credentials
- Drives.xml - Mapped drive credentials
- Printers.xml - Printer connections

The cpassword is encrypted with AES-256-CBC using a key published by Microsoft.
"""

import base64
import re
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, Any
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType

# Microsoft's published AES key (MSDN documentation)
GPP_AES_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)

# GPP XML file patterns
GPP_FILES = frozenset([
    'groups.xml',
    'services.xml',
    'scheduledtasks.xml',
    'datasources.xml',
    'printers.xml',
    'drives.xml',
])

# Patterns for detecting GPP content
CPASSWORD_PATTERN = re.compile(r'cpassword="([A-Za-z0-9+/=]+)"', re.IGNORECASE)
USERNAME_PATTERN = re.compile(r'(?:userName|runAs|accountName)="([^"]+)"', re.IGNORECASE)


def decrypt_cpassword(cpassword: str) -> Optional[str]:
    """Decrypt GPP cpassword using Microsoft's published AES key

    Args:
        cpassword: Base64-encoded encrypted password from GPP XML

    Returns:
        Decrypted plaintext password or None if decryption fails
    """
    if not cpassword:
        return None

    try:
        # Pad to 4-byte boundary for base64
        padding = 4 - (len(cpassword) % 4)
        if padding != 4:
            cpassword += '=' * padding

        # Decode base64
        encrypted = base64.b64decode(cpassword)

        # AES-256-CBC with null IV
        from Crypto.Cipher import AES
        cipher = AES.new(GPP_AES_KEY, AES.MODE_CBC, iv=b'\x00' * 16)
        decrypted = cipher.decrypt(encrypted)

        # Remove PKCS7 padding
        pad_len = decrypted[-1]
        if pad_len < 16:
            decrypted = decrypted[:-pad_len]

        # Decode UTF-16LE (Windows default)
        return decrypted.decode('utf-16-le')

    except ImportError:
        # Fallback: try using gpp-decrypt command
        try:
            import subprocess
            result = subprocess.run(
                ['gpp-decrypt', cpassword],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    except Exception:
        pass

    return None


@PrismParserRegistry.register
class GPPParser(PrismParser):
    """Parser for GPP XML files containing encrypted passwords"""

    @property
    def name(self) -> str:
        return "gpp"

    @property
    def description(self) -> str:
        return "Group Policy Preferences password parser (Groups.xml, Services.xml, etc.)"

    def can_parse(self, filepath: str) -> bool:
        """Detect GPP XML files by filename or content"""
        if not self.validate_file(filepath):
            return False

        path = Path(filepath)
        filename = path.name.lower()

        # Check by filename
        if filename in GPP_FILES:
            return True

        # Check by content for generic XML files
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(4096)

            # Look for cpassword attribute (definitive GPP marker)
            if CPASSWORD_PATTERN.search(content):
                return True

            # Look for GPP-specific XML elements
            gpp_markers = [
                '<Groups clsid=',
                '<Services clsid=',
                '<ScheduledTasks clsid=',
                '<DataSources clsid=',
                '<Printers clsid=',
                '<Drives clsid=',
            ]
            return any(marker in content for marker in gpp_markers)

        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse GPP XML file and decrypt passwords

        Args:
            filepath: Path to GPP XML file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted credentials
        """
        content = self.read_file(filepath)
        path = Path(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='gpp',
            lines_parsed=len(content.splitlines()),
        )

        # Determine GPP file type
        gpp_type = self._detect_gpp_type(path.name, content)

        # Parse based on type
        if gpp_type == 'groups':
            credentials = self._parse_groups_xml(content, filepath)
        elif gpp_type == 'services':
            credentials = self._parse_services_xml(content, filepath)
        elif gpp_type == 'scheduledtasks':
            credentials = self._parse_scheduledtasks_xml(content, filepath)
        elif gpp_type == 'datasources':
            credentials = self._parse_datasources_xml(content, filepath)
        elif gpp_type == 'drives':
            credentials = self._parse_drives_xml(content, filepath)
        elif gpp_type == 'printers':
            credentials = self._parse_printers_xml(content, filepath)
        else:
            # Generic extraction for unknown GPP types
            credentials = self._extract_all_cpasswords(content, filepath)

        summary.credentials.extend(credentials)

        # Infer domain from file path (often contains domain info)
        if not summary.source_domain:
            summary.source_domain = self._infer_domain_from_path(filepath)

        summary.source_hostname = hostname or ""

        return summary.deduplicate()

    def _detect_gpp_type(self, filename: str, content: str) -> str:
        """Detect GPP file type"""
        filename_lower = filename.lower()

        if 'groups' in filename_lower or '<Groups clsid=' in content:
            return 'groups'
        elif 'services' in filename_lower or '<Services clsid=' in content:
            return 'services'
        elif 'scheduledtasks' in filename_lower or '<ScheduledTasks clsid=' in content:
            return 'scheduledtasks'
        elif 'datasources' in filename_lower or '<DataSources clsid=' in content:
            return 'datasources'
        elif 'drives' in filename_lower or '<Drives clsid=' in content:
            return 'drives'
        elif 'printers' in filename_lower or '<Printers clsid=' in content:
            return 'printers'
        return 'unknown'

    def _parse_groups_xml(self, content: str, filepath: str) -> List[Credential]:
        """Parse Groups.xml - local group memberships"""
        credentials = []

        try:
            root = ET.fromstring(content)

            for user_elem in root.iter('User'):
                props = user_elem.find('Properties')
                if props is None:
                    continue

                username = props.get('userName', '')
                cpassword = props.get('cpassword', '')

                if not username and not cpassword:
                    continue

                cred = self._create_credential(
                    username=username,
                    cpassword=cpassword,
                    source=f"GPP Groups.xml ({filepath})",
                )
                if cred:
                    credentials.append(cred)

        except ET.ParseError:
            # Fall back to regex extraction
            credentials.extend(self._extract_all_cpasswords(content, filepath))

        return credentials

    def _parse_services_xml(self, content: str, filepath: str) -> List[Credential]:
        """Parse Services.xml - service account credentials"""
        credentials = []

        try:
            root = ET.fromstring(content)

            for svc_elem in root.iter('NTService'):
                props = svc_elem.find('Properties')
                if props is None:
                    continue

                username = props.get('accountName', '')
                cpassword = props.get('cpassword', '')
                svc_name = props.get('serviceName', '')

                if not username and not cpassword:
                    continue

                cred = self._create_credential(
                    username=username,
                    cpassword=cpassword,
                    source=f"GPP Services.xml - {svc_name} ({filepath})",
                )
                if cred:
                    credentials.append(cred)

        except ET.ParseError:
            credentials.extend(self._extract_all_cpasswords(content, filepath))

        return credentials

    def _parse_scheduledtasks_xml(self, content: str, filepath: str) -> List[Credential]:
        """Parse ScheduledTasks.xml - scheduled task credentials"""
        credentials = []

        try:
            root = ET.fromstring(content)

            # Handle different task types
            for task_elem in root.iter():
                if task_elem.tag in ('Task', 'TaskV2', 'ImmediateTask', 'ImmediateTaskV2'):
                    props = task_elem.find('Properties')
                    if props is None:
                        continue

                    username = props.get('runAs', '')
                    cpassword = props.get('cpassword', '')
                    task_name = props.get('name', 'Unknown Task')

                    if not username and not cpassword:
                        continue

                    cred = self._create_credential(
                        username=username,
                        cpassword=cpassword,
                        source=f"GPP ScheduledTasks.xml - {task_name} ({filepath})",
                    )
                    if cred:
                        credentials.append(cred)

        except ET.ParseError:
            credentials.extend(self._extract_all_cpasswords(content, filepath))

        return credentials

    def _parse_datasources_xml(self, content: str, filepath: str) -> List[Credential]:
        """Parse DataSources.xml - ODBC data source credentials"""
        credentials = []

        try:
            root = ET.fromstring(content)

            for ds_elem in root.iter('DataSource'):
                props = ds_elem.find('Properties')
                if props is None:
                    continue

                username = props.get('username', '')
                cpassword = props.get('cpassword', '')
                dsn = props.get('dsn', '')

                if not username and not cpassword:
                    continue

                cred = self._create_credential(
                    username=username,
                    cpassword=cpassword,
                    source=f"GPP DataSources.xml - {dsn} ({filepath})",
                )
                if cred:
                    credentials.append(cred)

        except ET.ParseError:
            credentials.extend(self._extract_all_cpasswords(content, filepath))

        return credentials

    def _parse_drives_xml(self, content: str, filepath: str) -> List[Credential]:
        """Parse Drives.xml - mapped drive credentials"""
        credentials = []

        try:
            root = ET.fromstring(content)

            for drive_elem in root.iter('Drive'):
                props = drive_elem.find('Properties')
                if props is None:
                    continue

                username = props.get('userName', '')
                cpassword = props.get('cpassword', '')
                path = props.get('path', '')

                if not username and not cpassword:
                    continue

                cred = self._create_credential(
                    username=username,
                    cpassword=cpassword,
                    source=f"GPP Drives.xml - {path} ({filepath})",
                )
                if cred:
                    credentials.append(cred)

        except ET.ParseError:
            credentials.extend(self._extract_all_cpasswords(content, filepath))

        return credentials

    def _parse_printers_xml(self, content: str, filepath: str) -> List[Credential]:
        """Parse Printers.xml - printer connection credentials"""
        credentials = []

        try:
            root = ET.fromstring(content)

            for printer_elem in root.iter('SharedPrinter'):
                props = printer_elem.find('Properties')
                if props is None:
                    continue

                username = props.get('username', '')
                cpassword = props.get('cpassword', '')
                printer_path = props.get('path', '')

                if not username and not cpassword:
                    continue

                cred = self._create_credential(
                    username=username,
                    cpassword=cpassword,
                    source=f"GPP Printers.xml - {printer_path} ({filepath})",
                )
                if cred:
                    credentials.append(cred)

        except ET.ParseError:
            credentials.extend(self._extract_all_cpasswords(content, filepath))

        return credentials

    def _extract_all_cpasswords(self, content: str, filepath: str) -> List[Credential]:
        """Extract cpasswords via regex (fallback for malformed XML)"""
        credentials = []

        # Find all cpassword values
        cpasswords = CPASSWORD_PATTERN.findall(content)
        usernames = USERNAME_PATTERN.findall(content)

        # Pair them up (best effort)
        for i, cpass in enumerate(cpasswords):
            username = usernames[i] if i < len(usernames) else 'unknown'
            cred = self._create_credential(
                username=username,
                cpassword=cpass,
                source=f"GPP ({filepath})",
            )
            if cred:
                credentials.append(cred)

        return credentials

    def _create_credential(
        self,
        username: str,
        cpassword: str,
        source: str
    ) -> Optional[Credential]:
        """Create a credential from username and cpassword

        Creates two credentials:
        1. GPP_PASSWORD - decrypted cleartext (if decryption succeeds)
        2. GPP_CPASSWORD - raw encrypted value (for reference/manual decrypt)
        """
        if not cpassword:
            return None

        # Parse domain from username (DOMAIN\user or user@domain)
        domain = ""
        clean_username = username

        if '\\' in username:
            domain, clean_username = username.split('\\', 1)
        elif '@' in username:
            clean_username, domain = username.split('@', 1)

        # Attempt decryption
        decrypted = decrypt_cpassword(cpassword)

        if decrypted:
            # Return decrypted cleartext credential
            return Credential(
                username=clean_username,
                domain=domain,
                cred_type=CredentialType.GPP_PASSWORD,
                value=decrypted,
            )
        else:
            # Return raw cpassword for manual decryption
            return Credential(
                username=clean_username,
                domain=domain,
                cred_type=CredentialType.GPP_CPASSWORD,
                value=cpassword,
            )

    def _infer_domain_from_path(self, filepath: str) -> str:
        r"""Try to infer domain from GPP file path

        GPP files are typically at:
        \\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
        """
        path_lower = filepath.lower()

        # Look for SYSVOL path pattern
        if 'sysvol' in path_lower:
            parts = filepath.replace('\\', '/').split('/')
            for i, part in enumerate(parts):
                if part.lower() == 'sysvol' and i + 1 < len(parts):
                    return parts[i + 1].upper()

        return ""
