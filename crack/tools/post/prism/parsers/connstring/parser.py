"""
Connection String Parser

Extracts database credentials from configuration files containing connection strings.

Supported formats:
- ASP.NET: <connectionStrings> XML sections
- Generic: Server=x;Database=y;User Id=z;Password=w
- .env: DB_PASSWORD=xxx, DATABASE_URL=postgres://user:pass@host/db
- PHP: $db_password = 'xxx'

Typical files:
- web.config, app.config (ASP.NET)
- .env, .env.local, .env.production
- config.ini, database.ini
- wp-config.php, settings.php
"""

import re
from typing import Optional, List, Tuple
from pathlib import Path
from urllib.parse import urlparse, unquote

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models.credential import Credential, CredentialType
from ...models.summary import ParsedSummary


# File extensions that commonly contain connection strings
CONNSTRING_EXTENSIONS = frozenset([
    '.config', '.conf', '.cfg',
    '.env', '.ini',
    '.php', '.inc',
    '.properties', '.json', '.yaml', '.yml',
])

# Filenames that commonly contain connection strings
CONNSTRING_FILENAMES = frozenset([
    'web.config', 'app.config', 'appsettings.json',
    '.env', '.env.local', '.env.production', '.env.development',
    'database.ini', 'config.ini', 'settings.ini',
    'wp-config.php', 'configuration.php', 'settings.php', 'config.php',
    'database.yml', 'database.yaml',
    'application.properties', 'application.yml',
])

# Regex patterns for connection string formats

# Generic key=value connection string (SQL Server, MySQL, etc.)
# Example: Server=localhost;Database=mydb;User Id=admin;Password=secret
GENERIC_CONNSTRING = re.compile(
    r'(?:connection\s*string|connectionstring|connstr)\s*[=:]\s*["\']?'
    r'([^"\'<>\n]+(?:password|pwd)\s*=\s*[^;"\'\n]+)',
    re.IGNORECASE
)

# Direct key=value pairs in connection strings
PASSWORD_IN_CONNSTRING = re.compile(
    r'(?:password|pwd)\s*=\s*([^;"\'\s\n<>]+)',
    re.IGNORECASE
)

USER_IN_CONNSTRING = re.compile(
    r'(?:user\s*id|uid|user|username)\s*=\s*([^;"\'\s\n<>]+)',
    re.IGNORECASE
)

SERVER_IN_CONNSTRING = re.compile(
    r'(?:server|host|data\s*source|hostname)\s*=\s*([^;"\'\s\n<>]+)',
    re.IGNORECASE
)

DATABASE_IN_CONNSTRING = re.compile(
    r'(?:database|initial\s*catalog|dbname)\s*=\s*([^;"\'\s\n<>]+)',
    re.IGNORECASE
)

# .env file patterns
# DB_PASSWORD=secret, DATABASE_URL=postgres://user:pass@host/db
ENV_PASSWORD_PATTERN = re.compile(
    r'^(?:DB_)?(?:PASSWORD|PASSWD|PWD|SECRET|API_KEY|TOKEN|PASS)\s*=\s*["\']?([^"\'#\n]+)',
    re.IGNORECASE | re.MULTILINE
)

ENV_USER_PATTERN = re.compile(
    r'^(?:DB_)?(?:USER|USERNAME|LOGIN)\s*=\s*["\']?([^"\'#\n]+)',
    re.IGNORECASE | re.MULTILINE
)

# Database URL pattern: postgres://user:pass@host:port/database
DATABASE_URL_PATTERN = re.compile(
    r'(?:DATABASE_URL|DB_URL|JDBC_URL|MONGO_URI|REDIS_URL|MYSQL_URL|POSTGRES_URL)\s*=\s*["\']?'
    r'(\w+://[^"\'#\s\n]+)',
    re.IGNORECASE
)

# PHP variable patterns
# $db_password = 'secret'; or define('DB_PASSWORD', 'secret');
PHP_VAR_PATTERN = re.compile(
    r'\$(?:db_?)?(?:password|passwd|pwd|pass)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

PHP_DEFINE_PATTERN = re.compile(
    r'define\s*\(\s*["\'](?:DB_)?(?:PASSWORD|PASSWD|PWD|PASS)["\']'
    r'\s*,\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

PHP_USER_VAR = re.compile(
    r'\$(?:db_?)?(?:user|username|login)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

PHP_DEFINE_USER = re.compile(
    r'define\s*\(\s*["\'](?:DB_)?(?:USER|USERNAME)["\']'
    r'\s*,\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

# ASP.NET XML connection string
# <add name="DefaultConnection" connectionString="Server=...;Password=..." />
XML_CONNSTRING_PATTERN = re.compile(
    r'<add\s+[^>]*connectionString\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

# Provider attribute often present
XML_PROVIDER_PATTERN = re.compile(
    r'<add\s+[^>]*providerName\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)


@PrismParserRegistry.register
class ConnectionStringParser(PrismParser):
    """Parser for database connection strings in config files"""

    @property
    def name(self) -> str:
        return "connstring"

    @property
    def description(self) -> str:
        return "Database connection string parser (web.config, .env, PHP configs)"

    def can_parse(self, filepath: str) -> bool:
        """Detect files containing connection strings by extension or content"""
        if not self.validate_file(filepath):
            return False

        path = Path(filepath)
        filename = path.name.lower()
        ext = path.suffix.lower()

        # Check by filename
        if filename in CONNSTRING_FILENAMES:
            return True

        # Check by extension
        if ext in CONNSTRING_EXTENSIONS:
            return True

        # Content-based detection for unknown files
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(8192)  # Check first 8KB

            # Look for connection string indicators
            indicators = [
                'connectionString=',
                'connectionStrings>',
                'DATABASE_URL=',
                'DB_PASSWORD=',
                'Data Source=',
                'Server=',
                '$db_password',
                "define('DB_PASSWORD",
            ]
            return any(ind.lower() in content.lower() for ind in indicators)

        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse config file for database credentials

        Args:
            filepath: Path to config file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted credentials
        """
        content = self.read_file(filepath)
        path = Path(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='connstring',
            lines_parsed=len(content.splitlines()),
        )

        credentials: List[Credential] = []

        # Parse based on file type
        ext = path.suffix.lower()
        filename = path.name.lower()

        if ext == '.config' or 'config' in filename:
            credentials.extend(self._parse_xml_config(content, filepath))

        if ext == '.php' or filename.endswith('.php'):
            credentials.extend(self._parse_php_config(content, filepath))

        if ext == '.env' or filename.startswith('.env'):
            credentials.extend(self._parse_env_file(content, filepath))

        # Always try generic connection string extraction
        credentials.extend(self._parse_generic_connstring(content, filepath))

        # Always try database URL extraction
        credentials.extend(self._parse_database_urls(content, filepath))

        summary.credentials.extend(credentials)
        # Set user-specified hostname (connstring doesn't have hostname detection)
        self.set_hostname(summary, None, hostname)

        return summary.deduplicate()

    def _parse_xml_config(self, content: str, filepath: str) -> List[Credential]:
        """Parse ASP.NET style XML config files"""
        credentials = []

        # Find all connection strings in XML
        for match in XML_CONNSTRING_PATTERN.finditer(content):
            connstr = match.group(1)
            creds = self._extract_from_connstring(connstr, f"XML config ({filepath})")
            credentials.extend(creds)

        return credentials

    def _parse_php_config(self, content: str, filepath: str) -> List[Credential]:
        """Parse PHP configuration files"""
        credentials = []

        # Extract username first
        username = None
        for pattern in [PHP_USER_VAR, PHP_DEFINE_USER]:
            match = pattern.search(content)
            if match:
                username = match.group(1)
                break

        # Extract passwords
        for pattern in [PHP_VAR_PATTERN, PHP_DEFINE_PATTERN]:
            for match in pattern.finditer(content):
                password = match.group(1)
                if password and not self._is_placeholder(password):
                    credentials.append(Credential(
                        username=username or 'unknown',
                        domain=f"PHP config ({Path(filepath).name})",
                        cred_type=CredentialType.CONNECTION_STRING,
                        value=password,
                    ))

        return credentials

    def _parse_env_file(self, content: str, filepath: str) -> List[Credential]:
        """Parse .env style configuration files"""
        credentials = []

        # Extract username
        username = None
        match = ENV_USER_PATTERN.search(content)
        if match:
            username = match.group(1).strip()

        # Extract passwords
        for match in ENV_PASSWORD_PATTERN.finditer(content):
            password = match.group(1).strip()
            if password and not self._is_placeholder(password):
                credentials.append(Credential(
                    username=username or 'unknown',
                    domain=f".env ({Path(filepath).name})",
                    cred_type=CredentialType.CONNECTION_STRING,
                    value=password,
                ))

        return credentials

    def _parse_database_urls(self, content: str, filepath: str) -> List[Credential]:
        """Parse database URLs like postgres://user:pass@host/db"""
        credentials = []

        for match in DATABASE_URL_PATTERN.finditer(content):
            url = match.group(1)
            cred = self._parse_database_url(url, filepath)
            if cred:
                credentials.append(cred)

        return credentials

    def _parse_database_url(self, url: str, filepath: str) -> Optional[Credential]:
        """Parse a single database URL and extract credentials"""
        try:
            parsed = urlparse(url)

            username = unquote(parsed.username) if parsed.username else None
            password = unquote(parsed.password) if parsed.password else None

            if password and not self._is_placeholder(password):
                # Build server info for domain field
                server_info = f"{parsed.scheme}://{parsed.hostname}"
                if parsed.port:
                    server_info += f":{parsed.port}"
                if parsed.path:
                    server_info += parsed.path

                return Credential(
                    username=username or 'unknown',
                    domain=server_info,
                    cred_type=CredentialType.CONNECTION_STRING,
                    value=password,
                )
        except Exception:
            pass

        return None

    def _parse_generic_connstring(self, content: str, filepath: str) -> List[Credential]:
        """Parse generic key=value connection strings"""
        credentials = []

        # Look for explicit connection string declarations
        for match in GENERIC_CONNSTRING.finditer(content):
            connstr = match.group(1)
            creds = self._extract_from_connstring(connstr, f"connection string ({filepath})")
            credentials.extend(creds)

        return credentials

    def _extract_from_connstring(self, connstr: str, source: str) -> List[Credential]:
        """Extract credentials from a connection string"""
        credentials = []

        # Extract components
        password_match = PASSWORD_IN_CONNSTRING.search(connstr)
        user_match = USER_IN_CONNSTRING.search(connstr)
        server_match = SERVER_IN_CONNSTRING.search(connstr)
        database_match = DATABASE_IN_CONNSTRING.search(connstr)

        if password_match:
            password = password_match.group(1).strip()
            if password and not self._is_placeholder(password):
                username = user_match.group(1).strip() if user_match else 'unknown'

                # Build server/database info for domain field
                domain_parts = []
                if server_match:
                    domain_parts.append(server_match.group(1).strip())
                if database_match:
                    domain_parts.append(database_match.group(1).strip())
                domain = '/'.join(domain_parts) if domain_parts else source

                credentials.append(Credential(
                    username=username,
                    domain=domain,
                    cred_type=CredentialType.CONNECTION_STRING,
                    value=password,
                ))

        return credentials

    def _is_placeholder(self, value: str) -> bool:
        """Check if a value is a placeholder rather than a real credential"""
        if not value:
            return True

        value_lower = value.lower().strip()

        # Common placeholders
        placeholders = [
            'your_password', 'yourpassword', 'your-password',
            'password', 'passwd', 'pass', 'pwd',
            'changeme', 'change_me', 'change-me',
            'secret', 'yoursecret', 'your_secret',
            'xxx', 'xxxx', '****', '...', '???',
            'enter_password', 'enter-password', 'enterpassword',
            'replace_me', 'replace-me', 'replaceme',
            'todo', 'fixme', 'placeholder',
            '${', '{{', '%{', '$(', '<password>',
        ]

        # Check exact matches and starts
        for ph in placeholders:
            if value_lower == ph or value_lower.startswith(ph):
                return True

        # Check for environment variable references
        if re.match(r'^\$\{?\w+\}?$', value):
            return True

        # Check for template placeholders
        if re.match(r'^\{\{.*\}\}$', value):
            return True

        return False
