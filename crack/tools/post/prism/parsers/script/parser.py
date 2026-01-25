"""
Generic Script Credential Parser (AGGRESSIVE)

Finds hardcoded credentials in scripts and configuration files.

Supported formats:
- PowerShell: $password = "xxx", $cred = "xxx", -Password "xxx"
- Bash: password="xxx", PASS=xxx, export SECRET=xxx
- Python: password = "xxx", api_key = "xxx"
- YAML: password: xxx, secret: xxx
- Generic: pwd=, passwd=, secret=, api_key=, token=

This parser is intentionally aggressive to catch credentials that might
be missed by more specific parsers. It may produce false positives.
"""

import re
from typing import Optional, List, Tuple
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models.credential import Credential, CredentialType
from ...models.summary import ParsedSummary


# File extensions for scripts
SCRIPT_EXTENSIONS = frozenset([
    '.ps1', '.psm1', '.psd1',  # PowerShell
    '.sh', '.bash', '.zsh', '.ksh',  # Shell
    '.py', '.pyw',  # Python
    '.yml', '.yaml',  # YAML
    '.bat', '.cmd',  # Windows batch
    '.rb',  # Ruby
    '.pl', '.pm',  # Perl
    '.js', '.ts',  # JavaScript/TypeScript
    '.vbs', '.vba',  # VBScript
])

# Keywords that indicate a credential variable
CREDENTIAL_KEYWORDS = [
    'password', 'passwd', 'pwd', 'pass',
    'secret', 'api_key', 'apikey', 'api-key',
    'token', 'auth_token', 'authtoken', 'access_token',
    'credential', 'cred', 'credentials',
    'private_key', 'privatekey', 'priv_key',
    'secret_key', 'secretkey',
    'auth', 'authentication',
    'key', 'api',  # Only when combined with value patterns
]

# PowerShell patterns
# $password = "secret"
# $cred = "secret"
# -Password "secret"
# -Credential "secret"
# [SecureString] patterns
PS_VAR_PATTERN = re.compile(
    r'\$(?:' + '|'.join(CREDENTIAL_KEYWORDS[:10]) + r')\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

PS_PARAM_PATTERN = re.compile(
    r'-(?:Password|Credential|Secret|Token|ApiKey)\s+["\']?([^"\'\s\n\r;]+)',
    re.IGNORECASE
)

PS_CONVERTTO_PATTERN = re.compile(
    r'ConvertTo-SecureString\s+["\']([^"\']+)["\']',
    re.IGNORECASE
)

# PSCredential with plaintext
PS_PSCREDENTIAL_PATTERN = re.compile(
    r'PSCredential\s*\(\s*["\']([^"\']+)["\']\s*,\s*'
    r'(?:\(ConvertTo-SecureString\s+)?["\']([^"\']+)["\']',
    re.IGNORECASE
)

# Bash/Shell patterns
# password="secret"
# PASS=secret
# export SECRET=xxx
BASH_VAR_PATTERN = re.compile(
    r'^(?:export\s+)?(?:' + '|'.join(CREDENTIAL_KEYWORDS[:8]) + r')\s*=\s*["\']?([^"\'#\s\n]+)',
    re.IGNORECASE | re.MULTILINE
)

# Bash here-doc with password
BASH_HEREDOC_PASSWORD = re.compile(
    r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']?([^"\'#\s\n]+)',
    re.IGNORECASE
)

# Python patterns
# password = "secret"
# api_key = "xxx"
# config["password"] = "xxx"
# config['password'] = 'xxx'
PYTHON_VAR_PATTERN = re.compile(
    r'(?:' + '|'.join(CREDENTIAL_KEYWORDS[:10]) + r')\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

PYTHON_DICT_PATTERN = re.compile(
    r'\[["\'](?:' + '|'.join(CREDENTIAL_KEYWORDS[:10]) + r')["\']\]\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

# YAML patterns
# password: secret
# secret: xxx
# api_key: xxx
YAML_PATTERN = re.compile(
    r'^[\s-]*(?:' + '|'.join(CREDENTIAL_KEYWORDS[:12]) + r')\s*:\s*["\']?([^"\'#\n]+)',
    re.IGNORECASE | re.MULTILINE
)

# Generic patterns (catch-all)
# pwd=xxx
# passwd=xxx
# secret=xxx
GENERIC_EQUALS_PATTERN = re.compile(
    r'(?:' + '|'.join(CREDENTIAL_KEYWORDS[:10]) + r')\s*=\s*["\']?([^"\'<>=\s\n;,\)]+)',
    re.IGNORECASE
)

# Quoted string after credential keyword
GENERIC_QUOTED_PATTERN = re.compile(
    r'(?:' + '|'.join(CREDENTIAL_KEYWORDS[:10]) + r')\s*[:=]\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)

# Windows batch patterns
# SET PASSWORD=xxx
BATCH_SET_PATTERN = re.compile(
    r'^SET\s+(?:' + '|'.join(CREDENTIAL_KEYWORDS[:8]) + r')\s*=\s*(.+)$',
    re.IGNORECASE | re.MULTILINE
)


@PrismParserRegistry.register
class ScriptParser(PrismParser):
    """Aggressive parser for hardcoded credentials in scripts"""

    @property
    def name(self) -> str:
        return "script"

    @property
    def description(self) -> str:
        return "Hardcoded credential finder (PowerShell, Bash, Python, YAML, batch)"

    def can_parse(self, filepath: str) -> bool:
        """Detect script files by extension"""
        if not self.validate_file(filepath):
            return False

        path = Path(filepath)
        ext = path.suffix.lower()

        # Check by extension
        if ext in SCRIPT_EXTENSIONS:
            return True

        # Check for shebang in unknown files
        try:
            with open(filepath, 'r', errors='ignore') as f:
                first_line = f.readline(256)

            # Shebang detection
            if first_line.startswith('#!'):
                shebangs = ['python', 'bash', 'sh', 'ruby', 'perl', 'node', 'zsh']
                return any(s in first_line.lower() for s in shebangs)

        except Exception:
            pass

        return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse script file for hardcoded credentials

        Args:
            filepath: Path to script file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted credentials
        """
        content = self.read_file(filepath)
        path = Path(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='script',
            lines_parsed=len(content.splitlines()),
        )

        credentials: List[Credential] = []

        # Detect script type and apply appropriate parsers
        ext = path.suffix.lower()

        if ext in ('.ps1', '.psm1', '.psd1'):
            credentials.extend(self._parse_powershell(content, filepath))

        if ext in ('.sh', '.bash', '.zsh', '.ksh') or self._has_shell_shebang(content):
            credentials.extend(self._parse_shell(content, filepath))

        if ext in ('.py', '.pyw'):
            credentials.extend(self._parse_python(content, filepath))

        if ext in ('.yml', '.yaml'):
            credentials.extend(self._parse_yaml(content, filepath))

        if ext in ('.bat', '.cmd'):
            credentials.extend(self._parse_batch(content, filepath))

        # Always apply generic patterns (catch stragglers)
        credentials.extend(self._parse_generic(content, filepath))

        summary.credentials.extend(credentials)
        # Set user-specified hostname (script doesn't have hostname detection)
        self.set_hostname(summary, None, hostname)

        return summary.deduplicate()

    def _has_shell_shebang(self, content: str) -> bool:
        """Check if file has a shell shebang"""
        first_line = content.split('\n', 1)[0] if content else ''
        if first_line.startswith('#!'):
            return any(s in first_line.lower() for s in ['bash', '/sh', 'zsh', 'ksh'])
        return False

    def _parse_powershell(self, content: str, filepath: str) -> List[Credential]:
        """Parse PowerShell scripts for credentials"""
        credentials = []

        # Variable assignments
        for match in PS_VAR_PATTERN.finditer(content):
            value = match.group(1)
            if self._is_valid_credential(value):
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"PowerShell variable ({filepath})"
                ))

        # Parameter values (-Password "xxx")
        for match in PS_PARAM_PATTERN.finditer(content):
            value = match.group(1)
            if self._is_valid_credential(value):
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"PowerShell parameter ({filepath})"
                ))

        # ConvertTo-SecureString (plaintext to secure)
        for match in PS_CONVERTTO_PATTERN.finditer(content):
            value = match.group(1)
            if self._is_valid_credential(value):
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"PowerShell SecureString ({filepath})"
                ))

        # PSCredential objects with both user and password
        for match in PS_PSCREDENTIAL_PATTERN.finditer(content):
            username = match.group(1)
            password = match.group(2)
            if self._is_valid_credential(password):
                # Parse domain from DOMAIN\user or user@domain format
                domain, user = self._parse_domain_user(username)
                credentials.append(Credential(
                    username=user,
                    domain=domain,
                    cred_type=CredentialType.CLEARTEXT,
                    value=password,
                    session_type=f"PSCredential ({Path(filepath).name})",
                ))

        return credentials

    def _parse_shell(self, content: str, filepath: str) -> List[Credential]:
        """Parse Bash/Shell scripts for credentials"""
        credentials = []

        # Environment variable assignments
        for match in BASH_VAR_PATTERN.finditer(content):
            value = match.group(1)
            if self._is_valid_credential(value):
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"Shell variable ({filepath})"
                ))

        # Password patterns in heredocs or config sections
        for match in BASH_HEREDOC_PASSWORD.finditer(content):
            value = match.group(1)
            if self._is_valid_credential(value):
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"Shell script ({filepath})"
                ))

        return credentials

    def _parse_python(self, content: str, filepath: str) -> List[Credential]:
        """Parse Python scripts for credentials"""
        credentials = []

        # Variable assignments
        for match in PYTHON_VAR_PATTERN.finditer(content):
            value = match.group(1)
            if self._is_valid_credential(value):
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"Python variable ({filepath})"
                ))

        # Dictionary assignments
        for match in PYTHON_DICT_PATTERN.finditer(content):
            value = match.group(1)
            if self._is_valid_credential(value):
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"Python dict ({filepath})"
                ))

        return credentials

    def _parse_yaml(self, content: str, filepath: str) -> List[Credential]:
        """Parse YAML files for credentials"""
        credentials = []

        for match in YAML_PATTERN.finditer(content):
            value = match.group(1).strip()
            if self._is_valid_credential(value):
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"YAML ({filepath})"
                ))

        return credentials

    def _parse_batch(self, content: str, filepath: str) -> List[Credential]:
        """Parse Windows batch files for credentials"""
        credentials = []

        for match in BATCH_SET_PATTERN.finditer(content):
            value = match.group(1).strip()
            if self._is_valid_credential(value):
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"Batch SET ({filepath})"
                ))

        return credentials

    def _parse_generic(self, content: str, filepath: str) -> List[Credential]:
        """Apply generic patterns to catch remaining credentials"""
        credentials = []
        seen_values = set()  # Avoid duplicates from multiple patterns

        # Quoted pattern first (more specific)
        for match in GENERIC_QUOTED_PATTERN.finditer(content):
            value = match.group(1)
            if value not in seen_values and self._is_valid_credential(value):
                seen_values.add(value)
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"Script ({filepath})"
                ))

        # Equals pattern (less specific, may catch more noise)
        for match in GENERIC_EQUALS_PATTERN.finditer(content):
            value = match.group(1)
            if value not in seen_values and self._is_valid_credential(value):
                seen_values.add(value)
                context = self._extract_context(content, match.start())
                credentials.append(self._create_credential(
                    value=value,
                    context=context,
                    source=f"Script ({filepath})"
                ))

        return credentials

    def _extract_context(self, content: str, position: int) -> str:
        """Extract surrounding context for a match"""
        # Find line containing the match
        line_start = content.rfind('\n', 0, position) + 1
        line_end = content.find('\n', position)
        if line_end == -1:
            line_end = len(content)

        line = content[line_start:line_end].strip()

        # Truncate if too long
        if len(line) > 100:
            # Try to find the variable name
            match_start = position - line_start
            context_start = max(0, match_start - 30)
            context_end = min(len(line), match_start + 50)
            line = '...' + line[context_start:context_end] + '...'

        return line

    def _create_credential(self, value: str, context: str, source: str) -> Credential:
        """Create a credential with context as username"""
        # Try to extract variable name from context
        var_name = self._extract_variable_name(context)

        return Credential(
            username=var_name or 'hardcoded',
            domain='',  # Domain field is for actual AD domains
            cred_type=CredentialType.CLEARTEXT,
            value=value,
            session_type=source,  # Use session_type for source tracking
        )

    def _parse_domain_user(self, username: str) -> Tuple[str, str]:
        """Parse domain and username from DOMAIN\\user or user@domain format

        Returns:
            Tuple of (domain, username)
        """
        # Handle DOMAIN\user format
        if '\\' in username:
            parts = username.split('\\', 1)
            return (parts[0].upper(), parts[1])

        # Handle user@domain format
        if '@' in username:
            parts = username.split('@', 1)
            return (parts[1].upper(), parts[0])

        # No domain
        return ('', username)

    def _extract_variable_name(self, context: str) -> Optional[str]:
        """Extract variable name from context line"""
        # PowerShell: $varname =
        match = re.search(r'\$(\w+)\s*=', context)
        if match:
            return match.group(1)

        # Bash: VARNAME=
        match = re.search(r'^(?:export\s+)?(\w+)\s*=', context)
        if match:
            return match.group(1)

        # Python: varname =
        match = re.search(r'^(\w+)\s*=', context.strip())
        if match:
            return match.group(1)

        # YAML: key:
        match = re.search(r'^[\s-]*(\w+)\s*:', context)
        if match:
            return match.group(1)

        return None

    def _is_valid_credential(self, value: str) -> bool:
        """Check if a value looks like a real credential"""
        if not value or len(value) < 3:
            return False

        value = value.strip()
        value_lower = value.lower()

        # Common placeholders to exclude
        placeholders = [
            'your_password', 'yourpassword', 'your-password',
            'password', 'passwd', 'pass', 'pwd', 'secret',
            'changeme', 'change_me', 'change-me',
            'xxx', 'xxxx', 'xxxxxxxx', '****', '...', '???',
            'enter_password', 'enter-password', 'enterpassword',
            'replace_me', 'replace-me', 'replaceme',
            'todo', 'fixme', 'placeholder', 'example',
            'none', 'null', 'undefined', 'empty', 'blank',
            'test', 'testing', 'demo', 'sample',
            'your_api_key', 'your_secret', 'your_token',
            'insert_here', 'insert-here', 'inserthere',
        ]

        # Exact match placeholders
        if value_lower in placeholders:
            return False

        # Starts with placeholder
        for ph in placeholders[:15]:
            if value_lower.startswith(ph):
                return False

        # Environment variable references
        if re.match(r'^\$\{?\w+\}?$', value):
            return False
        if re.match(r'^\$\(\w+\)$', value):
            return False
        if re.match(r'^%\w+%$', value):
            return False

        # Template placeholders
        if re.match(r'^\{\{.*\}\}$', value):
            return False
        if re.match(r'^<.*>$', value):
            return False

        # Only special characters or whitespace
        if re.match(r'^[\s\W]+$', value):
            return False

        # Looks like a file path
        if value.startswith('/') and '/' in value[1:]:
            return False
        if re.match(r'^[A-Z]:\\', value):
            return False

        # Looks like a URL without credentials
        if re.match(r'^https?://[^:@]+$', value):
            return False

        # Common false positives
        false_positives = [
            'true', 'false', 'yes', 'no', 'on', 'off',
            'enabled', 'disabled', 'active', 'inactive',
        ]
        if value_lower in false_positives:
            return False

        return True
