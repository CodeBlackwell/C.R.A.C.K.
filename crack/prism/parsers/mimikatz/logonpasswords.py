"""
Parser for sekurlsa::logonpasswords output

State machine approach for parsing credential sections.
"""

from typing import List, Optional, Tuple
from datetime import datetime
from enum import Enum, auto

from ...models import Credential, CredentialType, LogonSession
from .patterns import PATTERNS, is_hex_blob, is_null_value, clean_value


class ParseState(Enum):
    """State machine states for parsing"""
    IDLE = auto()
    IN_SESSION = auto()
    IN_MSV = auto()
    IN_WDIGEST = auto()
    IN_KERBEROS = auto()
    IN_CREDMAN = auto()
    IN_SSP = auto()
    IN_TSPKG = auto()


class LogonPasswordsParser:
    """Parser for sekurlsa::logonpasswords output"""

    def __init__(self):
        self.sessions: List[LogonSession] = []
        self.current_session: Optional[LogonSession] = None
        self.current_provider: Optional[str] = None
        self.state = ParseState.IDLE

        # Temp storage for credential being built
        self._cred_username: Optional[str] = None
        self._cred_domain: Optional[str] = None
        self._cred_password: Optional[str] = None
        self._cred_ntlm: Optional[str] = None
        self._cred_sha1: Optional[str] = None

    def parse(self, lines: List[str]) -> List[LogonSession]:
        """Parse logonpasswords output lines

        Args:
            lines: List of output lines

        Returns:
            List of parsed LogonSession objects
        """
        self.sessions = []
        self.current_session = None
        self.state = ParseState.IDLE

        for line_num, line in enumerate(lines):
            self._process_line(line, line_num)

        # Close final session
        if self.current_session:
            self._close_current_provider()
            self.sessions.append(self.current_session)

        return self.sessions

    def _process_line(self, line: str, line_num: int) -> None:
        """Process a single line through state machine"""

        # Check for new session header
        match = PATTERNS['session_header_simple'].search(line)
        if match:
            self._start_new_session(match, line_num)
            return

        # In IDLE state, look for session metadata
        if self.state == ParseState.IDLE:
            return

        # Check for provider transitions
        if PATTERNS['provider_msv'].match(line):
            self._switch_provider(ParseState.IN_MSV)
            return
        if PATTERNS['provider_wdigest'].match(line):
            self._switch_provider(ParseState.IN_WDIGEST)
            return
        if PATTERNS['provider_kerberos'].match(line):
            self._switch_provider(ParseState.IN_KERBEROS)
            return
        if PATTERNS['provider_credman'].match(line):
            self._switch_provider(ParseState.IN_CREDMAN)
            return
        if PATTERNS['provider_ssp'].match(line):
            self._switch_provider(ParseState.IN_SSP)
            return
        if PATTERNS['provider_tspkg'].match(line):
            self._switch_provider(ParseState.IN_TSPKG)
            return

        # Parse session metadata
        if self.state == ParseState.IN_SESSION:
            self._parse_session_metadata(line)
            return

        # Parse credential data based on provider
        if self.state in (ParseState.IN_MSV, ParseState.IN_WDIGEST,
                          ParseState.IN_KERBEROS, ParseState.IN_TSPKG,
                          ParseState.IN_CREDMAN):
            self._parse_credential_line(line, line_num)

    def _start_new_session(self, match, line_num: int) -> None:
        """Start parsing a new session"""
        # Close previous session if exists
        if self.current_session:
            self._close_current_provider()
            self.sessions.append(self.current_session)

        auth_high = int(match.group(1))
        auth_low = int(match.group(2))

        self.current_session = LogonSession(
            auth_id_high=auth_high,
            auth_id_low=auth_low,
            session_type="Unknown",
            username="",
            domain="",
        )
        self.state = ParseState.IN_SESSION
        self._reset_cred_temp()

    def _parse_session_metadata(self, line: str) -> None:
        """Parse session header metadata"""
        if not self.current_session:
            return

        # Session type
        match = PATTERNS['session_type'].search(line)
        if match:
            self.current_session.session_type = clean_value(match.group(1))
            return

        # Username
        match = PATTERNS['user_name'].search(line)
        if match:
            self.current_session.username = clean_value(match.group(1))
            return

        # Domain
        match = PATTERNS['domain'].search(line)
        if match:
            self.current_session.domain = clean_value(match.group(1))
            return

        # Logon server
        match = PATTERNS['logon_server'].search(line)
        if match:
            self.current_session.logon_server = clean_value(match.group(1))
            return

        # Logon time
        match = PATTERNS['logon_time'].search(line)
        if match:
            try:
                time_str = clean_value(match.group(1))
                # Try common formats
                for fmt in ('%m/%d/%Y %I:%M:%S %p', '%Y-%m-%d %H:%M:%S',
                            '%d/%m/%Y %H:%M:%S'):
                    try:
                        self.current_session.logon_time = datetime.strptime(time_str, fmt)
                        break
                    except ValueError:
                        continue
            except Exception:
                pass
            return

        # SID
        match = PATTERNS['sid'].search(line)
        if match:
            self.current_session.sid = match.group(1)
            return

    def _switch_provider(self, new_state: ParseState) -> None:
        """Switch to new credential provider section"""
        self._close_current_provider()
        self.state = new_state
        self._reset_cred_temp()

    def _close_current_provider(self) -> None:
        """Close current provider and save any pending credential"""
        if self.current_session and self._has_credential_data():
            self._save_current_credential()

    def _reset_cred_temp(self) -> None:
        """Reset temporary credential storage"""
        self._cred_username = None
        self._cred_domain = None
        self._cred_password = None
        self._cred_ntlm = None
        self._cred_sha1 = None

    def _has_credential_data(self) -> bool:
        """Check if we have any credential data to save"""
        return bool(
            self._cred_ntlm or
            self._cred_sha1 or
            (self._cred_password and not is_null_value(self._cred_password))
        )

    def _parse_credential_line(self, line: str, line_num: int) -> None:
        """Parse credential data line"""
        # Username
        match = PATTERNS['cred_username'].search(line)
        if match:
            val = clean_value(match.group(1))
            if not is_null_value(val):
                self._cred_username = val
            return

        # Domain
        match = PATTERNS['cred_domain'].search(line)
        if match:
            val = clean_value(match.group(1))
            if not is_null_value(val):
                self._cred_domain = val
            return

        # Password (cleartext or hex blob)
        match = PATTERNS['cred_password'].search(line)
        if match:
            val = clean_value(match.group(1))
            if not is_null_value(val):
                self._cred_password = val
            return

        # NTLM hash
        match = PATTERNS['cred_ntlm'].search(line)
        if match:
            self._cred_ntlm = match.group(1).lower()
            return

        # SHA1 hash
        match = PATTERNS['cred_sha1'].search(line)
        if match:
            self._cred_sha1 = match.group(1).lower()
            return

        # Check for credential block delimiter (Primary, CredentialKeys, etc.)
        if line.strip().startswith('[') and self._has_credential_data():
            self._save_current_credential()
            self._reset_cred_temp()

    def _save_current_credential(self) -> None:
        """Save accumulated credential data to current session"""
        if not self.current_session:
            return

        # Determine username/domain - use cred-specific if available,
        # otherwise fall back to session
        username = self._cred_username or self.current_session.username
        domain = self._cred_domain or self.current_session.domain

        if not username:
            return

        # Save NTLM hash
        if self._cred_ntlm:
            cred = Credential(
                username=username,
                domain=domain,
                cred_type=CredentialType.NTLM,
                value=self._cred_ntlm,
                sid=self.current_session.sid,
                logon_server=self.current_session.logon_server,
            )
            self.current_session.add_credential(cred)

        # Save SHA1 hash
        if self._cred_sha1:
            cred = Credential(
                username=username,
                domain=domain,
                cred_type=CredentialType.SHA1,
                value=self._cred_sha1,
                sid=self.current_session.sid,
                logon_server=self.current_session.logon_server,
            )
            self.current_session.add_credential(cred)

        # Save password (cleartext or hex blob)
        if self._cred_password and not is_null_value(self._cred_password):
            if is_hex_blob(self._cred_password):
                cred_type = CredentialType.MACHINE_HEX
            else:
                cred_type = CredentialType.CLEARTEXT

            cred = Credential(
                username=username,
                domain=domain,
                cred_type=cred_type,
                value=self._cred_password,
                sid=self.current_session.sid,
                logon_server=self.current_session.logon_server,
            )
            self.current_session.add_credential(cred)
