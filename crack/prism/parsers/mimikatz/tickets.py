"""
Parser for sekurlsa::tickets output

Extracts Kerberos TGT and TGS tickets.
"""

from typing import List, Optional
from datetime import datetime
from enum import Enum, auto

from ...models import KerberosTicket
from .patterns import PATTERNS, clean_value


class TicketParseState(Enum):
    """State machine states for ticket parsing"""
    IDLE = auto()
    IN_SESSION = auto()
    IN_GROUP = auto()
    IN_TICKET = auto()


class TicketsParser:
    """Parser for sekurlsa::tickets output"""

    def __init__(self):
        self.tickets: List[KerberosTicket] = []
        self.state = TicketParseState.IDLE

        # Current parsing context
        self._current_group: int = 0
        self._current_group_name: str = ""
        self._current_ticket: Optional[dict] = None

    def parse(self, lines: List[str]) -> List[KerberosTicket]:
        """Parse tickets output lines

        Args:
            lines: List of output lines

        Returns:
            List of parsed KerberosTicket objects
        """
        self.tickets = []
        self.state = TicketParseState.IDLE
        self._current_ticket = None

        for line_num, line in enumerate(lines):
            self._process_line(line, line_num)

        # Save final ticket if any
        self._save_current_ticket()

        return self.tickets

    def _process_line(self, line: str, line_num: int) -> None:
        """Process a single line through state machine"""

        # Check for group header (Group 0, Group 1, Group 2)
        match = PATTERNS['ticket_group'].search(line)
        if match:
            self._save_current_ticket()
            self._current_group = int(match.group(1))
            self._current_group_name = clean_value(match.group(2))
            self.state = TicketParseState.IN_GROUP
            return

        # Check for ticket index [00000000], [00000001], etc.
        match = PATTERNS['ticket_index'].search(line)
        if match and self.state in (TicketParseState.IN_GROUP, TicketParseState.IN_TICKET):
            self._save_current_ticket()
            self._start_new_ticket()
            return

        # In IDLE state, nothing to parse
        if self.state == TicketParseState.IDLE:
            return

        # Parse ticket data
        if self.state == TicketParseState.IN_TICKET and self._current_ticket:
            self._parse_ticket_line(line)

    def _start_new_ticket(self) -> None:
        """Start parsing a new ticket"""
        self._current_ticket = {
            'group_type': self._current_group,
            'service_type': '',
            'service_target': '',
            'service_realm': '',
            'client_name': '',
            'client_realm': '',
            'start_time': None,
            'end_time': None,
            'max_renew_time': None,
            'flags': '',
            'flags_hex': '',
            'session_key_type': '',
            'session_key_value': '',
            'ticket_encryption': '',
            'kvno': None,
            'saved_path': None,
        }
        self.state = TicketParseState.IN_TICKET

    def _parse_ticket_line(self, line: str) -> None:
        """Parse a ticket data line"""
        if not self._current_ticket:
            return

        # Start/End/MaxRenew times
        match = PATTERNS['ticket_start_end_renew'].search(line)
        if match:
            self._current_ticket['start_time'] = self._parse_time(match.group(1))
            self._current_ticket['end_time'] = self._parse_time(match.group(2))
            self._current_ticket['max_renew_time'] = self._parse_time(match.group(3))
            return

        # Service Name (full format with realm)
        match = PATTERNS['ticket_service_name'].search(line)
        if match:
            self._current_ticket['service_type'] = clean_value(match.group(1))
            self._current_ticket['service_target'] = clean_value(match.group(2))
            self._current_ticket['service_realm'] = clean_value(match.group(3))
            return

        # Service Name (simple format)
        if 'Service Name' in line and not self._current_ticket['service_type']:
            match = PATTERNS['ticket_service_simple'].search(line)
            if match:
                parts = match.group(1).split(';')
                if parts:
                    self._current_ticket['service_type'] = clean_value(parts[0])
                    if len(parts) > 1:
                        self._current_ticket['service_target'] = clean_value(parts[1])
                return

        # Client Name
        match = PATTERNS['ticket_client_name'].search(line)
        if match:
            client = clean_value(match.group(1))
            realm = clean_value(match.group(2))
            # Handle delegation tickets: "SECURE$ ; @ SECURA.YZX ( $Delegation Ticket$ )"
            if '(' in client:
                client = client.split('(')[0].strip()
            if '(' in realm:
                realm = realm.split('(')[0].strip()
            self._current_ticket['client_name'] = client
            self._current_ticket['client_realm'] = realm
            return

        # Flags
        match = PATTERNS['ticket_flags'].search(line)
        if match:
            self._current_ticket['flags_hex'] = match.group(1)
            self._current_ticket['flags'] = clean_value(match.group(2))
            return

        # Session Key type
        match = PATTERNS['ticket_session_key'].search(line)
        if match:
            self._current_ticket['session_key_type'] = f"{match.group(1)}-{match.group(2)}"
            return

        # Session Key value (64 hex chars on next line)
        match = PATTERNS['ticket_session_key_value'].search(line)
        if match and not self._current_ticket['session_key_value']:
            self._current_ticket['session_key_value'] = match.group(1)
            return

        # Ticket encryption type
        match = PATTERNS['ticket_encryption'].search(line)
        if match:
            self._current_ticket['ticket_encryption'] = f"{match.group(1)}-{match.group(2)}"
            self._current_ticket['kvno'] = int(match.group(3))
            return

        # Saved to file
        match = PATTERNS['ticket_saved'].search(line)
        if match:
            self._current_ticket['saved_path'] = clean_value(match.group(1))
            return

    def _save_current_ticket(self) -> None:
        """Save current ticket to list"""
        if not self._current_ticket:
            return

        # Only save if we have meaningful data
        if not self._current_ticket['service_type'] and not self._current_ticket['client_name']:
            self._current_ticket = None
            return

        ticket = KerberosTicket(
            service_type=self._current_ticket['service_type'],
            service_target=self._current_ticket['service_target'],
            service_realm=self._current_ticket['service_realm'],
            client_name=self._current_ticket['client_name'],
            client_realm=self._current_ticket['client_realm'],
            start_time=self._current_ticket['start_time'],
            end_time=self._current_ticket['end_time'],
            max_renew_time=self._current_ticket['max_renew_time'],
            flags=self._current_ticket['flags'],
            flags_hex=self._current_ticket['flags_hex'],
            session_key_type=self._current_ticket['session_key_type'],
            session_key_value=self._current_ticket['session_key_value'],
            ticket_encryption=self._current_ticket['ticket_encryption'],
            kvno=self._current_ticket['kvno'],
            saved_path=self._current_ticket['saved_path'],
            group_type=self._current_ticket['group_type'],
        )

        self.tickets.append(ticket)
        self._current_ticket = None

    def _parse_time(self, time_str: str) -> Optional[datetime]:
        """Parse time string to datetime"""
        if not time_str:
            return None

        time_str = clean_value(time_str)
        if not time_str:
            return None

        # Try common formats
        formats = [
            '%m/%d/%Y %I:%M:%S %p',    # 12/12/2025 8:35:07 PM
            '%m/%d/%Y %H:%M:%S',        # 12/12/2025 20:35:07
            '%Y-%m-%d %H:%M:%S',        # 2025-12-12 20:35:07
            '%d/%m/%Y %H:%M:%S',        # 12/12/2025 20:35:07
        ]

        for fmt in formats:
            try:
                return datetime.strptime(time_str, fmt)
            except ValueError:
                continue

        return None
