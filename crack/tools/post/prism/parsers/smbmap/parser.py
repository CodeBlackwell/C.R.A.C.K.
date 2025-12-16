"""
SMBMap Parser

Main parser for smbmap share enumeration output.
"""

import logging
from enum import Enum, auto
from typing import Optional, List

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models.smbmap_scan import (
    SmbmapSummary, SmbShare, SmbEntry,
    SmbPermission, SmbEntryType
)
from . import patterns

logger = logging.getLogger(__name__)


class ParseState(Enum):
    """Parser state machine states"""
    IDLE = auto()
    IN_HEADER = auto()
    IN_SHARE_TABLE = auto()
    IN_DIR_LISTING = auto()


@PrismParserRegistry.register
class SmbmapParser(PrismParser):
    """Parser for smbmap share enumeration output"""

    @property
    def name(self) -> str:
        return "smbmap"

    @property
    def description(self) -> str:
        return "SMBMap share enumeration parser"

    def can_parse(self, filepath: str) -> bool:
        """Detect smbmap output by signature patterns"""
        if not self.validate_file(filepath):
            return False

        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(8192)

            # Primary check - SMBMap banner
            has_banner = bool(patterns.SMBMAP_BANNER.search(content))

            # Secondary checks
            has_ip_status = bool(patterns.IP_STATUS.search(content))
            has_share_table = bool(patterns.SHARE_TABLE_HEADER.search(content))
            has_share_entry = bool(patterns.SHARE_ENTRY.search(content))

            # Accept if:
            # - Has SMBMap banner
            # - OR has IP status line with share table/entries
            return has_banner or (has_ip_status and (has_share_table or has_share_entry))

        except Exception as e:
            logger.debug(f"Error checking file {filepath}: {e}")
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> SmbmapSummary:
        """Parse smbmap output and return structured summary"""
        content = self.read_file(filepath)
        lines = content.splitlines()

        summary = SmbmapSummary(
            source_file=filepath,
            source_tool='smbmap',
            lines_parsed=len(lines),
        )

        # Extract target info from IP status line
        self._parse_target_info(content, summary)

        # Parse shares using state machine
        self._parse_shares(lines, summary)

        # Extract any warnings/errors
        self._parse_warnings(content, summary)

        # Set hostname from parameter or parsed value
        if hostname:
            summary.target_hostname = hostname

        logger.info(f"Parsed {filepath}: {len(summary.shares)} shares, "
                   f"{len(summary.readable_shares)} readable")

        return summary

    def _parse_target_info(self, content: str, summary: SmbmapSummary):
        """Extract target IP, port, hostname, auth status"""
        # Try primary IP status pattern
        match = patterns.IP_STATUS.search(content)
        if match:
            ip, port, name, status = match.groups()
            summary.target_ip = ip
            summary.target_port = int(port) if port else 445
            summary.target_hostname = name if name != ip else ""
            summary.auth_status = status or ""
            return

        # Try alternative pattern
        alt_match = patterns.ALT_IP_HEADER.search(content)
        if alt_match:
            summary.target_ip = alt_match.group(1)

        # Try to extract username/domain from command line in output
        user_match = patterns.USERNAME_PATTERN.search(content)
        if user_match:
            summary.username = user_match.group(1)

        domain_match = patterns.DOMAIN_PATTERN.search(content)
        if domain_match:
            summary.domain = domain_match.group(1)

    def _parse_shares(self, lines: List[str], summary: SmbmapSummary):
        """Parse share table and directory listings using state machine"""
        state = ParseState.IDLE
        current_share: Optional[SmbShare] = None
        current_path: str = ""

        for line in lines:
            stripped = line.strip()

            # Skip empty lines in IDLE state
            if not stripped and state == ParseState.IDLE:
                continue

            # State transitions
            if patterns.SHARE_TABLE_HEADER.match(stripped):
                state = ParseState.IN_SHARE_TABLE
                continue

            if patterns.SHARE_SEPARATOR.match(stripped):
                continue  # Skip separator lines

            # In share table
            if state in (ParseState.IDLE, ParseState.IN_SHARE_TABLE):
                share_match = patterns.SHARE_ENTRY.match(line)
                if not share_match:
                    share_match = patterns.SHARE_ENTRY_ALT.match(stripped)

                if share_match:
                    state = ParseState.IN_SHARE_TABLE
                    name, perm_str, comment = share_match.groups()
                    share = SmbShare(
                        name=name.strip(),
                        permission=SmbPermission.from_string(perm_str),
                        comment=comment.strip() if comment else "",
                    )
                    summary.shares.append(share)
                    continue

            # Directory context line: ./ShareName or ./ShareName/subdir
            if patterns.is_dir_context_line(stripped):
                ctx_match = patterns.DIR_CONTEXT.match(stripped)
                if ctx_match:
                    current_path = ctx_match.group(1)
                    # Find or create share from path
                    share_name = current_path.split('/')[0]
                    current_share = summary.get_share_by_name(share_name)
                    state = ParseState.IN_DIR_LISTING
                continue

            # In directory listing
            if state == ParseState.IN_DIR_LISTING:
                # Check for directory entry
                entry_match = patterns.DIR_ENTRY.match(stripped)
                if not entry_match:
                    entry_match = patterns.DIR_ENTRY_ALT.match(stripped)

                if entry_match and current_share:
                    perms, size, date_str, name = entry_match.groups()
                    name = name.strip()

                    # Skip . and .. entries
                    if name in ('.', '..'):
                        continue

                    # Determine type from permissions
                    entry_type = SmbEntryType.DIRECTORY if perms.startswith('d') else SmbEntryType.FILE

                    entry = SmbEntry(
                        name=name,
                        entry_type=entry_type,
                        size=int(size),
                        permissions=perms,
                        date=patterns.parse_datetime(date_str),
                        path=current_path,
                    )
                    current_share.entries.append(entry)
                    continue

                # Back to share table if we see a share entry
                if patterns.is_share_table_line(line):
                    state = ParseState.IN_SHARE_TABLE
                    share_match = patterns.SHARE_ENTRY.match(line)
                    if not share_match:
                        share_match = patterns.SHARE_ENTRY_ALT.match(stripped)
                    if share_match:
                        name, perm_str, comment = share_match.groups()
                        share = SmbShare(
                            name=name.strip(),
                            permission=SmbPermission.from_string(perm_str),
                            comment=comment.strip() if comment else "",
                        )
                        summary.shares.append(share)
                    continue

    def _parse_warnings(self, content: str, summary: SmbmapSummary):
        """Extract warnings and errors"""
        for match in patterns.ERROR_PATTERN.finditer(content):
            msg = match.group(1)
            # Skip common non-error messages
            if 'Checking for open ports' not in msg:
                summary.warnings.append(f"ERROR: {msg}")

        for match in patterns.WARNING_PATTERN.finditer(content):
            summary.warnings.append(f"WARNING: {match.group(1)}")
