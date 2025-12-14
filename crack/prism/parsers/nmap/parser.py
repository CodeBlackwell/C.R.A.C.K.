"""
Nmap Parser

Main parser for nmap human-readable output (.nmap files).
"""

import logging
import re
from typing import Optional

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import NmapScanSummary
from . import patterns
from .host_parser import HostParser

logger = logging.getLogger(__name__)


@PrismParserRegistry.register
class NmapParser(PrismParser):
    """Parser for nmap human-readable output (.nmap files)"""

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Nmap scan output parser (.nmap human-readable format)"

    def can_parse(self, filepath: str) -> bool:
        """Detect nmap output by signature patterns"""
        if not self.validate_file(filepath):
            return False

        try:
            # Read first 8KB for detection
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(8192)

            # Primary checks - nmap header or footer
            has_header = bool(patterns.NMAP_HEADER.search(content))
            has_footer = bool(patterns.NMAP_FOOTER.search(content))
            has_report = bool(patterns.SCAN_REPORT.search(content))

            # Secondary - port table structure
            has_port_table = bool(patterns.PORT_TABLE_HEADER.search(content))
            has_port_entry = bool(re.search(r'\d+/tcp\s+open', content))

            # File extension hint
            has_nmap_extension = filepath.lower().endswith('.nmap')

            # Accept if:
            # - Has nmap header OR footer
            # - AND (has port data OR has .nmap extension OR has scan report)
            primary = has_header or has_footer
            secondary = has_port_table or has_port_entry or has_nmap_extension or has_report

            return primary and secondary

        except Exception as e:
            logger.debug(f"Error checking file {filepath}: {e}")
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> NmapScanSummary:
        """Parse nmap output and return structured summary"""
        content = self.read_file(filepath)
        lines = content.splitlines()

        summary = NmapScanSummary(
            source_file=filepath,
            source_tool='nmap',
            lines_parsed=len(lines),
        )

        # Extract scan metadata from header/footer
        self._parse_metadata(content, summary)

        # Parse hosts using state machine parser
        host_parser = HostParser()
        summary.hosts = host_parser.parse(lines)

        logger.info(f"Parsed {filepath}: {len(summary.hosts_up)} hosts up, "
                   f"{summary.stats['total_open_ports']} open ports")

        return summary

    def _parse_metadata(self, content: str, summary: NmapScanSummary):
        """Extract scan metadata from file content"""
        # Parse command line from header
        cmd_match = patterns.SCAN_COMMAND.search(content)
        if cmd_match:
            summary.nmap_version = cmd_match.group(1)
            summary.scan_start = patterns.parse_datetime(cmd_match.group(2))
            summary.nmap_command = cmd_match.group(3)

            # Extract target spec from command
            command = cmd_match.group(3)
            # Target is typically last argument(s)
            parts = command.split()
            if parts:
                # Find args that look like IPs or ranges
                for part in reversed(parts):
                    if re.match(r'^\d+\.', part) or '-' in part and '.' in part:
                        summary.target_spec = part
                        break

        # Parse completion from footer
        complete_match = patterns.SCAN_COMPLETE.search(content)
        if complete_match:
            summary.scan_end = patterns.parse_datetime(complete_match.group(1))
            summary.scan_duration = float(complete_match.group(4))

        # If no header, try just footer for version
        if not summary.nmap_version:
            header_match = patterns.NMAP_HEADER.search(content)
            if header_match:
                summary.nmap_version = header_match.group(1)
