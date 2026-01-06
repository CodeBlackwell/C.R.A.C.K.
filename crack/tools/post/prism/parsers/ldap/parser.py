"""
LDAP Parser

Parses ldapsearch LDIF output for Active Directory enumeration.

Extracts:
- Domain information (password policy, functional level)
- Users (especially Kerberoastable, AS-REP roastable, with descriptions)
- Computers (domain controllers, delegation targets)
- Groups (high-value groups, memberships)

Usage:
    crack prism ldap_dump.txt
    ldapsearch -x -H ldap://10.10.10.175 -b "DC=DOMAIN,DC=LOCAL" > ldap.txt
    crack prism ldap.txt
"""

import base64
import logging
import re
from typing import Optional, List, Dict, Tuple, Any

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import LdapSummary, PartialEntry
from ...models.ldap_entry import (
    LdapEntry, LdapUser, LdapComputer, LdapGroup, LdapDomainInfo
)
from . import patterns

logger = logging.getLogger(__name__)


@PrismParserRegistry.register
class LdapParser(PrismParser):
    """Parser for ldapsearch LDIF output"""

    @property
    def name(self) -> str:
        return "ldap"

    @property
    def description(self) -> str:
        return "LDAP/ldapsearch LDIF output parser (AD enumeration)"

    def can_parse(self, filepath: str) -> bool:
        """Detect ldapsearch LDIF output by signature patterns"""
        if not self.validate_file(filepath):
            return False

        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(8192)

            # Check for LDIF signatures
            has_ldif_header = bool(patterns.LDIF_HEADER.search(content))
            has_ldap_version = bool(patterns.LDIF_VERSION.search(content))
            has_base = bool(patterns.LDIF_BASE.search(content))
            has_dn = bool(patterns.DN_LINE.search(content))
            has_dc = bool(patterns.DC_PATTERN.search(content))

            # Need either LDIF header or multiple LDAP indicators
            if has_ldif_header:
                return True

            # Fallback: looks like raw LDIF
            ldap_indicators = sum([
                has_ldap_version,
                has_base,
                has_dn,
                has_dc,
            ])
            return ldap_indicators >= 2

        except Exception as e:
            logger.debug(f"LDAP detection failed: {e}")
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> LdapSummary:
        """Parse LDIF file and return structured summary

        Args:
            filepath: Path to LDIF file
            hostname: Optional source hostname (unused, extracted from content)

        Returns:
            LdapSummary with extracted objects
        """
        content = self.read_file(filepath)
        lines = content.splitlines()

        summary = LdapSummary(
            source_file=filepath,
            source_tool="ldapsearch",
            lines_parsed=len(lines),
        )

        # Parse entries from LDIF
        entries = self._parse_ldif_entries(content)
        summary.total_entries = len(entries)

        # Classify and process each entry
        for entry in entries:
            obj = self._classify_entry(entry)
            if obj is None:
                # No objectClass - create partial entry from DN
                dn_list = entry.get('dn', [])
                if dn_list:
                    partial = PartialEntry(dn=dn_list[0])
                    # Only keep user/computer hints, skip containers
                    if partial.entry_type in ('user_hint', 'computer_hint'):
                        summary.partial_entries.append(partial)
                    else:
                        summary.other_entries += 1
                else:
                    summary.other_entries += 1
            elif isinstance(obj, LdapDomainInfo):
                summary.domain_info = obj
            elif isinstance(obj, LdapUser):
                summary.users.append(obj)
            elif isinstance(obj, LdapComputer):
                summary.computers.append(obj)
            elif isinstance(obj, LdapGroup):
                summary.groups.append(obj)
            else:
                summary.other_entries += 1

        return summary

    def _parse_ldif_entries(self, content: str) -> List[Dict[str, Any]]:
        """Parse LDIF content into list of entry dictionaries

        LDIF format:
        - Entries separated by blank lines
        - Each entry starts with dn: line
        - Continuation lines start with single space
        - Base64 values use :: instead of :
        - Comments start with #
        """
        entries = []
        current_entry: Dict[str, Any] = {}
        current_attr: Optional[str] = None
        current_value: str = ""
        is_base64: bool = False

        def save_attribute():
            """Save current attribute to entry"""
            nonlocal current_attr, current_value, is_base64
            if current_attr:
                # Decode base64 if needed
                if is_base64:
                    try:
                        current_value = base64.b64decode(current_value).decode('utf-8', errors='replace')
                    except Exception:
                        pass  # Keep raw value if decode fails

                # Store as list (attributes can have multiple values)
                attr_lower = current_attr.lower()
                if attr_lower not in current_entry:
                    current_entry[attr_lower] = []
                current_entry[attr_lower].append(current_value.strip())

            current_attr = None
            current_value = ""
            is_base64 = False

        def save_entry():
            """Save current entry to list"""
            nonlocal current_entry
            save_attribute()
            if current_entry and 'dn' in current_entry:
                entries.append(current_entry)
            current_entry = {}

        for line in content.splitlines():
            # Skip comments
            if line.startswith('#'):
                continue

            # Blank line = end of entry
            if not line.strip():
                save_entry()
                continue

            # Continuation line (starts with space)
            if line.startswith(' ') and current_attr:
                current_value += line[1:]  # Remove leading space
                continue

            # New attribute line
            save_attribute()

            # Check for base64 encoded value (::)
            if '::' in line:
                match = re.match(r'^([a-zA-Z][a-zA-Z0-9-]*)::[ ]*(.*)$', line)
                if match:
                    current_attr = match.group(1)
                    current_value = match.group(2)
                    is_base64 = True
                    continue

            # Regular attribute line (:)
            if ':' in line:
                match = re.match(r'^([a-zA-Z][a-zA-Z0-9-]*):[ ]*(.*)$', line)
                if match:
                    current_attr = match.group(1)
                    current_value = match.group(2)
                    is_base64 = False
                    continue

        # Save last entry
        save_entry()

        return entries

    def _classify_entry(self, entry: Dict[str, Any]) -> Optional[Any]:
        """Classify an LDIF entry into appropriate model

        Args:
            entry: Dictionary of attributes

        Returns:
            LdapUser, LdapComputer, LdapGroup, LdapDomainInfo, or None
        """
        object_classes = set(
            oc.lower() for oc in entry.get('objectclass', [])
        )

        # Get DN
        dn_list = entry.get('dn', [])
        dn = dn_list[0] if dn_list else ""

        if not dn:
            return None

        # Check if this is the domain root entry
        if object_classes & patterns.OBJECT_CLASS_DOMAIN:
            return self._parse_domain_entry(entry, dn)

        # Check for computer (before user, as computers are also 'user' class)
        if object_classes & patterns.OBJECT_CLASS_COMPUTER:
            return self._parse_computer_entry(entry, dn, object_classes)

        # Check for user/person
        if object_classes & patterns.OBJECT_CLASS_USER:
            return self._parse_user_entry(entry, dn, object_classes)

        # Check for group
        if object_classes & patterns.OBJECT_CLASS_GROUP:
            return self._parse_group_entry(entry, dn, object_classes)

        # Unknown entry type
        return None

    def _parse_domain_entry(self, entry: Dict[str, Any], dn: str) -> LdapDomainInfo:
        """Parse domain root entry for policy information"""
        domain_info = LdapDomainInfo(
            domain_dn=dn,
        )

        # Extract domain name from DN components
        dc_parts = patterns.DC_PATTERN.findall(dn)
        if dc_parts:
            domain_info.domain_name = dc_parts[0]
            domain_info.dns_name = '.'.join(dc_parts)

        # Password policy
        domain_info.min_pwd_length = self._get_int(entry, 'minpwdlength', 0)
        domain_info.pwd_history_length = self._get_int(entry, 'pwdhistorylength', 0)
        domain_info.lockout_threshold = self._get_int(entry, 'lockoutthreshold', 0)
        domain_info.lockout_duration = self._get_int(entry, 'lockoutduration', 0)
        domain_info.lockout_observation_window = self._get_int(entry, 'lockoutobservationwindow', 0)
        domain_info.max_pwd_age = self._get_int(entry, 'maxpwdage', 0)
        domain_info.min_pwd_age = self._get_int(entry, 'minpwdage', 0)
        domain_info.pwd_properties = self._get_int(entry, 'pwdproperties', 0)

        # Domain functional level
        domain_info.functional_level = self._get_int(entry, 'msds-behavior-version', 0)

        # Machine account quota
        domain_info.machine_account_quota = self._get_int(entry, 'ms-ds-machineaccountquota', 10)

        # FSMO role owner
        fsmo = entry.get('fsmoroleowner', [])
        if fsmo:
            domain_info.fsmo_role_owner = fsmo[0]

        return domain_info

    def _parse_user_entry(
        self,
        entry: Dict[str, Any],
        dn: str,
        object_classes: set
    ) -> LdapUser:
        """Parse user/person entry"""
        user = LdapUser(
            dn=dn,
            object_class=list(object_classes),
            attributes=entry,
        )
        return user

    def _parse_computer_entry(
        self,
        entry: Dict[str, Any],
        dn: str,
        object_classes: set
    ) -> LdapComputer:
        """Parse computer entry"""
        computer = LdapComputer(
            dn=dn,
            object_class=list(object_classes),
            attributes=entry,
        )
        return computer

    def _parse_group_entry(
        self,
        entry: Dict[str, Any],
        dn: str,
        object_classes: set
    ) -> LdapGroup:
        """Parse group entry"""
        group = LdapGroup(
            dn=dn,
            object_class=list(object_classes),
            attributes=entry,
        )
        return group

    def _get_int(self, entry: Dict, key: str, default: int = 0) -> int:
        """Get integer value from entry"""
        values = entry.get(key, [])
        if values:
            try:
                return int(values[0])
            except (ValueError, TypeError):
                pass
        return default
