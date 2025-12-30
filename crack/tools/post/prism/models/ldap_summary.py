"""
LDAP Summary Model

Aggregated results from parsing ldapsearch output.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

from .ldap_entry import LdapUser, LdapComputer, LdapGroup, LdapDomainInfo


@dataclass
class LdapSummary:
    """Aggregated results from parsing ldapsearch output"""

    # Source information
    source_file: str
    source_tool: str = "ldapsearch"
    parse_time: datetime = field(default_factory=datetime.now)

    # Domain info
    domain_info: Optional[LdapDomainInfo] = None

    # Extracted objects
    users: List[LdapUser] = field(default_factory=list)
    computers: List[LdapComputer] = field(default_factory=list)
    groups: List[LdapGroup] = field(default_factory=list)

    # Raw entries that didn't fit other categories
    other_entries: int = 0

    # Parse stats
    lines_parsed: int = 0
    total_entries: int = 0

    @property
    def kerberoastable_users(self) -> List[LdapUser]:
        """Users with SPNs (Kerberoastable)"""
        return [u for u in self.users if u.is_kerberoastable and not u.is_disabled]

    @property
    def asrep_roastable_users(self) -> List[LdapUser]:
        """Users with DONT_REQ_PREAUTH (AS-REP roastable)"""
        return [u for u in self.users if u.dont_require_preauth and not u.is_disabled]

    @property
    def users_with_descriptions(self) -> List[LdapUser]:
        """Users with descriptions (potential password hints)"""
        return [u for u in self.users if u.description and not u.is_machine_account]

    @property
    def admin_users(self) -> List[LdapUser]:
        """Users with adminCount=1"""
        return [u for u in self.users if u.admin_count and not u.is_machine_account]

    @property
    def delegation_users(self) -> List[LdapUser]:
        """Users trusted for delegation"""
        return [u for u in self.users if u.trusted_for_delegation and not u.is_machine_account]

    @property
    def disabled_users(self) -> List[LdapUser]:
        """Disabled user accounts"""
        return [u for u in self.users if u.is_disabled and not u.is_machine_account]

    @property
    def enabled_users(self) -> List[LdapUser]:
        """Enabled non-machine users"""
        return [u for u in self.users if not u.is_disabled and not u.is_machine_account]

    @property
    def domain_controllers(self) -> List[LdapComputer]:
        """Domain controller computer accounts"""
        return [c for c in self.computers if c.is_domain_controller]

    @property
    def delegation_computers(self) -> List[LdapComputer]:
        """Computers trusted for delegation (potential relay targets)"""
        return [c for c in self.computers if c.trusted_for_delegation]

    @property
    def high_value_groups(self) -> List[LdapGroup]:
        """Sensitive/admin groups"""
        return [g for g in self.groups if g.is_high_value]

    @property
    def high_value_targets(self) -> List[LdapUser]:
        """All high-value user targets"""
        return [u for u in self.users if u.high_value and not u.is_machine_account]

    @property
    def domain_name(self) -> str:
        """Domain name from domain_info or first DC"""
        if self.domain_info:
            return self.domain_info.dns_name or self.domain_info.domain_name
        return ""

    @property
    def stats(self) -> Dict[str, int]:
        """Quick statistics summary"""
        return {
            'total_entries': self.total_entries,
            'users': len(self.users),
            'enabled_users': len(self.enabled_users),
            'disabled_users': len(self.disabled_users),
            'computers': len(self.computers),
            'groups': len(self.groups),
            'kerberoastable': len(self.kerberoastable_users),
            'asrep_roastable': len(self.asrep_roastable_users),
            'with_descriptions': len(self.users_with_descriptions),
            'admin_users': len(self.admin_users),
            'delegation_users': len(self.delegation_users),
            'domain_controllers': len(self.domain_controllers),
            'high_value_groups': len(self.high_value_groups),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            'source_file': self.source_file,
            'source_tool': self.source_tool,
            'parse_time': self.parse_time.isoformat(),
            'domain': self.domain_info.to_dict() if self.domain_info else None,
            'stats': self.stats,
            'users': [u.to_dict() for u in self.users],
            'computers': [c.to_dict() for c in self.computers],
            'groups': [g.to_dict() for g in self.groups],
        }

    def __repr__(self) -> str:
        return (f"<LdapSummary domain={self.domain_name} "
                f"users={len(self.users)} computers={len(self.computers)} "
                f"groups={len(self.groups)}>")
