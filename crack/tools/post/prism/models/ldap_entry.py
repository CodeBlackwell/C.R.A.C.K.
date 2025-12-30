"""
LDAP Entry Models

Structured representations for parsed ldapsearch output.
Key focus areas for pentesting:
- Users with service principal names (Kerberoasting)
- Users with DONT_REQ_PREAUTH (AS-REP roasting)
- Descriptions containing password hints
- Admin accounts (adminCount=1)
- Password policy settings
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set
from enum import IntFlag
import base64
import re


class UserAccountControl(IntFlag):
    """Active Directory userAccountControl flags

    Reference: https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
    """
    SCRIPT = 0x0001
    ACCOUNTDISABLE = 0x0002
    HOMEDIR_REQUIRED = 0x0008
    LOCKOUT = 0x0010
    PASSWD_NOTREQD = 0x0020
    PASSWD_CANT_CHANGE = 0x0040
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080
    TEMP_DUPLICATE_ACCOUNT = 0x0100
    NORMAL_ACCOUNT = 0x0200
    INTERDOMAIN_TRUST_ACCOUNT = 0x0800
    WORKSTATION_TRUST_ACCOUNT = 0x1000
    SERVER_TRUST_ACCOUNT = 0x2000
    DONT_EXPIRE_PASSWORD = 0x10000
    MNS_LOGON_ACCOUNT = 0x20000
    SMARTCARD_REQUIRED = 0x40000
    TRUSTED_FOR_DELEGATION = 0x80000
    NOT_DELEGATED = 0x100000
    USE_DES_KEY_ONLY = 0x200000
    DONT_REQ_PREAUTH = 0x400000  # AS-REP roastable!
    PASSWORD_EXPIRED = 0x800000
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000
    PARTIAL_SECRETS_ACCOUNT = 0x04000000


@dataclass
class LdapEntry:
    """Base class for all LDAP entries"""

    dn: str
    object_class: List[str] = field(default_factory=list)
    attributes: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def cn(self) -> Optional[str]:
        """Extract CN from distinguished name"""
        match = re.match(r'CN=([^,]+)', self.dn, re.IGNORECASE)
        return match.group(1) if match else None

    @property
    def ou_path(self) -> str:
        """Extract OU path from DN"""
        parts = self.dn.split(',')
        ous = [p for p in parts if p.upper().startswith('OU=')]
        return ','.join(ous)

    def get_attr(self, name: str) -> Optional[str]:
        """Get first value of an attribute (case-insensitive)"""
        values = self.attributes.get(name.lower(), [])
        return values[0] if values else None

    def get_attrs(self, name: str) -> List[str]:
        """Get all values of an attribute (case-insensitive)"""
        return self.attributes.get(name.lower(), [])

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            'dn': self.dn,
            'cn': self.cn,
            'object_class': self.object_class,
            'attributes': self.attributes,
        }


@dataclass
class LdapUser(LdapEntry):
    """Active Directory user account"""

    @property
    def sam_account_name(self) -> str:
        return self.get_attr('sAMAccountName') or ''

    @property
    def display_name(self) -> str:
        return self.get_attr('displayName') or self.get_attr('name') or self.cn or ''

    @property
    def user_principal_name(self) -> Optional[str]:
        return self.get_attr('userPrincipalName')

    @property
    def description(self) -> Optional[str]:
        """Descriptions often contain password hints!"""
        return self.get_attr('description')

    @property
    def member_of(self) -> List[str]:
        return self.get_attrs('memberOf')

    @property
    def service_principal_names(self) -> List[str]:
        """SPNs make this account Kerberoastable"""
        return self.get_attrs('servicePrincipalName')

    @property
    def is_kerberoastable(self) -> bool:
        """Has SPNs and is not a machine account"""
        return bool(self.service_principal_names) and not self.is_machine_account

    @property
    def user_account_control(self) -> int:
        """Raw UAC value"""
        uac = self.get_attr('userAccountControl')
        return int(uac) if uac else 0

    @property
    def uac_flags(self) -> Set[str]:
        """Parse UAC flags into readable set"""
        uac = self.user_account_control
        flags = set()
        for flag in UserAccountControl:
            if uac & flag:
                flags.add(flag.name)
        return flags

    @property
    def is_disabled(self) -> bool:
        return bool(self.user_account_control & UserAccountControl.ACCOUNTDISABLE)

    @property
    def is_locked(self) -> bool:
        return bool(self.user_account_control & UserAccountControl.LOCKOUT)

    @property
    def dont_require_preauth(self) -> bool:
        """AS-REP roastable!"""
        return bool(self.user_account_control & UserAccountControl.DONT_REQ_PREAUTH)

    @property
    def password_never_expires(self) -> bool:
        return bool(self.user_account_control & UserAccountControl.DONT_EXPIRE_PASSWORD)

    @property
    def trusted_for_delegation(self) -> bool:
        return bool(self.user_account_control & UserAccountControl.TRUSTED_FOR_DELEGATION)

    @property
    def is_machine_account(self) -> bool:
        return self.sam_account_name.endswith('$')

    @property
    def admin_count(self) -> bool:
        """adminCount=1 means user is/was in a protected group"""
        val = self.get_attr('adminCount')
        return val == '1' if val else False

    @property
    def when_created(self) -> Optional[str]:
        return self.get_attr('whenCreated')

    @property
    def last_logon(self) -> Optional[str]:
        return self.get_attr('lastLogon')

    @property
    def pwd_last_set(self) -> Optional[str]:
        return self.get_attr('pwdLastSet')

    @property
    def high_value(self) -> bool:
        """Is this a high-value target?"""
        return (
            self.is_kerberoastable or
            self.dont_require_preauth or
            self.admin_count or
            self.trusted_for_delegation or
            bool(self.description)  # Descriptions may contain password hints
        )

    @property
    def attack_paths(self) -> List[str]:
        """List applicable attack paths"""
        paths = []
        if self.is_kerberoastable:
            paths.append('Kerberoast')
        if self.dont_require_preauth:
            paths.append('AS-REP Roast')
        if self.description:
            paths.append('Description (password hint?)')
        if self.trusted_for_delegation:
            paths.append('Delegation Abuse')
        return paths

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            'sAMAccountName': self.sam_account_name,
            'displayName': self.display_name,
            'userPrincipalName': self.user_principal_name,
            'description': self.description,
            'memberOf': self.member_of,
            'servicePrincipalNames': self.service_principal_names,
            'userAccountControl': self.user_account_control,
            'uacFlags': list(self.uac_flags),
            'isDisabled': self.is_disabled,
            'isKerberoastable': self.is_kerberoastable,
            'dontRequirePreauth': self.dont_require_preauth,
            'adminCount': self.admin_count,
            'highValue': self.high_value,
            'attackPaths': self.attack_paths,
        })
        return base


@dataclass
class LdapComputer(LdapEntry):
    """Active Directory computer account"""

    @property
    def sam_account_name(self) -> str:
        return self.get_attr('sAMAccountName') or ''

    @property
    def dns_hostname(self) -> Optional[str]:
        return self.get_attr('dNSHostName')

    @property
    def operating_system(self) -> Optional[str]:
        return self.get_attr('operatingSystem')

    @property
    def os_version(self) -> Optional[str]:
        return self.get_attr('operatingSystemVersion')

    @property
    def os_service_pack(self) -> Optional[str]:
        return self.get_attr('operatingSystemServicePack')

    @property
    def os_display(self) -> str:
        """Formatted OS string"""
        parts = [self.operating_system or 'Unknown']
        if self.os_version:
            parts.append(self.os_version)
        if self.os_service_pack:
            parts.append(self.os_service_pack)
        return ' '.join(parts)

    @property
    def service_principal_names(self) -> List[str]:
        return self.get_attrs('servicePrincipalName')

    @property
    def user_account_control(self) -> int:
        uac = self.get_attr('userAccountControl')
        return int(uac) if uac else 0

    @property
    def trusted_for_delegation(self) -> bool:
        return bool(self.user_account_control & UserAccountControl.TRUSTED_FOR_DELEGATION)

    @property
    def is_domain_controller(self) -> bool:
        """Check if this is a DC"""
        return bool(self.user_account_control & UserAccountControl.SERVER_TRUST_ACCOUNT)

    @property
    def is_windows(self) -> bool:
        os = (self.operating_system or '').lower()
        return 'windows' in os

    @property
    def is_server(self) -> bool:
        os = (self.operating_system or '').lower()
        return 'server' in os

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            'sAMAccountName': self.sam_account_name,
            'dnsHostname': self.dns_hostname,
            'operatingSystem': self.operating_system,
            'osVersion': self.os_version,
            'osDisplay': self.os_display,
            'servicePrincipalNames': self.service_principal_names,
            'trustedForDelegation': self.trusted_for_delegation,
            'isDomainController': self.is_domain_controller,
        })
        return base


@dataclass
class LdapGroup(LdapEntry):
    """Active Directory group"""

    @property
    def sam_account_name(self) -> str:
        return self.get_attr('sAMAccountName') or ''

    @property
    def description(self) -> Optional[str]:
        return self.get_attr('description')

    @property
    def members(self) -> List[str]:
        return self.get_attrs('member')

    @property
    def member_of(self) -> List[str]:
        return self.get_attrs('memberOf')

    @property
    def admin_count(self) -> bool:
        val = self.get_attr('adminCount')
        return val == '1' if val else False

    @property
    def is_high_value(self) -> bool:
        """Check if this is a sensitive group"""
        name = self.sam_account_name.lower()
        high_value_groups = {
            'domain admins', 'enterprise admins', 'schema admins',
            'administrators', 'backup operators', 'account operators',
            'server operators', 'print operators', 'dnsadmins',
            'group policy creator owners', 'remote desktop users',
        }
        return name in high_value_groups or self.admin_count

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            'sAMAccountName': self.sam_account_name,
            'description': self.description,
            'members': self.members,
            'memberOf': self.member_of,
            'adminCount': self.admin_count,
            'isHighValue': self.is_high_value,
        })
        return base


@dataclass
class LdapDomainInfo:
    """Domain-level information extracted from LDAP"""

    # Domain identification
    domain_dn: str = ""
    domain_name: str = ""  # EGOTISTICAL-BANK
    dns_name: str = ""     # EGOTISTICAL-BANK.LOCAL

    # Domain controllers
    fsmo_role_owner: str = ""

    # Password policy
    min_pwd_length: int = 0
    pwd_history_length: int = 0
    lockout_threshold: int = 0
    lockout_duration: int = 0  # In 100-nanosecond intervals (negative = relative)
    lockout_observation_window: int = 0
    max_pwd_age: int = 0
    min_pwd_age: int = 0
    pwd_properties: int = 0

    # Domain functional level
    functional_level: int = 0

    # Machine account quota
    machine_account_quota: int = 10

    @property
    def functional_level_name(self) -> str:
        """Map functional level to Windows version"""
        levels = {
            0: 'Windows 2000',
            1: 'Windows 2003 Interim',
            2: 'Windows 2003',
            3: 'Windows 2008',
            4: 'Windows 2008 R2',
            5: 'Windows 2012',
            6: 'Windows 2012 R2',
            7: 'Windows 2016',
        }
        return levels.get(self.functional_level, f'Unknown ({self.functional_level})')

    @property
    def pwd_complexity_required(self) -> bool:
        """Check if password complexity is required (bit 1 of pwdProperties)"""
        return bool(self.pwd_properties & 1)

    @property
    def lockout_duration_minutes(self) -> int:
        """Convert lockout duration to minutes"""
        if self.lockout_duration == 0:
            return 0  # Forever (until admin unlocks)
        # Negative value in 100-nanosecond intervals
        return abs(self.lockout_duration) // 600000000

    @property
    def max_pwd_age_days(self) -> int:
        """Convert max password age to days"""
        if self.max_pwd_age == 0:
            return 0  # Never expires
        return abs(self.max_pwd_age) // 864000000000

    @property
    def is_weak_policy(self) -> bool:
        """Check for weak password policy indicators"""
        return (
            self.min_pwd_length < 8 or
            self.lockout_threshold == 0 or  # No lockout
            self.lockout_threshold > 10 or  # Very high threshold
            not self.pwd_complexity_required
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            'domainDn': self.domain_dn,
            'domainName': self.domain_name,
            'dnsName': self.dns_name,
            'fsmoRoleOwner': self.fsmo_role_owner,
            'functionalLevel': self.functional_level,
            'functionalLevelName': self.functional_level_name,
            'passwordPolicy': {
                'minPwdLength': self.min_pwd_length,
                'pwdHistoryLength': self.pwd_history_length,
                'lockoutThreshold': self.lockout_threshold,
                'lockoutDurationMinutes': self.lockout_duration_minutes,
                'maxPwdAgeDays': self.max_pwd_age_days,
                'complexityRequired': self.pwd_complexity_required,
                'isWeakPolicy': self.is_weak_policy,
            },
            'machineAccountQuota': self.machine_account_quota,
        }
