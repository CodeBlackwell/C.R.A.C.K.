"""
SMBMap Scan Summary Model

Aggregated results from parsing smbmap output.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from enum import Enum


class SmbPermission(Enum):
    """SMB share permission levels"""
    NO_ACCESS = "NO ACCESS"
    READ_ONLY = "READ ONLY"
    READ_WRITE = "READ, WRITE"
    WRITE_ONLY = "WRITE ONLY"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, s: str) -> 'SmbPermission':
        """Parse permission from smbmap output string"""
        s = s.strip().upper()
        if s == "NO ACCESS":
            return cls.NO_ACCESS
        elif s == "READ ONLY":
            return cls.READ_ONLY
        elif s in ("READ, WRITE", "READ/WRITE", "READ WRITE"):
            return cls.READ_WRITE
        elif s == "WRITE ONLY":
            return cls.WRITE_ONLY
        return cls.UNKNOWN


class SmbEntryType(Enum):
    """SMB directory entry types"""
    FILE = "file"
    DIRECTORY = "directory"
    UNKNOWN = "unknown"


@dataclass
class SmbEntry:
    """Represents a file or directory entry in an SMB share"""
    name: str
    entry_type: SmbEntryType
    size: int = 0
    permissions: str = ""  # drwxrwxrwx style
    date: Optional[datetime] = None
    path: str = ""  # Full path within share

    @property
    def is_directory(self) -> bool:
        return self.entry_type == SmbEntryType.DIRECTORY

    @property
    def is_file(self) -> bool:
        return self.entry_type == SmbEntryType.FILE

    @property
    def extension(self) -> str:
        """Get file extension (lowercase)"""
        if '.' in self.name:
            return self.name.rsplit('.', 1)[-1].lower()
        return ""

    @property
    def full_path(self) -> str:
        """Get full path including filename"""
        if self.path:
            return f"{self.path}/{self.name}"
        return self.name

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.entry_type.value,
            'size': self.size,
            'permissions': self.permissions,
            'date': self.date.isoformat() if self.date else None,
            'path': self.path,
            'full_path': self.full_path,
        }


@dataclass
class SmbShare:
    """Represents an SMB share"""
    name: str
    permission: SmbPermission
    comment: str = ""
    entries: List[SmbEntry] = field(default_factory=list)

    @property
    def is_readable(self) -> bool:
        return self.permission in (SmbPermission.READ_ONLY, SmbPermission.READ_WRITE)

    @property
    def is_writable(self) -> bool:
        return self.permission in (SmbPermission.WRITE_ONLY, SmbPermission.READ_WRITE)

    @property
    def is_default_share(self) -> bool:
        """Check if this is a Windows default admin share"""
        return self.name.upper() in ('ADMIN$', 'C$', 'D$', 'E$', 'IPC$', 'PRINT$')

    @property
    def files(self) -> List[SmbEntry]:
        return [e for e in self.entries if e.is_file]

    @property
    def directories(self) -> List[SmbEntry]:
        return [e for e in self.entries if e.is_directory]

    @property
    def total_size(self) -> int:
        return sum(e.size for e in self.files)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'permission': self.permission.value,
            'comment': self.comment,
            'is_readable': self.is_readable,
            'is_writable': self.is_writable,
            'is_default_share': self.is_default_share,
            'entry_count': len(self.entries),
            'file_count': len(self.files),
            'directory_count': len(self.directories),
            'entries': [e.to_dict() for e in self.entries],
        }


# High-value file patterns for pentesting
HIGH_VALUE_FILES: Set[str] = {
    # GPP credentials
    'groups.xml', 'services.xml', 'scheduledtasks.xml',
    'datasources.xml', 'printers.xml', 'drives.xml',
    # Config files with potential credentials
    'web.config', 'applicationhost.config', 'machine.config',
    'connections.config', 'appsettings.json', 'appsettings.config',
    # Database files
    'ntds.dit', 'sam', 'system', 'security',
    # Scripts with potential creds
    'unattend.xml', 'unattended.xml', 'sysprep.xml', 'sysprep.inf',
    # SSH keys
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
    # Other sensitive
    '.htpasswd', '.htaccess', 'shadow', 'passwd',
    'credentials.xml', 'creds.txt', 'passwords.txt',
    'flag.txt', 'root.txt', 'user.txt',
}

HIGH_VALUE_EXTENSIONS: Set[str] = {
    'kdbx', 'kdb',     # KeePass
    'pfx', 'p12',      # Certificates
    'pem', 'key',      # Private keys
    'ppk',             # PuTTY keys
    'rdp',             # RDP connection files
    'vmdk', 'vhdx',    # Virtual disks
    'bak', 'old',      # Backup files
}


@dataclass
class SmbmapSummary:
    """Aggregated results from parsing smbmap output"""

    # Source information
    source_file: str
    source_tool: str = "smbmap"
    parse_time: datetime = field(default_factory=datetime.now)

    # Target info
    target_ip: str = ""
    target_port: int = 445
    target_hostname: str = ""

    # Authentication status
    auth_status: str = ""  # Authenticated, Guest, etc.
    username: str = ""
    domain: str = ""

    # Shares
    shares: List[SmbShare] = field(default_factory=list)

    # Statistics
    lines_parsed: int = 0

    # Warnings/errors
    warnings: List[str] = field(default_factory=list)

    @property
    def readable_shares(self) -> List[SmbShare]:
        """Shares we can read from"""
        return [s for s in self.shares if s.is_readable]

    @property
    def writable_shares(self) -> List[SmbShare]:
        """Shares we can write to"""
        return [s for s in self.shares if s.is_writable]

    @property
    def non_default_shares(self) -> List[SmbShare]:
        """Non-default shares (often more interesting)"""
        return [s for s in self.shares if not s.is_default_share]

    @property
    def accessible_shares(self) -> List[SmbShare]:
        """Any shares we have some access to"""
        return [s for s in self.shares
                if s.permission != SmbPermission.NO_ACCESS]

    @property
    def all_entries(self) -> List[SmbEntry]:
        """All entries across all shares"""
        entries = []
        for share in self.shares:
            entries.extend(share.entries)
        return entries

    @property
    def all_files(self) -> List[SmbEntry]:
        """All files across all shares"""
        return [e for e in self.all_entries if e.is_file]

    @property
    def high_value_files(self) -> List[SmbEntry]:
        """Files that are potentially high-value for pentesting"""
        results = []
        for entry in self.all_files:
            name_lower = entry.name.lower()
            # Check exact filename match
            if name_lower in HIGH_VALUE_FILES:
                results.append(entry)
                continue
            # Check extension
            if entry.extension in HIGH_VALUE_EXTENSIONS:
                results.append(entry)
                continue
        return results

    @property
    def stats(self) -> Dict[str, int]:
        """Quick statistics summary"""
        return {
            'total_shares': len(self.shares),
            'readable_shares': len(self.readable_shares),
            'writable_shares': len(self.writable_shares),
            'non_default_shares': len(self.non_default_shares),
            'total_entries': len(self.all_entries),
            'total_files': len(self.all_files),
            'high_value_files': len(self.high_value_files),
        }

    def get_share_by_name(self, name: str) -> Optional[SmbShare]:
        """Get share by name (case-insensitive)"""
        name_lower = name.lower()
        for share in self.shares:
            if share.name.lower() == name_lower:
                return share
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source_file': self.source_file,
            'source_tool': self.source_tool,
            'parse_time': self.parse_time.isoformat(),
            'target_ip': self.target_ip,
            'target_port': self.target_port,
            'target_hostname': self.target_hostname,
            'auth_status': self.auth_status,
            'username': self.username,
            'domain': self.domain,
            'stats': self.stats,
            'shares': [s.to_dict() for s in self.shares],
            'high_value_files': [f.to_dict() for f in self.high_value_files],
            'warnings': self.warnings,
        }

    def to_json(self) -> str:
        """Serialize to JSON string"""
        import json
        return json.dumps(self.to_dict(), indent=2, default=str)
