"""
Port Reference - Common OSCP ports and enumeration commands

Static reference data for quick lookup of:
- Common OSCP ports
- Service enumeration commands
- Quick wins for each service
- Common vulnerabilities
"""

from typing import Dict, List, Optional


class PortInfo:
    """Information about a specific port"""

    def __init__(self, port: int, service: str, description: str,
                 enum_commands: List[str], quick_wins: List[str] = None,
                 common_vulns: List[str] = None):
        """
        Initialize port information

        Args:
            port: Port number
            service: Service name
            description: Service description
            enum_commands: List of enumeration commands
            quick_wins: Quick win checks
            common_vulns: Common vulnerabilities
        """
        self.port = port
        self.service = service
        self.description = description
        self.enum_commands = enum_commands
        self.quick_wins = quick_wins or []
        self.common_vulns = common_vulns or []


class PortReference:
    """Static reference of common OSCP ports"""

    _ports: Dict[int, PortInfo] = {}

    @classmethod
    def register(cls, port_info: PortInfo):
        """Register port information

        Args:
            port_info: PortInfo instance to register
        """
        cls._ports[port_info.port] = port_info

    @classmethod
    def lookup(cls, port: int) -> Optional[PortInfo]:
        """Lookup port information

        Args:
            port: Port number

        Returns:
            PortInfo if found, None otherwise
        """
        return cls._ports.get(port)

    @classmethod
    def search_by_service(cls, service: str) -> List[PortInfo]:
        """Find ports by service name

        Args:
            service: Service name (partial match, case-insensitive)

        Returns:
            List of matching PortInfo objects
        """
        service_lower = service.lower()
        return [p for p in cls._ports.values()
                if service_lower in p.service.lower() or
                   service_lower in p.description.lower()]

    @classmethod
    def list_all(cls) -> List[PortInfo]:
        """Get all registered ports

        Returns:
            List of all PortInfo objects sorted by port number
        """
        return sorted(cls._ports.values(), key=lambda p: p.port)


def _register_defaults():
    """Register default OSCP port reference data"""

    # FTP - 21
    PortReference.register(PortInfo(
        port=21,
        service="FTP",
        description="File Transfer Protocol",
        enum_commands=[
            "ftp <TARGET>",
            "nmap -p 21 --script ftp-anon,ftp-bounce <TARGET>",
            "hydra -L users.txt -P passwords.txt ftp://<TARGET>"
        ],
        quick_wins=[
            "Try anonymous login: ftp <TARGET> (user: anonymous, pass: anonymous)",
            "Check for anonymous write access",
            "Download all files: mget *"
        ],
        common_vulns=[
            "Anonymous login enabled",
            "Writable directories",
            "ProFTPD 1.3.5 - mod_copy RCE (CVE-2015-3306)",
            "vsftpd 2.3.4 - Backdoor (CVE-2011-2523)"
        ]
    ))

    # SSH - 22
    PortReference.register(PortInfo(
        port=22,
        service="SSH",
        description="Secure Shell",
        enum_commands=[
            "ssh <TARGET>",
            "nmap -p 22 --script ssh-auth-methods,ssh2-enum-algos <TARGET>",
            "hydra -L users.txt -P passwords.txt ssh://<TARGET>"
        ],
        quick_wins=[
            "Check SSH version for known vulnerabilities",
            "Try default credentials (root/toor, admin/admin)",
            "Look for SSH keys in web directories",
            "Check for username enumeration (OpenSSH < 7.7)"
        ],
        common_vulns=[
            "Weak passwords",
            "OpenSSH < 7.7 - User Enumeration (CVE-2018-15473)",
            "Default credentials",
            "Private keys with weak passphrases"
        ]
    ))

    # Telnet - 23
    PortReference.register(PortInfo(
        port=23,
        service="Telnet",
        description="Unencrypted remote shell",
        enum_commands=[
            "telnet <TARGET>",
            "nmap -p 23 --script telnet-encryption <TARGET>"
        ],
        quick_wins=[
            "Try default credentials",
            "No encryption - credentials sent in cleartext",
            "Banner may reveal OS/device type"
        ],
        common_vulns=[
            "Default credentials",
            "No encryption (sniffable)",
            "Buffer overflows in old implementations"
        ]
    ))

    # SMTP - 25
    PortReference.register(PortInfo(
        port=25,
        service="SMTP",
        description="Simple Mail Transfer Protocol",
        enum_commands=[
            "nc -nv <TARGET> 25",
            "smtp-user-enum -M VRFY -U users.txt -t <TARGET>",
            "nmap -p 25 --script smtp-enum-users,smtp-open-relay <TARGET>"
        ],
        quick_wins=[
            "Enumerate users with VRFY/EXPN/RCPT",
            "Check for open relay",
            "Banner grabbing may reveal version"
        ],
        common_vulns=[
            "User enumeration via VRFY/EXPN",
            "Open mail relay",
            "No authentication required"
        ]
    ))

    # DNS - 53
    PortReference.register(PortInfo(
        port=53,
        service="DNS",
        description="Domain Name System",
        enum_commands=[
            "dig @<TARGET> domain.com ANY",
            "dnsrecon -d domain.com -n <TARGET>",
            "dnsenum --dnsserver <TARGET> domain.com",
            "nmap -p 53 --script dns-zone-transfer <TARGET>"
        ],
        quick_wins=[
            "Try zone transfer: dig @<TARGET> domain.com AXFR",
            "Enumerate subdomains",
            "Check for recursive queries"
        ],
        common_vulns=[
            "Zone transfer enabled (AXFR)",
            "DNS cache poisoning",
            "Subdomain enumeration"
        ]
    ))

    # HTTP - 80
    PortReference.register(PortInfo(
        port=80,
        service="HTTP",
        description="Hypertext Transfer Protocol",
        enum_commands=[
            "gobuster dir -u http://<TARGET> -w /usr/share/wordlists/dirb/common.txt",
            "nikto -h http://<TARGET>",
            "whatweb http://<TARGET>",
            "curl -I http://<TARGET>"
        ],
        quick_wins=[
            "Check robots.txt, sitemap.xml",
            "View page source for comments/credentials",
            "Try /admin, /login, /upload, /backup",
            "Look for default credentials",
            "Check for directory listing"
        ],
        common_vulns=[
            "Directory traversal",
            "File upload vulnerabilities",
            "SQL injection",
            "Default credentials",
            "Outdated CMS/frameworks"
        ]
    ))

    # Kerberos - 88
    PortReference.register(PortInfo(
        port=88,
        service="Kerberos",
        description="Network authentication protocol",
        enum_commands=[
            "nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='domain.com' <TARGET>",
            "kerbrute userenum -d domain.com users.txt --dc <TARGET>"
        ],
        quick_wins=[
            "Enumerate valid usernames",
            "ASREPRoasting for accounts without pre-auth",
            "Kerberoasting for service accounts"
        ],
        common_vulns=[
            "User enumeration",
            "ASREPRoasting (accounts without Kerberos pre-auth)",
            "Kerberoasting (extract service tickets)"
        ]
    ))

    # POP3 - 110
    PortReference.register(PortInfo(
        port=110,
        service="POP3",
        description="Post Office Protocol",
        enum_commands=[
            "nc -nv <TARGET> 110",
            "nmap -p 110 --script pop3-capabilities <TARGET>"
        ],
        quick_wins=[
            "Try default credentials",
            "Banner may reveal version",
            "Check for user enumeration"
        ],
        common_vulns=[
            "Weak passwords",
            "Default credentials",
            "User enumeration"
        ]
    ))

    # RPC - 111
    PortReference.register(PortInfo(
        port=111,
        service="RPCbind",
        description="Remote Procedure Call",
        enum_commands=[
            "rpcinfo -p <TARGET>",
            "nmap -p 111 --script rpcinfo <TARGET>"
        ],
        quick_wins=[
            "Enumerate RPC services",
            "Look for NFS exports"
        ],
        common_vulns=[
            "Information disclosure",
            "NFS misconfiguration"
        ]
    ))

    # NetBIOS - 139
    PortReference.register(PortInfo(
        port=139,
        service="NetBIOS",
        description="NetBIOS Session Service",
        enum_commands=[
            "enum4linux -a <TARGET>",
            "nmblookup -A <TARGET>",
            "smbclient -L //<TARGET> -N"
        ],
        quick_wins=[
            "Enumerate shares, users, groups",
            "Null session enumeration",
            "Extract OS information"
        ],
        common_vulns=[
            "Null session enabled",
            "Information disclosure",
            "Weak SMB signing"
        ]
    ))

    # IMAP - 143
    PortReference.register(PortInfo(
        port=143,
        service="IMAP",
        description="Internet Message Access Protocol",
        enum_commands=[
            "nc -nv <TARGET> 143",
            "nmap -p 143 --script imap-capabilities <TARGET>"
        ],
        quick_wins=[
            "Try default credentials",
            "Banner grabbing",
            "Check capabilities"
        ],
        common_vulns=[
            "Weak passwords",
            "Default credentials"
        ]
    ))

    # SNMP - 161
    PortReference.register(PortInfo(
        port=161,
        service="SNMP",
        description="Simple Network Management Protocol",
        enum_commands=[
            "snmpwalk -v 2c -c public <TARGET>",
            "snmp-check <TARGET>",
            "onesixtyone -c community.txt <TARGET>"
        ],
        quick_wins=[
            "Try default community strings (public, private)",
            "Enumerate system information",
            "Extract user accounts, running processes"
        ],
        common_vulns=[
            "Default community strings",
            "Information disclosure",
            "SNMPv1/v2c no encryption"
        ]
    ))

    # LDAP - 389
    PortReference.register(PortInfo(
        port=389,
        service="LDAP",
        description="Lightweight Directory Access Protocol",
        enum_commands=[
            "ldapsearch -x -h <TARGET> -s base",
            "nmap -p 389 --script ldap-rootdse <TARGET>",
            "ldapdomaindump <TARGET> -u 'domain\\user' -p password"
        ],
        quick_wins=[
            "Anonymous bind enumeration",
            "Extract domain information",
            "Enumerate users and groups"
        ],
        common_vulns=[
            "Anonymous bind enabled",
            "Information disclosure",
            "Weak authentication"
        ]
    ))

    # HTTPS - 443
    PortReference.register(PortInfo(
        port=443,
        service="HTTPS",
        description="HTTP over TLS/SSL",
        enum_commands=[
            "gobuster dir -u https://<TARGET> -w /usr/share/wordlists/dirb/common.txt -k",
            "nikto -h https://<TARGET>",
            "sslscan <TARGET>:443",
            "testssl.sh <TARGET>:443"
        ],
        quick_wins=[
            "Check certificate for subdomains/emails",
            "Test for Heartbleed (sslscan)",
            "Try HTTP (port 80) for unencrypted version",
            "Check for SSL/TLS misconfigurations"
        ],
        common_vulns=[
            "Heartbleed (OpenSSL CVE-2014-0160)",
            "Weak SSL/TLS configuration",
            "Self-signed certificates",
            "Certificate subject alternative names reveal hosts"
        ]
    ))

    # SMB - 445
    PortReference.register(PortInfo(
        port=445,
        service="SMB",
        description="Server Message Block",
        enum_commands=[
            "enum4linux -a <TARGET>",
            "smbclient -L //<TARGET> -N",
            "smbmap -H <TARGET>",
            "crackmapexec smb <TARGET> --shares",
            "nmap -p 445 --script smb-vuln* <TARGET>"
        ],
        quick_wins=[
            "Try null session: smbclient -L //<TARGET> -N",
            "Check for writable shares",
            "Enumerate users and groups",
            "Test for EternalBlue (MS17-010)"
        ],
        common_vulns=[
            "EternalBlue (MS17-010)",
            "Null session enabled",
            "Writable shares",
            "SMBv1 enabled",
            "Anonymous access"
        ]
    ))

    # MSSQL - 1433
    PortReference.register(PortInfo(
        port=1433,
        service="MSSQL",
        description="Microsoft SQL Server",
        enum_commands=[
            "nmap -p 1433 --script ms-sql-info <TARGET>",
            "sqsh -S <TARGET> -U sa -P password",
            "impacket-mssqlclient sa@<TARGET>"
        ],
        quick_wins=[
            "Try default credentials (sa with blank password)",
            "Check for xp_cmdshell enabled",
            "Look for linked servers"
        ],
        common_vulns=[
            "Default/weak credentials",
            "xp_cmdshell command execution",
            "SQL injection",
            "Linked server attacks"
        ]
    ))

    # Oracle - 1521
    PortReference.register(PortInfo(
        port=1521,
        service="Oracle",
        description="Oracle Database",
        enum_commands=[
            "tnscmd10g version -h <TARGET>",
            "nmap -p 1521 --script oracle-sid-brute <TARGET>",
            "odat sidguesser -s <TARGET>"
        ],
        quick_wins=[
            "Enumerate SID",
            "Try default credentials",
            "Check version for CVEs"
        ],
        common_vulns=[
            "Default credentials",
            "TNS listener vulnerabilities",
            "SID enumeration"
        ]
    ))

    # NFS - 2049
    PortReference.register(PortInfo(
        port=2049,
        service="NFS",
        description="Network File System",
        enum_commands=[
            "showmount -e <TARGET>",
            "nmap -p 2049 --script nfs-ls,nfs-showmount <TARGET>",
            "mount -t nfs <TARGET>:/share /mnt/nfs"
        ],
        quick_wins=[
            "List NFS exports",
            "Mount shares without authentication",
            "Check for root_squash disabled"
        ],
        common_vulns=[
            "Anonymous mount access",
            "root_squash disabled (privilege escalation)",
            "Sensitive file exposure"
        ]
    ))

    # MySQL - 3306
    PortReference.register(PortInfo(
        port=3306,
        service="MySQL",
        description="MySQL Database",
        enum_commands=[
            "mysql -h <TARGET> -u root",
            "mysql -h <TARGET> -u root -p",
            "nmap -p 3306 --script mysql-enum <TARGET>",
            "hydra -L users.txt -P passwords.txt mysql://<TARGET>"
        ],
        quick_wins=[
            "Try default credentials (root with no password)",
            "Check for anonymous access",
            "Enumerate databases if accessible",
            "Look for UDF privilege escalation"
        ],
        common_vulns=[
            "Default/weak credentials",
            "Remote root access enabled",
            "Unauthenticated access",
            "UDF (User Defined Function) exploitation"
        ]
    ))

    # RDP - 3389
    PortReference.register(PortInfo(
        port=3389,
        service="RDP",
        description="Remote Desktop Protocol",
        enum_commands=[
            "nmap -p 3389 --script rdp-enum-encryption <TARGET>",
            "xfreerdp /v:<TARGET> /u:user /p:password",
            "rdesktop <TARGET>"
        ],
        quick_wins=[
            "Check for weak encryption",
            "Try default/common credentials",
            "Test for BlueKeep vulnerability"
        ],
        common_vulns=[
            "BlueKeep (CVE-2019-0708)",
            "Weak credentials",
            "NLA not enforced",
            "RDP session hijacking"
        ]
    ))

    # PostgreSQL - 5432
    PortReference.register(PortInfo(
        port=5432,
        service="PostgreSQL",
        description="PostgreSQL Database",
        enum_commands=[
            "psql -h <TARGET> -U postgres",
            "nmap -p 5432 --script pgsql-brute <TARGET>"
        ],
        quick_wins=[
            "Try default credentials (postgres/postgres)",
            "Check for trust authentication",
            "Command execution via COPY"
        ],
        common_vulns=[
            "Default credentials",
            "Trust authentication enabled",
            "Command execution via COPY FROM PROGRAM"
        ]
    ))

    # WinRM - 5985/5986
    PortReference.register(PortInfo(
        port=5985,
        service="WinRM",
        description="Windows Remote Management (HTTP)",
        enum_commands=[
            "evil-winrm -i <TARGET> -u user -p password",
            "crackmapexec winrm <TARGET> -u user -p password"
        ],
        quick_wins=[
            "Try captured credentials",
            "Remote PowerShell access",
            "Upload/download files"
        ],
        common_vulns=[
            "Weak credentials",
            "Privilege escalation via WinRM"
        ]
    ))

    # VNC - 5900
    PortReference.register(PortInfo(
        port=5900,
        service="VNC",
        description="Virtual Network Computing",
        enum_commands=[
            "vncviewer <TARGET>",
            "nmap -p 5900 --script vnc-info <TARGET>"
        ],
        quick_wins=[
            "Try connecting without password",
            "Check for weak authentication",
            "Banner reveals VNC version"
        ],
        common_vulns=[
            "No authentication required",
            "Weak passwords",
            "Known VNC vulnerabilities"
        ]
    ))

    # Redis - 6379
    PortReference.register(PortInfo(
        port=6379,
        service="Redis",
        description="Redis In-Memory Database",
        enum_commands=[
            "redis-cli -h <TARGET>",
            "nmap -p 6379 --script redis-info <TARGET>"
        ],
        quick_wins=[
            "Try connecting without authentication",
            "Dump all keys",
            "Write SSH keys via CONFIG SET dir"
        ],
        common_vulns=[
            "No authentication",
            "Remote code execution via cron/SSH",
            "Data exposure"
        ]
    ))

    # HTTP Proxy - 8080
    PortReference.register(PortInfo(
        port=8080,
        service="HTTP-Proxy",
        description="HTTP Alternate / Proxy",
        enum_commands=[
            "gobuster dir -u http://<TARGET>:8080 -w /usr/share/wordlists/dirb/common.txt",
            "nikto -h http://<TARGET>:8080",
            "curl http://<TARGET>:8080"
        ],
        quick_wins=[
            "Check for default web server pages",
            "Look for admin interfaces",
            "Test for open proxy"
        ],
        common_vulns=[
            "Default credentials",
            "Open proxy misconfiguration",
            "Web application vulnerabilities"
        ]
    ))


# Auto-register on import
_register_defaults()
