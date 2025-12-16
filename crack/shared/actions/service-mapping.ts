/**
 * Service-to-Action Category Mapping
 *
 * Defines which action categories appear based on detected services.
 * Uses a hybrid approach: curated menu structure with Neo4j enrichment.
 */

import type {
  ActionCategory,
  ActionTool,
  ActionVariant,
  ServiceMatcher,
  ServiceInfo,
} from '../types/actions-panel';

// =============================================================================
// SERVICE MATCHERS
// =============================================================================

/** Service matchers for common protocols */
export const SERVICE_MATCHERS: Record<string, ServiceMatcher> = {
  smb: {
    ports: [139, 445],
    serviceNames: ['microsoft-ds', 'netbios-ssn', 'smb'],
  },
  http: {
    ports: [80, 443, 8080, 8443, 8000, 8888, 8081],
    serviceNames: ['http', 'https', 'ssl/http', 'apache', 'nginx', 'iis', 'tomcat'],
  },
  ssh: {
    ports: [22],
    serviceNames: ['ssh', 'openssh'],
  },
  ftp: {
    ports: [21],
    serviceNames: ['ftp', 'vsftpd', 'proftpd', 'pure-ftpd'],
  },
  ldap: {
    ports: [389, 636, 3268, 3269],
    serviceNames: ['ldap', 'ldaps', 'ldapssl'],
  },
  kerberos: {
    ports: [88],
    serviceNames: ['kerberos', 'kerberos-sec'],
  },
  mssql: {
    ports: [1433, 1434],
    serviceNames: ['ms-sql', 'mssql', 'ms-sql-s', 'ms-sql-m'],
  },
  mysql: {
    ports: [3306],
    serviceNames: ['mysql', 'mariadb'],
  },
  rdp: {
    ports: [3389],
    serviceNames: ['rdp', 'ms-wbt-server', 'microsoft-rdp'],
  },
  winrm: {
    ports: [5985, 5986],
    serviceNames: ['wsman', 'winrm', 'http-alt'],
  },
  dns: {
    ports: [53],
    serviceNames: ['domain', 'dns'],
  },
  smtp: {
    ports: [25, 465, 587],
    serviceNames: ['smtp', 'smtps', 'submission'],
  },
  snmp: {
    ports: [161, 162],
    serviceNames: ['snmp'],
    protocols: ['udp'],
  },
  rpc: {
    ports: [111, 135],
    serviceNames: ['rpcbind', 'msrpc', 'epmap'],
  },
  nfs: {
    ports: [2049],
    serviceNames: ['nfs', 'nfsd'],
  },
  telnet: {
    ports: [23],
    serviceNames: ['telnet'],
  },
  vnc: {
    ports: [5900, 5901, 5902],
    serviceNames: ['vnc', 'rfb'],
  },
  redis: {
    ports: [6379],
    serviceNames: ['redis'],
  },
  postgresql: {
    ports: [5432],
    serviceNames: ['postgresql', 'postgres'],
  },
  mongodb: {
    ports: [27017, 27018],
    serviceNames: ['mongodb', 'mongod'],
  },
  // Active Directory detection (combination of DC services)
  activeDirectory: {
    ports: [88, 389, 636, 445, 3268, 3269],
    serviceNames: ['kerberos', 'ldap', 'microsoft-ds', 'kpasswd', 'msrpc'],
  },
};

// =============================================================================
// CURATED ACTION CATEGORIES
// =============================================================================

/** Curated action categories with tool structure */
export const ACTION_CATEGORIES: ActionCategory[] = [
  // ─────────────────────────────────────────────────────────────────────────────
  // PORT SCAN (Always Show)
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'port-scan',
    name: 'Port Scan',
    icon: 'radar',
    description: 'Network discovery and port scanning',
    alwaysShow: true,
    tools: [
      {
        id: 'nmap',
        name: 'Nmap',
        icon: 'terminal',
        variants: [
          {
            id: 'nmap-quick',
            label: 'Quick Scan',
            command: 'nmap -sC -sV <IP>',
            description: 'Default scripts + version detection',
            oscpRelevance: 'high',
          },
          {
            id: 'nmap-full',
            label: 'Full Port Scan',
            command: 'nmap -p- --min-rate=1000 <IP>',
            description: 'Scan all 65535 TCP ports',
            oscpRelevance: 'high',
          },
          {
            id: 'nmap-service',
            label: 'Service Scan',
            command: 'nmap -sV -sC -p <PORT> <IP>',
            description: 'Detailed service enumeration on specific ports',
            oscpRelevance: 'high',
          },
          {
            id: 'nmap-stealth',
            label: 'Stealth Scan',
            command: 'sudo nmap -sS -Pn <IP>',
            description: 'SYN scan without completing handshake',
            oscpRelevance: 'medium',
          },
          {
            id: 'nmap-udp',
            label: 'UDP Top 20',
            command: 'sudo nmap -sU --top-ports=20 <IP>',
            description: 'Top 20 UDP ports',
            oscpRelevance: 'high',
          },
          {
            id: 'nmap-vuln',
            label: 'Vuln Scripts',
            command: 'nmap --script vuln <IP>',
            description: 'Run vulnerability detection scripts',
            oscpRelevance: 'medium',
          },
        ],
      },
      {
        id: 'masscan',
        name: 'Masscan',
        icon: 'bolt',
        variants: [
          {
            id: 'masscan-fast',
            label: 'Fast Full Scan',
            command: 'sudo masscan -p1-65535 --rate=1000 <IP>',
            description: 'Fast full port scan',
            oscpRelevance: 'medium',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // SMB
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'smb',
    name: 'SMB',
    icon: 'folder-share',
    description: 'SMB/CIFS enumeration',
    serviceMatcher: SERVICE_MATCHERS.smb,
    tools: [
      {
        id: 'enum4linux',
        name: 'enum4linux',
        variants: [
          {
            id: 'enum4linux-all',
            label: 'Full Enumeration',
            command: 'enum4linux -a <IP>',
            description: 'Complete SMB enumeration',
            oscpRelevance: 'high',
          },
          {
            id: 'enum4linux-users',
            label: 'Users Only',
            command: 'enum4linux -U <IP>',
            description: 'Enumerate users',
            oscpRelevance: 'high',
          },
          {
            id: 'enum4linux-shares',
            label: 'Shares Only',
            command: 'enum4linux -S <IP>',
            description: 'Enumerate shares',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'smbmap',
        name: 'smbmap',
        variants: [
          {
            id: 'smbmap-null',
            label: 'Null Session',
            command: 'smbmap -H <IP>',
            description: 'List shares with null session',
            oscpRelevance: 'high',
          },
          {
            id: 'smbmap-guest',
            label: 'Guest Session',
            command: 'smbmap -H <IP> -u guest',
            description: 'List shares as guest',
            oscpRelevance: 'high',
          },
          {
            id: 'smbmap-recursive',
            label: 'Recursive List',
            command: 'smbmap -H <IP> -R',
            description: 'Recursively list all files',
            oscpRelevance: 'medium',
          },
        ],
      },
      {
        id: 'smbclient',
        name: 'smbclient',
        variants: [
          {
            id: 'smbclient-list',
            label: 'List Shares',
            command: 'smbclient -N -L //<IP>',
            description: 'List available shares',
            oscpRelevance: 'high',
          },
          {
            id: 'smbclient-connect',
            label: 'Connect to Share',
            command: 'smbclient -N //<IP>/<SHARE>',
            description: 'Connect to specific share',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'crackmapexec-smb',
        name: 'CrackMapExec',
        variants: [
          {
            id: 'cme-smb-null',
            label: 'Null Auth Check',
            command: 'crackmapexec smb <IP>',
            description: 'Check SMB info and null auth',
            oscpRelevance: 'high',
          },
          {
            id: 'cme-smb-shares',
            label: 'Enumerate Shares',
            command: 'crackmapexec smb <IP> --shares',
            description: 'List shares with permissions',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'nmap-smb',
        name: 'Nmap SMB Scripts',
        variants: [
          {
            id: 'nmap-smb-enum',
            label: 'SMB Enum',
            command: 'nmap --script "smb-enum*" -p 139,445 <IP>',
            description: 'SMB enumeration scripts',
            oscpRelevance: 'high',
          },
          {
            id: 'nmap-smb-vuln',
            label: 'SMB Vulns',
            command: 'nmap --script "smb-vuln*" -p 139,445 <IP>',
            description: 'Check for MS17-010, etc.',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // HTTP
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'http',
    name: 'HTTP',
    icon: 'world',
    description: 'Web application enumeration',
    serviceMatcher: SERVICE_MATCHERS.http,
    tools: [
      {
        id: 'gobuster',
        name: 'Gobuster',
        variants: [
          {
            id: 'gobuster-dir-common',
            label: 'Dir (common.txt)',
            command: 'gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt',
            description: 'Directory brute with common wordlist',
            oscpRelevance: 'high',
          },
          {
            id: 'gobuster-dir-medium',
            label: 'Dir (medium)',
            command: 'gobuster dir -u http://<IP> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            description: 'Directory brute with medium wordlist',
            oscpRelevance: 'high',
          },
          {
            id: 'gobuster-extensions',
            label: 'With Extensions',
            command: 'gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,txt,html',
            description: 'Directory brute with file extensions',
            oscpRelevance: 'high',
          },
          {
            id: 'gobuster-vhost',
            label: 'VHost Enum',
            command: 'gobuster vhost -u http://<IP> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',
            description: 'Virtual host enumeration',
            oscpRelevance: 'medium',
          },
        ],
      },
      {
        id: 'ffuf',
        name: 'ffuf',
        variants: [
          {
            id: 'ffuf-dir',
            label: 'Directory Fuzz',
            command: 'ffuf -u http://<IP>/FUZZ -w /usr/share/wordlists/dirb/common.txt',
            description: 'Fast directory fuzzing',
            oscpRelevance: 'high',
          },
          {
            id: 'ffuf-filter',
            label: 'Filter by Status',
            command: 'ffuf -u http://<IP>/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 404',
            description: 'Directory fuzz filtering 404s',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'nikto',
        name: 'Nikto',
        variants: [
          {
            id: 'nikto-scan',
            label: 'Full Scan',
            command: 'nikto -h http://<IP>',
            description: 'Vulnerability scan',
            oscpRelevance: 'medium',
          },
        ],
      },
      {
        id: 'whatweb',
        name: 'WhatWeb',
        variants: [
          {
            id: 'whatweb-scan',
            label: 'Fingerprint',
            command: 'whatweb http://<IP>',
            description: 'Identify web technologies',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'curl',
        name: 'curl',
        variants: [
          {
            id: 'curl-headers',
            label: 'Get Headers',
            command: 'curl -I http://<IP>',
            description: 'Fetch HTTP headers',
            oscpRelevance: 'high',
          },
          {
            id: 'curl-robots',
            label: 'robots.txt',
            command: 'curl http://<IP>/robots.txt',
            description: 'Check robots.txt',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // LDAP
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'ldap',
    name: 'LDAP',
    icon: 'sitemap',
    description: 'LDAP/Active Directory enumeration',
    serviceMatcher: SERVICE_MATCHERS.ldap,
    tools: [
      {
        id: 'ldapsearch',
        name: 'ldapsearch',
        variants: [
          {
            id: 'ldapsearch-anon',
            label: 'Anonymous Bind',
            command: 'ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local"',
            description: 'Anonymous LDAP query',
            oscpRelevance: 'high',
          },
          {
            id: 'ldapsearch-users',
            label: 'Enumerate Users',
            command: 'ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local" "(objectClass=user)"',
            description: 'List all user objects',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'nmap-ldap',
        name: 'Nmap LDAP Scripts',
        variants: [
          {
            id: 'nmap-ldap-enum',
            label: 'LDAP Enum',
            command: 'nmap --script "ldap*" -p 389,636 <IP>',
            description: 'LDAP enumeration scripts',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // SSH
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'ssh',
    name: 'SSH',
    icon: 'terminal-2',
    description: 'SSH enumeration',
    serviceMatcher: SERVICE_MATCHERS.ssh,
    tools: [
      {
        id: 'ssh-connect',
        name: 'SSH Connect',
        variants: [
          {
            id: 'ssh-connect-basic',
            label: 'Connect',
            command: 'ssh <USER>@<IP>',
            description: 'SSH connection',
            oscpRelevance: 'high',
          },
          {
            id: 'ssh-connect-key',
            label: 'Connect with Key',
            command: 'ssh -i <KEY> <USER>@<IP>',
            description: 'SSH with private key',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'nmap-ssh',
        name: 'Nmap SSH Scripts',
        variants: [
          {
            id: 'nmap-ssh-enum',
            label: 'SSH Enum',
            command: 'nmap --script "ssh*" -p 22 <IP>',
            description: 'SSH enumeration scripts',
            oscpRelevance: 'medium',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // FTP
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'ftp',
    name: 'FTP',
    icon: 'upload',
    description: 'FTP enumeration',
    serviceMatcher: SERVICE_MATCHERS.ftp,
    tools: [
      {
        id: 'ftp-connect',
        name: 'FTP Client',
        variants: [
          {
            id: 'ftp-anon',
            label: 'Anonymous Login',
            command: 'ftp <IP>',
            description: 'Try anonymous FTP login',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'nmap-ftp',
        name: 'Nmap FTP Scripts',
        variants: [
          {
            id: 'nmap-ftp-enum',
            label: 'FTP Enum',
            command: 'nmap --script "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor" -p 21 <IP>',
            description: 'FTP enumeration scripts',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // MSSQL
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'mssql',
    name: 'MSSQL',
    icon: 'database',
    description: 'Microsoft SQL Server enumeration',
    serviceMatcher: SERVICE_MATCHERS.mssql,
    tools: [
      {
        id: 'mssqlclient',
        name: 'mssqlclient.py',
        variants: [
          {
            id: 'mssql-connect',
            label: 'Connect',
            command: 'mssqlclient.py <USER>:<PASS>@<IP>',
            description: 'Connect to MSSQL',
            oscpRelevance: 'high',
          },
          {
            id: 'mssql-windows',
            label: 'Windows Auth',
            command: 'mssqlclient.py <DOMAIN>/<USER>:<PASS>@<IP> -windows-auth',
            description: 'Connect with Windows auth',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'nmap-mssql',
        name: 'Nmap MSSQL Scripts',
        variants: [
          {
            id: 'nmap-mssql-enum',
            label: 'MSSQL Enum',
            command: 'nmap --script "ms-sql*" -p 1433 <IP>',
            description: 'MSSQL enumeration scripts',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // MySQL
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'mysql',
    name: 'MySQL',
    icon: 'database',
    description: 'MySQL enumeration',
    serviceMatcher: SERVICE_MATCHERS.mysql,
    tools: [
      {
        id: 'mysql-connect',
        name: 'MySQL Client',
        variants: [
          {
            id: 'mysql-connect-basic',
            label: 'Connect',
            command: 'mysql -h <IP> -u <USER> -p',
            description: 'Connect to MySQL',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'nmap-mysql',
        name: 'Nmap MySQL Scripts',
        variants: [
          {
            id: 'nmap-mysql-enum',
            label: 'MySQL Enum',
            command: 'nmap --script "mysql*" -p 3306 <IP>',
            description: 'MySQL enumeration scripts',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // RDP
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'rdp',
    name: 'RDP',
    icon: 'device-desktop',
    description: 'Remote Desktop Protocol',
    serviceMatcher: SERVICE_MATCHERS.rdp,
    tools: [
      {
        id: 'xfreerdp',
        name: 'xfreerdp',
        variants: [
          {
            id: 'rdp-connect',
            label: 'Connect',
            command: 'xfreerdp /v:<IP> /u:<USER> /p:<PASS> /cert:ignore',
            description: 'RDP connection',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'nmap-rdp',
        name: 'Nmap RDP Scripts',
        variants: [
          {
            id: 'nmap-rdp-enum',
            label: 'RDP Enum',
            command: 'nmap --script "rdp*" -p 3389 <IP>',
            description: 'RDP enumeration scripts',
            oscpRelevance: 'medium',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // WinRM
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'winrm',
    name: 'WinRM',
    icon: 'terminal',
    description: 'Windows Remote Management',
    serviceMatcher: SERVICE_MATCHERS.winrm,
    tools: [
      {
        id: 'evil-winrm',
        name: 'evil-winrm',
        variants: [
          {
            id: 'winrm-connect',
            label: 'Connect',
            command: 'evil-winrm -i <IP> -u <USER> -p <PASS>',
            description: 'WinRM shell',
            oscpRelevance: 'high',
          },
          {
            id: 'winrm-hash',
            label: 'Connect (PTH)',
            command: 'evil-winrm -i <IP> -u <USER> -H <HASH>',
            description: 'WinRM with NTLM hash',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // DNS
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'dns',
    name: 'DNS',
    icon: 'world-www',
    description: 'DNS enumeration',
    serviceMatcher: SERVICE_MATCHERS.dns,
    tools: [
      {
        id: 'dig',
        name: 'dig',
        variants: [
          {
            id: 'dig-any',
            label: 'Query ANY',
            command: 'dig @<IP> <DOMAIN> ANY',
            description: 'Query all record types',
            oscpRelevance: 'high',
          },
          {
            id: 'dig-axfr',
            label: 'Zone Transfer',
            command: 'dig @<IP> <DOMAIN> AXFR',
            description: 'Attempt zone transfer',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'nmap-dns',
        name: 'Nmap DNS Scripts',
        variants: [
          {
            id: 'nmap-dns-enum',
            label: 'DNS Enum',
            command: 'nmap --script "dns*" -p 53 <IP>',
            description: 'DNS enumeration scripts',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // SNMP
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'snmp',
    name: 'SNMP',
    icon: 'antenna',
    description: 'SNMP enumeration',
    serviceMatcher: SERVICE_MATCHERS.snmp,
    tools: [
      {
        id: 'snmpwalk',
        name: 'snmpwalk',
        variants: [
          {
            id: 'snmpwalk-public',
            label: 'Walk (public)',
            command: 'snmpwalk -v2c -c public <IP>',
            description: 'SNMP walk with public community',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'onesixtyone',
        name: 'onesixtyone',
        variants: [
          {
            id: 'snmp-brute',
            label: 'Brute Community',
            command: 'onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <IP>',
            description: 'Brute force community strings',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // NFS
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'nfs',
    name: 'NFS',
    icon: 'folders',
    description: 'NFS enumeration',
    serviceMatcher: SERVICE_MATCHERS.nfs,
    tools: [
      {
        id: 'showmount',
        name: 'showmount',
        variants: [
          {
            id: 'nfs-exports',
            label: 'List Exports',
            command: 'showmount -e <IP>',
            description: 'Show NFS exports',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'mount',
        name: 'mount',
        variants: [
          {
            id: 'nfs-mount',
            label: 'Mount Share',
            command: 'sudo mount -t nfs <IP>:<SHARE> /mnt/nfs',
            description: 'Mount NFS share',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // Kerberos
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'kerberos',
    name: 'Kerberos',
    icon: 'key',
    description: 'Kerberos attacks',
    serviceMatcher: SERVICE_MATCHERS.kerberos,
    tools: [
      {
        id: 'kerbrute',
        name: 'kerbrute',
        variants: [
          {
            id: 'kerbrute-users',
            label: 'User Enum',
            command: 'kerbrute userenum --dc <IP> -d <DOMAIN> users.txt',
            description: 'Enumerate valid usernames',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'impacket-kerberos',
        name: 'Impacket',
        variants: [
          {
            id: 'getnpusers',
            label: 'AS-REP Roast',
            command: 'GetNPUsers.py <DOMAIN>/ -usersfile users.txt -dc-ip <IP> -format hashcat',
            description: 'Find AS-REP roastable users',
            oscpRelevance: 'high',
          },
          {
            id: 'getuserspns',
            label: 'Kerberoast',
            command: 'GetUserSPNs.py <DOMAIN>/<USER>:<PASS> -dc-ip <IP> -request',
            description: 'Request TGS tickets for cracking',
            oscpRelevance: 'high',
          },
        ],
      },
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────────
  // ACTIVE DIRECTORY
  // ─────────────────────────────────────────────────────────────────────────────
  {
    id: 'active-directory',
    name: 'Active Directory',
    icon: 'shield',
    description: 'Active Directory attacks and enumeration',
    serviceMatcher: SERVICE_MATCHERS.activeDirectory,
    tools: [
      {
        id: 'bloodhound',
        name: 'BloodHound',
        variants: [
          {
            id: 'bloodhound-python',
            label: 'BloodHound.py',
            command: 'bloodhound-python -u <USER> -p <PASS> -d <DOMAIN> -dc <IP> -c All',
            description: 'Collect all AD data for BloodHound',
            oscpRelevance: 'high',
          },
          {
            id: 'sharphound',
            label: 'SharpHound',
            command: 'SharpHound.exe -c All --domain <DOMAIN>',
            description: 'Run SharpHound collector on target',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'mimikatz',
        name: 'Mimikatz',
        variants: [
          {
            id: 'mimikatz-logonpasswords',
            label: 'logonpasswords',
            command: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
            description: 'Dump credentials from memory',
            oscpRelevance: 'high',
          },
          {
            id: 'mimikatz-dcsync',
            label: 'DCSync',
            command: 'mimikatz.exe "lsadump::dcsync /domain:<DOMAIN> /user:<USER>" "exit"',
            description: 'DCSync to extract password hash',
            oscpRelevance: 'high',
          },
          {
            id: 'mimikatz-golden',
            label: 'Golden Ticket',
            command: 'mimikatz.exe "kerberos::golden /user:<USER> /domain:<DOMAIN> /sid:<SID> /krbtgt:<HASH>" "exit"',
            description: 'Create golden ticket',
            oscpRelevance: 'medium',
          },
          {
            id: 'mimikatz-pth',
            label: 'Pass-the-Hash',
            command: 'mimikatz.exe "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH>" "exit"',
            description: 'Pass-the-hash to spawn process',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'kerberoasting',
        name: 'Kerberoasting',
        variants: [
          {
            id: 'kerberoast-getuserspns',
            label: 'GetUserSPNs.py',
            command:
              'GetUserSPNs.py <DOMAIN>/<USER>:<PASS> -dc-ip <IP> -request -outputfile kerberoast.txt',
            description: 'Request TGS tickets for offline cracking',
            oscpRelevance: 'high',
          },
          {
            id: 'kerberoast-rubeus',
            label: 'Rubeus Kerberoast',
            command: 'Rubeus.exe kerberoast /outfile:hashes.txt',
            description: 'Kerberoast with Rubeus',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'asreproast',
        name: 'AS-REP Roasting',
        variants: [
          {
            id: 'asrep-getnpusers',
            label: 'GetNPUsers.py',
            command:
              'GetNPUsers.py <DOMAIN>/ -usersfile users.txt -dc-ip <IP> -format hashcat -outputfile asrep.txt',
            description: 'AS-REP roast users without preauth',
            oscpRelevance: 'high',
          },
          {
            id: 'asrep-rubeus',
            label: 'Rubeus AS-REP',
            command: 'Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt',
            description: 'AS-REP roast with Rubeus',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'secretsdump',
        name: 'SecretsDump',
        variants: [
          {
            id: 'secretsdump-local',
            label: 'Local SAM',
            command: 'secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL',
            description: 'Extract hashes from registry hives',
            oscpRelevance: 'high',
          },
          {
            id: 'secretsdump-remote',
            label: 'Remote Dump',
            command: 'secretsdump.py <DOMAIN>/<USER>:<PASS>@<IP>',
            description: 'Remote secrets extraction',
            oscpRelevance: 'high',
          },
          {
            id: 'secretsdump-ntds',
            label: 'NTDS.dit Dump',
            command: 'secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL',
            description: 'Extract hashes from NTDS.dit',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'crackmapexec-ad',
        name: 'CrackMapExec AD',
        variants: [
          {
            id: 'cme-ad-users',
            label: 'Enum Users',
            command: 'crackmapexec smb <IP> -u <USER> -p <PASS> --users',
            description: 'Enumerate domain users',
            oscpRelevance: 'high',
          },
          {
            id: 'cme-ad-pass-pol',
            label: 'Password Policy',
            command: 'crackmapexec smb <IP> -u <USER> -p <PASS> --pass-pol',
            description: 'Get password policy',
            oscpRelevance: 'high',
          },
          {
            id: 'cme-ad-sam',
            label: 'Dump SAM',
            command: 'crackmapexec smb <IP> -u <USER> -p <PASS> --sam',
            description: 'Dump SAM database',
            oscpRelevance: 'high',
          },
          {
            id: 'cme-ad-lsa',
            label: 'Dump LSA',
            command: 'crackmapexec smb <IP> -u <USER> -p <PASS> --lsa',
            description: 'Dump LSA secrets',
            oscpRelevance: 'high',
          },
          {
            id: 'cme-ad-ntds',
            label: 'Dump NTDS',
            command: 'crackmapexec smb <IP> -u <USER> -p <PASS> --ntds',
            description: 'Dump NTDS.dit via VSS',
            oscpRelevance: 'high',
          },
        ],
      },
      {
        id: 'impacket-ad',
        name: 'Impacket',
        variants: [
          {
            id: 'psexec',
            label: 'psexec.py',
            command: 'psexec.py <DOMAIN>/<USER>:<PASS>@<IP>',
            description: 'Remote command execution via SMB',
            oscpRelevance: 'high',
          },
          {
            id: 'wmiexec',
            label: 'wmiexec.py',
            command: 'wmiexec.py <DOMAIN>/<USER>:<PASS>@<IP>',
            description: 'Remote command execution via WMI',
            oscpRelevance: 'high',
          },
          {
            id: 'smbexec',
            label: 'smbexec.py',
            command: 'smbexec.py <DOMAIN>/<USER>:<PASS>@<IP>',
            description: 'Remote command execution via SMB service',
            oscpRelevance: 'high',
          },
          {
            id: 'atexec',
            label: 'atexec.py',
            command: 'atexec.py <DOMAIN>/<USER>:<PASS>@<IP> "command"',
            description: 'Remote command execution via Task Scheduler',
            oscpRelevance: 'medium',
          },
        ],
      },
    ],
  },
];

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Check if a service matches a ServiceMatcher
 */
export function matchesService(
  service: ServiceInfo,
  matcher: ServiceMatcher
): boolean {
  // Check port match
  if (matcher.ports?.includes(service.port)) {
    return true;
  }

  // Check service name match (partial, case-insensitive)
  if (matcher.serviceNames && service.service_name) {
    const lowerName = service.service_name.toLowerCase();
    if (matcher.serviceNames.some((pattern) => lowerName.includes(pattern.toLowerCase()))) {
      return true;
    }
  }

  // Check protocol match
  if (matcher.protocols && matcher.protocols.includes(service.protocol as 'tcp' | 'udp')) {
    // Protocol alone isn't enough, need port or service name too
    return false;
  }

  return false;
}

/**
 * Get relevant action categories for a list of services
 */
export function getRelevantCategories(services: ServiceInfo[]): ActionCategory[] {
  return ACTION_CATEGORIES.filter((category) => {
    // Always show categories marked as such
    if (category.alwaysShow) return true;

    // Check if any service matches the category's matcher
    if (!category.serviceMatcher) return false;
    return services.some((service) => matchesService(service, category.serviceMatcher!));
  });
}

/**
 * Get all categories (for debugging/admin)
 */
export function getAllCategories(): ActionCategory[] {
  return ACTION_CATEGORIES;
}

/**
 * Get Neo4j tags for a category (for enrichment queries)
 */
export const CATEGORY_TAG_MAP: Record<string, string[]> = {
  'port-scan': ['NMAP', 'PORT_SCANNING', 'MASSCAN', 'DISCOVERY'],
  smb: ['SMB', 'SMBCLIENT', 'SMBMAP', 'ENUM4LINUX', 'CRACKMAPEXEC'],
  http: ['HTTP', 'WEB', 'GOBUSTER', 'FFUF', 'NIKTO', 'WHATWEB', 'DIRECTORY_ENUMERATION'],
  ldap: ['LDAP', 'LDAPSEARCH', 'ACTIVE_DIRECTORY'],
  ssh: ['SSH'],
  ftp: ['FTP'],
  mssql: ['MSSQL', 'MS-SQL', 'DATABASE'],
  mysql: ['MYSQL', 'DATABASE'],
  rdp: ['RDP', 'REMOTE_DESKTOP'],
  winrm: ['WINRM', 'EVIL-WINRM'],
  dns: ['DNS'],
  snmp: ['SNMP'],
  nfs: ['NFS', 'NETWORK_FILE_SYSTEM'],
  kerberos: ['KERBEROS', 'KERBRUTE', 'ASREPROAST', 'KERBEROAST'],
  'active-directory': [
    'ACTIVE_DIRECTORY',
    'BLOODHOUND',
    'MIMIKATZ',
    'KERBEROAST',
    'ASREPROAST',
    'SECRETSDUMP',
    'IMPACKET',
    'PSEXEC',
    'WMIEXEC',
    'DCSYNC',
    'GOLDEN_TICKET',
    'PASS_THE_HASH',
  ],
};
