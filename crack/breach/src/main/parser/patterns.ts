/**
 * PRISM Pattern Library for Terminal Output Parsing
 *
 * TypeScript port of PRISM regex patterns for real-time credential detection.
 * Patterns are organized by source tool/format for efficient matching.
 */

import type { SecretType } from '@shared/types/credential';
import type { FindingCategory, FindingSeverity } from '@shared/types/finding';
import type {
  SignalConfidence,
  PortState,
  OsFamily,
  HostReachabilitySignal,
  PortStatusSignal,
  DnsResolutionSignal,
  OsDetectionSignal,
  HostIdentitySignal,
  UserEnumerationSignal,
  CrackedHashSignal,
} from '@shared/types/signal';
import { inferOsFromTtl, getServiceFromPort } from '@shared/types/signal';

/** Parsed credential from terminal output */
export interface ParsedCredential {
  username: string;
  domain?: string;
  secret: string;
  secretType: SecretType;
  source: string;
}

/** Parsed finding from terminal output */
export interface ParsedFinding {
  title: string;
  category: FindingCategory;
  severity: FindingSeverity;
  description: string;
  evidence: string;
}

// ============================================================================
// CREDENTIAL PATTERNS
// ============================================================================

export const CREDENTIAL_PATTERNS = {
  // Mimikatz patterns
  mimikatz: {
    // Session header
    sessionHeader: /Authentication Id\s*:\s*(\d+)\s*;\s*(\d+)/i,
    // Credential values (within provider block)
    credUsername: /^\s*\*\s*Username\s*:\s*(.+)$/im,
    credDomain: /^\s*\*\s*Domain\s*:\s*(.+)$/im,
    credPassword: /^\s*\*\s*Password\s*:\s*(.+)$/im,
    credNtlm: /^\s*\*\s*NTLM\s*:\s*([a-fA-F0-9]{32})\s*$/im,
  },

  // Secretsdump patterns (SAM, NTDS, DCC2)
  secretsdump: {
    // SAM/NTDS: user:rid:lmhash:nthash:::
    samNtds: /^([^:\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::?\s*$/m,
    // DCC2: $DCC2$iterations#user#hash
    dcc2: /\$DCC2\$(\d+)#([^#]+)#([a-fA-F0-9]+)/i,
    // Domain prefix: DOMAIN\user:rid:...
    domainUser: /^([^\\]+)\\([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::?\s*$/m,
  },

  // Kerberoast patterns
  kerberoast: {
    // TGS hash: $krb5tgs$23$*user$realm$service*$...
    krb5tgs: /\$krb5tgs\$(\d+)\$\*?([^$*]+)\$([^$*]+)\$([^$*]+)\*?\$([a-fA-F0-9$]+)/i,
    // AS-REP roast: $krb5asrep$23$user@REALM:...
    krb5asrep: /\$krb5asrep\$(\d+)\$([^@:]+)@([^:]+):([a-fA-F0-9$]+)/i,
  },

  // GPP patterns
  gpp: {
    // cpassword attribute in XML
    cpassword: /cpassword="([A-Za-z0-9+/=]+)"/i,
    // Username from same context
    userName: /(?:userName|runAs|accountName)="([^"]+)"/i,
  },

  // Generic patterns (quick detection)
  generic: {
    // NTLM hash format: lmhash:nthash (32:32 hex chars)
    ntlmHash: /\b([a-fA-F0-9]{32}):([a-fA-F0-9]{32})\b/,
    // SSH private key header
    sshKey: /-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
    // Password in output (generic)
    passwordInOutput: /password\s*[=:]\s*["']?([^"'\s\n]{4,})["']?/i,
    // Password shown in cleartext after login/auth
    clearPassword: /password:\s*([^\s\n]+)/i,
  },
};

// ============================================================================
// FINDING PATTERNS (SQLi, LFI, RCE, Recon indicators)
// ============================================================================

export const FINDING_PATTERNS: Array<{
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  pattern: RegExp;
  description: string;
}> = [
  // -------------------------------------------------------------------------
  // NMAP RECONNAISSANCE FINDINGS
  // -------------------------------------------------------------------------

  // Domain Controller detection
  {
    category: 'recon',
    severity: 'info',
    title: 'Active Directory Domain Controller Detected',
    pattern: /(?:88\/tcp\s+open\s+kerberos|3268\/tcp\s+open\s+(?:globalcatLDAP|ldap)|Active Directory)/i,
    description: 'Host appears to be an Active Directory Domain Controller',
  },

  // Legacy/EOL Windows versions
  {
    category: 'config',
    severity: 'high',
    title: 'Legacy Windows OS - End of Life',
    pattern: /Windows\s+(?:Server\s+)?(?:2003|2008|XP|Vista|7)\b/i,
    description: 'Host running end-of-life Windows version with no security updates',
  },

  // SMB Signing disabled (vulnerable to relay)
  {
    category: 'config',
    severity: 'high',
    title: 'SMB Signing Not Required',
    pattern: /message_signing:\s*disabled|SMB.*signing.*not\s+required/i,
    description: 'SMB signing not enforced - vulnerable to NTLM relay attacks',
  },

  // SMB Signing enabled (note for spray attacks)
  {
    category: 'config',
    severity: 'low',
    title: 'SMB Signing Enabled',
    pattern: /Message\s+signing\s+enabled\s+and\s+required/i,
    description: 'SMB signing is enforced - NTLM relay attacks blocked',
  },

  // LDAP without SSL
  {
    category: 'config',
    severity: 'medium',
    title: 'LDAP Without TLS (Port 389)',
    pattern: /389\/tcp\s+open\s+ldap/i,
    description: 'LDAP service on port 389 - credentials may be transmitted in cleartext',
  },

  // Anonymous FTP
  {
    category: 'config',
    severity: 'medium',
    title: 'Anonymous FTP Login Allowed',
    pattern: /(?:Anonymous\s+FTP\s+login\s+allowed|ftp-anon)/i,
    description: 'FTP server allows anonymous access',
  },

  // Null SMB session
  {
    category: 'config',
    severity: 'medium',
    title: 'SMB Null Session Allowed',
    pattern: /(?:account_used:\s*<blank>|NT_STATUS_OK.*null\s+session)/i,
    description: 'SMB allows null/anonymous session - may leak user/share info',
  },

  // MS17-010 (EternalBlue)
  {
    category: 'vuln',
    severity: 'critical',
    title: 'MS17-010 (EternalBlue) - VULNERABLE',
    pattern: /(?:smb-vuln-ms17-010|VULNERABLE.*MS17-010|Host is likely VULNERABLE to MS17-010)/i,
    description: 'System vulnerable to EternalBlue (MS17-010) - Remote code execution',
  },

  // MS08-067
  {
    category: 'vuln',
    severity: 'critical',
    title: 'MS08-067 (Conficker) - VULNERABLE',
    pattern: /(?:smb-vuln-ms08-067|VULNERABLE.*MS08-067)/i,
    description: 'System vulnerable to MS08-067 - Remote code execution',
  },

  // BlueKeep
  {
    category: 'vuln',
    severity: 'critical',
    title: 'CVE-2019-0708 (BlueKeep) - VULNERABLE',
    pattern: /(?:rdp-vuln-ms12-020|VULNERABLE.*BlueKeep|CVE-2019-0708)/i,
    description: 'System vulnerable to BlueKeep - Remote code execution via RDP',
  },

  // Kerberos pre-auth disabled (AS-REP roast)
  {
    category: 'config',
    severity: 'high',
    title: 'Kerberos Pre-Authentication Disabled',
    pattern: /(?:DONT_REQ_PREAUTH|UF_DONT_REQUIRE_PREAUTH)/i,
    description: 'Account does not require Kerberos pre-authentication - AS-REP roastable',
  },

  // Domain/FQDN detection
  {
    category: 'recon',
    severity: 'info',
    title: 'Domain Name Discovered',
    pattern: /Domain:\s*(\S+\.(?:local|htb|corp|internal|lan|home|test))/i,
    description: 'Active Directory or DNS domain name discovered',
  },

  // Hostname in LDAP
  {
    category: 'recon',
    severity: 'info',
    title: 'Hostname via LDAP',
    pattern: /Site:\s*\S+|NetBIOS.*name:\s*\S+/i,
    description: 'Hostname or site information discovered via LDAP',
  },

  // -------------------------------------------------------------------------
  // SQL INJECTION INDICATORS
  // -------------------------------------------------------------------------
  {
    category: 'sqli',
    severity: 'high',
    title: 'SQL Injection - Error Based',
    pattern: /(?:SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLSTATE\[|SQLite3::)/i,
    description: 'Database error message indicating potential SQL injection vulnerability',
  },
  {
    category: 'sqli',
    severity: 'high',
    title: 'SQL Injection - Union Based',
    pattern: /(?:UNION\s+(?:ALL\s+)?SELECT|column.*match|different number of columns)/i,
    description: 'UNION-based SQL injection indicator',
  },

  // Local File Inclusion indicators
  {
    category: 'lfi',
    severity: 'high',
    title: 'LFI - /etc/passwd Disclosure',
    pattern: /root:x:0:0:|daemon:x:1:1:/,
    description: 'Contents of /etc/passwd file exposed via LFI',
  },
  {
    category: 'lfi',
    severity: 'medium',
    title: 'LFI - Windows System File',
    pattern: /\[boot loader\]|\[operating systems\]/i,
    description: 'Windows boot.ini or system file exposed via LFI',
  },

  // Remote Code Execution indicators
  {
    category: 'rce',
    severity: 'critical',
    title: 'RCE - Command Execution Confirmed',
    pattern: /uid=\d+\([^)]+\)\s+gid=\d+/,
    description: 'Output of id command indicating successful RCE',
  },
  {
    category: 'rce',
    severity: 'critical',
    title: 'RCE - Whoami Output',
    pattern: /(?:nt authority\\|builtin\\|WORKGROUP\\)/i,
    description: 'Windows whoami output indicating successful RCE',
  },

  // Privilege Escalation indicators
  {
    category: 'privesc',
    severity: 'high',
    title: 'PrivEsc - SUID Binary Found',
    pattern: /-rwsr-xr-x|SUID.*\/usr\/bin|setuid\(0\)/,
    description: 'SUID binary identified for potential privilege escalation',
  },
  {
    category: 'privesc',
    severity: 'high',
    title: 'PrivEsc - Sudo NOPASSWD',
    pattern: /NOPASSWD:\s*(ALL|\/.*)/i,
    description: 'Sudo NOPASSWD permission detected',
  },
  {
    category: 'privesc',
    severity: 'medium',
    title: 'PrivEsc - Capabilities',
    pattern: /cap_setuid|cap_net_bind|cap_dac_override/i,
    description: 'Linux capabilities that may allow privilege escalation',
  },

  // Information Disclosure
  {
    category: 'info',
    severity: 'medium',
    title: 'Info Disclosure - Internal IP',
    pattern: /(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)/,
    description: 'Internal IP address disclosed',
  },
  {
    category: 'info',
    severity: 'low',
    title: 'Info Disclosure - Version Banner',
    pattern: /(?:Apache\/\d|nginx\/\d|IIS\/\d|PHP\/\d|OpenSSH_\d)/i,
    description: 'Software version information disclosed',
  },
];

// ============================================================================
// NETWORK PATTERNS (Ping, Port Scans, DNS)
// ============================================================================

export const NETWORK_PATTERNS = {
  // Ping patterns
  ping: {
    // Linux ping success: 64 bytes from 192.168.1.10: icmp_seq=1 ttl=128 time=0.512 ms
    success: /(\d+)\s+bytes\s+from\s+([\d.]+)(?:\s+\([^)]+\))?:\s+icmp_seq=(\d+)\s+ttl=(\d+)(?:\s+time=([\d.]+)\s*ms)?/i,
    // Ping statistics: 4 packets transmitted, 4 received, 0% packet loss
    stats: /(\d+)\s+packets?\s+transmitted,\s*(\d+)\s+(?:packets?\s+)?received,\s*(\d+)%\s+packet\s+loss/i,
    // Destination unreachable
    unreachable: /Destination\s+Host\s+Unreachable|Request\s+timed?\s*out|100%\s+packet\s+loss/i,
    // Windows ping: Reply from 192.168.1.10: bytes=32 time<1ms TTL=128
    windowsSuccess: /Reply\s+from\s+([\d.]+):\s+bytes=(\d+)\s+time[<=](\d+)ms\s+TTL=(\d+)/i,
  },

  // Port scan patterns
  port: {
    // Nmap: 22/tcp   open   ssh        OpenSSH 8.9p1 Ubuntu
    nmapPort: /^(\d+)\/(tcp|udp)\s+(open|closed|filtered|open\|filtered|unfiltered)\s+(\S+)(?:\s+(.+))?$/im,
    // Nmap with state reason: 22/tcp open  ssh syn-ack ttl 64
    nmapPortReason: /^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(\S+)\s+ttl\s+(\d+))?/im,
    // Masscan: Discovered open port 22/tcp on 192.168.1.10
    masscanPort: /Discovered\s+open\s+port\s+(\d+)\/(tcp|udp)\s+on\s+([\d.]+)/i,
    // Netcat success: Connection to 192.168.1.10 22 port [tcp/ssh] succeeded!
    ncSuccess: /Connection\s+to\s+([\d.]+)\s+(\d+)\s+port\s+\[(tcp|udp)(?:\/([^\]]+))?\]\s+succeeded/i,
    // Netcat refused: nc: connect to 192.168.1.10 port 22 (tcp) failed: Connection refused
    ncRefused: /connect\s+to\s+([\d.]+)\s+port\s+(\d+)\s+\((tcp|udp)\)\s+failed:\s+Connection\s+refused/i,
    // Netcat timeout: nc: connect to 192.168.1.10 port 22 (tcp) timed out
    ncTimeout: /connect\s+to\s+([\d.]+)\s+port\s+(\d+)\s+\((tcp|udp)\)\s+(?:timed\s+out|failed)/i,
    // Rustscan: Open 192.168.1.10:22
    rustscanPort: /Open\s+([\d.]+):(\d+)/i,
  },

  // DNS patterns
  dns: {
    // dig answer section: dc01.corp.local.    600    IN    A    192.168.1.10
    digAnswer: /^(\S+)\.\s+(\d+)\s+IN\s+(A|AAAA|CNAME|PTR|MX|TXT|NS|SRV)\s+(.+)$/im,
    // nslookup: Name: dc01.corp.local  Address: 192.168.1.10
    nslookupName: /^Name:\s*(\S+)/im,
    nslookupAddr: /^Address:\s*([\d.]+)$/im,
    // host command: dc01.corp.local has address 192.168.1.10
    hostAnswer: /^(\S+)\s+has\s+(?:address|IPv6 address)\s+([\d.:]+)/im,
    // PTR record: 10.1.168.192.in-addr.arpa domain name pointer dc01.corp.local.
    ptrRecord: /(\S+)\s+domain\s+name\s+pointer\s+(\S+)/i,
  },
};

// ============================================================================
// OS DETECTION PATTERNS
// ============================================================================

export const OS_PATTERNS = {
  // Windows version strings
  windowsVer: /Microsoft\s+Windows\s+\[Version\s+([\d.]+)\]/i,
  windowsOs: /Windows\s+(Server\s+)?(\d{4}|1[01]|XP|Vista|7|8)/i,
  // Linux uname: Linux kali 6.1.0-kali9-amd64 #1 SMP ...
  linuxUname: /Linux\s+(\S+)\s+([\d.-]+\S*)/i,
  // Nmap OS detection: OS: Windows Server 2019 Standard 17763
  nmapOs: /OS:\s*(.+?)(?:;|$)/i,
  // Nmap OS details: OS details: Linux 4.15 - 5.6
  nmapOsDetails: /OS\s+details?:\s*(.+)/i,
  // CPE: OS CPE: cpe:/o:microsoft:windows_server_2019
  osCpe: /OS\s+CPE:\s*(cpe:\/o:\S+)/i,
  // SSH banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
  sshBanner: /SSH-[\d.]+-(\S+)\s*(\S+)?/i,
  // /etc/os-release: PRETTY_NAME="Ubuntu 22.04.1 LTS"
  osRelease: /PRETTY_NAME="([^"]+)"/i,
  // cat /etc/issue: Ubuntu 22.04.1 LTS \n \l
  etcIssue: /^(Ubuntu|Debian|CentOS|Fedora|Red Hat|Arch|Kali|Alpine)\s*([\d.]+)?/im,
};

// ============================================================================
// HOST IDENTITY PATTERNS
// ============================================================================

export const HOST_IDENTITY_PATTERNS = {
  // NetBIOS: NetBIOS computer name: DC01
  netbiosName: /NetBIOS\s+(?:computer\s+)?name:\s*(\S+)/i,
  // NetBIOS domain: NetBIOS domain name: CORP
  netbiosDomain: /NetBIOS\s+domain\s+name:\s*(\S+)/i,
  // DNS domain name: DNS domain name: corp.local
  dnsDomain: /DNS\s+domain\s+name:\s*(\S+)/i,
  // SMB: Domain: CORP  OS: Windows Server 2019
  smbDomain: /Domain:\s*(\S+)/i,
  // LDAP rootDSE: defaultNamingContext: DC=corp,DC=local
  ldapNamingContext: /defaultNamingContext:\s*(.+)/i,
  // hostname command output (just the hostname)
  hostname: /^([a-zA-Z0-9][-a-zA-Z0-9]*)\s*$/m,
};

// ============================================================================
// USER ENUMERATION PATTERNS
// ============================================================================

export const USER_PATTERNS = {
  // enum4linux: [*] CORP\Administrator
  enum4linuxUser: /^\[\*\]\s+(?:(\S+)\\)?(\S+)\s*$/im,
  // rpcclient: user:[Administrator] rid:[0x1f4]
  rpcUser: /user:\[([^\]]+)\]\s+rid:\[0x([a-fA-F0-9]+)\]/i,
  // Linux id command: uid=0(root) gid=0(root) groups=0(root)
  linuxId: /uid=(\d+)\(([^)]+)\)\s+gid=(\d+)\(([^)]+)\)(?:\s+groups=(.+))?/i,
  // /etc/passwd: user1:x:1000:1000:User One:/home/user1:/bin/bash
  passwdLine: /^([^:]+):x:(\d+):(\d+):([^:]*):([^:]*):([^:]*)$/m,
  // net user (Windows): User name                    Administrator
  netUser: /^User\s+name\s+(\S+)/im,
  // crackmapexec: SMB ... [*] Windows Server 2019 ... (name:DC01) (domain:CORP)
  cmeHost: /\(name:([^)]+)\)\s+\(domain:([^)]+)\)/i,
  // Impacket GetADUsers: Name: Administrator
  impacketUser: /^Name:\s+(\S+)/im,
};

// ============================================================================
// HASH CRACKING PATTERNS
// ============================================================================

export const CRACK_PATTERNS = {
  // Hashcat potfile: hash:plaintext (colon-separated)
  hashcatPot: /^([a-fA-F0-9$*:]{20,}):(.+)$/m,
  // Hashcat cracking progress: Status...........: Cracked
  hashcatStatus: /^Status[. ]*:\s*(Cracked|Exhausted|Running|Paused)/im,
  // Hashcat recovered: Recovered........: 1/1 (100.00%)
  hashcatRecovered: /^Recovered[. ]*:\s*(\d+)\/(\d+)/im,
  // John cracked: password (username)
  johnCracked: /^(\S+)\s+\(([^)]+)\)\s*$/m,
  // John status: 1 password hash cracked
  johnStatus: /(\d+)\s+password\s+hash(?:es)?\s+cracked/i,
};

// ============================================================================
// PARSED NETWORK SIGNAL INTERFACES
// ============================================================================

export interface ParsedPing {
  ip: string;
  reachable: boolean;
  ttl?: number;
  latencyMs?: number;
  packetsTransmitted?: number;
  packetsReceived?: number;
  packetLoss?: number;
}

export interface ParsedPort {
  ip: string;
  port: number;
  protocol: 'tcp' | 'udp';
  state: PortState;
  service?: string;
  version?: string;
}

export interface ParsedDns {
  hostname: string;
  ip: string;
  recordType: 'A' | 'AAAA' | 'CNAME' | 'PTR' | 'MX' | 'TXT' | 'NS' | 'SRV';
  ttl?: number;
}

export interface ParsedOs {
  osFamily: OsFamily;
  osVersion?: string;
  kernelVersion?: string;
  cpe?: string;
  inferredFromTtl?: boolean;
}

export interface ParsedHost {
  hostname?: string;
  netbiosDomain?: string;
  dnsDomain?: string;
  fqdn?: string;
}

export interface ParsedUser {
  domain?: string;
  username: string;
  uid?: number;
  gid?: number;
  groups?: string[];
  isPrivileged?: boolean;
  shell?: string;
}

export interface ParsedCrackedHash {
  originalHash: string;
  plaintext: string;
  hashType?: string;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Check if value is null/empty in mimikatz output
 */
export function isNullValue(value: string | undefined): boolean {
  if (!value) return true;
  const cleaned = value.trim().toLowerCase();
  return cleaned === '(null)' || cleaned === 'null' || cleaned === '' || cleaned === 'n/a';
}

/**
 * Clean extracted credential value
 */
export function cleanValue(value: string | undefined): string {
  if (!value) return '';
  const cleaned = value.trim();
  if (cleaned.toLowerCase() === '(null)' || cleaned.toLowerCase() === 'null') {
    return '';
  }
  return cleaned;
}

/**
 * Check if username is a machine account (ends with $)
 */
export function isMachineAccount(username: string): boolean {
  return username.endsWith('$');
}

/**
 * Extract domain and username from DOMAIN\user format
 */
export function parseDomainUser(input: string): { domain?: string; username: string } {
  if (input.includes('\\')) {
    const parts = input.split('\\');
    return { domain: parts[0], username: parts[1] };
  }
  if (input.includes('@')) {
    const parts = input.split('@');
    return { username: parts[0], domain: parts[1] };
  }
  return { username: input };
}

/**
 * Match credentials in a text block
 * Returns array of parsed credentials
 */
export function matchCredentials(text: string): ParsedCredential[] {
  const credentials: ParsedCredential[] = [];

  // SAM/NTDS hashes
  const samMatches = text.matchAll(new RegExp(CREDENTIAL_PATTERNS.secretsdump.samNtds, 'gm'));
  for (const match of samMatches) {
    const [, user, , lm, nt] = match;
    if (user && nt && !user.includes('_history')) {
      const { domain, username } = parseDomainUser(user);
      credentials.push({
        username,
        domain,
        secret: `${lm}:${nt}`,
        secretType: 'sam',
        source: 'secretsdump',
      });
    }
  }

  // Domain user format
  const domainMatches = text.matchAll(new RegExp(CREDENTIAL_PATTERNS.secretsdump.domainUser, 'gm'));
  for (const match of domainMatches) {
    const [, domain, user, , lm, nt] = match;
    if (user && nt) {
      credentials.push({
        username: user,
        domain,
        secret: `${lm}:${nt}`,
        secretType: 'ntlm',
        source: 'secretsdump',
      });
    }
  }

  // DCC2 hashes
  const dcc2Match = text.match(CREDENTIAL_PATTERNS.secretsdump.dcc2);
  if (dcc2Match) {
    const [fullMatch, iterations, user, hash] = dcc2Match;
    credentials.push({
      username: user,
      secret: fullMatch,
      secretType: 'dcc2',
      source: 'secretsdump',
    });
  }

  // Kerberoast TGS
  const tgsMatch = text.match(CREDENTIAL_PATTERNS.kerberoast.krb5tgs);
  if (tgsMatch) {
    const [fullMatch, , user, realm] = tgsMatch;
    credentials.push({
      username: user,
      domain: realm,
      secret: fullMatch,
      secretType: 'kerberos',
      source: 'kerberoast',
    });
  }

  // AS-REP roast
  const asrepMatch = text.match(CREDENTIAL_PATTERNS.kerberoast.krb5asrep);
  if (asrepMatch) {
    const [fullMatch, , user, realm] = asrepMatch;
    credentials.push({
      username: user,
      domain: realm,
      secret: fullMatch,
      secretType: 'kerberos',
      source: 'asreproast',
    });
  }

  // GPP cpassword
  const cpassMatch = text.match(CREDENTIAL_PATTERNS.gpp.cpassword);
  if (cpassMatch) {
    const userMatch = text.match(CREDENTIAL_PATTERNS.gpp.userName);
    credentials.push({
      username: userMatch?.[1] || 'unknown',
      secret: cpassMatch[1],
      secretType: 'gpp',
      source: 'gpp',
    });
  }

  // Generic NTLM hash
  const ntlmMatch = text.match(CREDENTIAL_PATTERNS.generic.ntlmHash);
  if (ntlmMatch && credentials.length === 0) {
    credentials.push({
      username: 'unknown',
      secret: ntlmMatch[0],
      secretType: 'ntlm',
      source: 'terminal',
    });
  }

  return credentials;
}

/**
 * Match findings in a text block
 * Returns array of parsed findings
 */
export function matchFindings(text: string): ParsedFinding[] {
  const findings: ParsedFinding[] = [];

  for (const pattern of FINDING_PATTERNS) {
    const match = text.match(pattern.pattern);
    if (match) {
      findings.push({
        title: pattern.title,
        category: pattern.category,
        severity: pattern.severity,
        description: pattern.description,
        evidence: match[0].substring(0, 200), // Limit evidence length
      });
    }
  }

  return findings;
}

// ============================================================================
// NETWORK SIGNAL MATCHING FUNCTIONS
// ============================================================================

/**
 * Extract ping results from text
 */
export function matchPing(text: string, targetIp?: string): ParsedPing | null {
  // Try Linux ping success
  const linuxMatch = text.match(NETWORK_PATTERNS.ping.success);
  if (linuxMatch) {
    const [, , ip, , ttl, latency] = linuxMatch;
    return {
      ip: targetIp || ip,
      reachable: true,
      ttl: parseInt(ttl, 10),
      latencyMs: latency ? parseFloat(latency) : undefined,
    };
  }

  // Try Windows ping success
  const windowsMatch = text.match(NETWORK_PATTERNS.ping.windowsSuccess);
  if (windowsMatch) {
    const [, ip, , latency, ttl] = windowsMatch;
    return {
      ip: targetIp || ip,
      reachable: true,
      ttl: parseInt(ttl, 10),
      latencyMs: parseInt(latency, 10),
    };
  }

  // Check for statistics line with packet counts
  const statsMatch = text.match(NETWORK_PATTERNS.ping.stats);
  if (statsMatch) {
    const [, transmitted, received, loss] = statsMatch;
    const packetsTransmitted = parseInt(transmitted, 10);
    const packetsReceived = parseInt(received, 10);
    const packetLoss = parseInt(loss, 10);

    // If we have an IP from earlier match, use that
    const ipMatch = text.match(/from\s+([\d.]+)/);
    const ip = targetIp || ipMatch?.[1] || '';

    return {
      ip,
      reachable: packetsReceived > 0,
      packetsTransmitted,
      packetsReceived,
      packetLoss,
    };
  }

  // Check for unreachable
  if (NETWORK_PATTERNS.ping.unreachable.test(text)) {
    // Try to extract IP from context
    const ipMatch = text.match(/([\d.]+)/);
    return {
      ip: targetIp || ipMatch?.[1] || '',
      reachable: false,
      packetLoss: 100,
    };
  }

  return null;
}

/**
 * Extract port scan results from text
 */
export function matchPorts(text: string, contextIp?: string): ParsedPort[] {
  const ports: ParsedPort[] = [];
  const seenPorts = new Set<string>();

  // Nmap port lines
  const nmapMatches = text.matchAll(new RegExp(NETWORK_PATTERNS.port.nmapPort.source, 'gim'));
  for (const match of nmapMatches) {
    const [, portStr, protocol, state, service, version] = match;
    const port = parseInt(portStr, 10);
    const key = `${contextIp}:${port}/${protocol}`;

    if (!seenPorts.has(key)) {
      seenPorts.add(key);
      ports.push({
        ip: contextIp || '',
        port,
        protocol: protocol.toLowerCase() as 'tcp' | 'udp',
        state: state.toLowerCase() as PortState,
        service: service || getServiceFromPort(port),
        version: version?.trim(),
      });
    }
  }

  // Masscan discoveries
  const masscanMatches = text.matchAll(new RegExp(NETWORK_PATTERNS.port.masscanPort.source, 'gi'));
  for (const match of masscanMatches) {
    const [, portStr, protocol, ip] = match;
    const port = parseInt(portStr, 10);
    const key = `${ip}:${port}/${protocol}`;

    if (!seenPorts.has(key)) {
      seenPorts.add(key);
      ports.push({
        ip,
        port,
        protocol: protocol.toLowerCase() as 'tcp' | 'udp',
        state: 'open',
        service: getServiceFromPort(port),
      });
    }
  }

  // Netcat success
  const ncMatches = text.matchAll(new RegExp(NETWORK_PATTERNS.port.ncSuccess.source, 'gi'));
  for (const match of ncMatches) {
    const [, ip, portStr, protocol, service] = match;
    const port = parseInt(portStr, 10);
    const key = `${ip}:${port}/${protocol}`;

    if (!seenPorts.has(key)) {
      seenPorts.add(key);
      ports.push({
        ip,
        port,
        protocol: protocol.toLowerCase() as 'tcp' | 'udp',
        state: 'open',
        service: service || getServiceFromPort(port),
      });
    }
  }

  // Netcat refused (closed port)
  const ncRefusedMatches = text.matchAll(new RegExp(NETWORK_PATTERNS.port.ncRefused.source, 'gi'));
  for (const match of ncRefusedMatches) {
    const [, ip, portStr, protocol] = match;
    const port = parseInt(portStr, 10);
    const key = `${ip}:${port}/${protocol}`;

    if (!seenPorts.has(key)) {
      seenPorts.add(key);
      ports.push({
        ip,
        port,
        protocol: protocol.toLowerCase() as 'tcp' | 'udp',
        state: 'closed',
        service: getServiceFromPort(port),
      });
    }
  }

  // Rustscan
  const rustscanMatches = text.matchAll(new RegExp(NETWORK_PATTERNS.port.rustscanPort.source, 'gi'));
  for (const match of rustscanMatches) {
    const [, ip, portStr] = match;
    const port = parseInt(portStr, 10);
    const key = `${ip}:${port}/tcp`;

    if (!seenPorts.has(key)) {
      seenPorts.add(key);
      ports.push({
        ip,
        port,
        protocol: 'tcp',
        state: 'open',
        service: getServiceFromPort(port),
      });
    }
  }

  return ports;
}

/**
 * Extract DNS resolution results from text
 */
export function matchDns(text: string): ParsedDns[] {
  const results: ParsedDns[] = [];
  const seen = new Set<string>();

  // dig answer section
  const digMatches = text.matchAll(new RegExp(NETWORK_PATTERNS.dns.digAnswer.source, 'gim'));
  for (const match of digMatches) {
    const [, hostname, ttlStr, recordType, value] = match;
    const key = `${hostname}:${recordType}:${value}`;

    if (!seen.has(key) && (recordType === 'A' || recordType === 'AAAA')) {
      seen.add(key);
      results.push({
        hostname: hostname.replace(/\.$/, ''), // Remove trailing dot
        ip: value.trim(),
        recordType: recordType as ParsedDns['recordType'],
        ttl: parseInt(ttlStr, 10),
      });
    }
  }

  // host command
  const hostMatches = text.matchAll(new RegExp(NETWORK_PATTERNS.dns.hostAnswer.source, 'gim'));
  for (const match of hostMatches) {
    const [, hostname, ip] = match;
    const key = `${hostname}:A:${ip}`;

    if (!seen.has(key)) {
      seen.add(key);
      results.push({
        hostname,
        ip,
        recordType: ip.includes(':') ? 'AAAA' : 'A',
      });
    }
  }

  // nslookup (requires matching Name and Address lines)
  const nameMatch = text.match(NETWORK_PATTERNS.dns.nslookupName);
  const addrMatch = text.match(NETWORK_PATTERNS.dns.nslookupAddr);
  if (nameMatch && addrMatch) {
    const hostname = nameMatch[1];
    const ip = addrMatch[1];
    const key = `${hostname}:A:${ip}`;

    if (!seen.has(key)) {
      seen.add(key);
      results.push({
        hostname,
        ip,
        recordType: 'A',
      });
    }
  }

  return results;
}

/**
 * Extract OS detection info from text
 */
export function matchOs(text: string, ttlHint?: number): ParsedOs | null {
  // Windows version string
  const windowsVerMatch = text.match(OS_PATTERNS.windowsVer);
  if (windowsVerMatch) {
    return {
      osFamily: 'Windows',
      kernelVersion: windowsVerMatch[1],
      osVersion: `Windows ${windowsVerMatch[1]}`,
    };
  }

  // Windows OS name
  const windowsOsMatch = text.match(OS_PATTERNS.windowsOs);
  if (windowsOsMatch) {
    const serverPrefix = windowsOsMatch[1] || '';
    const version = windowsOsMatch[2];
    return {
      osFamily: 'Windows',
      osVersion: `Windows ${serverPrefix}${version}`.trim(),
    };
  }

  // Linux uname
  const unameMatch = text.match(OS_PATTERNS.linuxUname);
  if (unameMatch) {
    return {
      osFamily: 'Linux',
      osVersion: unameMatch[1],
      kernelVersion: unameMatch[2],
    };
  }

  // Nmap OS detection
  const nmapOsMatch = text.match(OS_PATTERNS.nmapOs);
  if (nmapOsMatch) {
    const osString = nmapOsMatch[1].trim();
    const family: OsFamily = osString.toLowerCase().includes('windows') ? 'Windows' :
                             osString.toLowerCase().includes('linux') ? 'Linux' :
                             osString.toLowerCase().includes('mac') ? 'macOS' : 'Unknown';
    return {
      osFamily: family,
      osVersion: osString,
    };
  }

  // CPE
  const cpeMatch = text.match(OS_PATTERNS.osCpe);
  if (cpeMatch) {
    const cpe = cpeMatch[1];
    const family: OsFamily = cpe.includes('microsoft') || cpe.includes('windows') ? 'Windows' :
                             cpe.includes('linux') ? 'Linux' :
                             cpe.includes('apple') ? 'macOS' : 'Unknown';
    return {
      osFamily: family,
      cpe,
    };
  }

  // os-release
  const osReleaseMatch = text.match(OS_PATTERNS.osRelease);
  if (osReleaseMatch) {
    return {
      osFamily: 'Linux',
      osVersion: osReleaseMatch[1],
    };
  }

  // /etc/issue
  const issueMatch = text.match(OS_PATTERNS.etcIssue);
  if (issueMatch) {
    return {
      osFamily: 'Linux',
      osVersion: `${issueMatch[1]} ${issueMatch[2] || ''}`.trim(),
    };
  }

  // Fallback: TTL-based inference
  if (ttlHint !== undefined) {
    return {
      osFamily: inferOsFromTtl(ttlHint),
      inferredFromTtl: true,
    };
  }

  return null;
}

/**
 * Extract host identity info from text
 */
export function matchHostIdentity(text: string): ParsedHost | null {
  const result: ParsedHost = {};
  let hasData = false;

  const netbiosNameMatch = text.match(HOST_IDENTITY_PATTERNS.netbiosName);
  if (netbiosNameMatch) {
    result.hostname = netbiosNameMatch[1];
    hasData = true;
  }

  const netbiosDomainMatch = text.match(HOST_IDENTITY_PATTERNS.netbiosDomain);
  if (netbiosDomainMatch) {
    result.netbiosDomain = netbiosDomainMatch[1];
    hasData = true;
  }

  const dnsDomainMatch = text.match(HOST_IDENTITY_PATTERNS.dnsDomain);
  if (dnsDomainMatch) {
    result.dnsDomain = dnsDomainMatch[1];
    hasData = true;
  }

  // Build FQDN if we have hostname and domain
  if (result.hostname && result.dnsDomain) {
    result.fqdn = `${result.hostname}.${result.dnsDomain}`;
  }

  return hasData ? result : null;
}

/**
 * Extract user enumeration info from text
 */
export function matchUsers(text: string): ParsedUser[] {
  const users: ParsedUser[] = [];
  const seen = new Set<string>();

  // enum4linux users
  const enum4linuxMatches = text.matchAll(new RegExp(USER_PATTERNS.enum4linuxUser.source, 'gim'));
  for (const match of enum4linuxMatches) {
    const [, domain, username] = match;
    const key = `${domain || ''}\\${username}`.toLowerCase();

    if (!seen.has(key) && username) {
      seen.add(key);
      users.push({
        domain,
        username,
        isPrivileged: /admin|root/i.test(username),
      });
    }
  }

  // rpcclient users
  const rpcMatches = text.matchAll(new RegExp(USER_PATTERNS.rpcUser.source, 'gi'));
  for (const match of rpcMatches) {
    const [, username, rid] = match;
    const key = `\\${username}`.toLowerCase();

    if (!seen.has(key)) {
      seen.add(key);
      // RID 500 = Administrator, RID 501 = Guest
      const ridNum = parseInt(rid, 16);
      users.push({
        username,
        uid: ridNum,
        isPrivileged: ridNum === 0x1f4, // 500
      });
    }
  }

  // Linux id command
  const idMatch = text.match(USER_PATTERNS.linuxId);
  if (idMatch) {
    const [, uid, username, gid, , groupsStr] = idMatch;
    const key = `\\${username}`.toLowerCase();

    if (!seen.has(key)) {
      seen.add(key);
      const groups = groupsStr
        ? groupsStr.split(',').map((g) => {
            const groupMatch = g.match(/\d+\(([^)]+)\)/);
            return groupMatch ? groupMatch[1] : g.trim();
          })
        : [];

      users.push({
        username,
        uid: parseInt(uid, 10),
        gid: parseInt(gid, 10),
        groups,
        isPrivileged: parseInt(uid, 10) === 0,
      });
    }
  }

  // /etc/passwd lines
  const passwdMatches = text.matchAll(new RegExp(USER_PATTERNS.passwdLine.source, 'gm'));
  for (const match of passwdMatches) {
    const [, username, uid, gid, , home, shell] = match;
    const key = `\\${username}`.toLowerCase();

    if (!seen.has(key) && !/^#/.test(username)) {
      seen.add(key);
      users.push({
        username,
        uid: parseInt(uid, 10),
        gid: parseInt(gid, 10),
        shell,
        isPrivileged: parseInt(uid, 10) === 0,
      });
    }
  }

  return users;
}

/**
 * Extract cracked hash results from text
 */
export function matchCrackedHashes(text: string): ParsedCrackedHash[] {
  const results: ParsedCrackedHash[] = [];
  const seen = new Set<string>();

  // Hashcat potfile format: hash:plaintext
  const hashcatMatches = text.matchAll(new RegExp(CRACK_PATTERNS.hashcatPot.source, 'gm'));
  for (const match of hashcatMatches) {
    const [, hash, plaintext] = match;
    if (!seen.has(hash) && plaintext && plaintext.length < 100) {
      seen.add(hash);
      results.push({
        originalHash: hash,
        plaintext: plaintext.trim(),
      });
    }
  }

  // John format: plaintext (username)
  const johnMatches = text.matchAll(new RegExp(CRACK_PATTERNS.johnCracked.source, 'gm'));
  for (const match of johnMatches) {
    const [, plaintext, username] = match;
    // For John, we don't have the original hash in this format
    // The username is more of an identifier
    const key = `john:${username}`;
    if (!seen.has(key)) {
      seen.add(key);
      results.push({
        originalHash: `[john:${username}]`,
        plaintext: plaintext.trim(),
      });
    }
  }

  return results;
}
