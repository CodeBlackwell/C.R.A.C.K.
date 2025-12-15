/**
 * Nmap Action Templates
 *
 * Command templates for target scanning.
 * Placeholders: <IP>, <HOSTNAME>, <PORT>
 */

import type { CommandAction } from '../types/actions';

/** Nmap scan actions */
export const NMAP_ACTIONS: CommandAction[] = [
  // ═══════════════════════════════════════════════════════════════════════════
  // DISCOVERY
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'nmap-quick',
    label: 'Quick Scan',
    category: 'Discovery',
    command: 'nmap -sC -sV <IP>',
    description: 'Default scripts + version detection',
  },
  {
    id: 'nmap-full',
    label: 'Full Port Scan',
    category: 'Discovery',
    command: 'nmap -p- --min-rate=1000 <IP>',
    description: 'Scan all 65535 TCP ports',
  },
  {
    id: 'nmap-top1000',
    label: 'Top 1000 Ports',
    category: 'Discovery',
    command: 'nmap -sC -sV --top-ports=1000 <IP>',
    description: 'Top 1000 ports with scripts',
  },
  {
    id: 'nmap-udp',
    label: 'UDP Top 20',
    category: 'Discovery',
    command: 'sudo nmap -sU --top-ports=20 <IP>',
    description: 'Top 20 UDP ports',
  },
  {
    id: 'nmap-udp-full',
    label: 'UDP Top 100',
    category: 'Discovery',
    command: 'sudo nmap -sU --top-ports=100 --min-rate=1000 <IP>',
    description: 'Top 100 UDP ports',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // VULNERABILITY
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'nmap-vuln',
    label: 'Vuln Scripts',
    category: 'Vulnerability',
    command: 'nmap --script vuln <IP>',
    description: 'Run vulnerability scripts',
  },
  {
    id: 'nmap-safe',
    label: 'Safe Scripts',
    category: 'Vulnerability',
    command: 'nmap --script safe <IP>',
    description: 'Run safe enumeration scripts',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // SERVICE-SPECIFIC
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'nmap-smb',
    label: 'SMB Enum',
    category: 'Service Scripts',
    command: 'nmap --script "smb-enum*" -p 139,445 <IP>',
    description: 'SMB enumeration scripts',
  },
  {
    id: 'nmap-smb-vuln',
    label: 'SMB Vulns',
    category: 'Service Scripts',
    command: 'nmap --script "smb-vuln*" -p 139,445 <IP>',
    description: 'SMB vulnerability scripts (MS17-010, etc.)',
  },
  {
    id: 'nmap-ldap',
    label: 'LDAP Enum',
    category: 'Service Scripts',
    command: 'nmap --script "ldap*" -p 389,636 <IP>',
    description: 'LDAP enumeration scripts',
  },
  {
    id: 'nmap-dns',
    label: 'DNS Enum',
    category: 'Service Scripts',
    command: 'nmap --script "dns*" -p 53 <IP>',
    description: 'DNS enumeration scripts',
  },
  {
    id: 'nmap-http',
    label: 'HTTP Enum',
    category: 'Service Scripts',
    command: 'nmap --script "http-enum,http-headers,http-methods,http-title" -p 80,443,8080 <IP>',
    description: 'HTTP enumeration scripts',
  },
  {
    id: 'nmap-ftp',
    label: 'FTP Enum',
    category: 'Service Scripts',
    command: 'nmap --script "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor" -p 21 <IP>',
    description: 'FTP enumeration scripts',
  },
  {
    id: 'nmap-ssh',
    label: 'SSH Enum',
    category: 'Service Scripts',
    command: 'nmap --script "ssh*" -p 22 <IP>',
    description: 'SSH enumeration scripts',
  },
  {
    id: 'nmap-mysql',
    label: 'MySQL Enum',
    category: 'Service Scripts',
    command: 'nmap --script "mysql*" -p 3306 <IP>',
    description: 'MySQL enumeration scripts',
  },
  {
    id: 'nmap-mssql',
    label: 'MSSQL Enum',
    category: 'Service Scripts',
    command: 'nmap --script "ms-sql*" -p 1433 <IP>',
    description: 'MSSQL enumeration scripts',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // AGGRESSIVE / COMPREHENSIVE
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'nmap-aggressive',
    label: 'Aggressive Scan',
    category: 'Comprehensive',
    command: 'nmap -A <IP>',
    description: 'OS detection, version, scripts, traceroute',
  },
  {
    id: 'nmap-all',
    label: 'Full Enum',
    category: 'Comprehensive',
    command: 'nmap -sC -sV -O -p- --min-rate=1000 <IP>',
    description: 'Full port scan with scripts, versions, OS',
  },
];

/** Get actions grouped by category */
export function getNmapActionsByCategory(): Map<string, CommandAction[]> {
  const groups = new Map<string, CommandAction[]>();
  for (const action of NMAP_ACTIONS) {
    const existing = groups.get(action.category) || [];
    existing.push(action);
    groups.set(action.category, existing);
  }
  return groups;
}

/** Category display order */
export const NMAP_CATEGORY_ORDER = [
  'Discovery',
  'Vulnerability',
  'Service Scripts',
  'Comprehensive',
];
