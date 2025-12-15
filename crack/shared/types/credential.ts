/**
 * Credential Types for B.R.E.A.C.H.
 *
 * Represents discovered credentials with source tracking and access validation.
 */

export type SecretType =
  | 'password'   // Cleartext password
  | 'ntlm'       // NTLM hash
  | 'kerberos'   // Kerberos TGS/AS-REP hash
  | 'ssh_key'    // SSH private key
  | 'ticket'     // Kerberos ticket
  | 'gpp'        // GPP decrypted password
  | 'sam'        // SAM hash
  | 'dcc2';      // Domain Cached Credentials v2

export interface Credential {
  id: string;
  username: string;
  secret: string;
  secretType: SecretType;
  domain?: string;
  source: string;                    // "Groups.xml", "kerberoast", "mimikatz", "manual"
  sourceSessionId?: string;          // Session that discovered it
  targetId?: string;                 // Target it was found on
  engagementId: string;
  validatedAccess: string[];         // ["smb:Users", "smb:SYSVOL", "winrm"]
  isAdmin: boolean;
  createdAt: string;
  notes?: string;
}

export interface CredentialAction {
  id: string;
  label: string;
  icon?: string;
  command: string;
  requiresDomain: boolean;
  services: string[];
}

// Standard credential actions for "Use with..." dropdown
export const CREDENTIAL_ACTIONS: CredentialAction[] = [
  {
    id: 'smbmap',
    label: 'SMBMap',
    command: 'smbmap -u "<USER>" -p "<PASS>" -H <TARGET>',
    requiresDomain: false,
    services: ['smb'],
  },
  {
    id: 'smbclient',
    label: 'SMBClient',
    command: 'smbclient -U "<USER>%<PASS>" //<TARGET>/<SHARE>',
    requiresDomain: false,
    services: ['smb'],
  },
  {
    id: 'smbclient-domain',
    label: 'SMBClient (Domain)',
    command: 'smbclient -U "<DOMAIN>/<USER>%<PASS>" //<TARGET>/<SHARE>',
    requiresDomain: true,
    services: ['smb'],
  },
  {
    id: 'wmiexec',
    label: 'WMIExec',
    command: 'wmiexec.py "<DOMAIN>/<USER>:<PASS>@<TARGET>"',
    requiresDomain: true,
    services: ['smb'],
  },
  {
    id: 'psexec',
    label: 'PSExec',
    command: 'psexec.py "<DOMAIN>/<USER>:<PASS>@<TARGET>"',
    requiresDomain: true,
    services: ['smb'],
  },
  {
    id: 'evil-winrm',
    label: 'Evil-WinRM',
    command: 'evil-winrm -i <TARGET> -u "<USER>" -p "<PASS>"',
    requiresDomain: false,
    services: ['winrm'],
  },
  {
    id: 'evil-winrm-domain',
    label: 'Evil-WinRM (Domain)',
    command: 'evil-winrm -i <TARGET> -u "<DOMAIN>\\<USER>" -p "<PASS>"',
    requiresDomain: true,
    services: ['winrm'],
  },
  {
    id: 'ldapsearch',
    label: 'LDAP Query',
    command: 'ldapsearch -x -H "ldap://<TARGET>" -D "<USER>@<DOMAIN>" -w "<PASS>" -b "dc=<DC1>,dc=<DC2>"',
    requiresDomain: true,
    services: ['ldap'],
  },
  {
    id: 'crackmapexec-smb',
    label: 'CrackMapExec SMB',
    command: 'crackmapexec smb <TARGET> -u "<USER>" -p "<PASS>" -d "<DOMAIN>"',
    requiresDomain: true,
    services: ['smb'],
  },
  {
    id: 'GetUserSPNs',
    label: 'Kerberoast',
    command: 'GetUserSPNs.py "<DOMAIN>/<USER>:<PASS>" -dc-ip <TARGET> -request',
    requiresDomain: true,
    services: ['kerberos'],
  },
  {
    id: 'secretsdump',
    label: 'Secrets Dump',
    command: 'secretsdump.py "<DOMAIN>/<USER>:<PASS>@<TARGET>"',
    requiresDomain: true,
    services: ['smb'],
  },
];

/**
 * Substitute placeholders in command template with credential values
 */
export function substituteCredential(
  command: string,
  credential: Credential,
  targetIp: string,
  share?: string
): string {
  let result = command
    .replace(/<USER>/g, credential.username)
    .replace(/<PASS>/g, credential.secret)
    .replace(/<TARGET>/g, targetIp);

  if (credential.domain) {
    result = result
      .replace(/<DOMAIN>/g, credential.domain)
      .replace(/<DC1>/g, credential.domain.split('.')[0] || '')
      .replace(/<DC2>/g, credential.domain.split('.')[1] || '');
  }

  if (share) {
    result = result.replace(/<SHARE>/g, share);
  }

  return result;
}

/**
 * Get applicable actions for a credential based on secret type
 * When called with just secretType, returns all actions for that type
 * When called with full credential and services, filters appropriately
 */
export function getApplicableActions(
  secretTypeOrCredential: SecretType | Credential,
  availableServices?: string[]
): CredentialAction[] {
  // If just a secret type string, return common actions
  if (typeof secretTypeOrCredential === 'string') {
    const secretType = secretTypeOrCredential;
    // For password-based types, return all common actions
    if (['password', 'gpp'].includes(secretType)) {
      return CREDENTIAL_ACTIONS.filter(a => !a.requiresDomain || a.services.includes('smb'));
    }
    // For hash types, return fewer actions (need to crack first)
    if (['ntlm', 'sam', 'dcc2'].includes(secretType)) {
      return CREDENTIAL_ACTIONS.filter(a => ['wmiexec', 'psexec', 'secretsdump'].includes(a.id));
    }
    // For kerberos, return kerberos-related actions
    if (secretType === 'kerberos') {
      return CREDENTIAL_ACTIONS.filter(a => a.services.includes('kerberos'));
    }
    return [];
  }

  // Full credential filtering
  const credential = secretTypeOrCredential;
  return CREDENTIAL_ACTIONS.filter(action => {
    // Check if credential has domain when required
    if (action.requiresDomain && !credential.domain) {
      return false;
    }
    // Check if at least one required service is available
    if (availableServices) {
      return action.services.some(svc => availableServices.includes(svc));
    }
    return true;
  });
}
