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

// Re-export comprehensive credential actions from shared/actions
import {
  CREDENTIAL_ACTIONS as ALL_CREDENTIAL_ACTIONS,
  getCredentialActionsByCategory,
  CREDENTIAL_CATEGORY_ORDER,
} from '../actions/credentials';
import type { CommandAction } from './actions';

export type { CommandAction as CredentialAction };
export {
  ALL_CREDENTIAL_ACTIONS as CREDENTIAL_ACTIONS,
  getCredentialActionsByCategory,
  CREDENTIAL_CATEGORY_ORDER,
};

// Actions applicable to password-based credentials (cleartext)
const PASSWORD_ACTIONS = [
  'smbclient', 'smbmap', 'cme-smb', 'cme-smb-shares', 'ldapsearch', 'rpcclient',
  'kerberoast', 'asreproast', 'gettgt',
  'psexec', 'wmiexec', 'smbexec', 'atexec', 'evil-winrm', 'xfreerdp',
  'secretsdump', 'secretsdump-dc', 'lsassy',
];

// Actions applicable to NTLM hash credentials (pass-the-hash)
const HASH_ACTIONS = [
  'pth-psexec', 'pth-wmiexec', 'pth-evil-winrm', 'pth-cme',
];

// Actions applicable to kerberos hashes (need cracking first)
const KERBEROS_ACTIONS = [
  'kerberoast', 'asreproast', 'gettgt',
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
    .replace(/<IP>/g, targetIp)
    .replace(/<TARGET>/g, targetIp);  // Backwards compat

  if (credential.domain) {
    result = result
      .replace(/<DOMAIN>/g, credential.domain)
      .replace(/<DC1>/g, credential.domain.split('.')[0] || '')
      .replace(/<DC2>/g, credential.domain.split('.')[1] || '');
  }

  // For NTLM hashes (pass-the-hash actions)
  if (['ntlm', 'sam'].includes(credential.secretType)) {
    result = result.replace(/<HASH>/g, credential.secret);
  }

  if (share) {
    result = result.replace(/<SHARE>/g, share);
  }

  return result;
}

/**
 * Get applicable actions for a credential based on secret type
 * Returns actions appropriate for the credential type (password, hash, kerberos)
 */
export function getApplicableActions(
  secretTypeOrCredential: SecretType | Credential
): CommandAction[] {
  const secretType = typeof secretTypeOrCredential === 'string'
    ? secretTypeOrCredential
    : secretTypeOrCredential.secretType;

  // For password-based types (cleartext passwords), return password actions
  if (['password', 'gpp'].includes(secretType)) {
    return ALL_CREDENTIAL_ACTIONS.filter(a => PASSWORD_ACTIONS.includes(a.id));
  }

  // For NTLM hash types, return pass-the-hash actions
  if (['ntlm', 'sam'].includes(secretType)) {
    return ALL_CREDENTIAL_ACTIONS.filter(a => HASH_ACTIONS.includes(a.id));
  }

  // For kerberos hashes (need cracking first), return limited actions
  if (['kerberos', 'dcc2'].includes(secretType)) {
    return ALL_CREDENTIAL_ACTIONS.filter(a => KERBEROS_ACTIONS.includes(a.id));
  }

  // For tickets and SSH keys, no standard lateral movement actions
  // (tickets need special handling, SSH keys need ssh command)
  return [];
}

/**
 * Get applicable actions grouped by category
 */
export function getApplicableActionsByCategory(
  secretType: SecretType
): Map<string, CommandAction[]> {
  const actions = getApplicableActions(secretType);
  const groups = new Map<string, CommandAction[]>();

  for (const action of actions) {
    const existing = groups.get(action.category) || [];
    existing.push(action);
    groups.set(action.category, existing);
  }

  return groups;
}
