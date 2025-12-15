/**
 * B.R.E.A.C.H. Action Types
 *
 * Type definitions for command actions (credentials, nmap, etc.)
 */

/** Command action template */
export interface CommandAction {
  /** Unique action identifier */
  id: string;
  /** Display label */
  label: string;
  /** Action category for grouping */
  category: string;
  /** Command template with placeholders */
  command: string;
  /** Optional description */
  description?: string;
  /** Icon name (tabler icons) */
  icon?: string;
}

/**
 * Placeholders for command substitution:
 * - <IP> - Target IP address
 * - <USER> - Username
 * - <PASS> - Password
 * - <DOMAIN> - Domain name
 * - <HASH> - NTLM hash
 * - <PORT> - Port number
 * - <HOSTNAME> - Target hostname
 */

/** Context for credential actions */
export interface CredentialActionContext {
  ip: string;
  username: string;
  password?: string;
  domain?: string;
  hash?: string;
}

/** Context for target actions */
export interface TargetActionContext {
  ip: string;
  hostname?: string;
  port?: number;
}

/** Substitute placeholders in command template */
export function substituteCommand(
  template: string,
  context: CredentialActionContext | TargetActionContext
): string {
  let result = template;

  if ('ip' in context && context.ip) {
    result = result.replace(/<IP>/g, context.ip);
  }
  if ('username' in context && context.username) {
    result = result.replace(/<USER>/g, context.username);
  }
  if ('password' in context && context.password) {
    result = result.replace(/<PASS>/g, context.password);
  }
  if ('domain' in context && context.domain) {
    result = result.replace(/<DOMAIN>/g, context.domain);
  }
  if ('hash' in context && context.hash) {
    result = result.replace(/<HASH>/g, context.hash);
  }
  if ('hostname' in context && context.hostname) {
    result = result.replace(/<HOSTNAME>/g, context.hostname);
  }
  if ('port' in context && context.port) {
    result = result.replace(/<PORT>/g, context.port.toString());
  }

  return result;
}
