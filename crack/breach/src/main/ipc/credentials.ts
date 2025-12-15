/**
 * Credential IPC Handlers
 *
 * CRUD operations for credentials stored in Neo4j.
 */

import { ipcMain } from 'electron';
import { debug } from '../debug';
import { runQuery, runWrite } from '@shared/neo4j/query';
import type { Credential, SecretType } from '@shared/types/credential';

/**
 * Generate credential ID
 */
function generateCredentialId(): string {
  return `cred-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Register credential IPC handlers
 */
export function registerCredentialHandlers(): void {
  debug.ipc('Registering credential IPC handlers');

  // List all credentials for an engagement
  ipcMain.handle('credential-list', async (_, engagementId: string) => {
    debug.ipc('credential-list called', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_CREDENTIAL]->(c:Credential)
        OPTIONAL MATCH (c)-[:FOUND_ON]->(t:Target)
        RETURN c, t.ip AS targetIp, t.hostname AS targetHostname
        ORDER BY c.created_at DESC
      `;
      const results = await runQuery(query, { engagementId });

      const credentials: Credential[] = results.map((r: any) => ({
        ...r.c.properties,
        targetIp: r.targetIp,
        targetHostname: r.targetHostname,
      }));

      debug.ipc('credential-list completed', { count: credentials.length });
      return credentials;
    } catch (error) {
      debug.error('credential-list failed', error);
      return [];
    }
  });

  // Add a new credential
  ipcMain.handle('credential-add', async (_, credential: Omit<Credential, 'id' | 'createdAt'>) => {
    debug.ipc('credential-add called', {
      username: credential.username,
      source: credential.source,
    });

    try {
      const id = generateCredentialId();
      const createdAt = new Date().toISOString();

      const query = `
        MATCH (e:Engagement {id: $engagementId})
        CREATE (c:Credential {
          id: $id,
          username: $username,
          secret: $secret,
          secretType: $secretType,
          domain: $domain,
          source: $source,
          sourceSessionId: $sourceSessionId,
          targetId: $targetId,
          engagementId: $engagementId,
          validatedAccess: $validatedAccess,
          isAdmin: $isAdmin,
          createdAt: $createdAt,
          notes: $notes
        })
        MERGE (e)-[:HAS_CREDENTIAL]->(c)
        WITH c
        OPTIONAL MATCH (t:Target {id: $targetId})
        FOREACH (_ IN CASE WHEN t IS NOT NULL THEN [1] ELSE [] END |
          MERGE (c)-[:FOUND_ON]->(t)
        )
        OPTIONAL MATCH (s:TerminalSession {id: $sourceSessionId})
        FOREACH (_ IN CASE WHEN s IS NOT NULL THEN [1] ELSE [] END |
          MERGE (c)-[:EXTRACTED_BY]->(s)
        )
        RETURN c
      `;

      const params = {
        id,
        username: credential.username,
        secret: credential.secret,
        secretType: credential.secretType,
        domain: credential.domain || '',
        source: credential.source,
        sourceSessionId: credential.sourceSessionId || '',
        targetId: credential.targetId || '',
        engagementId: credential.engagementId,
        validatedAccess: credential.validatedAccess || [],
        isAdmin: credential.isAdmin || false,
        createdAt,
        notes: credential.notes || '',
      };

      await runWrite(query, params);

      const newCredential: Credential = {
        ...credential,
        id,
        createdAt,
      };

      debug.ipc('credential-add completed', { id });
      return newCredential;
    } catch (error) {
      debug.error('credential-add failed', error);
      throw error;
    }
  });

  // Update a credential
  ipcMain.handle('credential-update', async (_, id: string, updates: Partial<Credential>) => {
    debug.ipc('credential-update called', { id, updates: Object.keys(updates) });

    try {
      const setParts: string[] = [];
      const params: Record<string, any> = { id };

      if (updates.validatedAccess !== undefined) {
        setParts.push('c.validatedAccess = $validatedAccess');
        params.validatedAccess = updates.validatedAccess;
      }
      if (updates.isAdmin !== undefined) {
        setParts.push('c.isAdmin = $isAdmin');
        params.isAdmin = updates.isAdmin;
      }
      if (updates.notes !== undefined) {
        setParts.push('c.notes = $notes');
        params.notes = updates.notes;
      }

      if (setParts.length === 0) {
        return true;
      }

      const query = `
        MATCH (c:Credential {id: $id})
        SET ${setParts.join(', ')}
        RETURN c
      `;

      await runWrite(query, params);
      debug.ipc('credential-update completed', { id });
      return true;
    } catch (error) {
      debug.error('credential-update failed', error);
      return false;
    }
  });

  // Delete a credential
  ipcMain.handle('credential-delete', async (_, id: string) => {
    debug.ipc('credential-delete called', { id });

    try {
      const query = `
        MATCH (c:Credential {id: $id})
        DETACH DELETE c
      `;
      await runWrite(query, { id });
      debug.ipc('credential-delete completed', { id });
      return true;
    } catch (error) {
      debug.error('credential-delete failed', error);
      return false;
    }
  });

  // Validate credential access to a service
  ipcMain.handle('credential-validate-access', async (
    _,
    credentialId: string,
    serviceId: string,
    accessType: string
  ) => {
    debug.ipc('credential-validate-access called', { credentialId, serviceId, accessType });

    try {
      // Add the access to validatedAccess array
      const query = `
        MATCH (c:Credential {id: $credentialId})
        SET c.validatedAccess = CASE
          WHEN $accessType IN c.validatedAccess THEN c.validatedAccess
          ELSE c.validatedAccess + $accessType
        END
        WITH c
        MATCH (s:Service {id: $serviceId})
        MERGE (c)-[:GRANTS_ACCESS_TO]->(s)
        RETURN c
      `;

      await runWrite(query, { credentialId, serviceId, accessType });
      debug.ipc('credential-validate-access completed');
      return true;
    } catch (error) {
      debug.error('credential-validate-access failed', error);
      return false;
    }
  });

  // Get credentials by target
  ipcMain.handle('credential-by-target', async (_, targetId: string) => {
    debug.ipc('credential-by-target called', { targetId });

    try {
      const query = `
        MATCH (c:Credential)-[:FOUND_ON]->(t:Target {id: $targetId})
        RETURN c
        ORDER BY c.created_at DESC
      `;
      const results = await runQuery(query, { targetId });
      const credentials = results.map((r: any) => r.c.properties);

      debug.ipc('credential-by-target completed', { count: credentials.length });
      return credentials;
    } catch (error) {
      debug.error('credential-by-target failed', error);
      return [];
    }
  });

  // Get admin credentials for quick shell access
  ipcMain.handle('credential-get-admin', async (_, engagementId: string) => {
    debug.ipc('credential-get-admin called', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_CREDENTIAL]->(c:Credential)
        WHERE c.isAdmin = true
        OPTIONAL MATCH (c)-[:FOUND_ON]->(t:Target)
        RETURN c, t.ip AS targetIp
        ORDER BY c.created_at DESC
      `;
      const results = await runQuery(query, { engagementId });
      const credentials = results.map((r: any) => ({
        ...r.c.properties,
        targetIp: r.targetIp,
      }));

      debug.ipc('credential-get-admin completed', { count: credentials.length });
      return credentials;
    } catch (error) {
      debug.error('credential-get-admin failed', error);
      return [];
    }
  });

  debug.ipc('Credential IPC handlers registered');
}
