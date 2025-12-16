/**
 * Session IPC Handlers
 *
 * IPC handlers for terminal session management.
 */

import { ipcMain, BrowserWindow } from 'electron';
import { ptyManager, setPtyMainWindow as setPtyWindow } from '../pty/manager';
import { debug } from '../debug';
import { matchCredentials, matchFindings } from '../parser/patterns';
import { runWrite } from '@shared/neo4j/query';
import { generateFindingId } from '@shared/types/finding';
import type { CreateSessionOptions } from '@shared/types/session';
import type { Credential } from '@shared/types/credential';
import type { Finding } from '@shared/types/finding';

/**
 * Emit credential-discovered event to renderer
 */
function emitCredentialDiscovered(credential: Credential, sessionId: string): void {
  const mainWindow = BrowserWindow.getAllWindows()[0];
  if (mainWindow && !mainWindow.isDestroyed()) {
    const isHighValue =
      credential.secretType === 'password' ||
      credential.secretType === 'gpp' ||
      credential.isAdmin;

    mainWindow.webContents.send('credential-discovered', {
      credential,
      sessionId,
      isHighValue,
    });
  }
}

/**
 * Emit finding-discovered event to renderer
 */
function emitFindingDiscovered(finding: Finding, sessionId: string): void {
  const mainWindow = BrowserWindow.getAllWindows()[0];
  if (mainWindow && !mainWindow.isDestroyed()) {
    const isHighValue = finding.severity === 'critical' || finding.severity === 'high';

    mainWindow.webContents.send('finding-discovered', {
      finding,
      sessionId,
      isHighValue,
    });
  }
}

/** Export setPtyMainWindow for main process */
export { setPtyWindow as setPtyMainWindow };

/** Register all session-related IPC handlers */
export function registerSessionHandlers(): void {
  debug.ipc('Registering session IPC handlers');

  // Create a new session
  ipcMain.handle(
    'session-create',
    async (_, command: string, args: string[], options: CreateSessionOptions) => {
      debug.ipc('session-create called', { command, args, options });
      try {
        const session = await ptyManager.createSession(command, args, options);
        debug.ipc('session-create completed', { sessionId: session.id });
        return session;
      } catch (error) {
        debug.error('session-create failed', error);
        throw error;
      }
    }
  );

  // Write to session stdin
  ipcMain.handle('session-write', (_, sessionId: string, data: string) => {
    return ptyManager.write(sessionId, data);
  });

  // Resize session terminal
  ipcMain.handle('session-resize', (_, sessionId: string, cols: number, rows: number) => {
    return ptyManager.resize(sessionId, cols, rows);
  });

  // Kill a session
  ipcMain.handle('session-kill', (_, sessionId: string, signal?: string) => {
    debug.ipc('session-kill called', { sessionId, signal });
    return ptyManager.kill(sessionId, signal);
  });

  // Background a session
  ipcMain.handle('session-background', (_, sessionId: string) => {
    return ptyManager.background(sessionId);
  });

  // Foreground a session
  ipcMain.handle('session-foreground', (_, sessionId: string) => {
    return ptyManager.foreground(sessionId);
  });

  // Get single session
  ipcMain.handle('session-get', (_, sessionId: string) => {
    return ptyManager.getSession(sessionId);
  });

  // List all sessions
  ipcMain.handle('session-list', () => {
    return ptyManager.getAllSessions();
  });

  // Get sessions by type
  ipcMain.handle('session-list-by-type', (_, type: string) => {
    return ptyManager.getSessionsByType(type as any);
  });

  // Get sessions by target
  ipcMain.handle('session-list-by-target', (_, targetId: string) => {
    return ptyManager.getSessionsByTarget(targetId);
  });

  // Get session output buffer
  ipcMain.handle('session-get-output', (_, sessionId: string) => {
    return ptyManager.getOutputBuffer(sessionId);
  });

  // Link sessions
  ipcMain.handle('session-link', (_, sourceId: string, targetId: string) => {
    return ptyManager.linkSessions(sourceId, targetId);
  });

  // Set session label
  ipcMain.handle('session-set-label', (_, sessionId: string, label: string) => {
    return ptyManager.setSessionLabel(sessionId, label);
  });

  // Manual PRISM scan of session output
  ipcMain.handle(
    'session-prism-scan',
    async (_, sessionId: string, engagementId: string, targetId?: string) => {
      debug.ipc('session-prism-scan called', { sessionId, engagementId });

      try {
        const output = ptyManager.getOutputBuffer(sessionId);
        const text = output.join('\n');

        // Use existing parser patterns
        const parsedCredentials = matchCredentials(text);
        const parsedFindings = matchFindings(text);

        const storedCredentials: Credential[] = [];
        const storedFindings: Finding[] = [];

        // Store credentials
        for (const cred of parsedCredentials) {
          const id = `cred-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
          const createdAt = new Date().toISOString();

          try {
            await runWrite(
              `
              MATCH (e:Engagement {id: $engagementId})
              MERGE (c:Credential {
                username: $username,
                secretType: $secretType,
                secret: $secret,
                engagementId: $engagementId
              })
              ON CREATE SET
                c.id = $id,
                c.domain = $domain,
                c.source = $source,
                c.sourceSessionId = $sourceSessionId,
                c.targetId = $targetId,
                c.validatedAccess = [],
                c.isAdmin = false,
                c.createdAt = $createdAt,
                c.notes = ''
              MERGE (e)-[:HAS_CREDENTIAL]->(c)
              RETURN c
              `,
              {
                id,
                username: cred.username,
                secret: cred.secret,
                secretType: cred.secretType,
                domain: cred.domain || '',
                source: cred.source,
                sourceSessionId: sessionId,
                targetId: targetId || '',
                engagementId,
                createdAt,
              }
            );

            const storedCred: Credential = {
              id,
              username: cred.username,
              secret: cred.secret,
              secretType: cred.secretType,
              domain: cred.domain,
              source: cred.source,
              sourceSessionId: sessionId,
              targetId,
              engagementId,
              validatedAccess: [],
              isAdmin: false,
              createdAt,
            };
            storedCredentials.push(storedCred);

            // Emit event to trigger UI refresh
            emitCredentialDiscovered(storedCred, sessionId);
          } catch (err) {
            debug.error('Failed to store credential', err);
          }
        }

        // Store findings
        for (const finding of parsedFindings) {
          const id = generateFindingId();
          const createdAt = new Date().toISOString();

          try {
            await runWrite(
              `
              MATCH (e:Engagement {id: $engagementId})
              MERGE (f:Finding {
                title: $title,
                category: $category,
                evidence: $evidence,
                engagementId: $engagementId
              })
              ON CREATE SET
                f.id = $id,
                f.severity = $severity,
                f.description = $description,
                f.status = 'open',
                f.cveId = '',
                f.cvssScore = '',
                f.targetId = $targetId,
                f.sourceSessionId = $sourceSessionId,
                f.createdAt = $createdAt
              MERGE (e)-[:HAS_FINDING]->(f)
              RETURN f
              `,
              {
                id,
                title: finding.title,
                severity: finding.severity,
                category: finding.category,
                description: finding.description,
                evidence: finding.evidence,
                targetId: targetId || '',
                sourceSessionId: sessionId,
                engagementId,
                createdAt,
              }
            );

            const storedFinding: Finding = {
              id,
              title: finding.title,
              severity: finding.severity,
              category: finding.category,
              description: finding.description,
              evidence: finding.evidence,
              status: 'open',
              targetId,
              sourceSessionId: sessionId,
              engagementId,
              createdAt,
            };
            storedFindings.push(storedFinding);

            // Emit event to trigger UI refresh
            emitFindingDiscovered(storedFinding, sessionId);
          } catch (err) {
            debug.error('Failed to store finding', err);
          }
        }

        debug.ipc('session-prism-scan completed', {
          credentials: storedCredentials.length,
          findings: storedFindings.length,
        });

        return { credentials: storedCredentials, findings: storedFindings };
      } catch (error) {
        debug.error('session-prism-scan failed', error);
        return { credentials: [], findings: [] };
      }
    }
  );

  debug.ipc('Session IPC handlers registered');
}
