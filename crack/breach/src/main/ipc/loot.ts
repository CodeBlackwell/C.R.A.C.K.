/**
 * Loot IPC Handlers
 *
 * CRUD operations for loot (files, flags, hashes) stored in Neo4j.
 */

import { ipcMain } from 'electron';
import { debug } from '../debug';
import { runQuery, runWrite } from '@shared/neo4j/query';
import { detectPatterns, isFlagFile, generateLootId } from '@shared/types/loot';
import type { Loot, LootType, PatternType } from '@shared/types/loot';
import { extractFromLoot } from '../parser';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Register loot IPC handlers
 */
export function registerLootHandlers(): void {
  debug.ipc('Registering loot IPC handlers');

  // List all loot for an engagement
  ipcMain.handle('loot-list', async (_, engagementId: string) => {
    debug.ipc('loot-list called', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_LOOT]->(l:Loot)
        OPTIONAL MATCH (l)-[:FROM_TARGET]->(t:Target)
        RETURN l, t.ip AS targetIp, t.hostname AS targetHostname
        ORDER BY l.created_at DESC
      `;
      const results = await runQuery(query, { engagementId });

      const loot: Loot[] = results.map((r: any) => ({
        ...r.l.properties,
        detectedPatterns: r.l.properties.detectedPatterns || [],
        targetIp: r.targetIp,
        targetHostname: r.targetHostname,
      }));

      debug.ipc('loot-list completed', { count: loot.length });
      return loot;
    } catch (error) {
      debug.error('loot-list failed', error);
      return [];
    }
  });

  // Add new loot (with automatic pattern detection)
  ipcMain.handle('loot-add', async (_, lootData: {
    name: string;
    path: string;
    sourcePath?: string;
    sourceSessionId: string;
    targetId: string;
    engagementId: string;
    content?: string;  // Optional: content for pattern detection
    notes?: string;
  }) => {
    debug.ipc('loot-add called', { name: lootData.name, path: lootData.path });

    try {
      const id = generateLootId();
      const createdAt = new Date().toISOString();

      // Determine loot type
      let type: LootType = 'file';
      if (isFlagFile(lootData.name)) {
        type = 'flag';
      }

      // Read content for pattern detection if not provided
      let content = lootData.content;
      let size: number | undefined;

      if (!content && fs.existsSync(lootData.path)) {
        const stat = fs.statSync(lootData.path);
        size = stat.size;

        // Only read text files under 1MB
        if (size < 1024 * 1024) {
          try {
            content = fs.readFileSync(lootData.path, 'utf-8');
          } catch {
            // Binary file, skip content reading
          }
        }
      }

      // Detect patterns in content
      let detectedPatterns: PatternType[] = [];
      let extractedData: Record<string, string> = {};
      let contentPreview: string | undefined;

      if (content) {
        const detection = detectPatterns(content);
        detectedPatterns = detection.patterns;
        extractedData = detection.matches;
        contentPreview = content.slice(0, 500);

        // Update type based on patterns
        if (detectedPatterns.includes('kerberos_hash') || detectedPatterns.includes('ntlm_hash')) {
          type = 'hash';
        } else if (detectedPatterns.includes('ssh_key')) {
          type = 'key';
        } else if (detectedPatterns.includes('gpp_password') || detectedPatterns.includes('connection_string')) {
          type = 'config';
        }
      }

      const query = `
        MATCH (e:Engagement {id: $engagementId})
        CREATE (l:Loot {
          id: $id,
          type: $type,
          name: $name,
          path: $path,
          sourcePath: $sourcePath,
          sourceSessionId: $sourceSessionId,
          targetId: $targetId,
          engagementId: $engagementId,
          contentPreview: $contentPreview,
          size: $size,
          detectedPatterns: $detectedPatterns,
          extractedData: $extractedData,
          createdAt: $createdAt,
          notes: $notes
        })
        MERGE (e)-[:HAS_LOOT]->(l)
        WITH l
        OPTIONAL MATCH (t:Target {id: $targetId})
        FOREACH (_ IN CASE WHEN t IS NOT NULL THEN [1] ELSE [] END |
          MERGE (l)-[:FROM_TARGET]->(t)
        )
        OPTIONAL MATCH (s:TerminalSession {id: $sourceSessionId})
        FOREACH (_ IN CASE WHEN s IS NOT NULL THEN [1] ELSE [] END |
          MERGE (l)-[:DISCOVERED_BY]->(s)
        )
        RETURN l
      `;

      const params = {
        id,
        type,
        name: lootData.name,
        path: lootData.path,
        sourcePath: lootData.sourcePath || '',
        sourceSessionId: lootData.sourceSessionId,
        targetId: lootData.targetId,
        engagementId: lootData.engagementId,
        contentPreview: contentPreview || '',
        size: size || 0,
        detectedPatterns,
        extractedData: JSON.stringify(extractedData),
        createdAt,
        notes: lootData.notes || '',
      };

      await runWrite(query, params);

      const newLoot: Loot = {
        id,
        type,
        name: lootData.name,
        path: lootData.path,
        sourcePath: lootData.sourcePath,
        sourceSessionId: lootData.sourceSessionId,
        targetId: lootData.targetId,
        engagementId: lootData.engagementId,
        contentPreview,
        size,
        detectedPatterns,
        extractedData,
        createdAt,
        notes: lootData.notes,
      };

      debug.ipc('loot-add completed', {
        id,
        type,
        patterns: detectedPatterns,
      });
      return newLoot;
    } catch (error) {
      debug.error('loot-add failed', error);
      throw error;
    }
  });

  // Get loot content (for preview)
  ipcMain.handle('loot-get-content', async (_, id: string) => {
    debug.ipc('loot-get-content called', { id });

    try {
      const query = `
        MATCH (l:Loot {id: $id})
        RETURN l.path AS path
      `;
      const results = await runQuery(query, { id });

      if (results.length === 0) {
        return null;
      }

      const filePath = results[0].path as string;

      if (!fs.existsSync(filePath)) {
        return { error: 'File not found', path: filePath };
      }

      const stat = fs.statSync(filePath);

      // Limit to 100KB for preview
      if (stat.size > 100 * 1024) {
        const content = fs.readFileSync(filePath, 'utf-8').slice(0, 100 * 1024);
        return { content, truncated: true, size: stat.size };
      }

      const content = fs.readFileSync(filePath, 'utf-8');
      return { content, truncated: false, size: stat.size };
    } catch (error) {
      debug.error('loot-get-content failed', error);
      return { error: String(error) };
    }
  });

  // Delete loot
  ipcMain.handle('loot-delete', async (_, id: string, deleteFile: boolean = false) => {
    debug.ipc('loot-delete called', { id, deleteFile });

    try {
      if (deleteFile) {
        const query = `
          MATCH (l:Loot {id: $id})
          RETURN l.path AS path
        `;
        const results = await runQuery(query, { id });

        if (results.length > 0 && fs.existsSync(results[0].path as string)) {
          fs.unlinkSync(results[0].path as string);
        }
      }

      const query = `
        MATCH (l:Loot {id: $id})
        DETACH DELETE l
      `;
      await runWrite(query, { id });

      debug.ipc('loot-delete completed', { id });
      return true;
    } catch (error) {
      debug.error('loot-delete failed', error);
      return false;
    }
  });

  // Get loot with specific patterns (for Quick Actions)
  ipcMain.handle('loot-by-pattern', async (_, engagementId: string, pattern: PatternType) => {
    debug.ipc('loot-by-pattern called', { engagementId, pattern });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_LOOT]->(l:Loot)
        WHERE $pattern IN l.detectedPatterns
        RETURN l
        ORDER BY l.created_at DESC
      `;
      const results = await runQuery(query, { engagementId, pattern });
      const loot = results.map((r: any) => r.l.properties);

      debug.ipc('loot-by-pattern completed', { count: loot.length });
      return loot;
    } catch (error) {
      debug.error('loot-by-pattern failed', error);
      return [];
    }
  });

  // Get flags only
  ipcMain.handle('loot-get-flags', async (_, engagementId: string) => {
    debug.ipc('loot-get-flags called', { engagementId });

    try {
      const query = `
        MATCH (e:Engagement {id: $engagementId})-[:HAS_LOOT]->(l:Loot)
        WHERE l.type = 'flag'
        OPTIONAL MATCH (l)-[:FROM_TARGET]->(t:Target)
        RETURN l, t.ip AS targetIp
        ORDER BY l.created_at DESC
      `;
      const results = await runQuery(query, { engagementId });
      const flags = results.map((r: any) => ({
        ...r.l.properties,
        targetIp: r.targetIp,
      }));

      debug.ipc('loot-get-flags completed', { count: flags.length });
      return flags;
    } catch (error) {
      debug.error('loot-get-flags failed', error);
      return [];
    }
  });

  // Update loot notes
  ipcMain.handle('loot-update-notes', async (_, id: string, notes: string) => {
    debug.ipc('loot-update-notes called', { id });

    try {
      const query = `
        MATCH (l:Loot {id: $id})
        SET l.notes = $notes
        RETURN l
      `;
      await runWrite(query, { id, notes });
      debug.ipc('loot-update-notes completed');
      return true;
    } catch (error) {
      debug.error('loot-update-notes failed', error);
      return false;
    }
  });

  // Extract credential from loot file (PRISM integration)
  ipcMain.handle('loot-extract', async (
    _,
    lootId: string,
    pattern: PatternType,
    engagementId: string,
    targetId?: string
  ) => {
    debug.ipc('loot-extract called', { lootId, pattern, engagementId });

    try {
      // 1. Get loot file path from Neo4j
      const pathQuery = `
        MATCH (l:Loot {id: $lootId})
        RETURN l.path AS path, l.name AS name
      `;
      const pathResults = await runQuery(pathQuery, { lootId });

      if (pathResults.length === 0) {
        return { success: false, error: 'Loot not found' };
      }

      const filePath = pathResults[0].path as string;
      const lootName = pathResults[0].name as string;

      // 2. Read file content
      if (!fs.existsSync(filePath)) {
        return { success: false, error: `File not found: ${filePath}` };
      }

      const content = fs.readFileSync(filePath, 'utf-8');

      // 3. Extract using PRISM loot-extractor
      const result = await extractFromLoot(content, pattern, {
        engagementId,
        targetId,
        lootId,
        lootName,
      });

      debug.ipc('loot-extract completed', {
        success: result.success,
        hasCredential: !!result.credential,
        hasHash: !!result.hash,
      });

      return result;
    } catch (error) {
      debug.error('loot-extract failed', error);
      return { success: false, error: String(error) };
    }
  });

  debug.ipc('Loot IPC handlers registered');
}
