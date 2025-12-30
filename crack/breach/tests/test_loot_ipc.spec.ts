/**
 * Loot IPC Handler Tests
 *
 * Business Value Focus (TIER 3: EDGE CASE HANDLING - Medium):
 * - Loot file tracking with pattern detection
 * - Automatic categorization (flag, hash, key, config)
 * - File content preview and extraction
 * - Credential extraction from loot files (PRISM integration)
 *
 * Tests protect against:
 * - Lost loot file references
 * - Incorrect pattern detection
 * - File content corruption
 * - Extraction failures
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ipcMain } from 'electron';
import * as fs from 'fs';
import {
  runQuery,
  runWrite,
  setMockQueryResults,
  setMockQueryError,
  setMockWriteError,
  resetNeo4jMocks,
  createMockLootResult,
  capturedQueries,
  getLastQuery,
} from './__mocks__/neo4j';
import {
  capturedHandlers,
  invokeHandler,
  resetElectronMocks,
} from './__mocks__/electron';

// Mock all dependencies
vi.mock('@shared/neo4j/query', () => import('./__mocks__/neo4j'));
vi.mock('electron', () => import('./__mocks__/electron'));
vi.mock('../src/main/debug', () => ({
  debug: {
    ipc: vi.fn(),
    error: vi.fn(),
  },
}));
vi.mock('@shared/types/loot', () => ({
  detectPatterns: vi.fn((content: string) => {
    const patterns: string[] = [];
    const matches: Record<string, string> = {};

    if (content.includes('cpassword=')) {
      patterns.push('gpp_password');
      matches.gpp_password = 'encrypted-value';
    }
    if (content.includes('$krb5tgs$')) {
      patterns.push('kerberos_hash');
      matches.kerberos_hash = '$krb5tgs$test';
    }
    if (content.includes('-----BEGIN RSA PRIVATE KEY-----')) {
      patterns.push('ssh_key');
    }
    if (content.includes('HTB{')) {
      patterns.push('flag');
      const match = content.match(/HTB\{[^}]+\}/);
      if (match) matches.flag = match[0];
    }

    return { patterns, matches };
  }),
  isFlagFile: vi.fn((filename: string) => {
    const flagFiles = ['user.txt', 'root.txt', 'proof.txt', 'local.txt', 'flag.txt'];
    return flagFiles.some(f => filename.toLowerCase().endsWith(f));
  }),
  generateLootId: vi.fn(() => `loot-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`),
  LOOT_PATTERNS: [],
  FLAG_FILENAMES: ['user.txt', 'root.txt', 'proof.txt', 'local.txt', 'flag.txt'],
}));
vi.mock('../src/main/parser', () => ({
  extractFromLoot: vi.fn(async (content, pattern, context) => ({
    success: true,
    credential: pattern === 'gpp_password' ? {
      id: 'cred-extracted',
      username: 'extracted_user',
      secret: 'decrypted_password',
      secretType: 'gpp',
    } : null,
    hash: pattern === 'kerberos_hash' ? {
      type: 'kerberos',
      hash: '$krb5tgs$test',
    } : null,
  })),
}));

// Mock fs module
vi.mock('fs', () => ({
  existsSync: vi.fn(() => true),
  readFileSync: vi.fn(() => 'mock file content'),
  statSync: vi.fn(() => ({ size: 1024 })),
  unlinkSync: vi.fn(),
}));

let registerLootHandlers: () => void;

beforeEach(async () => {
  resetElectronMocks();
  resetNeo4jMocks();
  vi.clearAllMocks();

  const module = await import('../src/main/ipc/loot');
  registerLootHandlers = module.registerLootHandlers;
  registerLootHandlers();
});

afterEach(() => {
  vi.clearAllMocks();
});

// ============================================================================
// loot-list Handler Tests
// ============================================================================

describe('loot-list handler', () => {
  describe('BV: Users can view all loot for an engagement', () => {
    it('should return all loot for specified engagement', async () => {
      /**
       * BV: Users see complete loot inventory
       *
       * Scenario:
       *   Given: Engagement has multiple loot items
       *   When: loot-list is called
       *   Then: All loot items are returned with metadata
       */
      const mockLoot = [
        createMockLootResult({ id: 'loot-1', name: 'user.txt', type: 'flag' }),
        createMockLootResult({ id: 'loot-2', name: 'Groups.xml', type: 'config' }),
      ];
      setMockQueryResults(mockLoot);

      const result = await invokeHandler<any[]>('loot-list', 'eng-123');

      expect(result).toHaveLength(2);
      expect(result[0]).toHaveProperty('id', 'loot-1');
      expect(result[1]).toHaveProperty('id', 'loot-2');
    });

    it('should include target information in results', async () => {
      /**
       * BV: Users know which target loot came from
       */
      const mockLoot = [
        createMockLootResult({
          id: 'loot-1',
          targetIp: '192.168.1.100',
          targetHostname: 'DC01',
        }),
      ];
      setMockQueryResults(mockLoot);

      const result = await invokeHandler<any[]>('loot-list', 'eng-123');

      expect(result[0]).toHaveProperty('targetIp', '192.168.1.100');
      expect(result[0]).toHaveProperty('targetHostname', 'DC01');
    });

    it('should order by creation date descending', async () => {
      /**
       * BV: Most recent loot appears first
       */
      setMockQueryResults([]);

      await invokeHandler('loot-list', 'eng-123');

      const query = getLastQuery();
      expect(query?.query.toLowerCase()).toContain('order by');
      expect(query?.query.toLowerCase()).toContain('desc');
    });

    it('should return empty array when no loot exists', async () => {
      /**
       * BV: Empty state handled gracefully
       */
      setMockQueryResults([]);

      const result = await invokeHandler<any[]>('loot-list', 'eng-123');

      expect(result).toEqual([]);
    });

    it('should return empty array on Neo4j error', async () => {
      /**
       * BV: Errors handled gracefully
       */
      setMockQueryError(new Error('Query failed'));

      const result = await invokeHandler<any[]>('loot-list', 'eng-123');

      expect(result).toEqual([]);
    });
  });
});

// ============================================================================
// loot-add Handler Tests
// ============================================================================

describe('loot-add handler', () => {
  const validLootData = {
    name: 'test.txt',
    path: '/tmp/loot/test.txt',
    sourcePath: '/home/user/test.txt',
    sourceSessionId: 'session-123',
    targetId: 'target-123',
    engagementId: 'eng-123',
  };

  describe('BV: Users can add loot with automatic detection', () => {
    it('should generate unique loot ID', async () => {
      /**
       * BV: Each loot item has unique identifier
       */
      const result = await invokeHandler<any>('loot-add', validLootData);

      expect(result.id).toMatch(/^loot-[a-z0-9]+-[a-z0-9]+$/);
    });

    it('should detect flag files by name', async () => {
      /**
       * BV: user.txt/root.txt automatically tagged as flags
       */
      const flagData = {
        ...validLootData,
        name: 'user.txt',
        content: '32characterflaghashgoeshere12345',
      };

      const result = await invokeHandler<any>('loot-add', flagData);

      expect(result.type).toBe('flag');
    });

    it('should detect GPP password patterns', async () => {
      /**
       * BV: Groups.xml with cpassword is flagged
       */
      (fs.readFileSync as any).mockReturnValueOnce(
        '<Groups><User cpassword="encrypted_password_here"/></Groups>'
      );

      const gppData = {
        ...validLootData,
        name: 'Groups.xml',
        content: '<Groups><User cpassword="encrypted_password_here"/></Groups>',
      };

      const result = await invokeHandler<any>('loot-add', gppData);

      expect(result.detectedPatterns).toContain('gpp_password');
    });

    it('should detect Kerberos hashes', async () => {
      /**
       * BV: Kerberoast output is flagged for cracking
       */
      const kerbData = {
        ...validLootData,
        name: 'kerberoast.txt',
        content: '$krb5tgs$23$*user$DOMAIN*$test',
      };

      const result = await invokeHandler<any>('loot-add', kerbData);

      expect(result.detectedPatterns).toContain('kerberos_hash');
      expect(result.type).toBe('hash');
    });

    it('should detect SSH private keys', async () => {
      /**
       * BV: SSH keys are identified for use
       */
      const sshData = {
        ...validLootData,
        name: 'id_rsa',
        content: '-----BEGIN RSA PRIVATE KEY-----\nMIIEow...',
      };

      const result = await invokeHandler<any>('loot-add', sshData);

      expect(result.detectedPatterns).toContain('ssh_key');
      expect(result.type).toBe('key');
    });

    it('should detect CTF flags in content', async () => {
      /**
       * BV: HTB/OSCP flags are identified
       */
      const flagData = {
        ...validLootData,
        name: 'notes.txt',
        content: 'Found the flag: HTB{s3cr3t_fl4g_h3r3}',
      };

      const result = await invokeHandler<any>('loot-add', flagData);

      expect(result.detectedPatterns).toContain('flag');
    });

    it('should include content preview for small files', async () => {
      /**
       * BV: Quick preview without opening file
       */
      const result = await invokeHandler<any>('loot-add', {
        ...validLootData,
        content: 'This is the file content that will be previewed',
      });

      expect(result.contentPreview).toBeDefined();
    });

    it('should link loot to engagement', async () => {
      /**
       * BV: Loot is scoped to engagement
       */
      await invokeHandler('loot-add', validLootData);

      const query = getLastQuery();
      expect(query?.query).toContain('HAS_LOOT');
      expect(query?.params.engagementId).toBe('eng-123');
    });

    it('should link loot to target when specified', async () => {
      /**
       * BV: Loot tracks which target it came from
       */
      await invokeHandler('loot-add', validLootData);

      const query = getLastQuery();
      expect(query?.query).toContain('FROM_TARGET');
      expect(query?.params.targetId).toBe('target-123');
    });

    it('should throw error on Neo4j failure', async () => {
      /**
       * BV: Save failures are reported
       */
      setMockWriteError(new Error('Write failed'));

      await expect(
        invokeHandler('loot-add', validLootData)
      ).rejects.toThrow('Write failed');
    });
  });
});

// ============================================================================
// loot-get-content Handler Tests
// ============================================================================

describe('loot-get-content handler', () => {
  describe('BV: Users can preview loot file content', () => {
    it('should return file content when file exists', async () => {
      /**
       * BV: File contents are accessible for analysis
       */
      setMockQueryResults([{ path: '/tmp/loot/test.txt' }]);
      (fs.readFileSync as any).mockReturnValueOnce('This is the file content');
      (fs.statSync as any).mockReturnValueOnce({ size: 25 });

      const result = await invokeHandler<any>('loot-get-content', 'loot-123');

      expect(result.content).toBe('This is the file content');
      expect(result.truncated).toBe(false);
    });

    it('should truncate large files', async () => {
      /**
       * BV: Large files don't crash the UI
       */
      setMockQueryResults([{ path: '/tmp/loot/large.bin' }]);
      (fs.statSync as any).mockReturnValueOnce({ size: 200 * 1024 }); // 200KB
      (fs.readFileSync as any).mockReturnValueOnce('A'.repeat(100 * 1024));

      const result = await invokeHandler<any>('loot-get-content', 'loot-123');

      expect(result.truncated).toBe(true);
      expect(result.size).toBe(200 * 1024);
    });

    it('should return error when file not found', async () => {
      /**
       * BV: Missing files are handled gracefully
       */
      setMockQueryResults([{ path: '/tmp/loot/missing.txt' }]);
      (fs.existsSync as any).mockReturnValueOnce(false);

      const result = await invokeHandler<any>('loot-get-content', 'loot-123');

      expect(result.error).toContain('File not found');
    });

    it('should return null when loot ID not found', async () => {
      /**
       * BV: Invalid loot IDs handled gracefully
       */
      setMockQueryResults([]);

      const result = await invokeHandler<any>('loot-get-content', 'non-existent');

      expect(result).toBeNull();
    });

    it('should return error on read failure', async () => {
      /**
       * BV: Read errors are reported
       */
      setMockQueryResults([{ path: '/tmp/loot/test.txt' }]);
      (fs.readFileSync as any).mockImplementationOnce(() => {
        throw new Error('Permission denied');
      });

      const result = await invokeHandler<any>('loot-get-content', 'loot-123');

      expect(result.error).toBeDefined();
    });
  });
});

// ============================================================================
// loot-delete Handler Tests
// ============================================================================

describe('loot-delete handler', () => {
  describe('BV: Users can delete loot entries', () => {
    it('should delete loot from Neo4j', async () => {
      /**
       * BV: Loot entries can be removed
       */
      const result = await invokeHandler<boolean>('loot-delete', 'loot-123');

      expect(result).toBe(true);
      const query = getLastQuery();
      expect(query?.query.toLowerCase()).toContain('delete');
      expect(query?.params.id).toBe('loot-123');
    });

    it('should delete file when deleteFile=true', async () => {
      /**
       * BV: Associated file can be deleted with entry
       */
      setMockQueryResults([{ path: '/tmp/loot/test.txt' }]);

      await invokeHandler('loot-delete', 'loot-123', true);

      expect(fs.unlinkSync).toHaveBeenCalledWith('/tmp/loot/test.txt');
    });

    it('should not delete file when deleteFile=false', async () => {
      /**
       * BV: File preserved when only removing entry
       */
      await invokeHandler('loot-delete', 'loot-123', false);

      expect(fs.unlinkSync).not.toHaveBeenCalled();
    });

    it('should use DETACH DELETE for clean removal', async () => {
      /**
       * BV: No orphaned relationships
       */
      await invokeHandler('loot-delete', 'loot-123');

      const query = getLastQuery();
      expect(query?.query.toLowerCase()).toContain('detach delete');
    });

    it('should return false on Neo4j error', async () => {
      /**
       * BV: Deletion failures are reported
       */
      setMockWriteError(new Error('Delete failed'));

      const result = await invokeHandler<boolean>('loot-delete', 'loot-123');

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// loot-by-pattern Handler Tests
// ============================================================================

describe('loot-by-pattern handler', () => {
  describe('BV: Users can find loot by detected pattern', () => {
    it('should return loot with specified pattern', async () => {
      /**
       * BV: Quick access to specific loot types (e.g., all GPP files)
       */
      const mockLoot = [
        createMockLootResult({
          id: 'loot-1',
          name: 'Groups.xml',
          detectedPatterns: ['gpp_password'],
        }),
      ];
      setMockQueryResults(mockLoot);

      const result = await invokeHandler<any[]>(
        'loot-by-pattern',
        'eng-123',
        'gpp_password'
      );

      expect(result).toHaveLength(1);
      const query = getLastQuery();
      expect(query?.params.pattern).toBe('gpp_password');
    });

    it('should return empty array when no matches', async () => {
      /**
       * BV: No pattern matches handled gracefully
       */
      setMockQueryResults([]);

      const result = await invokeHandler<any[]>(
        'loot-by-pattern',
        'eng-123',
        'ssh_key'
      );

      expect(result).toEqual([]);
    });

    it('should return empty array on Neo4j error', async () => {
      /**
       * BV: Errors handled gracefully
       */
      setMockQueryError(new Error('Query failed'));

      const result = await invokeHandler<any[]>(
        'loot-by-pattern',
        'eng-123',
        'gpp_password'
      );

      expect(result).toEqual([]);
    });
  });
});

// ============================================================================
// loot-get-flags Handler Tests
// ============================================================================

describe('loot-get-flags handler', () => {
  describe('BV: Users can quickly access captured flags', () => {
    it('should return only flag-type loot', async () => {
      /**
       * BV: Quick access to proof files for OSCP reporting
       */
      const mockFlags = [
        createMockLootResult({
          id: 'loot-1',
          name: 'user.txt',
          type: 'flag',
          targetIp: '192.168.1.100',
        }),
        createMockLootResult({
          id: 'loot-2',
          name: 'root.txt',
          type: 'flag',
          targetIp: '192.168.1.100',
        }),
      ];
      setMockQueryResults(mockFlags);

      const result = await invokeHandler<any[]>('loot-get-flags', 'eng-123');

      expect(result).toHaveLength(2);
      expect(result.every(l => l.type === 'flag')).toBe(true);
    });

    it('should include target IP for each flag', async () => {
      /**
       * BV: Know which machine each flag came from
       */
      const mockFlags = [
        createMockLootResult({
          name: 'user.txt',
          type: 'flag',
          targetIp: '192.168.1.100',
        }),
      ];
      setMockQueryResults(mockFlags);

      const result = await invokeHandler<any[]>('loot-get-flags', 'eng-123');

      expect(result[0]).toHaveProperty('targetIp', '192.168.1.100');
    });

    it('should query by type=flag', async () => {
      /**
       * BV: Filter to flags only
       */
      setMockQueryResults([]);

      await invokeHandler('loot-get-flags', 'eng-123');

      const query = getLastQuery();
      expect(query?.query).toContain("l.type = 'flag'");
    });

    it('should return empty array on Neo4j error', async () => {
      /**
       * BV: Errors handled gracefully
       */
      setMockQueryError(new Error('Query failed'));

      const result = await invokeHandler<any[]>('loot-get-flags', 'eng-123');

      expect(result).toEqual([]);
    });
  });
});

// ============================================================================
// loot-update-notes Handler Tests
// ============================================================================

describe('loot-update-notes handler', () => {
  describe('BV: Users can add notes to loot', () => {
    it('should update loot notes', async () => {
      /**
       * BV: Context can be added to loot items
       */
      const result = await invokeHandler<boolean>(
        'loot-update-notes',
        'loot-123',
        'Decrypted with gpp-decrypt'
      );

      expect(result).toBe(true);
      const query = getLastQuery();
      expect(query?.params.notes).toBe('Decrypted with gpp-decrypt');
    });

    it('should return false on Neo4j error', async () => {
      /**
       * BV: Update failures are reported
       */
      setMockWriteError(new Error('Update failed'));

      const result = await invokeHandler<boolean>(
        'loot-update-notes',
        'loot-123',
        'Test notes'
      );

      expect(result).toBe(false);
    });
  });
});

// ============================================================================
// loot-extract Handler Tests
// ============================================================================

describe('loot-extract handler', () => {
  describe('BV: Users can extract credentials from loot files', () => {
    it('should extract GPP password and return credential', async () => {
      /**
       * BV: Auto-decrypt GPP passwords from Groups.xml
       */
      setMockQueryResults([{
        path: '/tmp/loot/Groups.xml',
        name: 'Groups.xml',
      }]);
      (fs.readFileSync as any).mockReturnValueOnce(
        '<Groups><User cpassword="encrypted"/></Groups>'
      );

      const result = await invokeHandler<any>(
        'loot-extract',
        'loot-123',
        'gpp_password',
        'eng-123',
        'target-123'
      );

      expect(result.success).toBe(true);
      expect(result.credential).toBeDefined();
      expect(result.credential.secretType).toBe('gpp');
    });

    it('should extract Kerberos hash and return hash data', async () => {
      /**
       * BV: Extract hashes for offline cracking
       */
      setMockQueryResults([{
        path: '/tmp/loot/kerberoast.txt',
        name: 'kerberoast.txt',
      }]);
      (fs.readFileSync as any).mockReturnValueOnce('$krb5tgs$23$*user$DOMAIN*$test');

      const result = await invokeHandler<any>(
        'loot-extract',
        'loot-123',
        'kerberos_hash',
        'eng-123'
      );

      expect(result.success).toBe(true);
      expect(result.hash).toBeDefined();
      expect(result.hash.type).toBe('kerberos');
    });

    it('should return error when loot not found', async () => {
      /**
       * BV: Missing loot handled gracefully
       */
      setMockQueryResults([]);

      const result = await invokeHandler<any>(
        'loot-extract',
        'non-existent',
        'gpp_password',
        'eng-123'
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Loot not found');
    });

    it('should return error when file not found', async () => {
      /**
       * BV: Missing files handled gracefully
       */
      setMockQueryResults([{ path: '/tmp/loot/missing.xml', name: 'missing.xml' }]);
      (fs.existsSync as any).mockReturnValueOnce(false);

      const result = await invokeHandler<any>(
        'loot-extract',
        'loot-123',
        'gpp_password',
        'eng-123'
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('File not found');
    });
  });
});

// ============================================================================
// Handler Registration Tests
// ============================================================================

describe('Handler Registration', () => {
  it('should register all loot handlers', () => {
    /**
     * BV: All loot operations available via IPC
     */
    const expectedHandlers = [
      'loot-list',
      'loot-add',
      'loot-get-content',
      'loot-delete',
      'loot-by-pattern',
      'loot-get-flags',
      'loot-update-notes',
      'loot-extract',
    ];

    for (const handler of expectedHandlers) {
      expect(capturedHandlers.has(handler)).toBe(true);
    }
  });
});

// ============================================================================
// Edge Cases
// ============================================================================

describe('Edge Cases', () => {
  describe('BV: Special file types', () => {
    it('should handle binary files gracefully', async () => {
      /**
       * BV: Binary files don't crash pattern detection
       */
      (fs.readFileSync as any).mockImplementationOnce(() => {
        throw new Error('Not UTF-8');
      });
      (fs.statSync as any).mockReturnValueOnce({ size: 1024 });
      (fs.existsSync as any).mockReturnValueOnce(true);

      // Should not throw
      const result = await invokeHandler<any>('loot-add', {
        name: 'binary.exe',
        path: '/tmp/loot/binary.exe',
        sourceSessionId: 'session-123',
        targetId: 'target-123',
        engagementId: 'eng-123',
      });

      expect(result).toHaveProperty('id');
    });

    it('should handle empty files', async () => {
      /**
       * BV: Empty files don't crash
       */
      (fs.readFileSync as any).mockReturnValueOnce('');
      (fs.statSync as any).mockReturnValueOnce({ size: 0 });

      const result = await invokeHandler<any>('loot-add', {
        name: 'empty.txt',
        path: '/tmp/loot/empty.txt',
        sourceSessionId: 'session-123',
        targetId: 'target-123',
        engagementId: 'eng-123',
        content: '',
      });

      expect(result).toHaveProperty('id');
      expect(result.detectedPatterns).toEqual([]);
    });
  });

  describe('BV: Special characters in paths', () => {
    it('should handle spaces in file paths', async () => {
      /**
       * BV: Windows paths with spaces work
       */
      const result = await invokeHandler<any>('loot-add', {
        name: 'my file.txt',
        path: '/tmp/loot/my file.txt',
        sourcePath: 'C:\\Users\\John Doe\\Documents\\my file.txt',
        sourceSessionId: 'session-123',
        targetId: 'target-123',
        engagementId: 'eng-123',
      });

      expect(result.path).toBe('/tmp/loot/my file.txt');
      expect(result.sourcePath).toBe('C:\\Users\\John Doe\\Documents\\my file.txt');
    });

    it('should handle unicode in file names', async () => {
      /**
       * BV: International characters preserved
       */
      const result = await invokeHandler<any>('loot-add', {
        name: 'archivo_espanol.txt',
        path: '/tmp/loot/archivo_espanol.txt',
        sourceSessionId: 'session-123',
        targetId: 'target-123',
        engagementId: 'eng-123',
      });

      expect(result.name).toBe('archivo_espanol.txt');
    });
  });

  describe('BV: Large file handling', () => {
    it('should skip content reading for files over 1MB', async () => {
      /**
       * BV: Large files don't cause memory issues
       */
      (fs.statSync as any).mockReturnValueOnce({ size: 2 * 1024 * 1024 }); // 2MB
      (fs.existsSync as any).mockReturnValueOnce(true);

      const result = await invokeHandler<any>('loot-add', {
        name: 'large.bin',
        path: '/tmp/loot/large.bin',
        sourceSessionId: 'session-123',
        targetId: 'target-123',
        engagementId: 'eng-123',
      });

      // Content should not be read for large files
      expect(result.detectedPatterns).toEqual([]);
    });
  });
});
