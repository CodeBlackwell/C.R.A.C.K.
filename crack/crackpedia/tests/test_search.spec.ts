/**
 * Tests for Crackpedia Command Search IPC Handlers
 *
 * Business Value Focus:
 * - Users search for commands by name, description, or command text
 * - Filter by category, subcategory, OSCP relevance, and tags
 * - Search must be case-insensitive and handle punctuation variations
 *
 * TIER 2: FUNCTIONAL CORRECTNESS - Search must find relevant commands
 * TIER 3: EDGE CASE HANDLING - Handle empty queries, special characters
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  clearIpcRegistry,
  invokeHandler,
} from './__mocks__/electron';
import {
  createMockDriver,
  setMockDriver,
  MockDriver,
} from './__mocks__/neo4j-driver';

// Mock modules
vi.mock('electron', () => import('./__mocks__/electron'));
vi.mock('neo4j-driver', () => import('./__mocks__/neo4j-driver'));
vi.mock('fs', () => ({
  existsSync: vi.fn(() => true),
  readdirSync: vi.fn(() => []),
}));
vi.mock('path', () => ({
  resolve: vi.fn((...args: string[]) => args.join('/')),
  extname: vi.fn((file: string) => {
    const match = file.match(/\.[^.]+$/);
    return match ? match[0] : '';
  }),
}));

describe('search-commands Handler', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  describe('Basic Search', () => {
    it('BV: Users can search commands by name', async () => {
      /**
       * Scenario:
       *   Given: Commands with "nmap" in their names exist in Neo4j
       *   When: User searches for "nmap"
       *   Then: Returns matching commands with id, name, category, description
       */
      mockDriver = createMockDriver({
        records: [
          {
            id: 'nmap-basic',
            name: 'Nmap Basic Scan',
            category: 'recon',
            description: 'Basic port scan',
            tags: ['OSCP:HIGH', 'network'],
            oscp_relevance: true,
          },
          {
            id: 'nmap-service',
            name: 'Nmap Service Detection',
            category: 'recon',
            description: 'Service version detection',
            tags: ['OSCP:HIGH', 'enumeration'],
            oscp_relevance: true,
          },
        ],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', 'nmap');

      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBe(2);
      expect(results[0]).toHaveProperty('id');
      expect(results[0]).toHaveProperty('name');
      expect(results[0]).toHaveProperty('category');
      expect(results[0]).toHaveProperty('description');
    });

    it('BV: Empty search query returns all commands (for browsing)', async () => {
      /**
       * Scenario:
       *   Given: Commands exist in Neo4j
       *   When: User searches with empty string
       *   Then: Returns all commands (up to limit)
       */
      mockDriver = createMockDriver({
        records: [
          { id: 'cmd-1', name: 'Command 1', category: 'test', description: 'Test' },
          { id: 'cmd-2', name: 'Command 2', category: 'test', description: 'Test' },
        ],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', '');

      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBe(2);
    });

    it('BV: Search with whitespace-only query treated as empty', async () => {
      /**
       * Scenario:
       *   Given: User enters only spaces in search box
       *   When: search-commands is called with "   "
       *   Then: Returns all commands (whitespace trimmed)
       */
      mockDriver = createMockDriver({
        records: [{ id: 'cmd-1', name: 'Test', category: 'test', description: 'Test' }],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', '   ');

      expect(Array.isArray(results)).toBe(true);
      // Query should execute without error
    });

    it('BV: Search by description finds relevant commands', async () => {
      /**
       * Scenario:
       *   Given: Command has "kerberoasting" in description but not in name
       *   When: User searches for "kerberoasting"
       *   Then: Command is found by description match
       */
      mockDriver = createMockDriver({
        records: [
          {
            id: 'tgs-attack',
            name: 'GetUserSPNs',
            category: 'post-exploit',
            description: 'Kerberoasting attack to extract TGS tickets',
            tags: ['OSCP:HIGH'],
            oscp_relevance: true,
          },
        ],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', 'kerberoasting');

      expect(results.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Filter by Category', () => {
    it('BV: Users can filter commands by category', async () => {
      /**
       * Scenario:
       *   Given: Commands in different categories exist
       *   When: User filters by category "recon"
       *   Then: Only recon commands are returned
       */
      mockDriver = createMockDriver({
        records: [
          { id: 'nmap-1', name: 'Nmap Scan', category: 'recon', description: 'Test' },
        ],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', '', { category: 'recon' });

      expect(Array.isArray(results)).toBe(true);
      // Verify query was called with category filter
      const session = mockDriver.sessions[0];
      expect(session.queries[0].params).toHaveProperty('category', 'recon');
    });

    it('BV: Users can filter by subcategory', async () => {
      /**
       * Scenario:
       *   Given: Commands with subcategories exist
       *   When: User filters by subcategory "port-scanning"
       *   Then: Only matching subcategory commands returned
       */
      mockDriver = createMockDriver({
        records: [
          {
            id: 'nmap-tcp',
            name: 'Nmap TCP Scan',
            category: 'recon',
            subcategory: 'port-scanning',
            description: 'TCP port scan',
          },
        ],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', '', {
        category: 'recon',
        subcategory: 'port-scanning',
      });

      const session = mockDriver.sessions[0];
      expect(session.queries[0].params).toHaveProperty('subcategory', 'port-scanning');
    });

    it('BV: "General" subcategory matches empty or null subcategory', async () => {
      /**
       * Scenario:
       *   Given: Commands without subcategory exist
       *   When: User filters by subcategory "General"
       *   Then: Commands with empty/null subcategory are returned
       */
      mockDriver = createMockDriver({
        records: [{ id: 'cmd-1', name: 'Test', category: 'test', subcategory: '' }],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', '', {
        subcategory: 'General',
      });

      // Query should include condition for empty subcategory
      const session = mockDriver.sessions[0];
      expect(session.queries[0].query).toContain('subcategory');
    });
  });

  describe('OSCP Relevance Filter', () => {
    it('BV: Users can filter to only OSCP-relevant commands', async () => {
      /**
       * Scenario:
       *   Given: Commands with varying OSCP relevance exist
       *   When: User filters with oscp_only=true
       *   Then: Only OSCP-relevant commands returned
       */
      mockDriver = createMockDriver({
        records: [
          { id: 'cmd-oscp', name: 'OSCP Tool', oscp_relevance: true },
        ],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', '', { oscp_only: true });

      const session = mockDriver.sessions[0];
      expect(session.queries[0].query).toContain('oscp_relevance');
    });
  });

  describe('Tag Filtering', () => {
    it('BV: Users can filter commands by tags', async () => {
      /**
       * Scenario:
       *   Given: Commands with various tags exist
       *   When: User filters by tags ["network", "enumeration"]
       *   Then: Commands with those tags are returned
       */
      mockDriver = createMockDriver({
        records: [
          { id: 'cmd-1', name: 'Network Scan', tags: ['network', 'enumeration'] },
        ],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', '', {
        tags: ['network', 'enumeration'],
      });

      const session = mockDriver.sessions[0];
      expect(session.queries[0].params).toHaveProperty('tags');
      expect(session.queries[0].params.tags).toEqual(['network', 'enumeration']);
    });

    it('BV: Empty tags array does not filter by tags', async () => {
      /**
       * Scenario:
       *   Given: Tags filter is empty array
       *   When: search-commands is called
       *   Then: Tag filter is not applied
       */
      mockDriver = createMockDriver({
        records: [{ id: 'cmd-1', name: 'Test' }],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', '', { tags: [] });

      const session = mockDriver.sessions[0];
      expect(session.queries[0].query).not.toContain('TAGGED');
    });
  });

  describe('Combined Filters', () => {
    it('BV: Users can combine search query with multiple filters', async () => {
      /**
       * Scenario:
       *   Given: User wants specific command type
       *   When: Searching "scan" with category "recon" and oscp_only
       *   Then: All conditions are applied
       */
      mockDriver = createMockDriver({
        records: [
          {
            id: 'nmap-oscp',
            name: 'Nmap OSCP Scan',
            category: 'recon',
            oscp_relevance: true,
          },
        ],
      });
      setMockDriver(mockDriver);

      await import('../src/main/neo4j');

      const results = await invokeHandler('search-commands', 'scan', {
        category: 'recon',
        oscp_only: true,
      });

      const session = mockDriver.sessions[0];
      const query = session.queries[0].query;

      expect(query).toContain('toLower');  // Search condition
      expect(query).toContain('category');  // Category filter
      expect(query).toContain('oscp_relevance');  // OSCP filter
      expect(session.queries[0].params).toHaveProperty('searchQuery', 'scan');
      expect(session.queries[0].params).toHaveProperty('category', 'recon');
    });
  });
});

describe('get-category-hierarchy Handler', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Category hierarchy enables navigation sidebar', async () => {
    /**
     * Scenario:
     *   Given: Commands organized in categories/subcategories
     *   When: get-category-hierarchy is called
     *   Then: Returns structured hierarchy with counts
     */
    mockDriver = createMockDriver({
      records: [
        {
          category: 'recon',
          subcategories: [
            { name: '', count: { low: 5, high: 0, toNumber: () => 5 } },
            { name: 'port-scanning', count: { low: 10, high: 0, toNumber: () => 10 } },
          ],
          totalCount: { low: 15, high: 0, toNumber: () => 15 },
        },
        {
          category: 'post-exploit',
          subcategories: [
            { name: 'credential-discovery', count: { low: 8, high: 0, toNumber: () => 8 } },
          ],
          totalCount: { low: 8, high: 0, toNumber: () => 8 },
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('get-category-hierarchy');

    expect(Array.isArray(results)).toBe(true);
    expect(results.length).toBe(2);
    expect(results[0]).toHaveProperty('category');
    expect(results[0]).toHaveProperty('subcategories');
    expect(results[0]).toHaveProperty('totalCount');
  });

  it('BV: Empty subcategories are labeled as "General"', async () => {
    /**
     * Scenario:
     *   Given: Commands without subcategory exist
     *   When: get-category-hierarchy is called
     *   Then: Empty subcategory name becomes "General"
     */
    mockDriver = createMockDriver({
      records: [
        {
          category: 'test',
          subcategories: [
            { name: '', count: 5 },
          ],
          totalCount: 5,
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('get-category-hierarchy');

    expect(results[0].subcategories[0].name).toBe('General');
  });
});

describe('search-cheatsheets Handler', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Users can search cheatsheets by name', async () => {
    /**
     * Scenario:
     *   Given: Cheatsheets exist in Neo4j
     *   When: User searches for "linux"
     *   Then: Matching cheatsheets are returned
     */
    mockDriver = createMockDriver({
      records: [
        {
          id: 'linux-privesc',
          name: 'Linux Privilege Escalation',
          description: 'Common privesc techniques',
          tags: 'linux|privesc|OSCP',
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-cheatsheets', 'linux');

    expect(Array.isArray(results)).toBe(true);
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0]).toHaveProperty('id');
    expect(results[0]).toHaveProperty('name');
  });

  it('BV: Pipe-separated tags are split into array', async () => {
    /**
     * Scenario:
     *   Given: Cheatsheet has tags as pipe-separated string
     *   When: search-cheatsheets is called
     *   Then: Tags are converted to array
     */
    mockDriver = createMockDriver({
      records: [
        {
          id: 'test-sheet',
          name: 'Test Sheet',
          description: 'Test',
          tags: 'tag1|tag2|tag3',
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-cheatsheets', '');

    expect(Array.isArray(results[0].tags)).toBe(true);
    expect(results[0].tags).toEqual(['tag1', 'tag2', 'tag3']);
  });

  it('BV: Filter cheatsheets by tags', async () => {
    /**
     * Scenario:
     *   Given: User wants cheatsheets with specific tags
     *   When: Filter by tags is applied
     *   Then: Query includes tag condition
     */
    mockDriver = createMockDriver({
      records: [{ id: 'filtered', name: 'Filtered', tags: 'linux' }],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-cheatsheets', '', {
      tags: ['linux', 'privesc'],
    });

    const session = mockDriver.sessions[0];
    expect(session.queries[0].params).toHaveProperty('tags');
  });
});

describe('search-chains Handler', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Users can search attack chains', async () => {
    /**
     * Scenario:
     *   Given: Attack chains exist in Neo4j
     *   When: User searches for "kerberos"
     *   Then: Matching chains are returned
     */
    mockDriver = createMockDriver({
      records: [
        {
          id: 'kerberoast-chain',
          name: 'Kerberoasting Attack Chain',
          description: 'Full kerberoasting workflow',
          category: 'active_directory',
          platform: 'Windows',
          difficulty: 'Medium',
          time_estimate: '30 minutes',
          oscp_relevant: true,
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-chains', 'kerberos');

    expect(Array.isArray(results)).toBe(true);
    expect(results[0]).toHaveProperty('id');
    expect(results[0]).toHaveProperty('name');
    expect(results[0]).toHaveProperty('platform');
    expect(results[0]).toHaveProperty('difficulty');
  });

  it('BV: Filter chains by category', async () => {
    /**
     * Scenario:
     *   Given: User wants chains in specific category
     *   When: Category filter is applied
     *   Then: Only matching category chains returned
     */
    mockDriver = createMockDriver({
      records: [
        { id: 'ad-chain', name: 'AD Chain', category: 'active_directory' },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-chains', '', {
      category: 'active_directory',
    });

    const session = mockDriver.sessions[0];
    expect(session.queries[0].params).toHaveProperty('category', 'active_directory');
  });

  it('BV: Category "all" does not filter by category', async () => {
    /**
     * Scenario:
     *   Given: User selects "all" category
     *   When: search-chains is called
     *   Then: Category filter is not applied
     */
    mockDriver = createMockDriver({
      records: [{ id: 'chain', name: 'Chain' }],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-chains', '', { category: 'all' });

    const session = mockDriver.sessions[0];
    expect(session.queries[0].params).not.toHaveProperty('category');
  });
});

describe('search-writeups Handler', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Users can search writeups by name or synopsis', async () => {
    /**
     * Scenario:
     *   Given: Writeups exist in Neo4j
     *   When: User searches for "hackthebox"
     *   Then: Matching writeups are returned
     */
    mockDriver = createMockDriver({
      records: [
        {
          id: 'htb-machine',
          name: 'HackTheBox Machine',
          platform: 'HackTheBox',
          difficulty: 'Medium',
          oscp_relevance: 'HIGH',
          machine_type: 'Linux',
          os: 'Linux',
          total_duration_minutes: 120,
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-writeups', 'hackthebox');

    expect(Array.isArray(results)).toBe(true);
    expect(results[0]).toHaveProperty('id');
    expect(results[0]).toHaveProperty('platform');
    expect(results[0]).toHaveProperty('difficulty');
  });

  it('BV: Filter writeups by platform', async () => {
    /**
     * Scenario:
     *   Given: Writeups from different platforms exist
     *   When: User filters by platform "HackTheBox"
     *   Then: Only HackTheBox writeups returned
     */
    mockDriver = createMockDriver({
      records: [{ id: 'htb', name: 'HTB Machine', platform: 'HackTheBox' }],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-writeups', '', {
      platform: 'HackTheBox',
    });

    const session = mockDriver.sessions[0];
    expect(session.queries[0].params).toHaveProperty('platform', 'HackTheBox');
  });

  it('BV: Filter writeups by difficulty', async () => {
    /**
     * Scenario:
     *   Given: Writeups with varying difficulty exist
     *   When: User filters by difficulty "Easy"
     *   Then: Only Easy writeups returned
     */
    mockDriver = createMockDriver({
      records: [{ id: 'easy', name: 'Easy Box', difficulty: 'Easy' }],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-writeups', '', {
      difficulty: 'Easy',
    });

    const session = mockDriver.sessions[0];
    expect(session.queries[0].params).toHaveProperty('difficulty', 'Easy');
  });

  it('BV: Filter writeups by OSCP relevance', async () => {
    /**
     * Scenario:
     *   Given: Writeups with OSCP relevance ratings exist
     *   When: User filters by oscp_relevance "HIGH"
     *   Then: Only highly relevant writeups returned
     */
    mockDriver = createMockDriver({
      records: [{ id: 'oscp-high', name: 'OSCP Relevant', oscp_relevance: 'HIGH' }],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-writeups', '', {
      oscp_relevance: 'HIGH',
    });

    const session = mockDriver.sessions[0];
    expect(session.queries[0].params).toHaveProperty('oscp_relevance', 'HIGH');
  });

  it('BV: Filter writeups by OS', async () => {
    /**
     * Scenario:
     *   Given: Writeups for different operating systems exist
     *   When: User filters by os "Windows"
     *   Then: Only Windows writeups returned
     */
    mockDriver = createMockDriver({
      records: [{ id: 'win', name: 'Windows Box', os: 'Windows' }],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-writeups', '', { os: 'Windows' });

    const session = mockDriver.sessions[0];
    expect(session.queries[0].params).toHaveProperty('os', 'Windows');
  });

  it('BV: Filter writeups by exam applicability', async () => {
    /**
     * Scenario:
     *   Given: Writeups with exam_applicable flag exist
     *   When: User filters by exam_applicable=true
     *   Then: Only exam-applicable writeups returned
     */
    mockDriver = createMockDriver({
      records: [{ id: 'exam', name: 'Exam Prep', exam_applicable: true }],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const results = await invokeHandler('search-writeups', '', {
      exam_applicable: true,
    });

    const session = mockDriver.sessions[0];
    expect(session.queries[0].params).toHaveProperty('exam_applicable', true);
  });
});
