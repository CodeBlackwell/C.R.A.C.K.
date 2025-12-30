/**
 * Tests for Crackpedia Graph Data IPC Handlers
 *
 * Business Value Focus:
 * - Users visualize command relationships in graph view
 * - Node/edge formatting must be correct for Cytoscape.js
 * - Attack chain graphs show step-by-step execution flow
 *
 * TIER 2: FUNCTIONAL CORRECTNESS - Graph data must be correctly formatted
 * TIER 1: DATA INTEGRITY - All relationships must be preserved
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
  createMockNode,
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

describe('get-graph Handler', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Graph includes center node for selected command', async () => {
    /**
     * Scenario:
     *   Given: A command exists with relationships
     *   When: get-graph is called with command ID
     *   Then: Returns graph with center node marked
     */
    mockDriver = createMockDriver({
      records: [
        {
          center: { id: 'nmap-basic', name: 'Nmap Basic Scan' },
          alternatives: [],
          prerequisites: [],
          nextSteps: [],
          alternativesFrom: [],
          prerequisitesFrom: [],
          nextStepsFrom: [],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-graph', 'nmap-basic');

    expect(result).toHaveProperty('elements');
    expect(result.elements).toHaveProperty('nodes');
    expect(result.elements).toHaveProperty('edges');
    expect(Array.isArray(result.elements.nodes)).toBe(true);
    expect(result.elements.nodes.length).toBeGreaterThanOrEqual(1);

    // Center node should be marked
    const centerNode = result.elements.nodes.find(
      (n: any) => n.data.id === 'nmap-basic'
    );
    expect(centerNode).toBeDefined();
    expect(centerNode.data.type).toBe('center');
  });

  it('BV: Graph includes ALTERNATIVE relationship edges', async () => {
    /**
     * Scenario:
     *   Given: Command has ALTERNATIVE relationships
     *   When: get-graph is called
     *   Then: Edges include alternative type with correct direction
     */
    mockDriver = createMockDriver({
      records: [
        {
          center: { id: 'nmap-basic', name: 'Nmap Basic' },
          alternatives: [
            {
              source: 'nmap-basic',
              target: 'masscan-basic',
              type: 'ALTERNATIVE',
              command: { id: 'masscan-basic', name: 'Masscan Basic' },
            },
          ],
          prerequisites: [],
          nextSteps: [],
          alternativesFrom: [],
          prerequisitesFrom: [],
          nextStepsFrom: [],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-graph', 'nmap-basic');

    expect(result.elements.edges.length).toBeGreaterThanOrEqual(1);

    const altEdge = result.elements.edges.find(
      (e: any) => e.data.type === 'alternative'
    );
    expect(altEdge).toBeDefined();
    expect(altEdge.data.source).toBe('nmap-basic');
    expect(altEdge.data.target).toBe('masscan-basic');
  });

  it('BV: Graph includes PREREQUISITE relationship edges', async () => {
    /**
     * Scenario:
     *   Given: Command has PREREQUISITE relationships
     *   When: get-graph is called
     *   Then: Edges include prerequisite type
     */
    mockDriver = createMockDriver({
      records: [
        {
          center: { id: 'exploit-cmd', name: 'Exploit Command' },
          alternatives: [],
          prerequisites: [
            {
              source: 'exploit-cmd',
              target: 'enum-cmd',
              type: 'PREREQUISITE',
              command: { id: 'enum-cmd', name: 'Enumeration Command' },
            },
          ],
          nextSteps: [],
          alternativesFrom: [],
          prerequisitesFrom: [],
          nextStepsFrom: [],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-graph', 'exploit-cmd');

    const prereqEdge = result.elements.edges.find(
      (e: any) => e.data.type === 'prerequisite'
    );
    expect(prereqEdge).toBeDefined();
  });

  it('BV: Graph includes NEXT_STEP relationship edges', async () => {
    /**
     * Scenario:
     *   Given: Command has NEXT_STEP relationships
     *   When: get-graph is called
     *   Then: Edges include next_step type
     */
    mockDriver = createMockDriver({
      records: [
        {
          center: { id: 'enum-cmd', name: 'Enumeration' },
          alternatives: [],
          prerequisites: [],
          nextSteps: [
            {
              source: 'enum-cmd',
              target: 'exploit-cmd',
              type: 'NEXT_STEP',
              command: { id: 'exploit-cmd', name: 'Exploit' },
            },
          ],
          alternativesFrom: [],
          prerequisitesFrom: [],
          nextStepsFrom: [],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-graph', 'enum-cmd');

    const nextEdge = result.elements.edges.find(
      (e: any) => e.data.type === 'next_step'
    );
    expect(nextEdge).toBeDefined();
  });

  it('BV: Graph includes incoming relationships (from other commands)', async () => {
    /**
     * Scenario:
     *   Given: Other commands have relationships TO this command
     *   When: get-graph is called
     *   Then: Incoming relationships are included with reversed direction
     */
    mockDriver = createMockDriver({
      records: [
        {
          center: { id: 'target-cmd', name: 'Target Command' },
          alternatives: [],
          prerequisites: [],
          nextSteps: [],
          alternativesFrom: [
            {
              source: 'source-cmd',
              target: 'target-cmd',
              type: 'ALTERNATIVE',
              command: { id: 'source-cmd', name: 'Source Command' },
            },
          ],
          prerequisitesFrom: [],
          nextStepsFrom: [],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-graph', 'target-cmd');

    // Should have the source command as a node
    const sourceNode = result.elements.nodes.find(
      (n: any) => n.data.id === 'source-cmd'
    );
    expect(sourceNode).toBeDefined();

    // Edge should connect source to target
    expect(result.elements.edges.length).toBeGreaterThanOrEqual(1);
  });

  it('BV: Empty graph returned when command has no relationships', async () => {
    /**
     * Scenario:
     *   Given: Command exists with no relationships
     *   When: get-graph is called
     *   Then: Returns graph with only center node and no edges
     */
    mockDriver = createMockDriver({
      records: [
        {
          center: { id: 'lonely-cmd', name: 'Lonely Command' },
          alternatives: [],
          prerequisites: [],
          nextSteps: [],
          alternativesFrom: [],
          prerequisitesFrom: [],
          nextStepsFrom: [],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-graph', 'lonely-cmd');

    expect(result.elements.nodes.length).toBe(1);
    expect(result.elements.edges.length).toBe(0);
  });

  it('BV: Empty graph returned when command not found', async () => {
    /**
     * Scenario:
     *   Given: Command ID does not exist in database
     *   When: get-graph is called
     *   Then: Returns empty graph structure
     */
    mockDriver = createMockDriver({ records: [] });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-graph', 'nonexistent');

    expect(result).toEqual({
      elements: {
        nodes: [],
        edges: [],
      },
    });
  });
});

describe('get-graph-with-metadata Handler', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Nodes include hasRelationships flag for expandable indicator', async () => {
    /**
     * Scenario:
     *   Given: Command graph with nodes that have their own relationships
     *   When: get-graph-with-metadata is called
     *   Then: Nodes include hasRelationships property
     */
    mockDriver = createMockDriver({
      records: [
        {
          center: { id: 'center-cmd', name: 'Center' },
          alternatives: [
            {
              source: 'center-cmd',
              target: 'alt-cmd',
              type: 'ALTERNATIVE',
              command: { id: 'alt-cmd', name: 'Alternative' },
            },
          ],
          prerequisites: [],
          nextSteps: [],
          alternativesFrom: [],
          prerequisitesFrom: [],
          nextStepsFrom: [],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-graph-with-metadata', 'center-cmd');

    expect(result.elements.nodes.length).toBeGreaterThanOrEqual(1);

    // Center node should have hasRelationships = false (already expanded)
    const centerNode = result.elements.nodes.find(
      (n: any) => n.data.id === 'center-cmd'
    );
    expect(centerNode.data.hasRelationships).toBe(false);
  });

  it('BV: Edge IDs include relationship type for uniqueness', async () => {
    /**
     * Scenario:
     *   Given: Same command pair could have multiple relationship types
     *   When: get-graph-with-metadata is called
     *   Then: Edge IDs include type to prevent duplicates
     */
    mockDriver = createMockDriver({
      records: [
        {
          center: { id: 'cmd-a', name: 'Command A' },
          alternatives: [
            {
              source: 'cmd-a',
              target: 'cmd-b',
              type: 'ALTERNATIVE',
              command: { id: 'cmd-b', name: 'Command B' },
            },
          ],
          prerequisites: [],
          nextSteps: [],
          alternativesFrom: [],
          prerequisitesFrom: [],
          nextStepsFrom: [],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-graph-with-metadata', 'cmd-a');

    const edge = result.elements.edges[0];
    expect(edge.data.id).toContain('ALTERNATIVE');
  });
});

describe('get-chain-graph Handler', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Chain graph shows steps as nodes in order', async () => {
    /**
     * Scenario:
     *   Given: Attack chain with multiple steps
     *   When: get-chain-graph is called
     *   Then: Returns nodes for each step with order information
     */
    mockDriver = createMockDriver({
      records: [
        {
          chainName: 'Kerberoasting Chain',
          steps: [
            { id: 'step-1', name: 'Enumerate SPNs', objective: 'Find service accounts', order: 1 },
            { id: 'step-2', name: 'Request TGS', objective: 'Get ticket', order: 2 },
            { id: 'step-3', name: 'Crack Hash', objective: 'Recover password', order: 3 },
          ],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-chain-graph', 'kerberoast-chain');

    expect(result.elements.nodes.length).toBe(3);
    expect(result.elements.edges.length).toBe(2); // step1->step2, step2->step3

    // Nodes should have step labels
    const node1 = result.elements.nodes.find((n: any) => n.data.id === 'step-1');
    expect(node1.data.label).toContain('Step 1');
    expect(node1.data.type).toBe('step');
  });

  it('BV: Chain graph edges show sequential flow', async () => {
    /**
     * Scenario:
     *   Given: Attack chain with 3 steps
     *   When: get-chain-graph is called
     *   Then: Edges connect steps in sequence with NEXT type
     */
    mockDriver = createMockDriver({
      records: [
        {
          chainName: 'Test Chain',
          steps: [
            { id: 'step-1', name: 'Step 1', order: 1 },
            { id: 'step-2', name: 'Step 2', order: 2 },
          ],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-chain-graph', 'test-chain');

    expect(result.elements.edges.length).toBe(1);

    const edge = result.elements.edges[0];
    expect(edge.data.source).toBe('step-1');
    expect(edge.data.target).toBe('step-2');
    expect(edge.data.type).toBe('next');
  });

  it('BV: Empty chain graph returned when chain has no steps', async () => {
    /**
     * Scenario:
     *   Given: Attack chain with no steps
     *   When: get-chain-graph is called
     *   Then: Returns empty graph
     */
    mockDriver = createMockDriver({
      records: [{ chainName: 'Empty Chain', steps: [] }],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-chain-graph', 'empty-chain');

    expect(result.elements.nodes.length).toBe(0);
    expect(result.elements.edges.length).toBe(0);
  });

  it('BV: Empty graph returned when chain not found', async () => {
    /**
     * Scenario:
     *   Given: Chain ID does not exist
     *   When: get-chain-graph is called
     *   Then: Returns empty graph structure
     */
    mockDriver = createMockDriver({ records: [] });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-chain-graph', 'nonexistent');

    expect(result).toEqual({
      elements: {
        nodes: [],
        edges: [],
      },
    });
  });
});

describe('get-command-chains Handler', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Shows all attack chains containing a command', async () => {
    /**
     * Scenario:
     *   Given: Command is used in multiple attack chains
     *   When: get-command-chains is called
     *   Then: Returns graph with all chains and their steps
     */
    mockDriver = createMockDriver({
      records: [
        {
          chain: { id: 'chain-1', name: 'Kerberoasting' },
          steps: [
            { step: { description: 'Step 1' }, command: { id: 'target-cmd' }, isTargetCommand: false },
            { step: { description: 'Step 2' }, command: { id: 'other-cmd' }, isTargetCommand: true },
          ],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-command-chains', 'target-cmd');

    expect(result.elements.nodes.length).toBeGreaterThanOrEqual(1);
    expect(result.elements.edges.length).toBeGreaterThanOrEqual(0);
  });

  it('BV: Target command step is marked as center type', async () => {
    /**
     * Scenario:
     *   Given: Command is used in a specific step
     *   When: get-command-chains is called
     *   Then: The step using target command is marked as center
     */
    mockDriver = createMockDriver({
      records: [
        {
          chain: { id: 'chain-1', name: 'Test Chain' },
          steps: [
            { step: { description: 'Step 1' }, command: { id: 'other-cmd' }, isTargetCommand: false },
            { step: { description: 'Step 2' }, command: { id: 'target-cmd' }, isTargetCommand: true },
          ],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-command-chains', 'target-cmd');

    const targetNode = result.elements.nodes.find((n: any) => n.data.type === 'center');
    expect(targetNode).toBeDefined();
  });

  it('BV: Empty graph when command not in any chains', async () => {
    /**
     * Scenario:
     *   Given: Command is not used in any attack chains
     *   When: get-command-chains is called
     *   Then: Returns empty graph
     */
    mockDriver = createMockDriver({ records: [] });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-command-chains', 'orphan-cmd');

    expect(result).toEqual({
      elements: {
        nodes: [],
        edges: [],
      },
    });
  });
});

describe('get-command Handler (Detail Fetching)', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Returns full command details with flags and variables', async () => {
    /**
     * Scenario:
     *   Given: Command exists with flags and variables
     *   When: get-command is called
     *   Then: Returns complete command object
     */
    mockDriver = createMockDriver({
      records: [
        {
          command: {
            id: 'nmap-full',
            name: 'Nmap Full Scan',
            description: 'Complete port scan',
            command: 'nmap -sV -sC -p- <TARGET>',
            category: 'recon',
            success_indicators: '["open port", "service detected"]',
            failure_indicators: '["host seems down", "no route"]',
            troubleshooting: '{"timeout": "Increase --host-timeout"}',
          },
          flags: [{ flag: '-sV', description: 'Version detection' }],
          variables: [{ name: 'TARGET', description: 'Target IP', required: true }],
          indicators: [],
          tags: ['OSCP:HIGH', 'network'],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-command', 'nmap-full');

    expect(result).not.toBeNull();
    expect(result.id).toBe('nmap-full');
    expect(result.name).toBe('Nmap Full Scan');
    expect(result.flags.length).toBeGreaterThanOrEqual(1);
    expect(result.variables.length).toBeGreaterThanOrEqual(1);
    expect(Array.isArray(result.success_indicators)).toBe(true);
    expect(Array.isArray(result.failure_indicators)).toBe(true);
  });

  it('BV: Parses JSON fields from string storage', async () => {
    /**
     * Scenario:
     *   Given: Command has JSON fields stored as strings
     *   When: get-command is called
     *   Then: JSON fields are parsed to objects/arrays
     */
    mockDriver = createMockDriver({
      records: [
        {
          command: {
            id: 'json-cmd',
            name: 'JSON Test',
            troubleshooting: '{"error1": "solution1"}',
            flag_explanations: '{"flag1": "explanation1"}',
            prerequisites: '["prereq1", "prereq2"]',
            alternatives: '["alt1", "alt2"]',
            examples: '[{"description": "Example 1", "command": "cmd"}]',
          },
          flags: [],
          variables: [],
          indicators: [],
          tags: [],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-command', 'json-cmd');

    expect(typeof result.troubleshooting).toBe('object');
    expect(typeof result.flag_explanations).toBe('object');
    expect(Array.isArray(result.prerequisites)).toBe(true);
    expect(Array.isArray(result.alternatives)).toBe(true);
    expect(Array.isArray(result.examples)).toBe(true);
  });

  it('BV: Returns null when command not found', async () => {
    /**
     * Scenario:
     *   Given: Command ID does not exist
     *   When: get-command is called
     *   Then: Returns null
     */
    mockDriver = createMockDriver({ records: [] });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-command', 'nonexistent');

    expect(result).toBeNull();
  });

  it('BV: Filters out empty flags and variables', async () => {
    /**
     * Scenario:
     *   Given: Query returns null/empty relationships
     *   When: get-command is called
     *   Then: Empty items are filtered from arrays
     */
    mockDriver = createMockDriver({
      records: [
        {
          command: { id: 'filter-test', name: 'Filter Test' },
          flags: [{ flag: null }, { flag: '-v' }, {}],
          variables: [{ name: null }, { name: 'VAR' }],
          indicators: [{ pattern: null }],
          tags: [null, 'valid-tag', ''],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-command', 'filter-test');

    expect(result.flags.length).toBe(1);
    expect(result.flags[0].flag).toBe('-v');
    expect(result.variables.length).toBe(1);
    expect(result.variables[0].name).toBe('VAR');
    expect(result.tags.length).toBe(1);
    expect(result.tags[0]).toBe('valid-tag');
  });
});

describe('get-chain Handler (Chain Details)', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Returns chain with all steps and linked commands', async () => {
    /**
     * Scenario:
     *   Given: Attack chain with steps linked to commands
     *   When: get-chain is called
     *   Then: Returns chain object with populated steps
     */
    mockDriver = createMockDriver({
      records: [
        {
          ac: {
            id: 'kerb-chain',
            name: 'Kerberoasting',
            description: 'Full kerberoasting attack',
            platform: 'Windows',
            difficulty: 'Medium',
          },
          steps: [
            {
              step: {
                properties: {
                  id: 'step-1',
                  name: 'Enumerate SPNs',
                  objective: 'Find service accounts',
                  order: 1,
                },
              },
              command: {
                properties: {
                  id: 'getuserspns',
                  name: 'GetUserSPNs',
                  command: 'GetUserSPNs.py ...',
                },
              },
            },
          ],
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-chain', 'kerb-chain');

    expect(result).not.toBeNull();
    expect(result.id).toBe('kerb-chain');
    expect(result.name).toBe('Kerberoasting');
    expect(result.steps.length).toBe(1);
    expect(result.steps[0].id).toBe('step-1');
    expect(result.steps[0].command).not.toBeNull();
    expect(result.steps[0].command.id).toBe('getuserspns');
  });

  it('BV: Returns null when chain not found', async () => {
    /**
     * Scenario:
     *   Given: Chain ID does not exist
     *   When: get-chain is called
     *   Then: Returns null
     */
    mockDriver = createMockDriver({ records: [] });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-chain', 'nonexistent');

    expect(result).toBeNull();
  });
});

describe('get-cheatsheet Handler (Cheatsheet Details)', () => {
  let mockDriver: MockDriver;

  beforeEach(() => {
    clearIpcRegistry();
    vi.clearAllMocks();
  });

  afterEach(() => {
    setMockDriver(null);
    vi.resetModules();
  });

  it('BV: Returns cheatsheet with parsed JSON fields', async () => {
    /**
     * Scenario:
     *   Given: Cheatsheet with JSON-serialized sections
     *   When: get-cheatsheet is called
     *   Then: Returns cheatsheet with parsed sections
     */
    mockDriver = createMockDriver({
      records: [
        {
          id: 'linux-privesc',
          name: 'Linux Privilege Escalation',
          description: 'Common Linux privesc techniques',
          tags: 'linux|privesc|OSCP',
          educational_header: JSON.stringify({
            how_to_recognize: ['SUID binaries', 'Weak permissions'],
            when_to_look_for: ['After initial shell'],
          }),
          scenarios: JSON.stringify([
            { name: 'SUID Exploitation', difficulty: 'Easy' },
          ]),
          sections: JSON.stringify([
            { title: 'Introduction', content: 'Overview of Linux privesc' },
          ]),
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-cheatsheet', 'linux-privesc');

    expect(result).not.toBeNull();
    expect(result.id).toBe('linux-privesc');
    expect(Array.isArray(result.tags)).toBe(true);
    expect(result.tags).toContain('linux');
    expect(typeof result.educational_header).toBe('object');
    expect(Array.isArray(result.scenarios)).toBe(true);
    expect(Array.isArray(result.sections)).toBe(true);
  });

  it('BV: Returns null when cheatsheet not found', async () => {
    /**
     * Scenario:
     *   Given: Cheatsheet ID does not exist
     *   When: get-cheatsheet is called
     *   Then: Returns null
     */
    mockDriver = createMockDriver({ records: [] });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-cheatsheet', 'nonexistent');

    expect(result).toBeNull();
  });

  it('BV: Handles malformed JSON gracefully', async () => {
    /**
     * Scenario:
     *   Given: Cheatsheet has invalid JSON in fields
     *   When: get-cheatsheet is called
     *   Then: Returns cheatsheet with default empty values
     */
    mockDriver = createMockDriver({
      records: [
        {
          id: 'malformed',
          name: 'Malformed Cheatsheet',
          description: 'Test',
          tags: 'test',
          educational_header: 'not valid json {',
          scenarios: 'also not json [',
          sections: null,
        },
      ],
    });
    setMockDriver(mockDriver);

    await import('../src/main/neo4j');

    const result = await invokeHandler('get-cheatsheet', 'malformed');

    expect(result).not.toBeNull();
    // Should have default values instead of crashing
    expect(result.scenarios).toEqual([]);
    expect(result.sections).toEqual([]);
  });
});
