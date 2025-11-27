import { useState, useEffect, useCallback } from 'react';
import { MantineProvider, AppShell, Text, Badge, Group, Paper, Center, Code, Stack, Divider, SegmentedControl, Button } from '@mantine/core';
import '@mantine/core/styles.css';
import CommandSearch from './components/CommandSearch';
import CheatsheetView from './components/CheatsheetView';
import CheatsheetDetails from './components/CheatsheetDetails';
import CheatsheetCommandList from './components/CheatsheetCommandList';
import ChainView from './components/ChainView';
import ChainDetails from './components/ChainDetails';
import ChainGraphView from './components/ChainGraphView';
import ChainStepDetails from './components/ChainStepDetails';
import ChainControlsPanel from './components/ChainControlsPanel';
import WriteupView from './components/WriteupView';
import WriteupDetails from './components/WriteupDetails';
import WriteupControlsPanel from './components/WriteupControlsPanel';
import GraphView from './components/GraphView';
import ChainExplorerGraph, { LayoutType, Orientation } from './components/ChainExplorerGraph';
import RelationshipsTree from './components/RelationshipsTree';
import CommandDetails from './components/CommandDetails';
import CommandChainGraph from './components/CommandChainGraph';
import { Command } from './types/command';
import { Cheatsheet } from './types/cheatsheet';

type ViewMode = 'details' | 'graph' | 'tree';

// Types for explorer state (shared with ChainExplorerGraph and RelationshipsTree)
interface GraphNode {
  data: {
    id: string;
    label: string;
    name?: string;
    category?: string;
    subcategory?: string;
    description?: string;
    command?: string;
    tags?: string[];
    type?: string;
    hasRelationships?: boolean;
  };
}

interface GraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label: string;
    type: string;
  };
}

interface ExpansionRecord {
  nodeId: string;
  parentNodeId: string | null;
  relationshipType?: string;
}
type ChainViewMode = 'graph' | 'list';

function App() {
  const [selectedCommand, setSelectedCommand] = useState<Command | null>(null);
  const [selectedCheatsheet, setSelectedCheatsheet] = useState<Cheatsheet | null>(null);
  const [selectedChainId, setSelectedChainId] = useState<string | null>(null);
  const [selectedStepId, setSelectedStepId] = useState<string | null>(null);
  const [selectedWriteupId, setSelectedWriteupId] = useState<string | null>(null);
  const [chainCommandView, setChainCommandView] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<{
    connected: boolean;
    uri?: string;
  }>({ connected: false });
  const [activeView, setActiveView] = useState<'commands' | 'cheatsheets' | 'chains' | 'writeups'>(() => {
    // Load persisted view from localStorage, default to 'chains'
    const saved = localStorage.getItem('crack-activeView');
    if (saved && ['commands', 'cheatsheets', 'chains', 'writeups'].includes(saved)) {
      return saved as 'commands' | 'cheatsheets' | 'chains' | 'writeups';
    }
    return 'chains';
  });
  const [expandedCommandId, setExpandedCommandId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('details');
  const [chainViewMode, setChainViewMode] = useState<ChainViewMode>('graph');

  // Explorer state (shared between ChainExplorerGraph and RelationshipsTree)
  const [explorerNodes, setExplorerNodes] = useState<Map<string, GraphNode>>(new Map());
  const [explorerEdges, setExplorerEdges] = useState<Map<string, GraphEdge>>(new Map());
  const [explorerExpanded, setExplorerExpanded] = useState<Set<string>>(new Set());
  const [explorerHistory, setExplorerHistory] = useState<ExpansionRecord[]>([]);
  const [highlightedNodeId, setHighlightedNodeId] = useState<string | null>(null);
  const [cleanMode, setCleanMode] = useState(true);
  const [graphLayout, setGraphLayout] = useState<LayoutType>('dagre');
  const [layoutOrientation, setLayoutOrientation] = useState<Orientation>('horizontal');

  // Debug: Log component mount
  useEffect(() => {
    console.log('[App] Component mounted');
    console.log('[App] Window dimensions:', {
      width: window.innerWidth,
      height: window.innerHeight,
    });
    console.log('[App] electronAPI available:', !!window.electronAPI);
  }, []);

  // Keyboard shortcuts for view navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Only trigger on Ctrl+Shift combinations
      if (!e.ctrlKey || !e.shiftKey) return;

      switch (e.key.toLowerCase()) {
        case 'c': // CTRL+SHIFT+C → Commands
          e.preventDefault();
          console.log('[App] Keyboard shortcut: Commands');
          setActiveView('commands');
          setSelectedChainId(null);
          setSelectedCheatsheet(null);
          setSelectedWriteupId(null);
          break;
        case 'x': // CTRL+SHIFT+X → Chains
          e.preventDefault();
          console.log('[App] Keyboard shortcut: Chains');
          setActiveView('chains');
          setSelectedCheatsheet(null);
          setSelectedCommand(null);
          setSelectedWriteupId(null);
          break;
        case 'z': // CTRL+SHIFT+Z → Cheatsheets
          e.preventDefault();
          console.log('[App] Keyboard shortcut: Cheatsheets');
          setActiveView('cheatsheets');
          setSelectedChainId(null);
          setSelectedCommand(null);
          setSelectedWriteupId(null);
          break;
        case 'w': // CTRL+SHIFT+W → Writeups
          e.preventDefault();
          console.log('[App] Keyboard shortcut: Writeups');
          setActiveView('writeups');
          setSelectedChainId(null);
          setSelectedCheatsheet(null);
          setSelectedCommand(null);
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Debug: Log active view changes and persist to localStorage
  useEffect(() => {
    console.log('[App] Active view changed:', activeView);
    localStorage.setItem('crack-activeView', activeView);
  }, [activeView]);

  useEffect(() => {
    console.log('[App] Checking Neo4j connection...');
    // Check Neo4j connection on mount
    window.electronAPI.healthCheck()
      .then((status) => {
        console.log('[App] Health check result:', status);
        setConnectionStatus(status);
        if (!status.connected) {
          console.error('[App] Failed to connect to Neo4j:', status.error);
        }
      })
      .catch((error) => {
        console.error('[App] Health check error:', error);
        setConnectionStatus({ connected: false, uri: 'Error' });
      });
  }, []);

  const handleCommandSelect = async (commandId: string) => {
    console.log('[App] Command selected:', commandId);
    try {
      const command = await window.electronAPI.getCommand(commandId);
      console.log('[App] Command data received:', command ? command.name : 'null');
      setSelectedCommand(command);
      setSelectedCheatsheet(null); // Clear cheatsheet when selecting command
    } catch (error) {
      console.error('[App] Error fetching command:', error);
    }
  };

  const handleCheatsheetSelect = async (cheatsheetId: string) => {
    console.log('[App] Cheatsheet selected:', cheatsheetId);
    try {
      const cheatsheet = await window.electronAPI.getCheatsheet(cheatsheetId);
      console.log('[App] Cheatsheet data received:', cheatsheet ? cheatsheet.name : 'null');
      setSelectedCheatsheet(cheatsheet);
      setSelectedCommand(null); // Clear command when selecting cheatsheet
      setExpandedCommandId(null); // Clear expanded command when selecting new cheatsheet
    } catch (error) {
      console.error('[App] Error fetching cheatsheet:', error);
    }
  };

  const handleChainSelect = (chainId: string) => {
    console.log('[App] Chain selected:', chainId);
    setSelectedChainId(chainId);
    setSelectedCommand(null); // Clear command when selecting chain
    setSelectedCheatsheet(null); // Clear cheatsheet when selecting chain
    setChainCommandView(null); // Clear chain command view when selecting new chain
  };

  const handleWriteupSelect = (writeupId: string) => {
    console.log('[App] Writeup selected:', writeupId);
    setSelectedWriteupId(writeupId);
    setSelectedCommand(null); // Clear command when selecting writeup
    setSelectedCheatsheet(null); // Clear cheatsheet when selecting writeup
    setSelectedChainId(null); // Clear chain when selecting writeup
  };

  const handleChainCommandClick = useCallback((commandId: string) => {
    console.log('[App] Chain command clicked:', commandId);
    setChainCommandView(commandId);
  }, []);

  const handleCommandBadgeClick = useCallback((commandId: string) => {
    console.log('[App] Command badge clicked:', commandId);
    setExpandedCommandId(commandId);
  }, []);

  const handleStepClick = useCallback((stepId: string) => {
    console.log('[App] ========== Step Click Handler START ==========');
    console.log('[App] Step clicked:', stepId);
    setSelectedStepId(stepId);
    console.log('[App] setSelectedStepId called with:', stepId);
    console.log('[App] ========== Step Click Handler END ==========');
    // Keep graph visible - user can manually switch tabs if desired
  }, []);

  const handleClearStep = useCallback(() => {
    console.log('[App] Clearing selected step');
    setSelectedStepId(null);
    setChainCommandView(null); // Clear chain command view when clearing step
  }, []);

  // Explorer state callbacks (for ChainExplorerGraph to emit state changes)
  const handleExplorerStateChange = useCallback((
    nodes: Map<string, GraphNode>,
    edges: Map<string, GraphEdge>,
    expanded: Set<string>,
    history: ExpansionRecord[]
  ) => {
    console.log('[App] Explorer state updated:', {
      nodes: nodes.size,
      edges: edges.size,
      expanded: expanded.size,
      history: history.length,
    });
    setExplorerNodes(nodes);
    setExplorerEdges(edges);
    setExplorerExpanded(expanded);
    setExplorerHistory(history);
  }, []);

  // Find descendant nodes for removal
  const findDescendantNodes = useCallback((nodeId: string, history: ExpansionRecord[]): Set<string> => {
    const descendants = new Set<string>();
    const findChildren = (parentId: string) => {
      history.forEach(record => {
        if (record.parentNodeId === parentId && !descendants.has(record.nodeId)) {
          descendants.add(record.nodeId);
          findChildren(record.nodeId);
        }
      });
    };
    findChildren(nodeId);
    return descendants;
  }, []);

  // Tree callbacks
  const handleTreeNodeClick = useCallback((nodeId: string) => {
    console.log('[App] Tree node clicked - highlighting:', nodeId);
    setHighlightedNodeId(nodeId);
    // Clear highlight after a short delay
    setTimeout(() => setHighlightedNodeId(null), 2000);
  }, []);

  const handleTreeNodeRemove = useCallback(async (nodeId: string) => {
    console.log('[App] ========== REMOVING NODE ==========');
    console.log('[App] Removing node from tree:', nodeId);
    console.log('[App] Current state before removal:', {
      nodesCount: explorerNodes.size,
      expandedCount: explorerExpanded.size,
      historyCount: explorerHistory.length,
    });

    // Find all descendants to remove (nodes in expansion history)
    const nodesToRemove = findDescendantNodes(nodeId, explorerHistory);
    nodesToRemove.add(nodeId);

    // Update expanded set and history first
    const newExpanded = new Set(explorerExpanded);
    nodesToRemove.forEach(id => {
      newExpanded.delete(id);
    });
    let newHistory = explorerHistory.filter(r => !nodesToRemove.has(r.nodeId));

    // Track if we're promoting a new root (need to load its relationships)
    let newRootId: string | null = null;
    let newRootGraphData: any = null;

    // If no expanded nodes remain, promote a connected node as new root
    if (newExpanded.size === 0) {
      // Find direct connections of the removed node that are still visible
      const connectedNodes: string[] = [];
      explorerEdges.forEach((edge) => {
        if (edge.data.source === nodeId && explorerNodes.has(edge.data.target) && !nodesToRemove.has(edge.data.target)) {
          connectedNodes.push(edge.data.target);
        }
        if (edge.data.target === nodeId && explorerNodes.has(edge.data.source) && !nodesToRemove.has(edge.data.source)) {
          connectedNodes.push(edge.data.source);
        }
      });

      // Promote the first connected node as new root
      if (connectedNodes.length > 0) {
        newRootId = connectedNodes[0];
        newExpanded.add(newRootId);
        newHistory = [{ nodeId: newRootId, parentNodeId: null }];
        console.log('[App] Promoted new root:', newRootId);

        // Fetch the new root's relationships
        try {
          newRootGraphData = await window.electronAPI.getGraphWithMetadata(newRootId);
          console.log('[App] Fetched new root relationships:', newRootGraphData);
        } catch (error) {
          console.error('[App] Error fetching new root relationships:', error);
        }
      }
    }

    // Build new nodes and edges
    let newNodes = new Map<string, GraphNode>();
    let newEdges = new Map<string, GraphEdge>();

    // If we have a new root with data, build from that
    if (newRootId && newRootGraphData?.elements) {
      // Add all nodes from new root's graph
      newRootGraphData.elements.nodes.forEach((node: GraphNode) => {
        newNodes.set(node.data.id, node);
      });
      // Add all edges from new root's graph
      newRootGraphData.elements.edges.forEach((edge: GraphEdge) => {
        newEdges.set(edge.data.id, edge);
      });
    } else {
      // No new root promotion - use BFS from remaining expanded nodes
      newEdges = new Map(explorerEdges);
      newEdges.forEach((edge, key) => {
        if (nodesToRemove.has(edge.data.source) || nodesToRemove.has(edge.data.target)) {
          newEdges.delete(key);
        }
      });

      // BFS to find all nodes reachable from remaining expanded nodes
      const reachableNodes = new Set<string>();
      const toVisit = Array.from(newExpanded);
      while (toVisit.length > 0) {
        const current = toVisit.pop()!;
        if (reachableNodes.has(current)) continue;
        reachableNodes.add(current);

        // Find connected nodes via remaining edges
        newEdges.forEach((edge) => {
          if (edge.data.source === current && !reachableNodes.has(edge.data.target)) {
            toVisit.push(edge.data.target);
          }
          if (edge.data.target === current && !reachableNodes.has(edge.data.source)) {
            toVisit.push(edge.data.source);
          }
        });
      }

      // Keep only reachable nodes
      newNodes = new Map(explorerNodes);
      newNodes.forEach((_, id) => {
        if (!reachableNodes.has(id)) {
          newNodes.delete(id);
        }
      });
    }

    console.log('[App] Node removal complete:', {
      removed: nodesToRemove.size,
      remaining: newNodes.size,
      newExpandedSize: newExpanded.size,
      newHistoryLength: newHistory.length,
      newRoot: newRootId,
    });
    console.log('[App] ========== SETTING NEW STATE ==========');

    setExplorerNodes(newNodes);
    setExplorerEdges(newEdges);
    setExplorerExpanded(newExpanded);
    setExplorerHistory(newHistory);
  }, [explorerNodes, explorerEdges, explorerExpanded, explorerHistory, findDescendantNodes]);

  const handleTreeNodeSelect = useCallback((nodeId: string) => {
    console.log('[App] Tree node selected for details:', nodeId);
    handleCommandSelect(nodeId);
  }, []);

  const handleClearAllTree = useCallback(() => {
    console.log('[App] Clearing all tree nodes');
    setExplorerNodes(new Map());
    setExplorerEdges(new Map());
    setExplorerExpanded(new Set());
    setExplorerHistory([]);
  }, []);

  // Debug: Log state changes
  useEffect(() => {
    console.log('[App] Selected command changed:', selectedCommand?.id || 'none');
  }, [selectedCommand]);

  // Reset view mode to details when command changes
  useEffect(() => {
    setViewMode('details');
    console.log('[App] View mode reset to details');
  }, [selectedCommand?.id]);

  // Reset chain view mode to graph when chain changes
  useEffect(() => {
    setChainViewMode('graph');
    setSelectedStepId(null); // Clear selected step when chain changes
    console.log('[App] Chain view mode reset to graph, step cleared');
  }, [selectedChainId]);

  // Track selectedStepId changes
  useEffect(() => {
    console.log('[App] ========== selectedStepId changed:', selectedStepId, '==========');
    console.log('[App] Current state after stepId change:', {
      selectedChainId,
      chainViewMode,
      selectedStepId,
      selectedCheatsheet: !!selectedCheatsheet,
    });
  }, [selectedStepId]);

  return (
    <MantineProvider
      defaultColorScheme="dark"
      theme={{
        primaryColor: 'cyan',
        fontFamily: 'Inter, system-ui, sans-serif',
        fontFamilyMonospace: 'JetBrains Mono, Monaco, Courier, monospace',
      }}
    >
      <AppShell
        header={{ height: 40 }}
        padding="md"
        styles={{
          main: {
            background: '#1a1b1e',
          },
        }}
      >
        <AppShell.Header
          style={{
            background: '#25262b',
            borderBottom: '1px solid #373A40',
            display: 'flex',
            alignItems: 'center',
            paddingLeft: '16px',
            paddingRight: '16px',
          }}
        >
          <Group justify="space-between" style={{ width: '100%' }}>
            <Text
              size="lg"
              fw={700}
              style={{
                background: 'linear-gradient(45deg, #22c1c3, #fdbb2d)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              CRACK // Command Graph Visualizer
            </Text>
            <Badge
              color={connectionStatus.connected ? 'teal' : 'red'}
              variant="light"
            >
              {connectionStatus.connected ? `Connected: ${connectionStatus.uri}` : 'Disconnected'}
            </Badge>
          </Group>
        </AppShell.Header>

        <AppShell.Main>
          <div style={{ display: 'flex', height: 'calc(100vh - 80px)', gap: '16px' }}>
            {/* Left Panel: Navigation */}
            <div style={{ width: '350px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {/* Navigation Header - 2 Row Layout */}
              <Paper
                p="xs"
                style={{
                  background: '#25262b',
                  border: '1px solid #373A40',
                }}
              >
                <Stack gap="xs">
                  {/* Row 1: Cheatsheets, Chains, Commands */}
                  <Group gap="xs" grow>
                    <Button
                      size="sm"
                      variant={activeView === 'cheatsheets' ? 'filled' : 'subtle'}
                      color={activeView === 'cheatsheets' ? 'cyan' : 'gray'}
                      onClick={() => {
                        setActiveView('cheatsheets');
                        // Clear other selections so center panel shows cheatsheets view
                        setSelectedChainId(null);
                        setSelectedCommand(null);
                        setSelectedWriteupId(null);
                      }}
                      style={{ flex: 1 }}
                    >
                      Cheatsheets
                    </Button>
                    <Button
                      size="sm"
                      variant={activeView === 'chains' ? 'filled' : 'subtle'}
                      color={activeView === 'chains' ? 'cyan' : 'gray'}
                      onClick={() => {
                        setActiveView('chains');
                        // Clear other selections so center panel shows chains view
                        setSelectedCheatsheet(null);
                        setSelectedCommand(null);
                        setSelectedWriteupId(null);
                      }}
                      style={{ flex: 1 }}
                    >
                      Chains
                    </Button>
                    <Button
                      size="sm"
                      variant={activeView === 'commands' ? 'filled' : 'subtle'}
                      color={activeView === 'commands' ? 'cyan' : 'gray'}
                      onClick={() => {
                        setActiveView('commands');
                        // Clear other selections so center panel shows commands view
                        setSelectedChainId(null);
                        setSelectedCheatsheet(null);
                        setSelectedWriteupId(null);
                      }}
                      style={{ flex: 1 }}
                    >
                      Commands
                    </Button>
                  </Group>
                  {/* Row 2: Writeups (full width) */}
                  <Button
                    size="sm"
                    variant={activeView === 'writeups' ? 'filled' : 'subtle'}
                    color={activeView === 'writeups' ? 'cyan' : 'gray'}
                    onClick={() => {
                      setActiveView('writeups');
                      // Clear other selections so center panel shows writeups view
                      setSelectedChainId(null);
                      setSelectedCheatsheet(null);
                      setSelectedCommand(null);
                    }}
                    fullWidth
                  >
                    Writeups
                  </Button>
                </Stack>
              </Paper>

              {/* Conditional View Rendering */}
              <div style={{ flex: 1, overflow: 'hidden' }}>
                {activeView === 'commands' && (
                  <CommandSearch onSelectCommand={handleCommandSelect} />
                )}
                {activeView === 'cheatsheets' && (
                  <CheatsheetView onSelectCheatsheet={handleCheatsheetSelect} />
                )}
                {activeView === 'chains' && (
                  <ChainView onSelectChain={handleChainSelect} />
                )}
                {activeView === 'writeups' && (
                  <WriteupView onSelectWriteup={handleWriteupSelect} />
                )}
              </div>
            </div>

            {/* Center Panel: Graph or Chain Graph based on view mode */}
            {!selectedCheatsheet && !selectedChainId && !selectedWriteupId && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {selectedCommand ? (
                  <>
                    <div style={{ flex: 1 }}>
                      {viewMode === 'details' || viewMode === 'tree' ? (
                        // Details/Tree mode: Show Chain Explorer (interactive relationship graph)
                        <ChainExplorerGraph
                          initialCommandId={selectedCommand.id}
                          onCommandSelect={handleCommandSelect}
                          onStateChange={handleExplorerStateChange}
                          highlightedNodeId={highlightedNodeId}
                          externalNodes={explorerNodes}
                          externalEdges={explorerEdges}
                          externalExpanded={explorerExpanded}
                          externalHistory={explorerHistory}
                          cleanMode={cleanMode}
                          onCleanModeChange={setCleanMode}
                          layout={graphLayout}
                          orientation={layoutOrientation}
                          onLayoutChange={setGraphLayout}
                          onOrientationChange={setLayoutOrientation}
                        />
                      ) : (
                        // Graph mode: Show attack chains (larger space)
                        <CommandChainGraph commandId={selectedCommand.id} />
                      )}
                    </div>

                    {/* Footer: Tags & Output Indicators (only in details/tree mode) */}
                    {(viewMode === 'details' || viewMode === 'tree') && (
                      <Paper
                        style={{
                          background: '#25262b',
                          border: '1px solid #373A40',
                          padding: '12px 16px',
                        }}
                      >
                        <Stack gap="md">
                          {/* Tags */}
                          {selectedCommand.tags && selectedCommand.tags.length > 0 && (
                            <div>
                              <Text size="xs" fw={600} mb="xs" c="dimmed">
                                Tags
                              </Text>
                              <Group gap="xs" wrap="wrap">
                                {selectedCommand.tags.map((tag) => (
                                  <Badge key={tag} variant="light" color="gray" size="sm">
                                    {tag}
                                  </Badge>
                                ))}
                              </Group>
                            </div>
                          )}

                          {/* Output Indicators */}
                          {selectedCommand.indicators && selectedCommand.indicators.length > 0 && (
                            <>
                              {selectedCommand.tags && selectedCommand.tags.length > 0 && <Divider />}
                              <div>
                                <Text size="xs" fw={600} mb="xs" c="dimmed">
                                  Output Indicators
                                </Text>
                                <Group gap="xs" wrap="wrap">
                                  {selectedCommand.indicators.map((indicator, idx) => {
                                    // Determine color based on indicator type
                                    const isPositive = ['success', 'positive', 'valid', 'found'].includes(
                                      indicator.type?.toLowerCase() || ''
                                    );
                                    const color = isPositive ? 'green' : 'red';

                                    return (
                                      <Badge
                                        key={idx}
                                        size="sm"
                                        color={color}
                                        variant="light"
                                        style={{
                                          cursor: 'default',
                                          fontFamily: 'monospace',
                                        }}
                                      >
                                        {indicator.pattern}
                                      </Badge>
                                    );
                                  })}
                                </Group>
                              </div>
                            </>
                          )}
                        </Stack>
                      </Paper>
                    )}
                  </>
                ) : (
                  <Paper
                    style={{
                      background: '#25262b',
                      border: '1px solid #373A40',
                      height: '100%',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Text c="dimmed" size="sm">
                      Select a command to view its relationship graph
                    </Text>
                  </Paper>
                )}
              </div>
            )}

            {/* Center Panel when cheatsheet selected: Cheatsheet Details */}
            {selectedCheatsheet && (
              <div style={{ flex: 1, height: '100%' }}>
                <CheatsheetDetails
                  cheatsheet={selectedCheatsheet}
                  onCommandClick={handleCommandBadgeClick}
                />
              </div>
            )}

            {/* Center Panel when chain selected: Chain Graph or List View */}
            {(() => {
              const shouldShowCenterPanel = selectedChainId && !selectedCheatsheet;
              console.log('[App] [RENDER] Center panel evaluation:', {
                selectedChainId,
                selectedCheatsheet: !!selectedCheatsheet,
                shouldShowCenterPanel,
                chainViewMode,
                selectedStepId,
              });
              return shouldShowCenterPanel ? (
                <div style={{ flex: 1, height: '100%' }}>
                  {chainViewMode === 'graph' ? (
                    <>
                      {console.log('[App] [RENDER] Rendering ChainGraphView for chain:', selectedChainId)}
                      <ChainGraphView
                        chainId={selectedChainId}
                        onCommandClick={handleChainCommandClick}
                        onStepClick={handleStepClick}
                        onCommandDoubleClick={handleChainCommandClick}
                      />
                    </>
                  ) : (
                    <>
                      {console.log('[App] [RENDER] Rendering ChainDetails for chain:', selectedChainId)}
                      <ChainDetails
                        chainId={selectedChainId}
                        onCommandClick={handleChainCommandClick}
                      />
                    </>
                  )}
                </div>
              ) : null;
            })()}

            {/* Center Panel when writeup selected: Writeup Details */}
            {selectedWriteupId && (
              <div style={{ flex: 1, height: '100%' }}>
                <WriteupDetails writeupId={selectedWriteupId} />
              </div>
            )}

            {/* Right Panel: Command Details, Graph View, or Tree based on view mode */}
            <div style={{ width: '450px', height: '100%' }}>
              {selectedCommand ? (
                <Paper
                  shadow="sm"
                  style={{
                    background: '#25262b',
                    border: '1px solid #373A40',
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    overflow: 'hidden',
                  }}
                >
                  {/* Header with view mode toggle - 3 tabs */}
                  <Group gap="xs" p="md" style={{ borderBottom: '1px solid #373A40' }}>
                    <Button
                      size="xs"
                      variant={viewMode === 'details' ? 'filled' : 'subtle'}
                      color="gray"
                      onClick={() => {
                        setViewMode('details');
                        console.log('[App] View mode changed to: details');
                      }}
                    >
                      Details
                    </Button>
                    <Button
                      size="xs"
                      variant={viewMode === 'graph' ? 'filled' : 'subtle'}
                      color="gray"
                      onClick={() => {
                        setViewMode('graph');
                        console.log('[App] View mode changed to: graph');
                      }}
                    >
                      Graph View
                    </Button>
                    <Button
                      size="xs"
                      variant={viewMode === 'tree' ? 'filled' : 'subtle'}
                      color="gray"
                      onClick={() => {
                        setViewMode('tree');
                        console.log('[App] View mode changed to: tree');
                      }}
                    >
                      Tree {explorerExpanded.size > 0 && `(${explorerExpanded.size})`}
                    </Button>
                  </Group>

                  {/* Content based on view mode */}
                  <div style={{ flex: 1, overflow: 'hidden' }}>
                    {viewMode === 'details' ? (
                      <CommandDetails
                        command={selectedCommand}
                        viewMode={viewMode}
                        onViewModeChange={setViewMode}
                        onCommandSelect={handleCommandSelect}
                        hideHeader={true}
                      />
                    ) : viewMode === 'graph' ? (
                      <GraphView
                        selectedCommandId={selectedCommand.id}
                        onNodeClick={handleCommandSelect}
                      />
                    ) : (
                      <RelationshipsTree
                        nodes={explorerNodes}
                        expandedNodes={explorerExpanded}
                        expansionHistory={explorerHistory}
                        onNodeClick={handleTreeNodeClick}
                        onNodeRemove={handleTreeNodeRemove}
                        onNodeSelect={handleTreeNodeSelect}
                        onClearAll={handleClearAllTree}
                      />
                    )}
                  </div>
                </Paper>
              ) : selectedCheatsheet ? (
                <CheatsheetCommandList
                  cheatsheet={selectedCheatsheet}
                  expandedCommandId={expandedCommandId}
                />
              ) : selectedChainId ? (
                <ChainControlsPanel
                  chainId={selectedChainId}
                  chainViewMode={chainViewMode}
                  onViewModeChange={setChainViewMode}
                  selectedStepId={selectedStepId}
                  onCommandClick={handleChainCommandClick}
                  onClearStep={handleClearStep}
                  onStepClick={handleStepClick}
                  chainCommandView={chainCommandView}
                  onCommandViewBack={() => {
                    console.log('[App] Clearing chain command view');
                    setChainCommandView(null);
                  }}
                />
              ) : selectedWriteupId ? (
                <WriteupControlsPanel writeupId={selectedWriteupId} />
              ) : (
                <Paper
                  shadow="sm"
                  p="md"
                  style={{
                    background: '#25262b',
                    border: '1px solid #373A40',
                    height: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Center>
                    <Text c="dimmed" size="sm" style={{ textAlign: 'center' }}>
                      Select a command, chain, cheatsheet, or writeup to view details
                    </Text>
                  </Center>
                </Paper>
              )}
            </div>
          </div>
        </AppShell.Main>
      </AppShell>
    </MantineProvider>
  );
}

export default App;
