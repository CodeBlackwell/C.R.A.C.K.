import { useEffect, useRef, useState, useCallback } from 'react';
import { Paper, Text, Loader, Center, Group, Badge, Box, Stack } from '@mantine/core';
import cytoscape, { Core, EventObject } from 'cytoscape';
// @ts-ignore
import coseBilkent from 'cytoscape-cose-bilkent';

// Register layout
cytoscape.use(coseBilkent);

interface ChainExplorerGraphProps {
  initialCommandId: string;
  onCommandSelect?: (commandId: string) => void;
  // Callbacks for state synchronization with App
  onStateChange?: (
    nodes: Map<string, GraphNode>,
    edges: Map<string, GraphEdge>,
    expanded: Set<string>,
    history: ExpansionRecord[]
  ) => void;
  highlightedNodeId?: string | null;
  // External state (for when tree modifies state)
  externalNodes?: Map<string, GraphNode>;
  externalEdges?: Map<string, GraphEdge>;
  externalExpanded?: Set<string>;
  externalHistory?: ExpansionRecord[];
}

// Export types for use in App.tsx
export type { GraphNode, GraphEdge, ExpansionRecord };

interface NodeTooltipData {
  name: string;
  category: string;
  subcategory?: string;
  description: string;
  command: string;
  tags: string[];
  x: number;
  y: number;
}

interface ExpansionRecord {
  nodeId: string;
  parentNodeId: string | null;
}

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

export default function ChainExplorerGraph({
  initialCommandId,
  onCommandSelect,
  onStateChange,
  highlightedNodeId,
  externalNodes,
  externalEdges,
  externalExpanded,
  externalHistory,
}: ChainExplorerGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  // State management
  const [loading, setLoading] = useState(false);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [graphNodes, setGraphNodes] = useState<Map<string, GraphNode>>(new Map());
  const [graphEdges, setGraphEdges] = useState<Map<string, GraphEdge>>(new Map());
  const [nodesWithUnexploredRels, setNodesWithUnexploredRels] = useState<Set<string>>(new Set());
  const [expansionHistory, setExpansionHistory] = useState<ExpansionRecord[]>([]);
  const [tooltip, setTooltip] = useState<NodeTooltipData | null>(null);
  const [nodeCount, setNodeCount] = useState(0);
  const [edgeCount, setEdgeCount] = useState(0);

  // Track previous external state to detect changes from tree
  const prevExternalNodesRef = useRef<Map<string, GraphNode>>();

  // Find descendant nodes for collapse
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

  // Update Cytoscape graph visualization
  const updateCytoscapeGraph = useCallback((
    nodes: Map<string, GraphNode>,
    edges: Map<string, GraphEdge>,
    expanded: Set<string>,
    unexplored: Set<string>
  ) => {
    if (!cyRef.current) return;

    console.log('[ChainExplorer] Updating Cytoscape:', {
      nodes: nodes.size,
      edges: edges.size,
      expanded: expanded.size,
      unexplored: unexplored.size
    });

    // Store current positions
    const existingPositions = new Map<string, { x: number; y: number }>();
    cyRef.current.nodes().forEach(node => {
      existingPositions.set(node.id(), node.position());
    });

    // Clear and rebuild
    cyRef.current.elements().remove();

    // Add nodes with state metadata for styling
    nodes.forEach((node, id) => {
      const nodeData = {
        ...node,
        data: {
          ...node.data,
          expanded: expanded.has(id) ? 'true' : 'false',
          hasUnexploredRels: unexplored.has(id) ? 'true' : 'false',
        }
      };
      cyRef.current!.add(nodeData);

      // Restore position if existed
      if (existingPositions.has(id)) {
        cyRef.current!.getElementById(id).position(existingPositions.get(id)!);
      }
    });

    // Add edges
    edges.forEach(edge => {
      cyRef.current!.add(edge);
    });

    // Update counts
    setNodeCount(nodes.size);
    setEdgeCount(edges.size);

    // Apply layout with animation
    const layout = cyRef.current.layout({
      name: 'cose-bilkent',
      nodeDimensionsIncludeLabels: true,
      idealEdgeLength: 150,
      nodeRepulsion: 4500,
      gravity: 0.25,
      randomize: false,
      animate: true,
      animationDuration: 500,
      fit: true,
      padding: 50,
    } as any);

    layout.run();
  }, []);

  // Expand a node to show its relationships
  const expandNode = useCallback(async (commandId: string) => {
    console.log('[ChainExplorer] expandNode called:', commandId);

    // If already expanded, collapse instead
    if (expandedNodes.has(commandId)) {
      console.log('[ChainExplorer] Node already expanded, collapsing:', commandId);
      collapseNode(commandId);
      return;
    }

    setLoading(true);
    try {
      const graphData = await window.electronAPI.getGraphWithMetadata(commandId);
      console.log('[ChainExplorer] Graph data received:', graphData);

      if (!graphData?.elements) {
        console.warn('[ChainExplorer] No graph data returned');
        return;
      }

      // Create new state copies
      const newNodes = new Map(graphNodes);
      const newEdges = new Map(graphEdges);
      const newUnexplored = new Set(nodesWithUnexploredRels);
      const newHistory = [...expansionHistory];

      // Find the parent of the node being expanded (for tree hierarchy)
      // The parent is the node that this node was connected from
      const currentNode = graphNodes.get(commandId);
      let parentNodeId: string | null = null;

      // Find which expanded node this one is connected to (for tree hierarchy)
      graphEdges.forEach((edge) => {
        if (edge.data.target === commandId && expandedNodes.has(edge.data.source)) {
          parentNodeId = edge.data.source;
        } else if (edge.data.source === commandId && expandedNodes.has(edge.data.target)) {
          parentNodeId = edge.data.target;
        }
      });

      // Add the clicked node to expansion history (this is the deliberately expanded node)
      newHistory.push({
        nodeId: commandId,
        parentNodeId: parentNodeId,
      });

      // Process new nodes (these are connections, not deliberately expanded)
      graphData.elements.nodes.forEach((node: GraphNode) => {
        const nodeId = node.data.id;
        if (!newNodes.has(nodeId)) {
          newNodes.set(nodeId, node);
          // Mark as unexplored if it has relationships to explore
          if (node.data.hasRelationships) {
            newUnexplored.add(nodeId);
          }
          // NOTE: Don't add to history - these are just visible connections
        }
      });

      // Process new edges
      graphData.elements.edges.forEach((edge: GraphEdge) => {
        const edgeKey = edge.data.id;
        if (!newEdges.has(edgeKey)) {
          newEdges.set(edgeKey, edge);
        }
      });

      // Mark this node as expanded
      newUnexplored.delete(commandId);
      const newExpanded = new Set(expandedNodes);
      newExpanded.add(commandId);

      // Update state
      setGraphNodes(newNodes);
      setGraphEdges(newEdges);
      setExpandedNodes(newExpanded);
      setNodesWithUnexploredRels(newUnexplored);
      setExpansionHistory(newHistory);

      // Update visualization
      updateCytoscapeGraph(newNodes, newEdges, newExpanded, newUnexplored);
    } catch (error) {
      console.error('[ChainExplorer] Error expanding node:', error);
    } finally {
      setLoading(false);
    }
  }, [expandedNodes, graphNodes, graphEdges, nodesWithUnexploredRels, expansionHistory, updateCytoscapeGraph]);

  // Collapse a node (remove its descendants)
  const collapseNode = useCallback((commandId: string) => {
    console.log('[ChainExplorer] collapseNode called:', commandId);

    // Find all descendant nodes
    const nodesToRemove = findDescendantNodes(commandId, expansionHistory);
    console.log('[ChainExplorer] Nodes to remove:', Array.from(nodesToRemove));

    const newNodes = new Map(graphNodes);
    const newEdges = new Map(graphEdges);
    const newExpanded = new Set(expandedNodes);
    const newUnexplored = new Set(nodesWithUnexploredRels);

    // Remove descendant nodes
    nodesToRemove.forEach(nodeId => {
      newNodes.delete(nodeId);
      newExpanded.delete(nodeId);
      newUnexplored.delete(nodeId);
    });

    // Remove edges connected to removed nodes
    newEdges.forEach((edge, key) => {
      if (nodesToRemove.has(edge.data.source) || nodesToRemove.has(edge.data.target)) {
        newEdges.delete(key);
      }
    });

    // Mark collapsed node as unexplored again
    newExpanded.delete(commandId);
    // Check if the node has relationships (it should, since it was expanded)
    const node = newNodes.get(commandId);
    if (node) {
      newUnexplored.add(commandId);
    }

    // Clean expansion history
    const newHistory = expansionHistory.filter(r =>
      !nodesToRemove.has(r.nodeId) && r.nodeId !== commandId
    );

    // Update state
    setGraphNodes(newNodes);
    setGraphEdges(newEdges);
    setExpandedNodes(newExpanded);
    setNodesWithUnexploredRels(newUnexplored);
    setExpansionHistory(newHistory);

    // Update visualization
    updateCytoscapeGraph(newNodes, newEdges, newExpanded, newUnexplored);
  }, [expandedNodes, graphNodes, graphEdges, nodesWithUnexploredRels, expansionHistory, findDescendantNodes, updateCytoscapeGraph]);

  // Emit state changes to parent
  useEffect(() => {
    if (onStateChange && graphNodes.size > 0) {
      onStateChange(graphNodes, graphEdges, expandedNodes, expansionHistory);
    }
  }, [graphNodes, graphEdges, expandedNodes, expansionHistory, onStateChange]);

  // Sync with external state changes (when tree removes nodes)
  useEffect(() => {
    if (externalNodes && externalEdges && externalExpanded && externalHistory) {
      // Only sync if external state is smaller (nodes were removed)
      if (externalNodes.size < graphNodes.size) {
        console.log('[ChainExplorer] Syncing with external state (nodes removed):', {
          external: externalNodes.size,
          internal: graphNodes.size,
        });
        setGraphNodes(externalNodes);
        setGraphEdges(externalEdges);
        setExpandedNodes(externalExpanded);
        setExpansionHistory(externalHistory);

        // Recalculate unexplored nodes
        const newUnexplored = new Set<string>();
        externalNodes.forEach((node, id) => {
          if (!externalExpanded.has(id) && node.data.hasRelationships) {
            newUnexplored.add(id);
          }
        });
        setNodesWithUnexploredRels(newUnexplored);

        // Update visualization
        updateCytoscapeGraph(externalNodes, externalEdges, externalExpanded, newUnexplored);
      }
    }
  }, [externalNodes, externalEdges, externalExpanded, externalHistory]);

  // Handle highlighted node from tree
  useEffect(() => {
    if (highlightedNodeId && cyRef.current) {
      const node = cyRef.current.getElementById(highlightedNodeId);
      if (node.length > 0) {
        // Flash the node
        node.animate({
          style: { 'border-color': '#ff6b6b', 'border-width': '6px' },
          duration: 300,
        }).animate({
          style: { 'border-color': node.data('expanded') === 'true' ? '#22c1c3' : '#ffd43b', 'border-width': '3px' },
          duration: 300,
        });
        // Center on the node
        cyRef.current.animate({
          center: { eles: node },
          duration: 300,
        });
      }
    }
  }, [highlightedNodeId]);

  // Initialize Cytoscape
  useEffect(() => {
    if (!containerRef.current) {
      console.warn('[ChainExplorer] Container ref is null');
      return;
    }

    console.log('[ChainExplorer] Initializing Cytoscape...');
    cyRef.current = cytoscape({
      container: containerRef.current,
      style: [
        // Base node style
        {
          selector: 'node',
          style: {
            'background-color': '#373A40',
            'label': 'data(label)',
            'color': '#fff',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': '11px',
            'font-family': 'monospace',
            'width': '70px',
            'height': '70px',
            'border-width': '2px',
            'border-color': '#555',
            'text-wrap': 'wrap',
            'text-max-width': '80px',
          },
        },
        // Expanded node style (cyan)
        {
          selector: 'node[expanded="true"]',
          style: {
            'background-color': '#22c1c3',
            'border-color': '#22c1c3',
            'border-width': '3px',
          },
        },
        // Center/initial node style
        {
          selector: 'node[type="center"]',
          style: {
            'background-color': '#22c1c3',
            'border-color': '#22c1c3',
            'border-width': '3px',
            'width': '90px',
            'height': '90px',
            'font-size': '12px',
            'font-weight': 'bold',
          },
        },
        // Node with unexplored relationships - glow + dashed border
        {
          selector: 'node[hasUnexploredRels="true"]',
          style: {
            'border-style': 'dashed',
            'border-width': '3px',
            'border-color': '#ffd43b',
            // @ts-ignore - Cytoscape shadow properties
            'shadow-blur': '15px',
            'shadow-color': '#ffd43b',
            'shadow-opacity': 0.8,
            'shadow-offset-x': '0px',
            'shadow-offset-y': '0px',
          },
        },
        // Edge styles
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#555',
            'target-arrow-color': '#555',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '10px',
            'color': '#aaa',
            'text-rotation': 'autorotate',
            'text-margin-y': -10,
          },
        },
        {
          selector: 'edge[type="alternative"]',
          style: {
            'line-color': '#fdbb2d',
            'target-arrow-color': '#fdbb2d',
          },
        },
        {
          selector: 'edge[type="prerequisite"]',
          style: {
            'line-color': '#ff6b6b',
            'target-arrow-color': '#ff6b6b',
          },
        },
        {
          selector: 'edge[type="next_step"]',
          style: {
            'line-color': '#51cf66',
            'target-arrow-color': '#51cf66',
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#22c1c3',
            'border-width': '4px',
          },
        },
      ],
      layout: {
        name: 'cose-bilkent',
        nodeDimensionsIncludeLabels: true,
        idealEdgeLength: 150,
        nodeRepulsion: 4500,
        gravity: 0.25,
      } as any,
      minZoom: 0.3,
      maxZoom: 3,
    });

    // Node click handler - expand/collapse
    cyRef.current.on('tap', 'node', (event) => {
      const nodeId = event.target.data('id');
      console.log('[ChainExplorer] Node clicked:', nodeId);
      expandNode(nodeId);
    });

    // Double-click to select command for details panel
    cyRef.current.on('dbltap', 'node', (event) => {
      const nodeId = event.target.data('id');
      console.log('[ChainExplorer] Node double-clicked:', nodeId);
      if (onCommandSelect) {
        onCommandSelect(nodeId);
      }
    });

    // Tooltip handlers
    cyRef.current.on('mouseover', 'node', (event: EventObject) => {
      const node = event.target;
      const pos = node.renderedPosition();

      setTooltip({
        name: node.data('name') || node.data('label') || 'Unknown',
        category: node.data('category') || 'Uncategorized',
        subcategory: node.data('subcategory'),
        description: node.data('description') || 'No description available',
        command: node.data('command') || '',
        tags: node.data('tags') || [],
        x: pos.x,
        y: pos.y,
      });
    });

    cyRef.current.on('mouseout', 'node', () => {
      setTooltip(null);
    });

    console.log('[ChainExplorer] Cytoscape initialized successfully');

    return () => {
      console.log('[ChainExplorer] Destroying Cytoscape instance');
      cyRef.current?.destroy();
    };
  }, []);

  // Load initial command when component mounts or initialCommandId changes
  useEffect(() => {
    console.log('[ChainExplorer] Initial command changed:', initialCommandId);

    // Reset state for new initial command
    setExpandedNodes(new Set());
    setGraphNodes(new Map());
    setGraphEdges(new Map());
    setNodesWithUnexploredRels(new Set());
    setExpansionHistory([]);
    setNodeCount(0);
    setEdgeCount(0);

    if (initialCommandId && cyRef.current) {
      // Clear existing graph
      cyRef.current.elements().remove();

      // Load initial command
      const loadInitial = async () => {
        setLoading(true);
        try {
          const graphData = await window.electronAPI.getGraphWithMetadata(initialCommandId);

          if (graphData?.elements) {
            const newNodes = new Map<string, GraphNode>();
            const newEdges = new Map<string, GraphEdge>();
            const newUnexplored = new Set<string>();
            const newHistory: ExpansionRecord[] = [];

            // Process nodes
            graphData.elements.nodes.forEach((node: GraphNode) => {
              newNodes.set(node.data.id, node);
              // Mark related nodes (not the initial command) as unexplored
              if (node.data.id !== initialCommandId && node.data.hasRelationships) {
                newUnexplored.add(node.data.id);
              }
              // NOTE: Don't add related nodes to history here - they are just visible connections
              // Only the initial command and deliberately clicked nodes go in history
            });

            // Add initial command to history (it's the root, so parentNodeId is null)
            newHistory.push({
              nodeId: initialCommandId,
              parentNodeId: null,
            });

            // Process edges
            graphData.elements.edges.forEach((edge: GraphEdge) => {
              newEdges.set(edge.data.id, edge);
            });

            // Initial command is expanded
            const newExpanded = new Set([initialCommandId]);

            // Update state
            setGraphNodes(newNodes);
            setGraphEdges(newEdges);
            setExpandedNodes(newExpanded);
            setNodesWithUnexploredRels(newUnexplored);
            setExpansionHistory(newHistory);

            // Update visualization
            updateCytoscapeGraph(newNodes, newEdges, newExpanded, newUnexplored);
          }
        } catch (error) {
          console.error('[ChainExplorer] Error loading initial graph:', error);
        } finally {
          setLoading(false);
        }
      };

      loadInitial();
    }
  }, [initialCommandId, updateCytoscapeGraph]);

  return (
    <Paper
      shadow="sm"
      p="md"
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <Group mb="md" justify="space-between">
        <Text size="lg" fw={600}>
          Relationship Explorer
        </Text>
        {nodeCount > 0 && (
          <Group gap="xs">
            <Badge variant="light" color="cyan" size="sm">
              {expandedNodes.size} expanded
            </Badge>
            <Badge variant="light" color="gray" size="sm">
              {nodeCount} nodes
            </Badge>
            <Badge variant="light" color="gray" size="sm">
              {edgeCount} edges
            </Badge>
          </Group>
        )}
      </Group>

      <div
        style={{
          flex: 1,
          position: 'relative',
          border: '1px solid #373A40',
          borderRadius: '4px',
          background: '#1a1b1e',
        }}
      >
        {loading && (
          <Center style={{ position: 'absolute', inset: 0, zIndex: 10 }}>
            <Loader size="lg" />
          </Center>
        )}

        <div
          ref={containerRef}
          style={{
            width: '100%',
            height: '100%',
          }}
        />

        {/* Tooltip */}
        {tooltip && (
          <Box
            style={{
              position: 'absolute',
              left: tooltip.x + 20,
              top: tooltip.y - 20,
              background: '#1a1b1e',
              border: '1px solid #373A40',
              borderRadius: '8px',
              padding: '12px',
              maxWidth: '350px',
              zIndex: 1000,
              pointerEvents: 'none',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.5)',
            }}
          >
            <Stack gap="xs">
              <Text size="sm" fw={700} c="cyan">
                {tooltip.name}
              </Text>

              <Group gap="xs">
                <Badge variant="light" color="blue" size="xs">
                  {tooltip.category}
                </Badge>
                {tooltip.subcategory && (
                  <Badge variant="light" color="grape" size="xs">
                    {tooltip.subcategory}
                  </Badge>
                )}
              </Group>

              {tooltip.description && (
                <Text size="xs" c="dimmed" lineClamp={3}>
                  {tooltip.description}
                </Text>
              )}

              {tooltip.command && tooltip.command.length < 80 && (
                <Text
                  size="xs"
                  c="gray.4"
                  style={{
                    fontFamily: 'monospace',
                    background: '#25262b',
                    padding: '4px 8px',
                    borderRadius: '4px',
                    overflowX: 'auto',
                  }}
                >
                  {tooltip.command}
                </Text>
              )}

              {tooltip.tags && tooltip.tags.length > 0 && (
                <Group gap="xs">
                  {tooltip.tags.slice(0, 4).map((tag, index) => (
                    <Badge key={index} variant="dot" color="gray" size="xs">
                      {tag}
                    </Badge>
                  ))}
                  {tooltip.tags.length > 4 && (
                    <Text size="xs" c="dimmed">
                      +{tooltip.tags.length - 4} more
                    </Text>
                  )}
                </Group>
              )}

              <Text size="xs" c="yellow" mt="xs">
                Click to expand/collapse | Double-click for details
              </Text>
            </Stack>
          </Box>
        )}

        {!initialCommandId && !loading && (
          <Center style={{ position: 'absolute', inset: 0 }}>
            <Text c="dimmed" size="sm">
              Select a command to explore its relationships
            </Text>
          </Center>
        )}

        {initialCommandId && !loading && nodeCount === 0 && (
          <Center style={{ position: 'absolute', inset: 0 }}>
            <div style={{ textAlign: 'center', maxWidth: '300px' }}>
              <Text c="dimmed" size="sm" mb="xs">
                This command has no relationships yet
              </Text>
              <Text c="dimmed" size="xs" style={{ opacity: 0.7 }}>
                Relationships include: alternatives, prerequisites, and next steps
              </Text>
            </div>
          </Center>
        )}
      </div>

      {/* Legend */}
      {nodeCount > 0 && (
        <Group gap="md" mt="md" justify="center" wrap="wrap">
          <Group gap="xs">
            <div
              style={{
                width: 16,
                height: 16,
                background: '#22c1c3',
                borderRadius: '50%',
                border: '3px solid #22c1c3',
              }}
            />
            <Text size="xs" c="dimmed">
              Expanded
            </Text>
          </Group>
          <Group gap="xs">
            <div
              style={{
                width: 16,
                height: 16,
                background: '#373A40',
                borderRadius: '50%',
                border: '3px dashed #ffd43b',
                boxShadow: '0 0 8px #ffd43b',
              }}
            />
            <Text size="xs" c="dimmed">
              Click to Expand
            </Text>
          </Group>
          <Group gap="xs">
            <div style={{ width: 20, height: 2, background: '#fdbb2d' }} />
            <Text size="xs" c="dimmed">
              Alternative
            </Text>
          </Group>
          <Group gap="xs">
            <div style={{ width: 20, height: 2, background: '#ff6b6b' }} />
            <Text size="xs" c="dimmed">
              Prerequisite
            </Text>
          </Group>
          <Group gap="xs">
            <div style={{ width: 20, height: 2, background: '#51cf66' }} />
            <Text size="xs" c="dimmed">
              Next Step
            </Text>
          </Group>
        </Group>
      )}
    </Paper>
  );
}
