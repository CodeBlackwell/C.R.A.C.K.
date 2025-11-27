import { useEffect, useRef, useState, useCallback } from 'react';
import { Paper, Text, Loader, Center, Group, Badge, Box, Stack, Button, SegmentedControl } from '@mantine/core';
import cytoscape, { Core, EventObject } from 'cytoscape';
// @ts-ignore
import coseBilkent from 'cytoscape-cose-bilkent';
// @ts-ignore
import dagre from 'cytoscape-dagre';
// @ts-ignore
import elk from 'cytoscape-elk';

// Register layouts
cytoscape.use(coseBilkent);
cytoscape.use(dagre);
cytoscape.use(elk);

// Layout types
export type LayoutType = 'grid' | 'bfs' | 'concentric' | 'dagre' | 'elk';
export type Orientation = 'horizontal' | 'vertical';

// DRY: Single config object for all layouts
const LAYOUT_CONFIGS: Record<LayoutType, (orientation: Orientation) => any> = {
  grid: () => ({ name: 'grid', rows: 3, cols: 3, fit: true, padding: 50 }),
  bfs: () => ({ name: 'breadthfirst', directed: true, spacingFactor: 1.5, fit: true, padding: 50 }),
  concentric: () => ({ name: 'concentric', minNodeSpacing: 50, fit: true, padding: 50 }),
  dagre: (o) => ({
    name: 'dagre',
    rankDir: o === 'horizontal' ? 'LR' : 'TB',
    nodeSep: 50,
    rankSep: 100,
    fit: true,
    padding: 50,
  }),
  elk: (o) => ({
    name: 'elk',
    elk: {
      algorithm: 'layered',
      'elk.direction': o === 'horizontal' ? 'RIGHT' : 'DOWN',
    },
    fit: true,
    padding: 50,
  }),
};

const DIRECTIONAL_LAYOUTS = new Set<LayoutType>(['dagre', 'elk']);

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
  // Clean mode: only show chain path + last node's connections
  cleanMode?: boolean;
  onCleanModeChange?: (cleanMode: boolean) => void;
  // Layout controls
  layout?: LayoutType;
  orientation?: Orientation;
  onLayoutChange?: (layout: LayoutType) => void;
  onOrientationChange?: (orientation: Orientation) => void;
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
  cleanMode = false,
  onCleanModeChange,
  layout = 'dagre',
  orientation = 'horizontal',
  onLayoutChange,
  onOrientationChange,
}: ChainExplorerGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  // State management
  const [loading, setLoading] = useState(false);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [graphNodes, setGraphNodes] = useState<Map<string, GraphNode>>(new Map());
  const [graphEdges, setGraphEdges] = useState<Map<string, GraphEdge>>(new Map());
  // Full state - tracks ALL fetched nodes/edges (before clean mode filtering)
  const [fullGraphNodes, setFullGraphNodes] = useState<Map<string, GraphNode>>(new Map());
  const [fullGraphEdges, setFullGraphEdges] = useState<Map<string, GraphEdge>>(new Map());
  const [, setNodesWithUnexploredRels] = useState<Set<string>>(new Set());
  const [expansionHistory, setExpansionHistory] = useState<ExpansionRecord[]>([]);
  const [tooltip, setTooltip] = useState<NodeTooltipData | null>(null);
  const [nodeCount, setNodeCount] = useState(0);
  const [edgeCount, setEdgeCount] = useState(0);

  // Track internal state size for sync comparison (avoids stale closure)
  const graphNodesSizeRef = useRef(0);

  // Refs to always have latest functions (fixes stale closure in Cytoscape events)
  const expandNodeRef = useRef<(commandId: string) => void>(() => {});
  const onCommandSelectRef = useRef<((commandId: string) => void) | undefined>(onCommandSelect);

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

    // Apply layout with animation using config
    const layoutConfig = LAYOUT_CONFIGS[layout](orientation);
    const layoutInstance = cyRef.current.layout({
      ...layoutConfig,
      animate: true,
      animationDuration: 300,
    } as any);

    layoutInstance.run();
  }, [layout, orientation]);

  // Rebuild visible graph from full state based on cleanMode
  const rebuildVisibleGraph = useCallback((
    fullNodes: Map<string, GraphNode>,
    fullEdges: Map<string, GraphEdge>,
    expanded: Set<string>,
    history: ExpansionRecord[],
    isCleanMode: boolean
  ) => {
    console.log('[ChainExplorer] rebuildVisibleGraph:', { isCleanMode, historyLength: history.length });

    let visibleNodes: Map<string, GraphNode>;
    let visibleEdges: Map<string, GraphEdge>;

    if (isCleanMode && history.length > 1) {
      // CLEAN MODE: Only show chain path + last node's connections
      const chainPath = new Set<string>();
      history.forEach(record => chainPath.add(record.nodeId));

      // Get the last expanded node (tip of the chain)
      const lastExpandedNode = history[history.length - 1].nodeId;

      visibleNodes = new Map<string, GraphNode>();
      visibleEdges = new Map<string, GraphEdge>();

      // Add all chain path nodes
      chainPath.forEach(id => {
        if (fullNodes.has(id)) {
          visibleNodes.set(id, fullNodes.get(id)!);
        }
      });

      // Add edges between chain path nodes
      fullEdges.forEach((edge, key) => {
        if (chainPath.has(edge.data.source) && chainPath.has(edge.data.target)) {
          visibleEdges.set(key, edge);
        }
      });

      // Add all connections from the last expanded node
      fullEdges.forEach((edge, key) => {
        if (edge.data.source === lastExpandedNode || edge.data.target === lastExpandedNode) {
          visibleEdges.set(key, edge);
          // Also add the connected node
          const connectedId = edge.data.source === lastExpandedNode ? edge.data.target : edge.data.source;
          if (fullNodes.has(connectedId)) {
            visibleNodes.set(connectedId, fullNodes.get(connectedId)!);
          }
        }
      });

      console.log('[ChainExplorer] Clean mode visible:', {
        chainPath: Array.from(chainPath),
        lastExpanded: lastExpandedNode,
        visibleNodes: visibleNodes.size,
        visibleEdges: visibleEdges.size,
      });
    } else {
      // NORMAL MODE: Show all nodes/edges
      visibleNodes = new Map(fullNodes);
      visibleEdges = new Map(fullEdges);
    }

    // Calculate unexplored nodes for visible set
    const visibleUnexplored = new Set<string>();
    visibleNodes.forEach((node, id) => {
      if (!expanded.has(id) && node.data.hasRelationships) {
        visibleUnexplored.add(id);
      }
    });

    // Update visible state
    setGraphNodes(visibleNodes);
    setGraphEdges(visibleEdges);
    setNodesWithUnexploredRels(visibleUnexplored);

    // Update visualization
    updateCytoscapeGraph(visibleNodes, visibleEdges, expanded, visibleUnexplored);
  }, [updateCytoscapeGraph]);

  // Re-render when cleanMode toggles (use refs to avoid other deps triggering this)
  const prevCleanModeRef = useRef(cleanMode);
  useEffect(() => {
    if (fullGraphNodes.size === 0) return;
    if (prevCleanModeRef.current !== cleanMode) {
      console.log('[ChainExplorer] cleanMode toggled:', prevCleanModeRef.current, '->', cleanMode);
      prevCleanModeRef.current = cleanMode;
      rebuildVisibleGraph(fullGraphNodes, fullGraphEdges, expandedNodes, expansionHistory, cleanMode);
    }
  }, [cleanMode, fullGraphNodes, fullGraphEdges, expandedNodes, expansionHistory, rebuildVisibleGraph]);

  // Expand a node to show its relationships
  const expandNode = useCallback(async (commandId: string) => {
    console.log('[ChainExplorer] expandNode called:', commandId, 'cleanMode:', cleanMode);

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

      // Find the parent of the node being expanded (for tree hierarchy)
      let parentNodeId: string | null = null;
      graphEdges.forEach((edge) => {
        if (edge.data.target === commandId && expandedNodes.has(edge.data.source)) {
          parentNodeId = edge.data.source;
        } else if (edge.data.source === commandId && expandedNodes.has(edge.data.target)) {
          parentNodeId = edge.data.target;
        }
      });

      // Build the new history with this node added
      const newHistory = [...expansionHistory, { nodeId: commandId, parentNodeId }];

      // Mark this node as expanded
      const newExpanded = new Set(expandedNodes);
      newExpanded.add(commandId);

      // ALWAYS update full state (accumulate all fetched data)
      const newFullNodes = new Map(fullGraphNodes);
      const newFullEdges = new Map(fullGraphEdges);

      // Add new nodes to full state
      graphData.elements.nodes.forEach((node: GraphNode) => {
        newFullNodes.set(node.data.id, node);
      });

      // Add new edges to full state
      graphData.elements.edges.forEach((edge: GraphEdge) => {
        newFullEdges.set(edge.data.id, edge);
      });

      console.log('[ChainExplorer] Updated full state:', {
        fullNodes: newFullNodes.size,
        fullEdges: newFullEdges.size,
      });

      // Update full state
      setFullGraphNodes(newFullNodes);
      setFullGraphEdges(newFullEdges);
      setExpandedNodes(newExpanded);
      setExpansionHistory(newHistory);

      // Rebuild visible graph based on cleanMode
      rebuildVisibleGraph(newFullNodes, newFullEdges, newExpanded, newHistory, cleanMode);
    } catch (error) {
      console.error('[ChainExplorer] Error expanding node:', error);
    } finally {
      setLoading(false);
    }
  }, [expandedNodes, graphEdges, fullGraphNodes, fullGraphEdges, expansionHistory, rebuildVisibleGraph, cleanMode]);

  // Keep refs updated with latest functions (fixes stale closure)
  useEffect(() => {
    expandNodeRef.current = expandNode;
  }, [expandNode]);

  useEffect(() => {
    onCommandSelectRef.current = onCommandSelect;
  }, [onCommandSelect]);

  // Keep graphNodes size ref updated
  useEffect(() => {
    graphNodesSizeRef.current = graphNodes.size;
  }, [graphNodes]);

  // Re-apply layout when layout/orientation changes
  useEffect(() => {
    if (!cyRef.current || cyRef.current.nodes().length === 0) return;
    const layoutConfig = LAYOUT_CONFIGS[layout](orientation);
    const layoutInstance = cyRef.current.layout({
      ...layoutConfig,
      animate: true,
      animationDuration: 300,
    } as any);
    layoutInstance.run();
  }, [layout, orientation]);

  // Collapse a node (remove its descendants and orphaned connections)
  // If collapsing would leave no expanded nodes, promote a connected node to be new root
  const collapseNode = useCallback(async (commandId: string) => {
    console.log('[ChainExplorer] collapseNode called:', commandId);

    // Find all descendant nodes (from expansion history)
    const nodesToRemove = findDescendantNodes(commandId, expansionHistory);
    nodesToRemove.add(commandId); // Include the collapsed node itself
    console.log('[ChainExplorer] Nodes to collapse:', Array.from(nodesToRemove));

    // Update expanded set and history first
    const newExpanded = new Set(expandedNodes);
    nodesToRemove.forEach(id => {
      newExpanded.delete(id);
    });
    let newHistory = expansionHistory.filter(r => !nodesToRemove.has(r.nodeId));

    // Remove edges connected to collapsed nodes
    let newEdges = new Map(fullGraphEdges);
    newEdges.forEach((edge, key) => {
      if (nodesToRemove.has(edge.data.source) || nodesToRemove.has(edge.data.target)) {
        newEdges.delete(key);
      }
    });

    // Track if we're promoting a new root (need to load its relationships)
    let newRootId: string | null = null;
    let newRootGraphData: any = null;

    // If no expanded nodes remain, promote a connected node as new root
    if (newExpanded.size === 0) {
      // Find direct connections of the collapsed node that are still visible
      const connectedNodes: string[] = [];
      fullGraphEdges.forEach((edge) => {
        if (edge.data.source === commandId && fullGraphNodes.has(edge.data.target) && !nodesToRemove.has(edge.data.target)) {
          connectedNodes.push(edge.data.target);
        }
        if (edge.data.target === commandId && fullGraphNodes.has(edge.data.source) && !nodesToRemove.has(edge.data.source)) {
          connectedNodes.push(edge.data.source);
        }
      });

      // Promote the first connected node as new root
      if (connectedNodes.length > 0) {
        newRootId = connectedNodes[0];
        newExpanded.add(newRootId);
        newHistory = [{ nodeId: newRootId, parentNodeId: null }];
        console.log('[ChainExplorer] Promoted new root:', newRootId);

        // Fetch the new root's relationships
        try {
          newRootGraphData = await window.electronAPI.getGraphWithMetadata(newRootId);
          console.log('[ChainExplorer] Fetched new root relationships:', newRootGraphData);
        } catch (error) {
          console.error('[ChainExplorer] Error fetching new root relationships:', error);
        }
      }
    }

    // Start with nodes/edges we want to keep
    let newNodes = new Map<string, GraphNode>();
    newEdges = new Map<string, GraphEdge>();

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
      newEdges = new Map(fullGraphEdges);
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
      newNodes = new Map(fullGraphNodes);
      newNodes.forEach((_, id) => {
        if (!reachableNodes.has(id)) {
          newNodes.delete(id);
        }
      });
    }

    // Recalculate unexplored nodes
    const newUnexplored = new Set<string>();
    newNodes.forEach((node, id) => {
      if (!newExpanded.has(id) && node.data.hasRelationships) {
        newUnexplored.add(id);
      }
    });

    console.log('[ChainExplorer] Collapse complete:', {
      removed: fullGraphNodes.size - newNodes.size,
      remaining: newNodes.size,
      newRoot: newRootId,
    });

    // Update full state (collapse truly removes from full state)
    setFullGraphNodes(newNodes);
    setFullGraphEdges(newEdges);
    setExpandedNodes(newExpanded);
    setExpansionHistory(newHistory);

    // Rebuild visible graph based on cleanMode
    rebuildVisibleGraph(newNodes, newEdges, newExpanded, newHistory, cleanMode);
  }, [expandedNodes, fullGraphNodes, fullGraphEdges, expansionHistory, findDescendantNodes, rebuildVisibleGraph, cleanMode]);

  // Emit state changes to parent
  useEffect(() => {
    if (onStateChange && graphNodes.size > 0) {
      onStateChange(graphNodes, graphEdges, expandedNodes, expansionHistory);
    }
  }, [graphNodes, graphEdges, expandedNodes, expansionHistory, onStateChange]);

  // Sync with external state changes (when tree removes nodes)
  useEffect(() => {
    console.log('[ChainExplorer] Sync effect triggered:', {
      hasExternalNodes: !!externalNodes,
      externalSize: externalNodes?.size,
      internalRefSize: graphNodesSizeRef.current,
    });
    if (externalNodes && externalEdges && externalExpanded && externalHistory) {
      // Only sync if external state is smaller (nodes were removed)
      // Use ref to get current internal size (avoids stale closure)
      const internalSize = graphNodesSizeRef.current;
      console.log('[ChainExplorer] Comparing sizes:', {
        external: externalNodes.size,
        internal: internalSize,
        shouldSync: externalNodes.size < internalSize,
      });
      if (externalNodes.size < internalSize) {
        console.log('[ChainExplorer] ========== SYNCING (nodes removed) ==========');
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
  }, [externalNodes, externalEdges, externalExpanded, externalHistory, updateCytoscapeGraph]);

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

    // Node click handler - expand/collapse AND update details
    // Uses refs to always call latest functions (avoids stale closure)
    cyRef.current.on('tap', 'node', (event) => {
      const nodeId = event.target.data('id');
      console.log('[ChainExplorer] Node clicked:', nodeId);
      expandNodeRef.current(nodeId);
      // Also update details view with clicked node
      if (onCommandSelectRef.current) {
        onCommandSelectRef.current(nodeId);
      }
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

  // Load initial command - smart behavior based on context
  // If the command is already visible in graph (as a connection), ACCUMULATE
  // If the command is new (from search), RESET and start fresh
  useEffect(() => {
    if (!initialCommandId || !cyRef.current) return;

    // Skip if already expanded (don't reload same command)
    if (expandedNodes.has(initialCommandId)) {
      console.log('[ChainExplorer] Command already expanded, skipping:', initialCommandId);
      return;
    }

    // Check if this command is already visible as a connection in the graph
    const isVisibleConnection = fullGraphNodes.has(initialCommandId);

    if (isVisibleConnection) {
      // ACCUMULATE: Command is a visible connection, just expand it
      console.log('[ChainExplorer] Expanding visible connection:', initialCommandId);
      expandNode(initialCommandId);
    } else {
      // RESET: New command from search, start fresh
      console.log('[ChainExplorer] New command from search, resetting graph:', initialCommandId);

      // Clear all state (both full and visible)
      setExpandedNodes(new Set());
      setFullGraphNodes(new Map());
      setFullGraphEdges(new Map());
      setGraphNodes(new Map());
      setGraphEdges(new Map());
      setNodesWithUnexploredRels(new Set());
      setExpansionHistory([]);

      // Clear cytoscape
      cyRef.current?.elements().remove();

      // Load fresh
      (async () => {
        setLoading(true);
        try {
          const graphData = await window.electronAPI.getGraphWithMetadata(initialCommandId);
          if (!graphData?.elements) return;

          const newFullNodes = new Map<string, GraphNode>();
          const newFullEdges = new Map<string, GraphEdge>();
          const newExpanded = new Set([initialCommandId]);
          const newHistory: ExpansionRecord[] = [{ nodeId: initialCommandId, parentNodeId: null }];

          // Add nodes to full state
          graphData.elements.nodes.forEach((node: GraphNode) => {
            newFullNodes.set(node.data.id, node);
          });

          // Add edges to full state
          graphData.elements.edges.forEach((edge: GraphEdge) => {
            newFullEdges.set(edge.data.id, edge);
          });

          // Update full state
          setFullGraphNodes(newFullNodes);
          setFullGraphEdges(newFullEdges);
          setExpandedNodes(newExpanded);
          setExpansionHistory(newHistory);

          // Rebuild visible graph (respects cleanMode)
          rebuildVisibleGraph(newFullNodes, newFullEdges, newExpanded, newHistory, cleanMode);
        } finally {
          setLoading(false);
        }
      })();
    }
  }, [initialCommandId, expandedNodes, fullGraphNodes, expandNode, rebuildVisibleGraph, cleanMode]);

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
        <Group gap="sm">
          <Text size="lg" fw={600}>
            Relationship Explorer
          </Text>
          <Button
            size="xs"
            variant={cleanMode ? 'filled' : 'subtle'}
            color={cleanMode ? 'cyan' : 'gray'}
            onClick={() => onCleanModeChange?.(!cleanMode)}
          >
            Clean
          </Button>
          <SegmentedControl
            size="xs"
            value={layout}
            onChange={(value) => onLayoutChange?.(value as LayoutType)}
            data={[
              { label: 'Grid', value: 'grid' },
              { label: 'BFS', value: 'bfs' },
              { label: 'Ring', value: 'concentric' },
              { label: 'Dagre', value: 'dagre' },
              { label: 'Elk', value: 'elk' },
            ]}
          />
          {DIRECTIONAL_LAYOUTS.has(layout) && (
            <SegmentedControl
              size="xs"
              value={orientation}
              onChange={(value) => onOrientationChange?.(value as Orientation)}
              data={[
                { label: '↔', value: 'horizontal' },
                { label: '↕', value: 'vertical' },
              ]}
            />
          )}
        </Group>
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
