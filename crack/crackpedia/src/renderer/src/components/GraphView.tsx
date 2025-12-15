import { useEffect, useRef, useState } from 'react';
import { Paper, Text, Loader, Center, Group, Badge, Box, Stack } from '@mantine/core';
import cytoscape, { Core, EventObject } from 'cytoscape';
// @ts-ignore
import coseBilkent from 'cytoscape-cose-bilkent';

// Register layout
cytoscape.use(coseBilkent);

interface GraphViewProps {
  selectedCommandId?: string;
  onNodeClick: (commandId: string) => void;
}

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

export default function GraphView({ selectedCommandId, onNodeClick }: GraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [loading, setLoading] = useState(false);
  const [nodeCount, setNodeCount] = useState(0);
  const [edgeCount, setEdgeCount] = useState(0);
  const [hasData, setHasData] = useState(false);
  const [tooltip, setTooltip] = useState<NodeTooltipData | null>(null);

  // Debug: Log mount and props
  useEffect(() => {
    console.log('[GraphView] Component mounted');
  }, []);

  useEffect(() => {
    console.log('[GraphView] Props changed:', {
      selectedCommandId,
      hasContainer: !!containerRef.current,
    });
  }, [selectedCommandId]);

  useEffect(() => {
    console.log('[GraphView] Container ref:', containerRef.current);
    if (!containerRef.current) {
      console.warn('[GraphView] Container ref is null - cannot initialize Cytoscape');
      return;
    }

    console.log('[GraphView] Initializing Cytoscape...');
    // Initialize Cytoscape
    cyRef.current = cytoscape({
      container: containerRef.current,
      style: [
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
            'width': '60px',
            'height': '60px',
            'border-width': '2px',
            'border-color': '#555',
            'text-wrap': 'wrap',
            'text-max-width': '80px',
          },
        },
        {
          selector: 'node[type="center"]',
          style: {
            'background-color': '#22c1c3',
            'border-color': '#22c1c3',
            'border-width': '3px',
            'width': '80px',
            'height': '80px',
            'font-size': '12px',
            'font-weight': 'bold',
          },
        },
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

    // Node click handler
    cyRef.current.on('tap', 'node', (event) => {
      const nodeId = event.target.data('id');
      console.log('[GraphView] Node clicked:', nodeId);
      onNodeClick(nodeId);
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

    console.log('[GraphView] Cytoscape initialized successfully');

    return () => {
      console.log('[GraphView] Destroying Cytoscape instance');
      cyRef.current?.destroy();
    };
  }, [onNodeClick]);

  useEffect(() => {
    console.log('[GraphView] loadGraph effect triggered:', {
      selectedCommandId,
      hasCyInstance: !!cyRef.current,
    });

    if (!selectedCommandId || !cyRef.current) {
      if (!selectedCommandId) {
        console.log('[GraphView] No command selected - skipping graph load');
      }
      if (!cyRef.current) {
        console.warn('[GraphView] Cytoscape instance not initialized - cannot load graph');
      }
      return;
    }

    const loadGraph = async () => {
      console.log('[GraphView] Loading graph for command:', selectedCommandId);
      setLoading(true);
      setHasData(false);
      try {
        const graphData = await window.electronAPI.getGraph(selectedCommandId);
        console.log('[GraphView] Graph data received:', graphData);

        if (graphData && graphData.elements) {
          console.log('[GraphView] Graph elements:', {
            nodes: graphData.elements.nodes.length,
            edges: graphData.elements.edges.length,
          });

          cyRef.current!.elements().remove();
          cyRef.current!.add(graphData.elements.nodes);
          cyRef.current!.add(graphData.elements.edges);
          console.log('[GraphView] Elements added to Cytoscape');

          // Update stats
          const nodeCount = graphData.elements.nodes.length;
          const edgeCount = graphData.elements.edges.length;
          setNodeCount(nodeCount);
          setEdgeCount(edgeCount);
          setHasData(nodeCount > 0);

          // Apply layout only if there's data
          if (nodeCount > 0) {
            console.log('[GraphView] Applying layout...');
            const layout = cyRef.current!.layout({
              name: 'cose-bilkent',
              nodeDimensionsIncludeLabels: true,
              idealEdgeLength: 150,
              nodeRepulsion: 4500,
              gravity: 0.25,
              randomize: false,
            } as any);
            layout.run();

            // Fit to viewport
            setTimeout(() => {
              console.log('[GraphView] Fitting graph to viewport');
              cyRef.current?.fit(undefined, 50);
            }, 600);

            console.log('[GraphView] Graph loaded successfully');
          } else {
            console.log('[GraphView] Command has no relationships');
          }
        } else {
          console.warn('[GraphView] No graph data returned');
        }
      } catch (error) {
        console.error('[GraphView] Error loading graph:', error);
      } finally {
        setLoading(false);
      }
    };

    loadGraph();
  }, [selectedCommandId]);

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
          Relationship Graph
        </Text>
        {nodeCount > 0 && (
          <Group gap="xs">
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
              {/* Command Name */}
              <Text size="sm" fw={700} c="cyan">
                {tooltip.name}
              </Text>

              {/* Category/Subcategory */}
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

              {/* Description */}
              {tooltip.description && (
                <Text size="xs" c="dimmed" lineClamp={3}>
                  {tooltip.description}
                </Text>
              )}

              {/* Command Syntax */}
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

              {/* Tags */}
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
            </Stack>
          </Box>
        )}

        {!selectedCommandId && !loading && (
          <Center style={{ position: 'absolute', inset: 0 }}>
            <Text c="dimmed" size="sm">
              Select a command to view its relationship graph
            </Text>
          </Center>
        )}

        {selectedCommandId && !loading && !hasData && (
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
        <Group gap="md" mt="md" justify="center">
          <Group gap="xs">
            <div
              style={{
                width: 12,
                height: 12,
                background: '#fdbb2d',
                borderRadius: '50%',
              }}
            />
            <Text size="xs" c="dimmed">
              Alternative
            </Text>
          </Group>
          <Group gap="xs">
            <div
              style={{
                width: 12,
                height: 12,
                background: '#ff6b6b',
                borderRadius: '50%',
              }}
            />
            <Text size="xs" c="dimmed">
              Prerequisite
            </Text>
          </Group>
          <Group gap="xs">
            <div
              style={{
                width: 12,
                height: 12,
                background: '#51cf66',
                borderRadius: '50%',
              }}
            />
            <Text size="xs" c="dimmed">
              Next Step
            </Text>
          </Group>
        </Group>
      )}
    </Paper>
  );
}
