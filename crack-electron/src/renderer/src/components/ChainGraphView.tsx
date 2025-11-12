import { useEffect, useRef, useState } from 'react';
import { Text, Loader, Center, Group, Badge, Stack, Paper } from '@mantine/core';
import cytoscape, { Core, EventObject } from 'cytoscape';
// @ts-ignore
import coseBilkent from 'cytoscape-cose-bilkent';

// Register layout
cytoscape.use(coseBilkent);

interface ChainGraphViewProps {
  chainId: string;
  onCommandClick?: (commandId: string) => void;
}

export default function ChainGraphView({ chainId, onCommandClick }: ChainGraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [loading, setLoading] = useState(false);
  const [stepCount, setStepCount] = useState(0);
  const [hasData, setHasData] = useState(false);

  // Debug: Log mount
  useEffect(() => {
    console.log('[ChainGraphView] Component mounted with chainId:', chainId);
  }, []);

  // Initialize Cytoscape
  useEffect(() => {
    if (!containerRef.current) {
      console.warn('[ChainGraphView] Container ref is null - cannot initialize Cytoscape');
      return;
    }

    console.log('[ChainGraphView] Initializing Cytoscape...');
    cyRef.current = cytoscape({
      container: containerRef.current,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#5c7cfa',
            'label': 'data(label)',
            'color': '#fff',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': '11px',
            'font-family': 'monospace',
            'width': '80px',
            'height': '80px',
            'border-width': '2px',
            'border-color': '#4c6ef5',
            'text-wrap': 'wrap',
            'text-max-width': '100px',
          },
        },
        {
          selector: 'node[type="step"]',
          style: {
            'background-color': '#5c7cfa',
            'border-color': '#4c6ef5',
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 3,
            'line-color': '#51cf66',
            'target-arrow-color': '#51cf66',
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
          selector: 'edge[type="next"]',
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
        nodeRepulsion: 5000,
        gravity: 0.3,
      } as any,
      minZoom: 0.3,
      maxZoom: 3,
    });

    console.log('[ChainGraphView] Cytoscape initialized successfully');

    // Add click handler for nodes
    cyRef.current.on('tap', 'node', (evt: EventObject) => {
      const node = evt.target;
      const commandId = node.data('commandId');
      console.log('[ChainGraphView] Node clicked:', {
        stepId: node.data('id'),
        commandId,
      });

      if (commandId && onCommandClick) {
        onCommandClick(commandId);
      }
    });

    return () => {
      console.log('[ChainGraphView] Destroying Cytoscape instance');
      cyRef.current?.destroy();
    };
  }, [onCommandClick]);

  // Load chain graph data
  useEffect(() => {
    console.log('[ChainGraphView] loadGraph effect triggered for:', chainId);

    if (!chainId || !cyRef.current) {
      if (!chainId) {
        console.log('[ChainGraphView] No chain ID - skipping graph load');
      }
      if (!cyRef.current) {
        console.warn('[ChainGraphView] Cytoscape instance not initialized - cannot load graph');
      }
      return;
    }

    const loadGraph = async () => {
      console.log('[ChainGraphView] Loading chain graph for:', chainId);
      setLoading(true);
      setHasData(false);
      try {
        const graphData = await window.electronAPI.getChainGraph(chainId);
        console.log('[ChainGraphView] Graph data received:', graphData);

        if (graphData && graphData.elements) {
          console.log('[ChainGraphView] Graph elements:', {
            nodes: graphData.elements.nodes.length,
            edges: graphData.elements.edges.length,
          });

          cyRef.current!.elements().remove();
          cyRef.current!.add(graphData.elements.nodes);
          cyRef.current!.add(graphData.elements.edges);
          console.log('[ChainGraphView] Elements added to Cytoscape');

          // Update stats
          const nodeCount = graphData.elements.nodes.length;
          setStepCount(nodeCount);
          setHasData(nodeCount > 0);

          // Apply layout only if there's data
          if (nodeCount > 0) {
            console.log('[ChainGraphView] Applying layout...');
            const layout = cyRef.current!.layout({
              name: 'cose-bilkent',
              nodeDimensionsIncludeLabels: true,
              idealEdgeLength: 150,
              nodeRepulsion: 5000,
              gravity: 0.3,
              randomize: false,
            } as any);
            layout.run();

            // Fit to viewport
            setTimeout(() => {
              console.log('[ChainGraphView] Fitting graph to viewport');
              cyRef.current?.fit(undefined, 50);
            }, 600);

            console.log('[ChainGraphView] Graph loaded successfully');
          } else {
            console.log('[ChainGraphView] Chain has no steps');
          }
        } else {
          console.warn('[ChainGraphView] No graph data returned');
        }
      } catch (error) {
        console.error('[ChainGraphView] Error loading graph:', error);
      } finally {
        setLoading(false);
      }
    };

    loadGraph();
  }, [chainId]);

  return (
    <Paper
      style={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        background: '#25262b',
        border: '1px solid #373A40',
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '12px 16px',
          borderBottom: '1px solid #373A40',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <Text size="sm" fw={600}>
          Chain Graph
        </Text>
        {stepCount > 0 && (
          <Badge variant="light" color="blue" size="sm">
            {stepCount} {stepCount === 1 ? 'step' : 'steps'}
          </Badge>
        )}
      </div>

      {/* Graph Container */}
      <div
        style={{
          flex: 1,
          position: 'relative',
          background: '#0d0e10',
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

        {!loading && !hasData && (
          <Center style={{ position: 'absolute', inset: 0 }}>
            <Stack gap="xs" align="center" style={{ maxWidth: '300px', textAlign: 'center' }}>
              <Text c="dimmed" size="sm">
                No steps found for this chain
              </Text>
              <Text c="dimmed" size="xs" style={{ opacity: 0.7 }}>
                The chain graph shows the sequential attack steps
              </Text>
            </Stack>
          </Center>
        )}
      </div>

      {/* Legend */}
      {stepCount > 0 && (
        <div
          style={{
            padding: '12px 16px',
            borderTop: '1px solid #373A40',
          }}
        >
          <Group gap="md" justify="center">
            <Group gap="xs">
              <div
                style={{
                  width: 12,
                  height: 12,
                  background: '#5c7cfa',
                  borderRadius: '50%',
                }}
              />
              <Text size="xs" c="dimmed">
                Attack Step
              </Text>
            </Group>
            <Group gap="xs">
              <div
                style={{
                  width: 20,
                  height: 2,
                  background: '#51cf66',
                }}
              />
              <Text size="xs" c="dimmed">
                Next Step
              </Text>
            </Group>
          </Group>
        </div>
      )}
    </Paper>
  );
}
