import { useEffect, useRef, useState } from 'react';
import { Text, Loader, Center, Group, Badge, Stack } from '@mantine/core';
import cytoscape, { Core } from 'cytoscape';
// @ts-ignore
import coseBilkent from 'cytoscape-cose-bilkent';

// Register layout
cytoscape.use(coseBilkent);

interface CommandChainGraphProps {
  commandId: string;
}

export default function CommandChainGraph({ commandId }: CommandChainGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [loading, setLoading] = useState(false);
  const [nodeCount, setNodeCount] = useState(0);
  const [edgeCount, setEdgeCount] = useState(0);
  const [chainCount, setChainCount] = useState(0);
  const [hasData, setHasData] = useState(false);

  // Debug: Log mount
  useEffect(() => {
    console.log('[CommandChainGraph] Component mounted with commandId:', commandId);
  }, []);

  // Initialize Cytoscape
  useEffect(() => {
    if (!containerRef.current) {
      console.warn('[CommandChainGraph] Container ref is null - cannot initialize Cytoscape');
      return;
    }

    console.log('[CommandChainGraph] Initializing Cytoscape...');
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
            'font-size': '10px',
            'font-family': 'monospace',
            'width': '70px',
            'height': '70px',
            'border-width': '2px',
            'border-color': '#555',
            'text-wrap': 'wrap',
            'text-max-width': '90px',
          },
        },
        {
          selector: 'node[type="center"]',
          style: {
            'background-color': '#22c1c3',
            'border-color': '#22c1c3',
            'border-width': '3px',
            'width': '90px',
            'height': '90px',
            'font-size': '11px',
            'font-weight': 'bold',
          },
        },
        {
          selector: 'node[type="step"]',
          style: {
            'background-color': '#5c7cfa',
            'border-color': '#5c7cfa',
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': '#51cf66',
            'target-arrow-color': '#51cf66',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '9px',
            'color': '#aaa',
            'text-rotation': 'autorotate',
            'text-margin-y': -10,
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
        idealEdgeLength: 120,
        nodeRepulsion: 4500,
        gravity: 0.25,
      } as any,
      minZoom: 0.3,
      maxZoom: 3,
    });

    console.log('[CommandChainGraph] Cytoscape initialized successfully');

    return () => {
      console.log('[CommandChainGraph] Destroying Cytoscape instance');
      cyRef.current?.destroy();
    };
  }, []);

  // Load attack chain data
  useEffect(() => {
    console.log('[CommandChainGraph] loadGraph effect triggered for:', commandId);

    if (!commandId || !cyRef.current) {
      if (!commandId) {
        console.log('[CommandChainGraph] No command ID - skipping graph load');
      }
      if (!cyRef.current) {
        console.warn('[CommandChainGraph] Cytoscape instance not initialized - cannot load graph');
      }
      return;
    }

    const loadGraph = async () => {
      console.log('[CommandChainGraph] Loading attack chains for command:', commandId);
      setLoading(true);
      setHasData(false);
      try {
        const graphData = await window.electronAPI.getCommandChains(commandId);
        console.log('[CommandChainGraph] Graph data received:', graphData);

        if (graphData && graphData.elements) {
          console.log('[CommandChainGraph] Graph elements:', {
            nodes: graphData.elements.nodes.length,
            edges: graphData.elements.edges.length,
          });

          // Count unique chains
          const chains = new Set<string>();
          graphData.elements.nodes.forEach((node: any) => {
            if (node.data.chainId) {
              chains.add(node.data.chainId);
            }
          });
          setChainCount(chains.size);

          cyRef.current!.elements().remove();
          cyRef.current!.add(graphData.elements.nodes);
          cyRef.current!.add(graphData.elements.edges);
          console.log('[CommandChainGraph] Elements added to Cytoscape');

          // Update stats
          const nodeCount = graphData.elements.nodes.length;
          const edgeCount = graphData.elements.edges.length;
          setNodeCount(nodeCount);
          setEdgeCount(edgeCount);
          setHasData(nodeCount > 0);

          // Apply layout only if there's data
          if (nodeCount > 0) {
            console.log('[CommandChainGraph] Applying layout...');
            const layout = cyRef.current!.layout({
              name: 'cose-bilkent',
              nodeDimensionsIncludeLabels: true,
              idealEdgeLength: 120,
              nodeRepulsion: 4500,
              gravity: 0.25,
              randomize: false,
            } as any);
            layout.run();

            // Fit to viewport
            setTimeout(() => {
              console.log('[CommandChainGraph] Fitting graph to viewport');
              cyRef.current?.fit(undefined, 50);
            }, 600);

            console.log('[CommandChainGraph] Graph loaded successfully');
          } else {
            console.log('[CommandChainGraph] Command is not in any attack chains');
          }
        } else {
          console.warn('[CommandChainGraph] No graph data returned');
        }
      } catch (error) {
        console.error('[CommandChainGraph] Error loading graph:', error);
      } finally {
        setLoading(false);
      }
    };

    loadGraph();
  }, [commandId]);

  return (
    <div
      style={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        background: '#1a1b1e',
        borderRadius: '4px',
        border: '1px solid #373A40',
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
          Attack Chains
        </Text>
        {nodeCount > 0 && (
          <Group gap="xs">
            <Badge variant="light" color="cyan" size="sm">
              {chainCount} {chainCount === 1 ? 'chain' : 'chains'}
            </Badge>
            <Badge variant="light" color="gray" size="sm">
              {nodeCount} steps
            </Badge>
          </Group>
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
                This command is not part of any attack chains yet
              </Text>
              <Text c="dimmed" size="xs" style={{ opacity: 0.7 }}>
                Attack chains show step-by-step exploitation sequences
              </Text>
            </Stack>
          </Center>
        )}
      </div>

      {/* Legend */}
      {nodeCount > 0 && (
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
                  background: '#22c1c3',
                  borderRadius: '50%',
                }}
              />
              <Text size="xs" c="dimmed">
                Current Command
              </Text>
            </Group>
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
                Chain Step
              </Text>
            </Group>
          </Group>
        </div>
      )}
    </div>
  );
}
