import { useEffect, useRef, useState } from 'react';
import { Text, Loader, Center, Group, Badge, Stack, Paper, Box } from '@mantine/core';
import cytoscape, { Core, EventObject } from 'cytoscape';
// @ts-ignore
import coseBilkent from 'cytoscape-cose-bilkent';

// Register layout
cytoscape.use(coseBilkent);

interface ChainGraphViewProps {
  chainId: string;
  onCommandClick?: (commandId: string) => void;
  onStepClick?: (stepId: string) => void;
  onCommandDoubleClick?: (commandId: string) => void;
}

interface TooltipData {
  name: string;
  objective?: string;
  description: string;
  commandName?: string;
  x: number;
  y: number;
}

export default function ChainGraphView({ chainId, onCommandClick, onStepClick, onCommandDoubleClick }: ChainGraphViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [loading, setLoading] = useState(false);
  const [stepCount, setStepCount] = useState(0);
  const [hasData, setHasData] = useState(false);
  const [tooltip, setTooltip] = useState<TooltipData | null>(null);

  // Debug: Log mount
  useEffect(() => {
    console.log('[ChainGraphView] ========== COMPONENT MOUNTED ==========');
    console.log('[ChainGraphView] Component mounted with chainId:', chainId);
    return () => {
      console.log('[ChainGraphView] ========== COMPONENT UNMOUNTING ==========');
      console.log('[ChainGraphView] Component unmounting for chainId:', chainId);
    };
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
            'label': (ele: any) => {
              const command = ele.data('command');
              const stepNum = ele.data('label'); // "Step X"
              if (command && command.properties && command.properties.name) {
                // Show command name + step number
                return `${command.properties.name}\n[${stepNum}]`;
              }
              // No command - show step number only
              return stepNum;
            },
            'color': '#fff',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-size': '10px',
            'font-family': 'Inter, system-ui, sans-serif',
            'width': '120px',
            'height': '120px',
            'border-width': '3px',
            'border-color': '#4c6ef5',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          },
        },
        {
          selector: 'node[type="step"]',
          style: {
            'background-color': (ele: any) => {
              // Different color if step has a command
              return ele.data('command') ? '#5c7cfa' : '#868e96';
            },
            'border-color': (ele: any) => {
              return ele.data('command') ? '#4c6ef5' : '#6c757d';
            },
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
      console.log('[ChainGraphView] ========== NODE TAP EVENT START ==========');
      const node = evt.target;
      const stepId = node.data('id');
      const command = node.data('command');
      const commandId = command?.id;
      console.log('[ChainGraphView] Node clicked:', {
        stepId,
        commandId,
        hasCommand: !!command,
        onStepClickDefined: !!onStepClick,
      });

      // Call step click handler (shows step details in right panel)
      if (onStepClick) {
        console.log('[ChainGraphView] Calling onStepClick with stepId:', stepId);
        onStepClick(stepId);
        console.log('[ChainGraphView] onStepClick returned');
      } else {
        console.warn('[ChainGraphView] onStepClick is not defined!');
      }
      console.log('[ChainGraphView] ========== NODE TAP EVENT END ==========');
    });

    // Add double-click handler for nodes to open command reference directly
    cyRef.current.on('dbltap', 'node', (evt: EventObject) => {
      console.log('[ChainGraphView] ========== NODE DOUBLE-TAP EVENT START ==========');
      const node = evt.target;
      const command = node.data('command');
      const commandId = command?.properties?.id;
      console.log('[ChainGraphView] Node double-clicked:', {
        commandId,
        hasCommand: !!command,
        commandStructure: command ? Object.keys(command) : [],
        onCommandDoubleClickDefined: !!onCommandDoubleClick,
      });

      // Call command double-click handler if command exists
      if (command && commandId && onCommandDoubleClick) {
        console.log('[ChainGraphView] Calling onCommandDoubleClick with commandId:', commandId);
        onCommandDoubleClick(commandId);
        console.log('[ChainGraphView] onCommandDoubleClick returned');
      } else if (!command) {
        console.warn('[ChainGraphView] Node has no associated command - cannot open command reference');
      } else if (!commandId) {
        console.warn('[ChainGraphView] Command exists but ID not found. Command structure:', command);
      } else if (!onCommandDoubleClick) {
        console.warn('[ChainGraphView] onCommandDoubleClick is not defined!');
      }
      console.log('[ChainGraphView] ========== NODE DOUBLE-TAP EVENT END ==========');
    });

    // Add tooltip on hover
    cyRef.current.on('mouseover', 'node', (evt: EventObject) => {
      const node = evt.target;
      const renderedPosition = node.renderedPosition();

      const tooltipData: TooltipData = {
        name: node.data('name') || 'Unnamed Step',
        objective: node.data('objective'),
        description: node.data('description') || '',
        commandName: node.data('command')?.properties?.name,
        x: renderedPosition.x,
        y: renderedPosition.y,
      };

      setTooltip(tooltipData);
    });

    // Hide tooltip on mouseout
    cyRef.current.on('mouseout', 'node', () => {
      setTooltip(null);
    });

    return () => {
      console.log('[ChainGraphView] Destroying Cytoscape instance');
      cyRef.current?.destroy();
    };
  }, [onCommandClick, onStepClick, onCommandDoubleClick]);

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
              maxWidth: '300px',
              zIndex: 1000,
              pointerEvents: 'none',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.5)',
            }}
          >
            <Stack gap="xs">
              <Text size="sm" fw={700} c="cyan">
                {tooltip.name}
              </Text>
              {tooltip.objective && (
                <Box>
                  <Text size="xs" fw={600} c="dimmed" mb={2}>
                    OBJECTIVE
                  </Text>
                  <Text size="xs" c="white">
                    {tooltip.objective}
                  </Text>
                </Box>
              )}
              <Box>
                <Text size="xs" fw={600} c="dimmed" mb={2}>
                  DESCRIPTION
                </Text>
                <Text size="xs" c="dimmed" lineClamp={4}>
                  {tooltip.description}
                </Text>
              </Box>
              {tooltip.commandName && (
                <Badge size="sm" variant="light" color="green">
                  Command: {tooltip.commandName}
                </Badge>
              )}
            </Stack>
          </Box>
        )}

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
                  border: '2px solid #4c6ef5',
                }}
              />
              <Text size="xs" c="dimmed">
                With Command
              </Text>
            </Group>
            <Group gap="xs">
              <div
                style={{
                  width: 12,
                  height: 12,
                  background: '#868e96',
                  borderRadius: '50%',
                  border: '2px solid #6c757d',
                }}
              />
              <Text size="xs" c="dimmed">
                No Command
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
                Sequential
              </Text>
            </Group>
          </Group>
        </div>
      )}
    </Paper>
  );
}
