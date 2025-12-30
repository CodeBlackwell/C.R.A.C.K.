import { useEffect, useState } from 'react';
import { Paper, Text, Badge, Group, Stack, Button, ScrollArea, Divider, Code, Loader, Center } from '@mantine/core';
import { AttackChain } from '../types/chain';
import ChainStepDetails from './ChainStepDetails';
import ChainCommandView from './ChainCommandView';
import GraphView from './GraphView';

interface ChainControlsPanelProps {
  chainId: string;
  chainViewMode: 'graph' | 'list';
  onViewModeChange: (mode: 'graph' | 'list') => void;
  selectedStepId?: string | null;
  onCommandClick?: (commandId: string) => void;
  onClearStep?: () => void;
  onStepClick?: (stepId: string) => void;
  chainCommandView?: string | null;
  onCommandViewBack?: () => void;
}

type RightPanelView = 'details' | 'graph';

export default function ChainControlsPanel({
  chainId,
  chainViewMode,
  onViewModeChange,
  selectedStepId,
  onCommandClick,
  onClearStep,
  onStepClick,
  chainCommandView,
  onCommandViewBack,
}: ChainControlsPanelProps) {
  const [chain, setChain] = useState<AttackChain | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [rightPanelView, setRightPanelView] = useState<RightPanelView>('details');
  const [projectRoot, setProjectRoot] = useState('');

  // Fetch project root on mount
  useEffect(() => {
    window.electronAPI.getProjectRoot().then(setProjectRoot);
  }, []);

  // Derive source file path from chain ID (same logic as ChainDetails)
  const getSourcePath = (id: string): string => {
    const basePath = `${projectRoot}/db/data/chains`;

    let subdirectory = '';
    if (id.startsWith('ad-')) {
      subdirectory = 'active_directory';
    } else if (id.startsWith('web-')) {
      subdirectory = 'enumeration';
    } else if (id.startsWith('windows-lateral-') || id.startsWith('linux-exploit-')) {
      subdirectory = 'lateral_movement';
    } else if (id.startsWith('linux-privesc-')) {
      subdirectory = 'privilege_escalation';
    }

    return `${basePath}/${subdirectory}/${id}.json`;
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'green';
      case 'intermediate': return 'yellow';
      case 'advanced': return 'red';
      default: return 'gray';
    }
  };

  const handleCopyPath = () => {
    if (chain) {
      const sourcePath = getSourcePath(chain.id);
      navigator.clipboard.writeText(sourcePath);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  useEffect(() => {
    console.log('[ChainControlsPanel] Component mounted with chainId:', chainId);
  }, []);

  useEffect(() => {
    if (!chainId) {
      setChain(null);
      return;
    }

    const loadChain = async () => {
      setLoading(true);
      try {
        console.log('[ChainControlsPanel] Loading chain:', chainId);
        const data = await window.electronAPI.getChain(chainId);
        console.log('[ChainControlsPanel] Chain loaded:', data);
        setChain(data);
      } catch (error) {
        console.error('[ChainControlsPanel] Error loading chain:', error);
        setChain(null);
      } finally {
        setLoading(false);
      }
    };

    loadChain();
  }, [chainId]);

  // Log content decision
  const showStepDetails = selectedStepId && chainViewMode === 'graph';
  console.log('[ChainControlsPanel] [RENDER] Content decision:', {
    selectedStepId,
    chainViewMode,
    showStepDetails,
  });

  if (loading || !chain) {
    return (
      <Paper
        shadow="sm"
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
          {loading ? <Loader size="lg" /> : <Text c="dimmed" size="sm">Failed to load chain</Text>}
        </Center>
      </Paper>
    );
  }

  return (
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
      {/* Header with view mode toggle */}
      <Stack gap="xs" p="md" style={{ borderBottom: '1px solid #373A40' }}>
        {/* Primary navigation: Details / Graph View */}
        <Group gap="xs">
          <Button
            size="xs"
            variant={rightPanelView === 'details' ? 'filled' : 'subtle'}
            color="gray"
            onClick={() => {
              setRightPanelView('details');
              console.log('[ChainControlsPanel] Right panel view changed to: details');
            }}
          >
            Details
          </Button>
          <Button
            size="xs"
            variant={rightPanelView === 'graph' ? 'filled' : 'subtle'}
            color="gray"
            onClick={() => {
              setRightPanelView('graph');
              console.log('[ChainControlsPanel] Right panel view changed to: graph');
            }}
          >
            Graph View
          </Button>
        </Group>

        {/* Secondary navigation: Only show in details mode */}
        {rightPanelView === 'details' && (
          <Group gap="xs">
            <Button
              size="xs"
              variant={chainViewMode === 'graph' && !selectedStepId ? 'filled' : 'subtle'}
              color="cyan"
              onClick={() => {
                onViewModeChange('graph');
                if (onClearStep) {
                  onClearStep();
                }
                console.log('[ChainControlsPanel] View mode changed to: graph, step cleared');
              }}
            >
              Chain Info
            </Button>
            <Button
              size="xs"
              variant={selectedStepId && chainViewMode === 'graph' ? 'filled' : 'subtle'}
              color="cyan"
              disabled={!selectedStepId}
              onClick={() => {
                // When clicked, switch to graph view to show the step details
                if (chainViewMode !== 'graph') {
                  onViewModeChange('graph');
                }
                console.log('[ChainControlsPanel] Switching to graph view to show step info');
              }}
            >
              Step Info
            </Button>
            <Button
              size="xs"
              variant={chainViewMode === 'list' ? 'filled' : 'subtle'}
              color="cyan"
              onClick={() => {
                onViewModeChange('list');
                console.log('[ChainControlsPanel] View mode changed to: list');
              }}
            >
              List View
            </Button>
          </Group>
        )}
      </Stack>

      {/* Content Area: Show based on view mode */}
      {chainCommandView && onCommandViewBack ? (
        // Command Reference View: Show command details with breadcrumb
        <div style={{ flex: 1, overflow: 'hidden' }}>
          {console.log('[ChainControlsPanel] [RENDER] Showing ChainCommandView for command:', chainCommandView)}
          <ChainCommandView
            commandId={chainCommandView}
            chainName={chain.name}
            stepNumber={selectedStepId ? parseInt(selectedStepId.split('-').pop() || '0', 10) : null}
            onBack={onCommandViewBack}
            onCommandClick={onCommandClick}
          />
        </div>
      ) : rightPanelView === 'graph' ? (
        // Graph View: Show command relationship graph
        <div style={{ flex: 1, overflow: 'hidden' }}>
          {(() => {
            // Get the command ID from the selected step
            const selectedStep = chain?.steps?.find(s => s.id === selectedStepId);
            const commandId = selectedStep?.command?.id;

            console.log('[ChainControlsPanel] [RENDER] Graph View mode:', {
              selectedStepId,
              hasStep: !!selectedStep,
              commandId,
            });

            if (!commandId) {
              return (
                <Paper
                  style={{
                    height: '100%',
                    background: '#25262b',
                    border: '1px solid #373A40',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Center>
                    <Stack gap="xs" align="center" style={{ maxWidth: '300px', textAlign: 'center' }}>
                      <Text c="dimmed" size="sm">
                        Select a step with a command to view its relationship graph
                      </Text>
                      <Text c="dimmed" size="xs" style={{ opacity: 0.7 }}>
                        Click a step in the chain graph, then switch to Graph View
                      </Text>
                    </Stack>
                  </Center>
                </Paper>
              );
            }

            return (
              <GraphView
                selectedCommandId={commandId}
                onNodeClick={(clickedCommandId) => {
                  if (onCommandClick) {
                    onCommandClick(clickedCommandId);
                  }
                }}
              />
            );
          })()}
        </div>
      ) : showStepDetails ? (
        // Details View: Show step details
        <div style={{ flex: 1, overflow: 'hidden' }}>
          {console.log('[ChainControlsPanel] [RENDER] Showing ChainStepDetails for step:', selectedStepId)}
          <ChainStepDetails
            chainId={chainId}
            stepId={selectedStepId}
            onCommandClick={onCommandClick}
          />
        </div>
      ) : (
        // Details View: Show chain metadata
        <ScrollArea
          style={{ flex: 1 }}
          type="auto"
          offsetScrollbars
          scrollbarSize={8}
        >
          {console.log('[ChainControlsPanel] [RENDER] Showing chain metadata')}
          <Stack gap="md" p="md">
            {/* Chain Name */}
            <div>
              <Text size="lg" fw={700} mb="xs">
                {chain.name}
              </Text>
              <Text size="xs" c="dimmed">
                {chain.category}
              </Text>
            </div>

            <Divider color="#373A40" />

            {/* Badges */}
            <div>
              <Text size="xs" fw={600} mb="xs" c="dimmed">
                Properties
              </Text>
              <Group gap={6}>
                <Badge
                  size="sm"
                  variant="light"
                  color={getDifficultyColor(chain.difficulty)}
                >
                  {chain.difficulty}
                </Badge>
                {(chain.oscp_relevant === true || chain.oscp_relevant === 'True') && (
                  <Badge size="sm" variant="light" color="blue">
                    OSCP
                  </Badge>
                )}
                {chain.time_estimate && (
                  <Badge size="sm" variant="dot" color="gray">
                    {chain.time_estimate}
                  </Badge>
                )}
                <Badge size="sm" variant="light" color="cyan">
                  {chain.platform}
                </Badge>
              </Group>
            </div>

            <Divider color="#373A40" />

            {/* Description */}
            {chain.description && (
              <>
                <div>
                  <Text size="xs" fw={600} mb="xs" c="dimmed">
                    Description
                  </Text>
                  <Text size="sm" c="dimmed">
                    {chain.description}
                  </Text>
                </div>
                <Divider color="#373A40" />
              </>
            )}

            {/* Source Path */}
            <div>
              <Text size="xs" fw={600} mb="xs" c="dimmed">
                Source File
              </Text>
              <Code
                onClick={handleCopyPath}
                style={{
                  fontSize: '10px',
                  background: copied ? '#2b8a3e' : '#1a1b1e',
                  border: `1px solid ${copied ? '#40c057' : '#373A40'}`,
                  padding: '8px',
                  display: 'block',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                  wordBreak: 'break-all',
                }}
              >
                {copied ? '✓ Copied to clipboard!' : getSourcePath(chain.id)}
              </Code>
            </div>

            {/* OSCP Notes */}
            {chain.notes && (
              <>
                <Divider color="#373A40" />
                <div>
                  <Text size="xs" fw={600} mb="xs" c="dimmed">
                    OSCP Notes
                  </Text>
                  <Paper
                    p="sm"
                    style={{
                      background: '#1a1b1e',
                      border: '1px solid #373A40',
                    }}
                  >
                    <Text size="xs" c="dimmed" style={{ whiteSpace: 'pre-wrap' }}>
                      {chain.notes}
                    </Text>
                  </Paper>
                </div>
              </>
            )}
          </Stack>
        </ScrollArea>
      )}
    </Paper>
  );
}
