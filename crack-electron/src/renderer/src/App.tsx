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
import CommandDetails from './components/CommandDetails';
import CommandChainGraph from './components/CommandChainGraph';
import { Command } from './types/command';
import { Cheatsheet } from './types/cheatsheet';

type ViewMode = 'details' | 'graph';
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
  const [activeView, setActiveView] = useState<'commands' | 'cheatsheets' | 'chains' | 'writeups'>('chains');
  const [expandedCommandId, setExpandedCommandId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('details');
  const [chainViewMode, setChainViewMode] = useState<ChainViewMode>('graph');

  // Debug: Log component mount
  useEffect(() => {
    console.log('[App] Component mounted');
    console.log('[App] Window dimensions:', {
      width: window.innerWidth,
      height: window.innerHeight,
    });
    console.log('[App] electronAPI available:', !!window.electronAPI);
  }, []);

  // Debug: Log active view changes
  useEffect(() => {
    console.log('[App] Active view changed:', activeView);
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
                      onClick={() => setActiveView('cheatsheets')}
                      style={{ flex: 1 }}
                    >
                      Cheatsheets
                    </Button>
                    <Button
                      size="sm"
                      variant={activeView === 'chains' ? 'filled' : 'subtle'}
                      color={activeView === 'chains' ? 'cyan' : 'gray'}
                      onClick={() => setActiveView('chains')}
                      style={{ flex: 1 }}
                    >
                      Chains
                    </Button>
                    <Button
                      size="sm"
                      variant={activeView === 'commands' ? 'filled' : 'subtle'}
                      color={activeView === 'commands' ? 'cyan' : 'gray'}
                      onClick={() => setActiveView('commands')}
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
                    onClick={() => setActiveView('writeups')}
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
                      {viewMode === 'details' ? (
                        // Details mode: Show relationship graph
                        <GraphView
                          selectedCommandId={selectedCommand.id}
                          onNodeClick={handleCommandSelect}
                        />
                      ) : (
                        // Graph mode: Show attack chains (larger space)
                        <CommandChainGraph commandId={selectedCommand.id} />
                      )}
                    </div>

                    {/* Footer: Tags & Output Indicators (only in details mode) */}
                    {viewMode === 'details' && (
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

            {/* Right Panel: Command Details or Graph View based on view mode */}
            <div style={{ width: '450px', height: '100%' }}>
              {selectedCommand ? (
                viewMode === 'details' ? (
                  // Details mode: Show command details
                  <CommandDetails
                    command={selectedCommand}
                    viewMode={viewMode}
                    onViewModeChange={setViewMode}
                    onCommandSelect={handleCommandSelect}
                  />
                ) : (
                  // Graph mode: Show relationship graph in right panel
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
                    </Group>

                    {/* Relationship graph */}
                    <div style={{ flex: 1, position: 'relative' }}>
                      <GraphView
                        selectedCommandId={selectedCommand.id}
                        onNodeClick={handleCommandSelect}
                      />
                    </div>

                    {/* Footer: Tags & Output Indicators */}
                    <Paper
                      style={{
                        background: '#25262b',
                        borderTop: '1px solid #373A40',
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
                  </Paper>
                )
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
