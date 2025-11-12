import { useState, useEffect } from 'react';
import { MantineProvider, AppShell, Text, Badge, Group, Paper, Center, Code, Stack, Divider, SegmentedControl } from '@mantine/core';
import '@mantine/core/styles.css';
import CommandSearch from './components/CommandSearch';
import CheatsheetView from './components/CheatsheetView';
import CheatsheetDetails from './components/CheatsheetDetails';
import ChainView from './components/ChainView';
import GraphView from './components/GraphView';
import CommandDetails from './components/CommandDetails';
import { Command } from './types/command';
import { Cheatsheet } from './types/cheatsheet';

function App() {
  const [selectedCommand, setSelectedCommand] = useState<Command | null>(null);
  const [selectedCheatsheet, setSelectedCheatsheet] = useState<Cheatsheet | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<{
    connected: boolean;
    uri?: string;
  }>({ connected: false });
  const [activeView, setActiveView] = useState<'commands' | 'cheatsheets' | 'chains'>('commands');

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
    } catch (error) {
      console.error('[App] Error fetching cheatsheet:', error);
    }
  };

  const handleCheatsheetCommandClick = async (commandId: string) => {
    console.log('[App] Command clicked from cheatsheet:', commandId);
    // Load command and switch to commands view
    await handleCommandSelect(commandId);
    setActiveView('commands');
  };

  // Debug: Log state changes
  useEffect(() => {
    console.log('[App] Selected command changed:', selectedCommand?.id || 'none');
  }, [selectedCommand]);

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
              {/* Navigation Header */}
              <SegmentedControl
                value={activeView}
                onChange={(value) => setActiveView(value as 'commands' | 'cheatsheets' | 'chains')}
                data={[
                  { label: 'Commands', value: 'commands' },
                  { label: 'Cheatsheets', value: 'cheatsheets' },
                  { label: 'Chains', value: 'chains' },
                ]}
                fullWidth
                styles={{
                  root: {
                    background: '#25262b',
                    border: '1px solid #373A40',
                  },
                  label: {
                    padding: '8px 16px',
                  },
                }}
              />

              {/* Conditional View Rendering */}
              <div style={{ flex: 1, overflow: 'hidden' }}>
                {activeView === 'commands' && (
                  <CommandSearch onSelectCommand={handleCommandSelect} />
                )}
                {activeView === 'cheatsheets' && (
                  <CheatsheetView onSelectCheatsheet={handleCheatsheetSelect} />
                )}
                {activeView === 'chains' && <ChainView />}
              </div>
            </div>

            {/* Center Panel: Graph (only shown when not viewing cheatsheet) */}
            {!selectedCheatsheet && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {selectedCommand ? (
                  <>
                    <div style={{ flex: 1 }}>
                      <GraphView
                        selectedCommandId={selectedCommand.id}
                        onNodeClick={handleCommandSelect}
                      />
                    </div>

                    {/* Footer: Tags & Output Indicators */}
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

            {/* Right Panel: Details (expands when graph is hidden) */}
            <div style={{ width: selectedCheatsheet ? 'auto' : '450px', flex: selectedCheatsheet ? 1 : undefined, height: '100%' }}>
              {selectedCommand ? (
                <CommandDetails command={selectedCommand} />
              ) : selectedCheatsheet ? (
                <CheatsheetDetails
                  cheatsheet={selectedCheatsheet}
                  onCommandClick={handleCheatsheetCommandClick}
                />
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
                      Select a command or cheatsheet to view details
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
