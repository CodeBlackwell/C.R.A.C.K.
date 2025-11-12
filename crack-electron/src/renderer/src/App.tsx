import { useState, useEffect } from 'react';
import { MantineProvider, AppShell, Text, Badge, Group, Paper, Center } from '@mantine/core';
import '@mantine/core/styles.css';
import CommandSearch from './components/CommandSearch';
import GraphView from './components/GraphView';
import CommandDetails from './components/CommandDetails';
import { Command } from './types/command';

function App() {
  const [selectedCommand, setSelectedCommand] = useState<Command | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<{
    connected: boolean;
    uri?: string;
  }>({ connected: false });

  // Debug: Log component mount
  useEffect(() => {
    console.log('[App] Component mounted');
    console.log('[App] Window dimensions:', {
      width: window.innerWidth,
      height: window.innerHeight,
    });
    console.log('[App] electronAPI available:', !!window.electronAPI);
  }, []);

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
    } catch (error) {
      console.error('[App] Error fetching command:', error);
    }
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
            {/* Left Panel: Search */}
            <div style={{ width: '350px' }}>
              <CommandSearch onSelectCommand={handleCommandSelect} />
            </div>

            {/* Center Panel: Graph */}
            <div style={{ flex: 1 }}>
              <GraphView
                selectedCommandId={selectedCommand?.id}
                onNodeClick={handleCommandSelect}
              />
            </div>

            {/* Right Panel: Details */}
            <div style={{ width: '450px' }}>
              {selectedCommand ? (
                <CommandDetails command={selectedCommand} />
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
                      Select a command to view details
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
