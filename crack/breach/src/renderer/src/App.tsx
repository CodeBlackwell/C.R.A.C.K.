/**
 * B.R.E.A.C.H. Main Application
 *
 * Layout: Target Sidebar | Workspace (Terminal/Topology) | Session Dock
 */

import { useState, useEffect, useCallback } from 'react';
import {
  MantineProvider,
  AppShell,
  Text,
  Badge,
  Group,
  Paper,
  Button,
} from '@mantine/core';
import '@mantine/core/styles.css';
import { TerminalTabs } from './components/terminal/TerminalTabs';
import { TargetSidebar } from './components/layout/TargetSidebar';
import { ContextPanel } from './components/context';
import { EngagementSelector } from './components/header';
import { EngagementManager } from './components/modals';
import type { TerminalSession } from '@shared/types/session';
import type { Loot, PatternType } from '@shared/types/loot';
import type { Engagement } from '@shared/types/engagement';

type WorkspaceView = 'terminals' | 'topology';

function App() {
  const [connectionStatus, setConnectionStatus] = useState<{
    connected: boolean;
    uri?: string;
  }>({ connected: false });
  const [sessions, setSessions] = useState<TerminalSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [workspaceView, setWorkspaceView] = useState<WorkspaceView>('terminals');
  const [activeEngagement, setActiveEngagement] = useState<Engagement | null>(null);
  const [contextPanelCollapsed, setContextPanelCollapsed] = useState(false);
  const [engagementManagerOpen, setEngagementManagerOpen] = useState(false);

  // Check Neo4j connection on mount
  useEffect(() => {
    console.log('[App] Checking Neo4j connection...');
    window.electronAPI
      .healthCheck()
      .then((status) => {
        console.log('[App] Health check result:', status);
        setConnectionStatus(status);
      })
      .catch((error) => {
        console.error('[App] Health check error:', error);
        setConnectionStatus({ connected: false, uri: 'Error' });
      });

    // Load active engagement
    window.electronAPI
      .getActiveEngagement()
      .then((engagement) => {
        console.log('[App] Active engagement:', engagement);
        setActiveEngagement(engagement as Engagement | null);
      })
      .catch(console.error);
  }, []);

  // Handle engagement change (reload related data)
  const handleEngagementChange = useCallback((engagement: Engagement | null) => {
    console.log('[App] Engagement changed:', engagement?.name || 'none');
    setActiveEngagement(engagement);
    // Future: reload targets, credentials, loot for new engagement
  }, []);

  // Listen for session events
  useEffect(() => {
    const handleSessionCreated = (_: unknown, session: TerminalSession) => {
      console.log('[App] Session created:', session.id);
      setSessions((prev) => [...prev, session]);
      setActiveSessionId(session.id);
    };

    const handleSessionStatus = (
      _: unknown,
      data: { sessionId: string; status: string }
    ) => {
      console.log('[App] Session status update:', data);
      setSessions((prev) =>
        prev.map((s) =>
          s.id === data.sessionId ? { ...s, status: data.status as TerminalSession['status'] } : s
        )
      );
    };

    window.electronAPI.onSessionCreated(handleSessionCreated as any);
    window.electronAPI.onSessionStatus(handleSessionStatus as any);

    return () => {
      window.electronAPI.removeSessionCreatedListener(handleSessionCreated as any);
      window.electronAPI.removeSessionStatusListener(handleSessionStatus as any);
    };
  }, []);

  // Load initial sessions
  useEffect(() => {
    window.electronAPI
      .sessionList()
      .then((sessionList) => {
        console.log('[App] Loaded sessions:', sessionList.length);
        setSessions(sessionList);
        if (sessionList.length > 0 && !activeSessionId) {
          setActiveSessionId(sessionList[0].id);
        }
      })
      .catch(console.error);
  }, []);

  const handleSessionSelect = useCallback((sessionId: string) => {
    setActiveSessionId(sessionId);
  }, []);

  const handleSessionKill = useCallback(async (sessionId: string) => {
    const success = await window.electronAPI.sessionKill(sessionId);
    if (success) {
      setSessions((prev) => prev.filter((s) => s.id !== sessionId));
      if (activeSessionId === sessionId) {
        setActiveSessionId(sessions[0]?.id || null);
      }
    }
  }, [activeSessionId, sessions]);

  const handleSessionBackground = useCallback(async (sessionId: string) => {
    await window.electronAPI.sessionBackground(sessionId);
  }, []);

  const handleNewSession = useCallback(async () => {
    // Default: bash shell
    const session = await window.electronAPI.sessionCreate('bash', [], {
      type: 'shell',
      label: 'bash',
      interactive: true,
    });
    console.log('[App] New session created:', session.id);
  }, []);

  // Handle using a credential (spawn command in new session)
  const handleUseCredential = useCallback(async (command: string, credentialId: string) => {
    console.log('[App] Using credential:', credentialId, 'Command:', command);
    // Create a new session with the command
    const session = await window.electronAPI.sessionCreate('bash', ['-c', command], {
      type: 'shell',
      label: `cred-${credentialId.slice(0, 6)}`,
      interactive: true,
    });
    console.log('[App] Credential session created:', session.id);
  }, []);

  // Handle extracting credentials from loot
  const handleExtractCredential = useCallback(async (loot: Loot, pattern: PatternType) => {
    console.log('[App] Extracting credential from loot:', loot.name, 'Pattern:', pattern);
    // TODO: Implement PRISM integration to extract and add credential
    // For now, just log it
  }, []);

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
        padding={0}
        styles={{
          main: {
            background: '#1a1b1e',
            display: 'flex',
            flexDirection: 'column',
          },
        }}
      >
        {/* Header */}
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
            <Group gap="md">
              <Text
                size="lg"
                fw={700}
                style={{
                  background: 'linear-gradient(45deg, #ff6b6b, #ffd93d)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                }}
              >
                B.R.E.A.C.H.
              </Text>
              <EngagementSelector
                activeEngagement={activeEngagement}
                onEngagementChange={handleEngagementChange}
                onOpenManager={() => setEngagementManagerOpen(true)}
                onQuickCreate={() => setEngagementManagerOpen(true)}
              />
            </Group>

            <Group gap="md">
              <Group gap="xs">
                <Button
                  size="xs"
                  variant={workspaceView === 'terminals' ? 'filled' : 'subtle'}
                  color="gray"
                  onClick={() => setWorkspaceView('terminals')}
                >
                  Terminals
                </Button>
                <Button
                  size="xs"
                  variant={workspaceView === 'topology' ? 'filled' : 'subtle'}
                  color="gray"
                  onClick={() => setWorkspaceView('topology')}
                >
                  Topology
                </Button>
              </Group>

              <Badge
                color={connectionStatus.connected ? 'teal' : 'red'}
                variant="light"
              >
                {connectionStatus.connected
                  ? `Neo4j: ${connectionStatus.uri}`
                  : 'Disconnected'}
              </Badge>
            </Group>
          </Group>
        </AppShell.Header>

        {/* Main Content */}
        <AppShell.Main>
          <div
            style={{
              display: 'flex',
              height: 'calc(100vh - 40px)',
              overflow: 'hidden',
            }}
          >
            {/* Left Sidebar: Targets */}
            <TargetSidebar
              engagementId={activeEngagement?.id as string}
              onTargetSelect={(targetId) => console.log('Target selected:', targetId)}
            />

            {/* Center: Workspace */}
            <div
              style={{
                flex: 1,
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden',
              }}
            >
              {workspaceView === 'terminals' ? (
                <TerminalTabs
                  sessions={sessions}
                  activeSessionId={activeSessionId}
                  onSessionSelect={handleSessionSelect}
                  onSessionKill={handleSessionKill}
                  onSessionBackground={handleSessionBackground}
                  onNewSession={handleNewSession}
                />
              ) : (
                <Paper
                  style={{
                    flex: 1,
                    background: '#25262b',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Text c="dimmed">Session Topology (Coming Soon)</Text>
                </Paper>
              )}
            </div>

            {/* Right: Context Panel (Credentials, Loot, Actions) */}
            <ContextPanel
              engagementId={activeEngagement?.id as string}
              collapsed={contextPanelCollapsed}
              onToggleCollapse={() => setContextPanelCollapsed(!contextPanelCollapsed)}
              onUseCredential={handleUseCredential}
              onExtractCredential={handleExtractCredential}
            />
          </div>
        </AppShell.Main>
      </AppShell>

      {/* Engagement Manager Modal */}
      <EngagementManager
        opened={engagementManagerOpen}
        onClose={() => setEngagementManagerOpen(false)}
        activeEngagement={activeEngagement}
        onEngagementChange={handleEngagementChange}
      />
    </MantineProvider>
  );
}

export default App;
