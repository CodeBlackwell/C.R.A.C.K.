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
import { log, LogCategory } from '@shared/electron/debug-renderer';
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
  const [selectedTarget, setSelectedTarget] = useState<{
    id: string;
    ip: string;
    hostname?: string;
  } | null>(null);

  // Check Neo4j connection on mount
  useEffect(() => {
    log.ipc('Checking Neo4j connection...');
    window.electronAPI
      .healthCheck()
      .then((status) => {
        log.data('Health check result', status);
        setConnectionStatus(status);
      })
      .catch((error) => {
        log.error(LogCategory.IPC, 'Health check failed', error);
        setConnectionStatus({ connected: false, uri: 'Error' });
      });

    // Load active engagement
    window.electronAPI
      .getActiveEngagement()
      .then((engagement) => {
        log.data('Active engagement loaded', { name: (engagement as Engagement | null)?.name });
        setActiveEngagement(engagement as Engagement | null);
      })
      .catch((err) => log.error(LogCategory.DATA, 'Failed to load engagement', err));
  }, []);

  // Handle engagement change (reload related data)
  const handleEngagementChange = useCallback((engagement: Engagement | null) => {
    log.action('Engagement changed', { name: engagement?.name || 'none', id: engagement?.id });
    setActiveEngagement(engagement);
    // Future: reload targets, credentials, loot for new engagement
  }, []);

  // Listen for session events
  useEffect(() => {
    const handleSessionCreated = (_: unknown, session: TerminalSession) => {
      log.lifecycle('Session created', { sessionId: session.id, type: session.type });
      setSessions((prev) => {
        // Prevent duplicates from StrictMode double-invocation
        if (prev.some((s) => s.id === session.id)) {
          return prev;
        }
        return [...prev, session];
      });
      setActiveSessionId(session.id);
    };

    const handleSessionStatus = (
      _: unknown,
      data: { sessionId: string; status: string }
    ) => {
      log.lifecycle('Session status update', data);
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
        log.data('Loaded sessions', { count: sessionList.length });
        setSessions(sessionList);
        if (sessionList.length > 0 && !activeSessionId) {
          setActiveSessionId(sessionList[0].id);
        }
      })
      .catch((err) => log.error(LogCategory.DATA, 'Failed to load sessions', err));
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
    log.action('New session created', { sessionId: session.id });
  }, []);

  // Handle using a credential (spawn command in new session)
  const handleUseCredential = useCallback(async (command: string, credentialId: string) => {
    log.action('Using credential', { credentialId, command: command.substring(0, 50) });
    // Create a new session with the command
    const session = await window.electronAPI.sessionCreate('bash', ['-c', command], {
      type: 'shell',
      label: `cred-${credentialId.slice(0, 6)}`,
      interactive: true,
    });
    log.lifecycle('Credential session created', { sessionId: session.id, credentialId });
  }, []);

  // Handle extracting credentials from loot
  const handleExtractCredential = useCallback(async (loot: Loot, pattern: PatternType) => {
    log.action('Extracting credential from loot', { lootName: loot.name, pattern });
    // TODO: Implement PRISM integration to extract and add credential
  }, []);

  // Handle target selection from sidebar
  const handleTargetSelect = useCallback((targetId: string, targetIp: string, targetHostname?: string) => {
    log.action('Target selected', { targetId, ip: targetIp, hostname: targetHostname });
    setSelectedTarget({ id: targetId, ip: targetIp, hostname: targetHostname });
  }, []);

  // Handle executing action from ActionsPanel
  const handleExecuteAction = useCallback(async (command: string, label: string) => {
    log.action('Executing action', { label, command: command.substring(0, 80), targetId: selectedTarget?.id });
    // Create a new terminal session with the command
    const session = await window.electronAPI.sessionCreate('bash', ['-c', command], {
      type: 'shell',
      label: label,
      interactive: true,
      targetId: selectedTarget?.id,
    });
    log.lifecycle('Action session created', { sessionId: session.id, label });
  }, [selectedTarget]);

  // Handle target action (Nmap scan, etc.)
  const handleTargetAction = useCallback(async (command: string, targetId: string, actionLabel: string) => {
    log.action('Target action', { label: actionLabel, targetId, command: command.substring(0, 80) });
    // Create a new session with the command
    const session = await window.electronAPI.sessionCreate('bash', ['-c', command], {
      type: 'shell',
      label: actionLabel,
      interactive: true,
    });
    log.lifecycle('Target action session created', { sessionId: session.id, targetId, label: actionLabel });
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
              selectedTargetId={selectedTarget?.id}
              onTargetSelect={handleTargetSelect}
              onTargetAction={handleTargetAction}
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
              selectedTargetId={selectedTarget?.id}
              selectedTargetIp={selectedTarget?.ip}
              selectedTargetHostname={selectedTarget?.hostname}
              onExecuteAction={handleExecuteAction}
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
