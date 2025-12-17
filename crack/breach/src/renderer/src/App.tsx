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
  Tooltip,
} from '@mantine/core';
import { IconRadar } from '@tabler/icons-react';
import '@mantine/core/styles.css';
import { TerminalTabs } from './components/terminal/TerminalTabs';
import { TargetSidebar } from './components/layout/TargetSidebar';
import { ContextPanel } from './components/context';
import { EngagementSelector } from './components/header';
import { EngagementManager, PrismScanModal, RestoreSessionsModal, type PrismScanResults } from './components/modals';
import { log, LogCategory } from '@shared/electron/debug-renderer';
import type { TerminalSession } from '@shared/types/session';
import type { Loot, PatternType } from '@shared/types/loot';
import type { Engagement } from '@shared/types/engagement';
import type { RestoreSessionInfo } from '@shared/types/persistence';

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
  const [scanModalOpen, setScanModalOpen] = useState(false);
  const [scanResults, setScanResults] = useState<PrismScanResults | null>(null);
  const [contextTab, setContextTab] = useState<string>('actions');
  const [restoreModalOpen, setRestoreModalOpen] = useState(false);
  const [persistedSessions, setPersistedSessions] = useState<RestoreSessionInfo[]>([]);
  const [autoscanEnabled, setAutoscanEnabled] = useState(true);

  // Check Neo4j connection and load autoscan state on mount
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

    // Load PRISM autoscan state
    window.electronAPI
      .prismGetAutoscan()
      .then((enabled) => {
        log.data('PRISM autoscan state loaded', { enabled });
        setAutoscanEnabled(enabled);
      })
      .catch((err) => log.error(LogCategory.IPC, 'Failed to load autoscan state', err));

    // Load active engagement or auto-select first if none active
    window.electronAPI
      .getActiveEngagement()
      .then(async (engagement) => {
        let activeEng: Engagement | null = null;

        if (engagement) {
          log.data('Active engagement loaded', { name: (engagement as Engagement).name });
          activeEng = engagement as Engagement;
          setActiveEngagement(activeEng);
        } else {
          // No active engagement - auto-select first if available
          log.data('No active engagement, checking for available engagements');
          const engagements = await window.electronAPI.engagementList();
          if (engagements && engagements.length > 0) {
            log.action('Auto-selecting first engagement', { name: engagements[0].name });
            await window.electronAPI.engagementActivate(engagements[0].id);
            activeEng = engagements[0] as Engagement;
            setActiveEngagement(activeEng);
          }
        }

        // Check for persisted sessions after engagement is loaded
        if (activeEng) {
          try {
            const restoreInfo = await window.electronAPI.sessionGetRestoreInfo(activeEng.id);
            if (restoreInfo && restoreInfo.length > 0) {
              log.data('Found persisted sessions', { count: restoreInfo.length });
              setPersistedSessions(restoreInfo);
              setRestoreModalOpen(true);
            }
          } catch (err) {
            log.error(LogCategory.DATA, 'Failed to check persisted sessions', err);
          }
        }
      })
      .catch((err) => log.error(LogCategory.DATA, 'Failed to load engagement', err));
  }, []);

  // Handle engagement change (reload related data)
  const handleEngagementChange = useCallback((engagement: Engagement | null) => {
    log.action('Engagement changed', { name: engagement?.name || 'none', id: engagement?.id });
    setActiveEngagement(engagement);
    // Future: reload targets, credentials, loot for new engagement
  }, []);

  // Handle PRISM autoscan toggle
  const handleAutoscanToggle = useCallback(async (enabled: boolean) => {
    log.action('PRISM autoscan toggled', { enabled });
    try {
      await window.electronAPI.prismSetAutoscan(enabled);
      setAutoscanEnabled(enabled);
    } catch (error) {
      log.error(LogCategory.IPC, 'Failed to toggle autoscan', error);
    }
  }, []);

  // Handle restoring persisted sessions
  const handleRestoreSessions = useCallback(async (sessionIds: string[]) => {
    if (!activeEngagement) return;

    log.action('Restoring sessions', { count: sessionIds.length });

    try {
      const restored = await window.electronAPI.sessionRestore(sessionIds, activeEngagement.id);
      log.data('Sessions restored', { count: restored.length });
      // Sessions will be added via session-created event
    } catch (error) {
      log.error(LogCategory.IPC, 'Failed to restore sessions', error);
    }
  }, [activeEngagement]);

  // Handle starting fresh (clearing persisted sessions)
  const handleStartFresh = useCallback(async () => {
    if (!activeEngagement) return;

    log.action('Starting fresh, clearing persisted sessions');

    try {
      await window.electronAPI.sessionClearPersisted(activeEngagement.id);
      setPersistedSessions([]);
    } catch (error) {
      log.error(LogCategory.IPC, 'Failed to clear persisted sessions', error);
    }
  }, [activeEngagement]);

  // Listen for session events - use window to survive HMR
  useEffect(() => {
    const HANDLERS_KEY = '__BREACH_SESSION_HANDLERS__';
    const existing = (window as any)[HANDLERS_KEY] as {
      created?: (event: unknown, session: TerminalSession) => void;
      status?: (event: unknown, data: { sessionId: string; status: string }) => void;
    } | undefined;

    // Remove existing listeners first (handles HMR and StrictMode)
    if (existing?.created) {
      window.electronAPI.removeSessionCreatedListener(existing.created as any);
    }
    if (existing?.status) {
      window.electronAPI.removeSessionStatusListener(existing.status as any);
    }

    const handleSessionCreated = (_: unknown, session: TerminalSession) => {
      log.lifecycle('Session created', { sessionId: session.id, type: session.type });
      setSessions((prev) => {
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

    // Store handlers globally to survive HMR
    (window as any)[HANDLERS_KEY] = {
      created: handleSessionCreated,
      status: handleSessionStatus,
    };

    window.electronAPI.onSessionCreated(handleSessionCreated as any);
    window.electronAPI.onSessionStatus(handleSessionStatus as any);

    return () => {
      const handlers = (window as any)[HANDLERS_KEY];
      if (handlers?.created) {
        window.electronAPI.removeSessionCreatedListener(handlers.created as any);
      }
      if (handlers?.status) {
        window.electronAPI.removeSessionStatusListener(handlers.status as any);
      }
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
      engagementId: activeEngagement?.id,
    });
    log.action('New session created', { sessionId: session.id });
  }, [activeEngagement?.id]);

  // Handle PRISM scan of session output
  const handlePrismScan = useCallback(async (sessionId: string) => {
    if (!activeEngagement) {
      log.error(LogCategory.ACTION, 'Cannot scan: no active engagement');
      return;
    }

    log.action('PRISM scan requested', { sessionId, engagementId: activeEngagement.id });

    try {
      const results = await window.electronAPI.sessionPrismScan(
        sessionId,
        activeEngagement.id,
        selectedTarget?.id
      );

      log.data('PRISM scan completed', {
        credentials: results.credentials.length,
        findings: results.findings.length,
      });

      setScanResults(results);
      setScanModalOpen(true);
    } catch (error) {
      log.error(LogCategory.IPC, 'PRISM scan failed', error);
    }
  }, [activeEngagement, selectedTarget?.id]);

  // Handle PRISM scan of selected text from terminal
  const handlePrismScanSelection = useCallback(async (text: string, sessionId: string) => {
    if (!activeEngagement) {
      log.error(LogCategory.ACTION, 'Cannot scan selection: no active engagement');
      return;
    }

    log.action('PRISM scan selection', { textLength: text.length, sessionId, engagementId: activeEngagement.id });

    try {
      const results = await window.electronAPI.prismScanText(
        text,
        activeEngagement.id,
        selectedTarget?.id,
        sessionId
      );

      log.data('PRISM scan selection completed', {
        credentials: results.credentials.length,
        findings: results.findings.length,
      });

      setScanResults(results);
      setScanModalOpen(true);
    } catch (error) {
      log.error(LogCategory.IPC, 'PRISM scan selection failed', error);
    }
  }, [activeEngagement, selectedTarget?.id]);

  // Handle using a credential (spawn command in new session)
  const handleUseCredential = useCallback(async (command: string, credentialId: string) => {
    log.action('Using credential', { credentialId, command: command.substring(0, 50) });
    // Create a new session with the command
    const session = await window.electronAPI.sessionCreate('bash', ['-c', command], {
      type: 'shell',
      label: `cred-${credentialId.slice(0, 6)}`,
      interactive: true,
      engagementId: activeEngagement?.id,
    });
    log.lifecycle('Credential session created', { sessionId: session.id, credentialId });
  }, [activeEngagement?.id]);

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
  const handleExecuteAction = useCallback(async (command: string, label: string, autorun: boolean = true) => {
    console.log('[App] handleExecuteAction called', { command, label, autorun, targetId: selectedTarget?.id });
    log.action('Executing action', { label, autorun, command: command.substring(0, 80), targetId: selectedTarget?.id });

    try {
      if (autorun) {
        // Execute immediately - create new terminal session
        console.log('[App] Creating new session with command:', command);
        const session = await window.electronAPI.sessionCreate('bash', ['-c', command], {
          type: 'shell',
          label: label,
          interactive: true,
          targetId: selectedTarget?.id,
          engagementId: activeEngagement?.id,
        });
        console.log('[App] Session created successfully', { sessionId: session.id });
        log.lifecycle('Action session created', { sessionId: session.id, label });
      } else {
        // Prefill mode - create shell and write command without executing
        const session = await window.electronAPI.sessionCreate('bash', [], {
          type: 'shell',
          label: label,
          interactive: true,
          targetId: selectedTarget?.id,
          engagementId: activeEngagement?.id,
        });
        // Write the command to terminal (without newline so it doesn't execute)
        await window.electronAPI.sessionWrite(session.id, command);
        log.lifecycle('Action session prefilled', { sessionId: session.id, label });
      }
    } catch (error) {
      console.error('[App] handleExecuteAction failed:', error);
      log.error(LogCategory.IPC, 'Failed to execute action', error);
    }
  }, [selectedTarget, activeEngagement?.id]);

  // Handle target action (Nmap scan, etc.)
  const handleTargetAction = useCallback(async (command: string, targetId: string, actionLabel: string) => {
    log.action('Target action', { label: actionLabel, targetId, command: command.substring(0, 80) });
    // Create a new session with the command
    const session = await window.electronAPI.sessionCreate('bash', ['-c', command], {
      type: 'shell',
      label: actionLabel,
      interactive: true,
      targetId: targetId,
      engagementId: activeEngagement?.id,
    });
    log.lifecycle('Target action session created', { sessionId: session.id, targetId, label: actionLabel });
  }, [activeEngagement?.id]);

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

              {/* PRISM Autoscan Toggle */}
              <Tooltip
                label={autoscanEnabled ? 'Click to disable PRISM autoscan' : 'Click to enable PRISM autoscan'}
                position="bottom"
              >
                <Badge
                  color={autoscanEnabled ? 'cyan' : 'gray'}
                  variant={autoscanEnabled ? 'filled' : 'outline'}
                  leftSection={<IconRadar size={12} />}
                  style={{ cursor: 'pointer', userSelect: 'none' }}
                  onClick={() => handleAutoscanToggle(!autoscanEnabled)}
                >
                  {autoscanEnabled ? 'PRISM' : 'PRISM Off'}
                </Badge>
              </Tooltip>

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
                  onSessionScan={handlePrismScan}
                  onNewSession={handleNewSession}
                  onPrismScanSelection={handlePrismScanSelection}
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
              activeTab={contextTab}
              onTabChange={setContextTab}
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

      {/* PRISM Scan Results Modal */}
      <PrismScanModal
        opened={scanModalOpen}
        onClose={() => setScanModalOpen(false)}
        results={scanResults}
        onViewFindings={() => {
          log.action('Navigate to Findings tab');
          setContextTab('findings');
          setContextPanelCollapsed(false);
          setScanModalOpen(false);
        }}
        onViewCredentials={() => {
          log.action('Navigate to Credentials tab');
          setContextTab('credentials');
          setContextPanelCollapsed(false);
          setScanModalOpen(false);
        }}
      />

      {/* Session Restore Modal */}
      <RestoreSessionsModal
        opened={restoreModalOpen}
        onClose={() => setRestoreModalOpen(false)}
        sessions={persistedSessions}
        engagementName={activeEngagement?.name}
        onRestore={handleRestoreSessions}
        onStartFresh={handleStartFresh}
      />
    </MantineProvider>
  );
}

export default App;
