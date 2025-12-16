/**
 * TerminalTabs - Tabbed Terminal Container
 *
 * Manages multiple terminal sessions with tab navigation.
 */

import { useMemo } from 'react';
import {
  Tabs,
  Group,
  ActionIcon,
  Badge,
  Text,
  Menu,
  Paper,
  Box,
} from '@mantine/core';
import {
  IconPlus,
  IconX,
  IconPlayerPause,
  IconTerminal2,
  IconServer,
  IconRoute,
  IconRadar,
  IconWorld,
  IconDotsVertical,
} from '@tabler/icons-react';
import { TerminalPane } from './TerminalPane';
import type { TerminalSession, SessionType } from '@shared/types/session';

interface TerminalTabsProps {
  sessions: TerminalSession[];
  activeSessionId: string | null;
  onSessionSelect: (sessionId: string) => void;
  onSessionKill: (sessionId: string) => void;
  onSessionBackground: (sessionId: string) => void;
  onSessionScan?: (sessionId: string) => void;
  onNewSession: () => void;
}

/** Icon map for session types */
const SESSION_ICONS: Record<SessionType, typeof IconTerminal2> = {
  shell: IconTerminal2,
  listener: IconServer,
  tunnel: IconRoute,
  proxy: IconWorld,
  scan: IconRadar,
  server: IconServer,
  custom: IconTerminal2,
};

/** Color map for session status */
const STATUS_COLORS: Record<string, string> = {
  starting: 'yellow',
  running: 'green',
  backgrounded: 'blue',
  stopped: 'gray',
  error: 'red',
  completed: 'teal',
  disconnected: 'orange',
};

export function TerminalTabs({
  sessions,
  activeSessionId,
  onSessionSelect,
  onSessionKill,
  onSessionBackground,
  onSessionScan,
  onNewSession,
}: TerminalTabsProps) {
  // Memoize session list to avoid unnecessary re-renders
  const sortedSessions = useMemo(() => {
    return [...sessions].sort((a, b) => {
      // Active sessions first, then by creation time
      if (a.status === 'running' && b.status !== 'running') return -1;
      if (b.status === 'running' && a.status !== 'running') return 1;
      return new Date(a.startedAt).getTime() - new Date(b.startedAt).getTime();
    });
  }, [sessions]);

  if (sessions.length === 0) {
    return (
      <Paper
        style={{
          flex: 1,
          background: '#1a1b1e',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexDirection: 'column',
          gap: '16px',
        }}
      >
        <IconTerminal2 size={48} color="#6e7681" />
        <Text c="dimmed" size="lg">
          No active sessions
        </Text>
        <ActionIcon
          variant="filled"
          color="cyan"
          size="lg"
          onClick={onNewSession}
        >
          <IconPlus size={20} />
        </ActionIcon>
      </Paper>
    );
  }

  return (
    <Tabs
      value={activeSessionId || undefined}
      onChange={(value) => value && onSessionSelect(value)}
      style={{ display: 'flex', flexDirection: 'column', height: '100%' }}
    >
      {/* Tab List */}
      <Tabs.List
        style={{
          background: '#25262b',
          borderBottom: '1px solid #373A40',
          flexShrink: 0,
        }}
      >
        {sortedSessions.map((session) => {
          const Icon = SESSION_ICONS[session.type] || IconTerminal2;
          return (
            <Tabs.Tab
              key={session.id}
              value={session.id}
              leftSection={<Icon size={14} />}
              rightSection={
                <Group gap={4}>
                  <Badge
                    size="xs"
                    variant="dot"
                    color={STATUS_COLORS[session.status] || 'gray'}
                  />
                  <Menu position="bottom-end" withinPortal>
                    <Menu.Target>
                      <Box
                        component="span"
                        onClick={(e: React.MouseEvent) => e.stopPropagation()}
                        style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          width: 18,
                          height: 18,
                          borderRadius: 4,
                          cursor: 'pointer',
                          color: '#868e96',
                        }}
                        onMouseEnter={(e: React.MouseEvent<HTMLSpanElement>) => {
                          e.currentTarget.style.background = 'rgba(134, 142, 150, 0.1)';
                        }}
                        onMouseLeave={(e: React.MouseEvent<HTMLSpanElement>) => {
                          e.currentTarget.style.background = 'transparent';
                        }}
                      >
                        <IconDotsVertical size={12} />
                      </Box>
                    </Menu.Target>
                    <Menu.Dropdown>
                      <Menu.Item
                        leftSection={<IconRadar size={14} />}
                        onClick={() => onSessionScan?.(session.id)}
                      >
                        Scan with PRISM
                      </Menu.Item>
                      <Menu.Item
                        leftSection={<IconPlayerPause size={14} />}
                        onClick={() => onSessionBackground(session.id)}
                        disabled={session.status !== 'running'}
                      >
                        Background
                      </Menu.Item>
                      <Menu.Divider />
                      <Menu.Item
                        color="red"
                        leftSection={<IconX size={14} />}
                        onClick={() => onSessionKill(session.id)}
                      >
                        Kill Session
                      </Menu.Item>
                    </Menu.Dropdown>
                  </Menu>
                </Group>
              }
              style={{ fontFamily: 'JetBrains Mono, monospace' }}
            >
              {session.label || `${session.type}-${session.id.slice(0, 6)}`}
            </Tabs.Tab>
          );
        })}

        {/* New Session Button */}
        <ActionIcon
          variant="subtle"
          color="gray"
          size="sm"
          onClick={onNewSession}
          style={{ margin: '8px' }}
        >
          <IconPlus size={16} />
        </ActionIcon>
      </Tabs.List>

      {/* Terminal Panels */}
      <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        {sortedSessions.map((session) => (
          <Tabs.Panel
            key={session.id}
            value={session.id}
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
            }}
          >
            <TerminalPane
              sessionId={session.id}
              active={session.id === activeSessionId}
            />
          </Tabs.Panel>
        ))}
      </div>
    </Tabs>
  );
}
