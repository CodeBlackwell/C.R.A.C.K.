/**
 * SessionDock - Right Panel for Session Overview
 *
 * Compact session list with status indicators and quick actions.
 */

import { useMemo } from 'react';
import {
  Stack,
  ScrollArea,
  Text,
  Badge,
  Group,
  ActionIcon,
  Tooltip,
  Paper,
  Divider,
} from '@mantine/core';
import {
  IconTerminal2,
  IconServer,
  IconRoute,
  IconRadar,
  IconWorld,
  IconPlus,
  IconPlayerPlay,
  IconCircleFilled,
} from '@tabler/icons-react';
import type { TerminalSession, SessionType, SessionStatus } from '@shared/types/session';

interface SessionDockProps {
  sessions: TerminalSession[];
  activeSessionId: string | null;
  onSessionSelect: (sessionId: string) => void;
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
const STATUS_COLORS: Record<SessionStatus, string> = {
  starting: '#d29922',
  running: '#7ee787',
  backgrounded: '#58a6ff',
  stopped: '#6e7681',
  error: '#ff7b72',
  completed: '#39c5cf',
  disconnected: '#ffa198',
};

/** Group sessions by type */
function groupSessionsByType(sessions: TerminalSession[]): Map<SessionType, TerminalSession[]> {
  const groups = new Map<SessionType, TerminalSession[]>();

  for (const session of sessions) {
    const type = session.type;
    if (!groups.has(type)) {
      groups.set(type, []);
    }
    groups.get(type)!.push(session);
  }

  return groups;
}

export function SessionDock({
  sessions,
  activeSessionId,
  onSessionSelect,
  onNewSession,
}: SessionDockProps) {
  // Group and memoize sessions
  const groupedSessions = useMemo(() => groupSessionsByType(sessions), [sessions]);

  // Count running sessions
  const runningCount = useMemo(
    () => sessions.filter((s) => s.status === 'running').length,
    [sessions]
  );

  return (
    <Stack
      gap={0}
      style={{
        width: 200,
        height: '100%',
        background: '#25262b',
        borderLeft: '1px solid #373A40',
      }}
    >
      {/* Header */}
      <Group
        justify="space-between"
        p="xs"
        style={{ borderBottom: '1px solid #373A40' }}
      >
        <Group gap="xs">
          <IconPlayerPlay size={16} color="#868e96" />
          <Text size="sm" fw={600} c="dimmed">
            SESSIONS
          </Text>
        </Group>
        <Group gap={4}>
          {runningCount > 0 && (
            <Badge size="xs" variant="light" color="green">
              {runningCount}
            </Badge>
          )}
          <Tooltip label="New Session">
            <ActionIcon variant="subtle" color="gray" size="sm" onClick={onNewSession}>
              <IconPlus size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* Session List */}
      <ScrollArea style={{ flex: 1 }}>
        {sessions.length === 0 ? (
          <Stack align="center" justify="center" p="xl" gap="xs">
            <IconTerminal2 size={32} color="#6e7681" />
            <Text size="xs" c="dimmed" ta="center">
              No sessions
            </Text>
            <ActionIcon
              variant="light"
              color="cyan"
              size="md"
              onClick={onNewSession}
            >
              <IconPlus size={16} />
            </ActionIcon>
          </Stack>
        ) : (
          <Stack gap={0} p={4}>
            {Array.from(groupedSessions.entries()).map(([type, typeSessions], groupIndex) => {
              const Icon = SESSION_ICONS[type] || IconTerminal2;
              return (
                <div key={type}>
                  {groupIndex > 0 && <Divider my={4} color="#373A40" />}
                  <Text size="xs" c="dimmed" px={8} py={4} tt="uppercase">
                    {type}s ({typeSessions.length})
                  </Text>
                  {typeSessions.map((session) => (
                    <Paper
                      key={session.id}
                      p={6}
                      mb={2}
                      style={{
                        background:
                          session.id === activeSessionId ? '#373A40' : 'transparent',
                        cursor: 'pointer',
                        borderRadius: 4,
                      }}
                      onClick={() => onSessionSelect(session.id)}
                    >
                      <Group gap={6} wrap="nowrap">
                        <Icon size={14} color="#868e96" />
                        <Stack gap={0} style={{ flex: 1, overflow: 'hidden' }}>
                          <Text
                            size="xs"
                            fw={500}
                            truncate
                            style={{ fontFamily: 'JetBrains Mono, monospace' }}
                          >
                            {session.label || session.id.slice(0, 8)}
                          </Text>
                          {session.targetId && (
                            <Text size="xs" c="dimmed" truncate>
                              {session.targetId}
                            </Text>
                          )}
                        </Stack>
                        <Tooltip label={session.status}>
                          <IconCircleFilled
                            size={8}
                            color={STATUS_COLORS[session.status] || '#6e7681'}
                          />
                        </Tooltip>
                      </Group>
                    </Paper>
                  ))}
                </div>
              );
            })}
          </Stack>
        )}
      </ScrollArea>

      {/* Footer Stats */}
      <Group
        justify="space-between"
        p="xs"
        style={{ borderTop: '1px solid #373A40' }}
      >
        <Text size="xs" c="dimmed">
          Total: {sessions.length}
        </Text>
        <Group gap={4}>
          <IconCircleFilled size={6} color="#7ee787" />
          <Text size="xs" c="dimmed">
            {runningCount}
          </Text>
        </Group>
      </Group>
    </Stack>
  );
}
