/**
 * RestoreSessionsModal - Restore previous terminal sessions
 *
 * Shown on startup if persisted sessions exist from a previous run.
 */

import {
  Modal,
  Text,
  Group,
  Stack,
  Button,
  Badge,
  Paper,
  ScrollArea,
  Checkbox,
  ThemeIcon,
} from '@mantine/core';
import {
  IconHistory,
  IconTerminal2,
  IconServer,
  IconRoute,
  IconWorld,
  IconRadar,
  IconDeviceFloppy,
} from '@tabler/icons-react';
import { useState, useCallback, useMemo } from 'react';
import type { RestoreSessionInfo } from '@shared/types/persistence';
import type { SessionType } from '@shared/types/session';

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

/** Color map for session types */
const SESSION_COLORS: Record<SessionType, string> = {
  shell: 'cyan',
  listener: 'green',
  tunnel: 'orange',
  proxy: 'yellow',
  scan: 'blue',
  server: 'violet',
  custom: 'gray',
};

interface RestoreSessionsModalProps {
  opened: boolean;
  onClose: () => void;
  sessions: RestoreSessionInfo[];
  engagementName?: string;
  onRestore: (sessionIds: string[]) => void;
  onStartFresh: () => void;
}

export function RestoreSessionsModal({
  opened,
  onClose,
  sessions,
  engagementName,
  onRestore,
  onStartFresh,
}: RestoreSessionsModalProps) {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() =>
    new Set(sessions.map((s) => s.id))
  );

  // Reset selection when sessions change
  useMemo(() => {
    setSelectedIds(new Set(sessions.map((s) => s.id)));
  }, [sessions]);

  const toggleSession = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const toggleAll = useCallback(() => {
    if (selectedIds.size === sessions.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(sessions.map((s) => s.id)));
    }
  }, [selectedIds.size, sessions]);

  const handleRestore = useCallback(() => {
    onRestore(Array.from(selectedIds));
    onClose();
  }, [selectedIds, onRestore, onClose]);

  const handleStartFresh = useCallback(() => {
    onStartFresh();
    onClose();
  }, [onStartFresh, onClose]);

  const formatTimestamp = (iso?: string) => {
    if (!iso) return 'Unknown';
    const date = new Date(iso);
    const now = new Date();
    const diff = now.getTime() - date.getTime();

    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      closeOnClickOutside={false}
      closeOnEscape={false}
      title={
        <Group gap="xs">
          <ThemeIcon size="md" variant="light" color="cyan">
            <IconHistory size={16} />
          </ThemeIcon>
          <Text fw={600}>Restore Previous Sessions</Text>
        </Group>
      }
      size="md"
      styles={{
        header: { background: '#1a1b1e', borderBottom: '1px solid #373A40' },
        body: { background: '#25262b', padding: 0 },
        content: { background: '#25262b' },
      }}
    >
      <Stack gap={0}>
        {/* Summary */}
        <Stack p="md" gap="xs" style={{ borderBottom: '1px solid #373A40' }}>
          <Text size="sm">
            Found <Badge variant="filled" color="cyan" size="sm">{sessions.length}</Badge> session{sessions.length !== 1 ? 's' : ''} from your previous run
            {engagementName && (
              <>
                {' '}in <Text component="span" fw={600} c="cyan">{engagementName}</Text>
              </>
            )}
          </Text>
          <Text size="xs" c="dimmed">
            Sessions will be restored with their terminal history as scroll-back
          </Text>
        </Stack>

        {/* Select All */}
        <Group
          p="xs"
          px="md"
          style={{
            background: '#1a1b1e',
            borderBottom: '1px solid #373A40',
          }}
        >
          <Checkbox
            size="xs"
            checked={selectedIds.size === sessions.length}
            indeterminate={selectedIds.size > 0 && selectedIds.size < sessions.length}
            onChange={toggleAll}
            label={
              <Text size="xs" c="dimmed">
                {selectedIds.size === sessions.length
                  ? 'Deselect all'
                  : 'Select all'}
              </Text>
            }
          />
        </Group>

        {/* Sessions List */}
        <ScrollArea style={{ maxHeight: 300 }}>
          <Stack gap={4} p="sm">
            {sessions.map((session) => {
              const Icon = SESSION_ICONS[session.type] || IconTerminal2;
              const color = SESSION_COLORS[session.type] || 'gray';
              const isSelected = selectedIds.has(session.id);

              return (
                <Paper
                  key={session.id}
                  p="xs"
                  onClick={() => toggleSession(session.id)}
                  style={{
                    background: isSelected ? '#2c2e33' : '#1a1b1e',
                    border: `1px solid ${isSelected ? '#373A40' : '#25262b'}`,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <Group gap="sm" justify="space-between">
                    <Group gap="sm">
                      <Checkbox
                        size="xs"
                        checked={isSelected}
                        onChange={() => toggleSession(session.id)}
                        onClick={(e) => e.stopPropagation()}
                      />
                      <ThemeIcon size="sm" variant="light" color={color}>
                        <Icon size={14} />
                      </ThemeIcon>
                      <Stack gap={0}>
                        <Text size="sm" fw={500}>
                          {session.label || session.command}
                        </Text>
                        <Group gap="xs">
                          <Badge size="xs" variant="light" color={color}>
                            {session.type}
                          </Badge>
                          <Text size="xs" c="dimmed" style={{ fontFamily: 'monospace' }}>
                            {session.workingDir}
                          </Text>
                        </Group>
                      </Stack>
                    </Group>
                    <Stack gap={2} align="flex-end">
                      <Text size="xs" c="dimmed">
                        {formatTimestamp(session.lastActivityAt)}
                      </Text>
                      <Badge size="xs" variant="dot" color="gray">
                        {session.outputLineCount.toLocaleString()} lines
                      </Badge>
                    </Stack>
                  </Group>
                </Paper>
              );
            })}
          </Stack>
        </ScrollArea>

        {/* Footer Actions */}
        <Group
          p="md"
          justify="flex-end"
          gap="sm"
          style={{ borderTop: '1px solid #373A40' }}
        >
          <Button
            variant="subtle"
            color="red"
            onClick={handleStartFresh}
          >
            Start Fresh
          </Button>
          <Button
            variant="filled"
            color="cyan"
            leftSection={<IconDeviceFloppy size={14} />}
            onClick={handleRestore}
            disabled={selectedIds.size === 0}
          >
            Restore {selectedIds.size > 0 ? `(${selectedIds.size})` : ''}
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
