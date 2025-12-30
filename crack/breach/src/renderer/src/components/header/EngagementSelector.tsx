/**
 * EngagementSelector - Header dropdown for switching engagements
 *
 * Shows flat list of engagements with active indicator.
 * Provides quick access to create new and manage engagements.
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Menu,
  Button,
  Text,
  Group,
  Badge,
  Divider,
  Stack,
  Loader,
  ActionIcon,
} from '@mantine/core';
import {
  IconChevronDown,
  IconPlus,
  IconSettings,
  IconBriefcase,
  IconCircleFilled,
  IconFileExport,
} from '@tabler/icons-react';
import type { Engagement } from '@shared/types/engagement';
import { ExportReportModal } from '../modals/ExportReportModal';

interface EngagementSelectorProps {
  /** Currently active engagement */
  activeEngagement: Engagement | null;
  /** Called when user selects a different engagement */
  onEngagementChange: (engagement: Engagement) => void;
  /** Called when user wants to open the management modal */
  onOpenManager: () => void;
  /** Called when user wants to create a new engagement (quick create) */
  onQuickCreate: () => void;
}

export function EngagementSelector({
  activeEngagement,
  onEngagementChange,
  onOpenManager,
  onQuickCreate,
}: EngagementSelectorProps) {
  const [opened, setOpened] = useState(false);
  const [loading, setLoading] = useState(false);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [showExportModal, setShowExportModal] = useState(false);

  // Load engagements when dropdown opens
  const loadData = useCallback(async () => {
    if (!opened) return;
    setLoading(true);
    try {
      const data = await window.electronAPI.engagementList();
      setEngagements(data);
    } catch (error) {
      console.error('Failed to load engagements:', error);
    } finally {
      setLoading(false);
    }
  }, [opened]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle engagement selection
  const handleSelect = async (engagement: Engagement) => {
    if (engagement.id === activeEngagement?.id) {
      setOpened(false);
      return;
    }

    try {
      const activated = await window.electronAPI.engagementActivate(engagement.id);
      if (activated) {
        onEngagementChange(activated);
      }
    } catch (error) {
      console.error('Failed to activate engagement:', error);
    }
    setOpened(false);
  };

  // Get status color
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'teal';
      case 'paused':
        return 'yellow';
      case 'completed':
        return 'blue';
      case 'archived':
        return 'gray';
      default:
        return 'gray';
    }
  };

  return (
    <>
    <Menu
      opened={opened}
      onChange={setOpened}
      position="bottom-start"
      width={280}
      shadow="lg"
      withArrow
    >
      <Menu.Target>
        <Button
          variant="subtle"
          color="gray"
          size="sm"
          rightSection={<IconChevronDown size={14} />}
          styles={{
            root: {
              padding: '4px 12px',
              height: 'auto',
            },
          }}
        >
          <Group gap="xs">
            <IconBriefcase size={16} />
            <Text size="sm" fw={500}>
              {activeEngagement?.name || 'No Engagement'}
            </Text>
            {activeEngagement && (
              <Badge size="xs" color={getStatusColor(activeEngagement.status)} variant="light">
                {activeEngagement.status}
              </Badge>
            )}
          </Group>
        </Button>
      </Menu.Target>

      <Menu.Dropdown>
        {loading ? (
          <Stack align="center" py="md">
            <Loader size="sm" />
            <Text size="xs" c="dimmed">
              Loading engagements...
            </Text>
          </Stack>
        ) : engagements.length === 0 ? (
          <Stack align="center" py="md" gap="xs">
            <IconBriefcase size={24} style={{ opacity: 0.5 }} />
            <Text size="sm" c="dimmed">
              No engagements yet
            </Text>
            <Button
              size="xs"
              variant="light"
              leftSection={<IconPlus size={14} />}
              onClick={() => {
                setOpened(false);
                onQuickCreate();
              }}
            >
              Create First Engagement
            </Button>
          </Stack>
        ) : (
          <>
            {/* Engagements list */}
            <Menu.Label>
              <Text size="xs" fw={600}>
                Engagements
              </Text>
            </Menu.Label>

            {engagements.map((eng) => {
              const isActive = eng.id === activeEngagement?.id;
              return (
                <Menu.Item
                  key={eng.id}
                  onClick={() => handleSelect(eng)}
                  leftSection={
                    isActive ? (
                      <IconCircleFilled
                        size={8}
                        style={{ color: 'var(--mantine-color-teal-5)' }}
                      />
                    ) : (
                      <div style={{ width: 8 }} />
                    )
                  }
                  rightSection={
                    <Badge
                      size="xs"
                      color={getStatusColor(eng.status)}
                      variant="light"
                    >
                      {eng.status}
                    </Badge>
                  }
                  style={{
                    backgroundColor: isActive
                      ? 'var(--mantine-color-dark-5)'
                      : undefined,
                  }}
                >
                  <Text size="sm" fw={isActive ? 600 : 400}>
                    {eng.name}
                  </Text>
                </Menu.Item>
              );
            })}

            {/* Actions */}
            <Divider my="xs" />
            <Group justify="space-between" px="xs" pb="xs">
              <Button
                size="xs"
                variant="light"
                color="teal"
                leftSection={<IconPlus size={14} />}
                onClick={() => {
                  setOpened(false);
                  onQuickCreate();
                }}
              >
                New
              </Button>
              <Group gap={4}>
                <ActionIcon
                  variant="subtle"
                  color="gray"
                  onClick={() => {
                    setOpened(false);
                    setShowExportModal(true);
                  }}
                  disabled={!activeEngagement}
                  title="Export Report"
                >
                  <IconFileExport size={18} />
                </ActionIcon>
                <ActionIcon
                  variant="subtle"
                  color="gray"
                  onClick={() => {
                    setOpened(false);
                    onOpenManager();
                  }}
                  title="Manage Engagements"
                >
                  <IconSettings size={18} />
                </ActionIcon>
              </Group>
            </Group>
          </>
        )}
      </Menu.Dropdown>
    </Menu>

    {/* Export Report Modal */}
    {activeEngagement && (
      <ExportReportModal
        opened={showExportModal}
        onClose={() => setShowExportModal(false)}
        engagementId={activeEngagement.id}
        engagementName={activeEngagement.name}
      />
    )}
    </>
  );
}

export default EngagementSelector;
