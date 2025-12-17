/**
 * EngagementManager - Modal for managing engagements
 *
 * List, create, edit, archive, delete engagements.
 * Simplified model without client layer.
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Modal,
  Text,
  Group,
  Stack,
  Button,
  TextInput,
  Textarea,
  Select,
  Badge,
  ActionIcon,
  Card,
  Loader,
  Alert,
  Menu,
} from '@mantine/core';
import {
  IconBriefcase,
  IconPlus,
  IconTrash,
  IconEdit,
  IconArchive,
  IconPlayerPlay,
  IconPlayerPause,
  IconCheck,
  IconDots,
  IconAlertCircle,
  IconTarget,
  IconFlag,
  IconKey,
} from '@tabler/icons-react';
import type {
  Engagement,
  CreateEngagementData,
  EngagementStats,
  EngagementStatus,
} from '@shared/types/engagement';

interface EngagementManagerProps {
  /** Whether the modal is open */
  opened: boolean;
  /** Called when modal should close */
  onClose: () => void;
  /** Currently active engagement */
  activeEngagement: Engagement | null;
  /** Called when engagement is activated */
  onEngagementChange: (engagement: Engagement | null) => void;
}

type FormMode = 'list' | 'create' | 'edit';

export function EngagementManager({
  opened,
  onClose,
  activeEngagement,
  onEngagementChange,
}: EngagementManagerProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Data
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [stats, setStats] = useState<Map<string, EngagementStats>>(new Map());

  // Form state
  const [formMode, setFormMode] = useState<FormMode>('list');
  const [editingEngagement, setEditingEngagement] = useState<Engagement | null>(null);

  // Form fields
  const [engName, setEngName] = useState('');
  const [engScopeType, setEngScopeType] = useState<string | null>(null);
  const [engScopeText, setEngScopeText] = useState('');
  const [engNotes, setEngNotes] = useState('');

  // Load data
  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const engList = await window.electronAPI.engagementList();
      setEngagements(engList);

      // Load stats for active engagements
      const statsMap = new Map<string, EngagementStats>();
      for (const eng of engList.filter((e) => e.status === 'active')) {
        const engStats = await window.electronAPI.engagementStats(eng.id);
        if (engStats) {
          statsMap.set(eng.id, engStats);
        }
      }
      setStats(statsMap);
    } catch (err) {
      setError('Failed to load data');
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (opened) {
      loadData();
      setFormMode('list');
    }
  }, [opened, loadData]);

  // Reset form
  const resetForm = () => {
    setEngName('');
    setEngScopeType(null);
    setEngScopeText('');
    setEngNotes('');
    setEditingEngagement(null);
  };

  // Create engagement
  const handleCreate = async () => {
    if (!engName) {
      setError('Name is required');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const data: CreateEngagementData = {
        name: engName,
        scope_type: engScopeType || undefined,
        scope_text: engScopeText || undefined,
        notes: engNotes || undefined,
      };
      const created = await window.electronAPI.engagementCreate(data);
      if (created) {
        await loadData();
        setFormMode('list');
        resetForm();
      } else {
        setError('Failed to create engagement');
      }
    } catch (err) {
      setError('Failed to create engagement');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Update engagement
  const handleUpdate = async () => {
    if (!editingEngagement || !engName) {
      setError('Name is required');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      await window.electronAPI.engagementUpdate(editingEngagement.id, {
        name: engName,
        scope_type: engScopeType || undefined,
        scope_text: engScopeText || undefined,
        notes: engNotes || undefined,
      });
      await loadData();
      setFormMode('list');
      resetForm();
    } catch (err) {
      setError('Failed to update engagement');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Delete engagement
  const handleDelete = async (eng: Engagement) => {
    if (!confirm(`Delete "${eng.name}"? This will delete all associated data.`)) {
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const result = await window.electronAPI.engagementDelete(eng.id);
      if (result.success) {
        if (activeEngagement?.id === eng.id) {
          onEngagementChange(null);
        }
        await loadData();
      } else {
        setError(result.error || 'Failed to delete engagement');
      }
    } catch (err) {
      setError('Failed to delete engagement');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Update engagement status
  const handleStatusChange = async (eng: Engagement, status: EngagementStatus) => {
    setLoading(true);
    try {
      if (status === 'active') {
        const activated = await window.electronAPI.engagementActivate(eng.id);
        if (activated) {
          onEngagementChange(activated);
        }
      } else {
        await window.electronAPI.engagementUpdateStatus(eng.id, status);
        // If we're deactivating the current active engagement, clear it
        if (activeEngagement?.id === eng.id) {
          onEngagementChange(null);
        }
      }
      await loadData();
    } catch (err) {
      setError('Failed to update status');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // Start editing engagement
  const startEdit = (eng: Engagement) => {
    setEditingEngagement(eng);
    setEngName(eng.name);
    setEngScopeType(eng.scope_type || null);
    setEngScopeText(eng.scope_text || '');
    setEngNotes(eng.notes || '');
    setFormMode('edit');
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
    <Modal
      opened={opened}
      onClose={onClose}
      title={
        <Group gap="xs">
          <IconBriefcase size={20} />
          <Text fw={600}>Engagement Manager</Text>
        </Group>
      }
      size="lg"
      centered
    >
      {error && (
        <Alert
          icon={<IconAlertCircle size={16} />}
          color="red"
          mb="md"
          withCloseButton
          onClose={() => setError(null)}
        >
          {error}
        </Alert>
      )}

      {formMode === 'list' ? (
        <Stack gap="sm">
          {loading ? (
            <Stack align="center" py="xl">
              <Loader size="sm" />
            </Stack>
          ) : engagements.length === 0 ? (
            <Stack align="center" py="xl" gap="sm">
              <IconBriefcase size={32} style={{ opacity: 0.5 }} />
              <Text c="dimmed">No engagements yet</Text>
              <Button
                size="sm"
                leftSection={<IconPlus size={14} />}
                onClick={() => setFormMode('create')}
              >
                Create Engagement
              </Button>
            </Stack>
          ) : (
            <>
              {engagements.map((eng) => {
                const engStats = stats.get(eng.id);
                return (
                  <Card key={eng.id} padding="sm" withBorder>
                    <Group justify="space-between" wrap="nowrap">
                      <Stack gap={4}>
                        <Group gap="xs">
                          <Text fw={500}>{eng.name}</Text>
                          <Badge
                            size="xs"
                            color={getStatusColor(eng.status)}
                            variant="light"
                          >
                            {eng.status}
                          </Badge>
                        </Group>
                        <Text size="xs" c="dimmed">
                          {eng.start_date && `Started ${eng.start_date}`}
                          {eng.scope_type && ` | ${eng.scope_type}`}
                        </Text>
                        {engStats && (
                          <Group gap="xs">
                            <Group gap={4}>
                              <IconTarget size={12} />
                              <Text size="xs">{engStats.target_count}</Text>
                            </Group>
                            <Group gap={4}>
                              <IconFlag size={12} />
                              <Text size="xs">{engStats.finding_count}</Text>
                            </Group>
                            <Group gap={4}>
                              <IconKey size={12} />
                              <Text size="xs">{engStats.credential_count}</Text>
                            </Group>
                          </Group>
                        )}
                      </Stack>

                      <Menu position="bottom-end" withinPortal>
                        <Menu.Target>
                          <ActionIcon variant="subtle" color="gray">
                            <IconDots size={16} />
                          </ActionIcon>
                        </Menu.Target>
                        <Menu.Dropdown>
                          {eng.status !== 'active' && (
                            <Menu.Item
                              leftSection={<IconPlayerPlay size={14} />}
                              onClick={() => handleStatusChange(eng, 'active')}
                            >
                              Activate
                            </Menu.Item>
                          )}
                          {eng.status === 'active' && (
                            <Menu.Item
                              leftSection={<IconPlayerPause size={14} />}
                              onClick={() => handleStatusChange(eng, 'paused')}
                            >
                              Pause
                            </Menu.Item>
                          )}
                          {eng.status !== 'completed' && (
                            <Menu.Item
                              leftSection={<IconCheck size={14} />}
                              onClick={() => handleStatusChange(eng, 'completed')}
                            >
                              Mark Complete
                            </Menu.Item>
                          )}
                          <Menu.Divider />
                          <Menu.Item
                            leftSection={<IconEdit size={14} />}
                            onClick={() => startEdit(eng)}
                          >
                            Edit
                          </Menu.Item>
                          <Menu.Item
                            leftSection={<IconArchive size={14} />}
                            onClick={() => handleStatusChange(eng, 'archived')}
                          >
                            Archive
                          </Menu.Item>
                          <Menu.Divider />
                          <Menu.Item
                            leftSection={<IconTrash size={14} />}
                            color="red"
                            onClick={() => handleDelete(eng)}
                          >
                            Delete
                          </Menu.Item>
                        </Menu.Dropdown>
                      </Menu>
                    </Group>
                  </Card>
                );
              })}

              <Button
                variant="light"
                leftSection={<IconPlus size={14} />}
                onClick={() => {
                  resetForm();
                  setFormMode('create');
                }}
              >
                New Engagement
              </Button>
            </>
          )}
        </Stack>
      ) : (
        /* ENGAGEMENT FORM */
        <Stack gap="sm">
          <TextInput
            label="Name"
            placeholder="OSCP Lab, HTB Active, etc."
            value={engName}
            onChange={(e) => setEngName(e.currentTarget.value)}
            required
          />

          <Select
            label="Scope Type"
            placeholder="Select scope type"
            data={[
              { value: 'ip_range', label: 'IP Range' },
              { value: 'domain', label: 'Domain' },
              { value: 'application', label: 'Application' },
              { value: 'network', label: 'Network' },
            ]}
            value={engScopeType}
            onChange={setEngScopeType}
            clearable
          />

          <Textarea
            label="Scope Details"
            placeholder="192.168.1.0/24, example.com"
            value={engScopeText}
            onChange={(e) => setEngScopeText(e.currentTarget.value)}
            autosize
            minRows={2}
          />

          <Textarea
            label="Notes"
            placeholder="Additional notes..."
            value={engNotes}
            onChange={(e) => setEngNotes(e.currentTarget.value)}
            autosize
            minRows={2}
          />

          <Group justify="flex-end" mt="md">
            <Button
              variant="subtle"
              onClick={() => {
                setFormMode('list');
                resetForm();
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={formMode === 'create' ? handleCreate : handleUpdate}
              loading={loading}
            >
              {formMode === 'create' ? 'Create' : 'Save'}
            </Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}

export default EngagementManager;
