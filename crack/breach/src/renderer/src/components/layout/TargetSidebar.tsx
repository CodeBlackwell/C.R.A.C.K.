/**
 * TargetSidebar - Left Panel for Target Navigation
 *
 * Displays engagement targets with services and status indicators.
 * Includes inline form for adding new targets.
 */

import { useState, useEffect, useMemo } from 'react';
import {
  Stack,
  ScrollArea,
  Text,
  Badge,
  Group,
  Accordion,
  ActionIcon,
  Tooltip,
  TextInput,
  Loader,
  Button,
  Collapse,
  Alert,
  Menu,
  Divider,
} from '@mantine/core';
import {
  IconServer,
  IconNetwork,
  IconRefresh,
  IconSearch,
  IconCircleFilled,
  IconPlus,
  IconX,
  IconAlertCircle,
  IconRadar,
  IconTerminal2,
} from '@tabler/icons-react';
import {
  NMAP_ACTIONS,
  getNmapActionsByCategory,
  NMAP_CATEGORY_ORDER,
} from '@shared/actions/nmap';
import { substituteCommand } from '@shared/types/actions';
import type { CommandAction } from '@shared/types/actions';

interface Target {
  id: string;
  ip_address: string;
  hostname?: string;
  os_guess?: string;
  status?: string;
  serviceCount?: number;
}

interface Service {
  id: string;
  port: number;
  protocol: string;
  service_name?: string;
  version?: string;
  state?: string;
}

interface TargetSidebarProps {
  engagementId?: string;
  selectedTargetId?: string;
  onTargetSelect?: (targetId: string, targetIp: string, targetHostname?: string) => void;
  onTargetAction?: (command: string, targetId: string, actionLabel: string) => void;
}

/** Status color mapping */
const STATUS_COLORS: Record<string, string> = {
  up: 'green',
  down: 'red',
  unknown: 'gray',
  scanning: 'yellow',
  compromised: 'orange',
};

/** Basic IP validation regex */
const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

export function TargetSidebar({ engagementId, selectedTargetId, onTargetSelect, onTargetAction }: TargetSidebarProps) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [expandedTargets, setExpandedTargets] = useState<string[]>([]);
  const [targetServices, setTargetServices] = useState<Record<string, Service[]>>({});

  // Get Nmap actions grouped by category
  const nmapActionsByCategory = useMemo(() => getNmapActionsByCategory(), []);

  // Add target form state
  const [showAddForm, setShowAddForm] = useState(false);
  const [addLoading, setAddLoading] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);
  const [newIp, setNewIp] = useState('');
  const [newHostname, setNewHostname] = useState('');

  // Load targets for engagement
  useEffect(() => {
    if (!engagementId) return;

    setLoading(true);
    window.electronAPI
      .targetList(engagementId)
      .then((list) => {
        const targetList = list || [];
        setTargets(targetList);
        // Auto-select first target if none selected and targets exist
        if (targetList.length > 0 && !selectedTargetId) {
          const first = targetList[0];
          onTargetSelect?.(first.id, first.ip_address, first.hostname);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [engagementId]);

  // Load services when target is expanded
  const loadServices = async (targetId: string) => {
    if (targetServices[targetId]) return;

    const services = await window.electronAPI.targetServices(targetId);
    setTargetServices((prev) => ({
      ...prev,
      [targetId]: services || [],
    }));
  };

  // Handle accordion change
  const handleAccordionChange = (value: string[]) => {
    setExpandedTargets(value);
    value.forEach(loadServices);
  };

  // Filter targets by search
  const filteredTargets = useMemo(() => {
    if (!search) return targets;
    const lower = search.toLowerCase();
    return targets.filter(
      (t) =>
        t.ip_address.includes(lower) ||
        t.hostname?.toLowerCase().includes(lower) ||
        t.os_guess?.toLowerCase().includes(lower)
    );
  }, [targets, search]);

  // Refresh targets
  const handleRefresh = () => {
    if (!engagementId) return;
    setLoading(true);
    window.electronAPI
      .targetList(engagementId)
      .then((list) => setTargets(list || []))
      .finally(() => setLoading(false));
  };

  // Reset add form
  const resetAddForm = () => {
    setNewIp('');
    setNewHostname('');
    setAddError(null);
    setShowAddForm(false);
  };

  // Validate IP
  const isValidIp = (ip: string): boolean => {
    if (!IP_REGEX.test(ip)) return false;
    const parts = ip.split('.').map(Number);
    return parts.every((p) => p >= 0 && p <= 255);
  };

  // Handle add target
  const handleAddTarget = async () => {
    if (!engagementId) return;

    // Validate IP
    if (!newIp.trim()) {
      setAddError('IP address is required');
      return;
    }
    if (!isValidIp(newIp.trim())) {
      setAddError('Invalid IP address format');
      return;
    }

    setAddLoading(true);
    setAddError(null);

    try {
      const result = await window.electronAPI.targetAdd(engagementId, {
        ip_address: newIp.trim(),
        hostname: newHostname.trim() || undefined,
      });

      if (result && 'error' in result) {
        setAddError(result.error);
      } else if (result) {
        // Success - refresh list and reset form
        handleRefresh();
        resetAddForm();
      } else {
        setAddError('Failed to add target');
      }
    } catch (err) {
      setAddError('Failed to add target');
      console.error(err);
    } finally {
      setAddLoading(false);
    }
  };

  // Handle Nmap action on target
  const handleNmapAction = (target: Target, action: CommandAction) => {
    const command = substituteCommand(action.command, {
      ip: target.ip_address,
      hostname: target.hostname,
    });
    onTargetAction?.(command, target.id, action.label);
  };

  return (
    <Stack
      gap={0}
      style={{
        width: 280,
        height: '100%',
        background: '#25262b',
        borderRight: '1px solid #373A40',
      }}
    >
      {/* Header */}
      <Group
        justify="space-between"
        p="xs"
        style={{ borderBottom: '1px solid #373A40' }}
      >
        <Group gap="xs">
          <IconNetwork size={16} color="#868e96" />
          <Text size="sm" fw={600} c="dimmed">
            TARGETS
          </Text>
          <Badge size="xs" variant="light" color="gray">
            {targets.length}
          </Badge>
        </Group>
        <Group gap={4}>
          <Tooltip label="Add Target">
            <ActionIcon
              variant={showAddForm ? 'filled' : 'subtle'}
              color={showAddForm ? 'cyan' : 'gray'}
              size="sm"
              onClick={() => setShowAddForm(!showAddForm)}
              disabled={!engagementId}
            >
              {showAddForm ? <IconX size={14} /> : <IconPlus size={14} />}
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Refresh">
            <ActionIcon
              variant="subtle"
              color="gray"
              size="sm"
              onClick={handleRefresh}
              loading={loading}
              disabled={!engagementId}
            >
              <IconRefresh size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* Add Target Form (collapsible) */}
      <Collapse in={showAddForm}>
        <Stack
          gap="xs"
          p="xs"
          style={{
            background: '#1a1b1e',
            borderBottom: '1px solid #373A40',
          }}
        >
          {addError && (
            <Alert
              icon={<IconAlertCircle size={14} />}
              color="red"
              variant="light"
              p="xs"
              styles={{ message: { fontSize: 12 } }}
            >
              {addError}
            </Alert>
          )}
          <TextInput
            size="xs"
            placeholder="192.168.1.100"
            label="IP Address"
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
            styles={{
              input: { background: '#25262b', border: '1px solid #373A40' },
              label: { fontSize: 11, marginBottom: 4 },
            }}
            onKeyDown={(e) => e.key === 'Enter' && handleAddTarget()}
          />
          <TextInput
            size="xs"
            placeholder="dc01.corp.local (optional)"
            label="Hostname"
            value={newHostname}
            onChange={(e) => setNewHostname(e.target.value)}
            styles={{
              input: { background: '#25262b', border: '1px solid #373A40' },
              label: { fontSize: 11, marginBottom: 4 },
            }}
            onKeyDown={(e) => e.key === 'Enter' && handleAddTarget()}
          />
          <Group justify="flex-end" gap="xs">
            <Button size="xs" variant="subtle" color="gray" onClick={resetAddForm}>
              Cancel
            </Button>
            <Button
              size="xs"
              color="cyan"
              onClick={handleAddTarget}
              loading={addLoading}
            >
              Add Target
            </Button>
          </Group>
        </Stack>
      </Collapse>

      {/* Search */}
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #373A40' }}>
        <TextInput
          size="xs"
          placeholder="Search targets..."
          leftSection={<IconSearch size={14} />}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          styles={{
            input: {
              background: '#1a1b1e',
              border: '1px solid #373A40',
            },
          }}
        />
      </div>

      {/* Target List */}
      <ScrollArea style={{ flex: 1 }}>
        {!engagementId ? (
          <Text c="dimmed" size="sm" ta="center" p="xl">
            No active engagement
          </Text>
        ) : loading && targets.length === 0 ? (
          <Group justify="center" p="xl">
            <Loader size="sm" color="cyan" />
          </Group>
        ) : filteredTargets.length === 0 ? (
          <Stack align="center" p="xl" gap="sm">
            <Text c="dimmed" size="sm">
              No targets found
            </Text>
            {!showAddForm && (
              <Button
                size="xs"
                variant="light"
                leftSection={<IconPlus size={14} />}
                onClick={() => setShowAddForm(true)}
              >
                Add First Target
              </Button>
            )}
          </Stack>
        ) : (
          <Accordion
            multiple
            value={expandedTargets}
            onChange={handleAccordionChange}
            chevronPosition="left"
            styles={{
              item: { borderBottom: '1px solid #373A40' },
              control: { padding: '8px 12px' },
              content: { padding: '0 12px 8px 12px' },
            }}
          >
            {filteredTargets.map((target) => (
              <Accordion.Item key={target.id} value={target.id}>
                <Group gap={0} wrap="nowrap" pr="xs">
                  <Accordion.Control
                    onClick={() => onTargetSelect?.(target.id, target.ip_address, target.hostname)}
                    style={selectedTargetId === target.id ? { background: 'rgba(34, 139, 230, 0.1)' } : undefined}
                  >
                    <Group gap="xs" wrap="nowrap">
                      <IconCircleFilled
                        size={8}
                        color={
                          STATUS_COLORS[target.status || 'unknown'] || '#868e96'
                        }
                      />
                      <Stack gap={2} style={{ flex: 1, overflow: 'hidden' }}>
                        <Text
                          size="sm"
                          fw={500}
                          style={{
                            fontFamily: 'JetBrains Mono, monospace',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                          }}
                        >
                          {target.ip_address}
                        </Text>
                        {target.hostname && (
                          <Text size="xs" c="dimmed" truncate>
                            {target.hostname}
                          </Text>
                        )}
                      </Stack>
                      {target.serviceCount !== undefined && target.serviceCount > 0 && (
                        <Badge size="xs" variant="light" color="cyan">
                          {target.serviceCount}
                        </Badge>
                      )}
                    </Group>
                  </Accordion.Control>
                  {/* Nmap Scan Menu - Outside Accordion.Control to avoid nested buttons */}
                  <Menu shadow="md" width={240} position="bottom-end">
                    <Menu.Target>
                      <Tooltip label="Scan Target">
                        <ActionIcon
                          variant="subtle"
                          color="cyan"
                          size="sm"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <IconRadar size={14} />
                        </ActionIcon>
                      </Tooltip>
                    </Menu.Target>

                    <Menu.Dropdown onClick={(e) => e.stopPropagation()}>
                      {NMAP_CATEGORY_ORDER.map((category, categoryIndex) => {
                        const categoryActions = nmapActionsByCategory.get(category);
                        if (!categoryActions?.length) return null;

                        return (
                          <div key={category}>
                            {categoryIndex > 0 && nmapActionsByCategory.has(NMAP_CATEGORY_ORDER[categoryIndex - 1]) && (
                              <Divider />
                            )}
                            <Menu.Label>{category}</Menu.Label>
                            {categoryActions.map((action) => (
                              <Menu.Item
                                key={action.id}
                                leftSection={<IconTerminal2 size={14} />}
                                onClick={() => handleNmapAction(target, action)}
                              >
                                <Stack gap={0}>
                                  <Text size="xs">{action.label}</Text>
                                  {action.description && (
                                    <Text size="xs" c="dimmed" truncate style={{ maxWidth: 180 }}>
                                      {action.description}
                                    </Text>
                                  )}
                                </Stack>
                              </Menu.Item>
                            ))}
                          </div>
                        );
                      })}
                    </Menu.Dropdown>
                  </Menu>
                </Group>
                <Accordion.Panel>
                  <Stack gap={4}>
                    {target.os_guess && (
                      <Text size="xs" c="dimmed">
                        OS: {target.os_guess}
                      </Text>
                    )}
                    {targetServices[target.id]?.map((service) => (
                      <Group
                        key={service.id}
                        gap="xs"
                        style={{
                          padding: '4px 8px',
                          background: '#1a1b1e',
                          borderRadius: 4,
                        }}
                      >
                        <IconServer size={12} color="#868e96" />
                        <Text
                          size="xs"
                          style={{ fontFamily: 'JetBrains Mono, monospace' }}
                        >
                          {service.port}/{service.protocol}
                        </Text>
                        {service.service_name && (
                          <Badge size="xs" variant="dot" color="cyan">
                            {service.service_name}
                          </Badge>
                        )}
                      </Group>
                    ))}
                    {targetServices[target.id]?.length === 0 && (
                      <Text size="xs" c="dimmed" fs="italic">
                        No services discovered
                      </Text>
                    )}
                  </Stack>
                </Accordion.Panel>
              </Accordion.Item>
            ))}
          </Accordion>
        )}
      </ScrollArea>
    </Stack>
  );
}
