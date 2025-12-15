/**
 * TargetSidebar - Left Panel for Target Navigation
 *
 * Displays engagement targets with services and status indicators.
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
} from '@mantine/core';
import {
  IconServer,
  IconNetwork,
  IconRefresh,
  IconSearch,
  IconCircleFilled,
} from '@tabler/icons-react';

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
  onTargetSelect?: (targetId: string) => void;
}

/** Status color mapping */
const STATUS_COLORS: Record<string, string> = {
  up: 'green',
  down: 'red',
  unknown: 'gray',
  scanning: 'yellow',
  compromised: 'orange',
};

export function TargetSidebar({ engagementId, onTargetSelect }: TargetSidebarProps) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [expandedTargets, setExpandedTargets] = useState<string[]>([]);
  const [targetServices, setTargetServices] = useState<Record<string, Service[]>>({});

  // Load targets for engagement
  useEffect(() => {
    if (!engagementId) return;

    setLoading(true);
    window.electronAPI
      .targetList(engagementId)
      .then((list) => {
        setTargets(list || []);
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
        </Group>
        <Tooltip label="Refresh">
          <ActionIcon
            variant="subtle"
            color="gray"
            size="sm"
            onClick={handleRefresh}
            loading={loading}
          >
            <IconRefresh size={14} />
          </ActionIcon>
        </Tooltip>
      </Group>

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
          <Text c="dimmed" size="sm" ta="center" p="xl">
            No targets found
          </Text>
        ) : (
          <Accordion
            multiple
            value={expandedTargets}
            onChange={handleAccordionChange}
            styles={{
              item: { borderBottom: '1px solid #373A40' },
              control: { padding: '8px 12px' },
              content: { padding: '0 12px 8px 12px' },
            }}
          >
            {filteredTargets.map((target) => (
              <Accordion.Item key={target.id} value={target.id}>
                <Accordion.Control
                  onClick={() => onTargetSelect?.(target.id)}
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
