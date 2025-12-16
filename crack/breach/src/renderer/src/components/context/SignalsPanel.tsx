/**
 * SignalsPanel - Reconnaissance Signals Display
 *
 * Displays parsed reconnaissance data from terminal output:
 * - Open ports
 * - Host reachability
 * - DNS resolutions
 * - OS detections
 * - User enumerations
 * - Cracked hashes
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Stack,
  ScrollArea,
  Text,
  Badge,
  Group,
  ActionIcon,
  Tooltip,
  Collapse,
  ThemeIcon,
  Paper,
  Loader,
} from '@mantine/core';
import {
  IconRadar,
  IconRefresh,
  IconChevronDown,
  IconChevronRight,
  IconNetwork,
  IconWorldWww,
  IconDeviceDesktop,
  IconUsers,
  IconKey,
  IconServer,
  IconPlugConnected,
} from '@tabler/icons-react';
import type {
  Signal,
  SignalType,
  SignalSummary,
  PortStatusSignal,
  HostReachabilitySignal,
  DnsResolutionSignal,
  OsDetectionSignal,
  UserEnumerationSignal,
  CrackedHashSignal,
} from '@shared/types/signal';

interface SignalsPanelProps {
  engagementId?: string;
}

/** Signal type configuration */
const SIGNAL_TYPES: {
  type: SignalType;
  label: string;
  icon: typeof IconRadar;
  color: string;
}[] = [
  { type: 'port_status', label: 'Ports', icon: IconPlugConnected, color: 'cyan' },
  { type: 'host_reachability', label: 'Hosts', icon: IconServer, color: 'green' },
  { type: 'dns_resolution', label: 'DNS', icon: IconWorldWww, color: 'blue' },
  { type: 'os_detection', label: 'OS', icon: IconDeviceDesktop, color: 'violet' },
  { type: 'user_enumeration', label: 'Users', icon: IconUsers, color: 'orange' },
  { type: 'cracked_hash', label: 'Cracked', icon: IconKey, color: 'red' },
];

export function SignalsPanel({ engagementId }: SignalsPanelProps) {
  const [summary, setSummary] = useState<SignalSummary | null>(null);
  const [signals, setSignals] = useState<Signal[]>([]);
  const [loading, setLoading] = useState(false);
  const [expandedTypes, setExpandedTypes] = useState<Set<SignalType>>(
    new Set(['port_status'])
  );

  // Load signals summary and list
  const loadSignals = useCallback(async () => {
    if (!engagementId) return;

    setLoading(true);
    try {
      const [summaryResult, signalsResult] = await Promise.all([
        window.electronAPI.signalSummary(engagementId),
        window.electronAPI.signalList(engagementId),
      ]);
      setSummary(summaryResult);
      setSignals(signalsResult || []);
    } catch (err) {
      console.error('Failed to load signals:', err);
    } finally {
      setLoading(false);
    }
  }, [engagementId]);

  useEffect(() => {
    loadSignals();
  }, [loadSignals]);

  // Listen for signal events
  useEffect(() => {
    if (!engagementId) return;

    const handleReload = () => loadSignals();

    // Register all signal event listeners
    window.electronAPI.onPortDiscovered(handleReload);
    window.electronAPI.onHostReachability(handleReload);
    window.electronAPI.onDnsResolved(handleReload);
    window.electronAPI.onOsDetected(handleReload);
    window.electronAPI.onUserEnumerated(handleReload);
    window.electronAPI.onHashCracked(handleReload);

    return () => {
      window.electronAPI.removePortDiscoveredListener(handleReload);
      window.electronAPI.removeHostReachabilityListener(handleReload);
      window.electronAPI.removeDnsResolvedListener(handleReload);
      window.electronAPI.removeOsDetectedListener(handleReload);
      window.electronAPI.removeUserEnumeratedListener(handleReload);
      window.electronAPI.removeHashCrackedListener(handleReload);
    };
  }, [engagementId, loadSignals]);

  // Group signals by type
  const groupedSignals = useMemo(() => {
    const groups = new Map<SignalType, Signal[]>();
    for (const config of SIGNAL_TYPES) {
      groups.set(config.type, []);
    }
    for (const signal of signals) {
      const list = groups.get(signal.type);
      if (list) {
        list.push(signal);
      }
    }
    return groups;
  }, [signals]);

  // Get count for a signal type
  const getTypeCount = (type: SignalType): number => {
    if (!summary) return groupedSignals.get(type)?.length || 0;

    switch (type) {
      case 'port_status':
        return summary.ports.open + summary.ports.filtered;
      case 'host_reachability':
        return summary.hosts.reachable + summary.hosts.unreachable;
      case 'dns_resolution':
        return summary.dns;
      case 'user_enumeration':
        return summary.users;
      case 'cracked_hash':
        return summary.crackedHashes;
      default:
        return groupedSignals.get(type)?.length || 0;
    }
  };

  // Toggle type expansion
  const toggleType = (type: SignalType) => {
    setExpandedTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) {
        next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  };

  // Total signal count
  const totalSignals = signals.length;

  return (
    <Stack
      gap={0}
      style={{
        height: '100%',
        background: '#25262b',
      }}
    >
      {/* Header */}
      <Group
        justify="space-between"
        p="xs"
        style={{ borderBottom: '1px solid #373A40' }}
      >
        <Group gap="xs">
          <IconRadar size={16} color="#868e96" />
          <Text size="sm" fw={600} c="dimmed">
            SIGNALS
          </Text>
        </Group>
        <Group gap={4}>
          {summary && summary.ports.open > 0 && (
            <Tooltip label="Open ports">
              <Badge size="xs" variant="filled" color="cyan">
                {summary.ports.open}
              </Badge>
            </Tooltip>
          )}
          {summary && summary.hosts.reachable > 0 && (
            <Tooltip label="Reachable hosts">
              <Badge size="xs" variant="filled" color="green">
                {summary.hosts.reachable}
              </Badge>
            </Tooltip>
          )}
          <Tooltip label="Refresh">
            <ActionIcon
              variant="subtle"
              color="gray"
              size="sm"
              onClick={loadSignals}
              loading={loading}
            >
              <IconRefresh size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* Summary Bar */}
      {summary && (
        <Group
          gap="xs"
          p="xs"
          style={{ borderBottom: '1px solid #373A40', background: '#1a1b1e' }}
        >
          <Text size="xs" c="dimmed">
            {summary.hosts.reachable} hosts
          </Text>
          <Text size="xs" c="dimmed">•</Text>
          <Text size="xs" c="dimmed">
            {summary.ports.open} ports
          </Text>
          <Text size="xs" c="dimmed">•</Text>
          <Text size="xs" c="dimmed">
            {summary.dns} DNS
          </Text>
          <Text size="xs" c="dimmed">•</Text>
          <Text size="xs" c="dimmed">
            {summary.users} users
          </Text>
        </Group>
      )}

      {/* Signal List */}
      <ScrollArea style={{ flex: 1 }}>
        {!engagementId ? (
          <Text c="dimmed" size="sm" ta="center" p="xl">
            No active engagement
          </Text>
        ) : loading && signals.length === 0 ? (
          <Group justify="center" p="xl">
            <Loader size="sm" color="cyan" />
          </Group>
        ) : totalSignals === 0 ? (
          <Stack align="center" justify="center" p="xl" gap="xs">
            <IconRadar size={32} color="#6e7681" />
            <Text size="xs" c="dimmed" ta="center">
              No signals captured
            </Text>
            <Text size="xs" c="dimmed" ta="center">
              Run recon commands to detect hosts and ports
            </Text>
          </Stack>
        ) : (
          <Stack gap={0} p={4}>
            {SIGNAL_TYPES.map(({ type, label, icon: Icon, color }) => {
              const typeSignals = groupedSignals.get(type) || [];
              const count = getTypeCount(type);
              if (count === 0) return null;

              return (
                <div key={type}>
                  {/* Type Header */}
                  <Group
                    gap="xs"
                    p="xs"
                    style={{
                      cursor: 'pointer',
                      background: '#1a1b1e',
                      borderRadius: 4,
                      marginBottom: 4,
                    }}
                    onClick={() => toggleType(type)}
                  >
                    {expandedTypes.has(type) ? (
                      <IconChevronDown size={14} color="#868e96" />
                    ) : (
                      <IconChevronRight size={14} color="#868e96" />
                    )}
                    <ThemeIcon size="sm" variant="light" color={color} radius="sm">
                      <Icon size={12} />
                    </ThemeIcon>
                    <Text size="xs" fw={500}>
                      {label}
                    </Text>
                    <Badge size="xs" variant="light" color={color}>
                      {count}
                    </Badge>
                  </Group>

                  {/* Signals in Type Group */}
                  <Collapse in={expandedTypes.has(type)}>
                    <Stack gap={4} pl="md" pb="xs">
                      {typeSignals.map((signal) => (
                        <SignalCard key={signal.id} signal={signal} />
                      ))}
                    </Stack>
                  </Collapse>
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
          Total: {totalSignals} signals
        </Text>
        {summary && summary.crackedHashes > 0 && (
          <Group gap={4}>
            <IconKey size={10} color="#ff6b6b" />
            <Text size="xs" c="dimmed">
              {summary.crackedHashes} cracked
            </Text>
          </Group>
        )}
      </Group>
    </Stack>
  );
}

/** Render a signal card based on type */
function SignalCard({ signal }: { signal: Signal }) {
  switch (signal.type) {
    case 'port_status':
      return <PortCard signal={signal as PortStatusSignal} />;
    case 'host_reachability':
      return <HostCard signal={signal as HostReachabilitySignal} />;
    case 'dns_resolution':
      return <DnsCard signal={signal as DnsResolutionSignal} />;
    case 'os_detection':
      return <OsCard signal={signal as OsDetectionSignal} />;
    case 'user_enumeration':
      return <UserCard signal={signal as UserEnumerationSignal} />;
    case 'cracked_hash':
      return <CrackedCard signal={signal as CrackedHashSignal} />;
    default:
      return null;
  }
}

/** Port status signal card */
function PortCard({ signal }: { signal: PortStatusSignal }) {
  const stateColor = signal.state === 'open' ? 'green' : signal.state === 'filtered' ? 'yellow' : 'gray';
  return (
    <Paper
      p={6}
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        borderRadius: 4,
      }}
    >
      <Group gap="xs" justify="space-between" wrap="nowrap">
        <Group gap="xs" wrap="nowrap">
          <Badge size="xs" variant="filled" color={stateColor}>
            {signal.state}
          </Badge>
          <Text size="xs" ff="monospace">
            {signal.ip}:{signal.port}/{signal.protocol}
          </Text>
        </Group>
        {signal.service && (
          <Badge size="xs" variant="light" color="gray">
            {signal.service}
          </Badge>
        )}
      </Group>
      {signal.version && (
        <Text size="xs" c="dimmed" mt={4} truncate>
          {signal.version}
        </Text>
      )}
    </Paper>
  );
}

/** Host reachability signal card */
function HostCard({ signal }: { signal: HostReachabilitySignal }) {
  return (
    <Paper
      p={6}
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        borderRadius: 4,
      }}
    >
      <Group gap="xs" justify="space-between" wrap="nowrap">
        <Group gap="xs" wrap="nowrap">
          <Badge size="xs" variant="filled" color={signal.reachable ? 'green' : 'red'}>
            {signal.reachable ? 'UP' : 'DOWN'}
          </Badge>
          <Text size="xs" ff="monospace">
            {signal.ip}
          </Text>
        </Group>
        {signal.ttl && (
          <Badge size="xs" variant="light" color="gray">
            TTL={signal.ttl}
          </Badge>
        )}
      </Group>
      {signal.latencyMs && (
        <Text size="xs" c="dimmed" mt={4}>
          {signal.latencyMs.toFixed(1)}ms
        </Text>
      )}
    </Paper>
  );
}

/** DNS resolution signal card */
function DnsCard({ signal }: { signal: DnsResolutionSignal }) {
  return (
    <Paper
      p={6}
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        borderRadius: 4,
      }}
    >
      <Group gap="xs" justify="space-between" wrap="nowrap">
        <Text size="xs" ff="monospace" truncate style={{ flex: 1 }}>
          {signal.hostname}
        </Text>
        <Badge size="xs" variant="light" color="blue">
          {signal.recordType}
        </Badge>
      </Group>
      <Text size="xs" c="dimmed" mt={4} ff="monospace">
        → {signal.ip}
      </Text>
    </Paper>
  );
}

/** OS detection signal card */
function OsCard({ signal }: { signal: OsDetectionSignal }) {
  const osColor = signal.osFamily === 'Windows' ? 'blue' : signal.osFamily === 'Linux' ? 'orange' : 'gray';
  return (
    <Paper
      p={6}
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        borderRadius: 4,
      }}
    >
      <Group gap="xs" justify="space-between" wrap="nowrap">
        <Text size="xs" ff="monospace">
          {signal.ip}
        </Text>
        <Badge size="xs" variant="filled" color={osColor}>
          {signal.osFamily}
        </Badge>
      </Group>
      {signal.osVersion && (
        <Text size="xs" c="dimmed" mt={4} truncate>
          {signal.osVersion}
        </Text>
      )}
    </Paper>
  );
}

/** User enumeration signal card */
function UserCard({ signal }: { signal: UserEnumerationSignal }) {
  return (
    <Paper
      p={6}
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        borderRadius: 4,
        borderLeft: signal.isPrivileged ? '3px solid #ff6b6b' : undefined,
      }}
    >
      <Group gap="xs" justify="space-between" wrap="nowrap">
        <Text size="xs" ff="monospace">
          {signal.domain ? `${signal.domain}\\` : ''}
          {signal.username}
        </Text>
        {signal.isPrivileged && (
          <Badge size="xs" variant="filled" color="red">
            ADMIN
          </Badge>
        )}
        {signal.isService && (
          <Badge size="xs" variant="light" color="violet">
            SVC
          </Badge>
        )}
        {signal.isMachine && (
          <Badge size="xs" variant="light" color="gray">
            MACHINE
          </Badge>
        )}
      </Group>
      {signal.groups && signal.groups.length > 0 && (
        <Text size="xs" c="dimmed" mt={4} truncate>
          Groups: {signal.groups.slice(0, 3).join(', ')}
          {signal.groups.length > 3 && ` +${signal.groups.length - 3} more`}
        </Text>
      )}
    </Paper>
  );
}

/** Cracked hash signal card */
function CrackedCard({ signal }: { signal: CrackedHashSignal }) {
  return (
    <Paper
      p={6}
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        borderRadius: 4,
        borderLeft: '3px solid #ff6b6b',
      }}
    >
      <Group gap="xs" wrap="nowrap">
        <Badge size="xs" variant="filled" color="red">
          CRACKED
        </Badge>
        <Text size="xs" ff="monospace" truncate style={{ flex: 1 }}>
          {signal.plaintext}
        </Text>
      </Group>
      <Text size="xs" c="dimmed" mt={4} truncate ff="monospace">
        {signal.originalHash.substring(0, 32)}...
      </Text>
      {signal.crackedBy && (
        <Badge size="xs" variant="light" color="gray" mt={4}>
          via {signal.crackedBy}
        </Badge>
      )}
    </Paper>
  );
}
