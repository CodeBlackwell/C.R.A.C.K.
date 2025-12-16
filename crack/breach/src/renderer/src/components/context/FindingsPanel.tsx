/**
 * FindingsPanel - Vulnerability/Finding Management Panel
 *
 * Displays findings detected from terminal output with severity badges.
 * Auto-populated by PRISM parser for SQLi, LFI, RCE indicators.
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
  TextInput,
  Paper,
  Loader,
  Collapse,
  ThemeIcon,
  Menu,
} from '@mantine/core';
import {
  IconAlertTriangle,
  IconBug,
  IconSearch,
  IconRefresh,
  IconChevronDown,
  IconChevronRight,
  IconExternalLink,
  IconTrash,
  IconCheck,
  IconX,
  IconDatabase,
  IconFile,
  IconTerminal2,
  IconShield,
} from '@tabler/icons-react';
import type {
  Finding,
  FindingSeverity,
  FindingCategory,
  FindingStatus,
} from '@shared/types/finding';
import { getSeverityColor, getSeverityBadge } from '@shared/types/finding';

interface FindingsPanelProps {
  engagementId?: string;
  onFindingClick?: (finding: Finding) => void;
}

/** Icon map for finding categories */
const CATEGORY_ICONS: Record<FindingCategory, typeof IconBug> = {
  sqli: IconDatabase,
  lfi: IconFile,
  rfi: IconFile,
  rce: IconTerminal2,
  privesc: IconShield,
  credential: IconShield,
  config: IconAlertTriangle,
  vuln: IconBug,
  recon: IconSearch,
  info: IconAlertTriangle,
  other: IconBug,
};

/** Label map for finding categories */
const CATEGORY_LABELS: Record<FindingCategory, string> = {
  sqli: 'SQL Injection',
  lfi: 'Local File Inclusion',
  rfi: 'Remote File Inclusion',
  rce: 'Remote Code Execution',
  privesc: 'Privilege Escalation',
  credential: 'Credential Issue',
  config: 'Misconfiguration',
  vuln: 'Known Vulnerability',
  recon: 'Reconnaissance',
  info: 'Information Disclosure',
  other: 'Other',
};

/** Status colors */
const STATUS_COLORS: Record<FindingStatus, string> = {
  open: 'yellow',
  confirmed: 'orange',
  exploited: 'red',
  reported: 'blue',
  remediated: 'green',
};

/** Group findings by severity */
function groupFindingsBySeverity(
  findings: Finding[]
): Map<FindingSeverity, Finding[]> {
  const order: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
  const groups = new Map<FindingSeverity, Finding[]>();

  // Initialize in order
  for (const sev of order) {
    groups.set(sev, []);
  }

  for (const finding of findings) {
    const list = groups.get(finding.severity);
    if (list) {
      list.push(finding);
    }
  }

  // Remove empty groups
  for (const [sev, list] of groups) {
    if (list.length === 0) {
      groups.delete(sev);
    }
  }

  return groups;
}

export function FindingsPanel({
  engagementId,
  onFindingClick,
}: FindingsPanelProps) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [expandedSeverities, setExpandedSeverities] = useState<Set<FindingSeverity>>(
    new Set(['critical', 'high'])
  );

  // Load findings for engagement
  const loadFindings = useCallback(async () => {
    if (!engagementId) return;

    setLoading(true);
    try {
      const result = await window.electronAPI.findingList(engagementId);
      setFindings(result || []);
    } catch (err) {
      console.error('Failed to load findings:', err);
    } finally {
      setLoading(false);
    }
  }, [engagementId]);

  useEffect(() => {
    loadFindings();
  }, [loadFindings]);

  // Listen for new finding discoveries
  useEffect(() => {
    const handleDiscovery = () => {
      loadFindings();
    };

    window.electronAPI.onFindingDiscovered(handleDiscovery);
    return () => {
      window.electronAPI.removeFindingDiscoveredListener(handleDiscovery);
    };
  }, [loadFindings]);

  // Group and filter findings
  const groupedFindings = useMemo(() => {
    let filtered = findings;

    if (search) {
      const lower = search.toLowerCase();
      filtered = findings.filter(
        (f) =>
          f.title.toLowerCase().includes(lower) ||
          f.description.toLowerCase().includes(lower) ||
          f.evidence.toLowerCase().includes(lower) ||
          f.category.toLowerCase().includes(lower)
      );
    }

    return groupFindingsBySeverity(filtered);
  }, [findings, search]);

  // Toggle severity expansion
  const toggleSeverity = (severity: FindingSeverity) => {
    setExpandedSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(severity)) {
        next.delete(severity);
      } else {
        next.add(severity);
      }
      return next;
    });
  };

  // Handle status update
  const updateStatus = async (findingId: string, status: FindingStatus) => {
    try {
      await window.electronAPI.findingUpdate(findingId, { status });
      loadFindings();
    } catch (err) {
      console.error('Failed to update finding status:', err);
    }
  };

  // Handle delete
  const deleteFinding = async (findingId: string) => {
    try {
      await window.electronAPI.findingDelete(findingId);
      loadFindings();
    } catch (err) {
      console.error('Failed to delete finding:', err);
    }
  };

  // Count stats
  const stats = useMemo(() => {
    const critical = findings.filter((f) => f.severity === 'critical').length;
    const high = findings.filter((f) => f.severity === 'high').length;
    const exploited = findings.filter((f) => f.status === 'exploited').length;
    return { total: findings.length, critical, high, exploited };
  }, [findings]);

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
          <IconBug size={16} color="#868e96" />
          <Text size="sm" fw={600} c="dimmed">
            FINDINGS
          </Text>
        </Group>
        <Group gap={4}>
          {stats.critical > 0 && (
            <Tooltip label="Critical findings">
              <Badge size="xs" variant="filled" color="red">
                {stats.critical}
              </Badge>
            </Tooltip>
          )}
          {stats.high > 0 && (
            <Tooltip label="High severity findings">
              <Badge size="xs" variant="filled" color="orange">
                {stats.high}
              </Badge>
            </Tooltip>
          )}
          <Tooltip label="Refresh">
            <ActionIcon
              variant="subtle"
              color="gray"
              size="sm"
              onClick={loadFindings}
              loading={loading}
            >
              <IconRefresh size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* Search */}
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #373A40' }}>
        <TextInput
          size="xs"
          placeholder="Search findings..."
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

      {/* Findings List */}
      <ScrollArea style={{ flex: 1 }}>
        {!engagementId ? (
          <Text c="dimmed" size="sm" ta="center" p="xl">
            No active engagement
          </Text>
        ) : loading && findings.length === 0 ? (
          <Group justify="center" p="xl">
            <Loader size="sm" color="cyan" />
          </Group>
        ) : findings.length === 0 ? (
          <Stack align="center" justify="center" p="xl" gap="xs">
            <IconBug size={32} color="#6e7681" />
            <Text size="xs" c="dimmed" ta="center">
              No findings detected
            </Text>
            <Text size="xs" c="dimmed" ta="center">
              Run commands to detect vulnerabilities
            </Text>
          </Stack>
        ) : (
          <Stack gap={0} p={4}>
            {Array.from(groupedFindings.entries()).map(([severity, sevFindings]) => (
              <div key={severity}>
                {/* Severity Header */}
                <Group
                  gap="xs"
                  p="xs"
                  style={{
                    cursor: 'pointer',
                    background: '#1a1b1e',
                    borderRadius: 4,
                    marginBottom: 4,
                  }}
                  onClick={() => toggleSeverity(severity)}
                >
                  {expandedSeverities.has(severity) ? (
                    <IconChevronDown size={14} color="#868e96" />
                  ) : (
                    <IconChevronRight size={14} color="#868e96" />
                  )}
                  <Badge
                    size="sm"
                    variant="filled"
                    style={{
                      background: getSeverityColor(severity),
                    }}
                  >
                    {severity.toUpperCase()}
                  </Badge>
                  <Text size="xs" c="dimmed">
                    {sevFindings.length} finding{sevFindings.length !== 1 ? 's' : ''}
                  </Text>
                </Group>

                {/* Findings in Severity Group */}
                <Collapse in={expandedSeverities.has(severity)}>
                  <Stack gap={4} pl="md" pb="xs">
                    {sevFindings.map((finding) => (
                      <FindingCard
                        key={finding.id}
                        finding={finding}
                        onClick={() => onFindingClick?.(finding)}
                        onUpdateStatus={updateStatus}
                        onDelete={deleteFinding}
                      />
                    ))}
                  </Stack>
                </Collapse>
              </div>
            ))}
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
          Total: {stats.total}
        </Text>
        <Group gap={8}>
          {stats.exploited > 0 && (
            <Group gap={4}>
              <IconCheck size={10} color="#ff7b72" />
              <Text size="xs" c="dimmed">
                {stats.exploited} exploited
              </Text>
            </Group>
          )}
        </Group>
      </Group>
    </Stack>
  );
}

/** Individual finding card */
interface FindingCardProps {
  finding: Finding;
  onClick?: () => void;
  onUpdateStatus: (id: string, status: FindingStatus) => void;
  onDelete: (id: string) => void;
}

function FindingCard({ finding, onClick, onUpdateStatus, onDelete }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);
  const Icon = CATEGORY_ICONS[finding.category] || IconBug;
  const categoryLabel = CATEGORY_LABELS[finding.category] || finding.category;
  const badge = getSeverityBadge(finding.severity);

  return (
    <Paper
      p={8}
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        borderRadius: 4,
        borderLeft: `3px solid ${getSeverityColor(finding.severity)}`,
      }}
    >
      <Group gap="xs" justify="space-between" wrap="nowrap">
        {/* Icon and Info */}
        <Group
          gap="xs"
          wrap="nowrap"
          style={{ flex: 1, overflow: 'hidden', cursor: 'pointer' }}
          onClick={() => setExpanded(!expanded)}
        >
          <ThemeIcon
            size="sm"
            variant="light"
            color={finding.severity === 'critical' ? 'red' : 'gray'}
            radius="sm"
          >
            <Icon size={12} />
          </ThemeIcon>
          <Stack gap={2} style={{ flex: 1, overflow: 'hidden' }}>
            <Text size="xs" fw={500} truncate>
              {finding.title}
            </Text>
            <Group gap={4}>
              <Badge size="xs" variant="light" color="gray">
                {categoryLabel}
              </Badge>
              <Badge
                size="xs"
                variant="light"
                color={STATUS_COLORS[finding.status]}
              >
                {finding.status}
              </Badge>
            </Group>
          </Stack>
        </Group>

        {/* Actions */}
        <Group gap={4} wrap="nowrap">
          <Menu shadow="md" width={150} position="bottom-end">
            <Menu.Target>
              <Tooltip label="Update Status">
                <ActionIcon variant="subtle" color="gray" size="sm">
                  <IconChevronDown size={14} />
                </ActionIcon>
              </Tooltip>
            </Menu.Target>

            <Menu.Dropdown>
              <Menu.Label>Set Status</Menu.Label>
              <Menu.Item
                leftSection={<IconAlertTriangle size={14} />}
                onClick={() => onUpdateStatus(finding.id, 'confirmed')}
              >
                Confirmed
              </Menu.Item>
              <Menu.Item
                leftSection={<IconCheck size={14} color="#ff7b72" />}
                onClick={() => onUpdateStatus(finding.id, 'exploited')}
              >
                Exploited
              </Menu.Item>
              <Menu.Item
                leftSection={<IconExternalLink size={14} />}
                onClick={() => onUpdateStatus(finding.id, 'reported')}
              >
                Reported
              </Menu.Item>
              <Menu.Divider />
              <Menu.Item
                leftSection={<IconTrash size={14} />}
                color="red"
                onClick={() => onDelete(finding.id)}
              >
                Delete
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </Group>
      </Group>

      {/* Expanded Evidence */}
      <Collapse in={expanded}>
        <Stack gap="xs" mt="xs" pt="xs" style={{ borderTop: '1px solid #373A40' }}>
          {finding.description && (
            <Text size="xs" c="dimmed">
              {finding.description}
            </Text>
          )}
          {finding.evidence && (
            <Paper
              p="xs"
              style={{
                background: '#1a1b1e',
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: 11,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
                maxHeight: 100,
                overflow: 'auto',
              }}
            >
              {finding.evidence}
            </Paper>
          )}
          {finding.cveId && (
            <Badge size="xs" variant="outline" color="cyan">
              {finding.cveId}
            </Badge>
          )}
        </Stack>
      </Collapse>
    </Paper>
  );
}
