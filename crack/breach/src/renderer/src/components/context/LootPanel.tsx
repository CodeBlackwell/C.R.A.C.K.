/**
 * LootPanel - Loot/File Management Panel
 *
 * Displays captured files, flags, and detected patterns.
 * Integrates with PRISM pattern detection.
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
  Modal,
  Code,
  Loader,
  ThemeIcon,
  Tabs,
} from '@mantine/core';
import {
  IconFile,
  IconFlag,
  IconHash,
  IconKey,
  IconSearch,
  IconRefresh,
  IconEye,
  IconDownload,
  IconTrash,
  IconCircleFilled,
  IconFileCode,
  IconLock,
} from '@tabler/icons-react';
import type { Loot, LootType, PatternType } from '@shared/types/loot';
import { getPatternAction } from '@shared/types/loot';

interface LootPanelProps {
  engagementId?: string;
  onExtractCredential?: (loot: Loot, pattern: PatternType) => void;
  onPreview?: (loot: Loot) => void;
}

/** Icon map for loot types */
const LOOT_TYPE_ICONS: Record<LootType, typeof IconFile> = {
  file: IconFile,
  flag: IconFlag,
  hash: IconHash,
  key: IconLock,
  config: IconFileCode,
};

/** Color map for loot types */
const LOOT_TYPE_COLORS: Record<LootType, string> = {
  file: 'gray',
  flag: 'green',
  hash: 'orange',
  key: 'violet',
  config: 'cyan',
};

/** Pattern badge colors */
const PATTERN_COLORS: Partial<Record<PatternType, string>> = {
  gpp_password: 'yellow',
  ntlm_hash: 'orange',
  kerberos_hash: 'cyan',
  ssh_key: 'violet',
  flag: 'green',
  flag_format: 'green',
  password_in_file: 'red',
  connection_string: 'blue',
};

export function LootPanel({
  engagementId,
  onExtractCredential,
  onPreview,
}: LootPanelProps) {
  const [loot, setLoot] = useState<Loot[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [activeTab, setActiveTab] = useState<string | null>('all');
  const [previewModal, setPreviewModal] = useState<{
    open: boolean;
    loot: Loot | null;
    content: string | null;
    loading: boolean;
  }>({ open: false, loot: null, content: null, loading: false });

  // Load loot for engagement
  const loadLoot = useCallback(async () => {
    if (!engagementId) return;

    setLoading(true);
    try {
      const items = await window.electronAPI.lootList(engagementId);
      setLoot(items || []);
    } catch (err) {
      console.error('Failed to load loot:', err);
    } finally {
      setLoading(false);
    }
  }, [engagementId]);

  useEffect(() => {
    loadLoot();
  }, [loadLoot]);

  // Filter loot by tab and search
  const filteredLoot = useMemo(() => {
    let filtered = loot;

    // Filter by tab
    if (activeTab && activeTab !== 'all') {
      filtered = filtered.filter((l) => l.type === activeTab);
    }

    // Filter by search
    if (search) {
      const lower = search.toLowerCase();
      filtered = filtered.filter(
        (l) =>
          l.name.toLowerCase().includes(lower) ||
          l.sourcePath?.toLowerCase().includes(lower) ||
          l.detectedPatterns?.some((p) => p.toLowerCase().includes(lower))
      );
    }

    return filtered;
  }, [loot, activeTab, search]);

  // Count stats by type
  const stats = useMemo(() => {
    const flags = loot.filter((l) => l.type === 'flag').length;
    const hashes = loot.filter((l) => l.type === 'hash').length;
    const patterns = loot.filter((l) => l.detectedPatterns && l.detectedPatterns.length > 0).length;
    return { total: loot.length, flags, hashes, patterns };
  }, [loot]);

  // Open preview modal
  const handlePreview = async (item: Loot) => {
    setPreviewModal({ open: true, loot: item, content: null, loading: true });

    try {
      const result = await window.electronAPI.lootGetContent(item.id);
      setPreviewModal((prev) => ({
        ...prev,
        content: result?.content || 'Unable to read file',
        loading: false,
      }));
    } catch (err) {
      setPreviewModal((prev) => ({
        ...prev,
        content: 'Error loading content',
        loading: false,
      }));
    }
  };

  // Handle delete
  const handleDelete = async (item: Loot) => {
    try {
      await window.electronAPI.lootDelete(item.id);
      setLoot((prev) => prev.filter((l) => l.id !== item.id));
    } catch (err) {
      console.error('Failed to delete loot:', err);
    }
  };

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
          <IconFile size={16} color="#868e96" />
          <Text size="sm" fw={600} c="dimmed">
            LOOT
          </Text>
        </Group>
        <Group gap={4}>
          {stats.flags > 0 && (
            <Tooltip label="Flags captured">
              <Badge size="xs" variant="light" color="green">
                {stats.flags} flags
              </Badge>
            </Tooltip>
          )}
          {stats.patterns > 0 && (
            <Tooltip label="Files with detected patterns">
              <Badge size="xs" variant="light" color="orange">
                {stats.patterns}
              </Badge>
            </Tooltip>
          )}
          <Tooltip label="Refresh">
            <ActionIcon
              variant="subtle"
              color="gray"
              size="sm"
              onClick={loadLoot}
              loading={loading}
            >
              <IconRefresh size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* Tabs */}
      <Tabs
        value={activeTab}
        onChange={setActiveTab}
        variant="pills"
        radius="xs"
        styles={{
          root: { borderBottom: '1px solid #373A40', padding: '4px 8px' },
          tab: { fontSize: '10px', padding: '4px 8px' },
        }}
      >
        <Tabs.List>
          <Tabs.Tab value="all">All ({loot.length})</Tabs.Tab>
          <Tabs.Tab value="flag" color="green">
            Flags ({stats.flags})
          </Tabs.Tab>
          <Tabs.Tab value="hash" color="orange">
            Hashes ({stats.hashes})
          </Tabs.Tab>
        </Tabs.List>
      </Tabs>

      {/* Search */}
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #373A40' }}>
        <TextInput
          size="xs"
          placeholder="Search loot..."
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

      {/* Loot List */}
      <ScrollArea style={{ flex: 1 }}>
        {!engagementId ? (
          <Text c="dimmed" size="sm" ta="center" p="xl">
            No active engagement
          </Text>
        ) : loading && loot.length === 0 ? (
          <Group justify="center" p="xl">
            <Loader size="sm" color="cyan" />
          </Group>
        ) : filteredLoot.length === 0 ? (
          <Stack align="center" justify="center" p="xl" gap="xs">
            <IconFile size={32} color="#6e7681" />
            <Text size="xs" c="dimmed" ta="center">
              No loot captured
            </Text>
          </Stack>
        ) : (
          <Stack gap={4} p={4}>
            {filteredLoot.map((item) => (
              <LootCard
                key={item.id}
                loot={item}
                onPreview={() => handlePreview(item)}
                onDelete={() => handleDelete(item)}
                onExtractCredential={
                  onExtractCredential
                    ? (pattern) => onExtractCredential(item, pattern)
                    : undefined
                }
              />
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
          <Group gap={4}>
            <IconCircleFilled size={6} color="#7ee787" />
            <Text size="xs" c="dimmed">
              {stats.flags} flags
            </Text>
          </Group>
        </Group>
      </Group>

      {/* Preview Modal */}
      <Modal
        opened={previewModal.open}
        onClose={() => setPreviewModal({ open: false, loot: null, content: null, loading: false })}
        title={
          <Group gap="xs">
            <IconFile size={16} />
            <Text size="sm" fw={500}>
              {previewModal.loot?.name}
            </Text>
          </Group>
        }
        size="lg"
      >
        {previewModal.loading ? (
          <Group justify="center" p="xl">
            <Loader size="sm" />
          </Group>
        ) : (
          <Stack gap="xs">
            {previewModal.loot?.sourcePath && (
              <Text size="xs" c="dimmed">
                Source: {previewModal.loot.sourcePath}
              </Text>
            )}
            <Code
              block
              style={{
                maxHeight: 400,
                overflow: 'auto',
                background: '#1a1b1e',
                fontSize: '11px',
              }}
            >
              {previewModal.content}
            </Code>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}

/** Individual loot card */
interface LootCardProps {
  loot: Loot;
  onPreview: () => void;
  onDelete: () => void;
  onExtractCredential?: (pattern: PatternType) => void;
}

function LootCard({ loot, onPreview, onDelete, onExtractCredential }: LootCardProps) {
  const Icon = LOOT_TYPE_ICONS[loot.type] || IconFile;
  const color = LOOT_TYPE_COLORS[loot.type] || 'gray';

  return (
    <Paper
      p={8}
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        borderRadius: 4,
      }}
    >
      <Group gap="xs" justify="space-between" wrap="nowrap">
        {/* Icon and Info */}
        <Group gap="xs" wrap="nowrap" style={{ flex: 1, overflow: 'hidden' }}>
          <ThemeIcon size="sm" variant="light" color={color} radius="sm">
            <Icon size={12} />
          </ThemeIcon>
          <Stack gap={2} style={{ flex: 1, overflow: 'hidden' }}>
            <Text
              size="xs"
              fw={500}
              truncate
              style={{ fontFamily: 'JetBrains Mono, monospace' }}
            >
              {loot.name}
            </Text>
            {loot.sourcePath && (
              <Text size="xs" c="dimmed" truncate>
                {loot.sourcePath}
              </Text>
            )}
          </Stack>
        </Group>

        {/* Actions */}
        <Group gap={4} wrap="nowrap">
          <Tooltip label="Preview">
            <ActionIcon variant="subtle" color="gray" size="sm" onClick={onPreview}>
              <IconEye size={14} />
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Delete">
            <ActionIcon variant="subtle" color="red" size="sm" onClick={onDelete}>
              <IconTrash size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* Detected Patterns */}
      {loot.detectedPatterns && loot.detectedPatterns.length > 0 && (
        <Group gap={4} mt={6}>
          {loot.detectedPatterns.map((pattern) => {
            const action = getPatternAction(pattern as PatternType);
            const patternColor = PATTERN_COLORS[pattern as PatternType] || 'gray';

            return (
              <Tooltip
                key={pattern}
                label={action ? `Click to ${action.label}` : pattern}
              >
                <Badge
                  size="xs"
                  variant="light"
                  color={patternColor}
                  style={{ cursor: action ? 'pointer' : 'default' }}
                  onClick={() => {
                    if (action && onExtractCredential) {
                      onExtractCredential(pattern as PatternType);
                    }
                  }}
                >
                  {pattern}
                </Badge>
              </Tooltip>
            );
          })}
        </Group>
      )}

      {/* Content Preview */}
      {loot.contentPreview && (
        <Code
          block
          mt={6}
          style={{
            background: '#1a1b1e',
            fontSize: '10px',
            maxHeight: 60,
            overflow: 'hidden',
          }}
        >
          {loot.contentPreview.slice(0, 200)}
          {loot.contentPreview.length > 200 && '...'}
        </Code>
      )}
    </Paper>
  );
}
