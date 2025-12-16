/**
 * ContextPanel - Right Side Panel Container
 *
 * Collapsible panel containing Credential Vault, Loot, and Quick Actions.
 * Replaces SessionDock with more comprehensive context information.
 */

import { useState } from 'react';
import { Stack, Tabs, ActionIcon, Tooltip, Group, Text } from '@mantine/core';
import {
  IconKey,
  IconFile,
  IconBolt,
  IconChevronLeft,
  IconChevronRight,
} from '@tabler/icons-react';
import { CredentialVault } from './CredentialVault';
import { LootPanel } from './LootPanel';
import { ActionsPanel } from './ActionsPanel';
import type { Loot, PatternType } from '@shared/types/loot';

interface ContextPanelProps {
  engagementId?: string;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  onUseCredential?: (command: string, credentialId: string) => void;
  onExtractCredential?: (loot: Loot, pattern: PatternType) => void;
  /** Selected target for actions panel */
  selectedTargetId?: string;
  selectedTargetIp?: string;
  selectedTargetHostname?: string;
  onExecuteAction?: (command: string, label: string) => void;
}

export function ContextPanel({
  engagementId,
  collapsed = false,
  onToggleCollapse,
  onUseCredential,
  onExtractCredential,
  selectedTargetId,
  selectedTargetIp,
  selectedTargetHostname,
  onExecuteAction,
}: ContextPanelProps) {
  const [activeTab, setActiveTab] = useState<string | null>('actions');

  // Collapsed view - just icons
  if (collapsed) {
    return (
      <Stack
        gap={0}
        style={{
          width: 48,
          height: '100%',
          background: '#25262b',
          borderLeft: '1px solid #373A40',
        }}
      >
        <Group justify="center" p="xs" style={{ borderBottom: '1px solid #373A40' }}>
          <Tooltip label="Expand Panel" position="left">
            <ActionIcon
              variant="subtle"
              color="gray"
              size="sm"
              onClick={onToggleCollapse}
            >
              <IconChevronLeft size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>

        <Stack gap={0} align="center" pt="md">
          <Tooltip label="Quick Actions" position="left">
            <ActionIcon
              variant={activeTab === 'actions' ? 'light' : 'subtle'}
              color={activeTab === 'actions' ? 'orange' : 'gray'}
              size="lg"
              onClick={() => {
                setActiveTab('actions');
                onToggleCollapse?.();
              }}
            >
              <IconBolt size={18} />
            </ActionIcon>
          </Tooltip>

          <Tooltip label="Credentials" position="left">
            <ActionIcon
              variant={activeTab === 'credentials' ? 'light' : 'subtle'}
              color={activeTab === 'credentials' ? 'cyan' : 'gray'}
              size="lg"
              onClick={() => {
                setActiveTab('credentials');
                onToggleCollapse?.();
              }}
            >
              <IconKey size={18} />
            </ActionIcon>
          </Tooltip>

          <Tooltip label="Loot" position="left">
            <ActionIcon
              variant={activeTab === 'loot' ? 'light' : 'subtle'}
              color={activeTab === 'loot' ? 'green' : 'gray'}
              size="lg"
              onClick={() => {
                setActiveTab('loot');
                onToggleCollapse?.();
              }}
            >
              <IconFile size={18} />
            </ActionIcon>
          </Tooltip>
        </Stack>
      </Stack>
    );
  }

  // Expanded view
  return (
    <Stack
      gap={0}
      style={{
        width: 320,
        height: '100%',
        background: '#25262b',
        borderLeft: '1px solid #373A40',
      }}
    >
      {/* Tab Header */}
      <Tabs
        value={activeTab}
        onChange={setActiveTab}
        variant="pills"
        radius="xs"
        styles={{
          root: {
            borderBottom: '1px solid #373A40',
            background: '#1a1b1e',
          },
          list: {
            padding: '8px',
            gap: '4px',
          },
          tab: {
            fontSize: '11px',
            padding: '6px 12px',
            fontWeight: 500,
          },
        }}
      >
        <Group justify="space-between" wrap="nowrap" style={{ width: '100%' }}>
          <Tabs.List>
            <Tabs.Tab value="actions" leftSection={<IconBolt size={12} />}>
              Actions
            </Tabs.Tab>
            <Tabs.Tab value="credentials" leftSection={<IconKey size={12} />}>
              Creds
            </Tabs.Tab>
            <Tabs.Tab value="loot" leftSection={<IconFile size={12} />}>
              Loot
            </Tabs.Tab>
          </Tabs.List>

          <Tooltip label="Collapse Panel">
            <ActionIcon
              variant="subtle"
              color="gray"
              size="sm"
              onClick={onToggleCollapse}
              mr="xs"
            >
              <IconChevronRight size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Tabs>

      {/* Tab Content */}
      <div style={{ flex: 1, overflow: 'hidden' }}>
        {activeTab === 'credentials' && (
          <CredentialVault
            engagementId={engagementId}
            onUseCredential={onUseCredential}
          />
        )}

        {activeTab === 'loot' && (
          <LootPanel
            engagementId={engagementId}
            onExtractCredential={onExtractCredential}
          />
        )}

        {activeTab === 'actions' && (
          <ActionsPanel
            targetId={selectedTargetId}
            targetIp={selectedTargetIp}
            targetHostname={selectedTargetHostname}
            engagementId={engagementId}
            onExecuteAction={onExecuteAction}
          />
        )}
      </div>
    </Stack>
  );
}

export { CredentialVault } from './CredentialVault';
export { LootPanel } from './LootPanel';
export { ActionsPanel } from './ActionsPanel';
