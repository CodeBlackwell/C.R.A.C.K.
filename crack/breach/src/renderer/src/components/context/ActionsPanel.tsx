/**
 * ActionsPanel - Context-Aware Action Menu
 *
 * Displays pentesting actions relevant to selected target's services.
 * Accordion structure: Category -> Tool -> Command Variants
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Stack,
  ScrollArea,
  Accordion,
  Text,
  Badge,
  Group,
  ActionIcon,
  Tooltip,
  Loader,
  ThemeIcon,
  UnstyledButton,
} from '@mantine/core';
import {
  IconBolt,
  IconRadar,
  IconWorld,
  IconFolder,
  IconTerminal2,
  IconKey,
  IconDatabase,
  IconUpload,
  IconDeviceDesktop,
  IconAntenna,
  IconFolders,
  IconWorldWww,
  IconSitemap,
  IconRefresh,
  IconCode,
} from '@tabler/icons-react';
import {
  getRelevantCategories,
  ACTION_CATEGORIES,
} from '@shared/actions/service-mapping';
import type {
  ActionCategory,
  ActionVariant,
  ActionTool,
  ServiceInfo,
} from '@shared/types/actions-panel';

/** Icon mapping for categories */
const CATEGORY_ICONS: Record<string, typeof IconBolt> = {
  'port-scan': IconRadar,
  smb: IconFolder,
  http: IconWorld,
  ldap: IconSitemap,
  ssh: IconTerminal2,
  ftp: IconUpload,
  mssql: IconDatabase,
  mysql: IconDatabase,
  rdp: IconDeviceDesktop,
  winrm: IconTerminal2,
  dns: IconWorldWww,
  snmp: IconAntenna,
  nfs: IconFolders,
  kerberos: IconKey,
};

interface ActionsPanelProps {
  targetId?: string;
  targetIp?: string;
  targetHostname?: string;
  engagementId?: string;
  onExecuteAction?: (command: string, label: string, autorun: boolean) => void;
}

export function ActionsPanel({
  targetId,
  targetIp,
  targetHostname,
  engagementId,
  onExecuteAction,
}: ActionsPanelProps) {
  const [services, setServices] = useState<ServiceInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [expandedCategories, setExpandedCategories] = useState<string[]>(['port-scan']);
  const [expandedTools, setExpandedTools] = useState<string[]>([]);
  const [verbose, setVerbose] = useState(false);

  // Load services when target changes
  useEffect(() => {
    if (!targetId) {
      setServices([]);
      return;
    }

    setLoading(true);
    window.electronAPI
      .targetServices(targetId)
      .then((result) => setServices(result || []))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [targetId]);

  // Get relevant categories based on services
  const relevantCategories = useMemo(() => {
    if (!targetId) {
      // If no target selected, show Port Scan only
      return ACTION_CATEGORIES.filter((c) => c.alwaysShow);
    }
    return getRelevantCategories(services);
  }, [services, targetId]);

  // Handle accordion change
  const handleAccordionChange = (value: string[]) => {
    setExpandedCategories(value);
  };

  // Handle tool accordion change
  const handleToolChange = (categoryId: string, toolIds: string[]) => {
    setExpandedTools(toolIds);
  };

  // Execute action
  const handleExecuteAction = useCallback(
    (variant: ActionVariant) => {
      if (!onExecuteAction) return;

      // Substitute placeholders in command
      let command = variant.command;
      if (targetIp) {
        command = command.replace(/<IP>/g, targetIp);
        command = command.replace(/<TARGET>/g, targetIp);
      }
      if (targetHostname) {
        command = command.replace(/<HOSTNAME>/g, targetHostname);
      }

      // When verbose is ON, prefill command without executing (autorun=false)
      onExecuteAction(command, variant.label, !verbose);
    },
    [targetIp, targetHostname, onExecuteAction, verbose]
  );

  // Refresh services
  const handleRefresh = useCallback(() => {
    if (!targetId) return;
    setLoading(true);
    window.electronAPI
      .targetServices(targetId)
      .then((result) => setServices(result || []))
      .finally(() => setLoading(false));
  }, [targetId]);

  if (!targetId && !engagementId) {
    return (
      <Stack align="center" justify="center" style={{ height: '100%' }} gap="xs">
        <IconBolt size={32} color="#6e7681" />
        <Text size="xs" c="dimmed" ta="center">
          No engagement active
        </Text>
      </Stack>
    );
  }

  return (
    <Stack gap={0} style={{ height: '100%', background: '#25262b' }}>
      {/* Header */}
      <Group
        justify="space-between"
        p="xs"
        style={{ borderBottom: '1px solid #373A40' }}
      >
        <Group gap="xs">
          <IconBolt size={16} color="#f59f00" />
          <Text size="sm" fw={600} c="dimmed">
            ACTIONS
          </Text>
          {targetIp && (
            <Badge size="xs" variant="light" color="cyan">
              {targetIp}
            </Badge>
          )}
        </Group>
        <Group gap={4}>
          {services.length > 0 && (
            <Badge size="xs" variant="light" color="orange">
              {services.length} svc
            </Badge>
          )}
          <Tooltip label={verbose ? "Verbose: ON (prefill mode)" : "Verbose: OFF (auto-execute)"}>
            <ActionIcon
              variant={verbose ? 'filled' : 'subtle'}
              color={verbose ? 'cyan' : 'gray'}
              size="sm"
              onClick={() => setVerbose(!verbose)}
            >
              <IconCode size={14} />
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Refresh Services">
            <ActionIcon
              variant="subtle"
              color="gray"
              size="sm"
              onClick={handleRefresh}
              loading={loading}
              disabled={!targetId}
            >
              <IconRefresh size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* Content */}
      {loading ? (
        <Group justify="center" p="xl">
          <Loader size="sm" color="orange" />
        </Group>
      ) : !targetId ? (
        <Stack align="center" justify="center" style={{ flex: 1 }} gap="xs">
          <IconRadar size={32} color="#6e7681" />
          <Text size="xs" c="dimmed" ta="center">
            Select a target to view actions
          </Text>
          <Text size="xs" c="dimmed" ta="center" maw={200}>
            Actions appear based on detected services
          </Text>
        </Stack>
      ) : (
        <ScrollArea style={{ flex: 1 }}>
          <Accordion
            multiple
            value={expandedCategories}
            onChange={handleAccordionChange}
            styles={{
              item: { borderBottom: '1px solid #373A40' },
              control: { padding: '8px 12px' },
              content: { padding: '0' },
            }}
          >
            {relevantCategories.map((category) => (
              <CategoryAccordionItem
                key={category.id}
                category={category}
                expandedTools={expandedTools}
                onToolChange={(toolIds) => handleToolChange(category.id, toolIds)}
                onExecuteAction={handleExecuteAction}
                verbose={verbose}
                targetIp={targetIp}
                targetHostname={targetHostname}
              />
            ))}
          </Accordion>

          {/* Show detected services summary */}
          {services.length > 0 && (
            <Stack gap="xs" p="xs" style={{ borderTop: '1px solid #373A40' }}>
              <Text size="xs" c="dimmed" fw={500}>
                Detected Services
              </Text>
              <Group gap={4}>
                {services.slice(0, 8).map((svc) => (
                  <Badge
                    key={svc.id}
                    size="xs"
                    variant="outline"
                    color="gray"
                    style={{ fontFamily: 'JetBrains Mono, monospace' }}
                  >
                    {svc.port}/{svc.protocol}
                    {svc.service_name && ` ${svc.service_name}`}
                  </Badge>
                ))}
                {services.length > 8 && (
                  <Badge size="xs" variant="light" color="gray">
                    +{services.length - 8} more
                  </Badge>
                )}
              </Group>
            </Stack>
          )}
        </ScrollArea>
      )}
    </Stack>
  );
}

/** Category accordion item */
interface CategoryAccordionItemProps {
  category: ActionCategory;
  expandedTools: string[];
  onToolChange: (toolIds: string[]) => void;
  onExecuteAction: (variant: ActionVariant) => void;
  verbose: boolean;
  targetIp?: string;
  targetHostname?: string;
}

function CategoryAccordionItem({
  category,
  expandedTools,
  onToolChange,
  onExecuteAction,
  verbose,
  targetIp,
  targetHostname,
}: CategoryAccordionItemProps) {
  const Icon = CATEGORY_ICONS[category.id] || IconBolt;

  return (
    <Accordion.Item value={category.id}>
      <Accordion.Control>
        <Group gap="xs">
          <ThemeIcon size="sm" variant="light" color="orange" radius="sm">
            <Icon size={12} />
          </ThemeIcon>
          <Text size="xs" fw={500}>
            {category.name}
          </Text>
          <Badge size="xs" variant="light" color="gray">
            {category.tools.reduce((sum, t) => sum + t.variants.length, 0)}
          </Badge>
        </Group>
      </Accordion.Control>
      <Accordion.Panel>
        <Stack gap={0}>
          {category.tools.map((tool) => (
            <ToolSection
              key={tool.id}
              tool={tool}
              categoryId={category.id}
              onExecuteAction={onExecuteAction}
              verbose={verbose}
              targetIp={targetIp}
              targetHostname={targetHostname}
            />
          ))}
        </Stack>
      </Accordion.Panel>
    </Accordion.Item>
  );
}

/** Tool section with variants */
interface ToolSectionProps {
  tool: ActionTool;
  categoryId: string;
  onExecuteAction: (variant: ActionVariant) => void;
  verbose: boolean;
  targetIp?: string;
  targetHostname?: string;
}

function ToolSection({ tool, categoryId, onExecuteAction, verbose, targetIp, targetHostname }: ToolSectionProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Stack gap={0}>
      {/* Tool header */}
      <UnstyledButton
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: '6px 12px',
          background: '#1a1b1e',
          borderBottom: '1px solid #2c2e33',
        }}
      >
        <Group gap="xs">
          <Text size="xs" c="dimmed" style={{ width: 8 }}>
            {expanded ? '▼' : '▶'}
          </Text>
          <Text size="xs" fw={500} c="gray.4">
            {tool.name}
          </Text>
          <Badge size="xs" variant="dot" color="gray">
            {tool.variants.length}
          </Badge>
        </Group>
      </UnstyledButton>

      {/* Variants */}
      {expanded && (
        <Stack gap={0}>
          {tool.variants.map((variant) => (
            <VariantItem
              key={variant.id}
              variant={variant}
              onExecute={() => onExecuteAction(variant)}
              verbose={verbose}
              targetIp={targetIp}
              targetHostname={targetHostname}
            />
          ))}
        </Stack>
      )}
    </Stack>
  );
}

/** Individual variant/command item */
interface VariantItemProps {
  variant: ActionVariant;
  onExecute: () => void;
  verbose: boolean;
  targetIp?: string;
  targetHostname?: string;
}

function VariantItem({ variant, onExecute, verbose, targetIp, targetHostname }: VariantItemProps) {
  // Compute substituted command for display
  const displayCommand = useMemo(() => {
    let cmd = variant.command;
    if (targetIp) {
      cmd = cmd.replace(/<IP>/g, targetIp);
      cmd = cmd.replace(/<TARGET>/g, targetIp);
    }
    if (targetHostname) {
      cmd = cmd.replace(/<HOSTNAME>/g, targetHostname);
    }
    return cmd;
  }, [variant.command, targetIp, targetHostname]);

  return (
    <UnstyledButton
      onClick={onExecute}
      style={{
        padding: '6px 12px 6px 28px',
        background: '#25262b',
        borderBottom: '1px solid #2c2e33',
        transition: 'background 0.1s',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = '#2c2e33';
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = '#25262b';
      }}
    >
      <Group gap="xs" justify="space-between" wrap="nowrap">
        <Stack gap={0} style={{ flex: 1, overflow: 'hidden' }}>
          <Group gap="xs" wrap="nowrap">
            <IconTerminal2 size={12} color="#868e96" />
            <Text size="xs" truncate>
              {variant.label}
            </Text>
            {variant.oscpRelevance === 'high' && (
              <Badge size="xs" color="green" variant="light">
                OSCP
              </Badge>
            )}
          </Group>
          {variant.description && (
            <Text
              size="xs"
              c="dimmed"
              truncate
              pl={20}
              style={{ maxWidth: 220 }}
            >
              {variant.description}
            </Text>
          )}
          {verbose && (
            <Text
              size="xs"
              c="dimmed"
              pl={20}
              style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: 10,
                opacity: 0.7,
                wordBreak: 'break-all',
              }}
            >
              {displayCommand}
            </Text>
          )}
        </Stack>
      </Group>
    </UnstyledButton>
  );
}
