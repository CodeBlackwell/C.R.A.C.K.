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
  Paper,
  Box,
  Divider,
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
  IconPlayerPlay,
  IconSparkles,
} from '@tabler/icons-react';
import { SERVICE_MATCHERS } from '@shared/actions/service-mapping';
import type { ServiceInfo } from '@shared/types/actions-panel';
import type { CommandModule, CommandTool, CommandVariant } from '@shared/types/module-preferences';
import type { Credential } from '@shared/types/credential';
import type { Loot } from '@shared/types/loot';
import type { TerminalSession } from '@shared/types/session';
import type { RecommendedAction, RecommendationResult } from '@shared/types/recommendation';
import { getRecommendations, getPhaseLabel } from '@shared/recommendation/engine';
import { useModuleStore } from '../../stores/moduleStore';
import { ModuleSelector } from './ModuleSelector';
import { CommandSearchBar, DEFAULT_FILTERS, type SearchFilters } from './CommandSearchBar';

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
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loot, setLoot] = useState<Loot[]>([]);
  const [sessions, setSessions] = useState<TerminalSession[]>([]);
  const [recommendations, setRecommendations] = useState<RecommendationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [expandedCategories, setExpandedCategories] = useState<string[]>(['port-scan']);
  const [expandedTools, setExpandedTools] = useState<string[]>([]);
  const [verbose, setVerbose] = useState(true);
  const [showRecommendations, setShowRecommendations] = useState(true);
  const [lastExecutedRec, setLastExecutedRec] = useState<RecommendedAction | null>(null);

  // Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [searchFilters, setSearchFilters] = useState<SearchFilters>(DEFAULT_FILTERS);
  const [filterLogic, setFilterLogic] = useState<'AND' | 'OR'>('OR');
  const [globalSearching, setGlobalSearching] = useState(false);
  const [globalResults, setGlobalResults] = useState<CommandVariant[]>([]);

  // Get module store
  const {
    preferences,
    loadedModules,
    loadingModules,
    initialized,
    initialize,
    loadModule,
    getVisibleModules,
  } = useModuleStore();

  // Initialize module store on mount
  useEffect(() => {
    initialize();
  }, [initialize]);

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

  // Load credentials when engagement changes
  useEffect(() => {
    if (!engagementId) {
      setCredentials([]);
      return;
    }

    window.electronAPI
      .credentialList(engagementId)
      .then((result) => setCredentials(result || []))
      .catch(console.error);
  }, [engagementId]);

  // Load loot when engagement changes
  useEffect(() => {
    if (!engagementId) {
      setLoot([]);
      return;
    }

    window.electronAPI
      .lootList(engagementId)
      .then((result) => setLoot(result || []))
      .catch(console.error);
  }, [engagementId]);

  // Load sessions (for shell detection)
  useEffect(() => {
    window.electronAPI
      .sessionList()
      .then((result) => setSessions(result || []))
      .catch(console.error);

    // Re-fetch sessions periodically to detect new shells
    const interval = setInterval(() => {
      window.electronAPI
        .sessionList()
        .then((result) => setSessions(result || []))
        .catch(console.error);
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  // Compute recommendations when services/credentials/loot/sessions/target change
  useEffect(() => {
    if (!targetIp) {
      setRecommendations(null);
      return;
    }

    const result = getRecommendations({
      services,
      credentials,
      loot,
      sessions,
      targetIp,
      domain: credentials.find((c) => c.domain)?.domain,
    });
    setRecommendations(result);
  }, [services, credentials, loot, sessions, targetIp]);

  // Compute which modules SHOULD be shown (regardless of loaded state)
  const modulesToShow = useMemo(() => {
    const enabledModules = preferences.modules.filter((m) => m.enabled);

    if (!targetId) {
      // No target: show only port-scan
      return enabledModules.filter((m) => m.id === 'port-scan');
    }

    if (preferences.serviceMatchMode === 'all_enabled') {
      // Show all enabled modules
      return enabledModules;
    }

    // Relevant mode: filter by pinned or service match
    return enabledModules.filter((m) => {
      if (m.pinned || m.id === 'port-scan') return true;
      const matcher = SERVICE_MATCHERS[m.id];
      if (!matcher) return false;
      return services.some((svc) => {
        if (matcher.ports?.includes(svc.port)) return true;
        if (matcher.serviceNames && svc.service_name) {
          const serviceLower = svc.service_name.toLowerCase();
          return matcher.serviceNames.some((name) =>
            serviceLower.includes(name.toLowerCase())
          );
        }
        return false;
      });
    });
  }, [targetId, services, preferences]);

  // Trigger loading for modules that should be shown
  useEffect(() => {
    if (!initialized) return;

    for (const mod of modulesToShow) {
      if (!loadedModules.has(mod.id) && !loadingModules.has(mod.id)) {
        console.log('[ActionsPanel] Loading module:', mod.id);
        loadModule(mod.id);
      }
    }
    // NOTE: Intentionally NOT including loadedModules/loadingModules in deps
    // to avoid circular dependency. The effect should only trigger when
    // modulesToShow changes (new services detected, prefs changed, etc.)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modulesToShow, initialized, loadModule]);

  // Visible modules = should show AND is loaded
  const visibleModules = useMemo(() => {
    return modulesToShow
      .filter((m) => loadedModules.has(m.id))
      .map((m) => loadedModules.get(m.id)!);
  }, [modulesToShow, loadedModules]);

  // Filter modules based on search query and filters
  const filteredModules = useMemo(() => {
    // If no search active, return all visible modules
    if (!searchQuery && !searchFilters.oscpHigh) return visibleModules;

    const lower = searchQuery.toLowerCase();

    // Check if a variant matches the search criteria
    const matchesVariant = (v: CommandVariant): boolean => {
      const checks: boolean[] = [];

      // Text-based filters
      if (searchQuery) {
        if (searchFilters.name) {
          checks.push(v.label.toLowerCase().includes(lower));
        }
        if (searchFilters.command) {
          checks.push(v.command.toLowerCase().includes(lower));
        }
        if (searchFilters.description && v.description) {
          checks.push(v.description.toLowerCase().includes(lower));
        }
      }

      // OSCP:HIGH filter (standalone or combined)
      if (searchFilters.oscpHigh) {
        checks.push(v.oscpRelevance === 'high');
      }

      // No checks means no filters active (shouldn't reach here, but safety)
      if (checks.length === 0) return true;

      // Apply AND/OR logic
      return filterLogic === 'AND'
        ? checks.every(Boolean)
        : checks.some(Boolean);
    };

    // Filter modules -> tools -> variants
    return visibleModules
      .map((module) => ({
        ...module,
        tools: module.tools
          .map((tool) => ({
            ...tool,
            variants: tool.variants.filter(matchesVariant),
          }))
          .filter((tool) => tool.variants.length > 0),
      }))
      .filter((module) => module.tools.length > 0);
  }, [visibleModules, searchQuery, searchFilters, filterLogic]);

  // Total command count for search result display
  const totalCommandCount = useMemo(() => {
    return visibleModules.reduce(
      (acc, m) => acc + m.tools.reduce((t, tool) => t + tool.variants.length, 0),
      0
    );
  }, [visibleModules]);

  // Filtered command count
  const filteredCommandCount = useMemo(() => {
    return filteredModules.reduce(
      (acc, m) => acc + m.tools.reduce((t, tool) => t + tool.variants.length, 0),
      0
    );
  }, [filteredModules]);

  // Get next step recommendations based on last executed action
  const nextStepRecs = useMemo(() => {
    if (!lastExecutedRec?.nextSteps || !recommendations) return [];

    // Find recommendations matching the next step IDs
    // Look in all phases' recommendations, not just current
    const allRecs = recommendations.recommendations;
    return lastExecutedRec.nextSteps
      .map((stepId) => {
        // Try exact match first
        const exact = allRecs.find((r) => r.id === stepId);
        if (exact) return exact;
        // Try prefix match (e.g., 'rec-kerberoast' matches 'rec-kerberoast-cred123')
        return allRecs.find((r) => r.id.startsWith(stepId) || stepId.startsWith(r.id.split('-').slice(0, 3).join('-')));
      })
      .filter((r): r is RecommendedAction => r !== undefined)
      .slice(0, 3);
  }, [lastExecutedRec, recommendations]);

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
    (variant: CommandVariant) => {
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

  // Execute recommendation
  const handleExecuteRecommendation = useCallback(
    (rec: RecommendedAction) => {
      if (!onExecuteAction) return;
      // Command is already substituted by the engine
      onExecuteAction(rec.command, rec.label, !verbose);
      // Track for next steps
      if (rec.nextSteps && rec.nextSteps.length > 0) {
        setLastExecutedRec(rec);
      }
    },
    [onExecuteAction, verbose]
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

  // Global search (Neo4j query for all commands)
  const handleGlobalSearch = useCallback(async () => {
    if (searchQuery.length < 2) return;

    setGlobalSearching(true);
    try {
      const results = await window.electronAPI.commandsSearchGlobal({
        query: searchQuery,
        filters: searchFilters,
        filterLogic,
        limit: 50,
      });

      // Transform results to CommandVariant format
      const variants: CommandVariant[] = results.map((r) => ({
        id: r.id,
        label: r.name,
        command: r.command,
        description: r.description,
        oscpRelevance: r.oscpRelevance as 'high' | 'medium' | 'low' | undefined,
      }));

      setGlobalResults(variants);
      console.log('[ActionsPanel] Global search found', variants.length, 'results');
    } catch (error) {
      console.error('[ActionsPanel] Global search failed:', error);
      setGlobalResults([]);
    } finally {
      setGlobalSearching(false);
    }
  }, [searchQuery, searchFilters, filterLogic]);

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
            <>
              <Badge size="xs" variant="light" color="cyan">
                {targetIp}
              </Badge>
              <Tooltip label={`ping -c 3 ${targetIp}`}>
                <ActionIcon
                  variant="subtle"
                  color="green"
                  size="xs"
                  onClick={(e) => {
                    e.stopPropagation();
                    if (onExecuteAction) {
                      onExecuteAction(`ping -c 3 ${targetIp}`, 'Ping', true);
                    }
                  }}
                >
                  <IconRadar size={14} />
                </ActionIcon>
              </Tooltip>
            </>
          )}
        </Group>
        <Group gap={4}>
          {services.length > 0 && (
            <Badge size="xs" variant="light" color="orange">
              {services.length} svc
            </Badge>
          )}
          {loadingModules.size > 0 && (
            <Badge size="xs" variant="light" color="blue" leftSection={<Loader size={8} />}>
              {loadingModules.size}
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
          <ModuleSelector />
        </Group>
      </Group>

      {/* Search Bar */}
      <CommandSearchBar
        query={searchQuery}
        onQueryChange={setSearchQuery}
        filters={searchFilters}
        onFiltersChange={setSearchFilters}
        filterLogic={filterLogic}
        onFilterLogicToggle={() => setFilterLogic((l) => (l === 'AND' ? 'OR' : 'AND'))}
        onGlobalSearch={handleGlobalSearch}
        isSearching={globalSearching}
        resultCount={filteredCommandCount}
        totalCount={totalCommandCount}
      />

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
          {/* Recommendations Section */}
          {showRecommendations && recommendations && recommendations.recommendations.length > 0 && (
            <Box p="xs" style={{ borderBottom: '1px solid #373A40', background: '#1a1b1e' }}>
              <Group justify="space-between" mb="xs">
                <Group gap="xs">
                  <ThemeIcon size="sm" variant="light" color="cyan" radius="sm">
                    <IconSparkles size={12} />
                  </ThemeIcon>
                  <Text size="xs" fw={600} c="cyan.4">
                    RECOMMENDED
                  </Text>
                  <Badge size="xs" variant="light" color="cyan">
                    {getPhaseLabel(recommendations.phase)}
                  </Badge>
                </Group>
                <Tooltip label="Hide recommendations">
                  <ActionIcon
                    variant="subtle"
                    color="gray"
                    size="xs"
                    onClick={() => setShowRecommendations(false)}
                  >
                    ×
                  </ActionIcon>
                </Tooltip>
              </Group>
              <Text size="xs" c="dimmed" mb="xs">
                {recommendations.phaseReason}
              </Text>
              <Stack gap={4}>
                {recommendations.recommendations.slice(0, 3).map((rec) => (
                  <Paper
                    key={rec.id}
                    p="xs"
                    withBorder
                    style={{
                      background: '#25262b',
                      borderColor: '#373A40',
                      cursor: 'pointer',
                    }}
                    onClick={() => handleExecuteRecommendation(rec)}
                  >
                    <Group justify="space-between" wrap="nowrap">
                      <Stack gap={2} style={{ flex: 1, overflow: 'hidden' }}>
                        <Group gap="xs" wrap="nowrap">
                          <Text size="xs" fw={500} truncate>
                            {rec.label}
                          </Text>
                          <Badge size="xs" variant="dot" color="cyan">
                            {rec.score}
                          </Badge>
                        </Group>
                        <Text size="xs" c="dimmed" truncate>
                          {rec.rationale}
                        </Text>
                        {verbose && (
                          <Text
                            size="xs"
                            c="dimmed"
                            style={{
                              fontFamily: 'JetBrains Mono, monospace',
                              fontSize: 9,
                              opacity: 0.6,
                              wordBreak: 'break-all',
                            }}
                          >
                            {rec.command}
                          </Text>
                        )}
                      </Stack>
                      <ActionIcon variant="subtle" color="cyan" size="sm">
                        <IconPlayerPlay size={14} />
                      </ActionIcon>
                    </Group>
                  </Paper>
                ))}
              </Stack>
              {recommendations.recommendations.length > 3 && (
                <Text size="xs" c="dimmed" ta="center" mt="xs">
                  +{recommendations.recommendations.length - 3} more suggestions
                </Text>
              )}
            </Box>
          )}

          {/* Show collapsed recommendations indicator */}
          {!showRecommendations && recommendations && recommendations.recommendations.length > 0 && (
            <UnstyledButton
              onClick={() => setShowRecommendations(true)}
              style={{
                width: '100%',
                padding: '6px 12px',
                background: '#1a1b1e',
                borderBottom: '1px solid #373A40',
              }}
            >
              <Group gap="xs">
                <IconSparkles size={12} color="#22b8cf" />
                <Text size="xs" c="cyan.4">
                  Show {recommendations.recommendations.length} recommendations
                </Text>
                <Badge size="xs" variant="light" color="cyan">
                  {getPhaseLabel(recommendations.phase)}
                </Badge>
              </Group>
            </UnstyledButton>
          )}

          {/* Next Steps Section - shown after executing an action with follow-ups */}
          {nextStepRecs.length > 0 && lastExecutedRec && (
            <Box p="xs" style={{ borderBottom: '1px solid #373A40', background: '#1f2125' }}>
              <Group justify="space-between" mb="xs">
                <Group gap="xs">
                  <ThemeIcon size="sm" variant="light" color="green" radius="sm">
                    <IconPlayerPlay size={12} />
                  </ThemeIcon>
                  <Text size="xs" fw={600} c="green.4">
                    NEXT STEPS
                  </Text>
                  <Badge size="xs" variant="outline" color="gray">
                    after {lastExecutedRec.label}
                  </Badge>
                </Group>
                <Tooltip label="Dismiss">
                  <ActionIcon
                    variant="subtle"
                    color="gray"
                    size="xs"
                    onClick={() => setLastExecutedRec(null)}
                  >
                    ×
                  </ActionIcon>
                </Tooltip>
              </Group>
              <Stack gap={4}>
                {nextStepRecs.map((rec) => (
                  <Paper
                    key={rec.id}
                    p="xs"
                    withBorder
                    style={{
                      background: '#25262b',
                      borderColor: '#2f9e44',
                      borderWidth: 1,
                      cursor: 'pointer',
                    }}
                    onClick={() => handleExecuteRecommendation(rec)}
                  >
                    <Group justify="space-between" wrap="nowrap">
                      <Stack gap={2} style={{ flex: 1, overflow: 'hidden' }}>
                        <Text size="xs" fw={500} truncate>
                          {rec.label}
                        </Text>
                        <Text size="xs" c="dimmed" truncate>
                          {rec.rationale}
                        </Text>
                      </Stack>
                      <ActionIcon variant="subtle" color="green" size="sm">
                        <IconPlayerPlay size={14} />
                      </ActionIcon>
                    </Group>
                  </Paper>
                ))}
              </Stack>
            </Box>
          )}

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
            {filteredModules.map((module) => (
              <ModuleAccordionItem
                key={module.id}
                module={module}
                expandedTools={expandedTools}
                onToolChange={(toolIds) => handleToolChange(module.id, toolIds)}
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

/** Module accordion item */
interface ModuleAccordionItemProps {
  module: CommandModule;
  expandedTools: string[];
  onToolChange: (toolIds: string[]) => void;
  onExecuteAction: (variant: CommandVariant) => void;
  verbose: boolean;
  targetIp?: string;
  targetHostname?: string;
}

function ModuleAccordionItem({
  module,
  expandedTools,
  onToolChange,
  onExecuteAction,
  verbose,
  targetIp,
  targetHostname,
}: ModuleAccordionItemProps) {
  const Icon = CATEGORY_ICONS[module.id] || IconBolt;

  return (
    <Accordion.Item value={module.id}>
      <Accordion.Control>
        <Group gap="xs">
          <ThemeIcon size="sm" variant="light" color="orange" radius="sm">
            <Icon size={12} />
          </ThemeIcon>
          <Text size="xs" fw={500}>
            {module.name}
          </Text>
          <Badge size="xs" variant="light" color="gray">
            {module.commandCount}
          </Badge>
        </Group>
      </Accordion.Control>
      <Accordion.Panel>
        <Stack gap={0}>
          {module.tools.map((tool) => (
            <ToolSection
              key={tool.id}
              tool={tool}
              categoryId={module.id}
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
  tool: CommandTool;
  categoryId: string;
  onExecuteAction: (variant: CommandVariant) => void;
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
  variant: CommandVariant;
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
