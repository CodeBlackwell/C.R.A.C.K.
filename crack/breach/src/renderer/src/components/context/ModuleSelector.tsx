/**
 * ModuleSelector Component
 *
 * Dropdown menu for selecting which command modules to display in ActionsPanel.
 * Supports enabling/disabling modules, pinning, and service match mode toggle.
 */

import { useEffect } from 'react';
import {
  Menu,
  ActionIcon,
  Checkbox,
  Switch,
  Divider,
  Text,
  Badge,
  Group,
  Stack,
  Loader,
  Tooltip,
} from '@mantine/core';
import {
  IconSettings,
  IconPin,
  IconPinFilled,
  IconRefresh,
} from '@tabler/icons-react';
import { useModuleStore } from '../../stores/moduleStore';
import { MODULE_GROUPS } from '@shared/types/module-preferences';

interface ModuleSelectorProps {
  onModuleToggle?: (moduleId: string, enabled: boolean) => void;
}

export function ModuleSelector({ onModuleToggle }: ModuleSelectorProps) {
  const {
    availableModules,
    preferences,
    loadingModules,
    initialized,
    initialize,
    fetchAvailableModules,
    loadModule,
    toggleModuleEnabled,
    toggleModulePinned,
    setServiceMatchMode,
  } = useModuleStore();

  // Initialize on mount
  useEffect(() => {
    initialize();
  }, [initialize]);

  const handleToggle = async (moduleId: string) => {
    const pref = preferences.modules.find((m) => m.id === moduleId);
    const willBeEnabled = !pref?.enabled;

    toggleModuleEnabled(moduleId);

    // Lazy load if enabling
    if (willBeEnabled) {
      await loadModule(moduleId);
    }

    onModuleToggle?.(moduleId, willBeEnabled);
  };

  const handlePinToggle = (e: React.MouseEvent, moduleId: string) => {
    e.stopPropagation();
    toggleModulePinned(moduleId);
  };

  const getModulePref = (moduleId: string) =>
    preferences.modules.find((m) => m.id === moduleId);

  const getModuleMeta = (moduleId: string) =>
    availableModules.find((m) => m.id === moduleId);

  const isLoading = (moduleId: string) => loadingModules.has(moduleId);

  // Count enabled modules
  const enabledCount = preferences.modules.filter((m) => m.enabled).length;
  const totalCount = preferences.modules.length;

  return (
    <Menu width={300} position="bottom-end" shadow="lg" withArrow>
      <Menu.Target>
        <Tooltip label="Configure modules" position="left">
          <ActionIcon variant="subtle" color="gray" size="sm">
            <IconSettings size={14} />
          </ActionIcon>
        </Tooltip>
      </Menu.Target>

      <Menu.Dropdown>
        {/* Header */}
        <Group justify="space-between" px="sm" py="xs">
          <Text size="xs" fw={600} c="dimmed">
            COMMAND MODULES
          </Text>
          <Group gap={4}>
            <Badge size="xs" variant="light" color="blue">
              {enabledCount}/{totalCount}
            </Badge>
            <Tooltip label="Refresh from Neo4j">
              <ActionIcon
                size="xs"
                variant="subtle"
                color="gray"
                onClick={() => fetchAvailableModules()}
              >
                <IconRefresh size={12} />
              </ActionIcon>
            </Tooltip>
          </Group>
        </Group>

        <Divider />

        {/* Service Match Mode Toggle */}
        <Stack gap={0} px="sm" py="xs">
          <Text size="xs" c="dimmed" mb={4}>
            Display Mode
          </Text>
          <Switch
            size="xs"
            label={
              preferences.serviceMatchMode === 'relevant'
                ? 'Show relevant to services'
                : 'Show all enabled modules'
            }
            checked={preferences.serviceMatchMode === 'all_enabled'}
            onChange={(e) =>
              setServiceMatchMode(
                e.currentTarget.checked ? 'all_enabled' : 'relevant'
              )
            }
          />
        </Stack>

        <Divider />

        {/* Loading state */}
        {!initialized && (
          <Group justify="center" py="md">
            <Loader size="sm" />
            <Text size="xs" c="dimmed">
              Loading modules...
            </Text>
          </Group>
        )}

        {/* Module Groups */}
        {initialized &&
          Object.entries(MODULE_GROUPS).map(([groupName, moduleIds]) => (
            <div key={groupName}>
              <Menu.Label>{groupName}</Menu.Label>
              {moduleIds.map((moduleId) => {
                const pref = getModulePref(moduleId);
                const meta = getModuleMeta(moduleId);
                const loading = isLoading(moduleId);

                return (
                  <Menu.Item
                    key={moduleId}
                    closeMenuOnClick={false}
                    onClick={() => handleToggle(moduleId)}
                    leftSection={
                      loading ? (
                        <Loader size={14} />
                      ) : (
                        <Checkbox
                          size="xs"
                          checked={pref?.enabled ?? true}
                          onChange={() => {}}
                          styles={{ input: { cursor: 'pointer' } }}
                        />
                      )
                    }
                    rightSection={
                      <Group gap={4}>
                        {meta && (
                          <Badge size="xs" variant="light" color="gray">
                            {meta.commandCount}
                          </Badge>
                        )}
                        <Tooltip
                          label={
                            pref?.pinned
                              ? 'Unpin (hide when no matching services)'
                              : 'Pin (always show)'
                          }
                          position="left"
                        >
                          <span
                            role="button"
                            tabIndex={0}
                            onClick={(e) => handlePinToggle(e, moduleId)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                handlePinToggle(e as unknown as React.MouseEvent, moduleId);
                              }
                            }}
                            style={{
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              width: 18,
                              height: 18,
                              borderRadius: 4,
                              color: pref?.pinned ? '#fab005' : '#868e96',
                            }}
                          >
                            {pref?.pinned ? (
                              <IconPinFilled size={12} />
                            ) : (
                              <IconPin size={12} />
                            )}
                          </span>
                        </Tooltip>
                      </Group>
                    }
                  >
                    <Text size="xs">{meta?.name || moduleId}</Text>
                  </Menu.Item>
                );
              })}
            </div>
          ))}

        <Divider />

        {/* Footer hint */}
        <Text size="xs" c="dimmed" px="sm" py="xs">
          Pinned modules always show. Others appear when matching services are
          detected.
        </Text>
      </Menu.Dropdown>
    </Menu>
  );
}
