/**
 * Module Store
 *
 * Zustand store for managing command modules with lazy loading from Neo4j.
 */

import { create } from 'zustand';
import type {
  ModuleMetadata,
  CommandModule,
  ModulePreferences,
  ServiceMatchMode,
  ModuleId,
} from '@shared/types/module-preferences';
import { SERVICE_MATCHERS } from '@shared/actions/service-mapping';
import {
  getModulePreferences,
  setModulePreferences,
  setServiceMatchMode as saveServiceMatchMode,
} from '../lib/storage';

/** Service info from target */
interface ServiceInfo {
  port: number;
  protocol?: string;
  service_name?: string;
}

interface ModuleState {
  // Available modules from Neo4j (metadata only)
  availableModules: ModuleMetadata[];

  // Loaded module data (lazy loaded)
  loadedModules: Map<string, CommandModule>;

  // User preferences (persisted to localStorage)
  preferences: ModulePreferences;

  // Loading state
  loadingModules: Set<string>;

  // Initialization state
  initialized: boolean;

  // Actions
  initialize: () => Promise<void>;
  fetchAvailableModules: () => Promise<void>;
  loadModule: (moduleId: string) => Promise<CommandModule | null>;
  loadModules: (moduleIds: string[]) => Promise<void>;
  toggleModuleEnabled: (moduleId: string) => void;
  toggleModulePinned: (moduleId: string) => void;
  setServiceMatchMode: (mode: ServiceMatchMode) => void;

  // Computed
  getEnabledModuleIds: () => string[];
  getVisibleModules: (services: ServiceInfo[]) => CommandModule[];
  isModuleLoading: (moduleId: string) => boolean;
}

/** Check if a service matches a module's service matcher */
function matchesService(
  service: ServiceInfo,
  moduleId: string
): boolean {
  const matcher = SERVICE_MATCHERS[moduleId];
  if (!matcher) return false;

  // Check port match
  if (matcher.ports?.includes(service.port)) {
    return true;
  }

  // Check service name match
  if (matcher.serviceNames && service.service_name) {
    const serviceLower = service.service_name.toLowerCase();
    if (matcher.serviceNames.some((name) => serviceLower.includes(name.toLowerCase()))) {
      return true;
    }
  }

  // Check protocol match
  if (matcher.protocols && service.protocol) {
    const proto = service.protocol.toLowerCase() as 'tcp' | 'udp';
    if (matcher.protocols.includes(proto)) {
      return true;
    }
  }

  return false;
}

export const useModuleStore = create<ModuleState>((set, get) => ({
  availableModules: [],
  loadedModules: new Map(),
  preferences: getModulePreferences(),
  loadingModules: new Set(),
  initialized: false,

  initialize: async () => {
    if (get().initialized) return;
    await get().fetchAvailableModules();

    // Auto-load pinned modules (especially port-scan)
    const { preferences } = get();
    const pinnedModules = preferences.modules.filter((m) => m.pinned && m.enabled);
    console.log('[moduleStore] Auto-loading pinned modules:', pinnedModules.map((m) => m.id));
    for (const mod of pinnedModules) {
      get().loadModule(mod.id); // Fire and forget - don't await
    }

    set({ initialized: true });
  },

  fetchAvailableModules: async () => {
    try {
      const modules = await window.electronAPI.modulesList();
      set({ availableModules: modules });
    } catch (error) {
      console.error('Failed to fetch available modules:', error);
    }
  },

  loadModule: async (moduleId: string) => {
    const { loadedModules, loadingModules } = get();

    // Already loaded
    if (loadedModules.has(moduleId)) {
      return loadedModules.get(moduleId)!;
    }

    // Already loading
    if (loadingModules.has(moduleId)) {
      return null;
    }

    // Start loading
    set((state) => ({
      loadingModules: new Set([...state.loadingModules, moduleId]),
    }));

    try {
      const module = await window.electronAPI.modulesLoad(moduleId);
      if (module) {
        set((state) => {
          const updated = new Map(state.loadedModules);
          updated.set(moduleId, module);
          return {
            loadedModules: updated,
            loadingModules: new Set(
              [...state.loadingModules].filter((id) => id !== moduleId)
            ),
          };
        });
        return module;
      }
    } catch (error) {
      console.error(`Failed to load module ${moduleId}:`, error);
    }

    // Remove from loading on failure
    set((state) => ({
      loadingModules: new Set(
        [...state.loadingModules].filter((id) => id !== moduleId)
      ),
    }));
    return null;
  },

  loadModules: async (moduleIds: string[]) => {
    const { loadedModules, loadingModules } = get();

    // Filter out already loaded/loading
    const toLoad = moduleIds.filter(
      (id) => !loadedModules.has(id) && !loadingModules.has(id)
    );

    if (toLoad.length === 0) return;

    // Mark all as loading
    set((state) => ({
      loadingModules: new Set([...state.loadingModules, ...toLoad]),
    }));

    try {
      const modules = await window.electronAPI.modulesLoadBatch(toLoad);
      set((state) => {
        const updated = new Map(state.loadedModules);
        for (const [id, module] of Object.entries(modules)) {
          updated.set(id, module);
        }
        return {
          loadedModules: updated,
          loadingModules: new Set(
            [...state.loadingModules].filter((id) => !toLoad.includes(id))
          ),
        };
      });
    } catch (error) {
      console.error('Failed to batch load modules:', error);
      set((state) => ({
        loadingModules: new Set(
          [...state.loadingModules].filter((id) => !toLoad.includes(id))
        ),
      }));
    }
  },

  toggleModuleEnabled: (moduleId: string) => {
    const { preferences } = get();
    const updated: ModulePreferences = {
      ...preferences,
      modules: preferences.modules.map((m) =>
        m.id === moduleId ? { ...m, enabled: !m.enabled } : m
      ),
    };
    setModulePreferences(updated);
    set({ preferences: updated });
  },

  toggleModulePinned: (moduleId: string) => {
    const { preferences } = get();
    const updated: ModulePreferences = {
      ...preferences,
      modules: preferences.modules.map((m) =>
        m.id === moduleId ? { ...m, pinned: !m.pinned } : m
      ),
    };
    setModulePreferences(updated);
    set({ preferences: updated });
  },

  setServiceMatchMode: (mode: ServiceMatchMode) => {
    const updated = saveServiceMatchMode(mode);
    set({ preferences: updated });
  },

  getEnabledModuleIds: () => {
    const { preferences } = get();
    return preferences.modules.filter((m) => m.enabled).map((m) => m.id);
  },

  getVisibleModules: (services: ServiceInfo[]) => {
    const { preferences, loadedModules } = get();
    const { serviceMatchMode } = preferences;

    // Get enabled module IDs
    const enabledModules = preferences.modules.filter((m) => m.enabled);

    if (serviceMatchMode === 'all_enabled') {
      // Show all enabled modules that are loaded
      return enabledModules
        .filter((m) => loadedModules.has(m.id))
        .map((m) => loadedModules.get(m.id)!);
    }

    // Relevant mode: filter by service matchers
    const pinnedIds = enabledModules.filter((m) => m.pinned).map((m) => m.id);

    const matchingIds = enabledModules
      .filter((m) => {
        // Always include pinned
        if (pinnedIds.includes(m.id)) return true;
        // Check if any service matches this module
        return services.some((svc) => matchesService(svc, m.id));
      })
      .map((m) => m.id);

    // Return loaded modules that match
    return [...new Set([...pinnedIds, ...matchingIds])]
      .filter((id) => loadedModules.has(id))
      .map((id) => loadedModules.get(id)!);
  },

  isModuleLoading: (moduleId: string) => {
    return get().loadingModules.has(moduleId);
  },
}));
