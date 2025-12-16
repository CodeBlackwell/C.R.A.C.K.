/**
 * CommandSearchBar - Search and Filter Commands
 *
 * Search bar with filter options for the ActionsPanel.
 * Supports local (client-side) and global (Neo4j) search modes.
 */

import { useState, useRef, useEffect } from 'react';
import {
  TextInput,
  Group,
  ActionIcon,
  Tooltip,
  Badge,
  Collapse,
  Checkbox,
  Stack,
  Button,
  Loader,
} from '@mantine/core';
import {
  IconSearch,
  IconWorld,
  IconFilter,
  IconX,
  IconChevronDown,
  IconChevronUp,
} from '@tabler/icons-react';

/** Search filter options */
export interface SearchFilters {
  name: boolean;
  command: boolean;
  description: boolean;
  tags: boolean;
  oscpHigh: boolean;
}

/** Default filter state */
export const DEFAULT_FILTERS: SearchFilters = {
  name: true,
  command: true,
  description: true,
  tags: false,
  oscpHigh: false,
};

interface CommandSearchBarProps {
  query: string;
  onQueryChange: (query: string) => void;
  filters: SearchFilters;
  onFiltersChange: (filters: SearchFilters) => void;
  filterLogic: 'AND' | 'OR';
  onFilterLogicToggle: () => void;
  onGlobalSearch: () => void;
  isSearching: boolean;
  resultCount: number;
  totalCount: number;
}

export function CommandSearchBar({
  query,
  onQueryChange,
  filters,
  onFiltersChange,
  filterLogic,
  onFilterLogicToggle,
  onGlobalSearch,
  isSearching,
  resultCount,
  totalCount,
}: CommandSearchBarProps) {
  const [filtersExpanded, setFiltersExpanded] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Keyboard shortcut: Ctrl+F to focus search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault();
        inputRef.current?.focus();
      }
      if (e.key === 'Escape' && document.activeElement === inputRef.current) {
        onQueryChange('');
        inputRef.current?.blur();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onQueryChange]);

  // Handle filter checkbox change
  const handleFilterChange = (key: keyof SearchFilters) => {
    onFiltersChange({ ...filters, [key]: !filters[key] });
  };

  // Handle Enter key for global search
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && query.length >= 2) {
      onGlobalSearch();
    }
  };

  // Count active filters
  const activeFilterCount = Object.values(filters).filter(Boolean).length;

  return (
    <Stack gap={0} style={{ borderBottom: '1px solid #373A40' }}>
      {/* Main search row */}
      <Group gap="xs" p="xs" style={{ background: '#1a1b1e' }}>
        {/* Search input */}
        <TextInput
          ref={inputRef}
          size="xs"
          placeholder="Search commands... (Ctrl+F)"
          leftSection={<IconSearch size={14} />}
          rightSection={
            query ? (
              <ActionIcon
                size="xs"
                variant="subtle"
                color="gray"
                onClick={() => onQueryChange('')}
              >
                <IconX size={12} />
              </ActionIcon>
            ) : null
          }
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          onKeyDown={handleKeyDown}
          style={{ flex: 1 }}
          styles={{
            input: {
              background: '#25262b',
              border: '1px solid #373A40',
              fontSize: 11,
              '&:focus': {
                borderColor: '#f59f00',
              },
            },
          }}
        />

        {/* AND/OR toggle */}
        <Tooltip label={`Filter logic: ${filterLogic} (click to toggle)`}>
          <Button
            size="xs"
            variant={filterLogic === 'AND' ? 'filled' : 'light'}
            color={filterLogic === 'AND' ? 'orange' : 'gray'}
            onClick={onFilterLogicToggle}
            style={{ minWidth: 40, padding: '0 8px' }}
          >
            {filterLogic}
          </Button>
        </Tooltip>

        {/* Global search button */}
        <Tooltip label="Search all commands in database (Enter)">
          <ActionIcon
            size="sm"
            variant="light"
            color="blue"
            onClick={onGlobalSearch}
            disabled={query.length < 2 || isSearching}
            loading={isSearching}
          >
            <IconWorld size={14} />
          </ActionIcon>
        </Tooltip>

        {/* Filter toggle */}
        <Tooltip label={`Filters (${activeFilterCount} active)`}>
          <ActionIcon
            size="sm"
            variant={filtersExpanded ? 'filled' : 'subtle'}
            color={activeFilterCount > 0 ? 'orange' : 'gray'}
            onClick={() => setFiltersExpanded(!filtersExpanded)}
          >
            {filtersExpanded ? (
              <IconChevronUp size={14} />
            ) : (
              <IconFilter size={14} />
            )}
          </ActionIcon>
        </Tooltip>

        {/* Result count */}
        {query && (
          <Badge
            size="xs"
            variant="light"
            color={resultCount > 0 ? 'green' : 'red'}
          >
            {resultCount}/{totalCount}
          </Badge>
        )}
      </Group>

      {/* Filter checkboxes (collapsible) */}
      <Collapse in={filtersExpanded}>
        <Group
          gap="xs"
          p="xs"
          pt={4}
          style={{
            background: '#1a1b1e',
            borderTop: '1px solid #2c2e33',
          }}
        >
          <Checkbox
            size="xs"
            label="Name"
            checked={filters.name}
            onChange={() => handleFilterChange('name')}
            styles={{ label: { fontSize: 10, color: '#868e96' } }}
          />
          <Checkbox
            size="xs"
            label="Command"
            checked={filters.command}
            onChange={() => handleFilterChange('command')}
            styles={{ label: { fontSize: 10, color: '#868e96' } }}
          />
          <Checkbox
            size="xs"
            label="Description"
            checked={filters.description}
            onChange={() => handleFilterChange('description')}
            styles={{ label: { fontSize: 10, color: '#868e96' } }}
          />
          <Checkbox
            size="xs"
            label="Tags"
            checked={filters.tags}
            onChange={() => handleFilterChange('tags')}
            styles={{ label: { fontSize: 10, color: '#868e96' } }}
          />
          <Checkbox
            size="xs"
            label="OSCP:HIGH"
            checked={filters.oscpHigh}
            onChange={() => handleFilterChange('oscpHigh')}
            styles={{
              label: { fontSize: 10, color: filters.oscpHigh ? '#40c057' : '#868e96' },
            }}
          />
        </Group>
      </Collapse>
    </Stack>
  );
}
