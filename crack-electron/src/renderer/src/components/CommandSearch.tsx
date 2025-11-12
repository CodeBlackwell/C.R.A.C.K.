import { useState, useEffect, useRef } from 'react';
import {
  TextInput,
  Paper,
  Table,
  ScrollArea,
  Badge,
  Text,
  Loader,
  Group,
  Divider,
} from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconSearch } from '@tabler/icons-react';
import NestedCategoryAccordion from './NestedCategoryAccordion';
import { CategoryHierarchy } from '../types/category';

interface CommandSearchProps {
  onSelectCommand: (commandId: string) => void;
}

interface SearchResult {
  id: string;
  name: string;
  category: string;
  description: string;
  tags: string[];
  oscp_relevance: boolean;
}

export default function CommandSearch({ onSelectCommand }: CommandSearchProps) {
  const [query, setQuery] = useState('');
  const [debouncedQuery] = useDebouncedValue(query, 300);
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [hierarchies, setHierarchies] = useState<CategoryHierarchy[]>([]);
  const [hierarchiesLoading, setHierarchiesLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedSubcategory, setSelectedSubcategory] = useState<string | null>(null);
  const selectedRowRef = useRef<HTMLTableRowElement>(null);

  // Debug: Log mount
  useEffect(() => {
    console.log('[CommandSearch] Component mounted');
  }, []);

  // Fetch category hierarchies on mount
  useEffect(() => {
    const fetchHierarchies = async () => {
      try {
        console.log('[CommandSearch] Fetching category hierarchies...');
        const data = await window.electronAPI.getCategoryHierarchy();
        console.log('[CommandSearch] Hierarchies received:', data.length, 'categories');
        setHierarchies(data);
      } catch (error) {
        console.error('[CommandSearch] Failed to fetch hierarchies:', error);
        setHierarchies([]);
      } finally {
        setHierarchiesLoading(false);
      }
    };

    fetchHierarchies();
  }, []);

  // Search commands with category/subcategory filters
  useEffect(() => {
    console.log('[CommandSearch] Search triggered:', {
      debouncedQuery,
      selectedCategory,
      selectedSubcategory,
    });

    const search = async () => {
      setLoading(true);
      try {
        const filters: any = {};

        // Only add filters if category/subcategory are selected
        if (selectedCategory) {
          filters.category = selectedCategory;
        }
        if (selectedSubcategory) {
          filters.subcategory = selectedSubcategory;
        }

        console.log('[CommandSearch] Calling searchCommands API with filters:', filters);
        const data = await window.electronAPI.searchCommands(
          debouncedQuery,
          filters
        );
        console.log('[CommandSearch] Search results received:', data.length, 'commands');
        setResults(data);
        // Reset selection to first result when results change
        setSelectedIndex(0);
      } catch (error) {
        console.error('[CommandSearch] Search error:', error);
        setResults([]);
      } finally {
        setLoading(false);
      }
    };

    search();
  }, [debouncedQuery, selectedCategory, selectedSubcategory]);

  // Auto-load selected command when navigating with keyboard
  useEffect(() => {
    if (results.length > 0 && selectedIndex >= 0 && selectedIndex < results.length) {
      const selectedCmd = results[selectedIndex];
      setSelectedId(selectedCmd.id);
      onSelectCommand(selectedCmd.id);

      // Scroll selected row into view
      if (selectedRowRef.current) {
        selectedRowRef.current.scrollIntoView({
          behavior: 'smooth',
          block: 'nearest',
        });
      }
    }
  }, [selectedIndex, results]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (results.length === 0) return;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((prev) => Math.min(prev + 1, results.length - 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((prev) => Math.max(prev - 1, 0));
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [results.length]);

  const handleRowClick = (index: number) => {
    console.log('[CommandSearch] Row clicked at index:', index);
    setSelectedIndex(index);
  };

  const handleCategorySelect = (category: string, subcategory: string) => {
    console.log('[CommandSearch] Category/subcategory selected:', { category, subcategory });

    // If clicking the same category/subcategory, deselect it
    if (selectedCategory === category && selectedSubcategory === subcategory) {
      console.log('[CommandSearch] Deselecting category');
      setSelectedCategory(null);
      setSelectedSubcategory(null);
    } else {
      setSelectedCategory(category);
      setSelectedSubcategory(subcategory);
    }
    setQuery(''); // Clear search when changing category
  };

  return (
    <Paper
      shadow="sm"
      p="md"
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
      }}
    >
      {/* Category Hierarchy Accordion */}
      <Text size="lg" fw={600} mb="sm">
        Categories
      </Text>
      <ScrollArea h={300} mb="md">
        <NestedCategoryAccordion
          hierarchies={hierarchies}
          selectedCategory={selectedCategory}
          selectedSubcategory={selectedSubcategory}
          onSelect={handleCategorySelect}
          loading={hierarchiesLoading}
        />
      </ScrollArea>

      <Divider mb="md" />

      {/* Search Section */}
      <Group mb="md" justify="space-between">
        <Text size="lg" fw={600}>
          Commands ({results.length})
        </Text>
        {selectedCategory && selectedSubcategory && (
          <Badge size="sm" variant="light" color="blue">
            {selectedCategory} → {selectedSubcategory}
          </Badge>
        )}
      </Group>

      <TextInput
        placeholder={
          selectedCategory && selectedSubcategory
            ? 'Search in selected category...'
            : 'Search all commands...'
        }
        value={query}
        onChange={(e) => setQuery(e.currentTarget.value)}
        leftSection={<IconSearch size={16} />}
        rightSection={loading ? <Loader size={16} /> : null}
        mb="md"
        styles={{
          input: {
            background: '#1a1b1e',
            border: '1px solid #373A40',
            '&:focus': {
              borderColor: '#22c1c3',
            },
          },
        }}
      />

      <ScrollArea style={{ flex: 1 }}>
        <Table
          highlightOnHover
          style={{
            fontSize: '13px',
          }}
        >
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Category</Table.Th>
              <Table.Th>Tags</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {results.map((cmd, index) => (
              <Table.Tr
                key={cmd.id}
                ref={selectedIndex === index ? selectedRowRef : null}
                onClick={() => handleRowClick(index)}
                style={{
                  cursor: 'pointer',
                  background:
                    selectedIndex === index ? '#2C2E33' : 'transparent',
                }}
              >
                <Table.Td>
                  <Group gap="xs">
                    <Text size="sm" fw={500} style={{ fontFamily: 'monospace' }}>
                      {cmd.name}
                    </Text>
                    {cmd.oscp_relevance && (
                      <Badge size="xs" color="teal" variant="light">
                        OSCP
                      </Badge>
                    )}
                  </Group>
                </Table.Td>
                <Table.Td>
                  <Text size="xs" c="dimmed">
                    {cmd.category}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    {cmd.tags?.slice(0, 2).map((tag) => (
                      <Badge
                        key={tag}
                        size="xs"
                        variant="dot"
                        color="gray"
                      >
                        {tag}
                      </Badge>
                    ))}
                    {cmd.tags?.length > 2 && (
                      <Text size="xs" c="dimmed">
                        +{cmd.tags.length - 2}
                      </Text>
                    )}
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>

        {results.length === 0 && !loading && (
          <Text ta="center" c="dimmed" mt="xl">
            {query
              ? 'No commands found'
              : selectedCategory && selectedSubcategory
              ? 'No commands in this category'
              : 'Select a category or start searching'}
          </Text>
        )}
      </ScrollArea>
    </Paper>
  );
}
