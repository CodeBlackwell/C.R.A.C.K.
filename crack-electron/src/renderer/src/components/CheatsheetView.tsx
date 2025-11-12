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
} from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconSearch } from '@tabler/icons-react';
import { CheatsheetListItem } from '../types/cheatsheet';

interface CheatsheetViewProps {
  onSelectCheatsheet: (cheatsheetId: string) => void;
}

export default function CheatsheetView({ onSelectCheatsheet }: CheatsheetViewProps) {
  const [query, setQuery] = useState('');
  const [debouncedQuery] = useDebouncedValue(query, 300);
  const [results, setResults] = useState<CheatsheetListItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const selectedRowRef = useRef<HTMLTableRowElement>(null);

  useEffect(() => {
    console.log('[CheatsheetView] Component mounted');
  }, []);

  // Search cheatsheets
  useEffect(() => {
    console.log('[CheatsheetView] Search triggered:', { debouncedQuery });

    const search = async () => {
      setLoading(true);
      try {
        console.log('[CheatsheetView] Calling searchCheatsheets API');
        const data = await window.electronAPI.searchCheatsheets(debouncedQuery);
        console.log('[CheatsheetView] Search results received:', data.length, 'cheatsheets');
        setResults(data);
        setSelectedIndex(0);
      } catch (error) {
        console.error('[CheatsheetView] Search error:', error);
        setResults([]);
      } finally {
        setLoading(false);
      }
    };

    search();
  }, [debouncedQuery]);

  // Auto-load selected cheatsheet
  useEffect(() => {
    if (results.length > 0 && selectedIndex >= 0 && selectedIndex < results.length) {
      const selectedSheet = results[selectedIndex];
      setSelectedId(selectedSheet.id);
      onSelectCheatsheet(selectedSheet.id);

      // Scroll selected row into view
      if (selectedRowRef.current) {
        selectedRowRef.current.scrollIntoView({
          behavior: 'smooth',
          block: 'nearest',
        });
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    console.log('[CheatsheetView] Row clicked at index:', index);
    setSelectedIndex(index);
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
      <Group mb="md" justify="space-between">
        <Text size="lg" fw={600}>
          Cheatsheets ({results.length})
        </Text>
      </Group>

      <TextInput
        placeholder="Search cheatsheets..."
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
              <Table.Th>Tags</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {results.map((sheet, index) => (
              <Table.Tr
                key={sheet.id}
                ref={selectedIndex === index ? selectedRowRef : null}
                onClick={() => handleRowClick(index)}
                style={{
                  cursor: 'pointer',
                  background:
                    selectedIndex === index ? '#2C2E33' : 'transparent',
                }}
              >
                <Table.Td>
                  <Text size="sm" fw={500}>
                    {sheet.name}
                  </Text>
                  <Text size="xs" c="dimmed" lineClamp={1}>
                    {sheet.description}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    {sheet.tags?.slice(0, 2).map((tag) => (
                      <Badge
                        key={tag}
                        size="xs"
                        variant="dot"
                        color="cyan"
                      >
                        {tag}
                      </Badge>
                    ))}
                    {sheet.tags?.length > 2 && (
                      <Text size="xs" c="dimmed">
                        +{sheet.tags.length - 2}
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
              ? 'No cheatsheets found'
              : 'Start searching for cheatsheets'}
          </Text>
        )}
      </ScrollArea>
    </Paper>
  );
}
