import { useState, useEffect, useRef, useMemo } from 'react';
import {
  TextInput,
  Paper,
  ScrollArea,
  Badge,
  Text,
  Loader,
  Group,
  Accordion,
  Stack,
  Box,
} from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconSearch } from '@tabler/icons-react';
import { CheatsheetListItem } from '../types/cheatsheet';
import { groupByCategory } from '../utils/categoryUtils';

interface CheatsheetViewProps {
  onSelectCheatsheet: (cheatsheetId: string) => void;
}

export default function CheatsheetView({ onSelectCheatsheet }: CheatsheetViewProps) {
  const [query, setQuery] = useState('');
  const [debouncedQuery] = useDebouncedValue(query, 300);
  const [results, setResults] = useState<CheatsheetListItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedItemRef = useRef<HTMLDivElement>(null);

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
        // Select first result if available
        if (data.length > 0 && !selectedId) {
          setSelectedId(data[0].id);
          onSelectCheatsheet(data[0].id);
        }
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
    if (selectedId) {
      onSelectCheatsheet(selectedId);

      // Scroll selected item into view
      if (selectedItemRef.current) {
        selectedItemRef.current.scrollIntoView({
          behavior: 'smooth',
          block: 'nearest',
        });
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  // Group results by category
  const categorizedResults = useMemo(() => {
    return groupByCategory(results);
  }, [results]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (results.length === 0) return;

      const currentIndex = results.findIndex((s) => s.id === selectedId);

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        const nextIndex = Math.min(currentIndex + 1, results.length - 1);
        setSelectedId(results[nextIndex].id);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        const prevIndex = Math.max(currentIndex - 1, 0);
        setSelectedId(results[prevIndex].id);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [results, selectedId]);

  const handleSheetClick = (sheetId: string) => {
    console.log('[CheatsheetView] Sheet clicked:', sheetId);
    setSelectedId(sheetId);
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
        {results.length === 0 && !loading && (
          <Text ta="center" c="dimmed" mt="xl">
            {query ? 'No cheatsheets found' : 'Loading cheatsheets...'}
          </Text>
        )}

        {categorizedResults.size > 0 && (
          <Accordion
            multiple
            variant="separated"
            styles={{
              item: {
                background: '#1a1b1e',
                border: '1px solid #373A40',
                borderRadius: '8px',
                marginBottom: '8px',
              },
              control: {
                padding: '8px 12px',
                '&:hover': {
                  background: '#2C2E33',
                },
              },
              content: {
                padding: '0',
              },
              chevron: {
                color: '#22c1c3',
              },
            }}
          >
            {Array.from(categorizedResults.entries()).map(([category, sheets]) => (
              <Accordion.Item key={category} value={category}>
                <Accordion.Control>
                  <Group gap="xs">
                    <Text size="sm" fw={600} c="cyan">
                      {category}
                    </Text>
                    <Badge size="sm" variant="light" color="gray">
                      {sheets.length}
                    </Badge>
                  </Group>
                </Accordion.Control>
                <Accordion.Panel>
                  <Stack gap={0}>
                    {sheets.map((sheet) => (
                      <Box
                        key={sheet.id}
                        ref={selectedId === sheet.id ? selectedItemRef : null}
                        onClick={() => handleSheetClick(sheet.id)}
                        style={{
                          padding: '8px 12px',
                          cursor: 'pointer',
                          background:
                            selectedId === sheet.id ? '#2C2E33' : 'transparent',
                          borderLeft:
                            selectedId === sheet.id
                              ? '3px solid #22c1c3'
                              : '3px solid transparent',
                        }}
                        onMouseEnter={(e) => {
                          if (selectedId !== sheet.id) {
                            e.currentTarget.style.background = '#25262b';
                          }
                        }}
                        onMouseLeave={(e) => {
                          if (selectedId !== sheet.id) {
                            e.currentTarget.style.background = 'transparent';
                          }
                        }}
                      >
                        <Text size="sm" fw={500} mb={4}>
                          {sheet.name}
                        </Text>
                        <Text size="xs" c="dimmed" lineClamp={2} mb={6}>
                          {sheet.description}
                        </Text>
                        <Group gap={4}>
                          {sheet.tags?.slice(0, 3).map((tag) => (
                            <Badge key={tag} size="xs" variant="dot" color="cyan">
                              {tag}
                            </Badge>
                          ))}
                          {sheet.tags?.length > 3 && (
                            <Text size="xs" c="dimmed">
                              +{sheet.tags.length - 3}
                            </Text>
                          )}
                        </Group>
                      </Box>
                    ))}
                  </Stack>
                </Accordion.Panel>
              </Accordion.Item>
            ))}
          </Accordion>
        )}
      </ScrollArea>
    </Paper>
  );
}
