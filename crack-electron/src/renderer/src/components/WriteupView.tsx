import { useState, useEffect, useRef, useMemo } from 'react';
import {
  TextInput,
  Paper,
  ScrollArea,
  Badge,
  Text,
  Loader,
  Group,
  Stack,
  Box,
  Accordion,
} from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconSearch } from '@tabler/icons-react';
import { WriteupListItem } from '../types/writeup';

interface WriteupViewProps {
  onSelectWriteup: (writeupId: string) => void;
}

export default function WriteupView({ onSelectWriteup }: WriteupViewProps) {
  const [query, setQuery] = useState('');
  const [debouncedQuery] = useDebouncedValue(query, 300);
  const [results, setResults] = useState<WriteupListItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedItemRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    console.log('[WriteupView] Component mounted');
  }, []);

  // Search writeups
  useEffect(() => {
    console.log('[WriteupView] Search triggered:', { debouncedQuery });

    const search = async () => {
      setLoading(true);
      try {
        console.log('[WriteupView] Calling searchWriteups API');
        const data = await window.electronAPI.searchWriteups(debouncedQuery);
        console.log('[WriteupView] Search results received:', data.length, 'writeups');
        setResults(data);
        // Select first result if available
        if (data.length > 0 && !selectedId) {
          setSelectedId(data[0].id);
          onSelectWriteup(data[0].id);
        }
      } catch (error) {
        console.error('[WriteupView] Search error:', error);
        setResults([]);
      } finally {
        setLoading(false);
      }
    };

    search();
  }, [debouncedQuery]);

  // Auto-load selected writeup
  useEffect(() => {
    if (selectedId) {
      onSelectWriteup(selectedId);

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

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (results.length === 0) return;

      const currentIndex = results.findIndex((w) => w.id === selectedId);

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

  const handleWriteupClick = (writeupId: string) => {
    console.log('[WriteupView] Writeup clicked:', writeupId);
    setSelectedId(writeupId);
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy': return 'green';
      case 'medium': return 'yellow';
      case 'hard': return 'orange';
      case 'insane': return 'red';
      default: return 'gray';
    }
  };

  const getOSCPRelevanceColor = (relevance: string) => {
    switch (relevance) {
      case 'high': return 'cyan';
      case 'medium': return 'blue';
      case 'low': return 'gray';
      default: return 'gray';
    }
  };

  // Group writeups by platform
  const groupedWriteups = useMemo(() => {
    const groups = new Map<string, WriteupListItem[]>();
    results.forEach(writeup => {
      const platform = writeup.platform || 'Other';
      if (!groups.has(platform)) {
        groups.set(platform, []);
      }
      groups.get(platform)!.push(writeup);
    });
    // Sort platforms alphabetically
    return new Map([...groups.entries()].sort((a, b) => a[0].localeCompare(b[0])));
  }, [results]);

  const formatDuration = (minutes: number): string => {
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
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
          Writeups ({results.length})
        </Text>
      </Group>

      <TextInput
        placeholder="Search writeups..."
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
            {query ? 'No writeups found' : 'Loading writeups...'}
          </Text>
        )}

        {groupedWriteups.size > 0 && (
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
            {Array.from(groupedWriteups.entries()).map(([platform, writeups]) => (
              <Accordion.Item key={platform} value={platform}>
                <Accordion.Control>
                  <Group gap="xs">
                    <Text size="sm" fw={600} c="cyan">
                      {platform}
                    </Text>
                    <Badge size="sm" variant="light" color="gray">
                      {writeups.length}
                    </Badge>
                  </Group>
                </Accordion.Control>
                <Accordion.Panel>
                  <Stack gap={0}>
                    {writeups.map((writeup) => (
                      <Box
                        key={writeup.id}
                        ref={selectedId === writeup.id ? selectedItemRef : null}
                        onClick={() => handleWriteupClick(writeup.id)}
                        style={{
                          padding: '8px 12px',
                          cursor: 'pointer',
                          background: selectedId === writeup.id ? '#2C2E33' : 'transparent',
                          borderLeft: selectedId === writeup.id
                            ? '3px solid #22c1c3'
                            : '3px solid transparent',
                        }}
                        onMouseEnter={(e) => {
                          if (selectedId !== writeup.id) {
                            e.currentTarget.style.background = '#25262b';
                          }
                        }}
                        onMouseLeave={(e) => {
                          if (selectedId !== writeup.id) {
                            e.currentTarget.style.background = 'transparent';
                          }
                        }}
                      >
                        <Text size="sm" fw={500} mb={4}>
                          {writeup.name}
                        </Text>
                        <Text size="xs" c="dimmed" mb={6}>
                          {writeup.machine_type} • {writeup.os}
                        </Text>
                        <Group gap={4}>
                          <Badge
                            size="xs"
                            variant="light"
                            color={getDifficultyColor(writeup.difficulty)}
                          >
                            {writeup.difficulty}
                          </Badge>
                          <Badge
                            size="xs"
                            variant="light"
                            color={getOSCPRelevanceColor(writeup.oscp_relevance)}
                          >
                            {writeup.oscp_relevance}
                          </Badge>
                          {writeup.total_duration_minutes && (
                            <Badge size="xs" variant="dot" color="gray">
                              {formatDuration(writeup.total_duration_minutes)}
                            </Badge>
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
