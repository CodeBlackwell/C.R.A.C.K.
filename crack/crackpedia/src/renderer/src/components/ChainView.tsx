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
import { AttackChain } from '../types/chain';

interface ChainViewProps {
  onSelectChain: (chainId: string) => void;
}

export default function ChainView({ onSelectChain }: ChainViewProps) {
  const [query, setQuery] = useState('');
  const [debouncedQuery] = useDebouncedValue(query, 300);
  const [results, setResults] = useState<AttackChain[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedItemRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    console.log('[ChainView] Component mounted');
  }, []);

  // Search attack chains
  useEffect(() => {
    console.log('[ChainView] Search triggered:', { debouncedQuery });

    const search = async () => {
      setLoading(true);
      try {
        console.log('[ChainView] Calling searchChains API');
        const data = await window.electronAPI.searchChains(debouncedQuery);
        console.log('[ChainView] Search results received:', data.length, 'chains');
        setResults(data);
        // Select first result if available
        if (data.length > 0 && !selectedId) {
          setSelectedId(data[0].id);
          onSelectChain(data[0].id);
        }
      } catch (error) {
        console.error('[ChainView] Search error:', error);
        setResults([]);
      } finally {
        setLoading(false);
      }
    };

    search();
  }, [debouncedQuery]);

  // Auto-load selected chain
  useEffect(() => {
    if (selectedId) {
      onSelectChain(selectedId);

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

      const currentIndex = results.findIndex((c) => c.id === selectedId);

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

  const handleChainClick = (chainId: string) => {
    console.log('[ChainView] Chain clicked:', chainId);
    setSelectedId(chainId);
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'green';
      case 'intermediate': return 'yellow';
      case 'advanced': return 'red';
      default: return 'gray';
    }
  };

  // Extract category from chain ID (e.g., "ad-password-spray-safe" -> "AD")
  // or "lateral-movement-smb" -> "Lateral Movement"
  const getCategoryFromId = (id: string): string => {
    const parts = id.split('-');
    if (parts.length === 0) return 'Other';

    // Get first part and format it
    const prefix = parts[0];

    // Common prefixes mapping
    const prefixMap: Record<string, string> = {
      'ad': 'Active Directory',
      'enum': 'Enumeration',
      'lateral': 'Lateral Movement',
      'priv': 'Privilege Escalation',
      'privesc': 'Privilege Escalation',
      'cred': 'Credential Access',
      'exploit': 'Exploitation',
      'web': 'Web Application',
    };

    return prefixMap[prefix.toLowerCase()] || prefix.toUpperCase();
  };

  // Group chains by category
  const groupedChains = useMemo(() => {
    const groups = new Map<string, AttackChain[]>();
    results.forEach(chain => {
      const category = getCategoryFromId(chain.id);
      if (!groups.has(category)) {
        groups.set(category, []);
      }
      groups.get(category)!.push(chain);
    });
    // Sort categories alphabetically
    return new Map([...groups.entries()].sort((a, b) => a[0].localeCompare(b[0])));
  }, [results]);

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
          Attack Chains ({results.length})
        </Text>
      </Group>

      <TextInput
        placeholder="Search attack chains..."
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
            {query ? 'No attack chains found' : 'Loading attack chains...'}
          </Text>
        )}

        {groupedChains.size > 0 && (
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
            {Array.from(groupedChains.entries()).map(([category, chains]) => (
              <Accordion.Item key={category} value={category}>
                <Accordion.Control>
                  <Group gap="xs">
                    <Text size="sm" fw={600} c="cyan">
                      {category}
                    </Text>
                    <Badge size="sm" variant="light" color="gray">
                      {chains.length}
                    </Badge>
                  </Group>
                </Accordion.Control>
                <Accordion.Panel>
                  <Stack gap={0}>
                    {chains.map((chain) => (
                      <Box
                        key={chain.id}
                        ref={selectedId === chain.id ? selectedItemRef : null}
                        onClick={() => handleChainClick(chain.id)}
                        style={{
                          padding: '8px 12px',
                          cursor: 'pointer',
                          background: selectedId === chain.id ? '#2C2E33' : 'transparent',
                          borderLeft: selectedId === chain.id
                            ? '3px solid #22c1c3'
                            : '3px solid transparent',
                        }}
                        onMouseEnter={(e) => {
                          if (selectedId !== chain.id) {
                            e.currentTarget.style.background = '#25262b';
                          }
                        }}
                        onMouseLeave={(e) => {
                          if (selectedId !== chain.id) {
                            e.currentTarget.style.background = 'transparent';
                          }
                        }}
                      >
                        <Text size="sm" fw={500} mb={4}>
                          {chain.name}
                        </Text>
                        <Text size="xs" c="dimmed" lineClamp={2} mb={6}>
                          {chain.description}
                        </Text>
                        <Group gap={4}>
                          <Badge
                            size="xs"
                            variant="light"
                            color={getDifficultyColor(chain.difficulty)}
                          >
                            {chain.difficulty}
                          </Badge>
                          {(chain.oscp_relevant === true || chain.oscp_relevant === 'True') && (
                            <Badge size="xs" variant="light" color="blue">
                              OSCP
                            </Badge>
                          )}
                          {chain.time_estimate && (
                            <Badge size="xs" variant="dot" color="gray">
                              {chain.time_estimate}
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
