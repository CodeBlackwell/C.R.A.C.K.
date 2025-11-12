import { useEffect, useState } from 'react';
import {
  Paper,
  Text,
  Badge,
  Accordion,
  Group,
  Stack,
  Box,
  Divider,
  Button,
  ScrollArea,
} from '@mantine/core';
import { IconListCheck, IconGraph } from '@tabler/icons-react';
import { AttackChain } from '../types/chain';

interface ChainDetailsProps {
  chainId: string | null;
  onCommandClick?: (commandId: string) => void;
  onToggleGraph?: () => void;
  showGraphView?: boolean;
}

export default function ChainDetails({
  chainId,
  onCommandClick,
  onToggleGraph,
  showGraphView = false,
}: ChainDetailsProps) {
  const [chain, setChain] = useState<AttackChain | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // Derive source file path from chain ID
  const getSourcePath = (id: string): string => {
    const basePath = '/home/kali/Desktop/OSCP/crack/reference/data/attack_chains';

    // Determine subdirectory based on chain ID prefix
    let subdirectory = '';
    if (id.startsWith('ad-')) {
      subdirectory = 'active_directory';
    } else if (id.startsWith('web-')) {
      subdirectory = 'enumeration';
    } else if (id.startsWith('windows-lateral-') || id.startsWith('linux-exploit-')) {
      subdirectory = 'lateral_movement';
    } else if (id.startsWith('linux-privesc-')) {
      subdirectory = 'privilege_escalation';
    }

    return `${basePath}/${subdirectory}/${id}.json`;
  };

  const handleCopyPath = () => {
    if (chain) {
      const sourcePath = getSourcePath(chain.id);
      navigator.clipboard.writeText(sourcePath);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  useEffect(() => {
    console.log('[ChainDetails] Component mounted');
  }, []);

  useEffect(() => {
    if (!chainId) {
      setChain(null);
      return;
    }

    const loadChain = async () => {
      setLoading(true);
      try {
        console.log('[ChainDetails] Loading chain:', chainId);
        const data = await window.electronAPI.getChain(chainId);
        console.log('[ChainDetails] Chain loaded:', data);
        setChain(data);
      } catch (error) {
        console.error('[ChainDetails] Error loading chain:', error);
        setChain(null);
      } finally {
        setLoading(false);
      }
    };

    loadChain();
  }, [chainId]);

  if (!chainId) {
    return (
      <Paper
        shadow="sm"
        p="md"
        style={{
          background: '#25262b',
          border: '1px solid #373A40',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Text c="dimmed" size="sm">
          Select an attack chain to view details
        </Text>
      </Paper>
    );
  }

  if (loading || !chain) {
    return (
      <Paper
        shadow="sm"
        p="md"
        style={{
          background: '#25262b',
          border: '1px solid #373A40',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Text c="dimmed" size="sm">
          Loading chain details...
        </Text>
      </Paper>
    );
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'green';
      case 'intermediate': return 'yellow';
      case 'advanced': return 'red';
      default: return 'gray';
    }
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
      {/* Header */}
      <Box mb="md">
        <Group justify="space-between" mb="xs">
          <Text size="xl" fw={700}>
            {chain.name}
          </Text>
          {onToggleGraph && (
            <Button
              variant="light"
              size="xs"
              leftSection={showGraphView ? <IconListCheck size={16} /> : <IconGraph size={16} />}
              onClick={onToggleGraph}
            >
              {showGraphView ? 'List View' : 'Graph View'}
            </Button>
          )}
        </Group>

        <Text
          size="xs"
          c="dimmed"
          mb="md"
          style={{
            cursor: 'pointer',
            fontFamily: 'monospace',
            userSelect: 'none',
          }}
          onClick={handleCopyPath}
          title="Click to copy path"
        >
          {copied ? '✓ Copied to clipboard!' : `📄 ${getSourcePath(chain.id)}`}
        </Text>

        <Group gap={6} mb="sm">
          <Badge
            size="sm"
            variant="light"
            color={getDifficultyColor(chain.difficulty)}
          >
            {chain.difficulty}
          </Badge>
          {(chain.oscp_relevant === true || chain.oscp_relevant === 'True') && (
            <Badge size="sm" variant="light" color="blue">
              OSCP
            </Badge>
          )}
          {chain.time_estimate && (
            <Badge size="sm" variant="dot" color="gray">
              {chain.time_estimate}
            </Badge>
          )}
        </Group>

        <Text size="sm" c="dimmed" mb="md">
          {chain.description}
        </Text>
      </Box>

      <Divider mb="md" color="#373A40" />

      {/* OSCP Notes Section */}
      {chain.notes && (
        <>
          <Box mb="md">
            <Text size="sm" fw={600} mb="xs" c="cyan">
              OSCP Notes
            </Text>
            <Paper
              p="sm"
              style={{
                background: '#1a1b1e',
                border: '1px solid #373A40',
              }}
            >
              <Text size="xs" c="dimmed" style={{ whiteSpace: 'pre-wrap' }}>
                {chain.notes}
              </Text>
            </Paper>
          </Box>
          <Divider mb="md" color="#373A40" />
        </>
      )}

      {/* Steps Section */}
      <ScrollArea style={{ flex: 1 }}>
        <Text size="sm" fw={600} mb="xs">
          Attack Steps ({chain.steps?.length || 0})
        </Text>

        <Accordion
          variant="separated"
          styles={{
            item: {
              background: '#1a1b1e',
              border: '1px solid #373A40',
              borderRadius: '8px',
              marginBottom: '8px',
            },
            control: {
              padding: '12px',
              '&:hover': {
                background: '#2C2E33',
              },
            },
            content: {
              padding: '12px',
            },
            chevron: {
              color: '#22c1c3',
            },
          }}
        >
          {chain.steps?.map((step, index) => (
            <Accordion.Item key={step.id || `step-${index}`} value={step.id || `step-${index}`}>
              <Accordion.Control>
                <Group gap="xs">
                  <Badge size="sm" variant="filled" color="cyan">
                    Step {index + 1}
                  </Badge>
                  {step.command && (
                    <Badge size="sm" variant="dot" color="green">
                      Has Command
                    </Badge>
                  )}
                </Group>
              </Accordion.Control>
              <Accordion.Panel>
                <Stack gap="sm">
                  {/* Step Description */}
                  <Box>
                    <Text size="xs" fw={600} c="dimmed" mb={4}>
                      DESCRIPTION
                    </Text>
                    <Text size="xs" style={{ whiteSpace: 'pre-wrap' }}>
                      {step.description}
                    </Text>
                  </Box>

                  {/* Expected Output */}
                  {step.expected_output && (
                    <Box>
                      <Text size="xs" fw={600} c="dimmed" mb={4}>
                        EXPECTED OUTPUT
                      </Text>
                      <Paper
                        p="xs"
                        style={{
                          background: '#0a0b0e',
                          border: '1px solid #373A40',
                        }}
                      >
                        <Text size="xs" c="green" style={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                          {step.expected_output}
                        </Text>
                      </Paper>
                    </Box>
                  )}

                  {/* Step Notes */}
                  {step.notes && (
                    <Box>
                      <Text size="xs" fw={600} c="dimmed" mb={4}>
                        NOTES
                      </Text>
                      <Text size="xs" c="yellow" style={{ whiteSpace: 'pre-wrap' }}>
                        {step.notes}
                      </Text>
                    </Box>
                  )}

                  {/* Command Reference */}
                  {step.command && onCommandClick && (
                    <Box>
                      <Text size="xs" fw={600} c="dimmed" mb={4}>
                        COMMAND REFERENCE
                      </Text>
                      <Badge
                        size="md"
                        variant="light"
                        color="cyan"
                        style={{ cursor: 'pointer' }}
                        onClick={() => onCommandClick(step.command!.id)}
                      >
                        {step.command.name}
                      </Badge>
                    </Box>
                  )}
                </Stack>
              </Accordion.Panel>
            </Accordion.Item>
          ))}
        </Accordion>
      </ScrollArea>
    </Paper>
  );
}
