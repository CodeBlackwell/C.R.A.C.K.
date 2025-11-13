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
  ScrollArea,
} from '@mantine/core';
import { AttackChain } from '../types/chain';

interface ChainDetailsProps {
  chainId: string | null;
  onCommandClick?: (commandId: string) => void;
}

export default function ChainDetails({
  chainId,
  onCommandClick,
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
        <Text size="xl" fw={700} mb="xs">
          {chain.name}
        </Text>

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
                <Group gap="xs" wrap="wrap">
                  <Badge size="sm" variant="filled" color="cyan">
                    Step {index + 1}
                  </Badge>
                  <Text size="sm" fw={600} style={{ flex: 1 }}>
                    {step.name || 'Unnamed Step'}
                  </Text>
                  {step.command && (
                    <Badge size="xs" variant="dot" color="green">
                      Command
                    </Badge>
                  )}
                  {step.repeatable && (
                    <Badge size="xs" variant="dot" color="blue">
                      Repeatable
                    </Badge>
                  )}
                </Group>
              </Accordion.Control>
              <Accordion.Panel>
                <Stack gap="md">
                  {/* Objective (always visible) */}
                  {step.objective && (
                    <Box>
                      <Text size="xs" fw={600} c="dimmed" mb={4}>
                        OBJECTIVE
                      </Text>
                      <Text size="sm" c="cyan" fw={500}>
                        {step.objective}
                      </Text>
                    </Box>
                  )}

                  {/* Description (always visible) */}
                  <Box>
                    <Text size="xs" fw={600} c="dimmed" mb={4}>
                      DESCRIPTION
                    </Text>
                    <Text size="xs" style={{ whiteSpace: 'pre-wrap' }}>
                      {step.description}
                    </Text>
                  </Box>

                  {/* Dependencies */}
                  {step.dependencies && step.dependencies.length > 0 && (
                    <Box>
                      <Text size="xs" fw={600} c="dimmed" mb={4}>
                        DEPENDENCIES
                      </Text>
                      <Group gap="xs">
                        {step.dependencies.map((dep, idx) => (
                          <Badge key={idx} size="sm" variant="light" color="orange">
                            {dep}
                          </Badge>
                        ))}
                      </Group>
                    </Box>
                  )}

                  {/* Success Criteria (collapsible) */}
                  {step.success_criteria && step.success_criteria.length > 0 && (
                    <Box>
                      <Accordion
                        variant="contained"
                        styles={{
                          item: {
                            background: '#0a0b0e',
                            border: '1px solid #373A40',
                          },
                          control: {
                            padding: '8px',
                          },
                        }}
                      >
                        <Accordion.Item value={`${step.id}-success`}>
                          <Accordion.Control>
                            <Group gap="xs">
                              <Text size="xs" fw={600} c="green">
                                SUCCESS CRITERIA
                              </Text>
                              <Badge size="xs" variant="filled" color="green">
                                {step.success_criteria.length}
                              </Badge>
                            </Group>
                          </Accordion.Control>
                          <Accordion.Panel>
                            <Stack gap="xs">
                              {step.success_criteria.map((criteria, idx) => (
                                <Text key={idx} size="xs" c="dimmed">
                                  ✓ {criteria}
                                </Text>
                              ))}
                            </Stack>
                          </Accordion.Panel>
                        </Accordion.Item>
                      </Accordion>
                    </Box>
                  )}

                  {/* Failure Conditions (collapsible) */}
                  {step.failure_conditions && step.failure_conditions.length > 0 && (
                    <Box>
                      <Accordion
                        variant="contained"
                        styles={{
                          item: {
                            background: '#0a0b0e',
                            border: '1px solid #373A40',
                          },
                          control: {
                            padding: '8px',
                          },
                        }}
                      >
                        <Accordion.Item value={`${step.id}-failure`}>
                          <Accordion.Control>
                            <Group gap="xs">
                              <Text size="xs" fw={600} c="red">
                                FAILURE CONDITIONS
                              </Text>
                              <Badge size="xs" variant="filled" color="red">
                                {step.failure_conditions.length}
                              </Badge>
                            </Group>
                          </Accordion.Control>
                          <Accordion.Panel>
                            <Stack gap="xs">
                              {step.failure_conditions.map((condition, idx) => (
                                <Text key={idx} size="xs" c="dimmed">
                                  ✗ {condition}
                                </Text>
                              ))}
                            </Stack>
                          </Accordion.Panel>
                        </Accordion.Item>
                      </Accordion>
                    </Box>
                  )}

                  {/* Evidence to Collect (collapsible) */}
                  {step.evidence && step.evidence.length > 0 && (
                    <Box>
                      <Accordion
                        variant="contained"
                        styles={{
                          item: {
                            background: '#0a0b0e',
                            border: '1px solid #373A40',
                          },
                          control: {
                            padding: '8px',
                          },
                        }}
                      >
                        <Accordion.Item value={`${step.id}-evidence`}>
                          <Accordion.Control>
                            <Group gap="xs">
                              <Text size="xs" fw={600} c="yellow">
                                EVIDENCE TO COLLECT
                              </Text>
                              <Badge size="xs" variant="filled" color="yellow">
                                {step.evidence.length}
                              </Badge>
                            </Group>
                          </Accordion.Control>
                          <Accordion.Panel>
                            <Stack gap="xs">
                              {step.evidence.map((item, idx) => (
                                <Text key={idx} size="xs" c="dimmed">
                                  • {item}
                                </Text>
                              ))}
                            </Stack>
                          </Accordion.Panel>
                        </Accordion.Item>
                      </Accordion>
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
