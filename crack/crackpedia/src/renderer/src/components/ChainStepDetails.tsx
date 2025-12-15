import { useEffect, useState } from 'react';
import { Paper, Text, Badge, Group, Stack, Box, Divider, ScrollArea, Loader, Center, Accordion } from '@mantine/core';
import { AttackChain, ChainStep } from '../types/chain';

interface ChainStepDetailsProps {
  chainId: string;
  stepId: string;
  onCommandClick?: (commandId: string) => void;
}

export default function ChainStepDetails({
  chainId,
  stepId,
  onCommandClick,
}: ChainStepDetailsProps) {
  const [step, setStep] = useState<ChainStep | null>(null);
  const [stepNumber, setStepNumber] = useState<number>(0);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    console.log('[ChainStepDetails] Component mounted with:', { chainId, stepId });
  }, []);

  useEffect(() => {
    if (!chainId || !stepId) {
      setStep(null);
      return;
    }

    const loadStep = async () => {
      setLoading(true);
      try {
        console.log('[ChainStepDetails] Loading step:', stepId, 'from chain:', chainId);
        const chainData: AttackChain = await window.electronAPI.getChain(chainId);
        console.log('[ChainStepDetails] Chain loaded:', chainData);

        if (chainData && chainData.steps) {
          const foundStep = chainData.steps.find(s => s.id === stepId);
          const index = chainData.steps.findIndex(s => s.id === stepId);

          if (foundStep) {
            console.log('[ChainStepDetails] Step found:', foundStep);
            setStep(foundStep);
            setStepNumber(index + 1);
          } else {
            console.warn('[ChainStepDetails] Step not found:', stepId);
            setStep(null);
          }
        } else {
          console.warn('[ChainStepDetails] No steps in chain');
          setStep(null);
        }
      } catch (error) {
        console.error('[ChainStepDetails] Error loading step:', error);
        setStep(null);
      } finally {
        setLoading(false);
      }
    };

    loadStep();
  }, [chainId, stepId]);

  if (loading) {
    return (
      <Paper
        shadow="sm"
        style={{
          background: '#25262b',
          border: '1px solid #373A40',
          height: '100%',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Center>
          <Loader size="lg" />
        </Center>
      </Paper>
    );
  }

  if (!step) {
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
          Step not found
        </Text>
      </Paper>
    );
  }

  return (
    <Paper
      shadow="sm"
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
      <Box p="md" style={{ borderBottom: '1px solid #373A40' }}>
        <Group gap="xs" wrap="wrap" mb="xs">
          <Badge size="sm" variant="filled" color="cyan">
            Step {stepNumber}
          </Badge>
          <Text size="lg" fw={700} style={{ flex: 1 }}>
            {step.name || 'Unnamed Step'}
          </Text>
        </Group>
        <Group gap="xs">
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
          {step.dependencies && step.dependencies.length > 0 && (
            <Badge size="xs" variant="dot" color="orange">
              {step.dependencies.length} {step.dependencies.length === 1 ? 'Dependency' : 'Dependencies'}
            </Badge>
          )}
        </Group>
      </Box>

      {/* Scrollable Content */}
      <ScrollArea
        style={{ flex: 1 }}
        type="auto"
        offsetScrollbars
        scrollbarSize={8}
      >
        <Stack gap="md" p="md">
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

          <Divider color="#373A40" />

          {/* Dependencies */}
          {step.dependencies && step.dependencies.length > 0 && (
            <>
              <Box>
                <Text size="xs" fw={600} c="dimmed" mb={6}>
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
              <Divider color="#373A40" />
            </>
          )}

          {/* Success Criteria (collapsible) */}
          {step.success_criteria && step.success_criteria.length > 0 && (
            <Box>
              <Accordion
                variant="contained"
                styles={{
                  item: {
                    background: '#1a1b1e',
                    border: '1px solid #40c057',
                    borderLeft: '3px solid #40c057',
                  },
                  control: {
                    padding: '10px 12px',
                    '&:hover': {
                      background: '#2b2e33',
                    },
                  },
                  chevron: {
                    color: '#40c057',
                  },
                }}
              >
                <Accordion.Item value="success">
                  <Accordion.Control>
                    <Group gap="xs">
                      <Text size="sm" fw={600} c="green">
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
                    background: '#1a1b1e',
                    border: '1px solid #fa5252',
                    borderLeft: '3px solid #fa5252',
                  },
                  control: {
                    padding: '10px 12px',
                    '&:hover': {
                      background: '#2b2e33',
                    },
                  },
                  chevron: {
                    color: '#fa5252',
                  },
                }}
              >
                <Accordion.Item value="failure">
                  <Accordion.Control>
                    <Group gap="xs">
                      <Text size="sm" fw={600} c="red">
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
                    background: '#1a1b1e',
                    border: '1px solid #fab005',
                    borderLeft: '3px solid #fab005',
                  },
                  control: {
                    padding: '10px 12px',
                    '&:hover': {
                      background: '#2b2e33',
                    },
                  },
                  chevron: {
                    color: '#fab005',
                  },
                }}
              >
                <Accordion.Item value="evidence">
                  <Accordion.Control>
                    <Group gap="xs">
                      <Text size="sm" fw={600} c="yellow">
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

          <Divider color="#373A40" />

          {/* Command Reference */}
          {step.command && onCommandClick && (
            <Box>
              <Text size="xs" fw={600} c="dimmed" mb={6}>
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
      </ScrollArea>
    </Paper>
  );
}
