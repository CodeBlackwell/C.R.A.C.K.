import { Paper, Text, Code, Stack, Badge, Group, Divider, ScrollArea, Button, Accordion } from '@mantine/core';
import { useState } from 'react';
import { Command } from '../types/command';

interface CommandDetailsProps {
  command: Command;
  viewMode: 'details' | 'graph' | 'tree';
  onViewModeChange: (mode: 'details' | 'graph' | 'tree') => void;
  onCommandSelect?: (commandId: string) => void;
  hideHeader?: boolean;
}

export default function CommandDetails({ command, viewMode, onViewModeChange, onCommandSelect, hideHeader }: CommandDetailsProps) {
  const [copiedRef, setCopiedRef] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [copiedExampleIdx, setCopiedExampleIdx] = useState<number | null>(null);

  const copyToClipboard = async (text: string, type: 'ref' | 'cmd' | 'example', exampleIdx?: number) => {
    try {
      await navigator.clipboard.writeText(text);
      console.log(`[CommandDetails] Copied to clipboard: ${text.substring(0, 50)}...`);

      if (type === 'ref') {
        setCopiedRef(true);
        setTimeout(() => setCopiedRef(false), 2000);
      } else if (type === 'cmd') {
        setCopiedCmd(true);
        setTimeout(() => setCopiedCmd(false), 2000);
      } else if (type === 'example' && exampleIdx !== undefined) {
        setCopiedExampleIdx(exampleIdx);
        setTimeout(() => setCopiedExampleIdx(null), 2000);
      }
    } catch (error) {
      console.error('[CommandDetails] Failed to copy to clipboard:', error);
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
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Navigation Bar - hidden when controlled by parent */}
      {!hideHeader && (
        <Group gap="xs" mb="md" style={{ borderBottom: '1px solid #373A40', paddingBottom: '8px' }}>
          <Button
            size="xs"
            variant={viewMode === 'details' ? 'filled' : 'subtle'}
            color="gray"
            onClick={() => {
              onViewModeChange('details');
              console.log('[CommandDetails] View mode changed to: details');
            }}
          >
            Details
          </Button>
          <Button
            size="xs"
            variant={viewMode === 'graph' ? 'filled' : 'subtle'}
            color="gray"
            onClick={() => {
              onViewModeChange('graph');
              console.log('[CommandDetails] View mode changed to: graph');
            }}
          >
            Graph View
          </Button>
        </Group>
      )}

      {/* Details View */}
      <ScrollArea
        style={{ flex: 1 }}
        type="auto"
        offsetScrollbars
        scrollbarSize={8}
      >
        <Stack gap="md">
            {/* Header */}
            <div>
              <Group gap="xs" mb="xs">
                <Text size="xl" fw={700} style={{ fontFamily: 'monospace' }}>
                  {command.name}
                </Text>
                {command.oscp_relevance && (
                  <Badge color="teal" variant="light">
                    OSCP
                  </Badge>
                )}
              </Group>
              <Text size="sm" c="dimmed">
                {command.category}
              </Text>
              <Code
                onClick={() => copyToClipboard(`crack reference ${command.id}`, 'ref')}
                style={{
                  fontSize: '10px',
                  background: copiedRef ? '#2b8a3e' : '#1a1b1e',
                  border: `1px solid ${copiedRef ? '#40c057' : '#373A40'}`,
                  padding: '4px 8px',
                  marginTop: '4px',
                  display: 'inline-block',
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                }}
              >
                crack reference {command.id} {copiedRef ? '✓ copied' : '(click to copy)'}
              </Code>
            </div>

            {/* Description */}
            {command.description && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Description
                  </Text>
                  <Text size="sm" c="dimmed">
                    {command.description}
                  </Text>
                </div>
              </>
            )}

            {/* Command */}
            <Divider />
            <div>
              <Text size="sm" fw={600} mb="xs">
                Command {copiedCmd ? <Text component="span" size="xs" c="green">✓ copied</Text> : <Text component="span" size="xs" c="dimmed">(click to copy)</Text>}
              </Text>
              <Code
                block
                onClick={() => copyToClipboard(command.command, 'cmd')}
                style={{
                  background: copiedCmd ? '#2b8a3e' : '#1a1b1e',
                  fontSize: '12px',
                  padding: '12px',
                  border: `1px solid ${copiedCmd ? '#40c057' : '#373A40'}`,
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                }}
              >
                {command.command}
              </Code>
            </div>

            {/* Examples */}
            {command.examples && command.examples.length > 0 && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Examples
                  </Text>
                  <Stack gap="md">
                    {command.examples.map((example, idx) => {
                      const isCopied = copiedExampleIdx === idx;
                      return (
                        <Paper
                          key={idx}
                          p="sm"
                          style={{
                            background: '#1a1b1e',
                            border: '1px solid #373A40',
                          }}
                        >
                          {example.context && (
                            <Badge size="xs" color="blue" variant="light" mb="xs">
                              {example.context}
                            </Badge>
                          )}
                          <Text size="sm" c="dimmed" mb="xs">
                            {example.description}
                          </Text>
                          <Code
                            block
                            onClick={() => copyToClipboard(example.command, 'example', idx)}
                            style={{
                              background: isCopied ? '#2b8a3e' : '#0d0e10',
                              fontSize: '11px',
                              padding: '8px',
                              border: `1px solid ${isCopied ? '#40c057' : '#2c2e33'}`,
                              cursor: 'pointer',
                              transition: 'all 0.2s ease',
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-all',
                            }}
                          >
                            {example.command} {isCopied && '✓'}
                          </Code>
                        </Paper>
                      );
                    })}
                  </Stack>
                </div>
              </>
            )}

            {/* Notes */}
            {command.notes && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Notes
                  </Text>
                  <ScrollArea
                    style={{
                      maxHeight: '250px',
                      border: '1px solid #373A40',
                      borderRadius: '4px',
                      padding: '8px',
                      background: '#1a1b1e',
                    }}
                    type="auto"
                    offsetScrollbars
                  >
                    <Text
                      size="sm"
                      c="dimmed"
                      style={{
                        whiteSpace: 'pre-wrap',
                        wordWrap: 'break-word',
                        overflowWrap: 'break-word',
                        maxWidth: '100%'
                      }}
                    >
                      {command.notes}
                    </Text>
                  </ScrollArea>
                </div>
              </>
            )}

            {/* Educational Content */}
            {command.educational && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Educational
                  </Text>
                  <Accordion
                    variant="separated"
                    styles={{
                      item: { backgroundColor: '#1a1b1e', border: '1px solid #373A40' },
                      control: { padding: '8px 12px' },
                      content: { padding: '0 12px 12px 12px' },
                    }}
                  >
                    {/* Purpose */}
                    {command.educational.purpose && (
                      <Accordion.Item value="purpose">
                        <Accordion.Control>
                          <Text size="sm" fw={500}>Purpose</Text>
                        </Accordion.Control>
                        <Accordion.Panel>
                          <Text size="sm" c="dimmed" style={{ whiteSpace: 'pre-wrap' }}>
                            {command.educational.purpose}
                          </Text>
                        </Accordion.Panel>
                      </Accordion.Item>
                    )}

                    {/* Manual Alternative */}
                    {command.educational.manual_alternative && (
                      <Accordion.Item value="manual">
                        <Accordion.Control>
                          <Text size="sm" fw={500}>Manual Alternative</Text>
                        </Accordion.Control>
                        <Accordion.Panel>
                          <Code
                            block
                            style={{
                              fontSize: '11px',
                              background: '#0d0e10',
                              padding: '8px',
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-all',
                            }}
                          >
                            {command.educational.manual_alternative}
                          </Code>
                        </Accordion.Panel>
                      </Accordion.Item>
                    )}

                    {/* When to Use */}
                    {command.educational.when_to_use && command.educational.when_to_use.length > 0 && (
                      <Accordion.Item value="when">
                        <Accordion.Control>
                          <Text size="sm" fw={500}>When to Use</Text>
                        </Accordion.Control>
                        <Accordion.Panel>
                          <Stack gap="xs">
                            {command.educational.when_to_use.map((use, idx) => (
                              <Text key={idx} size="sm" c="dimmed">• {use}</Text>
                            ))}
                          </Stack>
                        </Accordion.Panel>
                      </Accordion.Item>
                    )}

                    {/* Common Failures */}
                    {command.educational.common_failures && command.educational.common_failures.length > 0 && (
                      <Accordion.Item value="failures">
                        <Accordion.Control>
                          <Group gap="xs">
                            <Text size="sm" fw={500}>Common Failures</Text>
                            <Badge size="xs" color="red" variant="light">
                              {command.educational.common_failures.length}
                            </Badge>
                          </Group>
                        </Accordion.Control>
                        <Accordion.Panel>
                          <Stack gap="xs">
                            {command.educational.common_failures.map((failure, idx) => (
                              <Paper
                                key={idx}
                                p="xs"
                                style={{
                                  background: '#0d0e10',
                                  borderLeft: '2px solid #ff6b6b',
                                }}
                              >
                                <Text size="xs" c="dimmed">{failure}</Text>
                              </Paper>
                            ))}
                          </Stack>
                        </Accordion.Panel>
                      </Accordion.Item>
                    )}

                    {/* OSCP Info (Time Estimate & Exam Relevance) */}
                    {(command.educational.time_estimate || command.educational.exam_relevance) && (
                      <Accordion.Item value="oscp">
                        <Accordion.Control>
                          <Text size="sm" fw={500}>OSCP Info</Text>
                        </Accordion.Control>
                        <Accordion.Panel>
                          <Stack gap="sm">
                            {command.educational.time_estimate && (
                              <div>
                                <Text size="xs" c="dimmed" mb={4}>Time Estimate</Text>
                                <Badge color="cyan" variant="light" size="sm">
                                  {command.educational.time_estimate}
                                </Badge>
                              </div>
                            )}
                            {command.educational.exam_relevance && (
                              <div>
                                <Text size="xs" c="dimmed" mb={4}>Exam Relevance</Text>
                                <Text size="sm" c="cyan">{command.educational.exam_relevance}</Text>
                              </div>
                            )}
                          </Stack>
                        </Accordion.Panel>
                      </Accordion.Item>
                    )}

                    {/* Technical Notes */}
                    {command.educational.technical_notes && command.educational.technical_notes.length > 0 && (
                      <Accordion.Item value="technical">
                        <Accordion.Control>
                          <Text size="sm" fw={500}>Technical Notes</Text>
                        </Accordion.Control>
                        <Accordion.Panel>
                          <Stack gap="xs">
                            {command.educational.technical_notes.map((note, idx) => (
                              <Text key={idx} size="sm" c="dimmed">• {note}</Text>
                            ))}
                          </Stack>
                        </Accordion.Panel>
                      </Accordion.Item>
                    )}
                  </Accordion>
                </div>
              </>
            )}

            {/* Flags */}
            {((command.flags && command.flags.length > 0) || command.flag_explanations) && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Flags
                  </Text>
                  <Stack gap="md">
                    {command.flags && command.flags.length > 0 ? (
                      command.flags.map((flag, idx) => (
                        <Paper
                          key={idx}
                          p="sm"
                          style={{
                            background: '#1a1b1e',
                            border: '1px solid #373A40',
                          }}
                        >
                          <Group gap="xs" mb="xs">
                            <Code
                              style={{
                                fontSize: '12px',
                                fontWeight: 600,
                                background: '#25262b',
                                padding: '4px 8px',
                              }}
                            >
                              {flag.name}
                            </Code>
                            {flag.required && (
                              <Badge size="xs" color="red" variant="light">
                                Required
                              </Badge>
                            )}
                          </Group>

                          {/* Description */}
                          <Text size="sm" c="dimmed" mb={flag.explanation || flag.example ? 'xs' : 0}>
                            {flag.description}
                          </Text>

                          {/* Detailed Explanation */}
                          {flag.explanation && (
                            <Text
                              size="xs"
                              c="dimmed"
                              style={{
                                background: '#0d0e10',
                                padding: '8px',
                                borderRadius: '4px',
                                borderLeft: '2px solid #4c6ef5',
                                marginTop: '8px',
                              }}
                            >
                              <Text size="xs" fw={600} c="blue" mb={4}>
                                Explanation:
                              </Text>
                              {flag.explanation}
                            </Text>
                          )}

                          {/* Example */}
                          {flag.example && (
                            <div style={{ marginTop: '8px' }}>
                              <Text size="xs" fw={500} c="dimmed" mb={4}>
                                Example:
                              </Text>
                              <Code
                                block
                                style={{
                                  fontSize: '11px',
                                  background: '#0d0e10',
                                  padding: '6px 8px',
                                  border: '1px solid #2c2e33',
                                }}
                              >
                                {flag.example}
                              </Code>
                            </div>
                          )}
                        </Paper>
                      ))
                    ) : command.flag_explanations ? (
                      Object.entries(command.flag_explanations).map(([flagName, explanation]) => (
                        <Paper
                          key={flagName}
                          p="sm"
                          style={{
                            background: '#1a1b1e',
                            border: '1px solid #373A40',
                          }}
                        >
                          <Code
                            style={{
                              fontSize: '12px',
                              fontWeight: 600,
                              background: '#25262b',
                              padding: '4px 8px',
                              marginBottom: '8px',
                              display: 'inline-block',
                            }}
                          >
                            {flagName}
                          </Code>
                          <Text size="sm" c="dimmed">
                            {explanation}
                          </Text>
                        </Paper>
                      ))
                    ) : null}
                  </Stack>
                </div>
              </>
            )}

            {/* Variables */}
            {command.variables && command.variables.length > 0 && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Variables
                  </Text>
                  <Stack gap="xs">
                    {command.variables.map((variable, idx) => (
                      <div key={idx}>
                        <Code style={{ fontSize: '11px' }}>{variable.name}</Code>
                        <Text size="xs" c="dimmed" pl="md" mt={4}>
                          {variable.description}
                        </Text>
                        {variable.default_value && (
                          <Text size="xs" c="dimmed" pl="md" mt={2}>
                            Default: <Code style={{ fontSize: '10px', color: '#909296' }}>{variable.default_value}</Code>
                          </Text>
                        )}
                        {variable.example && (
                          <Text size="xs" c="dimmed" pl="md" mt={2}>
                            Example: <Code style={{ fontSize: '10px' }}>{variable.example}</Code>
                          </Text>
                        )}
                      </div>
                    ))}
                  </Stack>
                </div>
              </>
            )}

            {/* Indicators */}
            {command.indicators && command.indicators.length > 0 && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Output Indicators
                  </Text>
                  <Stack gap="xs">
                    {command.indicators.map((indicator, idx) => {
                      const isSuccess = indicator.type?.toLowerCase() === 'success';
                      const borderColor = isSuccess ? '#51cf66' : '#ff6b6b';

                      return (
                        <Paper
                          key={idx}
                          p="sm"
                          style={{
                            background: '#1a1b1e',
                            border: '1px solid #373A40',
                            borderLeft: `3px solid ${borderColor}`,
                          }}
                        >
                          <Code
                            style={{
                              fontSize: '11px',
                              fontFamily: 'monospace',
                              background: '#0d0e10',
                              padding: '4px 8px',
                              display: 'block',
                              marginBottom: indicator.description ? '8px' : 0,
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-all',
                            }}
                          >
                            {indicator.pattern}
                          </Code>
                          {indicator.description && (
                            <Text size="xs" c="dimmed">{indicator.description}</Text>
                          )}
                        </Paper>
                      );
                    })}
                  </Stack>
                </div>
              </>
            )}

            {/* Prerequisites */}
            {command.prerequisites && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Prerequisites
                  </Text>
                  <Paper
                    p="sm"
                    style={{
                      background: '#1a1b1e',
                      border: '1px solid #373A40',
                    }}
                  >
                    {Array.isArray(command.prerequisites) ? (
                      <Stack gap="xs">
                        {command.prerequisites.map((prereq, idx) => (
                          <Text key={idx} size="sm" c="dimmed">
                            • {prereq}
                          </Text>
                        ))}
                      </Stack>
                    ) : (
                      <Text size="sm" c="dimmed">
                        {command.prerequisites}
                      </Text>
                    )}
                  </Paper>
                </div>
              </>
            )}

            {/* Troubleshooting */}
            {command.troubleshooting && Object.keys(command.troubleshooting).length > 0 && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Troubleshooting
                  </Text>
                  <Stack gap="md">
                    {Object.entries(command.troubleshooting).map(([error, solution]) => (
                      <Paper
                        key={error}
                        p="sm"
                        style={{
                          background: '#1a1b1e',
                          border: '1px solid #373A40',
                          borderLeft: '3px solid #fa5252',
                        }}
                      >
                        <Text size="sm" fw={600} c="red" mb="xs">
                          {error}
                        </Text>
                        <Text size="sm" c="dimmed">
                          {solution}
                        </Text>
                      </Paper>
                    ))}
                  </Stack>
                </div>
              </>
            )}

            {/* Alternatives */}
            {command.alternatives && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Alternative Commands
                  </Text>
                  <Paper
                    p="sm"
                    style={{
                      background: '#1a1b1e',
                      border: '1px solid #373A40',
                      borderLeft: '3px solid #fab005',
                    }}
                  >
                    {Array.isArray(command.alternatives) ? (
                      <Stack gap="xs">
                        {command.alternatives.map((alt, idx) => (
                          <Code key={idx} style={{ fontSize: '11px' }}>
                            {alt}
                          </Code>
                        ))}
                      </Stack>
                    ) : (
                      <Code style={{ fontSize: '11px' }}>{command.alternatives}</Code>
                    )}
                  </Paper>
                </div>
              </>
            )}

            {/* Related Commands */}
            {command.related_commands && command.related_commands.length > 0 && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Related Commands
                  </Text>
                  <Paper
                    p="sm"
                    style={{
                      background: '#1a1b1e',
                      border: '1px solid #373A40',
                      borderLeft: '3px solid #4c6ef5',
                    }}
                  >
                    <Group gap="xs" wrap="wrap">
                      {command.related_commands.map((relatedId, idx) => (
                        <Badge
                          key={idx}
                          color="blue"
                          variant="light"
                          style={{
                            cursor: onCommandSelect ? 'pointer' : 'default',
                            transition: 'transform 0.1s ease',
                          }}
                          onClick={() => onCommandSelect && onCommandSelect(relatedId)}
                          onMouseEnter={(e) => {
                            if (onCommandSelect) {
                              (e.target as HTMLElement).style.transform = 'scale(1.05)';
                            }
                          }}
                          onMouseLeave={(e) => {
                            (e.target as HTMLElement).style.transform = 'scale(1)';
                          }}
                        >
                          {relatedId}
                        </Badge>
                      ))}
                    </Group>
                  </Paper>
                </div>
              </>
            )}

            {/* Next Steps */}
            {command.next_steps && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Next Steps
                  </Text>
                  <Paper
                    p="sm"
                    style={{
                      background: '#1a1b1e',
                      border: '1px solid #373A40',
                      borderLeft: '3px solid #51cf66',
                    }}
                  >
                    {Array.isArray(command.next_steps) ? (
                      <Stack gap="xs">
                        {command.next_steps.map((step, idx) => (
                          <Text key={idx} size="sm" c="dimmed">
                            {idx + 1}. {step}
                          </Text>
                        ))}
                      </Stack>
                    ) : (
                      <Text size="sm" c="dimmed">
                        {command.next_steps}
                      </Text>
                    )}
                  </Paper>
                </div>
              </>
            )}
          </Stack>
        </ScrollArea>
    </Paper>
  );
}
