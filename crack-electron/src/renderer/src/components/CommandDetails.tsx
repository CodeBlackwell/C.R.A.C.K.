import { Paper, Text, Code, Stack, Badge, Group, Divider, ScrollArea } from '@mantine/core';
import { useState } from 'react';
import { Command } from '../types/command';

interface CommandDetailsProps {
  command: Command;
}

export default function CommandDetails({ command }: CommandDetailsProps) {
  const [copiedRef, setCopiedRef] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const copyToClipboard = async (text: string, type: 'ref' | 'cmd') => {
    try {
      await navigator.clipboard.writeText(text);
      console.log(`[CommandDetails] Copied to clipboard: ${text.substring(0, 50)}...`);

      if (type === 'ref') {
        setCopiedRef(true);
        setTimeout(() => setCopiedRef(false), 2000);
      } else {
        setCopiedCmd(true);
        setTimeout(() => setCopiedCmd(false), 2000);
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
