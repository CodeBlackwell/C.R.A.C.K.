import { Paper, Text, Code, Stack, Badge, Group, Divider, ScrollArea } from '@mantine/core';
import { Command } from '../types/command';

interface CommandDetailsProps {
  command: Command;
}

export default function CommandDetails({ command }: CommandDetailsProps) {
  return (
    <Paper
      shadow="sm"
      p="md"
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        flex: 1,
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      <ScrollArea style={{ flex: 1 }}>
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
              Command
            </Text>
            <Code
              block
              style={{
                background: '#1a1b1e',
                fontSize: '12px',
                padding: '12px',
                border: '1px solid #373A40',
              }}
            >
              {command.command}
            </Code>
          </div>

          {/* Tags */}
          {command.tags && command.tags.length > 0 && (
            <>
              <Divider />
              <div>
                <Text size="sm" fw={600} mb="xs">
                  Tags
                </Text>
                <Group gap="xs">
                  {command.tags.map((tag) => (
                    <Badge key={tag} variant="light" color="gray" size="sm">
                      {tag}
                    </Badge>
                  ))}
                </Group>
              </div>
            </>
          )}

          {/* Flags */}
          {command.flags && command.flags.length > 0 && (
            <>
              <Divider />
              <div>
                <Text size="sm" fw={600} mb="xs">
                  Flags
                </Text>
                <Stack gap="xs">
                  {command.flags.map((flag, idx) => (
                    <div key={idx}>
                      <Group gap="xs">
                        <Code style={{ fontSize: '11px' }}>{flag.name}</Code>
                        {flag.required && (
                          <Badge size="xs" color="red" variant="light">
                            Required
                          </Badge>
                        )}
                      </Group>
                      <Text size="xs" c="dimmed" pl="md" mt={4}>
                        {flag.description}
                      </Text>
                    </div>
                  ))}
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

          {/* Indicators */}
          {command.indicators && command.indicators.length > 0 && (
            <>
              <Divider />
              <div>
                <Text size="sm" fw={600} mb="xs">
                  Output Indicators
                </Text>
                <Stack gap="xs">
                  {command.indicators.map((indicator, idx) => (
                    <div key={idx}>
                      <Group gap="xs">
                        <Badge
                          size="xs"
                          color={indicator.type === 'success' ? 'green' : 'red'}
                          variant="light"
                        >
                          {indicator.type}
                        </Badge>
                        <Code style={{ fontSize: '10px' }}>{indicator.pattern}</Code>
                      </Group>
                      {indicator.description && (
                        <Text size="xs" c="dimmed" pl="md" mt={4}>
                          {indicator.description}
                        </Text>
                      )}
                    </div>
                  ))}
                </Stack>
              </div>
            </>
          )}
        </Stack>
      </ScrollArea>
    </Paper>
  );
}
