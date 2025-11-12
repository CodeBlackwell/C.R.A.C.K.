import { useState, useEffect } from 'react';
import { Paper, Text, ScrollArea, Accordion, Loader, Center, Stack, Badge, Group, Code, Divider } from '@mantine/core';
import { Cheatsheet } from '../types/cheatsheet';
import { Command } from '../types/command';

interface CheatsheetCommandListProps {
  cheatsheet: Cheatsheet;
}

export default function CheatsheetCommandList({ cheatsheet }: CheatsheetCommandListProps) {
  const [commands, setCommands] = useState<Command[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCommands = async () => {
      console.log('[CheatsheetCommandList] Fetching commands for cheatsheet:', cheatsheet.id);
      setLoading(true);

      // Extract all unique command IDs from scenarios and sections
      const commandIds = new Set<string>();

      // From scenarios
      cheatsheet.scenarios?.forEach((scenario) => {
        scenario.commands?.forEach((cmdId) => commandIds.add(cmdId));
      });

      // From sections
      cheatsheet.sections?.forEach((section) => {
        section.commands?.forEach((cmdId) => commandIds.add(cmdId));
      });

      console.log('[CheatsheetCommandList] Found command IDs:', Array.from(commandIds));

      // Fetch all commands
      const fetchedCommands: Command[] = [];
      for (const cmdId of commandIds) {
        try {
          const command = await window.electronAPI.getCommand(cmdId);
          if (command) {
            fetchedCommands.push(command);
          }
        } catch (error) {
          console.error(`[CheatsheetCommandList] Error fetching command ${cmdId}:`, error);
        }
      }

      console.log('[CheatsheetCommandList] Fetched commands:', fetchedCommands.length);
      setCommands(fetchedCommands);
      setLoading(false);
    };

    fetchCommands();
  }, [cheatsheet]);

  const handleCopyCommand = (command: string) => {
    navigator.clipboard.writeText(command);
  };

  if (loading) {
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
        <Center>
          <Stack align="center" gap="md">
            <Loader size="md" />
            <Text size="sm" c="dimmed">
              Loading commands...
            </Text>
          </Stack>
        </Center>
      </Paper>
    );
  }

  if (commands.length === 0) {
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
        <Text size="sm" c="dimmed">
          No commands found in this cheatsheet
        </Text>
      </Paper>
    );
  }

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
      <Text size="lg" fw={600} mb="md">
        Commands ({commands.length})
      </Text>

      <ScrollArea style={{ flex: 1 }}>
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
              padding: '12px 16px',
              '&:hover': {
                background: '#2C2E33',
              },
            },
            content: {
              padding: '16px',
            },
            chevron: {
              color: '#22c1c3',
            },
          }}
        >
          {commands.map((command) => (
            <Accordion.Item key={command.id} value={command.id}>
              <Accordion.Control>
                <Group gap="xs" justify="space-between" wrap="nowrap">
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <Text size="sm" fw={600} truncate>
                      {command.name}
                    </Text>
                    <Text size="xs" c="dimmed" truncate>
                      {command.id}
                    </Text>
                  </div>
                  {command.category && (
                    <Badge size="sm" variant="light" color="cyan">
                      {command.category}
                    </Badge>
                  )}
                </Group>
              </Accordion.Control>
              <Accordion.Panel>
                <Stack gap="md">
                  {/* Command */}
                  <div>
                    <Text size="xs" fw={600} mb="xs" c="dimmed">
                      COMMAND
                    </Text>
                    <Code
                      block
                      style={{
                        background: '#1a1b1e',
                        border: '1px solid #373A40',
                        padding: '12px',
                        cursor: 'pointer',
                        fontSize: '13px',
                      }}
                      onClick={() => handleCopyCommand(command.command)}
                      title="Click to copy"
                    >
                      {command.command}
                    </Code>
                  </div>

                  {/* Description */}
                  {command.description && (
                    <div>
                      <Text size="xs" fw={600} mb="xs" c="dimmed">
                        DESCRIPTION
                      </Text>
                      <Text size="sm">{command.description}</Text>
                    </div>
                  )}

                  {/* Flags */}
                  {command.flags && command.flags.length > 0 && (
                    <div>
                      <Text size="xs" fw={600} mb="xs" c="dimmed">
                        FLAGS ({command.flags.length})
                      </Text>
                      <Stack gap="xs">
                        {command.flags.slice(0, 5).map((flag, idx) => (
                          <div key={idx}>
                            <Code
                              style={{
                                background: '#1a1b1e',
                                padding: '4px 8px',
                                fontSize: '12px',
                              }}
                            >
                              {flag.flag}
                            </Code>
                            <Text size="xs" c="dimmed" ml="xs" component="span">
                              {flag.description}
                            </Text>
                          </div>
                        ))}
                        {command.flags.length > 5 && (
                          <Text size="xs" c="dimmed">
                            +{command.flags.length - 5} more flags
                          </Text>
                        )}
                      </Stack>
                    </div>
                  )}

                  {/* Variables */}
                  {command.variables && command.variables.length > 0 && (
                    <div>
                      <Text size="xs" fw={600} mb="xs" c="dimmed">
                        VARIABLES ({command.variables.length})
                      </Text>
                      <Group gap="xs">
                        {command.variables.slice(0, 5).map((variable, idx) => (
                          <Badge key={idx} size="sm" variant="light" color="blue">
                            {variable.name}
                          </Badge>
                        ))}
                        {command.variables.length > 5 && (
                          <Text size="xs" c="dimmed">
                            +{command.variables.length - 5} more
                          </Text>
                        )}
                      </Group>
                    </div>
                  )}

                  {/* Notes */}
                  {command.notes && (
                    <div>
                      <Text size="xs" fw={600} mb="xs" c="dimmed">
                        NOTES
                      </Text>
                      <Text size="sm" style={{ whiteSpace: 'pre-line' }}>
                        {command.notes}
                      </Text>
                    </div>
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
