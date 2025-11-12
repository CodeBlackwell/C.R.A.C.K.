import { Paper, Text, Stack, Accordion, Badge, Group, Divider, Code, ScrollArea } from '@mantine/core';
import { Cheatsheet } from '../types/cheatsheet';

interface CheatsheetDetailsProps {
  cheatsheet: Cheatsheet;
  onCommandClick?: (commandId: string) => void;
}

export default function CheatsheetDetails({ cheatsheet, onCommandClick }: CheatsheetDetailsProps) {
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
      <ScrollArea style={{ flex: 1 }}>
        <Stack gap="md">
          {/* Header */}
          <div>
            <Text size="xl" fw={700} mb="xs">
              {cheatsheet.name}
            </Text>
            <Text size="sm" c="dimmed" mb="md">
              {cheatsheet.description}
            </Text>
            <Group gap="xs">
              {cheatsheet.tags.map((tag) => (
                <Badge key={tag} size="sm" variant="light" color="cyan">
                  {tag}
                </Badge>
              ))}
            </Group>
          </div>

          <Divider />

          {/* Educational Header */}
          {cheatsheet.educational_header && (
            <>
              <div>
                <Text size="md" fw={600} mb="xs">
                  How to Recognize
                </Text>
                <Stack gap="xs">
                  {cheatsheet.educational_header.how_to_recognize.map((item, idx) => (
                    <Text key={idx} size="sm" c="dimmed">
                      • {item}
                    </Text>
                  ))}
                </Stack>
              </div>

              <div>
                <Text size="md" fw={600} mb="xs">
                  When to Look For
                </Text>
                <Stack gap="xs">
                  {cheatsheet.educational_header.when_to_look_for.map((item, idx) => (
                    <Text key={idx} size="sm" c="dimmed">
                      • {item}
                    </Text>
                  ))}
                </Stack>
              </div>

              <Divider />
            </>
          )}

          {/* Scenarios */}
          {cheatsheet.scenarios && cheatsheet.scenarios.length > 0 && (
            <div>
              <Text size="lg" fw={600} mb="md">
                Attack Scenarios
              </Text>
              <Accordion
                variant="separated"
                styles={{
                  item: {
                    background: '#1a1b1e',
                    border: '1px solid #373A40',
                    borderRadius: '8px',
                  },
                  control: {
                    padding: '14px 16px',
                    '&:hover': {
                      background: '#2C2E33',
                    },
                  },
                  content: {
                    padding: '0 16px 16px 16px',
                  },
                  chevron: {
                    color: '#22c1c3',
                  },
                }}
              >
                {cheatsheet.scenarios.map((scenario, idx) => (
                  <Accordion.Item key={idx} value={`scenario-${idx}`}>
                    <Accordion.Control>
                      <Group gap="xs">
                        <Badge size="sm" variant="filled" color="cyan">
                          {idx + 1}
                        </Badge>
                        <Text size="sm" fw={600}>
                          {scenario.title}
                        </Text>
                      </Group>
                    </Accordion.Control>
                    <Accordion.Panel>
                      <Stack gap="md">
                        <div>
                          <Text size="xs" fw={600} mb="xs" c="dimmed">
                            CONTEXT
                          </Text>
                          <Text size="sm">{scenario.context}</Text>
                        </div>

                        <div>
                          <Text size="xs" fw={600} mb="xs" c="dimmed">
                            APPROACH
                          </Text>
                          <Text size="sm">{scenario.approach}</Text>
                        </div>

                        {scenario.commands && scenario.commands.length > 0 && (
                          <div>
                            <Text size="xs" fw={600} mb="xs" c="dimmed">
                              COMMANDS
                            </Text>
                            <Group gap="xs">
                              {scenario.commands.map((cmdId) => (
                                <Badge
                                  key={cmdId}
                                  size="sm"
                                  variant="light"
                                  color="blue"
                                  style={{ cursor: onCommandClick ? 'pointer' : 'default' }}
                                  onClick={() => onCommandClick && onCommandClick(cmdId)}
                                >
                                  {cmdId}
                                </Badge>
                              ))}
                            </Group>
                          </div>
                        )}

                        <div>
                          <Text size="xs" fw={600} mb="xs" c="dimmed">
                            EXPECTED OUTCOME
                          </Text>
                          <Text size="sm">{scenario.expected_outcome}</Text>
                        </div>

                        <div>
                          <Text size="xs" fw={600} mb="xs" c="dimmed">
                            WHY THIS WORKS
                          </Text>
                          <Text size="sm">{scenario.why_this_works}</Text>
                        </div>
                      </Stack>
                    </Accordion.Panel>
                  </Accordion.Item>
                ))}
              </Accordion>
            </div>
          )}

          {/* Sections */}
          {cheatsheet.sections && cheatsheet.sections.length > 0 && (
            <div>
              <Text size="lg" fw={600} mb="md">
                Command Sections
              </Text>
              <Accordion
                variant="separated"
                styles={{
                  item: {
                    background: '#1a1b1e',
                    border: '1px solid #373A40',
                    borderRadius: '8px',
                  },
                  control: {
                    padding: '14px 16px',
                    '&:hover': {
                      background: '#2C2E33',
                    },
                  },
                  content: {
                    padding: '0 16px 16px 16px',
                  },
                  chevron: {
                    color: '#22c1c3',
                  },
                }}
              >
                {cheatsheet.sections.map((section, idx) => (
                  <Accordion.Item key={idx} value={`section-${idx}`}>
                    <Accordion.Control>
                      <Group gap="xs">
                        <Badge size="sm" variant="filled" color="green">
                          Phase {idx + 1}
                        </Badge>
                        <Text size="sm" fw={600}>
                          {section.title}
                        </Text>
                      </Group>
                    </Accordion.Control>
                    <Accordion.Panel>
                      <Stack gap="md">
                        {section.notes && (
                          <Text size="sm" c="dimmed">
                            {section.notes}
                          </Text>
                        )}
                        {section.commands && section.commands.length > 0 && (
                          <div>
                            <Text size="xs" fw={600} mb="xs" c="dimmed">
                              COMMANDS
                            </Text>
                            <Group gap="xs">
                              {section.commands.map((cmdId) => (
                                <Badge
                                  key={cmdId}
                                  size="sm"
                                  variant="light"
                                  color="green"
                                  style={{ cursor: onCommandClick ? 'pointer' : 'default' }}
                                  onClick={() => onCommandClick && onCommandClick(cmdId)}
                                >
                                  {cmdId}
                                </Badge>
                              ))}
                            </Group>
                          </div>
                        )}
                      </Stack>
                    </Accordion.Panel>
                  </Accordion.Item>
                ))}
              </Accordion>
            </div>
          )}
        </Stack>
      </ScrollArea>
    </Paper>
  );
}
