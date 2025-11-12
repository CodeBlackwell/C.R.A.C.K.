import { Paper, Text, Stack, Accordion, Badge, Group, Divider, Code, ScrollArea } from '@mantine/core';
import { useState } from 'react';
import { Cheatsheet } from '../types/cheatsheet';

interface CheatsheetDetailsProps {
  cheatsheet: Cheatsheet;
  onCommandClick?: (commandId: string) => void;
}

export default function CheatsheetDetails({ cheatsheet, onCommandClick }: CheatsheetDetailsProps) {
  const [copied, setCopied] = useState(false);

  // Derive source file path from cheatsheet ID
  const getSourcePath = (id: string): string => {
    const basePath = '/home/kali/Desktop/OSCP/crack/reference/data/cheatsheets';

    if (id.startsWith('ad-')) {
      return `${basePath}/active-directory/${id}.json`;
    } else if (id.startsWith('hash-') || id.includes('password') || id.includes('keepass') || id.includes('ssh-private-key')) {
      return `${basePath}/password-attacks/${id}.json`;
    } else if (id.startsWith('metasploit-')) {
      return `${basePath}/metasploit/${id}.json`;
    }

    // Default to root cheatsheets directory
    return `${basePath}/${id}.json`;
  };

  const sourcePath = getSourcePath(cheatsheet.id);

  const handleCopyPath = () => {
    navigator.clipboard.writeText(sourcePath);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
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
      <ScrollArea style={{ flex: 1 }}>
        <Stack gap="md">
          {/* Header */}
          <div>
            <Text size="xl" fw={700} mb="xs">
              {cheatsheet.name}
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
              {copied ? '✓ Copied to clipboard!' : `📄 ${sourcePath}`}
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
                      <Stack gap="xl">
                        <div>
                          <Text size="xs" fw={600} mb="xs" c="cyan">
                            CONTEXT
                          </Text>
                          <Text size="sm" style={{ whiteSpace: 'pre-line' }}>
                            {scenario.context}
                          </Text>
                        </div>

                        <div>
                          <Text size="xs" fw={600} mb="xs" c="yellow">
                            APPROACH
                          </Text>
                          <Text size="sm" style={{ whiteSpace: 'pre-line' }}>
                            {scenario.approach}
                          </Text>
                        </div>

                        {scenario.commands && scenario.commands.length > 0 && (
                          <div>
                            <Text size="xs" fw={600} mb="xs" c="blue">
                              COMMANDS
                            </Text>
                            <Group gap="xs">
                              {scenario.commands.map((cmdId) => (
                                <Badge
                                  key={cmdId}
                                  size="sm"
                                  variant="light"
                                  color="blue"
                                  style={{
                                    cursor: onCommandClick ? 'pointer' : 'default',
                                  }}
                                  onClick={() => onCommandClick?.(cmdId)}
                                >
                                  {cmdId}
                                </Badge>
                              ))}
                            </Group>
                          </div>
                        )}

                        <div>
                          <Text size="xs" fw={600} mb="xs" c="green">
                            EXPECTED OUTCOME
                          </Text>
                          <Text size="sm" style={{ whiteSpace: 'pre-line' }}>
                            {scenario.expected_outcome}
                          </Text>
                        </div>

                        <div>
                          <Text size="xs" fw={600} mb="xs" c="grape">
                            WHY THIS WORKS
                          </Text>
                          <Text size="sm" style={{ whiteSpace: 'pre-line' }}>
                            {scenario.why_this_works}
                          </Text>
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
                                  style={{
                                    cursor: onCommandClick ? 'pointer' : 'default',
                                  }}
                                  onClick={() => onCommandClick?.(cmdId)}
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
