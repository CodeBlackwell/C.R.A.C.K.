import { useState, useEffect } from 'react';
import { Paper, Text, Code, Stack, Badge, Group, Divider, ScrollArea, Button } from '@mantine/core';
import { IconArrowLeft } from '@tabler/icons-react';
import { Command } from '../types/command';
import CommandChainGraph from './CommandChainGraph';

interface ChainCommandViewProps {
  commandId: string;
  chainName: string;
  stepNumber: number | null;
  onBack: () => void;
}

export default function ChainCommandView({ commandId, chainName, stepNumber, onBack }: ChainCommandViewProps) {
  const [command, setCommand] = useState<Command | null>(null);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'details' | 'graph'>('details');
  const [copiedRef, setCopiedRef] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

  useEffect(() => {
    console.log('[ChainCommandView] Loading command:', commandId);
    setLoading(true);

    window.electronAPI.getCommand(commandId)
      .then((cmd) => {
        console.log('[ChainCommandView] Command loaded:', cmd ? cmd.name : 'null');
        setCommand(cmd);
      })
      .catch((error) => {
        console.error('[ChainCommandView] Error loading command:', error);
        setCommand(null);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [commandId]);

  const copyToClipboard = async (text: string, type: 'ref' | 'cmd') => {
    try {
      await navigator.clipboard.writeText(text);
      console.log(`[ChainCommandView] Copied to clipboard: ${text.substring(0, 50)}...`);

      if (type === 'ref') {
        setCopiedRef(true);
        setTimeout(() => setCopiedRef(false), 2000);
      } else {
        setCopiedCmd(true);
        setTimeout(() => setCopiedCmd(false), 2000);
      }
    } catch (error) {
      console.error('[ChainCommandView] Failed to copy to clipboard:', error);
    }
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
        <Text c="dimmed" size="sm">Loading command...</Text>
      </Paper>
    );
  }

  if (!command) {
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
        <Text c="dimmed" size="sm">Command not found</Text>
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
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Breadcrumb with Back Button */}
      <Group gap="xs" mb="md" style={{ borderBottom: '1px solid #373A40', paddingBottom: '8px' }}>
        <Button
          size="xs"
          variant="subtle"
          color="gray"
          leftSection={<IconArrowLeft size={14} />}
          onClick={onBack}
        >
          Back
        </Button>
        <Text size="xs" c="dimmed">
          {chainName} {stepNumber !== null ? `→ Step ${stepNumber}` : ''} → {command.name}
        </Text>
      </Group>

      {/* View Mode Toggle */}
      <Group gap="xs" mb="md" style={{ borderBottom: '1px solid #373A40', paddingBottom: '8px' }}>
        <Button
          size="xs"
          variant={viewMode === 'details' ? 'filled' : 'subtle'}
          color="gray"
          onClick={() => {
            setViewMode('details');
            console.log('[ChainCommandView] View mode changed to: details');
          }}
        >
          Details
        </Button>
        <Button
          size="xs"
          variant={viewMode === 'graph' ? 'filled' : 'subtle'}
          color="gray"
          onClick={() => {
            setViewMode('graph');
            console.log('[ChainCommandView] View mode changed to: graph');
          }}
        >
          Graph View
        </Button>
      </Group>

      {/* Content Area */}
      {viewMode === 'details' ? (
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

                          <Text size="sm" c="dimmed" mb={flag.explanation || flag.example ? 'xs' : 0}>
                            {flag.description}
                          </Text>

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
                                  padding: '8px',
                                  border: '1px solid #373A40',
                                }}
                              >
                                {flag.example}
                              </Code>
                            </div>
                          )}
                        </Paper>
                      ))
                    ) : command.flag_explanations ? (
                      <Text
                        size="sm"
                        c="dimmed"
                        style={{
                          whiteSpace: 'pre-wrap',
                          background: '#1a1b1e',
                          padding: '12px',
                          border: '1px solid #373A40',
                          borderRadius: '4px',
                        }}
                      >
                        {command.flag_explanations}
                      </Text>
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
                            {variable.name}
                          </Code>
                        </Group>
                        <Text size="sm" c="dimmed" mb={variable.example ? 'xs' : 0}>
                          {variable.description}
                        </Text>
                        {variable.example && (
                          <Code
                            block
                            style={{
                              fontSize: '11px',
                              background: '#0d0e10',
                              padding: '8px',
                              marginTop: '8px',
                              border: '1px solid #373A40',
                            }}
                          >
                            {variable.example}
                          </Code>
                        )}
                      </Paper>
                    ))}
                  </Stack>
                </div>
              </>
            )}

            {/* Tags */}
            {command.tags && command.tags.length > 0 && (
              <>
                <Divider />
                <div>
                  <Text size="sm" fw={600} mb="xs">
                    Tags
                  </Text>
                  <Group gap="xs">
                    {command.tags.map((tag, idx) => (
                      <Badge key={idx} variant="light" color="gray" size="sm">
                        {tag}
                      </Badge>
                    ))}
                  </Group>
                </div>
              </>
            )}
          </Stack>
        </ScrollArea>
      ) : (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <CommandChainGraph commandId={command.id} />
        </div>
      )}
    </Paper>
  );
}
