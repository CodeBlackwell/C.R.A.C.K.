import { useEffect, useState } from 'react';
import {
  Paper,
  Text,
  Badge,
  Group,
  Box,
  Divider,
  ScrollArea,
  Tabs,
  Accordion,
  Stack,
  Code,
} from '@mantine/core';
import {
  Writeup,
  AttackPhase,
  CommandUsed,
  FailedAttempt,
  Vulnerability,
} from '../types/writeup';

interface WriteupDetailsProps {
  writeupId: string | null;
}

export default function WriteupDetails({ writeupId }: WriteupDetailsProps) {
  const [writeup, setWriteup] = useState<Writeup | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    console.log('[WriteupDetails] Component mounted');
  }, []);

  useEffect(() => {
    if (!writeupId) {
      setWriteup(null);
      return;
    }

    const loadWriteup = async () => {
      setLoading(true);
      try {
        console.log('[WriteupDetails] Loading writeup:', writeupId);
        const data = await window.electronAPI.getWriteup(writeupId);
        console.log('[WriteupDetails] Writeup loaded:', data);
        setWriteup(data);
      } catch (error) {
        console.error('[WriteupDetails] Error loading writeup:', error);
        setWriteup(null);
      } finally {
        setLoading(false);
      }
    };

    loadWriteup();
  }, [writeupId]);

  if (!writeupId) {
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
          Select a writeup to view details
        </Text>
      </Paper>
    );
  }

  if (loading || !writeup) {
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
          Loading writeup details...
        </Text>
      </Paper>
    );
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy': return 'green';
      case 'medium': return 'yellow';
      case 'hard': return 'orange';
      case 'insane': return 'red';
      default: return 'gray';
    }
  };

  const getOSCPRelevanceColor = (relevance: string) => {
    switch (relevance) {
      case 'high': return 'cyan';
      case 'medium': return 'blue';
      case 'low': return 'gray';
      default: return 'gray';
    }
  };

  const formatDuration = (minutes: number): string => {
    if (minutes < 60) return `${minutes} minutes`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return mins > 0 ? `${hours}h ${mins}m` : `${hours} hours`;
  };

  // Extract values with proper fallbacks for nested structure
  const difficulty = writeup.metadata?.difficulty || 'unknown';
  const oscpScore = writeup.oscp_relevance?.score || 'low';
  const examApplicable = writeup.oscp_relevance?.exam_applicable || false;
  const platform = writeup.source?.platform || 'unknown';
  const oscpReasoning = writeup.oscp_relevance?.reasoning || '';
  const machineType = writeup.source?.type || 'unknown';
  const os = writeup.metadata?.os || 'unknown';
  const ipAddress = writeup.metadata?.ip_address || '';
  const totalDurationMinutes = writeup.time_breakdown?.total_minutes || 0;
  const author = writeup.metadata?.writeup_author || writeup.metadata?.machine_author || '';
  const releaseDate = writeup.source?.release_date || '';
  const retirementDate = writeup.source?.retire_date || '';
  const rating = writeup.metadata?.rating;

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
          {writeup.name}
        </Text>

        <Group gap={6} mb="sm">
          <Badge
            size="sm"
            variant="light"
            color={getDifficultyColor(difficulty)}
          >
            {difficulty}
          </Badge>
          <Badge
            size="sm"
            variant="light"
            color={getOSCPRelevanceColor(oscpScore)}
          >
            OSCP: {oscpScore}
          </Badge>
          {examApplicable && (
            <Badge size="sm" variant="filled" color="cyan">
              Exam Applicable
            </Badge>
          )}
          <Badge size="sm" variant="dot" color="gray">
            {platform}
          </Badge>
        </Group>
      </Box>

      <Divider mb="md" color="#373A40" />

      {/* Tabbed Content */}
      <Tabs
        defaultValue="overview"
        variant="pills"
        styles={{
          root: {
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
          },
          list: {
            marginBottom: '12px',
          },
          panel: {
            flex: 1,
            overflow: 'hidden',
          },
          tab: {
            color: '#909296',
            '&[data-active]': {
              backgroundColor: '#373A40',
              color: '#22c1c3',
            },
            '&:hover': {
              backgroundColor: '#2C2E33',
            },
          },
        }}
      >
        <Tabs.List>
          <Tabs.Tab value="overview">Overview</Tabs.Tab>
          <Tabs.Tab value="attack-phases">Attack Phases</Tabs.Tab>
          <Tabs.Tab value="skills-learnings">Skills & Learnings</Tabs.Tab>
          <Tabs.Tab value="metadata">Metadata</Tabs.Tab>
        </Tabs.List>

        {/* Overview Tab */}
        <Tabs.Panel value="overview">
          <ScrollArea style={{ height: '100%' }}>
            {/* Synopsis */}
            {writeup.synopsis && (
              <Box mb="md">
                <Text size="sm" fw={600} mb="xs" c="cyan">
                  Synopsis
                </Text>
                <Paper
                  p="sm"
                  style={{
                    background: '#1a1b1e',
                    border: '1px solid #373A40',
                  }}
                >
                  <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>
                    {writeup.synopsis}
                  </Text>
                </Paper>
              </Box>
            )}

            {/* OSCP Reasoning */}
            {oscpReasoning && (
              <Box mb="md">
                <Text size="sm" fw={600} mb="xs" c="cyan">
                  OSCP Relevance Reasoning
                </Text>
                <Paper
                  p="sm"
                  style={{
                    background: '#1a1b1e',
                    border: '1px solid #373A40',
                  }}
                >
                  <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>
                    {oscpReasoning}
                  </Text>
                </Paper>
              </Box>
            )}

            {/* Tags */}
            {writeup.tags && writeup.tags.length > 0 && (
              <Box mb="md">
                <Text size="sm" fw={600} mb="xs" c="cyan">
                  Tags
                </Text>
                <Group gap="xs">
                  {writeup.tags.map((tag, idx) => (
                    <Badge key={idx} size="sm" variant="light" color="gray">
                      {tag}
                    </Badge>
                  ))}
                </Group>
              </Box>
            )}
          </ScrollArea>
        </Tabs.Panel>

        {/* Attack Phases Tab */}
        <Tabs.Panel value="attack-phases">
          <ScrollArea style={{ height: '100%' }}>
            {writeup.attack_phases && Array.isArray(writeup.attack_phases) && writeup.attack_phases.length > 0 ? (
              <Accordion
                variant="contained"
                styles={{
                  item: {
                    background: '#1a1b1e',
                    border: '1px solid #373A40',
                    marginBottom: '8px',
                  },
                  control: {
                    '&:hover': {
                      background: '#25262b',
                    },
                  },
                  label: {
                    color: '#22c1c3',
                    fontWeight: 600,
                  },
                }}
              >
                {writeup.attack_phases.map((phase: AttackPhase, phaseIdx: number) => (
                  <Accordion.Item key={phaseIdx} value={`phase-${phaseIdx}`}>
                    <Accordion.Control>
                      <Group justify="space-between">
                        <Text size="sm" fw={600} tt="capitalize">
                          {phase.phase.replace(/_/g, ' ')}
                        </Text>
                        <Badge size="sm" variant="light" color="gray">
                          {phase.duration_minutes}m
                        </Badge>
                      </Group>
                    </Accordion.Control>
                    <Accordion.Panel>
                      <Stack gap="md">
                        {/* Phase Description */}
                        {phase.description && (
                          <Box>
                            <Text size="xs" c="dimmed" mb={4}>
                              Description
                            </Text>
                            <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>
                              {phase.description}
                            </Text>
                          </Box>
                        )}

                        <Divider color="#373A40" />

                        {/* Commands Used */}
                        {phase.commands_used && phase.commands_used.length > 0 && (
                          <Box>
                            <Text size="xs" fw={600} mb="xs" c="cyan">
                              Commands Executed ({phase.commands_used.length})
                            </Text>
                            <Accordion
                              variant="separated"
                              styles={{
                                item: {
                                  background: '#25262b',
                                  border: '1px solid #373A40',
                                },
                                label: {
                                  fontSize: '12px',
                                },
                              }}
                            >
                              {phase.commands_used.map((cmd: CommandUsed, cmdIdx: number) => (
                                <Accordion.Item key={cmdIdx} value={`cmd-${phaseIdx}-${cmdIdx}`}>
                                  <Accordion.Control>
                                    <Group gap="xs">
                                      <Badge size="xs" variant="filled" color={cmd.success ? 'green' : 'red'}>
                                        Step {cmd.step_number}
                                      </Badge>
                                      <Badge
                                        size="xs"
                                        variant="light"
                                        color="cyan"
                                        style={{ cursor: 'pointer' }}
                                        title="Click to view command reference"
                                      >
                                        {cmd.command_id}
                                      </Badge>
                                      <Text size="xs" lineClamp={1}>
                                        {cmd.context}
                                      </Text>
                                    </Group>
                                  </Accordion.Control>
                                  <Accordion.Panel>
                                    <Stack gap="xs">
                                      {cmd.command_executed && (
                                        <Box>
                                          <Text size="xs" c="dimmed" mb={4}>
                                            Command
                                          </Text>
                                          <Code block style={{ fontSize: '11px' }}>
                                            {cmd.command_executed}
                                          </Code>
                                        </Box>
                                      )}

                                      {cmd.output_snippet && (
                                        <Box>
                                          <Text size="xs" c="dimmed" mb={4}>
                                            Output
                                          </Text>
                                          <Code block style={{ fontSize: '11px', background: '#1a1b1e' }}>
                                            {cmd.output_snippet}
                                          </Code>
                                        </Box>
                                      )}

                                      {cmd.notes && (
                                        <Box>
                                          <Text size="xs" c="dimmed" mb={4}>
                                            Notes
                                          </Text>
                                          <Text size="xs" style={{ whiteSpace: 'pre-wrap' }}>
                                            {cmd.notes}
                                          </Text>
                                        </Box>
                                      )}

                                      {cmd.flags_used && Object.keys(cmd.flags_used).length > 0 && (
                                        <Box>
                                          <Text size="xs" c="dimmed" mb={4}>
                                            Flags Explained
                                          </Text>
                                          <Stack gap={4}>
                                            {Object.entries(cmd.flags_used).map(([flag, explanation]) => (
                                              <Group key={flag} gap="xs" wrap="nowrap">
                                                <Code style={{ fontSize: '11px' }}>{flag}</Code>
                                                <Text size="xs" c="dimmed">
                                                  {explanation}
                                                </Text>
                                              </Group>
                                            ))}
                                          </Stack>
                                        </Box>
                                      )}

                                      {cmd.credentials_obtained && cmd.credentials_obtained.length > 0 && (
                                        <Box>
                                          <Badge size="xs" color="yellow" variant="light">
                                            Credentials Obtained
                                          </Badge>
                                          {cmd.credentials_obtained.map((cred, credIdx) => (
                                            <Box
                                              key={credIdx}
                                              mt="xs"
                                              p="xs"
                                              style={{
                                                background: '#1a1b1e',
                                                border: '1px solid #373A40',
                                                borderRadius: '4px',
                                              }}
                                            >
                                              {cred.username && (
                                                <Text size="xs" ff="monospace">
                                                  {cred.username}:{cred.password || cred.password_hash}
                                                </Text>
                                              )}
                                            </Box>
                                          ))}
                                        </Box>
                                      )}
                                    </Stack>
                                  </Accordion.Panel>
                                </Accordion.Item>
                              ))}
                            </Accordion>
                          </Box>
                        )}

                        {/* Failed Attempts */}
                        {phase.failed_attempts && phase.failed_attempts.length > 0 && (
                          <Box>
                            <Text size="xs" fw={600} mb="xs" c="red">
                              Failed Attempts ({phase.failed_attempts.length})
                            </Text>
                            <Stack gap="xs">
                              {phase.failed_attempts.map((fail: FailedAttempt, failIdx: number) => (
                                <Paper
                                  key={failIdx}
                                  p="sm"
                                  style={{
                                    background: '#25262b',
                                    border: '1px solid #5c3030',
                                  }}
                                >
                                  <Text size="xs" fw={600} mb={4} c="red">
                                    {fail.attempt}
                                  </Text>
                                  <Stack gap={4}>
                                    <Group gap="xs">
                                      <Text size="xs" c="dimmed">
                                        Expected:
                                      </Text>
                                      <Text size="xs">{fail.expected}</Text>
                                    </Group>
                                    <Group gap="xs">
                                      <Text size="xs" c="dimmed">
                                        Actual:
                                      </Text>
                                      <Text size="xs">{fail.actual}</Text>
                                    </Group>
                                    <Box mt="xs">
                                      <Text size="xs" c="yellow" fw={600}>
                                        Lesson Learned:
                                      </Text>
                                      <Text size="xs" style={{ whiteSpace: 'pre-wrap' }}>
                                        {fail.lesson_learned}
                                      </Text>
                                    </Box>
                                    {fail.time_wasted_minutes && (
                                      <Badge size="xs" variant="light" color="orange">
                                        Time wasted: {fail.time_wasted_minutes}m
                                      </Badge>
                                    )}
                                  </Stack>
                                </Paper>
                              ))}
                            </Stack>
                          </Box>
                        )}

                        {/* Vulnerabilities */}
                        {phase.vulnerabilities && phase.vulnerabilities.length > 0 && (
                          <Box>
                            <Text size="xs" fw={600} mb="xs" c="orange">
                              Vulnerabilities Discovered ({phase.vulnerabilities.length})
                            </Text>
                            <Stack gap="xs">
                              {phase.vulnerabilities.map((vuln: Vulnerability, vulnIdx: number) => (
                                <Paper
                                  key={vulnIdx}
                                  p="sm"
                                  style={{
                                    background: '#25262b',
                                    border: '1px solid #5c4a30',
                                  }}
                                >
                                  <Group gap="xs" mb={4}>
                                    <Text size="xs" fw={600} c="orange">
                                      {vuln.name}
                                    </Text>
                                    {vuln.cve && (
                                      <Badge size="xs" variant="filled" color="orange">
                                        {vuln.cve}
                                      </Badge>
                                    )}
                                    <Badge size="xs" variant="light" color={vuln.severity === 'critical' ? 'red' : vuln.severity === 'high' ? 'orange' : 'yellow'}>
                                      {vuln.severity}
                                    </Badge>
                                  </Group>
                                  <Text size="xs" c="dimmed" mb={4}>
                                    {vuln.type} • {vuln.location}
                                  </Text>
                                  {vuln.payload_example && (
                                    <Code block style={{ fontSize: '11px', marginTop: '4px' }}>
                                      {vuln.payload_example}
                                    </Code>
                                  )}
                                  {vuln.notes && (
                                    <Text size="xs" mt="xs" style={{ whiteSpace: 'pre-wrap' }}>
                                      {vuln.notes}
                                    </Text>
                                  )}
                                </Paper>
                              ))}
                            </Stack>
                          </Box>
                        )}

                        {/* Key Findings */}
                        {phase.key_findings && phase.key_findings.length > 0 && (
                          <Box>
                            <Text size="xs" fw={600} mb="xs" c="yellow">
                              Key Findings
                            </Text>
                            <Stack gap={4}>
                              {phase.key_findings.map((finding, findIdx) => (
                                <Group key={findIdx} gap="xs" wrap="nowrap" align="flex-start">
                                  <Text size="xs" c="yellow">
                                    •
                                  </Text>
                                  <Text size="xs">{finding}</Text>
                                </Group>
                              ))}
                            </Stack>
                          </Box>
                        )}

                        {/* OSCP Notes */}
                        {phase.oscp_notes && (
                          <Paper
                            p="sm"
                            style={{
                              background: '#1a2830',
                              border: '1px solid #22c1c3',
                            }}
                          >
                            <Group gap="xs" mb={4}>
                              <Badge size="xs" variant="filled" color="cyan">
                                OSCP NOTES
                              </Badge>
                            </Group>
                            <Text size="xs" style={{ whiteSpace: 'pre-wrap' }}>
                              {phase.oscp_notes}
                            </Text>
                          </Paper>
                        )}
                      </Stack>
                    </Accordion.Panel>
                  </Accordion.Item>
                ))}
              </Accordion>
            ) : (
              <Paper
                p="md"
                style={{
                  background: '#1a1b1e',
                  border: '1px solid #373A40',
                  textAlign: 'center',
                }}
              >
                <Text c="dimmed" size="sm">
                  No attack phases documented for this writeup
                </Text>
              </Paper>
            )}
          </ScrollArea>
        </Tabs.Panel>

        {/* Skills & Learnings Tab */}
        <Tabs.Panel value="skills-learnings">
          <ScrollArea style={{ height: '100%' }}>
            <Stack gap="md">
              {/* Required Skills */}
              {writeup.skills?.required && writeup.skills.required.length > 0 && (
                <Box>
                  <Text size="sm" fw={600} mb="xs" c="gray">
                    Required Skills
                  </Text>
                  <Group gap="xs">
                    {writeup.skills.required.map((skill, idx) => (
                      <Badge key={idx} size="sm" variant="light" color="gray">
                        {skill}
                      </Badge>
                    ))}
                  </Group>
                </Box>
              )}

              {/* Learned Skills */}
              {writeup.skills?.learned && writeup.skills.learned.length > 0 && (
                <Box>
                  <Text size="sm" fw={600} mb="xs" c="cyan">
                    Learned Skills
                  </Text>
                  <Group gap="xs">
                    {writeup.skills.learned.map((skill, idx) => (
                      <Badge key={idx} size="sm" variant="filled" color="cyan">
                        {skill}
                      </Badge>
                    ))}
                  </Group>
                </Box>
              )}

              <Divider color="#373A40" />

              {/* Key Learnings */}
              {writeup.key_learnings && writeup.key_learnings.length > 0 && (
                <Box>
                  <Text size="sm" fw={600} mb="xs" c="yellow">
                    Key Learnings ({writeup.key_learnings.length})
                  </Text>
                  <Accordion
                    variant="separated"
                    styles={{
                      item: {
                        background: '#1a1b1e',
                        border: '1px solid #373A40',
                      },
                      label: {
                        fontSize: '13px',
                        fontWeight: 600,
                      },
                    }}
                  >
                    {writeup.key_learnings.map((learning, idx) => (
                      <Accordion.Item key={idx} value={`learning-${idx}`}>
                        <Accordion.Control>
                          <Group gap="xs">
                            <Badge
                              size="xs"
                              variant="filled"
                              color={
                                learning.importance === 'critical'
                                  ? 'red'
                                  : learning.importance === 'high'
                                    ? 'orange'
                                    : learning.importance === 'medium'
                                      ? 'yellow'
                                      : 'gray'
                              }
                            >
                              {learning.importance}
                            </Badge>
                            <Badge size="xs" variant="light" color="gray">
                              {learning.category}
                            </Badge>
                            <Text size="sm" lineClamp={1}>
                              {learning.lesson}
                            </Text>
                          </Group>
                        </Accordion.Control>
                        <Accordion.Panel>
                          <Stack gap="xs">
                            <Box>
                              <Text size="xs" fw={600} mb={4} c="yellow">
                                Lesson
                              </Text>
                              <Text size="xs">{learning.lesson}</Text>
                            </Box>
                            <Box>
                              <Text size="xs" fw={600} mb={4} c="cyan">
                                Details
                              </Text>
                              <Text size="xs" style={{ whiteSpace: 'pre-wrap' }}>
                                {learning.detail}
                              </Text>
                            </Box>
                            {learning.time_impact && (
                              <Box>
                                <Text size="xs" fw={600} mb={4} c="orange">
                                  Time Impact
                                </Text>
                                <Text size="xs">{learning.time_impact}</Text>
                              </Box>
                            )}
                            {learning.methodology && (
                              <Box>
                                <Text size="xs" fw={600} mb={4} c="dimmed">
                                  Methodology
                                </Text>
                                <Text size="xs" style={{ whiteSpace: 'pre-wrap' }}>
                                  {learning.methodology}
                                </Text>
                              </Box>
                            )}
                            {learning.notes && (
                              <Box>
                                <Text size="xs" fw={600} mb={4} c="dimmed">
                                  Notes
                                </Text>
                                <Text size="xs" style={{ whiteSpace: 'pre-wrap' }}>
                                  {learning.notes}
                                </Text>
                              </Box>
                            )}
                          </Stack>
                        </Accordion.Panel>
                      </Accordion.Item>
                    ))}
                  </Accordion>
                </Box>
              )}

              <Divider color="#373A40" />

              {/* Alternative Approaches */}
              {writeup.alternative_approaches &&
                typeof writeup.alternative_approaches === 'object' &&
                Object.keys(writeup.alternative_approaches).length > 0 && (
                  <Box>
                    <Text size="sm" fw={600} mb="xs" c="blue">
                      Alternative Approaches
                    </Text>
                    <Stack gap="md">
                      {/* Foothold Alternatives */}
                      {writeup.alternative_approaches.foothold &&
                        writeup.alternative_approaches.foothold.length > 0 && (
                          <Box>
                            <Text size="xs" fw={600} mb="xs" c="dimmed" tt="uppercase">
                              Foothold
                            </Text>
                            <Stack gap="xs">
                              {writeup.alternative_approaches.foothold.map((alt, idx) => (
                                <Paper
                                  key={idx}
                                  p="sm"
                                  style={{
                                    background: '#25262b',
                                    border: '1px solid #373A40',
                                  }}
                                >
                                  <Group gap="xs" mb={4}>
                                    <Text size="xs" fw={600}>
                                      {alt.method}
                                    </Text>
                                    <Badge
                                      size="xs"
                                      variant="light"
                                      color={alt.oscp_applicable ? 'green' : 'red'}
                                    >
                                      {alt.oscp_applicable ? 'OSCP Applicable' : 'Not OSCP Applicable'}
                                    </Badge>
                                  </Group>
                                  <Text size="xs" c="dimmed" mb="xs">
                                    {alt.description}
                                  </Text>
                                  {alt.reasoning && (
                                    <Text size="xs" c="yellow">
                                      {alt.reasoning}
                                    </Text>
                                  )}
                                  {alt.notes && (
                                    <Text size="xs" mt="xs" c="dimmed">
                                      {alt.notes}
                                    </Text>
                                  )}
                                </Paper>
                              ))}
                            </Stack>
                          </Box>
                        )}

                      {/* Lateral Movement Alternatives */}
                      {writeup.alternative_approaches.lateral_movement &&
                        writeup.alternative_approaches.lateral_movement.length > 0 && (
                          <Box>
                            <Text size="xs" fw={600} mb="xs" c="dimmed" tt="uppercase">
                              Lateral Movement
                            </Text>
                            <Stack gap="xs">
                              {writeup.alternative_approaches.lateral_movement.map((alt, idx) => (
                                <Paper
                                  key={idx}
                                  p="sm"
                                  style={{
                                    background: '#25262b',
                                    border: '1px solid #373A40',
                                  }}
                                >
                                  <Group gap="xs" mb={4}>
                                    <Text size="xs" fw={600}>
                                      {alt.method}
                                    </Text>
                                    <Badge
                                      size="xs"
                                      variant="light"
                                      color={alt.oscp_applicable ? 'green' : 'red'}
                                    >
                                      {alt.oscp_applicable ? 'OSCP Applicable' : 'Not OSCP Applicable'}
                                    </Badge>
                                  </Group>
                                  <Text size="xs" c="dimmed" mb="xs">
                                    {alt.description}
                                  </Text>
                                  {alt.reasoning && (
                                    <Text size="xs" c="yellow">
                                      {alt.reasoning}
                                    </Text>
                                  )}
                                  {alt.notes && (
                                    <Text size="xs" mt="xs" c="dimmed">
                                      {alt.notes}
                                    </Text>
                                  )}
                                </Paper>
                              ))}
                            </Stack>
                          </Box>
                        )}

                      {/* Privilege Escalation Alternatives */}
                      {writeup.alternative_approaches.privilege_escalation &&
                        writeup.alternative_approaches.privilege_escalation.length > 0 && (
                          <Box>
                            <Text size="xs" fw={600} mb="xs" c="dimmed" tt="uppercase">
                              Privilege Escalation
                            </Text>
                            <Stack gap="xs">
                              {writeup.alternative_approaches.privilege_escalation.map((alt, idx) => (
                                <Paper
                                  key={idx}
                                  p="sm"
                                  style={{
                                    background: '#25262b',
                                    border: '1px solid #373A40',
                                  }}
                                >
                                  <Group gap="xs" mb={4}>
                                    <Text size="xs" fw={600}>
                                      {alt.method}
                                    </Text>
                                    <Badge
                                      size="xs"
                                      variant="light"
                                      color={alt.oscp_applicable ? 'green' : 'red'}
                                    >
                                      {alt.oscp_applicable ? 'OSCP Applicable' : 'Not OSCP Applicable'}
                                    </Badge>
                                  </Group>
                                  <Text size="xs" c="dimmed" mb="xs">
                                    {alt.description}
                                  </Text>
                                  {alt.reasoning && (
                                    <Text size="xs" c="yellow">
                                      {alt.reasoning}
                                    </Text>
                                  )}
                                  {alt.notes && (
                                    <Text size="xs" mt="xs" c="dimmed">
                                      {alt.notes}
                                    </Text>
                                  )}
                                </Paper>
                              ))}
                            </Stack>
                          </Box>
                        )}
                    </Stack>
                  </Box>
                )}
            </Stack>
          </ScrollArea>
        </Tabs.Panel>

        {/* Metadata Tab */}
        <Tabs.Panel value="metadata">
          <ScrollArea style={{ height: '100%' }}>
            {/* Machine Details */}
            <Box mb="md">
              <Text size="sm" fw={600} mb="xs" c="cyan">
                Machine Details
              </Text>
              <Paper
                p="sm"
                style={{
                  background: '#1a1b1e',
                  border: '1px solid #373A40',
                }}
              >
                <Group gap="lg" grow>
                  <Box>
                    <Text size="xs" c="dimmed" mb={4}>
                      Type
                    </Text>
                    <Text size="sm">{machineType}</Text>
                  </Box>
                  <Box>
                    <Text size="xs" c="dimmed" mb={4}>
                      OS
                    </Text>
                    <Text size="sm">{os}</Text>
                  </Box>
                </Group>
                {ipAddress && (
                  <Box mt="sm">
                    <Text size="xs" c="dimmed" mb={4}>
                      IP Address
                    </Text>
                    <Text size="sm" ff="monospace">
                      {ipAddress}
                    </Text>
                  </Box>
                )}
              </Paper>
            </Box>

            {/* Time Information */}
            {totalDurationMinutes > 0 && (
              <Box mb="md">
                <Text size="sm" fw={600} mb="xs" c="cyan">
                  Time Information
                </Text>
                <Paper
                  p="sm"
                  style={{
                    background: '#1a1b1e',
                    border: '1px solid #373A40',
                  }}
                >
                  <Box>
                    <Text size="xs" c="dimmed" mb={4}>
                      Total Duration
                    </Text>
                    <Text size="sm">{formatDuration(totalDurationMinutes)}</Text>
                  </Box>
                </Paper>
              </Box>
            )}

            {/* Writeup Information */}
            <Box mb="md">
              <Text size="sm" fw={600} mb="xs" c="cyan">
                Writeup Information
              </Text>
              <Paper
                p="sm"
                style={{
                  background: '#1a1b1e',
                  border: '1px solid #373A40',
                }}
              >
                {author && (
                  <Box mb="sm">
                    <Text size="xs" c="dimmed" mb={4}>
                      Author
                    </Text>
                    <Text size="sm">{author}</Text>
                  </Box>
                )}
                {releaseDate && (
                  <Box mb="sm">
                    <Text size="xs" c="dimmed" mb={4}>
                      Release Date
                    </Text>
                    <Text size="sm">{releaseDate}</Text>
                  </Box>
                )}
                {retirementDate && (
                  <Box mb="sm">
                    <Text size="xs" c="dimmed" mb={4}>
                      Retirement Date
                    </Text>
                    <Text size="sm">{retirementDate}</Text>
                  </Box>
                )}
                {rating !== undefined && (
                  <Box>
                    <Text size="xs" c="dimmed" mb={4}>
                      Rating
                    </Text>
                    <Text size="sm">{rating}/5</Text>
                  </Box>
                )}
              </Paper>
            </Box>

            {/* Similar Machines */}
            {writeup.oscp_relevance?.similar_machines &&
              typeof writeup.oscp_relevance.similar_machines === 'object' &&
              Object.keys(writeup.oscp_relevance.similar_machines).length > 0 && (
                <Box mb="md">
                  <Text size="sm" fw={600} mb="xs" c="cyan">
                    Similar Machines
                  </Text>
                  <Paper
                    p="sm"
                    style={{
                      background: '#1a1b1e',
                      border: '1px solid #373A40',
                    }}
                  >
                    <Stack gap="sm">
                      {writeup.oscp_relevance.similar_machines.proving_grounds &&
                        writeup.oscp_relevance.similar_machines.proving_grounds.length > 0 && (
                          <Box>
                            <Text size="xs" c="dimmed" mb={4} tt="uppercase">
                              Proving Grounds
                            </Text>
                            <Group gap="xs">
                              {writeup.oscp_relevance.similar_machines.proving_grounds.map(
                                (machine, idx) => (
                                  <Badge key={idx} size="xs" variant="light" color="green">
                                    {machine}
                                  </Badge>
                                )
                              )}
                            </Group>
                          </Box>
                        )}

                      {writeup.oscp_relevance.similar_machines.hackthebox &&
                        writeup.oscp_relevance.similar_machines.hackthebox.length > 0 && (
                          <Box>
                            <Text size="xs" c="dimmed" mb={4} tt="uppercase">
                              HackTheBox
                            </Text>
                            <Group gap="xs">
                              {writeup.oscp_relevance.similar_machines.hackthebox.map(
                                (machine, idx) => (
                                  <Badge key={idx} size="xs" variant="light" color="orange">
                                    {machine}
                                  </Badge>
                                )
                              )}
                            </Group>
                          </Box>
                        )}

                      {writeup.oscp_relevance.similar_machines.oscp_labs &&
                        writeup.oscp_relevance.similar_machines.oscp_labs.length > 0 && (
                          <Box>
                            <Text size="xs" c="dimmed" mb={4} tt="uppercase">
                              OSCP Labs
                            </Text>
                            <Group gap="xs">
                              {writeup.oscp_relevance.similar_machines.oscp_labs.map((machine, idx) => (
                                <Badge key={idx} size="xs" variant="light" color="cyan">
                                  {machine}
                                </Badge>
                              ))}
                            </Group>
                          </Box>
                        )}
                    </Stack>
                  </Paper>
                </Box>
              )}

            {/* References */}
            {writeup.references && writeup.references.length > 0 && (
              <Box mb="md">
                <Text size="sm" fw={600} mb="xs" c="cyan">
                  References ({writeup.references.length})
                </Text>
                <Stack gap="xs">
                  {writeup.references.map((ref, idx) => (
                    <Paper
                      key={idx}
                      p="sm"
                      style={{
                        background: '#25262b',
                        border: '1px solid #373A40',
                      }}
                    >
                      <Group gap="xs" mb={4} wrap="nowrap">
                        <Badge size="xs" variant="light" color="gray">
                          {ref.type}
                        </Badge>
                        {ref.id && (
                          <Badge size="xs" variant="filled" color="orange">
                            {ref.id}
                          </Badge>
                        )}
                        {ref.name && (
                          <Text size="xs" fw={600} lineClamp={1}>
                            {ref.name}
                          </Text>
                        )}
                      </Group>
                      {ref.description && (
                        <Text size="xs" c="dimmed" mb="xs">
                          {ref.description}
                        </Text>
                      )}
                      {ref.url && (
                        <Code
                          block
                          style={{
                            fontSize: '10px',
                            whiteSpace: 'nowrap',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                          }}
                        >
                          {ref.url}
                        </Code>
                      )}
                      {ref.author && (
                        <Text size="xs" c="dimmed" mt="xs">
                          by {ref.author}
                        </Text>
                      )}
                    </Paper>
                  ))}
                </Stack>
              </Box>
            )}
          </ScrollArea>
        </Tabs.Panel>
      </Tabs>
    </Paper>
  );
}
