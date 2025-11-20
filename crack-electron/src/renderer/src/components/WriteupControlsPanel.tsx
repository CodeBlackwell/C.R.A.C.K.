import { useEffect, useState } from 'react';
import { Paper, Text, Badge, Group, Stack, ScrollArea, Divider, Progress, Box } from '@mantine/core';
import { Writeup } from '../types/writeup';

interface WriteupControlsPanelProps {
  writeupId: string | null;
}

export default function WriteupControlsPanel({ writeupId }: WriteupControlsPanelProps) {
  const [writeup, setWriteup] = useState<Writeup | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    console.log('[WriteupControlsPanel] Component mounted');
  }, []);

  useEffect(() => {
    if (!writeupId) {
      setWriteup(null);
      return;
    }

    const loadWriteup = async () => {
      setLoading(true);
      try {
        console.log('[WriteupControlsPanel] Loading writeup:', writeupId);
        const data = await window.electronAPI.getWriteup(writeupId);
        console.log('[WriteupControlsPanel] Writeup loaded:', data);
        setWriteup(data);
      } catch (error) {
        console.error('[WriteupControlsPanel] Error loading writeup:', error);
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
          Select a writeup
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
          Loading...
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

  const getOSCPRelevanceScore = (relevance: string): number => {
    switch (relevance) {
      case 'high': return 100;
      case 'medium': return 60;
      case 'low': return 30;
      default: return 0;
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
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  };

  // Extract values with proper fallbacks for nested structure
  const difficulty = writeup.metadata?.difficulty || 'unknown';
  const oscpScoreValue = writeup.oscp_relevance?.score || 'low';
  const examApplicable = writeup.oscp_relevance?.exam_applicable || false;
  const platform = writeup.source?.platform || 'unknown';
  const os = writeup.metadata?.os || 'unknown';
  const machineType = writeup.source?.type || 'unknown';
  const totalDurationMinutes = writeup.time_breakdown?.total_minutes || 0;
  const ipAddress = writeup.metadata?.ip_address || '';
  const author = writeup.metadata?.writeup_author || writeup.metadata?.machine_author || '';
  const rating = writeup.metadata?.rating;
  const releaseDate = writeup.source?.release_date || '';
  const retirementDate = writeup.source?.retire_date || '';

  const oscpScore = getOSCPRelevanceScore(oscpScoreValue);

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
          {/* OSCP Relevance Score */}
          <Box>
            <Text size="xs" fw={600} mb="xs" c="dimmed">
              OSCP Relevance
            </Text>
            <Progress
              value={oscpScore}
              color={getOSCPRelevanceColor(oscpScoreValue)}
              size="lg"
              mb="xs"
            />
            <Group justify="space-between">
              <Text size="xs" c="dimmed">
                {oscpScoreValue.toUpperCase()}
              </Text>
              {examApplicable && (
                <Badge size="xs" variant="filled" color="cyan">
                  Exam Applicable
                </Badge>
              )}
            </Group>
          </Box>

          <Divider color="#373A40" />

          {/* Quick Stats */}
          <Box>
            <Text size="xs" fw={600} mb="xs" c="dimmed">
              Quick Stats
            </Text>
            <Stack gap="xs">
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Difficulty</Text>
                <Badge
                  size="xs"
                  variant="light"
                  color={getDifficultyColor(difficulty)}
                >
                  {difficulty}
                </Badge>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Platform</Text>
                <Badge size="xs" variant="dot" color="gray">
                  {platform}
                </Badge>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">OS</Text>
                <Text size="xs">{os}</Text>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Type</Text>
                <Text size="xs">{machineType}</Text>
              </Group>
              {totalDurationMinutes > 0 && (
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">Duration</Text>
                  <Text size="xs">{formatDuration(totalDurationMinutes)}</Text>
                </Group>
              )}
            </Stack>
          </Box>

          <Divider color="#373A40" />

          {/* Machine Details */}
          <Box>
            <Text size="xs" fw={600} mb="xs" c="dimmed">
              Machine Details
            </Text>
            <Stack gap="xs">
              {ipAddress && (
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">IP Address</Text>
                  <Text size="xs" ff="monospace">{ipAddress}</Text>
                </Group>
              )}
              {author && (
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">Author</Text>
                  <Text size="xs">{author}</Text>
                </Group>
              )}
              {rating !== undefined && (
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">Rating</Text>
                  <Text size="xs">{rating}/5</Text>
                </Group>
              )}
            </Stack>
          </Box>

          {/* Timeline (if dates available) */}
          {(releaseDate || retirementDate) && (
            <>
              <Divider color="#373A40" />
              <Box>
                <Text size="xs" fw={600} mb="xs" c="dimmed">
                  Timeline
                </Text>
                <Stack gap="xs">
                  {releaseDate && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Released</Text>
                      <Text size="xs">{releaseDate}</Text>
                    </Group>
                  )}
                  {retirementDate && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Retired</Text>
                      <Text size="xs">{retirementDate}</Text>
                    </Group>
                  )}
                </Stack>
              </Box>
            </>
          )}

          {/* Time Breakdown (Phase 6) */}
          {writeup.time_breakdown && (
            <>
              <Divider color="#373A40" />
              <Box>
                <Text size="xs" fw={600} mb="xs" c="dimmed">
                  Time Breakdown
                </Text>
                <Stack gap="xs">
                  {writeup.time_breakdown.enumeration !== undefined && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Enumeration</Text>
                      <Text size="xs">{writeup.time_breakdown.enumeration}m</Text>
                    </Group>
                  )}
                  {writeup.time_breakdown.foothold !== undefined && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Foothold</Text>
                      <Text size="xs">{writeup.time_breakdown.foothold}m</Text>
                    </Group>
                  )}
                  {writeup.time_breakdown.foothold_sqli !== undefined && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Foothold (SQLi)</Text>
                      <Text size="xs">{writeup.time_breakdown.foothold_sqli}m</Text>
                    </Group>
                  )}
                  {writeup.time_breakdown.foothold_file_upload !== undefined && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Foothold (File Upload)</Text>
                      <Text size="xs">{writeup.time_breakdown.foothold_file_upload}m</Text>
                    </Group>
                  )}
                  {writeup.time_breakdown.lateral_movement !== undefined && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Lateral Movement</Text>
                      <Text size="xs">{writeup.time_breakdown.lateral_movement}m</Text>
                    </Group>
                  )}
                  {writeup.time_breakdown.privilege_escalation !== undefined && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Privilege Escalation</Text>
                      <Text size="xs">{writeup.time_breakdown.privilege_escalation}m</Text>
                    </Group>
                  )}
                  {writeup.time_breakdown.privilege_escalation_analysis !== undefined && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">PrivEsc (Analysis)</Text>
                      <Text size="xs">{writeup.time_breakdown.privilege_escalation_analysis}m</Text>
                    </Group>
                  )}
                  {writeup.time_breakdown.privilege_escalation_exploitation !== undefined && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">PrivEsc (Exploitation)</Text>
                      <Text size="xs">{writeup.time_breakdown.privilege_escalation_exploitation}m</Text>
                    </Group>
                  )}
                  <Divider color="#373A40" size="xs" />
                  <Group justify="space-between">
                    <Text size="xs" fw={600}>Total</Text>
                    <Text size="xs" fw={600}>
                      {writeup.time_breakdown.total_minutes}m ({(writeup.time_breakdown.total_hours || 0).toFixed(2)}h)
                    </Text>
                  </Group>
                  {writeup.time_breakdown.oscp_time_estimate && (
                    <Group justify="space-between">
                      <Text size="xs" c="cyan">OSCP Estimate</Text>
                      <Text size="xs" c="cyan">{writeup.time_breakdown.oscp_time_estimate}</Text>
                    </Group>
                  )}
                </Stack>
              </Box>
            </>
          )}

          {/* Enhanced Stats (Phase 7) */}
          {writeup.attack_phases && Array.isArray(writeup.attack_phases) && writeup.attack_phases.length > 0 && (
            <>
              <Divider color="#373A40" />
              <Box>
                <Text size="xs" fw={600} mb="xs" c="dimmed">
                  Attack Stats
                </Text>
                <Stack gap="xs">
                  <Group justify="space-between">
                    <Text size="xs" c="dimmed">Attack Phases</Text>
                    <Badge size="xs" variant="light" color="gray">
                      {writeup.attack_phases.length}
                    </Badge>
                  </Group>
                  <Group justify="space-between">
                    <Text size="xs" c="dimmed">Total Commands</Text>
                    <Badge size="xs" variant="light" color="green">
                      {Array.isArray(writeup.attack_phases)
                        ? writeup.attack_phases.reduce(
                            (sum, phase) => sum + (phase.commands_used?.length || 0),
                            0
                          )
                        : 0}
                    </Badge>
                  </Group>
                  <Group justify="space-between">
                    <Text size="xs" c="dimmed">Failed Attempts</Text>
                    <Badge size="xs" variant="light" color="red">
                      {Array.isArray(writeup.attack_phases)
                        ? writeup.attack_phases.reduce(
                            (sum, phase) => sum + (phase.failed_attempts?.length || 0),
                            0
                          )
                        : 0}
                    </Badge>
                  </Group>
                  <Group justify="space-between">
                    <Text size="xs" c="dimmed">Vulnerabilities</Text>
                    <Badge size="xs" variant="light" color="orange">
                      {Array.isArray(writeup.attack_phases)
                        ? writeup.attack_phases.reduce(
                            (sum, phase) => sum + (phase.vulnerabilities?.length || 0),
                            0
                          )
                        : 0}
                    </Badge>
                  </Group>
                  <Group justify="space-between">
                    <Text size="xs" c="dimmed">Credentials Obtained</Text>
                    <Badge size="xs" variant="light" color="yellow">
                      {Array.isArray(writeup.attack_phases)
                        ? writeup.attack_phases.reduce(
                            (sum, phase) => sum + (phase.credentials_obtained?.length || 0),
                            0
                          )
                        : 0}
                    </Badge>
                  </Group>
                </Stack>
              </Box>
            </>
          )}

          {/* Flags Captured */}
          {writeup.time_breakdown?.flags_captured && (
            <>
              <Divider color="#373A40" />
              <Box>
                <Text size="xs" fw={600} mb="xs" c="dimmed">
                  Flags Captured
                </Text>
                <Stack gap="xs">
                  {writeup.time_breakdown.flags_captured.user && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">User Flag</Text>
                      <Text size="xs" ff="monospace" c="green">
                        {writeup.time_breakdown.flags_captured.user}
                      </Text>
                    </Group>
                  )}
                  {writeup.time_breakdown.flags_captured.root && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Root Flag</Text>
                      <Text size="xs" ff="monospace" c="cyan">
                        {writeup.time_breakdown.flags_captured.root}
                      </Text>
                    </Group>
                  )}
                </Stack>
              </Box>
            </>
          )}

          {/* Similar Machines Quick Links */}
          {writeup.oscp_relevance?.similar_machines && (
            <>
              <Divider color="#373A40" />
              <Box>
                <Text size="xs" fw={600} mb="xs" c="dimmed">
                  Similar Machines
                </Text>
                <Stack gap="xs">
                  {writeup.oscp_relevance.similar_machines.proving_grounds &&
                    writeup.oscp_relevance.similar_machines.proving_grounds.length > 0 && (
                      <Box>
                        <Text size="xs" c="dimmed" mb={4}>
                          Proving Grounds
                        </Text>
                        <Group gap={4}>
                          {writeup.oscp_relevance.similar_machines.proving_grounds
                            .slice(0, 3)
                            .map((machine, idx) => (
                              <Badge key={idx} size="xs" variant="light" color="green">
                                {machine}
                              </Badge>
                            ))}
                          {writeup.oscp_relevance.similar_machines.proving_grounds.length > 3 && (
                            <Text size="xs" c="dimmed">
                              +{writeup.oscp_relevance.similar_machines.proving_grounds.length - 3} more
                            </Text>
                          )}
                        </Group>
                      </Box>
                    )}
                  {writeup.oscp_relevance.similar_machines.hackthebox &&
                    writeup.oscp_relevance.similar_machines.hackthebox.length > 0 && (
                      <Box>
                        <Text size="xs" c="dimmed" mb={4}>
                          HackTheBox
                        </Text>
                        <Group gap={4}>
                          {writeup.oscp_relevance.similar_machines.hackthebox.slice(0, 3).map((machine, idx) => (
                            <Badge key={idx} size="xs" variant="light" color="orange">
                              {machine}
                            </Badge>
                          ))}
                          {writeup.oscp_relevance.similar_machines.hackthebox.length > 3 && (
                            <Text size="xs" c="dimmed">
                              +{writeup.oscp_relevance.similar_machines.hackthebox.length - 3} more
                            </Text>
                          )}
                        </Group>
                      </Box>
                    )}
                  {writeup.oscp_relevance.similar_machines.oscp_labs &&
                    writeup.oscp_relevance.similar_machines.oscp_labs.length > 0 && (
                      <Box>
                        <Text size="xs" c="dimmed" mb={4}>
                          OSCP Labs
                        </Text>
                        <Group gap={4}>
                          {writeup.oscp_relevance.similar_machines.oscp_labs.slice(0, 3).map((machine, idx) => (
                            <Badge key={idx} size="xs" variant="light" color="cyan">
                              {machine}
                            </Badge>
                          ))}
                          {writeup.oscp_relevance.similar_machines.oscp_labs.length > 3 && (
                            <Text size="xs" c="dimmed">
                              +{writeup.oscp_relevance.similar_machines.oscp_labs.length - 3} more
                            </Text>
                          )}
                        </Group>
                      </Box>
                    )}
                </Stack>
              </Box>
            </>
          )}
        </Stack>
      </ScrollArea>
    </Paper>
  );
}
