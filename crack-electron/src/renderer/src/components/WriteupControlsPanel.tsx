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

  const oscpScore = getOSCPRelevanceScore(writeup.oscp_relevance);

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
              color={getOSCPRelevanceColor(writeup.oscp_relevance)}
              size="lg"
              mb="xs"
            />
            <Group justify="space-between">
              <Text size="xs" c="dimmed">
                {writeup.oscp_relevance.toUpperCase()}
              </Text>
              {writeup.exam_applicable && (
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
                  color={getDifficultyColor(writeup.difficulty)}
                >
                  {writeup.difficulty}
                </Badge>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Platform</Text>
                <Badge size="xs" variant="dot" color="gray">
                  {writeup.platform}
                </Badge>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">OS</Text>
                <Text size="xs">{writeup.os}</Text>
              </Group>
              <Group justify="space-between">
                <Text size="xs" c="dimmed">Type</Text>
                <Text size="xs">{writeup.machine_type}</Text>
              </Group>
              {writeup.total_duration_minutes && (
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">Duration</Text>
                  <Text size="xs">{formatDuration(writeup.total_duration_minutes)}</Text>
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
              {writeup.ip_address && (
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">IP Address</Text>
                  <Text size="xs" ff="monospace">{writeup.ip_address}</Text>
                </Group>
              )}
              {writeup.author && (
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">Author</Text>
                  <Text size="xs">{writeup.author}</Text>
                </Group>
              )}
              {writeup.rating !== undefined && (
                <Group justify="space-between">
                  <Text size="xs" c="dimmed">Rating</Text>
                  <Text size="xs">{writeup.rating}/5</Text>
                </Group>
              )}
            </Stack>
          </Box>

          {/* Timeline (if dates available) */}
          {(writeup.release_date || writeup.retirement_date) && (
            <>
              <Divider color="#373A40" />
              <Box>
                <Text size="xs" fw={600} mb="xs" c="dimmed">
                  Timeline
                </Text>
                <Stack gap="xs">
                  {writeup.release_date && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Released</Text>
                      <Text size="xs">{writeup.release_date}</Text>
                    </Group>
                  )}
                  {writeup.retirement_date && (
                    <Group justify="space-between">
                      <Text size="xs" c="dimmed">Retired</Text>
                      <Text size="xs">{writeup.retirement_date}</Text>
                    </Group>
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
