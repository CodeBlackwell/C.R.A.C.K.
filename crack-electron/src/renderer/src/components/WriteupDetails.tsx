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
} from '@mantine/core';
import { Writeup } from '../types/writeup';

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
            color={getDifficultyColor(writeup.difficulty)}
          >
            {writeup.difficulty}
          </Badge>
          <Badge
            size="sm"
            variant="light"
            color={getOSCPRelevanceColor(writeup.oscp_relevance)}
          >
            OSCP: {writeup.oscp_relevance}
          </Badge>
          {writeup.exam_applicable && (
            <Badge size="sm" variant="filled" color="cyan">
              Exam Applicable
            </Badge>
          )}
          <Badge size="sm" variant="dot" color="gray">
            {writeup.platform}
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
            {writeup.oscp_reasoning && (
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
                    {writeup.oscp_reasoning}
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
                    <Text size="sm">{writeup.machine_type}</Text>
                  </Box>
                  <Box>
                    <Text size="xs" c="dimmed" mb={4}>
                      OS
                    </Text>
                    <Text size="sm">{writeup.os}</Text>
                  </Box>
                </Group>
                {writeup.ip_address && (
                  <Box mt="sm">
                    <Text size="xs" c="dimmed" mb={4}>
                      IP Address
                    </Text>
                    <Text size="sm" ff="monospace">
                      {writeup.ip_address}
                    </Text>
                  </Box>
                )}
              </Paper>
            </Box>

            {/* Time Information */}
            {writeup.total_duration_minutes && (
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
                    <Text size="sm">{formatDuration(writeup.total_duration_minutes)}</Text>
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
                {writeup.author && (
                  <Box mb="sm">
                    <Text size="xs" c="dimmed" mb={4}>
                      Author
                    </Text>
                    <Text size="sm">{writeup.author}</Text>
                  </Box>
                )}
                {writeup.release_date && (
                  <Box mb="sm">
                    <Text size="xs" c="dimmed" mb={4}>
                      Release Date
                    </Text>
                    <Text size="sm">{writeup.release_date}</Text>
                  </Box>
                )}
                {writeup.retirement_date && (
                  <Box mb="sm">
                    <Text size="xs" c="dimmed" mb={4}>
                      Retirement Date
                    </Text>
                    <Text size="sm">{writeup.retirement_date}</Text>
                  </Box>
                )}
                {writeup.rating !== undefined && (
                  <Box>
                    <Text size="xs" c="dimmed" mb={4}>
                      Rating
                    </Text>
                    <Text size="sm">{writeup.rating}/5</Text>
                  </Box>
                )}
              </Paper>
            </Box>
          </ScrollArea>
        </Tabs.Panel>
      </Tabs>
    </Paper>
  );
}
