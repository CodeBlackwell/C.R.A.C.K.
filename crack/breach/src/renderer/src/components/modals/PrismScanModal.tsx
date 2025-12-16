/**
 * PrismScanModal - Display PRISM scan results
 *
 * Shows credentials and findings discovered from manual terminal scan.
 */

import {
  Modal,
  Text,
  Group,
  Stack,
  Button,
  Badge,
  Paper,
  ScrollArea,
  Collapse,
  ThemeIcon,
  Divider,
} from '@mantine/core';
import {
  IconRadar,
  IconKey,
  IconBug,
  IconChevronDown,
  IconChevronRight,
  IconCheck,
  IconX,
} from '@tabler/icons-react';
import { useState } from 'react';
import type { Credential } from '@shared/types/credential';
import type { Finding } from '@shared/types/finding';
import { getSeverityColor } from '@shared/types/finding';

/** Scan results structure */
export interface PrismScanResults {
  credentials: Credential[];
  findings: Finding[];
}

interface PrismScanModalProps {
  opened: boolean;
  onClose: () => void;
  results: PrismScanResults | null;
  onViewFindings?: () => void;
  onViewCredentials?: () => void;
}

export function PrismScanModal({
  opened,
  onClose,
  results,
  onViewFindings,
  onViewCredentials,
}: PrismScanModalProps) {
  const [credentialsExpanded, setCredentialsExpanded] = useState(true);
  const [findingsExpanded, setFindingsExpanded] = useState(true);

  const credentialCount = results?.credentials.length ?? 0;
  const findingCount = results?.findings.length ?? 0;
  const hasResults = credentialCount > 0 || findingCount > 0;

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={
        <Group gap="xs">
          <ThemeIcon size="md" variant="light" color="cyan">
            <IconRadar size={16} />
          </ThemeIcon>
          <Text fw={600}>PRISM Scan Results</Text>
        </Group>
      }
      size="md"
      styles={{
        header: { background: '#1a1b1e', borderBottom: '1px solid #373A40' },
        body: { background: '#25262b', padding: 0 },
        content: { background: '#25262b' },
      }}
    >
      <Stack gap={0}>
        {/* Summary */}
        <Group p="md" justify="center" gap="md" style={{ borderBottom: '1px solid #373A40' }}>
          <Badge
            size="lg"
            variant={credentialCount > 0 ? 'filled' : 'light'}
            color={credentialCount > 0 ? 'green' : 'gray'}
            leftSection={<IconKey size={14} />}
          >
            {credentialCount} Credential{credentialCount !== 1 ? 's' : ''}
          </Badge>
          <Badge
            size="lg"
            variant={findingCount > 0 ? 'filled' : 'light'}
            color={findingCount > 0 ? 'orange' : 'gray'}
            leftSection={<IconBug size={14} />}
          >
            {findingCount} Finding{findingCount !== 1 ? 's' : ''}
          </Badge>
        </Group>

        {/* Results Content */}
        <ScrollArea style={{ maxHeight: 400 }}>
          {!hasResults ? (
            <Stack align="center" justify="center" p="xl" gap="xs">
              <IconX size={48} color="#6e7681" />
              <Text c="dimmed" ta="center">
                No credentials or findings detected
              </Text>
              <Text size="xs" c="dimmed" ta="center">
                Try running more enumeration commands
              </Text>
            </Stack>
          ) : (
            <Stack gap={0} p="sm">
              {/* Credentials Section */}
              {credentialCount > 0 && (
                <>
                  <Group
                    gap="xs"
                    p="xs"
                    style={{
                      cursor: 'pointer',
                      background: '#1a1b1e',
                      borderRadius: 4,
                    }}
                    onClick={() => setCredentialsExpanded(!credentialsExpanded)}
                  >
                    {credentialsExpanded ? (
                      <IconChevronDown size={14} color="#868e96" />
                    ) : (
                      <IconChevronRight size={14} color="#868e96" />
                    )}
                    <IconKey size={14} color="#40c057" />
                    <Text size="sm" fw={500}>
                      Credentials ({credentialCount})
                    </Text>
                  </Group>
                  <Collapse in={credentialsExpanded}>
                    <Stack gap={4} p="xs">
                      {results?.credentials.map((cred) => (
                        <Paper
                          key={cred.id}
                          p="xs"
                          style={{
                            background: '#2c2e33',
                            border: '1px solid #373A40',
                          }}
                        >
                          <Group gap="xs" justify="space-between">
                            <Stack gap={2}>
                              <Text size="sm" fw={500} style={{ fontFamily: 'monospace' }}>
                                {cred.domain ? `${cred.domain}\\${cred.username}` : cred.username}
                              </Text>
                              <Group gap={4}>
                                <Badge size="xs" variant="light" color="cyan">
                                  {cred.secretType}
                                </Badge>
                                <Text size="xs" c="dimmed">
                                  via {cred.source}
                                </Text>
                              </Group>
                            </Stack>
                            <IconCheck size={16} color="#40c057" />
                          </Group>
                        </Paper>
                      ))}
                    </Stack>
                  </Collapse>
                </>
              )}

              {/* Findings Section */}
              {findingCount > 0 && (
                <>
                  {credentialCount > 0 && <Divider my="xs" />}
                  <Group
                    gap="xs"
                    p="xs"
                    style={{
                      cursor: 'pointer',
                      background: '#1a1b1e',
                      borderRadius: 4,
                    }}
                    onClick={() => setFindingsExpanded(!findingsExpanded)}
                  >
                    {findingsExpanded ? (
                      <IconChevronDown size={14} color="#868e96" />
                    ) : (
                      <IconChevronRight size={14} color="#868e96" />
                    )}
                    <IconBug size={14} color="#fd7e14" />
                    <Text size="sm" fw={500}>
                      Findings ({findingCount})
                    </Text>
                  </Group>
                  <Collapse in={findingsExpanded}>
                    <Stack gap={4} p="xs">
                      {results?.findings.map((finding) => (
                        <Paper
                          key={finding.id}
                          p="xs"
                          style={{
                            background: '#2c2e33',
                            border: '1px solid #373A40',
                            borderLeft: `3px solid ${getSeverityColor(finding.severity)}`,
                          }}
                        >
                          <Stack gap={2}>
                            <Group gap="xs" justify="space-between">
                              <Text size="sm" fw={500}>
                                {finding.title}
                              </Text>
                              <Badge
                                size="xs"
                                variant="filled"
                                style={{ background: getSeverityColor(finding.severity) }}
                              >
                                {finding.severity.toUpperCase()}
                              </Badge>
                            </Group>
                            <Text size="xs" c="dimmed" lineClamp={2}>
                              {finding.description}
                            </Text>
                          </Stack>
                        </Paper>
                      ))}
                    </Stack>
                  </Collapse>
                </>
              )}
            </Stack>
          )}
        </ScrollArea>

        {/* Footer Actions */}
        <Group
          p="md"
          justify="flex-end"
          gap="sm"
          style={{ borderTop: '1px solid #373A40' }}
        >
          {findingCount > 0 && (
            <Button
              variant="light"
              color="orange"
              leftSection={<IconBug size={14} />}
              onClick={() => {
                onViewFindings?.();
                onClose();
              }}
            >
              View Findings
            </Button>
          )}
          {credentialCount > 0 && (
            <Button
              variant="light"
              color="green"
              leftSection={<IconKey size={14} />}
              onClick={() => {
                onViewCredentials?.();
                onClose();
              }}
            >
              View Credentials
            </Button>
          )}
          <Button variant="default" onClick={onClose}>
            Close
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
