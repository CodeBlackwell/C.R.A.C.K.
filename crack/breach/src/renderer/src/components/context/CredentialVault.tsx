/**
 * CredentialVault - Credential Management Panel
 *
 * Displays discovered credentials with quick actions for lateral movement.
 * Integrates with PRISM parser output and Neo4j storage.
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Stack,
  ScrollArea,
  Text,
  Badge,
  Group,
  ActionIcon,
  Tooltip,
  TextInput,
  Paper,
  Menu,
  Divider,
  CopyButton,
  Loader,
  ThemeIcon,
  Collapse,
} from '@mantine/core';
import {
  IconKey,
  IconLock,
  IconHash,
  IconCertificate,
  IconSearch,
  IconRefresh,
  IconCopy,
  IconChevronDown,
  IconChevronRight,
  IconTerminal2,
  IconCircleFilled,
  IconDotsVertical,
  IconUser,
  IconServer,
  IconShield,
} from '@tabler/icons-react';
import type { Credential, SecretType } from '@shared/types/credential';
import {
  CREDENTIAL_ACTIONS,
  getApplicableActions,
  substituteCredential,
} from '@shared/types/credential';

interface CredentialVaultProps {
  engagementId?: string;
  onUseCredential?: (command: string, credentialId: string) => void;
}

/** Icon map for credential types */
const CRED_TYPE_ICONS: Partial<Record<SecretType, typeof IconKey>> = {
  password: IconKey,
  ntlm: IconHash,
  kerberos: IconCertificate,
  ssh_key: IconLock,
  ticket: IconCertificate,
  gpp: IconShield,
  sam: IconHash,
  dcc2: IconHash,
};

/** Color map for credential types */
const CRED_TYPE_COLORS: Partial<Record<SecretType, string>> = {
  password: 'green',
  ntlm: 'orange',
  kerberos: 'cyan',
  ssh_key: 'violet',
  ticket: 'cyan',
  gpp: 'yellow',
  sam: 'orange',
  dcc2: 'red',
};

/** Badge label for credential types */
const CRED_TYPE_LABELS: Partial<Record<SecretType, string>> = {
  password: 'Cleartext',
  ntlm: 'NTLM',
  kerberos: 'Kerberos',
  ssh_key: 'SSH Key',
  ticket: 'Ticket',
  gpp: 'GPP',
  sam: 'SAM',
  dcc2: 'DCC2',
};

/** Group credentials by domain */
function groupCredentialsByDomain(
  credentials: Credential[]
): Map<string, Credential[]> {
  const groups = new Map<string, Credential[]>();

  for (const cred of credentials) {
    const domain = cred.domain || 'Local';
    if (!groups.has(domain)) {
      groups.set(domain, []);
    }
    groups.get(domain)!.push(cred);
  }

  return groups;
}

export function CredentialVault({
  engagementId,
  onUseCredential,
}: CredentialVaultProps) {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set());

  // Load credentials for engagement
  const loadCredentials = useCallback(async () => {
    if (!engagementId) return;

    setLoading(true);
    try {
      const creds = await window.electronAPI.credentialList(engagementId);
      setCredentials(creds || []);

      // Auto-expand first domain
      if (creds.length > 0) {
        const firstDomain = creds[0].domain || 'Local';
        setExpandedDomains(new Set([firstDomain]));
      }
    } catch (err) {
      console.error('Failed to load credentials:', err);
    } finally {
      setLoading(false);
    }
  }, [engagementId]);

  useEffect(() => {
    loadCredentials();
  }, [loadCredentials]);

  // Group and filter credentials
  const groupedCredentials = useMemo(() => {
    let filtered = credentials;

    if (search) {
      const lower = search.toLowerCase();
      filtered = credentials.filter(
        (c) =>
          c.username.toLowerCase().includes(lower) ||
          c.domain?.toLowerCase().includes(lower) ||
          c.source?.toLowerCase().includes(lower)
      );
    }

    return groupCredentialsByDomain(filtered);
  }, [credentials, search]);

  // Toggle domain expansion
  const toggleDomain = (domain: string) => {
    setExpandedDomains((prev) => {
      const next = new Set(prev);
      if (next.has(domain)) {
        next.delete(domain);
      } else {
        next.add(domain);
      }
      return next;
    });
  };

  // Handle credential action
  const handleAction = (cred: Credential, actionId: string, target?: string) => {
    const action = CREDENTIAL_ACTIONS.find((a) => a.id === actionId);
    if (!action) return;

    const command = substituteCredential(action.command, cred, target || '<RHOST>');
    onUseCredential?.(command, cred.id);
  };

  // Count stats
  const stats = useMemo(() => {
    const cleartext = credentials.filter((c) => c.secretType === 'password').length;
    const admin = credentials.filter((c) => c.isAdmin).length;
    return { total: credentials.length, cleartext, admin };
  }, [credentials]);

  return (
    <Stack
      gap={0}
      style={{
        height: '100%',
        background: '#25262b',
      }}
    >
      {/* Header */}
      <Group
        justify="space-between"
        p="xs"
        style={{ borderBottom: '1px solid #373A40' }}
      >
        <Group gap="xs">
          <IconKey size={16} color="#868e96" />
          <Text size="sm" fw={600} c="dimmed">
            CREDENTIALS
          </Text>
        </Group>
        <Group gap={4}>
          {stats.cleartext > 0 && (
            <Tooltip label="Cleartext passwords">
              <Badge size="xs" variant="light" color="green">
                {stats.cleartext}
              </Badge>
            </Tooltip>
          )}
          {stats.admin > 0 && (
            <Tooltip label="Admin credentials">
              <Badge size="xs" variant="light" color="red">
                {stats.admin} admin
              </Badge>
            </Tooltip>
          )}
          <Tooltip label="Refresh">
            <ActionIcon
              variant="subtle"
              color="gray"
              size="sm"
              onClick={loadCredentials}
              loading={loading}
            >
              <IconRefresh size={14} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      {/* Search */}
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #373A40' }}>
        <TextInput
          size="xs"
          placeholder="Search credentials..."
          leftSection={<IconSearch size={14} />}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          styles={{
            input: {
              background: '#1a1b1e',
              border: '1px solid #373A40',
            },
          }}
        />
      </div>

      {/* Credential List */}
      <ScrollArea style={{ flex: 1 }}>
        {!engagementId ? (
          <Text c="dimmed" size="sm" ta="center" p="xl">
            No active engagement
          </Text>
        ) : loading && credentials.length === 0 ? (
          <Group justify="center" p="xl">
            <Loader size="sm" color="cyan" />
          </Group>
        ) : credentials.length === 0 ? (
          <Stack align="center" justify="center" p="xl" gap="xs">
            <IconKey size={32} color="#6e7681" />
            <Text size="xs" c="dimmed" ta="center">
              No credentials discovered
            </Text>
          </Stack>
        ) : (
          <Stack gap={0} p={4}>
            {Array.from(groupedCredentials.entries()).map(
              ([domain, domainCreds]) => (
                <div key={domain}>
                  {/* Domain Header */}
                  <Group
                    gap="xs"
                    p="xs"
                    style={{
                      cursor: 'pointer',
                      background: '#1a1b1e',
                      borderRadius: 4,
                      marginBottom: 4,
                    }}
                    onClick={() => toggleDomain(domain)}
                  >
                    {expandedDomains.has(domain) ? (
                      <IconChevronDown size={14} color="#868e96" />
                    ) : (
                      <IconChevronRight size={14} color="#868e96" />
                    )}
                    <IconServer size={14} color="#868e96" />
                    <Text size="xs" fw={500} c="dimmed" tt="uppercase">
                      {domain}
                    </Text>
                    <Badge size="xs" variant="light" color="gray">
                      {domainCreds.length}
                    </Badge>
                  </Group>

                  {/* Credentials in Domain */}
                  <Collapse in={expandedDomains.has(domain)}>
                    <Stack gap={4} pl="md" pb="xs">
                      {domainCreds.map((cred) => (
                        <CredentialCard
                          key={cred.id}
                          credential={cred}
                          onAction={(actionId, target) =>
                            handleAction(cred, actionId, target)
                          }
                        />
                      ))}
                    </Stack>
                  </Collapse>
                </div>
              )
            )}
          </Stack>
        )}
      </ScrollArea>

      {/* Footer Stats */}
      <Group
        justify="space-between"
        p="xs"
        style={{ borderTop: '1px solid #373A40' }}
      >
        <Text size="xs" c="dimmed">
          Total: {stats.total}
        </Text>
        <Group gap={8}>
          <Group gap={4}>
            <IconCircleFilled size={6} color="#7ee787" />
            <Text size="xs" c="dimmed">
              {stats.cleartext} clear
            </Text>
          </Group>
          <Group gap={4}>
            <IconCircleFilled size={6} color="#ff7b72" />
            <Text size="xs" c="dimmed">
              {stats.admin} admin
            </Text>
          </Group>
        </Group>
      </Group>
    </Stack>
  );
}

/** Individual credential card */
interface CredentialCardProps {
  credential: Credential;
  onAction: (actionId: string, target?: string) => void;
}

function CredentialCard({ credential, onAction }: CredentialCardProps) {
  const Icon = CRED_TYPE_ICONS[credential.secretType] || IconKey;
  const color = CRED_TYPE_COLORS[credential.secretType] || 'gray';
  const label = CRED_TYPE_LABELS[credential.secretType] || credential.secretType;

  // Get applicable actions for this credential type
  const actions = getApplicableActions(credential.secretType);

  // Format display
  const displayAccount = credential.domain
    ? `${credential.domain}\\${credential.username}`
    : credential.username;

  // Mask secret for display
  const maskedSecret = credential.secretType === 'password'
    ? credential.secret.substring(0, 3) + '*'.repeat(Math.max(0, credential.secret.length - 3))
    : credential.secret.substring(0, 16) + '...';

  return (
    <Paper
      p={8}
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        borderRadius: 4,
      }}
    >
      <Group gap="xs" justify="space-between" wrap="nowrap">
        {/* Icon and Info */}
        <Group gap="xs" wrap="nowrap" style={{ flex: 1, overflow: 'hidden' }}>
          <ThemeIcon size="sm" variant="light" color={color} radius="sm">
            <Icon size={12} />
          </ThemeIcon>
          <Stack gap={2} style={{ flex: 1, overflow: 'hidden' }}>
            <Group gap={4} wrap="nowrap">
              <Text
                size="xs"
                fw={500}
                truncate
                style={{ fontFamily: 'JetBrains Mono, monospace' }}
              >
                {displayAccount}
              </Text>
              {credential.isAdmin && (
                <Badge size="xs" color="red" variant="filled">
                  Admin
                </Badge>
              )}
            </Group>
            <Group gap={4}>
              <Badge size="xs" variant="dot" color={color}>
                {label}
              </Badge>
              {credential.source && (
                <Text size="xs" c="dimmed" truncate>
                  via {credential.source}
                </Text>
              )}
            </Group>
          </Stack>
        </Group>

        {/* Actions */}
        <Group gap={4} wrap="nowrap">
          {/* Copy credential */}
          <CopyButton
            value={
              credential.secretType === 'password'
                ? `${credential.username}:${credential.secret}`
                : credential.secret
            }
          >
            {({ copied, copy }) => (
              <Tooltip label={copied ? 'Copied!' : 'Copy credential'}>
                <ActionIcon
                  variant="subtle"
                  color={copied ? 'green' : 'gray'}
                  size="sm"
                  onClick={copy}
                >
                  <IconCopy size={14} />
                </ActionIcon>
              </Tooltip>
            )}
          </CopyButton>

          {/* Action menu */}
          {actions.length > 0 && (
            <Menu shadow="md" width={200} position="bottom-end">
              <Menu.Target>
                <ActionIcon variant="subtle" color="gray" size="sm">
                  <IconDotsVertical size={14} />
                </ActionIcon>
              </Menu.Target>

              <Menu.Dropdown>
                <Menu.Label>Use Credential</Menu.Label>
                {actions.map((action) => (
                  <Menu.Item
                    key={action.id}
                    leftSection={<IconTerminal2 size={14} />}
                    onClick={() => onAction(action.id)}
                  >
                    {action.label}
                  </Menu.Item>
                ))}
                <Divider />
                <Menu.Label>Secret</Menu.Label>
                <Menu.Item disabled>
                  <Text
                    size="xs"
                    style={{ fontFamily: 'JetBrains Mono, monospace' }}
                    c="dimmed"
                  >
                    {maskedSecret}
                  </Text>
                </Menu.Item>
              </Menu.Dropdown>
            </Menu>
          )}
        </Group>
      </Group>

      {/* Validated Access Tags */}
      {credential.validatedAccess && credential.validatedAccess.length > 0 && (
        <Group gap={4} mt={6}>
          {credential.validatedAccess.map((access) => (
            <Badge key={access} size="xs" variant="outline" color="cyan">
              {access}
            </Badge>
          ))}
        </Group>
      )}
    </Paper>
  );
}
