/**
 * ExportReportModal - Modal for exporting engagement reports
 *
 * Allows user to select format and options before export.
 */

import { useState } from 'react';
import {
  Modal,
  Text,
  Group,
  Stack,
  Button,
  SegmentedControl,
  Checkbox,
  Alert,
} from '@mantine/core';
import {
  IconFileExport,
  IconMarkdown,
  IconJson,
  IconAlertCircle,
  IconCheck,
} from '@tabler/icons-react';

interface ExportReportModalProps {
  /** Whether the modal is open */
  opened: boolean;
  /** Called when modal should close */
  onClose: () => void;
  /** Engagement ID to export */
  engagementId: string;
  /** Engagement name for display */
  engagementName: string;
}

export function ExportReportModal({
  opened,
  onClose,
  engagementId,
  engagementName,
}: ExportReportModalProps) {
  const [format, setFormat] = useState<'markdown' | 'json'>('markdown');
  const [includeTimeline, setIncludeTimeline] = useState(true);
  const [includeCredentials, setIncludeCredentials] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleExport = async () => {
    setExporting(true);
    setError(null);
    setSuccess(null);

    try {
      const result = await window.electronAPI.reportExport(engagementId, {
        format,
        includeTimeline,
        includeCredentials,
      });

      if (result.success) {
        setSuccess(`Report saved to: ${result.outputPath}`);
        // Close after a brief delay
        setTimeout(() => {
          onClose();
          setSuccess(null);
        }, 2000);
      } else if (result.canceled) {
        // User canceled the save dialog, do nothing
      } else {
        setError(result.error || 'Export failed');
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setExporting(false);
    }
  };

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={
        <Group gap="xs">
          <IconFileExport size={20} />
          <Text fw={600}>Export Report</Text>
        </Group>
      }
      size="sm"
      centered
    >
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          Export report for: <Text span fw={500} c="white">{engagementName}</Text>
        </Text>

        {error && (
          <Alert
            icon={<IconAlertCircle size={16} />}
            color="red"
            withCloseButton
            onClose={() => setError(null)}
          >
            {error}
          </Alert>
        )}

        {success && (
          <Alert
            icon={<IconCheck size={16} />}
            color="green"
          >
            {success}
          </Alert>
        )}

        {/* Format Selection */}
        <Stack gap={4}>
          <Text size="sm" fw={500}>Format</Text>
          <SegmentedControl
            value={format}
            onChange={(val) => setFormat(val as 'markdown' | 'json')}
            data={[
              {
                value: 'markdown',
                label: (
                  <Group gap={6} justify="center">
                    <IconMarkdown size={16} />
                    <span>Markdown</span>
                  </Group>
                ),
              },
              {
                value: 'json',
                label: (
                  <Group gap={6} justify="center">
                    <IconJson size={16} />
                    <span>JSON</span>
                  </Group>
                ),
              },
            ]}
            fullWidth
          />
        </Stack>

        {/* Options */}
        <Stack gap="xs">
          <Text size="sm" fw={500}>Options</Text>
          <Checkbox
            label="Include timeline appendix"
            description="Chronological list of all events"
            checked={includeTimeline}
            onChange={(e) => setIncludeTimeline(e.currentTarget.checked)}
          />
          <Checkbox
            label="Include credentials section"
            description="Uncheck to redact for sharing"
            checked={includeCredentials}
            onChange={(e) => setIncludeCredentials(e.currentTarget.checked)}
          />
        </Stack>

        {/* Actions */}
        <Group justify="flex-end" mt="md">
          <Button variant="subtle" onClick={onClose}>
            Cancel
          </Button>
          <Button
            leftSection={<IconFileExport size={16} />}
            onClick={handleExport}
            loading={exporting}
          >
            Export
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

export default ExportReportModal;
