/**
 * TerminalContextMenu - Right-click context menu for terminal
 *
 * Provides Copy, Paste, Select All, and PRISM scan options.
 */

import { Menu, Portal, Text } from '@mantine/core';
import {
  IconCopy,
  IconClipboard,
  IconSelectAll,
  IconScan,
} from '@tabler/icons-react';

interface TerminalContextMenuProps {
  opened: boolean;
  position: { x: number; y: number };
  selection: string;
  onClose: () => void;
  onCopy: () => void;
  onPaste: () => void;
  onSelectAll: () => void;
  onPrismScan: () => void;
}

export function TerminalContextMenu({
  opened,
  position,
  selection,
  onClose,
  onCopy,
  onPaste,
  onSelectAll,
  onPrismScan,
}: TerminalContextMenuProps) {
  if (!opened) return null;

  const hasSelection = selection.length > 0;
  const truncatedSelection =
    selection.length > 40 ? `${selection.substring(0, 40)}...` : selection;

  return (
    <Portal>
      <div
        style={{
          position: 'fixed',
          top: position.y,
          left: position.x,
          zIndex: 9999,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <Menu
          opened={opened}
          onClose={onClose}
          position="bottom-start"
          withinPortal={false}
          styles={{
            dropdown: {
              background: '#25262b',
              border: '1px solid #373a40',
              boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
            },
            item: {
              '&[data-hovered]': {
                background: '#373a40',
              },
            },
          }}
        >
          <Menu.Target>
            <div style={{ width: 1, height: 1 }} />
          </Menu.Target>
          <Menu.Dropdown>
            <Menu.Item
              leftSection={<IconCopy size={14} />}
              rightSection={
                <Text size="xs" c="dimmed">
                  Ctrl+Shift+C
                </Text>
              }
              disabled={!hasSelection}
              onClick={() => {
                onCopy();
                onClose();
              }}
            >
              Copy
            </Menu.Item>

            <Menu.Item
              leftSection={<IconClipboard size={14} />}
              rightSection={
                <Text size="xs" c="dimmed">
                  Ctrl+Shift+V
                </Text>
              }
              onClick={() => {
                onPaste();
                onClose();
              }}
            >
              Paste
            </Menu.Item>

            <Menu.Item
              leftSection={<IconSelectAll size={14} />}
              onClick={() => {
                onSelectAll();
                onClose();
              }}
            >
              Select All
            </Menu.Item>

            <Menu.Divider />

            <Menu.Item
              leftSection={<IconScan size={14} />}
              rightSection={
                <Text size="xs" c="dimmed">
                  Ctrl+Shift+P
                </Text>
              }
              disabled={!hasSelection}
              onClick={() => {
                onPrismScan();
                onClose();
              }}
            >
              <div>
                <Text size="sm">Scan with PRISM</Text>
                {hasSelection && (
                  <Text size="xs" c="dimmed" lineClamp={1}>
                    {truncatedSelection}
                  </Text>
                )}
              </div>
            </Menu.Item>
          </Menu.Dropdown>
        </Menu>
      </div>
    </Portal>
  );
}
