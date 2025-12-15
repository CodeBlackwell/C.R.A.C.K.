import { useMemo, useState } from 'react';
import { Text, Code, Box, Stack, useMantineTheme, ActionIcon, Tooltip, Alert } from '@mantine/core';
import { IconCopy, IconCheck, IconAlertCircle, IconInfoCircle } from '@tabler/icons-react';
import { parseDescription, ContentBlock } from '../utils/descriptionParser';

interface StyledDescriptionProps {
  description: string;
}

/**
 * Renders a styled description with proper syntax highlighting and formatting
 * Uses the theme system for all colors
 */
export default function StyledDescription({ description }: StyledDescriptionProps) {
  const theme = useMantineTheme();
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  // Parse description into content blocks
  const blocks = useMemo(() => parseDescription(description), [description]);

  // Get theme color from semantic mapping
  const getThemeColor = (colorPath: string): string => {
    const parts = colorPath.split('.');
    if (parts.length === 2) {
      const [colorName, shade] = parts;
      const color = theme.colors[colorName];
      if (color && Array.isArray(color)) {
        return color[parseInt(shade)];
      }
    }
    return colorPath;
  };

  // Copy text to clipboard
  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
    });
  };

  // Helper to split keyword from content
  const splitKeywordContent = (fullContent: string, keyword?: string) => {
    if (!keyword) return { keyword: '', content: fullContent };

    // Find the keyword in the content (case-insensitive)
    const keywordPattern = new RegExp(`^(${keyword}:?)\\s*`, 'i');
    const match = fullContent.match(keywordPattern);

    if (match) {
      const keywordPart = match[1];
      const contentPart = fullContent.slice(match[0].length);
      return { keyword: keywordPart, content: contentPart };
    }

    return { keyword: '', content: fullContent };
  };

  // Render individual content block
  const renderBlock = (block: ContentBlock, index: number) => {
    const stepColors = theme.other.stepContent;

    switch (block.type) {
      case 'major-header': {
        const { keyword, content } = splitKeywordContent(block.content, block.metadata?.keyword);
        return (
          <Text
            key={index}
            size="md"
            fw={700}
            mt={index === 0 ? 0 : 'md'}
            mb="xs"
          >
            <Text component="span" c={getThemeColor(stepColors.majorHeader)}>
              {keyword}
            </Text>
            {content && (
              <Text component="span" c="gray.4" ml={6}>
                {content}
              </Text>
            )}
          </Text>
        );
      }

      case 'subsection-header': {
        const { keyword, content } = splitKeywordContent(block.content, block.metadata?.keyword);
        return (
          <Text
            key={index}
            size="sm"
            fw={600}
            mt="sm"
            mb="xs"
          >
            <Text component="span" c={getThemeColor(stepColors.subsectionHeader)}>
              {keyword}
            </Text>
            {content && (
              <Text component="span" c="gray.5" ml={6}>
                {content}
              </Text>
            )}
          </Text>
        );
      }

      case 'emphasis': {
        const { keyword, content } = splitKeywordContent(block.content, block.metadata?.keyword);
        return (
          <Text
            key={index}
            size="sm"
            fw={600}
            mt="xs"
            mb="xs"
          >
            <Text component="span" c={getThemeColor(stepColors.emphasis)}>
              {keyword}
            </Text>
            {content && (
              <Text component="span" c="gray.3" ml={6}>
                {content}
              </Text>
            )}
          </Text>
        );
      }

      case 'success': {
        const { keyword, content } = splitKeywordContent(block.content, block.metadata?.keyword);
        return (
          <Text
            key={index}
            size="sm"
            mt="xs"
            mb="xs"
          >
            <Text component="span" c={getThemeColor(stepColors.success)} fw={600}>
              ✓ {keyword}
            </Text>
            {content && (
              <Text component="span" c="gray.4" ml={6}>
                {content}
              </Text>
            )}
          </Text>
        );
      }

      case 'failure': {
        const { keyword, content } = splitKeywordContent(block.content, block.metadata?.keyword);
        return (
          <Text
            key={index}
            size="sm"
            mt="xs"
            mb="xs"
          >
            <Text component="span" c={getThemeColor(stepColors.failure)} fw={600}>
              ✗ {keyword}
            </Text>
            {content && (
              <Text component="span" c="gray.4" ml={6}>
                {content}
              </Text>
            )}
          </Text>
        );
      }

      case 'warning': {
        const { keyword, content } = splitKeywordContent(block.content, block.metadata?.keyword);
        return (
          <Alert
            key={index}
            icon={<IconAlertCircle size={16} />}
            color="yellow"
            variant="light"
            styles={{
              root: {
                backgroundColor: theme.colors.yellow[9],
                borderColor: theme.colors.yellow[7],
              },
            }}
            mt="xs"
            mb="xs"
          >
            <Text size="sm">
              <Text component="span" c={getThemeColor(stepColors.warning)} fw={600}>
                {keyword}
              </Text>
              {content && (
                <Text component="span" c="gray.3" ml={6}>
                  {content}
                </Text>
              )}
            </Text>
          </Alert>
        );
      }

      case 'info': {
        const { keyword, content } = splitKeywordContent(block.content, block.metadata?.keyword);
        return (
          <Alert
            key={index}
            icon={<IconInfoCircle size={16} />}
            color="blue"
            variant="light"
            styles={{
              root: {
                backgroundColor: theme.colors.blue[9],
                borderColor: theme.colors.blue[7],
              },
            }}
            mt="xs"
            mb="xs"
          >
            <Text size="sm">
              <Text component="span" c={getThemeColor(stepColors.info)} fw={600}>
                {keyword}
              </Text>
              {content && (
                <Text component="span" c="gray.3" ml={6}>
                  {content}
                </Text>
              )}
            </Text>
          </Alert>
        );
      }

      case 'command':
        return (
          <Box key={index} mt="xs" mb="xs" style={{ position: 'relative' }}>
            <Code
              block
              style={{
                backgroundColor: getThemeColor(stepColors.commandBg),
                color: getThemeColor(stepColors.commandText),
                padding: '8px 40px 8px 12px',
                borderRadius: theme.radius.sm,
                border: `1px solid ${theme.colors.green[9]}`,
                fontSize: '0.85rem',
                position: 'relative',
              }}
            >
              {block.content}
            </Code>
            <Tooltip label={copiedIndex === index ? 'Copied!' : 'Copy command'}>
              <ActionIcon
                size="sm"
                variant="subtle"
                color="gray"
                onClick={() => copyToClipboard(block.content, index)}
                style={{
                  position: 'absolute',
                  right: 8,
                  top: 8,
                }}
              >
                {copiedIndex === index ? <IconCheck size={14} /> : <IconCopy size={14} />}
              </ActionIcon>
            </Tooltip>
          </Box>
        );

      case 'code-block':
        return (
          <Box key={index} mt="xs" mb="xs" style={{ position: 'relative' }}>
            <Code
              block
              style={{
                backgroundColor: getThemeColor(stepColors.codeBlockBg),
                color: theme.colors.gray[3],
                padding: '12px 40px 12px 12px',
                borderRadius: theme.radius.sm,
                border: `1px solid ${theme.colors.dark[4]}`,
                fontSize: '0.85rem',
                whiteSpace: 'pre',
                overflowX: 'auto',
              }}
            >
              {block.content}
            </Code>
            <Tooltip label={copiedIndex === index ? 'Copied!' : 'Copy code'}>
              <ActionIcon
                size="sm"
                variant="subtle"
                color="gray"
                onClick={() => copyToClipboard(block.content, index)}
                style={{
                  position: 'absolute',
                  right: 8,
                  top: 12,
                }}
              >
                {copiedIndex === index ? <IconCheck size={14} /> : <IconCopy size={14} />}
              </ActionIcon>
            </Tooltip>
          </Box>
        );

      case 'list-item':
        return (
          <Box key={index} ml="md" mt={4}>
            <Text size="sm" c="dimmed">
              <Text
                component="span"
                c={getThemeColor(stepColors.listBullet)}
                fw={600}
                mr={6}
              >
                {block.metadata?.prefix || '•'}
              </Text>
              {block.content}
            </Text>
          </Box>
        );

      case 'prose':
      default:
        return (
          <Text
            key={index}
            size="sm"
            c="dimmed"
            mt="xs"
            style={{ whiteSpace: 'pre-wrap' }}
          >
            {block.content}
          </Text>
        );
    }
  };

  return (
    <Stack gap="xs">
      {blocks.map((block, index) => renderBlock(block, index))}
    </Stack>
  );
}
