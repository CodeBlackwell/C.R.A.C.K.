import { Accordion, Badge, Group, Stack, Text, UnstyledButton } from '@mantine/core';
import { IconShield, IconSearch, IconSword, IconWorld, IconTransfer, IconKey, IconRoute, IconServer, IconTool, IconDatabase, IconNetwork, IconTerminal, IconLock, IconFolder } from '@tabler/icons-react';
import { CategoryHierarchy } from '../types/category';

interface NestedCategoryAccordionProps {
  hierarchies: CategoryHierarchy[];
  selectedCategory: string | null;
  selectedSubcategory: string | null;
  onSelect: (category: string, subcategory: string) => void;
  loading?: boolean;
}

// Map category names to icons
const getCategoryIcon = (category: string) => {
  const iconMap: Record<string, any> = {
    'active-directory': IconShield,
    'enumeration': IconSearch,
    'exploitation': IconSword,
    'web': IconWorld,
    'file-transfer': IconTransfer,
    'password-attacks': IconKey,
    'pivoting': IconRoute,
    'tunneling': IconRoute,
    'post-exploit': IconServer,
    'post-exploitation': IconServer,
    'privilege-escalation': IconLock,
    'recon': IconNetwork,
    'monitoring': IconTerminal,
    'utilities': IconTool,
    'custom': IconDatabase,
  };

  const IconComponent = iconMap[category.toLowerCase()] || IconFolder;
  return <IconComponent size={18} />;
};

// Get color for category badge
const getCategoryColor = (category: string): string => {
  const colorMap: Record<string, string> = {
    'active-directory': 'violet',
    'enumeration': 'blue',
    'exploitation': 'red',
    'web': 'cyan',
    'file-transfer': 'teal',
    'password-attacks': 'orange',
    'pivoting': 'grape',
    'tunneling': 'grape',
    'post-exploit': 'green',
    'post-exploitation': 'green',
    'privilege-escalation': 'yellow',
    'recon': 'indigo',
    'monitoring': 'gray',
    'utilities': 'pink',
    'custom': 'lime',
  };

  return colorMap[category.toLowerCase()] || 'gray';
};

export default function NestedCategoryAccordion({
  hierarchies,
  selectedCategory,
  selectedSubcategory,
  onSelect,
  loading = false,
}: NestedCategoryAccordionProps) {
  if (loading) {
    return (
      <Stack gap="xs" p="md">
        <Text size="sm" c="dimmed">Loading categories...</Text>
      </Stack>
    );
  }

  if (hierarchies.length === 0) {
    return (
      <Stack gap="xs" p="md">
        <Text size="sm" c="dimmed">No categories found</Text>
      </Stack>
    );
  }

  return (
    <Accordion
      multiple
      variant="contained"
      styles={{
        item: {
          marginBottom: 4,
        },
        control: {
          padding: '8px 12px',
        },
        content: {
          padding: 0,
        },
      }}
    >
      {hierarchies.map((hierarchy) => (
        <Accordion.Item key={hierarchy.category} value={hierarchy.category}>
          <Accordion.Control>
            <Group gap="xs" wrap="nowrap">
              {getCategoryIcon(hierarchy.category)}
              <Text size="sm" fw={500} style={{ flex: 1 }}>
                {hierarchy.category}
              </Text>
              <Badge
                size="sm"
                variant="light"
                color={getCategoryColor(hierarchy.category)}
              >
                {hierarchy.totalCount}
              </Badge>
            </Group>
          </Accordion.Control>
          <Accordion.Panel>
            <Stack gap={2}>
              {hierarchy.subcategories.map((subcategory) => {
                const isSelected =
                  selectedCategory === hierarchy.category &&
                  selectedSubcategory === subcategory.name;

                return (
                  <UnstyledButton
                    key={subcategory.name}
                    onClick={() => onSelect(hierarchy.category, subcategory.name)}
                    style={{
                      padding: '8px 16px 8px 32px',
                      backgroundColor: isSelected
                        ? 'var(--mantine-color-blue-light)'
                        : 'transparent',
                      borderRadius: 4,
                      transition: 'background-color 0.15s ease',
                    }}
                    styles={{
                      root: {
                        '&:hover': {
                          backgroundColor: isSelected
                            ? 'var(--mantine-color-blue-light)'
                            : 'var(--mantine-color-gray-light)',
                        },
                      },
                    }}
                  >
                    <Group gap="xs" wrap="nowrap" justify="space-between">
                      <Text
                        size="sm"
                        fw={isSelected ? 600 : 400}
                        c={isSelected ? 'blue' : 'dimmed'}
                      >
                        {subcategory.name}
                      </Text>
                      <Badge
                        size="xs"
                        variant={isSelected ? 'filled' : 'light'}
                        color={isSelected ? 'blue' : 'gray'}
                      >
                        {subcategory.count}
                      </Badge>
                    </Group>
                  </UnstyledButton>
                );
              })}
            </Stack>
          </Accordion.Panel>
        </Accordion.Item>
      ))}
    </Accordion>
  );
}
