import { useState, useMemo, useCallback } from 'react';
import {
  Paper,
  Text,
  Badge,
  Group,
  Stack,
  ScrollArea,
  ActionIcon,
  Box,
  Collapse,
  UnstyledButton,
  Center,
  Button,
} from '@mantine/core';

// Types matching ChainExplorerGraph
interface GraphNode {
  data: {
    id: string;
    label: string;
    name?: string;
    category?: string;
    subcategory?: string;
    description?: string;
    command?: string;
    tags?: string[];
    type?: string;
    hasRelationships?: boolean;
  };
}

interface ExpansionRecord {
  nodeId: string;
  parentNodeId: string | null;
  relationshipType?: string;
}

interface RelationshipsTreeProps {
  nodes: Map<string, GraphNode>;
  expandedNodes: Set<string>;
  expansionHistory: ExpansionRecord[];
  onNodeClick: (nodeId: string) => void;
  onNodeRemove: (nodeId: string) => void;
  onNodeSelect: (nodeId: string) => void;
  onClearAll?: () => void;
}

// Tree node structure for rendering
interface TreeNodeData {
  nodeId: string;
  node: GraphNode;
  children: TreeNodeData[];
  relationshipType?: string;
  depth: number;
}

// Get color for relationship type
const getRelationshipColor = (type?: string): string => {
  switch (type?.toLowerCase()) {
    case 'alternative':
      return 'yellow';
    case 'prerequisite':
      return 'red';
    case 'next_step':
      return 'green';
    default:
      return 'gray';
  }
};

// Format relationship type for display
const formatRelationshipType = (type?: string): string => {
  switch (type?.toLowerCase()) {
    case 'alternative':
      return 'ALT';
    case 'prerequisite':
      return 'PRE';
    case 'next_step':
      return 'NEXT';
    default:
      return type || '';
  }
};

// Individual tree node component
interface TreeNodeProps {
  treeNode: TreeNodeData;
  onNodeClick: (nodeId: string) => void;
  onNodeRemove: (nodeId: string) => void;
  onNodeSelect: (nodeId: string) => void;
  collapsedBranches: Set<string>;
  onToggleBranch: (nodeId: string) => void;
}

function TreeNode({
  treeNode,
  onNodeClick,
  onNodeRemove,
  onNodeSelect,
  collapsedBranches,
  onToggleBranch,
}: TreeNodeProps) {
  const { nodeId, node, children, relationshipType, depth } = treeNode;
  const hasChildren = children.length > 0;
  const isCollapsed = collapsedBranches.has(nodeId);
  const isRoot = depth === 0;

  return (
    <Box>
      <Group
        gap="xs"
        wrap="nowrap"
        style={{
          paddingLeft: depth * 20,
          paddingTop: 4,
          paddingBottom: 4,
          paddingRight: 8,
          borderRadius: 4,
          cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        className="tree-node-row"
      >
        {/* Expand/Collapse chevron */}
        {hasChildren ? (
          <ActionIcon
            size="xs"
            variant="subtle"
            color="gray"
            onClick={(e) => {
              e.stopPropagation();
              onToggleBranch(nodeId);
            }}
          >
            <Text size="xs" c="dimmed">
              {isCollapsed ? '>' : 'v'}
            </Text>
          </ActionIcon>
        ) : (
          <Box style={{ width: 22 }} /> // Spacer for alignment
        )}

        {/* Node name - clickable to highlight in graph */}
        <UnstyledButton
          onClick={() => onNodeClick(nodeId)}
          onDoubleClick={() => onNodeSelect(nodeId)}
          style={{ flex: 1, minWidth: 0 }}
        >
          <Text
            size="sm"
            truncate
            style={{
              fontWeight: isRoot ? 600 : 400,
              color: isRoot ? '#22c1c3' : 'inherit',
            }}
            title={node.data.name || node.data.label}
          >
            {node.data.name || node.data.label}
          </Text>
        </UnstyledButton>

        {/* Category badge */}
        {node.data.category && (
          <Badge size="xs" variant="light" color="blue">
            {node.data.category}
          </Badge>
        )}

        {/* Relationship type badge (not for roots) */}
        {relationshipType && !isRoot && (
          <Badge size="xs" variant="filled" color={getRelationshipColor(relationshipType)}>
            {formatRelationshipType(relationshipType)}
          </Badge>
        )}

        {/* Root indicator */}
        {isRoot && (
          <Badge size="xs" variant="outline" color="cyan">
            ROOT
          </Badge>
        )}

        {/* Remove button */}
        <ActionIcon
          size="xs"
          variant="subtle"
          color="red"
          onClick={(e) => {
            e.stopPropagation();
            onNodeRemove(nodeId);
          }}
          title="Remove node and descendants"
        >
          <Text size="xs">x</Text>
        </ActionIcon>
      </Group>

      {/* Children */}
      {hasChildren && (
        <Collapse in={!isCollapsed}>
          {children.map((child) => (
            <TreeNode
              key={child.nodeId}
              treeNode={child}
              onNodeClick={onNodeClick}
              onNodeRemove={onNodeRemove}
              onNodeSelect={onNodeSelect}
              collapsedBranches={collapsedBranches}
              onToggleBranch={onToggleBranch}
            />
          ))}
        </Collapse>
      )}
    </Box>
  );
}

export default function RelationshipsTree({
  nodes,
  expandedNodes,
  expansionHistory,
  onNodeClick,
  onNodeRemove,
  onNodeSelect,
  onClearAll,
}: RelationshipsTreeProps) {
  // Track collapsed branches in tree view (separate from graph expansion)
  const [collapsedBranches, setCollapsedBranches] = useState<Set<string>>(new Set());

  const toggleBranch = useCallback((nodeId: string) => {
    setCollapsedBranches((prev) => {
      const next = new Set(prev);
      if (next.has(nodeId)) {
        next.delete(nodeId);
      } else {
        next.add(nodeId);
      }
      return next;
    });
  }, []);

  // Build tree structure from expansion history
  const treeRoots = useMemo(() => {
    console.log('[RelationshipsTree] Building tree from:', {
      nodesCount: nodes.size,
      historyCount: expansionHistory.length,
    });

    // Find all root nodes (parentNodeId is null)
    const rootNodeIds = new Set<string>();
    const childMap = new Map<string, ExpansionRecord[]>();

    // Build parent -> children mapping from expansion history
    // Only nodes that were deliberately clicked/expanded appear in history
    expansionHistory.forEach((record) => {
      if (record.parentNodeId === null) {
        // Root nodes (initial commands or new search selections)
        rootNodeIds.add(record.nodeId);
      } else {
        // Child nodes (expanded from a parent)
        const children = childMap.get(record.parentNodeId) || [];
        children.push(record);
        childMap.set(record.parentNodeId, children);
      }
    });

    // NOTE: Don't add nodes that aren't in history - those are just visible connections
    // The tree should ONLY show deliberately expanded nodes

    // Recursive function to build tree
    const buildTreeNode = (
      nodeId: string,
      relationshipType: string | undefined,
      depth: number
    ): TreeNodeData | null => {
      const node = nodes.get(nodeId);
      if (!node) return null;

      const childRecords = childMap.get(nodeId) || [];
      const children: TreeNodeData[] = [];

      childRecords.forEach((record) => {
        const childNode = buildTreeNode(record.nodeId, record.relationshipType, depth + 1);
        if (childNode) {
          children.push(childNode);
        }
      });

      return {
        nodeId,
        node,
        children,
        relationshipType,
        depth,
      };
    };

    // Build tree from each root
    const roots: TreeNodeData[] = [];
    rootNodeIds.forEach((rootId) => {
      const rootRecord = expansionHistory.find((r) => r.nodeId === rootId);
      const tree = buildTreeNode(rootId, rootRecord?.relationshipType, 0);
      if (tree) {
        roots.push(tree);
      }
    });

    console.log('[RelationshipsTree] Built tree with roots:', roots.length);
    return roots;
  }, [nodes, expandedNodes, expansionHistory]);

  // Empty state - show when no nodes have been deliberately expanded
  if (expandedNodes.size === 0) {
    return (
      <Paper
        p="md"
        style={{
          background: '#25262b',
          border: '1px solid #373A40',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <Center style={{ flex: 1 }}>
          <Stack align="center" gap="sm">
            <Text c="dimmed" size="sm" ta="center">
              No nodes in tree yet
            </Text>
            <Text c="dimmed" size="xs" ta="center" style={{ maxWidth: 250 }}>
              Click nodes in the Relationship Explorer to expand and build your tree
            </Text>
          </Stack>
        </Center>
      </Paper>
    );
  }

  return (
    <Paper
      p="md"
      style={{
        background: '#25262b',
        border: '1px solid #373A40',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Header */}
      <Group justify="space-between" mb="sm">
        <Group gap="xs">
          <Text size="sm" fw={600}>
            Relationships Tree
          </Text>
          <Badge size="xs" variant="light" color="cyan">
            {expandedNodes.size} expanded
          </Badge>
          <Badge size="xs" variant="light" color="gray">
            {treeRoots.length} roots
          </Badge>
        </Group>
        {onClearAll && (
          <Button size="xs" variant="subtle" color="red" onClick={onClearAll}>
            Clear All
          </Button>
        )}
      </Group>

      {/* Legend */}
      <Group gap="md" mb="sm" wrap="wrap">
        <Group gap="xs">
          <Badge size="xs" variant="filled" color="yellow">
            ALT
          </Badge>
          <Text size="xs" c="dimmed">
            Alternative
          </Text>
        </Group>
        <Group gap="xs">
          <Badge size="xs" variant="filled" color="red">
            PRE
          </Badge>
          <Text size="xs" c="dimmed">
            Prerequisite
          </Text>
        </Group>
        <Group gap="xs">
          <Badge size="xs" variant="filled" color="green">
            NEXT
          </Badge>
          <Text size="xs" c="dimmed">
            Next Step
          </Text>
        </Group>
      </Group>

      {/* Tree content */}
      <ScrollArea style={{ flex: 1 }} offsetScrollbars>
        <Stack gap={0}>
          {treeRoots.map((root) => (
            <TreeNode
              key={root.nodeId}
              treeNode={root}
              onNodeClick={onNodeClick}
              onNodeRemove={onNodeRemove}
              onNodeSelect={onNodeSelect}
              collapsedBranches={collapsedBranches}
              onToggleBranch={toggleBranch}
            />
          ))}
        </Stack>
      </ScrollArea>

      {/* Footer hint */}
      <Text size="xs" c="dimmed" mt="sm" ta="center">
        Click to highlight in graph | Double-click to view details
      </Text>

      {/* Hover styles */}
      <style>
        {`
          .tree-node-row:hover {
            background: rgba(255, 255, 255, 0.05);
          }
        `}
      </style>
    </Paper>
  );
}
