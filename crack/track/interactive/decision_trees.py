"""
Decision Tree System - Navigate through decision trees

Provides:
- DecisionNode: Single decision point with choices and actions
- DecisionTree: Collection of nodes with navigation logic
- Navigation history (back button support)
- Context-aware node selection
"""

from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class Choice:
    """Single choice in a decision node"""
    id: str
    label: str
    description: str = None
    next_node: str = None  # ID of next node, or None for action
    action: Callable = None  # Function to execute
    requires: Dict[str, Any] = field(default_factory=dict)  # Required context


class DecisionNode:
    """Single decision point in a decision tree"""

    def __init__(
        self,
        node_id: str,
        question: str,
        choices: List[Choice],
        required_context: Dict[str, Any] = None
    ):
        """
        Args:
            node_id: Unique identifier for this node
            question: Question/prompt to display
            choices: List of Choice objects
            required_context: Context requirements to show this node
        """
        self.id = node_id
        self.question = question
        self.choices = choices
        self.required_context = required_context or {}

    def is_available(self, context: Dict[str, Any]) -> bool:
        """
        Check if this node should be shown based on context

        Args:
            context: Current context (profile state, etc.)

        Returns:
            True if node is available
        """
        for key, required_value in self.required_context.items():
            ctx_value = context.get(key)

            # Handle callable requirements (e.g., lambda functions)
            if callable(required_value):
                if not required_value(ctx_value):
                    return False
            # Direct comparison
            elif ctx_value != required_value:
                return False

        return True

    def get_available_choices(self, context: Dict[str, Any]) -> List[Choice]:
        """
        Get choices that are available based on context

        Args:
            context: Current context

        Returns:
            List of available Choice objects
        """
        available = []

        for choice in self.choices:
            # Check if choice requirements are met
            if not choice.requires:
                available.append(choice)
                continue

            # Check each requirement
            meets_requirements = True
            for key, required_value in choice.requires.items():
                ctx_value = context.get(key)

                if callable(required_value):
                    if not required_value(ctx_value):
                        meets_requirements = False
                        break
                elif ctx_value != required_value:
                    meets_requirements = False
                    break

            if meets_requirements:
                available.append(choice)

        return available

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary format for menu generation"""
        return {
            'id': self.id,
            'question': self.question,
            'choices': [
                {
                    'id': c.id,
                    'label': c.label,
                    'description': c.description
                }
                for c in self.choices
            ]
        }


class DecisionTree:
    """Decision tree with navigation"""

    def __init__(self, tree_id: str, root_node: DecisionNode):
        """
        Args:
            tree_id: Unique identifier for this tree
            root_node: Root DecisionNode
        """
        self.id = tree_id
        self.nodes: Dict[str, DecisionNode] = {}
        self.root = root_node
        self.current_node = root_node

        # Navigation history for back button
        self.history: List[str] = [root_node.id]

        # Register root
        self.nodes[root_node.id] = root_node

    def add_node(self, node: DecisionNode):
        """
        Add node to tree

        Args:
            node: DecisionNode to add
        """
        self.nodes[node.id] = node

    def get_node(self, node_id: str) -> Optional[DecisionNode]:
        """
        Get node by ID

        Args:
            node_id: Node identifier

        Returns:
            DecisionNode or None
        """
        return self.nodes.get(node_id)

    def navigate_to(self, node_id: str, context: Dict[str, Any]) -> Optional[DecisionNode]:
        """
        Navigate to specific node

        Args:
            node_id: Target node ID
            context: Current context

        Returns:
            Target node if available, None otherwise
        """
        target_node = self.get_node(node_id)

        if not target_node:
            return None

        # Check if node is available
        if not target_node.is_available(context):
            return None

        # Update current node and history
        self.current_node = target_node
        self.history.append(node_id)

        return target_node

    def navigate_forward(self, choice: Choice, context: Dict[str, Any]) -> Optional[DecisionNode]:
        """
        Navigate forward based on choice

        Args:
            choice: Selected Choice object
            context: Current context

        Returns:
            Next node or None if action choice
        """
        if not choice.next_node:
            # This is an action choice, not navigation
            return None

        return self.navigate_to(choice.next_node, context)

    def navigate_back(self) -> Optional[DecisionNode]:
        """
        Navigate back to previous node

        Returns:
            Previous node or None if at root
        """
        if len(self.history) <= 1:
            # Already at root
            return None

        # Remove current node from history
        self.history.pop()

        # Get previous node
        prev_node_id = self.history[-1]
        self.current_node = self.nodes[prev_node_id]

        return self.current_node

    def reset(self):
        """Reset tree to root node"""
        self.current_node = self.root
        self.history = [self.root.id]

    def get_current_choices(self, context: Dict[str, Any]) -> List[Choice]:
        """
        Get available choices for current node

        Args:
            context: Current context

        Returns:
            List of available choices
        """
        return self.current_node.get_available_choices(context)


class DecisionTreeFactory:
    """Factory for creating common decision trees"""

    @staticmethod
    def create_phase_tree(phase: str) -> Optional[DecisionTree]:
        """
        Create decision tree for specific phase

        Args:
            phase: Phase name (discovery, service-specific, exploitation, post-exploit)

        Returns:
            DecisionTree for the phase
        """
        if phase == 'discovery':
            return DecisionTreeFactory.create_discovery_tree()
        elif phase in ['service-detection', 'service-specific']:
            return DecisionTreeFactory.create_enumeration_tree()
        elif phase == 'exploitation':
            return DecisionTreeFactory.create_exploitation_tree()
        elif phase == 'post-exploit':
            return DecisionTreeFactory.create_post_exploit_tree()

        return None

    @staticmethod
    def create_discovery_tree() -> DecisionTree:
        """Create discovery phase decision tree - DYNAMIC from scan profiles"""
        from ..core.scan_profiles import get_profiles_for_phase

        # Load available scan profiles dynamically
        profiles = get_profiles_for_phase('discovery', 'lab')

        # Convert profiles to choices
        root_choices = []
        for profile in profiles:
            root_choices.append(Choice(
                id=f'scan-{profile["id"]}',
                label=profile['name'],
                description=f"{profile['use_case']} ({profile['estimated_time']})",
                action='execute_scan'  # Generic handler
            ))

        # Add non-scan options
        root_choices.extend([
            Choice(
                id='custom-scan',
                label='Custom scan command',
                description='Enter your own nmap command',
                action='execute_custom_scan'
            ),
            Choice(
                id='import-scan',
                label='Import existing scan results',
                description='Load nmap XML/gnmap file',
                action='import_scan'
            ),
            Choice(
                id='manual-entry',
                label='Manual port entry',
                description='Manually specify ports',
                action='manual_port_entry'
            )
        ])

        root = DecisionNode(
            node_id='discovery-root',
            question='No ports discovered yet. Choose scan strategy:',
            choices=root_choices,
            required_context={'has_ports': False}
        )

        tree = DecisionTree('discovery', root)
        return tree

    @staticmethod
    def create_enumeration_tree() -> DecisionTree:
        """Create service enumeration decision tree"""
        root_choices = [
            Choice(
                id='auto-enumerate',
                label='Auto-enumerate all services',
                description='Run all recommended enumeration tasks',
                action='enumerate_all'
            ),
            Choice(
                id='select-service',
                label='Choose specific service',
                description='Select which service to enumerate',
                next_node='service-selection'
            ),
            Choice(
                id='quick-wins',
                label='Show quick wins only',
                description='Fast, high-value tasks',
                action='show_quick_wins'
            )
        ]

        root = DecisionNode(
            node_id='enum-root',
            question='Services discovered. Select enumeration approach:',
            choices=root_choices
        )

        tree = DecisionTree('enumeration', root)
        return tree

    @staticmethod
    def create_exploitation_tree() -> DecisionTree:
        """Create exploitation phase decision tree"""
        root_choices = [
            Choice(
                id='research',
                label='Research exploits',
                description='Search exploitdb, GitHub, Metasploit',
                action='research_exploits'
            ),
            Choice(
                id='test-vuln',
                label='Test vulnerability',
                description='Verify exploit works',
                action='test_vulnerability'
            ),
            Choice(
                id='document',
                label='Document finding',
                description='Record vulnerability details',
                action='document_finding'
            )
        ]

        root = DecisionNode(
            node_id='exploit-root',
            question='Vulnerabilities found. Next steps:',
            choices=root_choices
        )

        tree = DecisionTree('exploitation', root)
        return tree

    @staticmethod
    def create_post_exploit_tree() -> DecisionTree:
        """Create post-exploitation decision tree"""
        root_choices = [
            Choice(
                id='privesc-enum',
                label='Privilege escalation enumeration',
                description='LinPEAS, WinPEAS, manual checks',
                action='privesc_enum'
            ),
            Choice(
                id='find-flags',
                label='Search for flags',
                description='Local.txt and proof.txt',
                action='find_flags'
            ),
            Choice(
                id='persistence',
                label='Establish persistence',
                description='Backdoors, scheduled tasks',
                action='setup_persistence'
            ),
            Choice(
                id='lateral-movement',
                label='Lateral movement',
                description='Pivot to other systems',
                action='lateral_movement'
            ),
            Choice(
                id='exfiltration',
                label='Data exfiltration',
                description='Transfer files and data',
                action='exfiltrate_data'
            )
        ]

        root = DecisionNode(
            node_id='post-exploit-root',
            question='Shell obtained. Post-exploitation actions:',
            choices=root_choices
        )

        tree = DecisionTree('post-exploit', root)
        return tree
