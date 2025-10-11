"""
Phase management and progression
"""

from typing import Dict, Any, List
from .definitions import PHASES, get_next_phase
from ..core.task_tree import TaskNode
from ..core.events import EventBus


class PhaseManager:
    """Manage phase progression and task creation"""

    @classmethod
    def get_initial_tasks(cls, phase_name: str, target: str, **kwargs) -> List[TaskNode]:
        """Get initial tasks for phase

        Args:
            phase_name: Phase name
            target: Target IP/hostname
            **kwargs: Additional context (e.g., discovered ports)

        Returns:
            List of TaskNode objects
        """
        phase = PHASES.get(phase_name)
        if not phase:
            raise ValueError(f"Unknown phase: {phase_name}")

        tasks = []
        for task_def in phase.get('initial_tasks', []):
            task = cls._create_task_from_definition(task_def, target, **kwargs)
            if task:
                tasks.append(task)

        return tasks

    @classmethod
    def _create_task_from_definition(cls, task_def: Dict[str, Any], target: str, **kwargs) -> TaskNode:
        """Create TaskNode from definition

        Args:
            task_def: Task definition dict
            target: Target IP/hostname
            **kwargs: Context for placeholder replacement

        Returns:
            TaskNode instance
        """
        task = TaskNode(
            task_id=task_def['id'],
            name=task_def['name'],
            task_type=task_def.get('type', 'command')
        )

        # Copy metadata
        task.metadata.update(task_def.get('metadata', {}))

        # Copy scan profile references (NEW - for scan type tasks)
        if 'scan_profiles' in task_def:
            task.metadata['scan_profiles'] = task_def['scan_profiles']
        if 'default_profile' in task_def:
            task.metadata['default_profile'] = task_def['default_profile']

        # Replace placeholders in command
        if 'command' in task.metadata and task.metadata['command']:
            command = task.metadata['command']
            command = command.replace('{TARGET}', target)

            # Replace {PORTS} with discovered ports if available
            if '{PORTS}' in command and 'ports' in kwargs:
                ports_str = ','.join(str(p) for p in kwargs['ports'])
                command = command.replace('{PORTS}', ports_str)

            task.metadata['command'] = command

        return task

    @classmethod
    def check_advancement(cls, current_phase: str, state: Dict[str, Any]) -> bool:
        """Check if can advance to next phase

        Args:
            current_phase: Current phase name
            state: Target state dictionary

        Returns:
            True if exit condition met
        """
        phase = PHASES.get(current_phase)
        if not phase:
            return False

        exit_condition = phase.get('exit_condition')
        if not exit_condition:
            return False

        try:
            return exit_condition(state)
        except Exception as e:
            return False

    @classmethod
    def advance_phase(cls, current_phase: str, profile) -> str:
        """Advance to next phase

        Args:
            current_phase: Current phase name
            profile: TargetProfile instance

        Returns:
            New phase name
        """
        next_phase = get_next_phase(current_phase)
        if not next_phase:
            return current_phase  # Already at final phase

        # Check exit condition
        if not cls.check_advancement(current_phase, profile.to_dict()):
            return current_phase  # Can't advance yet

        # Advance phase
        profile.set_phase(next_phase)

        # Add initial tasks for new phase
        context = {}
        if next_phase == 'service-detection' and profile.ports:
            context['ports'] = list(profile.ports.keys())

        initial_tasks = cls.get_initial_tasks(next_phase, profile.target, **context)
        for task in initial_tasks:
            profile.add_task(task)

        return next_phase

    @classmethod
    def get_phase_info(cls, phase_name: str) -> Dict[str, Any]:
        """Get phase information

        Args:
            phase_name: Phase name

        Returns:
            Phase definition dict
        """
        return PHASES.get(phase_name, {})

    @classmethod
    def is_dynamic_phase(cls, phase_name: str) -> bool:
        """Check if phase uses dynamic task generation

        Args:
            phase_name: Phase name

        Returns:
            True if phase is plugin-driven
        """
        phase = PHASES.get(phase_name, {})
        return phase.get('dynamic', False)
