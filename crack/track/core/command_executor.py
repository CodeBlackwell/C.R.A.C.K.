"""
Command Executor - Abstraction layer for command execution strategies

Strategy pattern implementation for flexible command execution.
Supports both subprocess (current) and screened terminal (new) modes.
"""

import subprocess
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from .terminal import ScreenedTerminal, CommandResult
from .task_tree import TaskNode
from .events import EventBus


class ExecutionResult:
    """Unified result from any executor strategy"""

    def __init__(self, task: TaskNode, command: str):
        self.task = task
        self.command = command
        self.success = False
        self.output = []
        self.exit_code = None
        self.duration = 0
        self.findings = {}
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            'task_id': self.task.id,
            'command': self.command,
            'success': self.success,
            'output': self.output,
            'exit_code': self.exit_code,
            'duration': self.duration,
            'findings': self.findings,
            'timestamp': self.timestamp
        }


class ExecutorStrategy(ABC):
    """Abstract base for execution strategies"""

    @abstractmethod
    def run(self, task: TaskNode, target: str) -> ExecutionResult:
        """
        Execute task command

        Args:
            task: Task node containing command
            target: Target IP/hostname for substitution

        Returns:
            ExecutionResult with output and status
        """
        pass

    @abstractmethod
    def cleanup(self):
        """Cleanup resources"""
        pass

    def _prepare_command(self, task: TaskNode, target: str) -> str:
        """
        Prepare command for execution

        Args:
            task: Task node
            target: Target for substitution

        Returns:
            Command string with substitutions
        """
        command = task.metadata.get('command', '')

        # Common substitutions
        command = command.replace('{TARGET}', target)
        command = command.replace('{target}', target)

        return command

    def _emit_events(self, result: ExecutionResult):
        """
        Emit events based on execution result

        Args:
            result: Execution result
        """
        # Task completion event
        if result.success:
            EventBus.emit('task_executed', {
                'task_id': result.task.id,
                'command': result.command,
                'success': True
            })
        else:
            EventBus.emit('task_failed', {
                'task_id': result.task.id,
                'command': result.command,
                'error': result.output[-1] if result.output else 'Unknown error'
            })

        # Finding events
        for finding_type, findings in result.findings.items():
            for finding in findings:
                EventBus.emit('finding_detected', {
                    'task_id': result.task.id,
                    'type': finding_type,
                    'data': finding
                })


class SubprocessExecutor(ExecutorStrategy):
    """
    Current implementation - execute via subprocess

    Simple, stateless execution using subprocess.run()
    """

    def run(self, task: TaskNode, target: str) -> ExecutionResult:
        """Execute command using subprocess"""
        command = self._prepare_command(task, target)
        result = ExecutionResult(task, command)

        start_time = datetime.now()

        try:
            # Execute command
            proc_result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=task.metadata.get('timeout', 120)
            )

            # Process results
            result.exit_code = proc_result.returncode
            result.success = (proc_result.returncode == 0)

            # Capture output
            if proc_result.stdout:
                result.output.extend(proc_result.stdout.strip().split('\n'))
            if proc_result.stderr:
                result.output.extend(proc_result.stderr.strip().split('\n'))

            result.duration = (datetime.now() - start_time).total_seconds()

        except subprocess.TimeoutExpired:
            result.success = False
            result.output.append(f"Command timed out after {task.metadata.get('timeout', 120)} seconds")

        except Exception as e:
            result.success = False
            result.output.append(f"Execution error: {str(e)}")

        # Emit events
        self._emit_events(result)

        return result

    def cleanup(self):
        """No cleanup needed for subprocess"""
        pass


class ScreenedExecutor(ExecutorStrategy):
    """
    New implementation - execute via persistent terminal

    Stateful execution with:
    - Persistent shell environment
    - Real-time output parsing
    - Automatic finding extraction
    """

    def __init__(self, terminal: Optional[ScreenedTerminal] = None):
        """
        Initialize with optional terminal

        Args:
            terminal: Existing terminal or None to create
        """
        self.terminal = terminal
        self.parser = None  # Will be initialized when needed

    def run(self, task: TaskNode, target: str) -> ExecutionResult:
        """Execute command using screened terminal"""
        if not self.terminal:
            self.terminal = ScreenedTerminal(target)
            self.terminal.start()

        command = self._prepare_command(task, target)
        result = ExecutionResult(task, command)

        try:
            # Execute via terminal
            term_result = self.terminal.execute(
                command,
                timeout=task.metadata.get('timeout', 120)
            )

            # Convert terminal result
            result.success = term_result.success
            result.output = term_result.output
            result.duration = term_result.duration
            result.findings = term_result.findings

            # Parse output for findings if parser available
            if self.parser:
                parsed_findings = self.parser.parse(
                    term_result.output,
                    task
                )
                result.findings.update(parsed_findings)

            # Update task status
            if result.success:
                task.mark_complete()
            else:
                # Mark as in-progress (user can retry)
                task.status = 'in-progress'

        except Exception as e:
            result.success = False
            result.output.append(f"Terminal execution error: {str(e)}")

        # Emit events
        self._emit_events(result)

        return result

    def set_parser(self, parser):
        """
        Set output parser for finding extraction

        Args:
            parser: OutputPatternMatcher instance
        """
        self.parser = parser

    def cleanup(self):
        """Stop terminal"""
        if self.terminal:
            self.terminal.stop()
            self.terminal = None


class CommandExecutor:
    """
    Factory for creating executor strategies

    Zen of Python: Simple factory, explicit strategies
    """

    _executors = {}  # Cache for reusable executors

    @classmethod
    def create(cls, mode: str = 'subprocess', **kwargs) -> ExecutorStrategy:
        """
        Create or get executor for specified mode

        Args:
            mode: Execution mode ('subprocess' or 'screened')
            **kwargs: Additional arguments for executor

        Returns:
            ExecutorStrategy instance
        """
        # Return cached executor if exists
        if mode in cls._executors:
            return cls._executors[mode]

        # Create new executor
        if mode == 'screened':
            executor = ScreenedExecutor(**kwargs)
        else:
            executor = SubprocessExecutor()

        # Cache for reuse
        cls._executors[mode] = executor

        return executor

    @classmethod
    def cleanup_all(cls):
        """Cleanup all cached executors"""
        for executor in cls._executors.values():
            executor.cleanup()
        cls._executors.clear()


class BatchExecutor:
    """
    Execute multiple tasks in sequence or parallel

    Useful for automated workflows in screened mode
    """

    def __init__(self, executor: ExecutorStrategy):
        """
        Initialize with executor strategy

        Args:
            executor: Executor to use
        """
        self.executor = executor
        self.results = []

    def execute_sequence(self, tasks: list, target: str) -> list:
        """
        Execute tasks in sequence

        Args:
            tasks: List of TaskNode objects
            target: Target IP/hostname

        Returns:
            List of ExecutionResult objects
        """
        results = []

        for task in tasks:
            # Skip if task has dependencies not met
            if not task._dependencies_satisfied():
                continue

            # Execute task
            result = self.executor.run(task, target)
            results.append(result)

            # Stop on failure unless task allows continuation
            if not result.success and not task.metadata.get('continue_on_failure', False):
                break

        self.results = results
        return results

    def get_summary(self) -> Dict[str, Any]:
        """
        Get execution summary

        Returns:
            Summary statistics
        """
        total = len(self.results)
        successful = sum(1 for r in self.results if r.success)
        failed = total - successful
        total_findings = sum(len(r.findings) for r in self.results)

        return {
            'total_tasks': total,
            'successful': successful,
            'failed': failed,
            'findings_extracted': total_findings,
            'total_duration': sum(r.duration for r in self.results)
        }