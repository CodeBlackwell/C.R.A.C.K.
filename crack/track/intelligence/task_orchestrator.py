"""
Task Orchestrator - Merges and prioritizes intelligence suggestions

Central coordinator for hybrid intelligence system. Combines reactive
(correlation) and proactive (methodology) task suggestions into a
unified priority queue.
"""

from typing import List, Dict, Any, Set
import logging

logger = logging.getLogger(__name__)


class TaskOrchestrator:
    """Coordinates task suggestions from multiple intelligence sources"""

    def __init__(self, target: str, profile: 'TargetProfile', config: Dict[str, Any]):
        """
        Initialize task orchestrator

        Args:
            target: Target IP/hostname
            profile: TargetProfile instance
            config: Intelligence configuration dict
        """
        self.target = target
        self.profile = profile
        self.config = config
        self.task_history: Set[str] = set()  # Deduplication
        self.scorer = None  # Will be set by caller (dependency injection)

        logger.info(f"[ORCHESTRATOR] Initialized for {target}")

    def generate_next_tasks(self, max_tasks: int = 5) -> List[Dict[str, Any]]:
        """
        Generate top N prioritized tasks from all intelligence sources

        Args:
            max_tasks: Maximum number of tasks to return

        Returns:
            List of task dicts sorted by priority (highest first)
        """
        # Placeholder: In Stage 2, will query correlation + methodology engines
        # For now, returns empty list (passive)
        all_tasks = []

        logger.debug(f"[ORCHESTRATOR] Generating next {max_tasks} tasks")

        # Future: all_tasks.extend(self.correlation_engine.get_tasks())
        # Future: all_tasks.extend(self.methodology_engine.get_tasks())

        if not all_tasks:
            return []

        # Deduplicate
        deduplicated = self.deduplicate_tasks(all_tasks)
        logger.info(f"[ORCHESTRATOR] Deduplicated: {len(all_tasks)} -> {len(deduplicated)} tasks")

        # Score and sort
        scored_tasks = []
        for task in deduplicated:
            if self.scorer:
                task['priority'] = self.scorer.calculate_priority(task, self.profile)
            else:
                task['priority'] = 0.0
            scored_tasks.append(task)

        scored_tasks.sort(key=lambda t: t['priority'], reverse=True)

        # Return top N
        top_tasks = scored_tasks[:max_tasks]
        logger.info(f"[ORCHESTRATOR] Top {len(top_tasks)} tasks selected")

        return top_tasks

    def merge_suggestions(self, method1_tasks: List[Dict], method2_tasks: List[Dict]) -> List[Dict]:
        """
        Merge task suggestions from Method 1 (correlation) and Method 2 (methodology)

        Args:
            method1_tasks: Reactive correlation tasks
            method2_tasks: Proactive methodology tasks

        Returns:
            Combined list with metadata indicating source
        """
        logger.debug(f"[ORCHESTRATOR.MERGE] M1:{len(method1_tasks)} M2:{len(method2_tasks)}")

        # Tag sources
        for task in method1_tasks:
            task['intelligence_source'] = 'correlation'
        for task in method2_tasks:
            task['intelligence_source'] = 'methodology'

        merged = method1_tasks + method2_tasks
        logger.info(f"[ORCHESTRATOR.MERGE] Merged {len(merged)} total tasks")

        return merged

    def deduplicate_tasks(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate tasks based on task ID and fingerprint

        Args:
            tasks: List of task dictionaries

        Returns:
            Deduplicated list
        """
        seen_ids = set()
        unique_tasks = []

        for task in tasks:
            task_id = task.get('id', '')

            # Skip if already seen
            if task_id in seen_ids or task_id in self.task_history:
                logger.debug(f"[ORCHESTRATOR.DEDUP] Skipping duplicate: {task_id}")
                continue

            seen_ids.add(task_id)
            unique_tasks.append(task)

        # Track in history
        self.task_history.update(seen_ids)

        return unique_tasks

    def set_scorer(self, scorer):
        """Inject TaskScorer dependency"""
        self.scorer = scorer
        logger.debug("[ORCHESTRATOR] TaskScorer injected")
