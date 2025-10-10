"""
Execution Overlay - Task execution outside Live display context

Handles:
- Stopping Live display before execution
- Executing task with normal terminal I/O
- Showing output in real-time
- Resuming Live display after completion

This is a minimal implementation to fix the dashboard freeze issue.
Full Task Workspace implementation is planned for Phase 4.
"""

from typing import Any, Dict
from rich.live import Live
from ..debug_logger import get_debug_logger


class ExecutionOverlay:
    """Execution overlay for running tasks outside Live context"""

    @classmethod
    def execute_task(cls, live: Live, session: 'TUISessionV2', task: Any) -> None:
        """
        Execute a task outside the Live display context

        Args:
            live: Rich Live context (will be stopped during execution)
            session: TUI session instance with access to parent's execute_task()
            task: TaskNode to execute

        Flow:
            1. Stop Live display
            2. Execute task with normal terminal I/O (parent's method)
            3. Wait for user acknowledgment
            4. Restart Live display
        """
        logger = get_debug_logger()
        logger.section("EXECUTE TASK OVERLAY")
        logger.log_execution_start(task.name, task.task_id)

        # Stop Live display to allow normal terminal I/O
        logger.log_live_action("STOP", "before task execution")
        live.stop()
        logger.debug("Live display stopped successfully")

        try:
            # Print header
            session.console.print("\n" + "=" * 80)
            session.console.print(f"[bold cyan]Executing Task: {task.name}[/]")
            session.console.print("=" * 80 + "\n")

            # Execute task using parent's method
            # This handles:
            # - Command construction
            # - Confirmation prompts
            # - Flag explanations
            # - Screened mode execution
            # - Output display
            # - Status updates
            logger.info("Calling session.execute_task()")
            session.execute_task(task)
            logger.info("session.execute_task() returned")

            # Print footer
            session.console.print("\n" + "=" * 80)
            session.console.print("[bold green]Task execution complete[/]")
            session.console.print("=" * 80)

            logger.log_execution_end(task.name, success=True)

        except KeyboardInterrupt:
            logger.warning("Task execution interrupted by user")
            session.console.print("\n[yellow]Task execution interrupted[/]")
            logger.log_execution_end(task.name, success=False)

        except Exception as e:
            logger.exception(f"Exception during task execution: {e}")
            session.console.print(f"\n[red]Error during execution: {e}[/]")
            import traceback
            if session.debug_mode:
                traceback.print_exc()
            logger.log_execution_end(task.name, success=False)

        finally:
            # Wait for user to acknowledge before returning to TUI
            session.console.print("\n[dim]Press Enter to return to dashboard...[/]")
            logger.debug("Waiting for user acknowledgment...")
            try:
                input()
                logger.debug("User pressed Enter")
            except (EOFError, KeyboardInterrupt):
                logger.warning("EOF or interrupt during acknowledgment")

            # Restart Live display
            logger.log_live_action("START", "after task execution")
            live.start()
            logger.debug("Live display restarted successfully")

    @classmethod
    def execute_choice(cls, live: Live, session: 'TUISessionV2', choice: Dict[str, Any]) -> None:
        """
        Execute a menu choice outside the Live display context

        Args:
            live: Rich Live context
            session: TUI session instance
            choice: Choice dictionary from dashboard menu

        This is a higher-level wrapper that handles routing different choice types.
        Currently just wraps execute_task, but can be extended for other choice types.
        """
        logger = get_debug_logger()
        logger.section("EXECUTE CHOICE OVERLAY")

        # Get choice details
        choice_id = choice.get('id')
        choice_label = choice.get('label', 'Unknown action')
        choice_index = choice.get('index', -1)

        logger.info(f"Choice ID: {choice_id}")
        logger.info(f"Choice label: {choice_label}")
        logger.info(f"Choice index: {choice_index}")

        # Stop Live display
        logger.log_live_action("STOP", "before executing choice")
        live.stop()
        logger.debug("Live display stopped")

        try:
            session.console.print(f"\n[cyan]Executing: {choice_label}[/]")

            # Route based on choice type
            if choice_id == 'next':
                logger.info("Choice type: next (execute recommended task)")

                # Execute next recommended task
                recommendations = session._current_recommendations
                next_task = recommendations.get('next')

                if next_task:
                    logger.info(f"Next task found: {next_task.name}")

                    # Restart Live for execute_task to stop it again
                    logger.log_live_action("START", "temporary restart for execute_task")
                    live.start()

                    cls.execute_task(live, session, next_task)
                else:
                    logger.warning("No recommended task available")
                    session.console.print("[yellow]No recommended task available[/]")
                    logger.debug("Waiting for user acknowledgment...")
                    input("\nPress Enter to continue...")
                    logger.log_live_action("START", "after no-task acknowledgment")
                    live.start()

            elif choice_id == 'help':
                logger.info("Choice type: help (showing help overlay)")
                session.console.print("[yellow]Help overlay - not yet implemented in TUI[/]")
                input("\nPress Enter to continue...")
                logger.log_live_action("START", "after help acknowledgment")
                live.start()

            elif choice_id == 'show-status':
                logger.info("Choice type: show-status (showing status overlay)")
                session.console.print("[yellow]Status overlay - use 's' shortcut instead[/]")
                input("\nPress Enter to continue...")
                logger.log_live_action("START", "after status acknowledgment")
                live.start()

            elif choice_id == 'exit':
                logger.info("Choice type: exit (exiting TUI)")
                session.console.print("[yellow]Exiting TUI...[/]")
                logger.log_live_action("START", "before exit")
                live.start()
                # Don't wait for input, just exit

            elif choice_id == 'import':
                logger.info("Choice type: import (scan file import wizard)")
                cls._run_import_wizard(live, session)

            else:
                logger.warning(f"Choice type: {choice_id} (NOT IMPLEMENTED - would cause freeze)")
                session.console.print(f"[yellow]Choice '{choice_label}' not yet implemented in TUI[/]")
                session.console.print(f"[dim]Choice ID: {choice_id}[/]")
                session.console.print(f"[cyan]This choice needs to be implemented to work properly.[/]")
                logger.debug("Waiting for user acknowledgment...")
                input("\nPress Enter to return to dashboard...")
                logger.log_live_action("START", "after not-implemented acknowledgment")
                live.start()

        except KeyboardInterrupt:
            logger.warning("Choice execution interrupted by user")
            session.console.print("\n[yellow]Action interrupted[/]")
            logger.log_live_action("START", "after interrupt")
            live.start()

        except Exception as e:
            logger.exception(f"Exception during choice execution: {e}")
            session.console.print(f"\n[red]Error: {e}[/]")
            if session.debug_mode:
                import traceback
                traceback.print_exc()

            logger.debug("Waiting for user acknowledgment after error...")
            input("\nPress Enter to continue...")

            logger.log_live_action("START", "after error")
            live.start()

    @classmethod
    def _run_import_wizard(cls, live: Live, session: 'TUISessionV2') -> None:
        """
        Run import wizard outside Live context

        Args:
            live: Rich Live context
            session: TUI session instance
        """
        from ..panels.import_form import ImportForm
        from ..input_handler import InputProcessor

        logger = get_debug_logger()
        logger.section("IMPORT WIZARD")
        logger.info("Starting import wizard")

        # Create import form with debug logging
        import_form = ImportForm(
            profile=session.profile,
            console=session.console,
            debug_logger=logger
        )

        # Wizard loop
        wizard_running = True
        while wizard_running:
            try:
                # Render current stage
                panel, choices = import_form.render()

                # Display panel
                session.console.print("\n")
                session.console.print(panel)
                session.console.print()

                # Get user input
                user_input = input("Choice: ").strip()
                logger.debug(f"User input: {repr(user_input)}")

                # Parse input against choices
                parsed = InputProcessor.parse_choice(user_input, choices)

                if not parsed:
                    session.console.print("[yellow]Invalid choice. Please try again.[/]")
                    continue

                # Get action from choice
                action = parsed.get('action', '')
                logger.info(f"Action: {action}")

                # Handle actions
                if action == 'back':
                    # Exit wizard, return to dashboard
                    logger.info("User cancelled import wizard")
                    wizard_running = False

                elif action == 'enter_path':
                    # Prompt for custom file path
                    file_path = input("\nEnter file path: ").strip()
                    logger.debug(f"File path entered: {file_path}")

                    if file_path:
                        import_form.set_file_path(file_path)

                elif action == 'use_path':
                    # Use suggested path
                    file_path = parsed.get('path')
                    logger.debug(f"Using suggested path: {file_path}")
                    import_form.set_file_path(file_path)

                elif action == 'next_stage':
                    # Advance to next stage
                    logger.info(f"Advancing from stage {import_form.stage}")
                    import_form.next_stage()
                    logger.info(f"Now at stage {import_form.stage}")

                elif action == 'prev_stage':
                    # Go back to previous stage
                    logger.info(f"Going back from stage {import_form.stage}")
                    import_form.prev_stage()
                    logger.info(f"Now at stage {import_form.stage}")

                elif action == 'select_strategy':
                    # Set merge strategy
                    strategy = parsed.get('strategy')
                    logger.info(f"Merge strategy selected: {strategy}")
                    import_form.merge_strategy = strategy

                elif action == 'import':
                    # Execute import
                    logger.info("Executing import...")
                    session.console.print("\n[cyan]Importing scan data...[/]")

                    success = import_form.import_to_profile(session.profile)

                    if success:
                        logger.info("Import successful")
                        session.console.print("[green]✓ Import complete![/]")
                    else:
                        logger.warning("Import failed")
                        session.console.print("[red]✗ Import failed[/]")

                    # Form automatically moves to COMPLETE stage

                elif action == 'cancel':
                    # Cancel import
                    logger.info("Import cancelled by user")
                    wizard_running = False

                elif action == 'reset':
                    # Reset form for another import
                    logger.info("Resetting form for new import")
                    import_form.reset()

                else:
                    logger.warning(f"Unknown action: {action}")
                    session.console.print(f"[yellow]Unknown action: {action}[/]")

            except KeyboardInterrupt:
                logger.warning("Import wizard interrupted by user")
                session.console.print("\n[yellow]Import cancelled[/]")
                wizard_running = False

            except Exception as e:
                logger.exception(f"Error in import wizard: {e}")
                session.console.print(f"\n[red]Error: {e}[/]")
                if session.debug_mode:
                    import traceback
                    traceback.print_exc()
                # Don't exit wizard on error, let user try again

        # Wizard complete
        logger.info("Import wizard finished")

        # Restart Live display (no confirmation needed - user already exited wizard)
        logger.log_live_action("START", "after import wizard")
        live.start()
