"""
Subprocess wrapper that captures all command I/O.

Provides captured_run() - a drop-in replacement for subprocess.run()
that automatically persists command input/output to the persistence layer.
"""

import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from ..config import PersistenceConfig
from ..models.raw_input import RawInput
from ..storage.dual_store import DualStore, get_store


@dataclass
class CapturedResult:
    """
    Wraps subprocess.CompletedProcess with RawInput reference.

    Provides the same interface as subprocess.CompletedProcess
    plus access to the persisted RawInput for provenance tracking.

    Attributes:
        raw_input: The RawInput object with UUID for provenance
        returncode: Process exit code
        _text: Whether to decode output as text
    """
    raw_input: RawInput
    returncode: int
    _text: bool = False

    @property
    def stdout(self) -> Union[str, bytes]:
        """Get stdout (as text if text=True was passed)."""
        if self._text:
            return self.raw_input.stdout_text
        return self.raw_input.stdout

    @property
    def stderr(self) -> Union[str, bytes]:
        """Get stderr (as text if text=True was passed)."""
        if self._text:
            return self.raw_input.stderr_text
        return self.raw_input.stderr

    @property
    def output(self) -> Union[str, bytes]:
        """Get combined stdout + stderr."""
        if self._text:
            return self.raw_input.output_text
        return self.raw_input.stdout + self.raw_input.stderr

    @property
    def success(self) -> bool:
        """Check if command succeeded."""
        return self.returncode == 0

    @property
    def args(self) -> List[str]:
        """Get command arguments."""
        return self.raw_input.args

    def check_returncode(self):
        """Raise CalledProcessError if returncode is non-zero."""
        if self.returncode != 0:
            raise subprocess.CalledProcessError(
                self.returncode,
                self.raw_input.command,
                self.stdout,
                self.stderr,
            )


class CapturedRunner:
    """
    Command runner that captures and persists all I/O.

    Usage:
        runner = CapturedRunner(store)
        result = runner.run(["nmap", "-sV", target], source_tool="bloodtrail")
        print(f"Raw input ID: {result.raw_input.id}")
    """

    def __init__(self, store: Optional[DualStore] = None):
        """
        Initialize runner.

        Args:
            store: DualStore for persistence (uses global if not provided)
        """
        self.store = store

    def _get_store(self) -> DualStore:
        """Get store instance."""
        if self.store is not None:
            return self.store
        return get_store()

    def run(
        self,
        args: Union[str, List[str]],
        *,
        # Persistence metadata
        source_tool: str = "unknown",
        source_module: str = "",
        target_ip: Optional[str] = None,
        target_hostname: Optional[str] = None,
        target_domain: Optional[str] = None,
        engagement_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        # Standard subprocess.run kwargs
        capture_output: bool = True,
        text: bool = False,
        timeout: Optional[float] = None,
        shell: bool = False,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> CapturedResult:
        """
        Execute command and persist to storage.

        This is a drop-in replacement for subprocess.run() that:
        1. Creates a RawInput with UUID before execution
        2. Captures stdout/stderr as bytes
        3. Records timing and exit code
        4. Persists to SQLite (and Neo4j if enabled)
        5. Returns CapturedResult with provenance info

        Args:
            args: Command and arguments (string or list)

            # Persistence metadata
            source_tool: Tool that triggered this ('bloodtrail', 'prism', etc.)
            source_module: Specific module (e.g., 'enumerators.enum4linux')
            target_ip: Target IP address
            target_hostname: Target hostname
            target_domain: Target domain
            engagement_id: Link to engagement (auto-detected if not provided)
            metadata: Additional context to store

            # Standard subprocess.run kwargs
            capture_output: Capture stdout/stderr (default True)
            text: Decode output as text (still stores bytes internally)
            timeout: Command timeout in seconds
            shell: Run through shell
            cwd: Working directory
            env: Environment variables
            **kwargs: Additional subprocess.run arguments

        Returns:
            CapturedResult with:
            - .stdout, .stderr, .returncode (subprocess interface)
            - .raw_input (RawInput with UUID for provenance)
            - .success (convenience bool)

        Example:
            result = captured_run(
                ["nmap", "-sV", "10.10.10.182"],
                source_tool="bloodtrail",
                source_module="enumerators.nmap",
                target_ip="10.10.10.182",
            )

            # Use like subprocess result
            if result.success:
                print(result.stdout)

            # Access provenance
            print(f"Stored as: {result.raw_input.id}")
        """
        # Build command string
        if shell:
            command = args if isinstance(args, str) else " ".join(args)
            args_list = [command]
        else:
            if isinstance(args, str):
                args_list = args.split()
                command = args
            else:
                args_list = list(args)
                command = " ".join(args_list)

        # Auto-detect engagement ID if not provided
        if engagement_id is None:
            engagement_id = self._get_active_engagement()

        # Create RawInput
        raw_input = RawInput(
            id=str(uuid.uuid4()),
            command=command,
            args=args_list,
            source_tool=source_tool,
            source_module=source_module,
            target_ip=target_ip,
            target_hostname=target_hostname,
            target_domain=target_domain,
            engagement_id=engagement_id,
            started_at=datetime.now(),
            metadata=metadata or {},
        )

        # Execute command
        try:
            result = subprocess.run(
                args,
                capture_output=capture_output,
                text=False,  # Always capture bytes internally
                timeout=timeout,
                shell=shell,
                cwd=cwd,
                env=env,
                **kwargs,
            )

            raw_input.stdout = result.stdout or b""
            raw_input.stderr = result.stderr or b""
            raw_input.exit_code = result.returncode
            raw_input.ended_at = datetime.now()
            raw_input.duration_ms = int(
                (raw_input.ended_at - raw_input.started_at).total_seconds() * 1000
            )

        except subprocess.TimeoutExpired as e:
            raw_input.stdout = e.stdout or b""
            raw_input.stderr = e.stderr or b""
            raw_input.exit_code = -1
            raw_input.ended_at = datetime.now()
            raw_input.duration_ms = int(
                (raw_input.ended_at - raw_input.started_at).total_seconds() * 1000
            )
            raw_input.metadata["timeout"] = True
            raw_input.metadata["timeout_seconds"] = timeout

            # Persist before re-raising
            self._persist(raw_input)
            raise

        except Exception as e:
            raw_input.exit_code = -2
            raw_input.ended_at = datetime.now()
            raw_input.stderr = str(e).encode()
            raw_input.metadata["error"] = str(e)

            # Persist before re-raising
            self._persist(raw_input)
            raise

        # Persist to storage
        self._persist(raw_input)

        return CapturedResult(
            raw_input=raw_input,
            returncode=raw_input.exit_code or 0,
            _text=text,
        )

    def _persist(self, raw_input: RawInput):
        """Persist raw input to storage."""
        if PersistenceConfig.is_enabled():
            store = self._get_store()
            store.save_raw_input(raw_input)

    def _get_active_engagement(self) -> Optional[str]:
        """Get active engagement ID if available."""
        try:
            from crack.tools.engagement.storage import EngagementStorage
            storage = EngagementStorage()
            return storage.get_active_engagement_id()
        except ImportError:
            return None
        except Exception:
            return None


# Global runner instance
_default_runner: Optional[CapturedRunner] = None


def get_runner() -> CapturedRunner:
    """Get the global CapturedRunner instance."""
    global _default_runner
    if _default_runner is None:
        _default_runner = CapturedRunner()
    return _default_runner


def captured_run(
    args: Union[str, List[str]],
    *,
    source_tool: str = "unknown",
    source_module: str = "",
    target_ip: Optional[str] = None,
    target_hostname: Optional[str] = None,
    target_domain: Optional[str] = None,
    engagement_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    capture_output: bool = True,
    text: bool = False,
    timeout: Optional[float] = None,
    shell: bool = False,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    **kwargs,
) -> CapturedResult:
    """
    Drop-in replacement for subprocess.run() that persists I/O.

    This is the main entry point for the capture system.

    Usage:
        from crack.tools.persistence import captured_run

        # Basic usage
        result = captured_run(["nmap", "-sV", target])

        # With metadata
        result = captured_run(
            ["crackmapexec", "smb", target, "-u", user, "-p", password],
            source_tool="bloodtrail",
            source_module="auto.orchestrator",
            target_ip=target,
        )

        # Use result like subprocess
        if result.success:
            print(result.stdout)

        # Access provenance for finding creation
        finding = UnifiedFinding(
            ...,
            source_input_id=result.raw_input.id,
        )

    Args:
        args: Command and arguments
        source_tool: Tool name for tracking
        source_module: Module name for tracking
        target_ip: Target IP address
        target_hostname: Target hostname
        target_domain: Target domain
        engagement_id: Link to engagement
        metadata: Additional context
        capture_output: Capture stdout/stderr
        text: Decode as text
        timeout: Command timeout
        shell: Run through shell
        cwd: Working directory
        env: Environment variables

    Returns:
        CapturedResult with command output and provenance info
    """
    runner = get_runner()
    return runner.run(
        args,
        source_tool=source_tool,
        source_module=source_module,
        target_ip=target_ip,
        target_hostname=target_hostname,
        target_domain=target_domain,
        engagement_id=engagement_id,
        metadata=metadata,
        capture_output=capture_output,
        text=text,
        timeout=timeout,
        shell=shell,
        cwd=cwd,
        env=env,
        **kwargs,
    )


def reset_runner():
    """Reset the global runner (for testing)."""
    global _default_runner
    _default_runner = None
