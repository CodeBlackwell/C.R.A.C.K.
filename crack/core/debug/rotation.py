"""Log file rotation and cleanup for CRACK debug logs."""

from pathlib import Path
from datetime import datetime, timedelta


class LogRotation:
    """Manage log file rotation and cleanup."""

    def __init__(
        self,
        log_dir: Path,
        max_age_days: int = 7,
        max_size_mb: int = 100,
    ):
        """
        Initialize rotation manager.

        Args:
            log_dir: Directory containing log files
            max_age_days: Delete logs older than this (default: 7 days)
            max_size_mb: Max total size before cleanup (default: 100MB)
        """
        self.log_dir = log_dir
        self.max_age_days = max_age_days
        self.max_size_mb = max_size_mb

    def cleanup_old_logs(self) -> int:
        """
        Remove old log files.

        Returns:
            Number of files deleted
        """
        if not self.log_dir.exists():
            return 0

        deleted = 0
        cutoff = datetime.now() - timedelta(days=self.max_age_days)

        for log_file in self.log_dir.glob("crack-*.jsonl"):
            try:
                # Extract date from filename (crack-YYYY-MM-DD.jsonl)
                date_str = log_file.stem.replace("crack-", "")
                file_date = datetime.strptime(date_str, "%Y-%m-%d")

                if file_date < cutoff:
                    log_file.unlink()
                    deleted += 1
            except (ValueError, OSError):
                continue

        return deleted

    def get_total_size_mb(self) -> float:
        """Get total size of log files in MB."""
        if not self.log_dir.exists():
            return 0.0

        total = sum(f.stat().st_size for f in self.log_dir.glob("crack-*.jsonl"))
        return total / (1024 * 1024)

    def needs_cleanup(self) -> bool:
        """Check if cleanup is needed based on size."""
        return self.get_total_size_mb() > self.max_size_mb
