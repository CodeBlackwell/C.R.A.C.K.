"""
Wordlist Manager - Discovery and caching system

Discovers wordlists from configured directory and caches metadata for fast access.
"""

import os
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime


# Category constants
CATEGORY_WEB = 'web'
CATEGORY_PASSWORDS = 'passwords'
CATEGORY_SUBDOMAINS = 'subdomains'
CATEGORY_USERNAMES = 'usernames'
CATEGORY_GENERAL = 'general'


@dataclass
class WordlistEntry:
    """Wordlist metadata entry"""

    path: str                       # Absolute path to wordlist file
    name: str                       # Filename without extension
    category: str                   # Category (web, passwords, etc.)
    size_bytes: int                 # File size in bytes
    line_count: int                 # Number of lines (exact or estimated)
    avg_word_length: float          # Average word length (sample-based for large files)
    description: str = ''           # Human-readable description
    last_scanned: str = ''          # ISO timestamp of last scan

    def __post_init__(self):
        """Ensure path is absolute and normalized"""
        self.path = str(Path(self.path).resolve())
        if not self.last_scanned:
            self.last_scanned = datetime.now().isoformat()


class WordlistManager:
    """
    Manages wordlist discovery, caching, and retrieval

    Features:
    - Recursive directory scanning for .txt/.lst files
    - Metadata caching for fast access (<10ms)
    - Fuzzy search by name/path
    - Category filtering
    - Performance targets: <5s first scan, <10ms cached
    """

    def __init__(self, wordlists_dir: str = '/usr/share/wordlists/',
                 cache_path: str = '~/.crack/wordlists_cache.json'):
        """
        Initialize WordlistManager

        Args:
            wordlists_dir: Root directory to scan for wordlists
            cache_path: Path to cache file (expanded automatically)
        """
        self.wordlists_dir = Path(wordlists_dir).resolve()
        self.cache_path = Path(cache_path).expanduser().resolve()
        self.cache: Dict[str, WordlistEntry] = {}  # path -> entry

        # Ensure cache directory exists
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)

        # Load cache if available
        self._load_cache()

    def scan_directory(self, force_rescan: bool = False) -> List[WordlistEntry]:
        """
        Scan wordlists directory recursively

        Args:
            force_rescan: Force rescan even if cache exists

        Returns:
            List of WordlistEntry objects
        """
        # Use cache if available and not forcing rescan
        if self.cache and not force_rescan:
            return list(self.cache.values())

        # Import metadata generator
        from .metadata import generate_metadata

        entries = []

        # Check if directory exists
        if not self.wordlists_dir.exists():
            return entries

        # Scan for wordlist files
        for ext in ['*.txt', '*.lst']:
            for file_path in self.wordlists_dir.rglob(ext):
                # Skip symlinks to avoid infinite loops
                if file_path.is_symlink():
                    continue

                # Skip if not a file
                if not file_path.is_file():
                    continue

                # Skip if no read permission
                if not os.access(file_path, os.R_OK):
                    continue

                try:
                    # Generate metadata
                    entry = generate_metadata(str(file_path))
                    entries.append(entry)

                    # Update cache
                    self.cache[entry.path] = entry

                except (PermissionError, OSError):
                    # Skip files we can't read
                    continue

        # Save updated cache
        self._save_cache()

        return entries

    def _load_cache(self) -> Dict[str, WordlistEntry]:
        """
        Load cache from disk

        Returns:
            Dictionary of path -> WordlistEntry
        """
        if not self.cache_path.exists():
            return {}

        try:
            with open(self.cache_path, 'r') as f:
                cache_data = json.load(f)

            # Convert dict to WordlistEntry objects
            for path, entry_dict in cache_data.items():
                self.cache[path] = WordlistEntry(**entry_dict)

            return self.cache

        except (json.JSONDecodeError, OSError, TypeError):
            # Cache corrupted or invalid - return empty
            return {}

    def _save_cache(self):
        """Save cache to disk"""
        try:
            # Convert WordlistEntry objects to dicts
            cache_data = {
                path: asdict(entry)
                for path, entry in self.cache.items()
            }

            with open(self.cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)

        except (OSError, TypeError):
            # Failed to save cache - not critical
            pass

    def get_wordlist(self, path: str) -> Optional[WordlistEntry]:
        """
        Get wordlist by path

        Args:
            path: Absolute or relative path to wordlist

        Returns:
            WordlistEntry or None if not found
        """
        # Normalize path
        normalized = str(Path(path).resolve())

        # Check cache first
        if normalized in self.cache:
            return self.cache[normalized]

        # Not in cache - try to generate metadata if file exists
        if Path(normalized).exists():
            from .metadata import generate_metadata
            try:
                entry = generate_metadata(normalized)
                self.cache[normalized] = entry
                self._save_cache()
                return entry
            except (PermissionError, OSError):
                return None

        return None

    def search(self, query: str) -> List[WordlistEntry]:
        """
        Fuzzy search wordlists by name or path

        Args:
            query: Search term (case-insensitive)

        Returns:
            List of matching WordlistEntry objects
        """
        query_lower = query.lower()
        matches = []

        for entry in self.cache.values():
            # Search in name
            if query_lower in entry.name.lower():
                matches.append(entry)
                continue

            # Search in path
            if query_lower in entry.path.lower():
                matches.append(entry)
                continue

            # Search in description
            if entry.description and query_lower in entry.description.lower():
                matches.append(entry)
                continue

        return matches

    def get_by_category(self, category: str) -> List[WordlistEntry]:
        """
        Get wordlists by category

        Args:
            category: Category name (web, passwords, etc.)

        Returns:
            List of WordlistEntry objects in category
        """
        return [
            entry for entry in self.cache.values()
            if entry.category == category
        ]

    def get_all(self) -> List[WordlistEntry]:
        """
        Get all cached wordlists

        Returns:
            List of all WordlistEntry objects
        """
        return list(self.cache.values())

    def clear_cache(self):
        """Clear cache and remove cache file"""
        self.cache.clear()
        if self.cache_path.exists():
            self.cache_path.unlink()

    def get_stats(self) -> Dict[str, int]:
        """
        Get cache statistics

        Returns:
            Dictionary with stats
        """
        return {
            'total_wordlists': len(self.cache),
            'total_categories': len(set(e.category for e in self.cache.values())),
            'cache_size_bytes': self.cache_path.stat().st_size if self.cache_path.exists() else 0
        }
