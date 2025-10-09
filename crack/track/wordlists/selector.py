"""
Wordlist Selector - Interactive selection system

Provides context-aware wordlist suggestions and interactive selection UI.
"""

import os
from typing import Optional, List, Dict, Any
from .manager import WordlistManager, WordlistEntry, CATEGORY_WEB, CATEGORY_PASSWORDS


# Tool patterns for task detection
WORDLIST_TOOLS = {
    'gobuster', 'dirb', 'dirbuster', 'wfuzz', 'ffuf', 'feroxbuster',  # Web enum
    'hydra', 'medusa', 'ncrack', 'patator',  # Password attacks
    'wpscan', 'joomscan', 'droopescan',  # CMS scanners
    'sqlmap',  # SQL injection
}

# Service to purpose mapping
SERVICE_TO_PURPOSE = {
    'http': 'web-enumeration',
    'https': 'web-enumeration',
    'ssh': 'password-cracking',
    'ftp': 'password-cracking',
    'smb': 'password-cracking',
    'mysql': 'password-cracking',
    'postgresql': 'password-cracking',
    'mssql': 'password-cracking',
}

# Task ID pattern to purpose mapping
TASK_PATTERN_TO_PURPOSE = {
    'gobuster': 'web-enumeration',
    'dirb': 'web-enumeration',
    'wfuzz': 'web-enumeration',
    'ffuf': 'web-enumeration',
    'feroxbuster': 'web-enumeration',
    'hydra': 'password-cracking',
    'medusa': 'password-cracking',
    'wpscan': 'web-enumeration',
    'nikto': 'web-enumeration',
}


class WordlistSelector:
    """
    Wordlist selection system with context-aware suggestions

    Features:
    - Task-aware suggestions (gobuster → web wordlists)
    - Interactive selection menu with metadata
    - Browse all wordlists with pagination
    - Fuzzy search functionality
    - Context-based relevance sorting
    """

    def __init__(self, manager: WordlistManager, task=None):
        """
        Initialize WordlistSelector

        Args:
            manager: WordlistManager instance
            task: TaskNode instance (optional, for context-aware suggestions)
        """
        self.manager = manager
        self.task = task

    def suggest_for_task(self, task) -> List[WordlistEntry]:
        """
        Suggest wordlists for a specific task based on context

        Args:
            task: TaskNode instance

        Returns:
            List of suggested WordlistEntry objects (top 3-5, sorted by relevance)
        """
        # Detect task purpose
        purpose = self._detect_task_purpose(task)

        if not purpose:
            # No specific purpose detected, return general wordlists
            return self._get_default_suggestions()

        # Get wordlists for the detected purpose
        suggestions = []

        if purpose == 'web-enumeration':
            suggestions = self._get_web_suggestions()
        elif purpose == 'password-cracking':
            suggestions = self._get_password_suggestions()
        elif purpose == 'subdomain-enumeration':
            suggestions = self._get_subdomain_suggestions()
        elif purpose == 'username-enumeration':
            suggestions = self._get_username_suggestions()
        else:
            suggestions = self._get_default_suggestions()

        # Limit to top 5
        return suggestions[:5]

    def _detect_task_purpose(self, task) -> Optional[str]:
        """
        Detect the purpose of a task for wordlist selection

        Checks:
        1. Explicit wordlist_purpose in metadata
        2. Task ID patterns (gobuster-* → web-enumeration)
        3. Service from metadata (http → web-enumeration)
        4. Command contains wordlist tool

        Args:
            task: TaskNode instance

        Returns:
            Purpose string or None
        """
        if not task:
            return None

        # 1. Check explicit wordlist_purpose in metadata
        if hasattr(task, 'metadata'):
            explicit_purpose = task.metadata.get('wordlist_purpose')
            if explicit_purpose:
                return explicit_purpose

            # 2. Check task ID patterns
            task_id = task.id if hasattr(task, 'id') else ''
            for pattern, purpose in TASK_PATTERN_TO_PURPOSE.items():
                if pattern in task_id.lower():
                    return purpose

            # 3. Check service from metadata
            service = task.metadata.get('service', '').lower()
            if service in SERVICE_TO_PURPOSE:
                return SERVICE_TO_PURPOSE[service]

            # 4. Check command for wordlist tools
            command = task.metadata.get('command')
            if command and isinstance(command, str):
                command = command.lower()
                for tool in WORDLIST_TOOLS:
                    if tool in command:
                        # Infer purpose from tool
                        if tool in ['gobuster', 'dirb', 'wfuzz', 'ffuf', 'feroxbuster', 'wpscan', 'nikto']:
                            return 'web-enumeration'
                        elif tool in ['hydra', 'medusa', 'ncrack', 'patator']:
                            return 'password-cracking'

        return None

    def _task_needs_wordlist(self, task) -> bool:
        """
        Check if a task requires a wordlist

        Args:
            task: TaskNode instance

        Returns:
            True if task needs wordlist
        """
        if not task or not hasattr(task, 'metadata'):
            return False

        command = task.metadata.get('command')
        if not command or not isinstance(command, str):
            return False

        command = command.lower()

        # Check for wordlist flags
        if '-w ' in command or '--wordlist' in command:
            return True

        # Check for wordlist tools
        for tool in WORDLIST_TOOLS:
            if tool in command:
                return True

        return False

    def _get_web_suggestions(self) -> List[WordlistEntry]:
        """Get web enumeration wordlist suggestions (sorted by relevance)"""
        # Get all web wordlists
        web_wordlists = self.manager.get_by_category(CATEGORY_WEB)

        if not web_wordlists:
            # Fallback: search for common web wordlists
            web_wordlists = self.manager.search('common.txt') + \
                           self.manager.search('directory') + \
                           self.manager.search('dirb')

        # Sort by relevance: smaller files first for QUICK_WIN
        # Prefer: common.txt < medium.txt < big.txt
        def sort_key(entry):
            name_lower = entry.name.lower()
            # Priority order
            if 'common' in name_lower:
                return (0, entry.line_count)
            elif 'small' in name_lower or 'quick' in name_lower:
                return (1, entry.line_count)
            elif 'medium' in name_lower:
                return (2, entry.line_count)
            elif 'big' in name_lower or 'large' in name_lower:
                return (3, entry.line_count)
            else:
                return (4, entry.line_count)

        web_wordlists.sort(key=sort_key)
        return web_wordlists

    def _get_password_suggestions(self) -> List[WordlistEntry]:
        """Get password cracking wordlist suggestions"""
        password_wordlists = self.manager.get_by_category(CATEGORY_PASSWORDS)

        if not password_wordlists:
            # Fallback: search for rockyou and password wordlists
            password_wordlists = self.manager.search('rockyou') + \
                                self.manager.search('password')

        # Sort: smaller password lists first for speed
        password_wordlists.sort(key=lambda e: e.line_count)
        return password_wordlists

    def _get_subdomain_suggestions(self) -> List[WordlistEntry]:
        """Get subdomain enumeration wordlist suggestions"""
        subdomain_wordlists = self.manager.search('subdomain') + \
                             self.manager.search('dns')
        subdomain_wordlists.sort(key=lambda e: e.line_count)
        return subdomain_wordlists

    def _get_username_suggestions(self) -> List[WordlistEntry]:
        """Get username enumeration wordlist suggestions"""
        username_wordlists = self.manager.search('user') + \
                            self.manager.search('names')
        username_wordlists.sort(key=lambda e: e.line_count)
        return username_wordlists

    def _get_default_suggestions(self) -> List[WordlistEntry]:
        """Get default general wordlist suggestions"""
        all_wordlists = self.manager.get_all()

        if not all_wordlists:
            return []

        # Sort by popularity: common.txt, rockyou.txt, etc.
        def sort_key(entry):
            name_lower = entry.name.lower()
            if 'common' in name_lower:
                return (0, entry.line_count)
            elif 'rockyou' in name_lower:
                return (1, entry.line_count)
            else:
                return (2, entry.line_count)

        all_wordlists.sort(key=sort_key)
        return all_wordlists[:5]

    def interactive_select(self) -> Optional[WordlistEntry]:
        """
        Launch interactive wordlist selection menu

        Returns:
            Selected WordlistEntry or None if cancelled
        """
        # Get suggestions based on task context
        suggestions = []
        if self.task:
            suggestions = self.suggest_for_task(self.task)
            purpose = self._detect_task_purpose(self.task)
        else:
            suggestions = self._get_default_suggestions()
            purpose = None

        # Display header
        print("\n" + "=" * 70)
        print("WORDLIST SELECTION")
        print("=" * 70)

        if purpose:
            print(f"\nDetected purpose: {purpose}")
            print(f"Task: {self.task.name if self.task else 'N/A'}")

        # Display suggestions
        if suggestions:
            print(f"\nSuggested wordlists ({len(suggestions)}):")
            print("-" * 70)
            self._display_wordlist_menu(suggestions)

        # Display options
        print("\nOptions:")
        print("  [1-N]   Select wordlist by number")
        print("  [b]     Browse all wordlists")
        print("  [s]     Search for wordlist")
        print("  [e]     Enter custom path")
        print("  [c]     Cancel")
        print()

        while True:
            try:
                choice = input("Choice: ").strip().lower()

                if not choice or choice == 'c':
                    return None

                elif choice == 'b':
                    return self._browse_all()

                elif choice == 's':
                    return self._search_wordlists()

                elif choice == 'e':
                    return self._enter_custom_path()

                elif choice.isdigit():
                    index = int(choice) - 1
                    if 0 <= index < len(suggestions):
                        selected = suggestions[index]
                        print(f"\nSelected: {selected.name}")
                        return selected
                    else:
                        print(f"Invalid choice. Enter 1-{len(suggestions)}")

                else:
                    print("Invalid option. Try again or press 'c' to cancel.")

            except KeyboardInterrupt:
                print("\n\nCancelled.")
                return None
            except EOFError:
                return None

    def _display_wordlist_menu(self, wordlists: List[WordlistEntry]):
        """
        Display wordlist menu with metadata

        Format: 1. common.txt (4.6K lines, 36KB, avg 7.5 chars) [QUICK]

        Args:
            wordlists: List of WordlistEntry objects
        """
        for i, entry in enumerate(wordlists, 1):
            # Format line count
            if entry.line_count >= 1_000_000:
                line_str = f"{entry.line_count / 1_000_000:.1f}M"
            elif entry.line_count >= 1_000:
                line_str = f"{entry.line_count / 1_000:.1f}K"
            else:
                line_str = str(entry.line_count)

            # Format file size
            if entry.size_bytes >= 1_000_000:
                size_str = f"{entry.size_bytes / 1_000_000:.1f}MB"
            elif entry.size_bytes >= 1_000:
                size_str = f"{entry.size_bytes / 1_000:.1f}KB"
            else:
                size_str = f"{entry.size_bytes}B"

            # Build tag based on size (QUICK for small wordlists)
            tags = []
            if entry.line_count < 10_000:
                tags.append('QUICK')
            elif entry.line_count > 1_000_000:
                tags.append('THOROUGH')

            tag_str = f" [{', '.join(tags)}]" if tags else ""

            # Display line
            print(f"  {i}. {entry.name:30s} ({line_str:>6s} lines, {size_str:>8s}, "
                  f"avg {entry.avg_word_length:.1f} chars){tag_str}")

            # Show category and description if available
            if entry.category != 'general' or entry.description:
                details = []
                if entry.category != 'general':
                    details.append(f"Category: {entry.category}")
                if entry.description:
                    details.append(entry.description)
                if details:
                    print(f"      {' | '.join(details)}")

    def _browse_all(self) -> Optional[WordlistEntry]:
        """
        Browse all wordlists with pagination and category filtering

        Returns:
            Selected WordlistEntry or None
        """
        print("\n" + "=" * 70)
        print("BROWSE ALL WORDLISTS")
        print("=" * 70)

        # Get all wordlists
        all_wordlists = self.manager.get_all()

        if not all_wordlists:
            print("No wordlists found.")
            input("\nPress Enter to continue...")
            return None

        # Sort alphabetically
        all_wordlists.sort(key=lambda e: e.name.lower())

        # Offer category filtering
        print("\nFilter by category:")
        print("  [a] All wordlists")
        print("  [w] Web enumeration")
        print("  [p] Password cracking")
        print("  [s] Subdomains")
        print("  [u] Usernames")
        print()

        filter_choice = input("Filter (or Enter for all): ").strip().lower()

        # Apply filter
        if filter_choice == 'w':
            all_wordlists = [e for e in all_wordlists if e.category == CATEGORY_WEB]
        elif filter_choice == 'p':
            all_wordlists = [e for e in all_wordlists if e.category == CATEGORY_PASSWORDS]
        elif filter_choice == 's':
            all_wordlists = [e for e in all_wordlists if 'subdomain' in e.name.lower() or 'dns' in e.name.lower()]
        elif filter_choice == 'u':
            all_wordlists = [e for e in all_wordlists if 'user' in e.name.lower()]

        if not all_wordlists:
            print("No wordlists match the filter.")
            input("\nPress Enter to continue...")
            return None

        # Paginate (10 per page)
        page_size = 10
        total_pages = (len(all_wordlists) + page_size - 1) // page_size
        current_page = 0

        while True:
            # Display current page
            start_idx = current_page * page_size
            end_idx = min(start_idx + page_size, len(all_wordlists))
            page_wordlists = all_wordlists[start_idx:end_idx]

            print(f"\nPage {current_page + 1}/{total_pages} ({len(all_wordlists)} total)")
            print("-" * 70)
            self._display_wordlist_menu(page_wordlists)

            # Display navigation
            print("\nOptions:")
            print("  [1-N]   Select wordlist by number")
            if current_page < total_pages - 1:
                print("  [n]     Next page")
            if current_page > 0:
                print("  [p]     Previous page")
            print("  [b]     Back to main menu")
            print()

            choice = input("Choice: ").strip().lower()

            if choice == 'b':
                return None
            elif choice == 'n' and current_page < total_pages - 1:
                current_page += 1
            elif choice == 'p' and current_page > 0:
                current_page -= 1
            elif choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(page_wordlists):
                    selected = page_wordlists[index]
                    print(f"\nSelected: {selected.name}")
                    return selected
                else:
                    print(f"Invalid choice. Enter 1-{len(page_wordlists)}")

    def _search_wordlists(self) -> Optional[WordlistEntry]:
        """
        Search for wordlists by name/path

        Returns:
            Selected WordlistEntry or None
        """
        print("\n" + "=" * 70)
        print("SEARCH WORDLISTS")
        print("=" * 70)

        query = input("\nEnter search term (name, path, or description): ").strip()

        if not query:
            return None

        # Search
        matches = self.manager.search(query)

        if not matches:
            print(f"\nNo wordlists found matching '{query}'")
            input("\nPress Enter to continue...")
            return None

        # Display matches
        print(f"\nFound {len(matches)} match(es):")
        print("-" * 70)
        self._display_wordlist_menu(matches)

        # Selection
        print("\nOptions:")
        print("  [1-N]   Select wordlist by number")
        print("  [b]     Back to main menu")
        print()

        while True:
            choice = input("Choice: ").strip().lower()

            if choice == 'b':
                return None
            elif choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(matches):
                    selected = matches[index]
                    print(f"\nSelected: {selected.name}")
                    return selected
                else:
                    print(f"Invalid choice. Enter 1-{len(matches)}")

    def _enter_custom_path(self) -> Optional[WordlistEntry]:
        """
        Enter custom wordlist path

        Returns:
            WordlistEntry for custom path or None
        """
        print("\n" + "=" * 70)
        print("CUSTOM WORDLIST PATH")
        print("=" * 70)

        path = input("\nEnter full path to wordlist: ").strip()

        if not path:
            return None

        # Check if file exists
        if not os.path.exists(path):
            print(f"\nError: File not found: {path}")
            input("\nPress Enter to continue...")
            return None

        # Get or generate metadata
        entry = self.manager.get_wordlist(path)

        if not entry:
            print(f"\nError: Could not read wordlist: {path}")
            input("\nPress Enter to continue...")
            return None

        print(f"\nSelected: {entry.name}")
        return entry
