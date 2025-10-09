"""
Fixtures for wordlist selection tests
"""

import pytest
from pathlib import Path
import tempfile
import shutil


@pytest.fixture
def temp_wordlists_dir(tmp_path):
    """
    Create temporary wordlists directory with test files

    Structure:
        wordlists/
        ├── dirb/
        │   ├── common.txt (100 lines)
        │   └── small.txt (50 lines)
        ├── passwords/
        │   ├── rockyou.txt (1000 lines, simulated large file)
        │   └── common-passwords.txt (20 lines)
        ├── seclists/
        │   └── Discovery/
        │       └── DNS/
        │           └── subdomains-top1000.txt (100 lines)
        └── custom-list.txt (10 lines)
    """
    wordlists_root = tmp_path / "wordlists"
    wordlists_root.mkdir()

    # DIRB wordlists (web enumeration)
    dirb_dir = wordlists_root / "dirb"
    dirb_dir.mkdir()

    common_txt = dirb_dir / "common.txt"
    common_txt.write_text("\n".join([f"directory{i}" for i in range(100)]))

    small_txt = dirb_dir / "small.txt"
    small_txt.write_text("\n".join([f"dir{i}" for i in range(50)]))

    # Password wordlists
    passwords_dir = wordlists_root / "passwords"
    passwords_dir.mkdir()

    rockyou_txt = passwords_dir / "rockyou.txt"
    # Simulate large file with 1000 lines
    rockyou_txt.write_text("\n".join([f"password{i}" for i in range(1000)]))

    common_passwords = passwords_dir / "common-passwords.txt"
    common_passwords.write_text("\n".join(["password", "admin", "123456", "letmein", "qwerty"]))

    # SecLists structure
    seclists_dir = wordlists_root / "seclists" / "Discovery" / "DNS"
    seclists_dir.mkdir(parents=True)

    subdomains_txt = seclists_dir / "subdomains-top1000.txt"
    subdomains_txt.write_text("\n".join([f"subdomain{i}" for i in range(100)]))

    # Custom wordlist at root
    custom_list = wordlists_root / "custom-list.txt"
    custom_list.write_text("\n".join([f"custom{i}" for i in range(10)]))

    return wordlists_root


@pytest.fixture
def temp_cache_file(tmp_path):
    """
    Create temporary cache file path

    Returns path but doesn't create file (manager will create it)
    """
    cache_dir = tmp_path / ".crack"
    cache_dir.mkdir()
    return cache_dir / "wordlists_cache.json"


@pytest.fixture
def mock_wordlist_entry():
    """
    Create sample WordlistEntry for testing

    Returns dict matching WordlistEntry dataclass structure
    """
    return {
        'path': '/usr/share/wordlists/dirb/common.txt',
        'name': 'common.txt',
        'category': 'web',
        'size_bytes': 4614,
        'line_count': 4615,
        'avg_word_length': 7.5,
        'description': 'DIRB common wordlist',
        'last_scanned': 1699564800
    }


@pytest.fixture
def large_wordlist_file(tmp_path):
    """
    Create large wordlist file for performance testing (100K lines)

    PROVES: Metadata generation handles large files efficiently
    """
    large_file = tmp_path / "large-wordlist.txt"

    # Generate 100K lines (simulates rockyou.txt size for testing)
    # Each line ~8 chars = ~800KB total
    with large_file.open('w') as f:
        for i in range(100000):
            f.write(f"word{i:05d}\n")

    return large_file


@pytest.fixture
def wordlists_with_various_sizes(tmp_path):
    """
    Create wordlists of various sizes for sampling tests

    Returns:
        dict with keys: small, medium, large (file paths)
    """
    test_dir = tmp_path / "size_test"
    test_dir.mkdir()

    files = {}

    # Small: 100 lines (exact count)
    files['small'] = test_dir / "small.txt"
    files['small'].write_text("\n".join([f"word{i}" for i in range(100)]))

    # Medium: 5000 lines (sample-based)
    files['medium'] = test_dir / "medium.txt"
    files['medium'].write_text("\n".join([f"word{i}" for i in range(5000)]))

    # Large: 50000 lines (estimate-based)
    files['large'] = test_dir / "large.txt"
    with files['large'].open('w') as f:
        for i in range(50000):
            f.write(f"word{i:05d}\n")

    return files


@pytest.fixture
def wordlists_by_category(tmp_path):
    """
    Create wordlists organized by expected category

    Returns dict: {category: [file_paths]}

    PROVES: Category detection works correctly
    """
    root = tmp_path / "categorized"
    root.mkdir()

    categories = {}

    # Web enumeration
    web_dir = root / "web"
    web_dir.mkdir()
    categories['web'] = [
        web_dir / "common.txt",
        web_dir / "directory-list.txt"
    ]
    for path in categories['web']:
        path.write_text("directory1\ndirectory2\n")

    # Password cracking
    pwd_dir = root / "passwords"
    pwd_dir.mkdir()
    categories['passwords'] = [
        pwd_dir / "rockyou.txt",
        pwd_dir / "common-passwords.txt"
    ]
    for path in categories['passwords']:
        path.write_text("password1\npassword2\n")

    # Subdomains
    subdomain_dir = root / "subdomains"
    subdomain_dir.mkdir()
    categories['subdomains'] = [
        subdomain_dir / "subdomains-top1000.txt"
    ]
    for path in categories['subdomains']:
        path.write_text("subdomain1\nsubdomain2\n")

    # Usernames
    username_dir = root / "usernames"
    username_dir.mkdir()
    categories['usernames'] = [
        username_dir / "common-usernames.txt"
    ]
    for path in categories['usernames']:
        path.write_text("admin\nroot\n")

    # General (no clear category)
    categories['general'] = [
        root / "custom-list.txt"
    ]
    for path in categories['general']:
        path.write_text("item1\nitem2\n")

    return categories


@pytest.fixture
def empty_wordlist_dir(tmp_path):
    """
    Create empty directory for edge case testing

    PROVES: Manager handles empty directories gracefully
    """
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    return empty_dir


@pytest.fixture
def permission_denied_dir(tmp_path):
    """
    Create directory with permission issues (Unix only)

    PROVES: Manager handles permission errors gracefully
    """
    restricted_dir = tmp_path / "restricted"
    restricted_dir.mkdir()

    # Create a file but make it unreadable
    restricted_file = restricted_dir / "unreadable.txt"
    restricted_file.write_text("secret\n")
    restricted_file.chmod(0o000)

    yield restricted_dir

    # Cleanup: restore permissions
    restricted_file.chmod(0o644)


@pytest.fixture
def symlink_wordlist_dir(tmp_path):
    """
    Create directory with symlinks to test skip behavior

    PROVES: Manager skips symlinks correctly
    """
    symlink_dir = tmp_path / "symlinks"
    symlink_dir.mkdir()

    # Real file
    real_file = symlink_dir / "real.txt"
    real_file.write_text("real\n")

    # Symlink to file
    symlink_file = symlink_dir / "link.txt"
    symlink_file.symlink_to(real_file)

    return symlink_dir
