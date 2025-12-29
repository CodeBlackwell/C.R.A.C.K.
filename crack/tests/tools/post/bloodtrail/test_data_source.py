"""
BloodTrail Data Source Tests

Business Value Focus:
- Users can import from directories and ZIP files
- Encoding issues (UTF-8, BOM, Latin-1) are handled gracefully
- Invalid paths produce clear error messages
- ZIP files with nested directories are handled

Ownership: tests/tools/post/bloodtrail/ (exclusive)
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
import json
import tempfile
import zipfile

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# DIRECTORY DATA SOURCE TESTS
# =============================================================================

class TestDirectoryDataSource(unittest.TestCase):
    """Tests for DirectoryDataSource class."""

    def test_creates_from_valid_directory(self):
        """
        BV: Users can open BloodHound output directories

        Scenario:
          Given: Valid directory path
          When: DirectoryDataSource is created
          Then: No error, source is usable
        """
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            source = DirectoryDataSource(Path(tmpdir))

            self.assertEqual(source.source_type, "directory")
            self.assertEqual(source.source_path, Path(tmpdir))

    def test_raises_for_nonexistent_directory(self):
        """
        BV: Clear error for missing paths

        Scenario:
          Given: Nonexistent path
          When: DirectoryDataSource is created
          Then: FileNotFoundError is raised
        """
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        with self.assertRaises(FileNotFoundError):
            DirectoryDataSource(Path("/nonexistent/path/12345"))

    def test_raises_for_file_not_directory(self):
        """
        BV: Clear error when file is passed instead of directory

        Scenario:
          Given: Path to a file
          When: DirectoryDataSource is created
          Then: ValueError is raised
        """
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaises(ValueError):
                DirectoryDataSource(Path(f.name))

    def test_lists_json_files(self):
        """
        BV: All JSON files in directory are discovered

        Scenario:
          Given: Directory with JSON files
          When: list_json_files() is called
          Then: All JSON files are returned
        """
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create test files
            (tmppath / "users.json").write_text("{}")
            (tmppath / "computers.json").write_text("{}")
            (tmppath / "other.txt").write_text("")  # Not JSON

            source = DirectoryDataSource(tmppath)
            files = source.list_json_files()

            self.assertEqual(len(files), 2)
            self.assertIn("users.json", files)
            self.assertIn("computers.json", files)
            self.assertNotIn("other.txt", files)

    def test_reads_json_file(self):
        """
        BV: JSON files are correctly parsed

        Scenario:
          Given: Directory with JSON file
          When: read_json() is called
          Then: Parsed dict is returned
        """
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            data = {"key": "value", "nested": {"a": 1}}
            (tmppath / "test.json").write_text(json.dumps(data))

            source = DirectoryDataSource(tmppath)
            result = source.read_json("test.json")

            self.assertEqual(result["key"], "value")
            self.assertEqual(result["nested"]["a"], 1)

    def test_iterates_json_files(self):
        """
        BV: All JSON files can be iterated

        Scenario:
          Given: Directory with multiple JSON files
          When: iter_json_files() is called
          Then: Each (filename, data) pair is yielded
        """
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            (tmppath / "file1.json").write_text('{"id": 1}')
            (tmppath / "file2.json").write_text('{"id": 2}')

            source = DirectoryDataSource(tmppath)
            results = list(source.iter_json_files())

            self.assertEqual(len(results), 2)
            filenames = [r[0] for r in results]
            self.assertIn("file1.json", filenames)
            self.assertIn("file2.json", filenames)

    def test_handles_utf8_bom_encoding(self):
        """
        BV: Windows-generated JSON with BOM is handled

        Scenario:
          Given: JSON file with UTF-8 BOM
          When: read_json() is called
          Then: File is correctly parsed
        """
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Write with BOM
            content = '\ufeff{"test": "value"}'
            (tmppath / "bom.json").write_text(content, encoding='utf-8')

            source = DirectoryDataSource(tmppath)
            result = source.read_json("bom.json")

            self.assertEqual(result["test"], "value")


# =============================================================================
# ZIP DATA SOURCE TESTS
# =============================================================================

class TestZipDataSource(unittest.TestCase):
    """Tests for ZipDataSource class."""

    def _create_test_zip(self, tmpdir, files):
        """Helper to create test ZIP file."""
        zip_path = Path(tmpdir) / "test.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return zip_path

    def test_creates_from_valid_zip(self):
        """
        BV: Users can open SharpHound ZIP output

        Scenario:
          Given: Valid ZIP file path
          When: ZipDataSource is created
          Then: No error, source is usable
        """
        from tools.post.bloodtrail.data_source import ZipDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = self._create_test_zip(tmpdir, {"test.json": "{}"})

            source = ZipDataSource(zip_path)

            self.assertEqual(source.source_type, "zip")
            self.assertEqual(source.source_path, zip_path)

    def test_raises_for_nonexistent_zip(self):
        """
        BV: Clear error for missing ZIP

        Scenario:
          Given: Nonexistent path
          When: ZipDataSource is created
          Then: FileNotFoundError is raised
        """
        from tools.post.bloodtrail.data_source import ZipDataSource

        with self.assertRaises(FileNotFoundError):
            ZipDataSource(Path("/nonexistent/file.zip"))

    def test_raises_for_invalid_zip(self):
        """
        BV: Clear error for corrupt/invalid ZIP

        Scenario:
          Given: File that is not a valid ZIP
          When: ZipDataSource is created
          Then: ValueError is raised
        """
        from tools.post.bloodtrail.data_source import ZipDataSource

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(b"not a zip file")
            f.flush()

            with self.assertRaises(ValueError):
                ZipDataSource(Path(f.name))

    def test_lists_json_files_in_zip(self):
        """
        BV: All JSON files in ZIP are discovered

        Scenario:
          Given: ZIP with JSON files
          When: list_json_files() is called
          Then: All JSON filenames are returned
        """
        from tools.post.bloodtrail.data_source import ZipDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = self._create_test_zip(tmpdir, {
                "users.json": "{}",
                "computers.json": "{}",
                "readme.txt": "info",
            })

            source = ZipDataSource(zip_path)
            files = source.list_json_files()

            self.assertEqual(len(files), 2)
            self.assertIn("users.json", files)
            self.assertIn("computers.json", files)

    def test_handles_nested_directories_in_zip(self):
        """
        BV: SharpHound ZIPs with nested dirs are handled

        Scenario:
          Given: ZIP with files in subdirectory
          When: list_json_files() is called
          Then: Nested JSON files are found
        """
        from tools.post.bloodtrail.data_source import ZipDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = self._create_test_zip(tmpdir, {
                "bloodhound/users.json": "{}",
                "bloodhound/computers.json": "{}",
            })

            source = ZipDataSource(zip_path)
            files = source.list_json_files()

            self.assertEqual(len(files), 2)

    def test_reads_json_from_zip(self):
        """
        BV: JSON files in ZIP are correctly parsed

        Scenario:
          Given: ZIP with JSON file
          When: read_json() is called
          Then: Parsed dict is returned
        """
        from tools.post.bloodtrail.data_source import ZipDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            content = json.dumps({"key": "value"})
            zip_path = self._create_test_zip(tmpdir, {"test.json": content})

            source = ZipDataSource(zip_path)
            result = source.read_json("test.json")

            self.assertEqual(result["key"], "value")

    def test_iterates_json_files_in_zip(self):
        """
        BV: All JSON files in ZIP can be iterated

        Scenario:
          Given: ZIP with multiple JSON files
          When: iter_json_files() is called
          Then: Each (filename, data) pair is yielded
        """
        from tools.post.bloodtrail.data_source import ZipDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = self._create_test_zip(tmpdir, {
                "file1.json": '{"id": 1}',
                "file2.json": '{"id": 2}',
            })

            source = ZipDataSource(zip_path)
            results = list(source.iter_json_files())

            self.assertEqual(len(results), 2)

    def test_skips_macosx_metadata(self):
        """
        BV: macOS metadata files are ignored

        Scenario:
          Given: ZIP with __MACOSX metadata
          When: list_json_files() is called
          Then: Metadata files are excluded
        """
        from tools.post.bloodtrail.data_source import ZipDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = self._create_test_zip(tmpdir, {
                "users.json": "{}",
                "__MACOSX/._users.json": "{}",
            })

            source = ZipDataSource(zip_path)
            files = source.list_json_files()

            self.assertEqual(len(files), 1)
            self.assertNotIn("._users.json", str(files))

    def test_close_releases_resources(self):
        """
        BV: ZIP file handle is released after use

        Scenario:
          Given: Open ZipDataSource
          When: close() is called
          Then: File handle is released
        """
        from tools.post.bloodtrail.data_source import ZipDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = self._create_test_zip(tmpdir, {"test.json": "{}"})

            source = ZipDataSource(zip_path)
            source.list_json_files()  # Trigger lazy open
            source.close()

            # Internal zipfile should be closed
            self.assertIsNone(source._zipfile)

    def test_context_manager_support(self):
        """
        BV: ZipDataSource can be used with 'with' statement

        Scenario:
          Given: ZipDataSource
          When: Used as context manager
          Then: Automatically closes on exit
        """
        from tools.post.bloodtrail.data_source import ZipDataSource

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = self._create_test_zip(tmpdir, {"test.json": "{}"})

            with ZipDataSource(zip_path) as source:
                files = source.list_json_files()
                self.assertEqual(len(files), 1)

            # Should be closed after exiting context
            self.assertIsNone(source._zipfile)


# =============================================================================
# FACTORY FUNCTION TESTS
# =============================================================================

class TestCreateDataSource(unittest.TestCase):
    """Tests for create_data_source() factory function."""

    def test_creates_directory_source_for_dir(self):
        """
        BV: Factory auto-detects directory

        Scenario:
          Given: Directory path
          When: create_data_source() is called
          Then: DirectoryDataSource is returned
        """
        from tools.post.bloodtrail.data_source import create_data_source

        with tempfile.TemporaryDirectory() as tmpdir:
            source = create_data_source(Path(tmpdir))

            self.assertEqual(source.source_type, "directory")

    def test_creates_zip_source_for_zip(self):
        """
        BV: Factory auto-detects ZIP files

        Scenario:
          Given: ZIP file path
          When: create_data_source() is called
          Then: ZipDataSource is returned
        """
        from tools.post.bloodtrail.data_source import create_data_source

        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "test.zip"
            with zipfile.ZipFile(zip_path, 'w') as zf:
                zf.writestr("test.json", "{}")

            source = create_data_source(zip_path)

            self.assertEqual(source.source_type, "zip")

    def test_raises_for_nonexistent_path(self):
        """
        BV: Clear error for invalid paths

        Scenario:
          Given: Nonexistent path
          When: create_data_source() is called
          Then: FileNotFoundError is raised
        """
        from tools.post.bloodtrail.data_source import create_data_source

        with self.assertRaises(FileNotFoundError):
            create_data_source(Path("/nonexistent/path"))


# =============================================================================
# VALIDATION FUNCTION TESTS
# =============================================================================

class TestIsValidBloodHoundSource(unittest.TestCase):
    """Tests for is_valid_bloodhound_source() function."""

    def test_valid_directory_returns_true(self):
        """
        BV: Valid directories are accepted

        Scenario:
          Given: Directory with JSON files
          When: is_valid_bloodhound_source() is called
          Then: Returns (True, message)
        """
        from tools.post.bloodtrail.data_source import is_valid_bloodhound_source

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "users.json").write_text("{}")

            is_valid, message = is_valid_bloodhound_source(Path(tmpdir))

            self.assertTrue(is_valid)
            self.assertIn("JSON", message)

    def test_empty_directory_returns_false(self):
        """
        BV: Empty directories are rejected

        Scenario:
          Given: Empty directory
          When: is_valid_bloodhound_source() is called
          Then: Returns (False, message)
        """
        from tools.post.bloodtrail.data_source import is_valid_bloodhound_source

        with tempfile.TemporaryDirectory() as tmpdir:
            is_valid, message = is_valid_bloodhound_source(Path(tmpdir))

            self.assertFalse(is_valid)
            self.assertIn("No JSON", message)

    def test_nonexistent_returns_false(self):
        """
        BV: Nonexistent paths are rejected

        Scenario:
          Given: Nonexistent path
          When: is_valid_bloodhound_source() is called
          Then: Returns (False, message)
        """
        from tools.post.bloodtrail.data_source import is_valid_bloodhound_source

        is_valid, message = is_valid_bloodhound_source(Path("/nonexistent"))

        self.assertFalse(is_valid)
        self.assertIn("not found", message)


if __name__ == "__main__":
    unittest.main()
