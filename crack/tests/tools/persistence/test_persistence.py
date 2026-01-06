"""
Tests for the unified persistence layer.

Tests cover:
- RawInput model
- FileInput model
- UnifiedFinding model with provenance
- SQLite storage
- captured_run() subprocess wrapper
- DualStore unified interface
- PersistenceConfig (--no-prism flag)
"""

import os
import tempfile
import pytest
from datetime import datetime
from unittest.mock import patch

from crack.tools.persistence.config import PersistenceConfig
from crack.tools.persistence.models.raw_input import RawInput, FileInput
from crack.tools.persistence.models.finding import (
    UnifiedFinding,
    FindingType,
    FindingPriority,
)
from crack.tools.persistence.storage.sqlite_store import SQLiteStore
from crack.tools.persistence.storage.dual_store import DualStore, get_store, reset_store
from crack.tools.persistence.capture.subprocess_wrapper import (
    captured_run,
    CapturedResult,
)


class TestPersistenceConfig:
    """Tests for PersistenceConfig."""

    def setup_method(self):
        """Reset config state before each test."""
        PersistenceConfig._runtime_disabled = False

    def teardown_method(self):
        """Reset config state after each test."""
        PersistenceConfig._runtime_disabled = False

    def test_is_enabled_by_default(self):
        """Persistence is enabled by default."""
        assert PersistenceConfig.is_enabled() is True

    def test_disable_runtime(self):
        """Can disable persistence at runtime."""
        PersistenceConfig.disable()
        assert PersistenceConfig.is_enabled() is False

    def test_enable_after_disable(self):
        """Can re-enable persistence after disabling."""
        PersistenceConfig.disable()
        PersistenceConfig.enable()
        assert PersistenceConfig.is_enabled() is True

    def test_env_var_disables(self):
        """CRACK_NO_PRISM env var disables persistence."""
        with patch.dict(os.environ, {"CRACK_NO_PRISM": "1"}):
            assert PersistenceConfig.is_enabled() is False

    def test_env_var_values(self):
        """Various truthy values for CRACK_NO_PRISM."""
        for val in ("1", "true", "yes", "TRUE", "Yes"):
            with patch.dict(os.environ, {"CRACK_NO_PRISM": val}):
                assert PersistenceConfig.is_enabled() is False

        for val in ("0", "false", "no", ""):
            with patch.dict(os.environ, {"CRACK_NO_PRISM": val}):
                PersistenceConfig._runtime_disabled = False
                assert PersistenceConfig.is_enabled() is True


class TestRawInput:
    """Tests for RawInput model."""

    def test_create_raw_input(self):
        """Can create a RawInput with UUID."""
        raw = RawInput(
            command="nmap -sV target",
            source_tool="bloodtrail",
        )
        assert raw.id is not None
        assert len(raw.id) == 36  # UUID format
        assert raw.command == "nmap -sV target"
        assert raw.source_tool == "bloodtrail"

    def test_raw_input_with_output(self):
        """RawInput stores stdout/stderr."""
        raw = RawInput(
            command="echo hello",
            stdout=b"hello\n",
            stderr=b"",
            exit_code=0,
            source_tool="test",
        )
        assert raw.stdout_text == "hello\n"
        assert raw.stderr_text == ""
        assert raw.success is True

    def test_raw_input_failure(self):
        """RawInput correctly identifies failures."""
        raw = RawInput(
            command="false",
            exit_code=1,
            source_tool="test",
        )
        assert raw.success is False

    def test_raw_input_to_dict(self):
        """RawInput serializes to dict."""
        raw = RawInput(
            command="test",
            source_tool="bloodtrail",
            target_ip="10.10.10.100",
        )
        data = raw.to_dict()
        assert data["id"] == raw.id
        assert data["command"] == "test"
        assert data["source_tool"] == "bloodtrail"
        assert data["target_ip"] == "10.10.10.100"

    def test_raw_input_to_neo4j_dict(self):
        """RawInput Neo4j dict excludes blobs."""
        raw = RawInput(
            command="test",
            stdout=b"lots of output",
            stderr=b"some errors",
            source_tool="bloodtrail",
        )
        data = raw.to_neo4j_dict()
        assert "stdout" not in data
        assert "stderr" not in data
        assert data["command"] == "test"


class TestFileInput:
    """Tests for FileInput model."""

    def test_create_file_input(self):
        """Can create a FileInput."""
        fi = FileInput(
            file_path="/tmp/test.txt",
            content=b"file content",
        )
        assert fi.id is not None
        assert fi.file_path == "/tmp/test.txt"
        assert fi.content == b"file content"

    def test_file_input_from_file(self, tmp_path):
        """FileInput.from_file computes content hash."""
        # Create a temp file
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"hello world")

        fi = FileInput.from_file(str(test_file))
        # SHA256 of "hello world"
        assert fi.file_hash is not None
        assert len(fi.file_hash) == 64  # SHA256 hex
        assert fi.content == b"hello world"
        assert fi.file_size == 11


class TestUnifiedFinding:
    """Tests for UnifiedFinding model."""

    def test_create_finding_with_provenance(self):
        """Finding requires source_input_id for provenance."""
        finding = UnifiedFinding(
            id="test-finding-1",
            finding_type=FindingType.CREDENTIAL,
            source="ldap_attribute",
            target="r.thompson",
            raw_value="clk0bjVldmE=",
            source_input_id="raw-input-uuid-123",
            extraction_method="ldap_parser",
        )
        assert finding.source_input_id == "raw-input-uuid-123"
        assert finding.source_input_type == "raw"
        assert finding.extraction_method == "ldap_parser"

    def test_finding_priority(self):
        """Finding priority levels."""
        critical = UnifiedFinding(
            finding_type=FindingType.CREDENTIAL,
            source="test",
            target="user",
            raw_value="password",
            priority=FindingPriority.CRITICAL,
            source_input_id="test-id",
        )
        assert critical.priority == FindingPriority.CRITICAL
        assert critical.priority.value == 1

    def test_finding_to_neo4j_dict(self):
        """Finding serializes for Neo4j."""
        finding = UnifiedFinding(
            finding_type=FindingType.LDAP_ATTRIBUTE,
            source="ad_enum",
            target="cascadeLegacyPwd",
            raw_value="base64value",
            decoded_value="password123",
            decode_method="base64",
            source_input_id="test-raw-id",
            tags=["password", "base64"],
        )
        data = finding.to_neo4j_dict()
        assert data["finding_type"] == "ldap_attribute"
        assert data["decoded_value"] == "password123"
        assert "password" in data["tags"]


class TestSQLiteStore:
    """Tests for SQLite storage backend."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a temporary SQLite store."""
        db_path = tmp_path / "test.db"
        return SQLiteStore(str(db_path))

    def test_save_and_get_raw_input(self, store):
        """Can save and retrieve RawInput."""
        raw = RawInput(
            command="nmap -p 80 target",
            stdout=b"80/tcp open http",
            exit_code=0,
            source_tool="bloodtrail",
            target_ip="10.10.10.100",
        )
        store.save_raw_input(raw)

        retrieved = store.get_raw_input(raw.id)
        assert retrieved is not None
        assert retrieved.command == "nmap -p 80 target"
        assert retrieved.stdout == b"80/tcp open http"
        assert retrieved.target_ip == "10.10.10.100"

    def test_query_raw_inputs_by_tool(self, store):
        """Can query raw inputs by source tool."""
        for i in range(3):
            raw = RawInput(
                command=f"cmd{i}",
                source_tool="bloodtrail",
            )
            store.save_raw_input(raw)

        raw2 = RawInput(command="other", source_tool="prism")
        store.save_raw_input(raw2)

        results = store.query_raw_inputs(source_tool="bloodtrail")
        assert len(results) == 3

    def test_save_and_get_file_input(self, store):
        """Can save and retrieve FileInput."""
        fi = FileInput(
            file_path="/tmp/test.txt",
            content=b"file content here",
        )
        store.save_file_input(fi)

        retrieved = store.get_file_input(fi.id)
        assert retrieved is not None
        assert retrieved.file_path == "/tmp/test.txt"
        assert retrieved.content == b"file content here"

    def test_save_and_get_finding(self, store):
        """Can save and retrieve Finding."""
        # First save a raw input
        raw = RawInput(command="test", source_tool="test")
        store.save_raw_input(raw)

        # Then save a finding
        finding = UnifiedFinding(
            finding_type=FindingType.CREDENTIAL,
            source="test",
            target="admin",
            raw_value="password123",
            source_input_id=raw.id,
        )
        store.save_finding(finding)

        results = store.get_findings_for_input(raw.id)
        assert len(results) == 1
        assert results[0].target == "admin"
        assert results[0].raw_value == "password123"

    def test_mark_raw_input_parsed(self, store):
        """Can mark raw input as parsed."""
        raw = RawInput(command="test", source_tool="test")
        store.save_raw_input(raw)

        store.mark_raw_input_parsed(raw.id, "nmap_parser", finding_count=5)

        retrieved = store.get_raw_input(raw.id)
        assert retrieved.parsed is True
        assert retrieved.parser_used == "nmap_parser"
        assert retrieved.finding_count == 5

    def test_get_stats(self, store):
        """Can get storage statistics."""
        # Save some data
        store.save_raw_input(RawInput(command="cmd1", source_tool="test"))
        store.save_raw_input(RawInput(command="cmd2", source_tool="test"))
        store.save_file_input(FileInput(file_path="/test", content=b"x"))

        stats = store.get_stats()
        assert stats["raw_inputs"] == 2
        assert stats["file_inputs"] == 1


class TestCapturedRun:
    """Tests for captured_run() subprocess wrapper."""

    def setup_method(self):
        """Reset persistence state."""
        PersistenceConfig._runtime_disabled = False
        reset_store()

    def teardown_method(self):
        """Cleanup."""
        PersistenceConfig._runtime_disabled = False
        reset_store()

    def test_captured_run_basic(self, tmp_path):
        """captured_run executes command and captures output."""
        # Use temp dir for test db
        with patch.object(
            PersistenceConfig, 'get',
            return_value=PersistenceConfig(sqlite_path=str(tmp_path / "test.db"))
        ):
            result = captured_run(
                ["echo", "hello world"],
                source_tool="test",
            )
            assert result.returncode == 0
            assert b"hello world" in result.stdout
            assert result.raw_input is not None
            assert result.raw_input.command == "echo hello world"

    def test_captured_run_with_target(self, tmp_path):
        """captured_run stores target metadata."""
        with patch.object(
            PersistenceConfig, 'get',
            return_value=PersistenceConfig(sqlite_path=str(tmp_path / "test.db"))
        ):
            result = captured_run(
                ["echo", "test"],
                source_tool="bloodtrail",
                source_module="smb_crawler",
                target_ip="10.10.10.100",
            )
            assert result.raw_input.source_tool == "bloodtrail"
            assert result.raw_input.source_module == "smb_crawler"
            assert result.raw_input.target_ip == "10.10.10.100"

    def test_captured_run_disabled(self):
        """captured_run still works when persistence disabled."""
        PersistenceConfig.disable()
        result = captured_run(["echo", "test"], source_tool="test")
        assert result.returncode == 0
        assert b"test" in result.stdout
        # Note: raw_input is still populated for access to result data,
        # it just isn't persisted to storage
        assert result.raw_input is not None
        assert result.raw_input.command == "echo test"

    def test_captured_run_shell_command(self, tmp_path):
        """captured_run handles shell=True."""
        with patch.object(
            PersistenceConfig, 'get',
            return_value=PersistenceConfig(sqlite_path=str(tmp_path / "test.db"))
        ):
            result = captured_run(
                "echo 'shell mode'",
                shell=True,
                source_tool="test",
            )
            assert result.returncode == 0
            assert b"shell mode" in result.stdout


class TestDualStore:
    """Tests for DualStore unified interface."""

    @pytest.fixture
    def dual_store(self, tmp_path):
        """Create a DualStore with temp SQLite (no Neo4j)."""
        reset_store()
        with patch.object(
            PersistenceConfig, 'get',
            return_value=PersistenceConfig(
                sqlite_path=str(tmp_path / "test.db"),
                neo4j_uri="",  # Disable Neo4j
            )
        ):
            store = get_store()
            yield store
            reset_store()

    def test_dual_store_save_raw_input(self, dual_store):
        """DualStore saves to SQLite."""
        raw = RawInput(
            command="test command",
            stdout=b"output",
            source_tool="test",
        )
        dual_store.save_raw_input(raw)

        retrieved = dual_store.get_raw_input(raw.id)
        assert retrieved is not None
        assert retrieved.command == "test command"

    def test_dual_store_stats(self, dual_store):
        """DualStore returns combined stats."""
        raw = RawInput(command="test", source_tool="test")
        dual_store.save_raw_input(raw)

        stats = dual_store.get_stats()
        assert stats["raw_inputs"] == 1

    def test_dual_store_disabled(self):
        """DualStore operations are no-ops when persistence disabled."""
        reset_store()
        PersistenceConfig.disable()

        # get_store still returns a DualStore object (singleton)
        store = get_store()
        assert store is not None

        # But is_enabled returns False
        assert store.is_enabled() is False

        # And operations are no-ops
        raw = RawInput(command="test", source_tool="test")
        result = store.save_raw_input(raw)
        assert result is None  # Not saved

        # Stats show disabled
        stats = store.get_stats()
        assert stats.get("enabled") is False

        # Re-enable for other tests
        PersistenceConfig.enable()
        reset_store()


class TestProvenance:
    """Tests for provenance tracking (finding → raw_input)."""

    @pytest.fixture
    def store(self, tmp_path):
        """Create a SQLite store."""
        return SQLiteStore(str(tmp_path / "test.db"))

    def test_finding_links_to_raw_input(self, store):
        """Finding references source RawInput."""
        # Simulate: run command → get output → parse → create finding
        raw = RawInput(
            command="ldapsearch -x -h target -b 'dc=cascade,dc=local'",
            stdout=b"cascadeLegacyPwd: clk0bjVldmE=",
            source_tool="bloodtrail",
            target_ip="10.10.10.182",
        )
        store.save_raw_input(raw)

        # Parser creates finding with provenance
        finding = UnifiedFinding(
            finding_type=FindingType.LDAP_ATTRIBUTE,
            source="ldap",
            target="cascadeLegacyPwd",
            raw_value="clk0bjVldmE=",
            decoded_value="rY4n5eva",
            decode_method="base64",
            source_input_id=raw.id,  # PROVENANCE
            extraction_method="ldap_parser",
        )
        store.save_finding(finding)

        # Query: "what command found this?"
        findings = store.get_findings_for_input(raw.id)
        assert len(findings) == 1
        assert findings[0].source_input_id == raw.id

        # Can trace back to source
        source = store.get_raw_input(findings[0].source_input_id)
        assert source.command == "ldapsearch -x -h target -b 'dc=cascade,dc=local'"
        assert b"cascadeLegacyPwd" in source.stdout

    def test_multiple_findings_from_one_input(self, store):
        """Multiple findings can reference same raw input."""
        raw = RawInput(
            command="enum4linux target",
            stdout=b"user1\nuser2\nuser3",
            source_tool="bloodtrail",
        )
        store.save_raw_input(raw)

        for user in ["user1", "user2", "user3"]:
            finding = UnifiedFinding(
                finding_type=FindingType.INFO,  # Generic finding type
                source="enum4linux",
                target=user,
                raw_value=user,
                source_input_id=raw.id,
            )
            store.save_finding(finding)

        findings = store.get_findings_for_input(raw.id)
        assert len(findings) == 3
        assert all(f.source_input_id == raw.id for f in findings)
