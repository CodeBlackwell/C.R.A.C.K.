"""Unit tests for attack chain command resolution support."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import types

import pytest

# The top-level ``crack`` package eagerly imports optional modules that are not
# required for these unit tests and currently contain syntax issues. To avoid
# importing that package initializer we provide a lightweight namespace package
# stub that exposes the real package directory via ``__path__``.
PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if "crack" not in sys.modules:
    crack_stub = types.ModuleType("crack")
    crack_stub.__path__ = [str(PACKAGE_ROOT)]
    sys.modules["crack"] = crack_stub

if "jsonschema" not in sys.modules:
    jsonschema_stub = types.ModuleType("jsonschema")

    class _DraftValidator:  # pragma: no cover - minimal stand-in for tests
        def __init__(self, schema: object) -> None:
            self.schema = schema

        def iter_errors(self, instance: object):
            return []

    class _ValidationError(Exception):
        pass

    def _validate(instance: object, schema: object) -> None:
        return None

    jsonschema_stub.Draft202012Validator = _DraftValidator
    jsonschema_stub.ValidationError = _ValidationError
    jsonschema_stub.validate = _validate
    sys.modules["jsonschema"] = jsonschema_stub

from crack.reference.chains.command_resolver import CommandResolver
from crack.reference.chains.loader import ChainLoader
from crack.reference.chains.validator import ChainValidator


@pytest.fixture()
def sample_chain(tmp_path: Path) -> Path:
    """Create a minimal attack chain definition on disk for loader tests."""

    chain = {
        "id": "linux-priv-esc-demo",
        "name": "Demo PrivEsc Chain",
        "description": "Minimal chain used for unit testing",
        "version": "1.0.0",
        "metadata": {
            "author": "Unit Tester",
            "created": "2024-01-01",
            "updated": "2024-01-01",
            "tags": ["demo"],
            "category": "privilege_escalation",
            "platform": "linux",
        },
        "difficulty": "beginner",
        "time_estimate": "30 minutes",
        "oscp_relevant": True,
        "steps": [
            {
                "id": "gather-info",
                "name": "Gather System Info",
                "objective": "Collect privilege escalation insights",
                "command_ref": "system-enum-command",
            }
        ],
    }

    path = tmp_path / "demo-chain.json"
    path.write_text(json.dumps(chain), encoding="utf-8")
    return path


class TestCommandResolver:
    """CommandResolver behaviour and helper utilities."""

    @pytest.mark.unit
    def test_extract_command_refs(self) -> None:
        resolver = CommandResolver(commands={"known": {"id": "known"}})
        chain = {
            "steps": [
                {"command_ref": "known"},
                {"command_ref": "missing"},
                {"name": "no command"},
            ]
        }

        references = resolver.extract_command_refs(chain)

        assert references == ["known", "missing"]

    @pytest.mark.unit
    def test_validate_references_reports_missing(self) -> None:
        resolver = CommandResolver(commands={"existing": {"id": "existing"}})

        missing = resolver.validate_references(["existing", "missing", "missing"])

        assert "missing" in missing
        assert "existing" not in missing
        assert "could not be resolved" in missing["missing"]

    @pytest.mark.unit
    def test_resolve_command_ref_prefers_known_commands(self) -> None:
        sentinel = {"id": "sentinel"}
        resolver = CommandResolver(commands={"sentinel": sentinel})

        assert resolver.resolve_command_ref("sentinel") is sentinel
        assert resolver.resolve_command_ref("unknown") is None


class TestChainValidationIntegration:
    """Integration tests that ensure validators honour the resolver."""

    @pytest.mark.unit
    def test_validate_command_refs_uses_resolver(self) -> None:
        resolver = CommandResolver(commands={"valid-command": {"id": "valid-command"}})
        validator = ChainValidator(command_resolver=resolver)
        chain = {
            "steps": [
                {
                    "id": "step-one",
                    "name": "Valid Step",
                    "objective": "Do the thing",
                    "command_ref": "valid-command",
                },
                {
                    "name": "Missing Command",
                    "objective": "Break",
                    "command_ref": "unknown-command",
                },
                {
                    "name": "No Command",
                    "objective": "Also break",
                },
            ]
        }

        errors = validator.validate_command_refs(chain)

        assert len(errors) == 2
        assert "unknown-command" in "\n".join(errors)
        assert any("missing required command_ref" in error for error in errors)

    @pytest.mark.unit
    def test_loader_rejects_chain_with_missing_command(self, sample_chain: Path) -> None:
        resolver = CommandResolver(commands={})
        loader = ChainLoader(command_resolver=resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_chain(sample_chain)

        assert "Command validation failed" in str(excinfo.value)

    @pytest.mark.unit
    def test_loader_accepts_chain_with_known_command(self, sample_chain: Path) -> None:
        resolver = CommandResolver(commands={"system-enum-command": {"id": "system-enum-command"}})
        loader = ChainLoader(command_resolver=resolver)

        chain = loader.load_chain(sample_chain)

        assert chain["id"] == "linux-priv-esc-demo"
        assert chain["steps"][0]["command_ref"] == "system-enum-command"
