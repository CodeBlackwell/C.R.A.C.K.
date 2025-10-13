"""
Tests for ChainActivation and ParsingResult extensions.

Validates backward compatibility and new activation functionality.
"""

import pytest
from dataclasses import asdict
from crack.reference.chains.parsing.base import (
    ChainActivation,
    ParsingResult,
)


class TestChainActivation:
    """Test ChainActivation dataclass"""

    def test_create_with_required_fields(self):
        """ChainActivation can be created with required fields only"""
        activation = ChainActivation(
            chain_id="test-chain",
            reason="Test reason"
        )

        assert activation.chain_id == "test-chain"
        assert activation.reason == "Test reason"
        assert activation.confidence == "high"  # Default
        assert activation.variables == {}  # Default

    def test_create_with_all_fields(self):
        """ChainActivation can be created with all fields"""
        activation = ChainActivation(
            chain_id="linux-privesc-sudo",
            reason="Found 3 GTFOBins entries",
            confidence="medium",
            variables={"<BINARY>": "vim", "<TARGET>": "192.168.1.1"}
        )

        assert activation.chain_id == "linux-privesc-sudo"
        assert activation.reason == "Found 3 GTFOBins entries"
        assert activation.confidence == "medium"
        assert activation.variables == {"<BINARY>": "vim", "<TARGET>": "192.168.1.1"}

    def test_confidence_levels(self):
        """ChainActivation supports different confidence levels"""
        for level in ["high", "medium", "low"]:
            activation = ChainActivation(
                chain_id="test",
                reason="test",
                confidence=level
            )
            assert activation.confidence == level

    def test_empty_variables_dict(self):
        """ChainActivation with no variables has empty dict (not None)"""
        activation = ChainActivation(chain_id="test", reason="test")
        assert activation.variables == {}
        assert isinstance(activation.variables, dict)

    def test_dataclass_equality(self):
        """ChainActivation instances are equal if fields match"""
        act1 = ChainActivation(
            chain_id="test",
            reason="reason",
            confidence="high",
            variables={"<A>": "1"}
        )
        act2 = ChainActivation(
            chain_id="test",
            reason="reason",
            confidence="high",
            variables={"<A>": "1"}
        )

        assert act1 == act2

    def test_dataclass_inequality(self):
        """ChainActivation instances are unequal if any field differs"""
        base = ChainActivation(chain_id="test", reason="reason")

        # Different chain_id
        assert base != ChainActivation(chain_id="other", reason="reason")

        # Different reason
        assert base != ChainActivation(chain_id="test", reason="other")

        # Different confidence
        assert base != ChainActivation(
            chain_id="test",
            reason="reason",
            confidence="low"
        )

        # Different variables
        assert base != ChainActivation(
            chain_id="test",
            reason="reason",
            variables={"<A>": "1"}
        )

    def test_to_dict_conversion(self):
        """ChainActivation can be converted to dict (for JSON serialization)"""
        activation = ChainActivation(
            chain_id="test-chain",
            reason="Test reason",
            confidence="medium",
            variables={"<VAR>": "value"}
        )

        data = asdict(activation)

        assert data == {
            'chain_id': 'test-chain',
            'reason': 'Test reason',
            'confidence': 'medium',
            'variables': {'<VAR>': 'value'}
        }


class TestParsingResultBackwardCompatibility:
    """Test backward compatibility with existing parsers"""

    def test_create_without_activates_chains(self):
        """ParsingResult can be created without activates_chains (backward compat)"""
        result = ParsingResult(
            findings={'binaries': ['vim', 'nano']},
            variables={'<BINARY>': 'vim'},
            parser_name='test-parser',
            success=True
        )

        assert result.activates_chains == []  # Default empty list
        assert not result.has_activations()

    def test_old_parser_style_still_works(self):
        """Old-style parser return values work without modification"""
        # Simulate old parser that doesn't know about activates_chains
        result = ParsingResult(
            findings={'count': 3},
            variables={'<VAR>': 'value'}
        )

        # All old fields work
        assert result.findings == {'count': 3}
        assert result.variables == {'<VAR>': 'value'}
        assert result.has_selections() is False
        assert result.get_all_variables() == {'<VAR>': 'value'}

        # New field exists with safe default
        assert hasattr(result, 'activates_chains')
        assert result.activates_chains == []
        assert result.has_activations() is False


class TestParsingResultWithActivations:
    """Test ParsingResult with new activation functionality"""

    def test_create_with_activations(self):
        """ParsingResult can be created with activation suggestions"""
        activations = [
            ChainActivation(
                chain_id="sudo-chain",
                reason="Found sudo entries",
                confidence="high"
            ),
            ChainActivation(
                chain_id="suid-chain",
                reason="Found SUID binaries",
                confidence="medium"
            )
        ]

        result = ParsingResult(
            findings={'sudo_count': 3, 'suid_count': 5},
            parser_name='privesc-parser',
            activates_chains=activations
        )

        assert len(result.activates_chains) == 2
        assert result.has_activations() is True
        assert result.activates_chains[0].chain_id == "sudo-chain"
        assert result.activates_chains[1].chain_id == "suid-chain"

    def test_has_activations_true(self):
        """has_activations() returns True when activations exist"""
        result = ParsingResult(
            activates_chains=[
                ChainActivation(chain_id="test", reason="test")
            ]
        )

        assert result.has_activations() is True

    def test_has_activations_false_when_empty(self):
        """has_activations() returns False when list is empty"""
        result = ParsingResult(activates_chains=[])
        assert result.has_activations() is False

    def test_has_activations_false_when_none_specified(self):
        """has_activations() returns False when activates_chains not specified"""
        result = ParsingResult()
        assert result.has_activations() is False

    def test_multiple_activations_with_variables(self):
        """Multiple activations can each have different inherited variables"""
        result = ParsingResult(
            findings={'binaries': ['vim', 'nano', 'less']},
            activates_chains=[
                ChainActivation(
                    chain_id="exploit-vim",
                    reason="vim is GTFOBins exploitable",
                    variables={"<BINARY>": "vim"}
                ),
                ChainActivation(
                    chain_id="exploit-less",
                    reason="less is GTFOBins exploitable",
                    variables={"<BINARY>": "less"}
                )
            ]
        )

        assert len(result.activates_chains) == 2
        assert result.activates_chains[0].variables == {"<BINARY>": "vim"}
        assert result.activates_chains[1].variables == {"<BINARY>": "less"}

    def test_activation_with_complex_variables(self):
        """Activations can inherit complex variable sets"""
        result = ParsingResult(
            activates_chains=[
                ChainActivation(
                    chain_id="web-exploit",
                    reason="Found vulnerable web service",
                    variables={
                        "<TARGET>": "192.168.1.1",
                        "<PORT>": "8080",
                        "<URL>": "http://192.168.1.1:8080/admin"
                    }
                )
            ]
        )

        activation = result.activates_chains[0]
        assert activation.variables["<TARGET>"] == "192.168.1.1"
        assert activation.variables["<PORT>"] == "8080"
        assert activation.variables["<URL>"] == "http://192.168.1.1:8080/admin"

    def test_all_existing_methods_still_work(self):
        """All existing ParsingResult methods work with new field"""
        result = ParsingResult(
            findings={'binaries': ['vim']},
            variables={'<BINARY>': 'vim'},
            selection_required={'<PORT>': ['80', '443']},
            parser_name='test',
            success=True,
            warnings=['Warning 1'],
            activates_chains=[
                ChainActivation(chain_id="test", reason="test")
            ]
        )

        # Old methods
        assert result.has_selections() is True
        assert result.get_all_variables() == {'<BINARY>': 'vim'}

        # New method
        assert result.has_activations() is True

        # All fields accessible
        assert result.findings == {'binaries': ['vim']}
        assert result.parser_name == 'test'
        assert result.success is True
        assert result.warnings == ['Warning 1']

    def test_to_dict_includes_activations(self):
        """ParsingResult can be converted to dict including activations"""
        result = ParsingResult(
            findings={'count': 1},
            activates_chains=[
                ChainActivation(
                    chain_id="test-chain",
                    reason="Test",
                    confidence="high",
                    variables={"<VAR>": "val"}
                )
            ]
        )

        data = asdict(result)

        assert 'activates_chains' in data
        assert len(data['activates_chains']) == 1
        assert data['activates_chains'][0]['chain_id'] == 'test-chain'
        assert data['activates_chains'][0]['variables'] == {"<VAR>": "val"}


class TestParsingResultEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_empty_parsing_result(self):
        """Completely empty ParsingResult has safe defaults"""
        result = ParsingResult()

        assert result.findings == {}
        assert result.variables == {}
        assert result.selection_required == {}
        assert result.parser_name == ""
        assert result.success is True
        assert result.warnings == []
        assert result.activates_chains == []

    def test_large_activation_list(self):
        """ParsingResult can handle many activations"""
        activations = [
            ChainActivation(chain_id=f"chain-{i}", reason=f"Reason {i}")
            for i in range(100)
        ]

        result = ParsingResult(activates_chains=activations)

        assert len(result.activates_chains) == 100
        assert result.has_activations() is True

    def test_activation_with_special_characters_in_variables(self):
        """Activation variables can contain special characters"""
        result = ParsingResult(
            activates_chains=[
                ChainActivation(
                    chain_id="test",
                    reason="test",
                    variables={
                        "<PATH>": "/path/with/spaces and/special!chars",
                        "<CMD>": "echo 'quoted string'",
                        "<URL>": "http://example.com?param=value&other=123"
                    }
                )
            ]
        )

        vars = result.activates_chains[0].variables
        assert "/path/with/spaces and/special!chars" in vars["<PATH>"]
        assert "quoted string" in vars["<CMD>"]
        assert "?" in vars["<URL>"]
