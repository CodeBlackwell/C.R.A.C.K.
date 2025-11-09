"""
Tests for validation framework.
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from validation import FieldValidator, ValidationResult


class TestFieldValidator(unittest.TestCase):
    """Tests for FieldValidator class"""

    def setUp(self):
        """Set up test fixtures"""
        self.validator = FieldValidator()

    def test_validate_node_extraction_valid(self):
        """Test validation of valid node extraction"""
        data = [
            {'id': '1', 'name': 'test', 'category': 'example'},
            {'id': '2', 'name': 'test2', 'category': 'example2'}
        ]

        result = self.validator.validate_node_extraction(
            entity_type='Command',
            expected_fields=['id', 'name', 'category'],
            id_field='id',
            extracted_data=data
        )

        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)
        self.assertEqual(len(result.warnings), 0)

    def test_validate_node_extraction_missing_fields(self):
        """Test validation detects missing fields"""
        data = [
            {'id': '1', 'name': 'test'},  # Missing 'category'
        ]

        result = self.validator.validate_node_extraction(
            entity_type='Command',
            expected_fields=['id', 'name', 'category'],
            id_field='id',
            extracted_data=data
        )

        self.assertFalse(result.is_valid)
        self.assertTrue(result.has_errors)
        self.assertEqual(len(result.errors), 1)

    def test_validate_node_extraction_missing_id(self):
        """Test validation detects missing ID field"""
        data = [
            {'name': 'test', 'category': 'example'},  # Missing 'id'
        ]

        result = self.validator.validate_node_extraction(
            entity_type='Command',
            expected_fields=['id', 'name', 'category'],
            id_field='id',
            extracted_data=data
        )

        self.assertFalse(result.is_valid)
        self.assertTrue(result.has_errors)
        # Should have 2 errors: missing 'id' field + empty ID
        self.assertGreaterEqual(len(result.errors), 1)

    def test_validate_node_extraction_extra_fields(self):
        """Test validation warns about extra fields"""
        data = [
            {'id': '1', 'name': 'test', 'category': 'example', 'extra': 'field'},
        ]

        result = self.validator.validate_node_extraction(
            entity_type='Command',
            expected_fields=['id', 'name', 'category'],
            id_field='id',
            extracted_data=data
        )

        self.assertTrue(result.is_valid)  # Extra fields are warnings, not errors
        self.assertFalse(result.has_errors)
        self.assertTrue(result.has_warnings)

    def test_validate_node_extraction_empty_data(self):
        """Test validation handles empty data"""
        result = self.validator.validate_node_extraction(
            entity_type='Command',
            expected_fields=['id', 'name', 'category'],
            id_field='id',
            extracted_data=[]
        )

        self.assertTrue(result.is_valid)  # Empty is warning, not error
        self.assertTrue(result.has_warnings)

    def test_validate_relationship_extraction_valid(self):
        """Test validation of valid relationship extraction"""
        data = [
            {'command_id': 'cmd1', 'variable_id': 'var1', 'position': '0'},
            {'command_id': 'cmd2', 'variable_id': 'var2', 'position': '1'}
        ]

        result = self.validator.validate_relationship_extraction(
            entity_type='USES_VARIABLE',
            expected_fields=['command_id', 'variable_id', 'position'],
            start_id_col='command_id',
            end_id_col='variable_id',
            extracted_data=data
        )

        self.assertTrue(result.is_valid)
        self.assertEqual(len(result.errors), 0)

    def test_validate_relationship_extraction_missing_start_id(self):
        """Test validation detects missing start ID"""
        data = [
            {'variable_id': 'var1', 'position': '0'},  # Missing command_id
        ]

        result = self.validator.validate_relationship_extraction(
            entity_type='USES_VARIABLE',
            expected_fields=['command_id', 'variable_id', 'position'],
            start_id_col='command_id',
            end_id_col='variable_id',
            extracted_data=data
        )

        self.assertFalse(result.is_valid)
        self.assertTrue(result.has_errors)


class TestValidationResult(unittest.TestCase):
    """Tests for ValidationResult class"""

    def test_add_error(self):
        """Test adding errors"""
        result = ValidationResult(is_valid=True)
        result.add_error('Command', 'Test error')

        self.assertFalse(result.is_valid)
        self.assertTrue(result.has_errors)
        self.assertEqual(len(result.errors), 1)

    def test_add_warning(self):
        """Test adding warnings"""
        result = ValidationResult(is_valid=True)
        result.add_warning('Command', 'Test warning')

        self.assertTrue(result.is_valid)  # Warnings don't affect validity
        self.assertTrue(result.has_warnings)
        self.assertEqual(len(result.warnings), 1)

    def test_merge(self):
        """Test merging validation results"""
        result1 = ValidationResult(is_valid=True)
        result1.add_error('Command', 'Error 1')

        result2 = ValidationResult(is_valid=True)
        result2.add_warning('Variable', 'Warning 1')

        result1.merge(result2)

        self.assertFalse(result1.is_valid)
        self.assertEqual(len(result1.errors), 1)
        self.assertEqual(len(result1.warnings), 1)


if __name__ == '__main__':
    unittest.main()
