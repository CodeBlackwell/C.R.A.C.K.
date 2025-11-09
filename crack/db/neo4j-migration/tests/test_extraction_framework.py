"""
Tests for extraction framework.
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from extraction import (
    ExtractionContext,
    SimpleNodeExtractor,
    generate_id
)


class TestExtractionContext(unittest.TestCase):
    """Tests for ExtractionContext class"""

    def setUp(self):
        """Set up test fixtures"""
        self.context = ExtractionContext()

    def test_generate_id(self):
        """Test ID generation"""
        id1 = self.context.generate_id("test")
        id2 = self.context.generate_id("test")

        # Same input should generate same ID
        self.assertEqual(id1, id2)

        # Different input should generate different ID
        id3 = self.context.generate_id("different")
        self.assertNotEqual(id1, id3)

    def test_next_id(self):
        """Test sequential ID generation"""
        id1 = self.context.next_id("entity")
        id2 = self.context.next_id("entity")

        self.assertEqual(id1, "entity_1")
        self.assertEqual(id2, "entity_2")

    def test_is_seen(self):
        """Test deduplication tracking"""
        self.assertFalse(self.context.is_seen("test_id"))

        self.context.mark_seen("test_id")
        self.assertTrue(self.context.is_seen("test_id"))

    def test_add_error(self):
        """Test error collection"""
        self.context.add_error("Test error")
        self.assertEqual(len(self.context.errors), 1)
        self.assertEqual(self.context.errors[0], "Test error")

    def test_add_warning(self):
        """Test warning collection"""
        self.context.add_warning("Test warning")
        self.assertEqual(len(self.context.warnings), 1)
        self.assertEqual(self.context.warnings[0], "Test warning")


class TestSimpleNodeExtractor(unittest.TestCase):
    """Tests for SimpleNodeExtractor class"""

    def test_extract_nodes_basic(self):
        """Test basic node extraction with field mapping"""
        field_mapping = {
            'id': 'id',
            'name': 'name',
            'category': 'category'
        }

        extractor = SimpleNodeExtractor(field_mapping)

        sources = [
            {'id': '1', 'name': 'test1', 'category': 'cat1', 'extra': 'ignore'},
            {'id': '2', 'name': 'test2', 'category': 'cat2'}
        ]

        nodes = extractor.extract_nodes(sources)

        self.assertEqual(len(nodes), 2)
        self.assertEqual(nodes[0]['id'], '1')
        self.assertEqual(nodes[0]['name'], 'test1')
        self.assertEqual(nodes[0]['category'], 'cat1')

        # Extra fields should not be in output
        self.assertNotIn('extra', nodes[0])

    def test_extract_nodes_missing_id(self):
        """Test handling of missing ID field"""
        field_mapping = {
            'id': 'id',
            'name': 'name'
        }

        extractor = SimpleNodeExtractor(field_mapping)

        sources = [
            {'name': 'test1'},  # Missing 'id'
        ]

        nodes = extractor.extract_nodes(sources)

        # Should skip entity without ID
        self.assertEqual(len(nodes), 0)

    def test_extract_nodes_none_values(self):
        """Test handling of None values"""
        field_mapping = {
            'id': 'id',
            'name': 'name',
            'description': 'description'
        }

        extractor = SimpleNodeExtractor(field_mapping)

        sources = [
            {'id': '1', 'name': 'test1', 'description': None}
        ]

        nodes = extractor.extract_nodes(sources)

        self.assertEqual(len(nodes), 1)
        # None should be converted to empty string
        self.assertEqual(nodes[0]['description'], '')

    def test_get_nested_field(self):
        """Test nested field access"""
        field_mapping = {
            'id': 'id',
            'version': 'metadata.version'
        }

        extractor = SimpleNodeExtractor(field_mapping)

        sources = [
            {'id': '1', 'metadata': {'version': '1.0.0'}}
        ]

        nodes = extractor.extract_nodes(sources)

        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]['version'], '1.0.0')

    def test_no_relationships_extracted(self):
        """Test that SimpleNodeExtractor doesn't extract relationships"""
        field_mapping = {'id': 'id'}
        extractor = SimpleNodeExtractor(field_mapping)

        rels = extractor.extract_relationships([])
        self.assertEqual(len(rels), 0)


class TestGenerateId(unittest.TestCase):
    """Tests for generate_id utility function"""

    def test_generate_id_consistency(self):
        """Test that same input generates same ID"""
        id1 = generate_id("test")
        id2 = generate_id("test")
        self.assertEqual(id1, id2)

    def test_generate_id_uniqueness(self):
        """Test that different inputs generate different IDs"""
        id1 = generate_id("test1")
        id2 = generate_id("test2")
        self.assertNotEqual(id1, id2)

    def test_generate_id_length(self):
        """Test that generated IDs are 16 characters"""
        id = generate_id("test")
        self.assertEqual(len(id), 16)


if __name__ == '__main__':
    unittest.main()
