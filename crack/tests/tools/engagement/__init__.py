"""
Tests for Engagement Tracking Module.

Business Value Focus:
- CRUD operations correctly persist engagement data to Neo4j
- Active engagement state is properly managed across sessions
- Integration helpers work gracefully when Neo4j is unavailable
- Data model serialization preserves all fields (no data loss)

Test Files:
- test_models.py: Dataclass validation, enum handling, to_dict/from_dict
- test_adapter.py: EngagementAdapter CRUD operations with mocked Neo4j
- test_integration.py: EngagementIntegration helper for tool integration
"""
