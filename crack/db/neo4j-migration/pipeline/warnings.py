"""
Warning collection system for extraction pipeline.

Provides centralized warning tracking across extractors with categorization
and reporting capabilities.
"""

from typing import List, Dict, Set
from dataclasses import dataclass, field
from enum import Enum


class WarningCategory(Enum):
    """Categories of extraction warnings"""
    MISSING_DATA = "missing_data"          # Expected field missing
    EMPTY_VALUE = "empty_value"            # Field present but empty
    DEPRECATED = "deprecated"              # Using deprecated field/pattern
    UNEXPECTED = "unexpected"              # Unexpected data format
    SKIPPED = "skipped"                    # Entity skipped due to error
    DATA_QUALITY = "data_quality"          # Data quality issues


@dataclass
class ExtractionWarning:
    """
    Represents a warning during data extraction.
    """
    category: WarningCategory
    entity_type: str          # e.g., 'Command', 'Variable'
    message: str              # Description of warning
    entity_id: str = None     # ID of affected entity
    field: str = None         # Affected field name
    context: Dict = field(default_factory=dict)  # Additional context


@dataclass
class WarningCollector:
    """
    Collects and aggregates extraction warnings.
    """
    warnings: List[ExtractionWarning] = field(default_factory=list)

    def add_warning(
        self,
        category: WarningCategory,
        entity_type: str,
        message: str,
        entity_id: str = None,
        field: str = None,
        **context
    ):
        """
        Add a warning to the collection.

        Args:
            category: Warning category
            entity_type: Type of entity (e.g., 'Command')
            message: Warning message
            entity_id: ID of affected entity (optional)
            field: Field name (optional)
            **context: Additional context as keyword arguments
        """
        warning = ExtractionWarning(
            category=category,
            entity_type=entity_type,
            message=message,
            entity_id=entity_id,
            field=field,
            context=context
        )
        self.warnings.append(warning)

    def get_by_category(self, category: WarningCategory) -> List[ExtractionWarning]:
        """Get all warnings of a specific category"""
        return [w for w in self.warnings if w.category == category]

    def get_by_entity_type(self, entity_type: str) -> List[ExtractionWarning]:
        """Get all warnings for a specific entity type"""
        return [w for w in self.warnings if w.entity_type == entity_type]

    def count_by_category(self) -> Dict[WarningCategory, int]:
        """Get warning counts by category"""
        counts = {}
        for category in WarningCategory:
            counts[category] = len(self.get_by_category(category))
        return counts

    def has_warnings(self) -> bool:
        """Check if any warnings exist"""
        return len(self.warnings) > 0

    def clear(self):
        """Clear all warnings"""
        self.warnings = []

    def print_report(self, max_per_category: int = 10):
        """
        Print formatted warning report.

        Args:
            max_per_category: Maximum warnings to show per category
        """
        if not self.has_warnings():
            return

        print()
        print("=" * 60)
        print("Extraction Warnings")
        print("=" * 60)

        counts = self.count_by_category()
        total = sum(counts.values())
        print(f"Total warnings: {total}")
        print()

        # Group by category
        for category in WarningCategory:
            category_warnings = self.get_by_category(category)
            if not category_warnings:
                continue

            print(f"{category.value.upper().replace('_', ' ')}: {len(category_warnings)}")

            # Show first N warnings
            for warning in category_warnings[:max_per_category]:
                location = f"{warning.entity_type}"
                if warning.field:
                    location += f".{warning.field}"
                if warning.entity_id:
                    location += f" [{warning.entity_id}]"

                print(f"  ! {location}: {warning.message}")

            # Indicate if there are more
            if len(category_warnings) > max_per_category:
                remaining = len(category_warnings) - max_per_category
                print(f"  ... and {remaining} more")

            print()

        print("=" * 60)
