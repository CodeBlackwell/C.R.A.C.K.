"""
Engagement Tracking Module

Provides unified client/engagement/target tracking with Neo4j persistence.

Usage:
    from crack.tools.engagement import EngagementAdapter, get_active_engagement

    # Get adapter
    adapter = EngagementAdapter()

    # Create client and engagement
    client_id = adapter.create_client("ACME Corp")
    eng_id = adapter.create_engagement("Q4 Pentest", client_id)

    # Set as active
    adapter.set_active_engagement(eng_id)

    # Add targets and findings
    target_id = adapter.add_target(eng_id, "192.168.1.100")
    adapter.add_service(target_id, 80, service_name="http")
    adapter.add_finding(eng_id, "SQL Injection", severity="critical")
"""

from .models import (
    Client,
    Engagement,
    Target,
    Finding,
    Service,
    EngagementStatus,
    FindingSeverity,
)
from .adapter import EngagementAdapter
from .storage import (
    get_active_engagement_id,
    set_active_engagement_id,
    clear_active_engagement,
    EngagementStorage,
)
from .integration import EngagementIntegration

__all__ = [
    # Models
    'Client',
    'Engagement',
    'Target',
    'Finding',
    'Service',
    'EngagementStatus',
    'FindingSeverity',
    # Adapter
    'EngagementAdapter',
    # Storage
    'get_active_engagement_id',
    'set_active_engagement_id',
    'clear_active_engagement',
    'EngagementStorage',
    # Integration helper
    'EngagementIntegration',
]
