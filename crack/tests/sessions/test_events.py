"""
Unit tests for session management event system.

Tests cover:
- SessionEvent: Event type enumeration
- EventBus: Subscription, publishing, thread safety, singleton pattern
"""

import unittest
import threading
import time
from crack.sessions.events import SessionEvent, EventBus


class TestSessionEvent(unittest.TestCase):
    """Test SessionEvent enumeration."""

    def test_event_types(self):
        """Test all defined event types exist."""
        self.assertTrue(hasattr(SessionEvent, 'SESSION_STARTED'))
        self.assertTrue(hasattr(SessionEvent, 'SESSION_DIED'))
        self.assertTrue(hasattr(SessionEvent, 'SESSION_UPGRADED'))
        self.assertTrue(hasattr(SessionEvent, 'SESSION_STABILIZED'))
        self.assertTrue(hasattr(SessionEvent, 'LISTENER_STARTED'))
        self.assertTrue(hasattr(SessionEvent, 'LISTENER_STOPPED'))
        self.assertTrue(hasattr(SessionEvent, 'LISTENER_CRASHED'))

    def test_event_uniqueness(self):
        """Test event types are unique."""
        events = [
            SessionEvent.SESSION_STARTED,
            SessionEvent.SESSION_DIED,
            SessionEvent.SESSION_UPGRADED,
            SessionEvent.SESSION_STABILIZED,
            SessionEvent.LISTENER_STARTED,
            SessionEvent.LISTENER_STOPPED,
            SessionEvent.LISTENER_CRASHED
        ]

        # Check all values are unique
        self.assertEqual(len(events), len(set(events)))


class TestEventBus(unittest.TestCase):
    """Test EventBus functionality."""

    def setUp(self):
        """Reset event bus before each test."""
        EventBus.reset()

    def tearDown(self):
        """Clean up after each test."""
        EventBus.reset()

    def test_singleton_pattern(self):
        """Test EventBus uses singleton pattern."""
        bus1 = EventBus()
        bus2 = EventBus()

        self.assertIs(bus1, bus2)

    def test_subscribe_and_publish(self):
        """Test basic subscription and event publishing."""
        received_events = []

        def handler(data):
            received_events.append(data)

        # Subscribe handler
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler)

        # Publish event
        EventBus.publish(SessionEvent.SESSION_STARTED, {
            'session_id': 'test-123',
            'target': '192.168.45.150'
        })

        # Verify handler was called
        self.assertEqual(len(received_events), 1)
        self.assertEqual(received_events[0]['session_id'], 'test-123')
        self.assertEqual(received_events[0]['target'], '192.168.45.150')

    def test_multiple_handlers(self):
        """Test multiple handlers for same event."""
        handler1_calls = []
        handler2_calls = []

        def handler1(data):
            handler1_calls.append(data)

        def handler2(data):
            handler2_calls.append(data)

        # Subscribe both handlers
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler1)
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler2)

        # Publish event
        EventBus.publish(SessionEvent.SESSION_STARTED, {'session_id': 'test'})

        # Both handlers should be called
        self.assertEqual(len(handler1_calls), 1)
        self.assertEqual(len(handler2_calls), 1)

    def test_unsubscribe(self):
        """Test unsubscribing handlers."""
        received_events = []

        def handler(data):
            received_events.append(data)

        # Subscribe and publish
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler)
        EventBus.publish(SessionEvent.SESSION_STARTED, {'test': 1})
        self.assertEqual(len(received_events), 1)

        # Unsubscribe and publish again
        EventBus.unsubscribe(SessionEvent.SESSION_STARTED, handler)
        EventBus.publish(SessionEvent.SESSION_STARTED, {'test': 2})

        # Handler should not be called after unsubscribe
        self.assertEqual(len(received_events), 1)

    def test_publish_without_subscribers(self):
        """Test publishing event with no subscribers (should not error)."""
        # Should not raise exception
        EventBus.publish(SessionEvent.SESSION_STARTED, {'test': 'data'})

    def test_publish_with_empty_data(self):
        """Test publishing event with no data."""
        received_events = []

        def handler(data):
            received_events.append(data)

        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler)
        EventBus.publish(SessionEvent.SESSION_STARTED)

        # Handler should receive empty dict
        self.assertEqual(len(received_events), 1)
        self.assertEqual(received_events[0], {})

    def test_handler_exception_isolation(self):
        """Test that exception in one handler doesn't affect others."""
        handler1_calls = []
        handler2_calls = []

        def handler1(data):
            handler1_calls.append(data)
            raise ValueError("Handler 1 error")

        def handler2(data):
            handler2_calls.append(data)

        # Subscribe both handlers
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler1)
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler2)

        # Publish event (should not raise exception)
        EventBus.publish(SessionEvent.SESSION_STARTED, {'test': 'data'})

        # Both handlers should be called despite handler1 error
        self.assertEqual(len(handler1_calls), 1)
        self.assertEqual(len(handler2_calls), 1)

    def test_clear_specific_event(self):
        """Test clearing handlers for specific event."""
        handler1_calls = []
        handler2_calls = []

        def handler1(data):
            handler1_calls.append(data)

        def handler2(data):
            handler2_calls.append(data)

        # Subscribe to different events
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler1)
        EventBus.subscribe(SessionEvent.SESSION_DIED, handler2)

        # Clear only SESSION_STARTED
        EventBus.clear(SessionEvent.SESSION_STARTED)

        # Publish both events
        EventBus.publish(SessionEvent.SESSION_STARTED, {'test': 1})
        EventBus.publish(SessionEvent.SESSION_DIED, {'test': 2})

        # Only handler2 should be called
        self.assertEqual(len(handler1_calls), 0)
        self.assertEqual(len(handler2_calls), 1)

    def test_clear_all_events(self):
        """Test clearing all event handlers."""
        handler1_calls = []
        handler2_calls = []

        def handler1(data):
            handler1_calls.append(data)

        def handler2(data):
            handler2_calls.append(data)

        # Subscribe to different events
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler1)
        EventBus.subscribe(SessionEvent.SESSION_DIED, handler2)

        # Clear all handlers
        EventBus.clear()

        # Publish events
        EventBus.publish(SessionEvent.SESSION_STARTED, {'test': 1})
        EventBus.publish(SessionEvent.SESSION_DIED, {'test': 2})

        # No handlers should be called
        self.assertEqual(len(handler1_calls), 0)
        self.assertEqual(len(handler2_calls), 0)

    def test_get_handlers(self):
        """Test getting list of handlers."""
        def handler1(data):
            pass

        def handler2(data):
            pass

        # Subscribe handlers
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler1)
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler2)

        # Get handlers
        handlers = EventBus.get_handlers(SessionEvent.SESSION_STARTED)

        self.assertEqual(len(handlers), 2)
        self.assertIn(handler1, handlers)
        self.assertIn(handler2, handlers)

        # Get handlers for event with no subscribers
        empty_handlers = EventBus.get_handlers(SessionEvent.SESSION_DIED)
        self.assertEqual(len(empty_handlers), 0)

    def test_thread_safety_subscribe(self):
        """Test thread-safe subscription."""
        handlers_added = []

        def subscribe_handler(handler_num):
            def handler(data):
                pass
            handler.__name__ = f'handler_{handler_num}'
            EventBus.subscribe(SessionEvent.SESSION_STARTED, handler)
            handlers_added.append(handler_num)

        # Create multiple threads subscribing simultaneously
        threads = []
        for i in range(10):
            t = threading.Thread(target=subscribe_handler, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads to complete
        for t in threads:
            t.join()

        # All handlers should be registered
        self.assertEqual(len(handlers_added), 10)
        handlers = EventBus.get_handlers(SessionEvent.SESSION_STARTED)
        self.assertEqual(len(handlers), 10)

    def test_thread_safety_publish(self):
        """Test thread-safe event publishing."""
        received_events = []
        lock = threading.Lock()

        def handler(data):
            with lock:
                received_events.append(data)

        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler)

        # Publish from multiple threads
        def publish_event(event_num):
            EventBus.publish(SessionEvent.SESSION_STARTED, {'event': event_num})

        threads = []
        for i in range(10):
            t = threading.Thread(target=publish_event, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # All events should be received
        self.assertEqual(len(received_events), 10)

    def test_debug_mode(self):
        """Test debug mode enable/disable."""
        # Enable debug
        EventBus.set_debug(True)

        # Create handler
        received_events = []
        def handler(data):
            received_events.append(data)

        # Subscribe and publish (should log debug messages)
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler)
        EventBus.publish(SessionEvent.SESSION_STARTED, {'test': 'data'})

        # Handler should still work
        self.assertEqual(len(received_events), 1)

        # Disable debug
        EventBus.set_debug(False)

    def test_reset(self):
        """Test reset clears all state."""
        def handler(data):
            pass

        # Subscribe handlers
        EventBus.subscribe(SessionEvent.SESSION_STARTED, handler)
        EventBus.subscribe(SessionEvent.SESSION_DIED, handler)
        EventBus.set_debug(True)

        # Reset
        EventBus.reset()

        # All handlers should be cleared
        self.assertEqual(len(EventBus.get_handlers(SessionEvent.SESSION_STARTED)), 0)
        self.assertEqual(len(EventBus.get_handlers(SessionEvent.SESSION_DIED)), 0)


class TestEventBusIntegration(unittest.TestCase):
    """Integration tests for realistic event scenarios."""

    def setUp(self):
        """Reset event bus before each test."""
        EventBus.reset()

    def tearDown(self):
        """Clean up after each test."""
        EventBus.reset()

    def test_session_lifecycle_events(self):
        """Test complete session lifecycle event flow."""
        events_log = []

        def log_event(event_type):
            def handler(data):
                events_log.append((event_type, data))
            return handler

        # Subscribe to all session events
        EventBus.subscribe(SessionEvent.SESSION_STARTED, log_event('started'))
        EventBus.subscribe(SessionEvent.SESSION_UPGRADED, log_event('upgraded'))
        EventBus.subscribe(SessionEvent.SESSION_STABILIZED, log_event('stabilized'))
        EventBus.subscribe(SessionEvent.SESSION_DIED, log_event('died'))

        # Simulate session lifecycle
        session_id = 'test-session-123'

        # 1. Session starts
        EventBus.publish(SessionEvent.SESSION_STARTED, {
            'session_id': session_id,
            'target': '192.168.45.150',
            'port': 4444
        })

        # 2. Session upgraded
        EventBus.publish(SessionEvent.SESSION_UPGRADED, {
            'session_id': session_id,
            'method': 'python-pty'
        })

        # 3. Session stabilized
        EventBus.publish(SessionEvent.SESSION_STABILIZED, {
            'session_id': session_id
        })

        # 4. Session dies
        EventBus.publish(SessionEvent.SESSION_DIED, {
            'session_id': session_id,
            'reason': 'connection_lost'
        })

        # Verify all events were logged in order
        self.assertEqual(len(events_log), 4)
        self.assertEqual(events_log[0][0], 'started')
        self.assertEqual(events_log[1][0], 'upgraded')
        self.assertEqual(events_log[2][0], 'stabilized')
        self.assertEqual(events_log[3][0], 'died')

    def test_listener_lifecycle_events(self):
        """Test listener lifecycle event flow."""
        events_log = []

        def log_event(event_type):
            def handler(data):
                events_log.append((event_type, data))
            return handler

        # Subscribe to listener events
        EventBus.subscribe(SessionEvent.LISTENER_STARTED, log_event('started'))
        EventBus.subscribe(SessionEvent.LISTENER_STOPPED, log_event('stopped'))
        EventBus.subscribe(SessionEvent.LISTENER_CRASHED, log_event('crashed'))

        listener_id = 'listener-123'

        # 1. Listener starts
        EventBus.publish(SessionEvent.LISTENER_STARTED, {
            'listener_id': listener_id,
            'port': 4444
        })

        # 2. Listener stops
        EventBus.publish(SessionEvent.LISTENER_STOPPED, {
            'listener_id': listener_id
        })

        # 3. Listener crashes
        EventBus.publish(SessionEvent.LISTENER_CRASHED, {
            'listener_id': listener_id,
            'error': 'port_in_use'
        })

        # Verify all events were logged
        self.assertEqual(len(events_log), 3)
        self.assertEqual(events_log[0][0], 'started')
        self.assertEqual(events_log[1][0], 'stopped')
        self.assertEqual(events_log[2][0], 'crashed')


if __name__ == '__main__':
    unittest.main()
