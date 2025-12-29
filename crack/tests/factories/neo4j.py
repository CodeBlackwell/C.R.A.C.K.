"""
Mock Neo4j Driver for Testing

Provides mock implementations of neo4j.Driver, Session, and Transaction
for testing Neo4j interactions without a live database.

Business Value Focus:
- Tests can verify Neo4j queries without running database
- Configurable responses for success/failure scenarios
- Query tracking for assertion on executed Cypher
- Connection failure simulation for resilience testing

Usage Examples:
    # Basic mock with records
    driver = MockNeo4jDriver(records=[{"name": "test"}])
    session = driver.session()
    result = session.run("MATCH (n) RETURN n")

    # Simulate connection failure
    driver = MockNeo4jDriver(should_fail=True)

    # Access executed queries for assertions
    assert "MATCH" in driver.get_session().queries_run[0][0]

    # Transaction support
    with driver.session() as session:
        tx = session.begin_transaction()
        tx.run("CREATE (n:Test)")
        tx.commit()
"""

from typing import List, Dict, Any, Optional, Iterator, Callable
from dataclasses import dataclass, field
from contextlib import contextmanager
from threading import Lock


@dataclass
class MockRecord:
    """
    Mock Neo4j record.

    Mimics neo4j.Record interface for test compatibility.
    """

    _data: Dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        return self._data.get(key)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def keys(self) -> List[str]:
        return list(self._data.keys())

    def values(self) -> List[Any]:
        return list(self._data.values())

    def items(self) -> List[tuple]:
        return list(self._data.items())

    def data(self) -> Dict[str, Any]:
        """Return record as dict (matches neo4j.Record.data())."""
        return self._data.copy()


class MockNeo4jResult:
    """
    Mock Neo4j query result.

    Provides iterator interface matching neo4j.Result.
    """

    def __init__(self, records: List[Dict[str, Any]] = None):
        """
        Initialize with list of record dicts.

        Args:
            records: List of dicts to return as records.
        """
        self._records = [MockRecord(_data=r) for r in (records or [])]
        self._index = 0
        self._consumed = False

    def __iter__(self) -> Iterator[MockRecord]:
        return iter(self._records)

    def __next__(self) -> MockRecord:
        if self._index >= len(self._records):
            raise StopIteration
        record = self._records[self._index]
        self._index += 1
        return record

    def single(self) -> Optional[MockRecord]:
        """Return single record or None (matches neo4j.Result.single())."""
        if len(self._records) == 0:
            return None
        if len(self._records) > 1:
            raise ValueError("Result contains more than one record")
        return self._records[0]

    def peek(self) -> Optional[MockRecord]:
        """Peek at next record without consuming."""
        if self._index >= len(self._records):
            return None
        return self._records[self._index]

    def data(self) -> List[Dict[str, Any]]:
        """Return all records as list of dicts."""
        return [r.data() for r in self._records]

    def consume(self) -> 'MockResultSummary':
        """Consume result and return summary."""
        self._consumed = True
        return MockResultSummary(record_count=len(self._records))

    def fetch(self, n: int) -> List[MockRecord]:
        """Fetch up to n records."""
        remaining = self._records[self._index:self._index + n]
        self._index += len(remaining)
        return remaining


@dataclass
class MockResultSummary:
    """Mock result summary."""

    record_count: int = 0
    query_type: str = "r"  # r=read, w=write
    counters: Dict[str, int] = field(default_factory=dict)


class MockNeo4jTransaction:
    """
    Mock Neo4j transaction.

    Tracks all queries executed within transaction for assertions.
    Supports commit/rollback state tracking.
    """

    def __init__(
        self,
        records: List[Dict[str, Any]] = None,
        should_fail: bool = False,
        failure_exception: Exception = None
    ):
        """
        Initialize transaction mock.

        Args:
            records: Records to return from run().
            should_fail: If True, raise exception on run().
            failure_exception: Exception to raise (default: RuntimeError).
        """
        self.records = records or []
        self.should_fail = should_fail
        self.failure_exception = failure_exception or RuntimeError("Mock transaction failure")

        self.queries_run: List[tuple] = []
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def run(self, query: str, **params) -> MockNeo4jResult:
        """
        Execute query within transaction.

        Args:
            query: Cypher query string.
            **params: Query parameters.

        Returns:
            MockNeo4jResult with configured records.

        Raises:
            Configured exception if should_fail=True.
        """
        if self.should_fail:
            raise self.failure_exception

        self.queries_run.append((query, params))
        return MockNeo4jResult(self.records)

    def commit(self) -> None:
        """Commit transaction."""
        if self.rolled_back:
            raise RuntimeError("Cannot commit rolled-back transaction")
        if self.closed:
            raise RuntimeError("Transaction already closed")
        self.committed = True
        self.closed = True

    def rollback(self) -> None:
        """Rollback transaction."""
        if self.committed:
            raise RuntimeError("Cannot rollback committed transaction")
        if self.closed:
            raise RuntimeError("Transaction already closed")
        self.rolled_back = True
        self.closed = True

    def close(self) -> None:
        """Close transaction (auto-rollback if not committed)."""
        if not self.closed:
            if not self.committed:
                self.rolled_back = True
            self.closed = True

    def __enter__(self) -> 'MockNeo4jTransaction':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            self.rollback()
        elif not self.committed and not self.rolled_back:
            self.rollback()
        self.close()


class MockNeo4jSession:
    """
    Mock Neo4j session.

    Provides session interface for executing queries and managing transactions.
    Tracks all queries for test assertions.
    """

    def __init__(
        self,
        records: List[Dict[str, Any]] = None,
        should_fail: bool = False,
        failure_exception: Exception = None
    ):
        """
        Initialize session mock.

        Args:
            records: Records to return from run().
            should_fail: If True, raise exception on run().
            failure_exception: Exception to raise (default: ConnectionError).
        """
        self.records = records or []
        self.should_fail = should_fail
        self.failure_exception = failure_exception or ConnectionError("Mock connection failure")

        self.queries_run: List[tuple] = []
        self.transactions: List[MockNeo4jTransaction] = []
        self.closed = False
        self._current_tx: Optional[MockNeo4jTransaction] = None

    def run(self, query: str, **params) -> MockNeo4jResult:
        """
        Execute query in auto-commit transaction.

        Args:
            query: Cypher query string.
            **params: Query parameters.

        Returns:
            MockNeo4jResult with configured records.

        Raises:
            Configured exception if should_fail=True.
        """
        if self.closed:
            raise RuntimeError("Session is closed")

        if self.should_fail:
            raise self.failure_exception

        self.queries_run.append((query, params))
        return MockNeo4jResult(self.records)

    def begin_transaction(self) -> MockNeo4jTransaction:
        """
        Begin explicit transaction.

        Returns:
            MockNeo4jTransaction for explicit transaction control.
        """
        if self.closed:
            raise RuntimeError("Session is closed")

        if self._current_tx and not self._current_tx.closed:
            raise RuntimeError("Transaction already in progress")

        tx = MockNeo4jTransaction(
            records=self.records,
            should_fail=self.should_fail,
            failure_exception=self.failure_exception
        )
        self.transactions.append(tx)
        self._current_tx = tx
        return tx

    def read_transaction(self, work: Callable, *args, **kwargs) -> Any:
        """
        Execute work in read transaction.

        Args:
            work: Function to execute with transaction.
            *args: Arguments for work function.
            **kwargs: Keyword arguments for work function.

        Returns:
            Result of work function.
        """
        tx = self.begin_transaction()
        try:
            result = work(tx, *args, **kwargs)
            tx.commit()
            return result
        except Exception:
            tx.rollback()
            raise

    def write_transaction(self, work: Callable, *args, **kwargs) -> Any:
        """
        Execute work in write transaction.

        Args:
            work: Function to execute with transaction.
            *args: Arguments for work function.
            **kwargs: Keyword arguments for work function.

        Returns:
            Result of work function.
        """
        return self.read_transaction(work, *args, **kwargs)

    def close(self) -> None:
        """Close session."""
        if self._current_tx and not self._current_tx.closed:
            self._current_tx.close()
        self.closed = True

    def __enter__(self) -> 'MockNeo4jSession':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class MockNeo4jDriver:
    """
    Mock Neo4j driver for testing.

    Provides driver interface matching neo4j.Driver.
    Configurable for success/failure scenarios.

    Thread-safe for parallel test execution.
    """

    def __init__(
        self,
        records: List[Dict[str, Any]] = None,
        should_fail: bool = False,
        failure_exception: Exception = None
    ):
        """
        Initialize driver mock.

        Args:
            records: Records to return from queries.
            should_fail: If True, sessions will raise exceptions.
            failure_exception: Custom exception for failures.
        """
        self.records = records or []
        self.should_fail = should_fail
        self.failure_exception = failure_exception

        self._sessions: List[MockNeo4jSession] = []
        self._lock = Lock()
        self.closed = False

    def session(self, database: str = None) -> MockNeo4jSession:
        """
        Create new session.

        Args:
            database: Database name (ignored in mock).

        Returns:
            MockNeo4jSession for query execution.
        """
        if self.closed:
            raise RuntimeError("Driver is closed")

        session = MockNeo4jSession(
            records=self.records,
            should_fail=self.should_fail,
            failure_exception=self.failure_exception
        )

        with self._lock:
            self._sessions.append(session)

        return session

    def verify_connectivity(self) -> None:
        """
        Verify driver connectivity.

        Raises exception if should_fail=True.
        """
        if self.should_fail:
            raise self.failure_exception or ConnectionError("Mock connectivity check failed")

    def close(self) -> None:
        """Close driver and all sessions."""
        with self._lock:
            for session in self._sessions:
                if not session.closed:
                    session.close()
            self.closed = True

    def get_session(self, index: int = 0) -> Optional[MockNeo4jSession]:
        """
        Get session by index for test assertions.

        Args:
            index: Session index (default: 0 for first).

        Returns:
            MockNeo4jSession or None if index out of range.
        """
        with self._lock:
            if 0 <= index < len(self._sessions):
                return self._sessions[index]
            return None

    def get_all_queries(self) -> List[tuple]:
        """
        Get all queries from all sessions.

        Returns:
            List of (query, params) tuples.
        """
        all_queries = []
        with self._lock:
            for session in self._sessions:
                all_queries.extend(session.queries_run)
        return all_queries

    def __enter__(self) -> 'MockNeo4jDriver':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# =============================================================================
# Helper Functions for Common Mock Scenarios
# =============================================================================

def create_mock_driver_success(records: List[Dict[str, Any]] = None) -> MockNeo4jDriver:
    """
    Create mock driver that returns successful results.

    Args:
        records: Records to return from queries.

    Returns:
        Configured MockNeo4jDriver.
    """
    return MockNeo4jDriver(records=records or [])


def create_mock_driver_failure(
    exception_type: type = ConnectionError,
    message: str = "Connection refused"
) -> MockNeo4jDriver:
    """
    Create mock driver that simulates connection failure.

    Args:
        exception_type: Type of exception to raise.
        message: Exception message.

    Returns:
        MockNeo4jDriver configured to fail.
    """
    return MockNeo4jDriver(
        should_fail=True,
        failure_exception=exception_type(message)
    )


def create_mock_driver_with_node(
    node_labels: List[str],
    properties: Dict[str, Any]
) -> MockNeo4jDriver:
    """
    Create mock driver returning a single node.

    Args:
        node_labels: Labels for the node.
        properties: Node properties.

    Returns:
        MockNeo4jDriver with node record.

    Example:
        driver = create_mock_driver_with_node(
            ["User"], {"name": "admin", "domain": "CORP"}
        )
    """
    node_record = {
        "n": {
            "labels": node_labels,
            "properties": properties
        }
    }
    return MockNeo4jDriver(records=[node_record])
