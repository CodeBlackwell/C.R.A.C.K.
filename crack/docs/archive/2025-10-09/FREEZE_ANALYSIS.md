# Sessions Test Freeze - Root Cause Analysis

## Summary
Full sessions test suite (`pytest tests/sessions/`) causes system freeze. Individual test files pass successfully. The freeze occurs when running all 407 tests together.

## Root Cause: Service Plugin Registry Autouse Fixture

**Location**: `tests/conftest.py:19-66`

### The Problem

The `clear_event_bus_and_plugin_state()` autouse fixture runs before **EVERY single test** (407 times) and performs expensive operations:

```python
@pytest.fixture(autouse=True)
def clear_event_bus_and_plugin_state():
    # SAVE current plugin state (copies entire registry)
    saved_plugins = ServiceRegistry._plugins.copy()

    # Clear EventBus handlers
    EventBus.clear()

    # Reset ServiceRegistry initialization flag
    ServiceRegistry._initialized = False

    # Clear plugin resolution state
    if hasattr(ServiceRegistry, '_plugin_claims'):
        ServiceRegistry._plugin_claims.clear()
    if hasattr(ServiceRegistry, '_resolved_ports'):
        ServiceRegistry._resolved_ports.clear()

    # Re-initialize plugins (LOADS ALL 235+ SERVICE PLUGINS)
    ServiceRegistry.initialize_plugins()

    yield

    # RESTORE plugin registry after each test
    ServiceRegistry._plugins = saved_plugins
    ServiceRegistry._initialized = True

    # Cleanup after test
    EventBus.clear()
    if hasattr(ServiceRegistry, '_plugin_claims'):
        ServiceRegistry._plugin_claims.clear()
    if hasattr(ServiceRegistry, '_resolved_ports'):
        ServiceRegistry._resolved_ports.clear()
```

### Why It Freezes

1. **Plugin Re-initialization**: `ServiceRegistry.initialize_plugins()` loads and registers **235+ service plugins** from `track/services/`
2. **407 Tests × 235 Plugins = 95,645 plugin operations** in setup/teardown
3. **Memory Accumulation**: Each copy operation accumulates memory without proper garbage collection between tests
4. **Import System Strain**: Python's import system is stressed by repeatedly loading service plugin modules

### Evidence

**Working scenarios:**
- Individual test files: ✅ Pass (small number of tests, manageable plugin reloads)
- Integration tests: ✅ Pass (11 tests, 2,585 plugin operations)
- HTTP/DNS/ICMP tests: ✅ Pass (<50 tests each)

**Freezing scenario:**
- Full suite: ❌ Freeze (407 tests, 95,645+ plugin operations)

## Why This Fixture Exists

The fixture was added to solve Track test isolation issues:
- EventBus handlers accumulating across tests
- Service plugin port conflict resolution carrying over
- Plugin state pollution between tests

## Solutions

### Option 1: Scope Fixture to Module Level (RECOMMENDED)
Change autouse fixture scope from "function" to "module":

```python
@pytest.fixture(scope="module", autouse=True)
def clear_event_bus_and_plugin_state():
    # Runs once per test MODULE instead of per test function
    # 18 modules × 235 plugins = 4,230 operations (95% reduction)
```

**Impact**: 95% reduction in plugin operations (4,230 vs 95,645)
**Risk**: Low - Tests within same module share plugin state (acceptable for sessions tests)

### Option 2: Conditional Activation
Only activate for Track tests that need it:

```python
@pytest.fixture(autouse=False)  # Remove autouse
def clear_event_bus_and_plugin_state():
    # Same implementation
```

Then explicitly request it in Track tests:
```python
def test_something(clear_event_bus_and_plugin_state):
    # Only runs for tests that explicitly request it
```

**Impact**: Zero overhead for sessions tests (they don't need plugin registry)
**Risk**: Low - Must remember to add fixture to Track tests that need isolation

### Option 3: Marker-Based Activation
Use pytest markers to conditionally run fixture:

```python
@pytest.fixture(autouse=True)
def clear_event_bus_and_plugin_state(request):
    # Skip if test doesn't have 'track' marker
    if 'track' not in [marker.name for marker in request.node.iter_markers()]:
        yield
        return

    # Rest of implementation...
```

Mark Track tests:
```python
@pytest.mark.track
def test_service_plugin():
    pass
```

**Impact**: Zero overhead for unmarked tests
**Risk**: Low - Must remember to mark new Track tests

## Test Results Summary

### ✅ Currently Passing (Verified)
- **Track tests**: 3,168/3,168 passing (100%)
- **HTTP listener**: 1/1 passing
- **ICMP listener**: 4/4 passing
- **Integration tests**: 11/12 passing (1 skipped - async)
- **HTTP upgrader**: 1/1 passing

### ⚠️ Not Tested (Would Freeze System)
- Full sessions suite: 407 tests (untested due to freeze risk)
- Sessions unit tests: ~350 tests
- Individual modules: Should pass but not verified

## Recommended Action

**Implement Option 1** - Change fixture scope to "module":

1. Minimal code change (one line)
2. Maintains test isolation within reason
3. Solves freeze issue immediately
4. No changes needed to existing tests

**Command to test after fix:**
```bash
# Should complete in <30 seconds instead of freezing
timeout 60 python -m pytest tests/sessions/ -v --tb=short
```

## Files to Modify

1. `/home/kali/OSCP/crack/tests/conftest.py` - Line 19: Add `scope="module"`

**Current:**
```python
@pytest.fixture(autouse=True)
def clear_event_bus_and_plugin_state():
```

**Fixed:**
```python
@pytest.fixture(scope="module", autouse=True)
def clear_event_bus_and_plugin_state():
```

## Additional Notes

- The sessions tests don't actually need the service plugin registry
- This fixture was designed for Track tests (`track/` module)
- Separating Track and Sessions fixtures would be ideal long-term
- Consider splitting `conftest.py` into:
  - `tests/track/conftest.py` (plugin registry fixture)
  - `tests/sessions/conftest.py` (session-specific fixtures)
  - `tests/conftest.py` (shared fixtures only)
