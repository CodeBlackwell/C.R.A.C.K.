# Pattern Learning System Integration (Stage 5)

## Overview

Stage 5 adds **adaptive intelligence** through pattern learning. The system tracks task outcomes, analyzes successful patterns, and automatically tunes scoring weights to improve suggestions over time.

## Components

### 1. SuccessTracker (`track/intelligence/success_tracker.py`)

**Purpose:** Tracks task execution outcomes and attack chain completions.

**Key Features:**
- Records task success/failure with timestamps
- Tracks execution times for estimation
- Records chain completion rates
- Calculates success rates by pattern (task, chain, category)
- Persists to `profile.metadata['success_tracker']`

**API:**
```python
from crack.track.intelligence import SuccessTracker

tracker = SuccessTracker(profile)

# Record task outcome
tracker.record_task_outcome(
    task_id='nmap-scan-80',
    success=True,
    time_taken=15.3,
    metadata={'category': 'enumeration'}
)

# Record chain completion
tracker.record_chain_completion(
    chain_id='sqli-to-shell',
    steps_completed=3,
    total_steps=5,
    total_time=120.0
)

# Query success rates
success_rate = tracker.get_success_rate('nmap-scan-80', 'task')  # 0.0-1.0
avg_time = tracker.get_average_time('nmap-scan-80')  # seconds

# Get statistics
stats = tracker.get_pattern_statistics('nmap-scan-80', 'task')
# {'pattern': '...', 'success_rate': 0.85, 'average_time': 15.3, 'sample_count': 10}
```

### 2. PatternAnalyzer (`track/intelligence/pattern_analyzer.py`)

**Purpose:** Analyzes success patterns and optimizes scoring weights.

**Key Features:**
- Analyzes user task selection preferences
- Detects high-success patterns (70%+ task success, 60%+ chain completion)
- Auto-tunes scoring weights based on historical data
- Provides pattern insights and recommendations

**API:**
```python
from crack.track.intelligence import PatternAnalyzer

analyzer = PatternAnalyzer(success_tracker, config)

# Analyze user preferences
preferences = analyzer.analyze_user_preferences()
# {'enumeration': 0.85, 'exploitation': 0.72, ...}

# Detect successful patterns
patterns = analyzer.detect_successful_patterns(min_samples=3)
# [{'pattern_id': 'nmap-scan', 'success_rate': 0.9, 'sample_count': 15}, ...]

# Auto-tune weights
updated_weights = analyzer.update_scoring_weights(learning_rate=0.1)
# {'quick_win': 2.2, 'chain_progress': 1.65, ...}

# Get comprehensive insights
insights = analyzer.get_pattern_insights()
# {'user_preferences': {...}, 'successful_patterns': [...],
#  'current_weights': {...}, 'recommendations': [...]}
```

### 3. Telemetry (`track/intelligence/telemetry.py`)

**Purpose:** Anonymous usage statistics for system effectiveness measurement.

**Privacy:**
- Opt-in by default (enabled=False)
- Local storage only (~/.crack/telemetry.json)
- No IP addresses, targets, or credentials
- Anonymous counters only

**API:**
```python
from crack.track.intelligence import Telemetry

telemetry = Telemetry(enabled=True)  # Opt-in

# Record events
telemetry.record_intelligence_suggestion(5)  # 5 suggestions generated
telemetry.record_suggestion_accepted('chain-sqli-step-1')
telemetry.record_chain_attempt('sqli-to-shell')
telemetry.record_chain_completion('sqli-to-shell', 0.6)
telemetry.record_pattern_detection()
telemetry.record_weight_update()

# Get metrics
metrics = telemetry.get_metrics()
# {
#   'intelligence_suggestions': 100,
#   'suggestions_accepted': 45,
#   'acceptance_rate': 0.45,
#   'chain_attempts': 10,
#   'chain_completions': 6,
#   'completion_rate': 0.6,
#   ...
# }

# Clear metrics (privacy)
telemetry.clear_metrics()
```

## Integration Strategy

### Passive Integration (Current)

**Stage 5 components are available but not yet wired into TUI/Orchestrator.**

Reason: Pattern learning requires sufficient historical data (10+ task executions) to be effective. Integrating prematurely would show "insufficient data" messages to all users.

### How to Enable Pattern Learning

**Option 1: Manual Initialization (Developer/Power User)**
```python
# In Python console or custom script
from crack.track.core.state import TargetProfile
from crack.track.intelligence import SuccessTracker, PatternAnalyzer, Telemetry

profile = TargetProfile.load('192.168.45.100')

# Initialize components
tracker = SuccessTracker(profile)
analyzer = PatternAnalyzer(tracker, config)
telemetry = Telemetry(enabled=True)  # Opt-in

# Record task outcome after execution
tracker.record_task_outcome('task-1', success=True, time_taken=10.5)

# Analyze patterns after sufficient data collected
if len(tracker.task_outcomes) >= 10:
    patterns = analyzer.detect_successful_patterns()
    print(f"Detected {len(patterns)} successful patterns")

    # Auto-tune weights
    updated_weights = analyzer.update_scoring_weights()
    print(f"Updated weights: {updated_weights}")
```

**Option 2: TUISessionV2 Integration (Future: V2.2)**
```python
# In TUISessionV2.__init__() (future enhancement)
if self.orchestrator:
    self.tracker = SuccessTracker(self.profile)
    self.analyzer = PatternAnalyzer(self.tracker, self.orchestrator.config)
    self.telemetry = Telemetry(enabled=self.config.get('telemetry', {}).get('enabled', False))

# After task execution (future enhancement)
def _execute_task_with_tracking(self, task):
    start_time = time.time()
    success = self._execute_task(task)
    elapsed = time.time() - start_time

    # Record outcome
    self.tracker.record_task_outcome(task['id'], success, elapsed, task.get('metadata'))

    # Analyze patterns periodically
    if len(self.tracker.task_outcomes) % 10 == 0:
        self.analyzer.update_scoring_weights()
        self.telemetry.record_weight_update()
```

## Configuration

**Enable Pattern Learning:**
```json
// ~/.crack/config.json
{
  "intelligence": {
    "enabled": true,
    "pattern_learning": {
      "enabled": true,  // Future: Enable automatic tracking
      "min_samples": 3,  // Minimum samples for pattern detection
      "learning_rate": 0.1,  // Weight update aggressiveness
      "auto_tune": true  // Automatically update weights
    },
    "telemetry": {
      "enabled": false,  // Opt-in required
      "storage_path": "~/.crack/telemetry.json"
    }
  }
}
```

## Testing

**Unit Tests:**
- `test_success_tracker.py` - 17 tests (100% passing)
- `test_pattern_analyzer.py` - 17 tests (100% passing)
- `test_telemetry.py` - 16 tests (100% passing)

**Total:** 50 tests validating all pattern learning functionality

**Integration Tests (Future):**
```bash
# Test end-to-end pattern learning flow
crack track --tui 192.168.45.100 --enable-learning

# Execute 10+ tasks to build history
# Check that weights are updated:
cat ~/.crack/targets/192.168.45.100.json | jq '.metadata.success_tracker'

# View insights
python3 -c "
from crack.track.core.state import TargetProfile
from crack.track.intelligence import SuccessTracker, PatternAnalyzer

profile = TargetProfile.load('192.168.45.100')
tracker = SuccessTracker(profile)
analyzer = PatternAnalyzer(tracker, {})

insights = analyzer.get_pattern_insights()
print(insights)
"
```

## Privacy & Ethics

**Telemetry Privacy Principles:**
1. **Opt-in by default** - Users must explicitly enable
2. **Local storage only** - Data never leaves the system
3. **Anonymous counters** - No personally identifiable information
4. **Clear metrics command** - Easy to reset data
5. **Transparent** - Code is open source, users can audit

**What is NOT collected:**
- IP addresses
- Target hostnames
- Credentials
- Command arguments
- Personal information
- Network traffic

**What IS collected (if opted in):**
- Suggestion counts (integer)
- Acceptance counts (integer)
- Chain attempt/completion counts (integer)
- Pattern detection events (boolean)
- Weight update events (boolean)

## Performance Impact

**Minimal overhead:**
- SuccessTracker: O(1) inserts, O(n) queries (n = number of outcomes)
- PatternAnalyzer: O(n) analysis, runs infrequently (every 10 tasks)
- Telemetry: O(1) operations, disk I/O only if enabled
- Storage: ~1KB per 10 task outcomes

**No UI blocking:**
- All operations asynchronous via event handlers
- Persistence happens in background
- Pattern analysis triggered periodically, not per task

## Roadmap

**V2.0 (Current):**
- ✅ SuccessTracker implementation
- ✅ PatternAnalyzer implementation
- ✅ Telemetry implementation
- ✅ 50 unit tests passing
- ❌ Not yet integrated into TUI

**V2.1 (Planned):**
- 🔲 Wire pattern learning into TUISessionV2
- 🔲 Automatic task outcome tracking
- 🔲 Periodic weight updates
- 🔲 User-facing insights panel

**V2.2 (Future):**
- 🔲 Advanced pattern detection (sequence analysis)
- 🔲 Cross-target pattern learning
- 🔲 Community pattern sharing (opt-in)
- 🔲 Machine learning models (optional)

## Developer Notes

**Extending Pattern Learning:**

1. **Add new pattern types:**
```python
# In PatternAnalyzer
def detect_time_patterns(self):
    """Detect patterns in execution times"""
    # Analyze task execution time trends
    pass
```

2. **Add new telemetry metrics:**
```python
# In Telemetry
def record_custom_metric(self, metric_name, value):
    """Record custom metric"""
    if metric_name not in self.metrics:
        self.metrics[metric_name] = 0
    self.metrics[metric_name] += value
    self._save_metrics()
```

3. **Custom weight update strategies:**
```python
# In PatternAnalyzer
def update_weights_custom(self, strategy='conservative'):
    """Custom weight update with different strategies"""
    if strategy == 'aggressive':
        learning_rate = 0.2
    elif strategy == 'conservative':
        learning_rate = 0.05
    return self.update_scoring_weights(learning_rate)
```

## Status

**Implementation:** ✅ Complete (Stage 5.1-5.3)
**Integration:** 🔲 Pending (Stage 5.4-5.5)
**Testing:** ✅ 50/50 tests passing
**Documentation:** ✅ Complete
