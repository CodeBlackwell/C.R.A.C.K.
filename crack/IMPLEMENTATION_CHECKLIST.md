# CRACK V2.0 Hybrid Intelligence System - Implementation Checklist

## Executive Summary

Implementation of a hybrid intelligence system combining reactive event-driven correlation (Method 1) with proactive methodology state machine (Method 2) to guide OSCP penetration testing workflows. The system provides intelligent task suggestions without being prescriptive, maintaining user autonomy while accelerating attack chain discovery.

## Dependency Graph

```
┌─────────────────────────────────────────────────────────────────┐
│                         Stage 1: Core Foundation                 │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │ Task Orchestrator│    │  Config System   │                   │
│  └────────┬─────────┘    └────────┬─────────┘                  │
│           └────────────┬───────────┘                            │
└────────────────────────┼────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Stage 2: Intelligence Engines                 │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │   Correlation    │    │   Methodology    │                   │
│  │   Intelligence   │    │   State Machine  │                   │
│  └────────┬─────────┘    └────────┬─────────┘                  │
│           └────────────┬───────────┘                            │
└────────────────────────┼────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Stage 3: Attack Chains                       │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │  Chain Catalog   │    │  Chain Executor  │                   │
│  └────────┬─────────┘    └────────┬─────────┘                  │
│           └────────────┬───────────┘                            │
└────────────────────────┼────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Stage 4: TUI Integration                     │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │  Guidance Panel  │    │    Shortcuts     │                   │
│  └────────┬─────────┘    └────────┬─────────┘                  │
│           └────────────┬───────────┘                            │
└────────────────────────┼────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Stage 5: Pattern Learning                    │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │ Success Tracker  │    │ Pattern Analyzer │                   │
│  └────────┬─────────┘    └────────┬─────────┘                  │
│           └────────────┬───────────┘                            │
└────────────────────────┼────────────────────────────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Stage 6: Optimization                        │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │    Performance   │    │   Telemetry      │                   │
│  └──────────────────┘    └──────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Stage 1: Core Foundation & Configuration

**Goal:** Establish task orchestration and configuration system as foundation for intelligence engines.

### Components to Build

1. **`track/intelligence/__init__.py`**
   - Package initialization
   - Version constants

2. **`track/intelligence/task_orchestrator.py`**
   - Class: `TaskOrchestrator`
   - Methods:
     - `__init__(target, profile, config)`
     - `generate_next_tasks(max_tasks=5)`
     - `merge_suggestions(method1_tasks, method2_tasks)`
     - `calculate_priority(task, context)`
     - `deduplicate_tasks(tasks)`
   - Priority scoring algorithm (7 factors)
   - Task history tracking
   - Deduplication logic

3. **`track/intelligence/scoring.py`**
   - Class: `TaskScorer`
   - Scoring factors:
     - Phase alignment (0-20 points)
     - Chain progress (0-30 points)
     - Quick-win potential (0-25 points)
     - Time estimate (0-10 points)
     - Dependency satisfaction (0-15 points)
     - Success probability (0-20 points)
     - User preference history (0-10 points)

4. **Configuration Extension (`~/.crack/config.json`)**
   ```json
   {
     "intelligence": {
       "enabled": true,
       "correlation": {
         "enabled": true,
         "auto_queue": true,
         "credential_spray": true,
         "cross_service_patterns": true
       },
       "methodology": {
         "enabled": true,
         "enforce_phases": false,
         "quick_wins_priority": true,
         "phase_transition_auto": false
       },
       "scoring_weights": {
         "phase_alignment": 1.0,
         "chain_progress": 1.5,
         "quick_win": 2.0,
         "time_estimate": 0.5,
         "dependencies": 1.0,
         "success_probability": 1.2,
         "user_preference": 0.8
       },
       "ui": {
         "show_guidance": true,
         "guidance_position": "top",
         "max_suggestions": 5,
         "show_reasoning": true
       }
     }
   }
   ```

### Dependencies
- Existing: EventBus, TargetProfile, TaskNode, Storage
- External: None

### Integration Points
- TargetProfile: Store orchestrator reference
- EventBus: Subscribe to task/finding events
- Config system: Load/save intelligence settings

### Testing Strategy
- **Unit Tests:**
  - `tests/track/test_task_orchestrator.py` (15 tests)
  - Test scoring algorithm with various inputs
  - Test deduplication logic
  - Test priority queue ordering
- **Integration Tests:**
  - Test config loading/saving
  - Test event handler registration

### Success Criteria
- [ ] TaskOrchestrator can merge task lists from 2 sources
- [ ] Priority scoring produces intuitive ordering
- [ ] Deduplication prevents duplicate task IDs
- [ ] Configuration persists across sessions
- [ ] 90% unit test coverage

### Estimated Effort
- Development: 2 days
- Testing: 1 day
- Total: 3 days

### Risk Factors
- Complex scoring algorithm may need tuning
- Config schema changes may break existing configs
- Priority ordering may be non-intuitive initially

### Rollback Strategy
- Feature flag: `intelligence.enabled` in config
- Preserve existing FindingsProcessor/ServicePlugin flows
- Git branch protection before merge

---

## Stage 2: Intelligence Engines

**Goal:** Implement reactive correlation intelligence and proactive methodology state machine.

### Components to Build

1. **`track/intelligence/correlation_engine.py`**
   - Class: `CorrelationIntelligence`
   - Methods:
     - `__init__(target, profile)`
     - `analyze_finding(finding)`
     - `analyze_credential(credential)`
     - `detect_attack_chains(context)`
     - `generate_correlation_tasks()`
   - Pattern definitions (credential spray, username variants, etc.)
   - Cross-service correlation logic
   - Attack chain trigger detection

2. **`track/methodology/methodology_engine.py`**
   - Class: `MethodologyEngine`
   - Properties:
     - `current_phase`: RECONNAISSANCE/SERVICE_ENUMERATION/etc.
     - `phase_progress`: Dict of completion metrics
   - Methods:
     - `__init__(profile)`
     - `evaluate_phase_transition()`
     - `get_phase_tasks(phase)`
     - `detect_quick_wins(context)`
     - `validate_phase_requirements(phase)`
   - Phase definitions and transitions
   - Quick-win pattern detection (OSCP-specific)

3. **`track/methodology/phases.py`**
   - Enum: `Phase`
     - RECONNAISSANCE
     - SERVICE_ENUMERATION
     - VULNERABILITY_DISCOVERY
     - EXPLOITATION
     - PRIVILEGE_ESCALATION
     - LATERAL_MOVEMENT
   - Phase transition requirements
   - Phase-specific task templates

### Dependencies
- Stage 1: TaskOrchestrator, configuration system
- Existing: EventBus, TargetProfile, FindingTypes

### Integration Points
- EventBus: Subscribe to finding_added, task_completed, service_detected
- TaskOrchestrator: Provide task suggestions
- FindingsProcessor: Coordinate to avoid duplication

### Testing Strategy
- **Unit Tests:**
  - `tests/track/test_correlation_engine.py` (20 tests)
  - `tests/track/test_methodology_engine.py` (15 tests)
  - Test pattern matching
  - Test phase transitions
  - Test quick-win detection
- **Integration Tests:**
  - Test with real finding events
  - Test coordination with FindingsProcessor

### Success Criteria
- [ ] Correlation detects credential spray opportunities
- [ ] Methodology suggests phase-appropriate tasks
- [ ] Quick-wins are prioritized correctly
- [ ] Phase transitions validate requirements
- [ ] 85% test coverage

### Estimated Effort
- Development: 3 days
- Testing: 2 days
- Total: 5 days

### Risk Factors
- Pattern definitions may be incomplete
- Phase transition logic may be too rigid
- Coordination with existing systems complex

### Rollback Strategy
- Feature flags per engine
- Maintain separation from existing systems
- A/B testing capability

---

## Stage 3: Attack Chain Implementation

**Goal:** Define and execute multi-step attack sequences with progress tracking.

### Components to Build

1. **`track/methodology/attack_chains.py`**
   - Class: `AttackChain`
     - Properties: id, name, description, steps, prerequisites
   - Class: `ChainStep`
     - Properties: id, name, command_template, success_indicators, failure_indicators
   - Catalog of chains:
     - SQLi → Shell
     - LFI → RCE
     - Upload → Shell
     - SSTI → RCE
     - XXE → File Read
     - Deserialization → RCE
     - Buffer Overflow → Shell
     - Privilege Escalation chains

2. **`track/methodology/chain_executor.py`**
   - Class: `ChainExecutor`
   - Methods:
     - `__init__(chain, profile)`
     - `get_next_step()`
     - `validate_step_completion(step, output)`
     - `track_progress()`
     - `generate_step_command(step, context)`
   - Dynamic command generation
   - Progress persistence
   - Failure recovery

3. **`track/methodology/chain_catalog.py`**
   - YAML/JSON definitions of attack chains
   - Version management
   - OSCP-specific chains
   - Community-contributed chains

### Dependencies
- Stage 2: MethodologyEngine
- Existing: TaskNode, CommandExecutor

### Integration Points
- MethodologyEngine: Chain activation triggers
- TaskOrchestrator: Chain steps as prioritized tasks
- TUI: Chain progress visualization

### Testing Strategy
- **Unit Tests:**
  - `tests/track/test_attack_chains.py` (25 tests)
  - Test each chain definition
  - Test step validation
  - Test command generation
- **Functional Tests:**
  - Test chain execution in mock environment
  - Test failure recovery

### Success Criteria
- [ ] 10+ attack chains defined
- [ ] Chain progress persists across sessions
- [ ] Step validation detects success/failure
- [ ] Commands are properly templated
- [ ] 80% test coverage

### Estimated Effort
- Development: 4 days
- Testing: 2 days
- Documentation: 1 day
- Total: 7 days

### Risk Factors
- Chain definitions may become outdated
- Success/failure indicators may be unreliable
- Complex chains hard to test

### Rollback Strategy
- Chains as optional guidance
- Disable per-chain via config
- Maintain manual execution path

---

## Stage 4: TUI Integration

**Goal:** Integrate intelligence system into TUI with guidance panel and shortcuts.

### Components to Build

1. **`track/interactive/panels/guidance_panel.py`**
   - Class: `GuidancePanel`
   - Methods:
     - `render()`
     - `get_top_suggestions(max=5)`
     - `format_suggestion(task, reasoning)`
   - Display top 3-5 recommendations
   - Show reasoning for each suggestion
   - Phase indicator
   - Active chain visualization

2. **TUI Session Integration** (modify `tui_session_v2.py`)
   - Initialize orchestrator in `__init__`
   - Add guidance panel to dashboard
   - Query orchestrator for suggestions
   - Track user task selection (preference learning)

3. **Shortcut Updates**
   - `g` - Toggle guidance panel
   - `:phase` - Manual phase transition
   - `:chain` - View active chains
   - `:intel` - Intelligence settings

4. **`track/interactive/overlays/intelligence_overlay.py`**
   - Intelligence system status
   - Active patterns
   - Chain progress
   - Correlation insights

### Dependencies
- Stages 1-3: All intelligence components
- Existing: TUI infrastructure, ShortcutHandler, ThemeManager

### Integration Points
- TUISessionV2: Main integration point
- Dashboard: Add guidance panel
- Task execution: Track for learning
- Debug logging: Intelligence decisions

### Testing Strategy
- **TUI Validation Tests:**
  - `tests/track/test_guidance_panel.py` (10 tests)
  - Mock input sequences
  - Log assertion patterns
  - Visual verification checklist
- **Integration Tests:**
  - Test panel rendering
  - Test suggestion updates
  - Test shortcut functionality

### Success Criteria
- [ ] Guidance panel shows top 5 suggestions
- [ ] Reasoning is clear and educational
- [ ] Panel updates reactively to events
- [ ] Shortcuts work as expected
- [ ] No performance degradation (<100ms)

### Estimated Effort
- Development: 3 days
- Testing: 2 days
- UI polish: 1 day
- Total: 6 days

### Risk Factors
- UI complexity may confuse users
- Performance impact on TUI
- Screen space constraints

### Rollback Strategy
- Config flag to hide guidance
- Preserve existing UI functionality
- Gradual rollout with beta testers

---

## Stage 5: Pattern Learning & Optimization

**Goal:** Track successful patterns and optimize suggestions based on user behavior.

### Components to Build

1. **`track/intelligence/success_tracker.py`**
   - Class: `SuccessTracker`
   - Methods:
     - `record_task_outcome(task, success, time_taken)`
     - `record_chain_completion(chain, steps_completed)`
     - `get_success_rate(pattern)`
   - Persistent success metrics
   - Time tracking for estimates

2. **`track/intelligence/pattern_analyzer.py`**
   - Class: `PatternAnalyzer`
   - Methods:
     - `analyze_user_preferences(history)`
     - `detect_successful_patterns()`
     - `update_scoring_weights()`
   - Machine learning lite approach
   - Pattern frequency analysis
   - Weight auto-tuning

3. **`track/intelligence/telemetry.py`**
   - Anonymous usage statistics
   - Attack chain success rates
   - Common failure points
   - Performance metrics

### Dependencies
- Stages 1-4: Full intelligence system
- Existing: Storage, EventBus

### Integration Points
- TaskOrchestrator: Use learned weights
- MethodologyEngine: Inform phase transitions
- Config: Persist learned parameters

### Testing Strategy
- **Unit Tests:**
  - `tests/track/test_success_tracker.py` (10 tests)
  - `tests/track/test_pattern_analyzer.py` (10 tests)
  - Test with synthetic history
  - Test weight updates
- **Long-term Tests:**
  - Multi-session learning validation
  - Pattern detection accuracy

### Success Criteria
- [ ] Success rates tracked accurately
- [ ] Patterns detected from history
- [ ] Weights update improve suggestions
- [ ] Performance metrics collected
- [ ] 75% test coverage

### Estimated Effort
- Development: 3 days
- Testing: 1 day
- Analysis tools: 1 day
- Total: 5 days

### Risk Factors
- Learning may produce unexpected results
- Privacy concerns with telemetry
- Storage requirements may grow

### Rollback Strategy
- Disable learning via config
- Clear learned data command
- Opt-out telemetry

---

## Stage 6: Performance Optimization & Monitoring

**Goal:** Ensure system performs well under load and provide monitoring capabilities.

### Components to Build

1. **`track/intelligence/performance.py`**
   - Class: `PerformanceMonitor`
   - Methods:
     - `start_timing(operation)`
     - `end_timing(operation)`
     - `get_metrics()`
   - Operation timing
   - Memory profiling
   - Bottleneck detection

2. **Caching Layer**
   - Cache correlation patterns
   - Cache scoring results
   - TTL-based invalidation
   - LRU eviction

3. **Async Processing**
   - Background correlation analysis
   - Async chain detection
   - Non-blocking UI updates

4. **`track/intelligence/diagnostics.py`**
   - System health checks
   - Intelligence effectiveness metrics
   - Debug commands for troubleshooting

### Dependencies
- Stages 1-5: Complete system
- External: asyncio, cachetools

### Integration Points
- All intelligence components
- TUI for performance metrics display
- Debug logging system

### Testing Strategy
- **Performance Tests:**
  - `tests/track/test_performance.py`
  - Load testing with 1000+ findings
  - Memory usage profiling
  - Response time validation
- **Stress Tests:**
  - Concurrent operations
  - Cache effectiveness
  - Async operation validation

### Success Criteria
- [ ] All operations <100ms
- [ ] Memory usage <50MB overhead
- [ ] Cache hit rate >80%
- [ ] No UI blocking
- [ ] Diagnostic commands functional

### Estimated Effort
- Development: 2 days
- Testing: 1 day
- Optimization: 2 days
- Total: 5 days

### Risk Factors
- Async complexity may introduce bugs
- Cache invalidation issues
- Performance varies by system

### Rollback Strategy
- Disable caching if issues
- Sync fallback for async operations
- Performance flags in config

---

## Testing Milestones

### Coverage Targets
- Stage 1: 90% coverage (foundation critical)
- Stage 2: 85% coverage (complex logic)
- Stage 3: 80% coverage (external dependencies)
- Stage 4: 75% coverage (UI testing challenges)
- Stage 5: 75% coverage (learning algorithms)
- Stage 6: 70% coverage (performance testing)
- **Overall Target: 80% coverage**

### Test Execution Plan
1. Unit tests run on every commit
2. Integration tests run before merge
3. TUI validation tests run manually
4. Performance tests run weekly
5. User acceptance tests before release

---

## Rollout & Monitoring Plan

### Beta Testing (Week 1-2)
1. Feature flag: `intelligence.enabled = false` by default
2. Select 5-10 beta testers from community
3. Provide feedback form and debug commands
4. Daily check-ins for issues

### Gradual Rollout (Week 3-4)
1. Enable for 25% of users
2. Monitor telemetry for issues
3. Collect success metrics
4. Refine scoring weights

### Full Release (Week 5)
1. Enable by default
2. Documentation release
3. Video tutorials
4. Community feedback forum

### Monitoring Metrics
- Task suggestion acceptance rate
- Chain completion rate
- User preference patterns
- Performance metrics (p50, p95, p99)
- Error rates and types
- User retention

### Success Indicators
- 50%+ suggestion acceptance rate
- 30%+ chain completion rate
- <100ms suggestion generation
- <5% error rate
- Positive user feedback

---

## Risk Mitigation Summary

### Technical Risks
1. **Complexity:** Modular design, comprehensive testing
2. **Performance:** Caching, async processing, profiling
3. **Integration:** Feature flags, gradual rollout
4. **Maintenance:** Clear documentation, monitoring

### User Experience Risks
1. **Confusion:** Clear reasoning, educational focus
2. **Overwhelm:** Limit suggestions, progressive disclosure
3. **Trust:** Transparency, explain decisions
4. **Autonomy:** Suggestions not requirements

### Project Risks
1. **Scope creep:** Fixed stages, clear boundaries
2. **Timeline slip:** Buffer time, parallel work
3. **Quality issues:** Continuous testing, beta program
4. **Adoption:** Community engagement, tutorials

---

## Implementation Timeline

**Total Duration: 31 days**

- **Week 1:** Stage 1 (Core Foundation) - 3 days
- **Week 2:** Stage 2 (Intelligence Engines) - 5 days
- **Week 3-4:** Stage 3 (Attack Chains) - 7 days
- **Week 4-5:** Stage 4 (TUI Integration) - 6 days
- **Week 5-6:** Stage 5 (Pattern Learning) - 5 days
- **Week 6:** Stage 6 (Optimization) - 5 days

**Parallel Activities:**
- Documentation: Throughout
- Testing: Continuous
- Code reviews: Daily
- Beta feedback: Week 4 onwards

---

## Definition of Done

### Per Stage
- [ ] All components implemented
- [ ] Unit tests passing
- [ ] Integration tests passing
- [ ] Documentation complete
- [ ] Code review approved
- [ ] Performance validated

### Overall
- [ ] 80% test coverage achieved
- [ ] All stages integrated
- [ ] Beta testing completed
- [ ] Documentation published
- [ ] Performance targets met
- [ ] Rollback plan tested
- [ ] Monitoring in place
- [ ] Community feedback positive

---

## Appendix: Key Design Decisions

1. **Hybrid Approach:** Combines reactive (event-driven) and proactive (methodology) for comprehensive coverage
2. **Non-Prescriptive:** Suggestions only, maintaining user autonomy
3. **Educational Focus:** Always explain reasoning to teach methodology
4. **OSCP Optimization:** Quick-wins and time estimates for exam scenarios
5. **Extensible Architecture:** Easy to add new patterns, chains, and plugins
6. **Performance First:** <100ms target ensures no UI degradation
7. **Privacy Conscious:** Optional telemetry, no personal data collected
8. **Gradual Learning:** System improves over time without being intrusive