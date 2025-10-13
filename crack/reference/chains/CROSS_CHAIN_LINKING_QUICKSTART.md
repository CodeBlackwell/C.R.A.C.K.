# Cross-Chain Linking Developer Quickstart

**Quick reference for implementing cross-chain activation in parsers**

---

## For Parser Developers

### Basic Pattern

```python
from crack.reference.chains.parsing.base import (
    BaseOutputParser,
    ParsingResult,
    ChainActivation
)

class MyParser(BaseOutputParser):
    @property
    def name(self) -> str:
        return "my-parser"

    def can_parse(self, step, command):
        return "my-command" in command

    def parse(self, output, step, command):
        # 1. Extract findings (existing logic)
        findings = self._extract_findings(output)

        # 2. Create base result
        result = ParsingResult(
            findings=findings,
            parser_name=self.name,
            success=True
        )

        # 3. Add activations based on findings
        if findings.get('exploitable_count', 0) > 0:
            result.activates_chains.append(
                ChainActivation(
                    chain_id="target-chain-id",
                    reason="Found exploitable condition",
                    confidence="high",
                    variables={"<BINARY>": findings['binary']}
                )
            )

        return result
```

---

## Activation Examples

### Simple Activation (No Variables)
```python
result.activates_chains.append(
    ChainActivation(
        chain_id="linux-privesc-docker",
        reason="User is in docker group"
    )
)
```

### Activation with Variable Inheritance
```python
result.activates_chains.append(
    ChainActivation(
        chain_id="sudo-exploit-vim",
        reason="vim has sudo NOPASSWD entry",
        confidence="high",
        variables={
            "<BINARY>": "vim",
            "<EXPLOIT_TYPE>": "sudo"
        }
    )
)
```

### Multiple Activations with Priority
```python
# High priority
result.activates_chains.append(
    ChainActivation(
        chain_id="quick-win-chain",
        reason="NOPASSWD sudo available",
        confidence="high"
    )
)

# Medium priority
result.activates_chains.append(
    ChainActivation(
        chain_id="alternate-chain",
        reason="SUID binary found",
        confidence="medium"
    )
)
```

### Conditional Activation
```python
gtfobins_count = findings.get('gtfobins_exploitable_count', 0)

if gtfobins_count > 0:
    result.activates_chains.append(
        ChainActivation(
            chain_id="gtfobins-exploit",
            reason=f"Found {gtfobins_count} GTFOBins-exploitable entries",
            confidence="high" if gtfobins_count >= 3 else "medium"
        )
    )
```

---

## Confidence Levels

| Level | When to Use |
|-------|-------------|
| `high` | NOPASSWD sudo, docker group, known CVE |
| `medium` | Standard SUID, writable cron, capabilities |
| `low` | Speculative paths, uncommon techniques |

---

## Backward Compatibility

**Old parsers (no changes needed):**
```python
def parse(self, output, step, command):
    return ParsingResult(
        findings={'binaries': ['vim']},
        variables={'<BINARY>': 'vim'}
    )
    # activates_chains defaults to [] - no activation occurs
```

**New parsers (opt-in activation):**
```python
def parse(self, output, step, command):
    result = ParsingResult(
        findings={'binaries': ['vim']}
    )

    # Add activation only when relevant
    if some_condition:
        result.activates_chains.append(...)

    return result
```

---

## Testing Your Parser

```python
def test_parser_activates_chain():
    """Parser suggests activation when condition met"""
    parser = MyParser()
    output = "exploitable condition found"

    result = parser.parse(output, {}, "my-command")

    assert result.has_activations() is True
    assert len(result.activates_chains) == 1
    assert result.activates_chains[0].chain_id == "expected-chain"
    assert result.activates_chains[0].confidence == "high"

def test_parser_no_activation_when_condition_not_met():
    """Parser does not activate when condition absent"""
    parser = MyParser()
    output = "no exploitable condition"

    result = parser.parse(output, {}, "my-command")

    assert result.has_activations() is False
    assert result.activates_chains == []
```

---

## Common Patterns

### Pattern 1: Single Binary Activation
```python
# When single exploitable binary found
result.activates_chains.append(
    ChainActivation(
        chain_id="binary-exploit",
        reason=f"Found exploitable binary: {binary}",
        variables={"<BINARY>": binary}
    )
)
```

### Pattern 2: Multiple Binary Activations
```python
# When multiple exploitable binaries found
for binary in exploitable_binaries:
    result.activates_chains.append(
        ChainActivation(
            chain_id=f"exploit-{binary}",
            reason=f"{binary} is exploitable via GTFOBins",
            variables={"<BINARY>": binary}
        )
    )
```

### Pattern 3: Conditional Chain Selection
```python
# Choose different chain based on conditions
if has_nopasswd_sudo:
    chain_id = "quick-win-sudo"
    confidence = "high"
elif has_password_sudo:
    chain_id = "sudo-with-password"
    confidence = "medium"
else:
    chain_id = "alternate-privesc"
    confidence = "low"

result.activates_chains.append(
    ChainActivation(
        chain_id=chain_id,
        reason="Sudo privilege found",
        confidence=confidence
    )
)
```

### Pattern 4: Threshold-Based Activation
```python
# Only activate if findings exceed threshold
if findings['count'] >= 3:
    result.activates_chains.append(
        ChainActivation(
            chain_id="mass-exploit",
            reason=f"Found {findings['count']} exploitable entries",
            confidence="high"
        )
    )
```

---

## Variable Naming Conventions

**Use existing chain placeholders:**
- `<TARGET>` - Target IP/hostname
- `<BINARY>` - Binary name
- `<PATH>` - File/directory path
- `<PORT>` - Port number
- `<USER>` - Username
- `<PASSWORD>` - Password/credential
- `<URL>` - Full URL
- `<LHOST>` - Local host IP
- `<LPORT>` - Local port

**Check target chain JSON for required variables:**
```bash
grep "<BINARY>" reference/data/attack_chains/linux-privesc-sudo.json
```

---

## Integration with ChainInteractive (Phase 2+)

**User Flow (Future Implementation):**
1. User executes chain step
2. Parser detects condition → returns activation
3. ChainInteractive prompts: "Found exploitable sudo entry. Switch to sudo-exploit chain? (y/n)"
4. User selects 'y' → Child chain activated with inherited variables
5. User completes child chain → Returns to parent chain

**Activation Handler (Phase 2):**
```python
# In ChainInteractive (future)
def _handle_activations(self, parse_result):
    """Handle chain activations from parser"""
    if not parse_result.has_activations():
        return

    for activation in parse_result.activates_chains:
        # Check circular prevention
        can_activate, reason = self.activation_manager.can_activate(
            self.chain_id,
            activation.chain_id
        )

        if not can_activate:
            print(f"Cannot activate: {reason}")
            continue

        # Prompt user
        prompt = f"Found: {activation.reason}. Switch to {activation.chain_id}? (y/n)"
        if input(prompt).lower() == 'y':
            # Launch child chain with inherited variables
            self._launch_child_chain(activation)
```

---

## ActivationManager Usage (Phase 2+)

```python
from crack.reference.chains.activation_manager import ActivationManager

# Initialize (once per session)
manager = ActivationManager()

# Before activating child chain
can_activate, reason = manager.can_activate("parent-chain", "child-chain")
if can_activate:
    manager.push_activation("parent-chain")
    manager.record_activation("parent-chain", "child-chain")
    # Execute child chain...
    manager.pop_activation()  # When returning to parent
else:
    print(f"Activation blocked: {reason}")

# Query state
current = manager.get_current_chain()
depth = manager.get_activation_depth()
```

---

## Debugging

### Check if Parser Emits Activations
```python
# In interactive.py (Phase 2)
if parse_result.has_activations():
    print(f"Parser emitted {len(parse_result.activates_chains)} activations:")
    for act in parse_result.activates_chains:
        print(f"  - {act.chain_id}: {act.reason} (confidence: {act.confidence})")
```

### Validate Chain IDs
```python
# Verify target chain exists
from crack.reference.chains.registry import ChainRegistry

if activation.chain_id not in ChainRegistry._chains:
    print(f"Warning: Chain '{activation.chain_id}' not found in registry")
```

---

## Best Practices

1. **Only activate when high value** - Don't activate for every finding
2. **Use descriptive reasons** - User needs context to decide
3. **Set appropriate confidence** - Helps prioritization
4. **Inherit relevant variables** - Pre-populate target chain
5. **Test both paths** - Activation present AND absent
6. **Document activation logic** - Comment why chain is activated

---

## Migration Checklist

When updating an existing parser:

- [ ] Read existing parser logic
- [ ] Identify activation conditions (e.g., GTFOBins found)
- [ ] Choose target chain ID
- [ ] Determine confidence level
- [ ] Extract variables to inherit
- [ ] Add activation to parse() method
- [ ] Write test for activation logic
- [ ] Write test for no-activation case
- [ ] Verify backward compatibility (old tests still pass)
- [ ] Document activation in parser docstring

---

## Reference

**Classes:**
- `ChainActivation` - Activation metadata
- `ParsingResult` - Parser return type (extended)
- `ActivationManager` - State management (Phase 2+)

**Methods:**
- `ParsingResult.has_activations()` - Check if activations exist
- `ActivationManager.can_activate()` - Circular prevention
- `ActivationManager.push_activation()` - Add to stack
- `ActivationManager.pop_activation()` - Remove from stack

**Files:**
- `parsing/base.py` - Base classes
- `activation_manager.py` - State manager
- `interactive.py` - Executor (Phase 2+)

**Documentation:**
- `PHASE1_IMPLEMENTATION_REPORT.md` - Full implementation details
- `Cross_Chain_Linking_Solution_Checklist.md` - Original design doc

---

## Support

**Questions?**
1. Check existing parser implementations (sudo_parser.py, suid_parser.py)
2. Review test files for examples
3. Read PHASE1_IMPLEMENTATION_REPORT.md for details

**Issues?**
1. Run tests: `pytest tests/reference/chains/test_chain_activation_base.py -xvs`
2. Check backward compatibility: `pytest tests/reference/chains/ -xvs`
3. Verify type hints: `mypy reference/chains/parsing/base.py`
