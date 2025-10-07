# Enumeration Module Test Suite

## Philosophy: User-Story Driven Testing

This test suite validates that the enumeration tool **actually helps pentesters**, not just that code executes without errors.

**Key Principle**: Tests should prove the tool has value, not the other way around.

## Test Structure

### 1. User Stories (`test_user_stories.py`)
Real-world pentesting scenarios based on OSCP exam situations:

- **Story 1**: New target engagement - "I need a methodical checklist"
- **Story 2**: Import nmap results - "Auto-generate service-specific tasks"
- **Story 3**: Track progress - "Don't repeat work or miss steps"
- **Story 4**: Document findings - "Track sources for OSCP report"
- **Story 5**: Generate report - "Export comprehensive markdown writeup"
- **Story 6**: Resume after break - "Don't lose hours of work"
- **Story 7**: Multi-service target - "Organize tasks, don't overwhelm me"
- **Story 8**: Exploitation transition - "Give me privesc checklist"

### 2. Guidance Quality (`test_guidance_quality.py`)
Validates that recommendations are actually helpful:

- Quick wins are actually quick
- Don't suggest impossible tasks (SMB when SMB isn't open)
- Logical progression (discovery → service enum → exploitation)
- Exploit research for vulnerable versions
- Manual techniques taught (not just tool usage)
- No information overload
- Failure learning (explain what failure looks like)

### 3. Edge Cases (`test_edge_cases.py`)
Handles messy reality:

- Empty scan results (all ports filtered)
- Corrupted nmap XML
- Wrong file types
- Targets with 50+ ports
- Special characters in version strings
- Multiple scans of same target
- Corrupted saved profiles

### 4. Documentation (`test_documentation.py`)
OSCP report requirements:

- Every finding has a source
- Timeline reconstruction
- Command reproducibility
- Valid markdown export
- Flag explanations
- Complete report sections

## Running Tests

```bash
# All enumeration tests
pytest tests/enumeration/ -v

# Specific test file
pytest tests/enumeration/test_user_stories.py -v

# Single test class
pytest tests/enumeration/test_user_stories.py::TestUserStory1_NewTargetEngagement -v

# Single test
pytest tests/enumeration/test_user_stories.py::TestUserStory1_NewTargetEngagement::test_create_new_target_shows_discovery_tasks -v

# With coverage
pytest tests/enumeration/ --cov=crack.enumeration --cov-report=html

# Fast tests only (skip slow edge cases)
pytest tests/enumeration/ -v -m "not slow"
```

## Test Fixtures (conftest.py)

Realistic OSCP scenario data:

- `typical_oscp_nmap_xml` - SSH, HTTP, SMB (most common)
- `web_heavy_nmap_xml` - Multiple web ports (80, 443, 8080, 8443)
- `vulnerable_smb_nmap_xml` - Samba 3.0.20 (CVE-2007-2447)
- `minimal_linux_nmap_xml` - Only SSH and HTTP (requires deep web enum)
- `windows_dc_nmap_xml` - Domain Controller (53, 88, 135, 389, 445, 3389)
- `nmap_gnmap_typical` - Greppable format

## Real-World Scenarios Tested

### Scenario 1: Typical OSCP Lab Box
```python
# Import nmap scan → Get HTTP, SMB, SSH tasks
# Services: OpenSSH 8.2, Apache 2.4.41, Samba 4.13.13
# Expected: gobuster, enum4linux, version research
```

### Scenario 2: Web Application Server
```python
# 4 web services on different ports
# Expected: Separate enumeration for each port
# Test: No task duplication, clear prioritization
```

### Scenario 3: Ancient Vulnerable Samba
```python
# Samba 3.0.20 (known CVE-2007-2447)
# Expected: Automatic exploit research task
# Test: searchsploit suggestion, CVE reference
```

### Scenario 4: Minimal Linux Box
```python
# Only SSH and HTTP open
# Expected: Deep web enumeration (no SMB distractions)
# Test: Recommendations focus on available attack surface
```

### Scenario 5: Windows Domain Controller
```python
# Full AD infrastructure (Kerberos, LDAP, SMB, RDP)
# Expected: Domain-specific enumeration tasks
# Test: Kerberoasting, LDAP enum, SMB shares
```

## Success Criteria

A test **passes** if it validates real-world value:

✅ **Good Test**: "User imports nmap XML → Gets actionable HTTP enumeration tasks with commands"
❌ **Bad Test**: "NmapXMLParser.parse() returns dict"

✅ **Good Test**: "Quick wins don't suggest 2-hour gobuster scans"
❌ **Bad Test**: "recommend() function returns list"

✅ **Good Test**: "Finding without source raises ValueError with helpful message"
❌ **Bad Test**: "add_finding() accepts 3 parameters"

## Test Coverage Goals

- **User Stories**: 100% of critical workflows
- **Guidance Quality**: 80%+ of recommendations are helpful
- **Edge Cases**: Graceful handling, not crashes
- **Documentation**: OSCP report requirements met

## Adding New Tests

When adding a test, ask:

1. **Does this test a real user workflow?**
2. **What would frustrate a pentester?**
3. **What would cause an incomplete OSCP report?**
4. **How does this help discover holes in guidance?**

### Template for New User Story Test

```python
class TestUserStory9_YourScenario:
    """
    USER STORY:
    As a pentester [doing what],
    I want [feature],
    So that [benefit].

    ACCEPTANCE CRITERIA:
    - [Specific testable outcome 1]
    - [Specific testable outcome 2]
    - [Specific testable outcome 3]
    """

    def test_descriptive_scenario_name(self, clean_profile):
        """
        SCENARIO: [Specific real-world situation]
        EXPECTATION: [What user expects to happen]
        """
        # Arrange
        profile = clean_profile("192.168.45.100")

        # Act
        # ... perform user actions ...

        # Assert with helpful failure messages
        assert condition, "User-facing explanation of what went wrong"
```

## Debugging Failed Tests

When a test fails, it indicates **a real user would be frustrated**:

1. **Read the assertion message** - Written for user context
2. **Check the scenario description** - What workflow broke?
3. **Consider the user impact** - Would this block their pentest?
4. **Fix the tool, not the test** - Tests reflect real requirements

## Running Tests in CI/CD

```bash
# Quick smoke test
pytest tests/enumeration/test_user_stories.py::TestUserStory1_NewTargetEngagement -v

# Full test suite with coverage
pytest tests/enumeration/ --cov=crack.enumeration --cov-report=term-missing --cov-fail-under=70

# Generate HTML coverage report
pytest tests/enumeration/ --cov=crack.enumeration --cov-report=html
open htmlcov/index.html
```

## Test Data Philosophy

- **Contrived but realistic** - Based on actual OSCP lab boxes
- **Version numbers matter** - Test CVE detection
- **Edge cases from experience** - Corrupted scans, filtered ports, huge scans
- **Messy reality** - Special characters, missing data, concurrent scans

## Contribution Guidelines

New tests should:

1. Tell a story (not just test a function)
2. Use realistic data (from OSCP/HTB experiences)
3. Have clear assertion messages (explain user impact)
4. Test guidance quality (not just code execution)
5. Consider OSCP exam constraints (no tools, time pressure)

---

**Remember**: We're not just testing code. We're validating that this tool **helps pentesters succeed in OSCP**.
