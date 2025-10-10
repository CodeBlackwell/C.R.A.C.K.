# Plugin Migration Roadmap

## Migration Overview

Total Plugins: 122
Current State: 2 manual-only (1.6%)
Target State: <6 manual-only (<5%)
Plugins Needing Migration: ~30-40 high-value targets

## Migration Tiers

### Tier 1: Critical - Manual-Only Plugins (Week 1)
**Goal**: Eliminate manual-only anti-pattern

| Plugin | Current Activation | New Activation | Priority | Effort | Notes |
|--------|-------------------|----------------|----------|--------|-------|
| post_exploit.py | Manual-only (returns False) | Finding: shell_obtained | **CRITICAL** | 2h | Currently requires manual trigger - major UX pain |
| windows_privesc.py | Manual-only (returns False) | Finding: os_windows, shell_obtained | **CRITICAL** | 2h | 900+ lines of tasks sitting dormant |
| linux_privesc.py | Manual-only (returns False) | Finding: os_linux, shell_obtained | **CRITICAL** | 1h | Essential for OSCP privilege escalation |
| linux_privesc_advanced.py | Manual-only (returns False) | Finding: os_linux, root_shell | **CRITICAL** | 1h | Advanced techniques need automation |

**Success Metric**: 0% manual-only plugins

### Tier 2: High-Value - CMS & Framework Plugins (Week 1-2)
**Goal**: Auto-activate on CMS/framework detection

| Plugin | Current Activation | New Activation | Priority | Effort | Notes |
|--------|-------------------|----------------|----------|--------|-------|
| wordpress.py | Port 80/443 only | Finding: cms_wordpress | HIGH | 2h | 1000+ lines of enumeration tasks |
| cms.py | Port-based | Finding: cms_detected | HIGH | 2h | Generic CMS enumeration |
| nodejs.py | Port-based | Finding: framework_nodejs | HIGH | 1h | Node.js specific attacks |
| php.py | Port-based | Finding: tech_php | HIGH | 1h | PHP-specific enumeration |
| ruby_on_rails.py | Port-based | Finding: framework_rails | MEDIUM | 1h | Rails-specific tasks |
| spring_boot.py | Port-based | Finding: framework_spring | MEDIUM | 1h | Spring actuators, etc. |
| nextjs.py | Port-based | Finding: framework_nextjs | MEDIUM | 1h | Next.js specific paths |
| python_web.py | Port-based | Finding: tech_python | MEDIUM | 1h | Django/Flask detection |

**Success Metric**: CMS plugins activate on detection, not just port

### Tier 3: OS & Environment Plugins (Week 2)
**Goal**: Context-aware activation based on environment

| Plugin | Current Activation | New Activation | Priority | Effort | Notes |
|--------|-------------------|----------------|----------|--------|-------|
| linux_enumeration.py | Port-based | Finding: os_linux | HIGH | 1h | Basic Linux enum |
| linux_persistence.py | Port-based | Finding: root_shell | HIGH | 1h | Persistence after root |
| linux_container_escape.py | Port-based | Finding: container_detected | HIGH | 2h | Docker/LXC escapes |
| linux_kernel_exploit.py | Port-based | Finding: kernel_vulnerable | MEDIUM | 1h | Kernel exploit research |
| windows_core.py | Port-based | Finding: os_windows | HIGH | 1h | Windows fundamentals |
| windows_dll_ipc_privesc.py | Port-based | Finding: os_windows | MEDIUM | 1h | DLL hijacking |
| windows_privesc_extended.py | Port-based | Finding: os_windows | MEDIUM | 1h | Extended techniques |
| macos_privesc.py | Port-based | Finding: os_macos | LOW | 1h | macOS privilege escalation |
| macos_enumeration.py | Port-based | Finding: os_macos | LOW | 1h | macOS enumeration |

**Success Metric**: OS-specific plugins activate on OS detection

### Tier 4: Active Directory & Domain Plugins (Week 2-3)
**Goal**: Activate on domain membership detection

| Plugin | Current Activation | New Activation | Priority | Effort | Notes |
|--------|-------------------|----------------|----------|--------|-------|
| ad_enumeration.py | Port 389/445 | Finding: domain_joined | HIGH | 2h | AD enumeration tasks |
| ad_attacks.py | Port-based | Finding: domain_admin_potential | HIGH | 2h | Kerberoasting, etc. |
| ad_persistence.py | Port-based | Finding: domain_admin_obtained | MEDIUM | 1h | Golden ticket, etc. |
| ad_certificates.py | Port-based | Finding: adcs_detected | MEDIUM | 1h | ADCS attacks |
| lateral_movement.py | Port-based | Finding: credential_found | HIGH | 2h | Credential-based lateral |

**Success Metric**: AD plugins activate on domain discovery

### Tier 5: Exploitation & Vulnerability Plugins (Week 3)
**Goal**: Activate on vulnerability discovery

| Plugin | Current Activation | New Activation | Priority | Effort | Notes |
|--------|-------------------|----------------|----------|--------|-------|
| binary_exploit.py | Port-based | Finding: binary_vulnerable | MEDIUM | 2h | Buffer overflow tasks |
| injection_attacks.py | Already finding-based | Enhance with more types | MEDIUM | 1h | SQL, XSS, etc. |
| deserialization_attacks.py | Port-based | Finding: deserialization_point | MEDIUM | 1h | Java, Python, PHP |
| ssrf_attacks.py | Port-based | Finding: ssrf_potential | MEDIUM | 1h | SSRF exploitation |
| ssti_attacks.py | Port-based | Finding: ssti_potential | MEDIUM | 1h | Template injection |
| xxe_attacks.py | Port-based | Finding: xml_parser_found | LOW | 1h | XXE exploitation |

**Success Metric**: Vuln-specific plugins activate on vulnerability detection

### Tier 6: Credential & Access Plugins (Week 3)
**Goal**: Activate on credential/access findings

| Plugin | Current Activation | New Activation | Priority | Effort | Notes |
|--------|-------------------|----------------|----------|--------|-------|
| credential_theft.py | Port-based | Finding: credential_found | HIGH | 1h | Credential exploitation |
| reverse_shells.py | Port-based | Finding: rce_potential | HIGH | 1h | Shell generation |
| c2_operations.py | Port-based | Finding: c2_needed | MEDIUM | 2h | C2 setup tasks |
| phishing.py | Unclear | Finding: email_access | LOW | 1h | Phishing campaigns |

**Success Metric**: Credential plugins activate on credential discovery

### Tier 7: Cloud & Container Plugins (Week 4)
**Goal**: Modern environment detection

| Plugin | Current Activation | New Activation | Priority | Effort | Notes |
|--------|-------------------|----------------|----------|--------|-------|
| kubernetes.py (if exists) | Port-based | Finding: kubernetes_detected | MEDIUM | 2h | K8s enumeration |
| cloud_enum.py (if exists) | Port-based | Finding: cloud_detected | MEDIUM | 2h | AWS/Azure/GCP |
| docker.py (if exists) | Port-based | Finding: docker_detected | MEDIUM | 1h | Docker enumeration |

### Plugins to Remain Port-Only
These plugins are inherently network-service based and don't need finding activation:

- **Network Services**: ftp.py, ssh.py, smtp.py, pop3.py, imap.py, ntp.py
- **Databases**: mysql.py, postgresql.py, mongodb.py, oracle.py, couchdb.py
- **Web Servers**: apache.py, nginx.py, iis.py
- **Network Protocols**: snmp.py, nfs.py, smb.py, rpcbind.py
- **Legacy**: legacy_protocols.py, legacy_file_services.py

Total: ~40 plugins remain port-only (appropriate for their function)

## Implementation Timeline

### Week 1: Foundation + Critical
- [ ] Day 1-2: Implement core infrastructure (base class, registry)
- [ ] Day 3: Migrate Tier 1 plugins (manual-only)
- [ ] Day 4: Test Tier 1 thoroughly
- [ ] Day 5: Begin Tier 2 (CMS plugins)

### Week 2: High-Value Plugins
- [ ] Day 1-3: Complete Tier 2 (CMS/frameworks)
- [ ] Day 4-5: Implement Tier 3 (OS/environment)

### Week 3: Domain & Exploits
- [ ] Day 1-2: Implement Tier 4 (AD/domain)
- [ ] Day 3-4: Implement Tier 5 (exploitation)
- [ ] Day 5: Implement Tier 6 (credentials)

### Week 4: Testing & Polish
- [ ] Day 1-2: Implement Tier 7 (cloud/containers)
- [ ] Day 3: Integration testing
- [ ] Day 4: Documentation updates
- [ ] Day 5: User acceptance testing

## Migration Checklist Template

For each plugin migration:

```markdown
## Plugin: [plugin_name].py

### Pre-Migration Analysis
- [ ] Current activation: [port/manual/finding]
- [ ] Task count: [number]
- [ ] Has on_task_complete: [yes/no]
- [ ] Dependencies: [list]

### Implementation
- [ ] Add detect_from_finding() method
- [ ] Define confidence scoring logic
- [ ] Update get_task_tree() to handle finding context
- [ ] Add finding type imports

### Testing
- [ ] Unit test for detect_from_finding()
- [ ] Integration test for finding→activation
- [ ] Regression test for port-based activation
- [ ] Manual test in TUI

### Documentation
- [ ] Update method docstrings
- [ ] Add finding types to constants
- [ ] Update plugin header comments
```

## Success Metrics

### Quantitative
- **Manual plugins**: 2 → 0 (100% reduction)
- **Finding-aware plugins**: 2 → 40+ (2000% increase)
- **Auto-activation rate**: 10% → 60%+ of discoveries
- **User interventions**: 50% reduction in manual triggers

### Qualitative
- **User Experience**: Plugins "just work" when context appears
- **Intelligence**: Right plugin activates at right time
- **Efficiency**: Fewer clicks, more automation
- **OSCP Readiness**: Better exam time management

## Risk Mitigation

### Risk 1: Breaking Existing Functionality
**Mitigation**:
- Default detect_from_finding() returns 0
- All changes are additive, not destructive
- Comprehensive regression testing

### Risk 2: Performance Degradation
**Mitigation**:
- Deduplication prevents repeated activation
- Lazy evaluation of plugin detection
- Profile-based caching

### Risk 3: Activation Conflicts
**Mitigation**:
- Reuse confidence score system
- Clear precedence rules
- Logging for debugging

### Risk 4: User Confusion
**Mitigation**:
- Clear activation source in task metadata
- Visual indicators in TUI
- Comprehensive documentation

## Rollback Plan

If issues arise:

1. **Immediate**: Set `ENABLE_FINDING_ACTIVATION = False` in config
2. **Selective**: Disable per-plugin via config overrides
3. **Full Rollback**: Git revert to pre-migration tag
4. **Gradual Enable**: Roll out plugin by plugin

## Post-Migration Maintenance

### Monthly Review
- Analyze activation patterns
- Identify missed opportunities
- Tune confidence scores
- Add new finding types

### Continuous Improvement
- User feedback integration
- Performance optimization
- New finding type support
- Plugin enhancement based on usage

## Appendix: Finding Type Mapping

| Finding Pattern | Finding Type | Activates Plugins |
|-----------------|--------------|-------------------|
| "shell obtained" | shell_obtained | post_exploit, *_privesc |
| "WordPress detected" | cms_wordpress | wordpress |
| "Windows Server" | os_windows | windows_* |
| "Linux kernel" | os_linux | linux_* |
| "domain controller" | domain_joined | ad_* |
| "Docker container" | container_detected | *_container_escape |
| "CVE-*" | cve_found | exploit research plugins |
| "credentials found" | credential_found | credential_*, lateral_movement |
| "SQL injection" | sql_injection | injection_attacks |
| "admin panel" | admin_panel_found | auth_bypass, credential_theft |