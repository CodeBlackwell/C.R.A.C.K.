# AV Evasion Cheatsheet Proposals

## Overview

This document proposes future cheatsheet expansions for the CRACK reference system, building on the foundation established in the PEN-300 AV evasion modules.

---

## Completed Cheatsheets ✅

### Phase 1: Core AV Evasion (COMPLETE)

1. **AMSI Bypass** (6 commands) - Context corruption, memory patching, registry bypass
2. **Shellcode Runners** (7 commands) - C# templates, encryption, compilation
3. **Signature Evasion** (7 commands) - msfvenom encoding, Find-AVSignature, template injection
4. **Heuristic Evasion** (7 commands) - Sandbox detection, sleep timers, API checks
5. **VBA Evasion** (6 commands) - Office macros, obfuscation, WMI dechaining
6. **JScript Evasion** (5 commands) - WSH exploitation, COM objects, self-modification
7. **UAC Bypass** (4 commands) - FodHelper, EventVwr, integrity checks
8. **Debugging** (6 commands) - WinDbg, Frida, memory inspection

**Total:** 48 commands across 8 modules

---

## Proposed Expansions

### Phase 2: Advanced Evasion Techniques (Priority: HIGH)

#### 9. **ETW Bypass** (Event Tracing for Windows)
**Rationale:** ETW is critical telemetry source for EDR. Patching ETW providers disables logging.
**Estimated Commands:** 8-10
**Techniques:**
- ETW provider identification (`logman query providers`)
- NtTraceControl patching (disable ETW)
- ETW event suppression (provider-level)
- .NET ETW bypass (CLR tracing)
- PowerShell script block logging bypass
- Module load event suppression
- Process creation event hiding
- Testing and validation methods

**Difficulty:** Advanced
**OSCP Relevance:** Medium (useful for stealth, not required for basic passes)
**Time to Implement:** 15-20 hours
**References:** Red team blogs, Cobalt Strike tradecraft

---

#### 10. **Process Injection** (Code Injection Techniques)
**Rationale:** Classic technique for evading process-level monitoring. Inject into trusted processes.
**Estimated Commands:** 12-15
**Techniques:**
- CreateRemoteThread injection (classic)
- QueueUserAPC injection (asynchronous)
- Thread hijacking (suspend→inject→resume)
- Process hollowing (RunPE)
- Module stomping (overwrite loaded DLL)
- Reflective DLL injection
- Process Doppelgänging
- AtomBombing
- Early bird APC injection
- Parent PID spoofing (PPID spoofing)
- C# injection templates
- PowerShell injection (Invoke-ReflectivePEInjection)

**Difficulty:** Intermediate-Advanced
**OSCP Relevance:** Medium-High (common in Active Directory scenarios)
**Time to Implement:** 25-30 hours
**References:** PEN-300 Chapter 8, Malware analysis courses

---

#### 11. **DLL Unhooking** (API Hooking Bypass)
**Rationale:** EDR products hook Win32 APIs for monitoring. Unhooking restores original code.
**Estimated Commands:** 8-10
**Techniques:**
- Identify hooked functions (GetProcAddress comparison)
- Direct syscalls (bypass API layer entirely)
- Fresh copy technique (load clean ntdll.dll from disk)
- Heaven's Gate (WoW64 transition for 32-bit→64-bit syscalls)
- Manual mapping (load DLL without API calls)
- API hashing (obfuscate API resolution)
- Inline hooking detection
- IAT/EAT hooking detection

**Difficulty:** Advanced
**OSCP Relevance:** Low (exam-safe environments don't use heavy EDR)
**Time to Implement:** 20-25 hours
**References:** Red team tradecraft, malware dev courses

---

### Phase 3: Active Directory Evasion (Priority: HIGH)

#### 12. **Kerberos Evasion** (Golden/Silver Ticket Stealth)
**Rationale:** Kerberos attacks are heavily monitored. Evasion critical for persistence.
**Estimated Commands:** 10-12
**Techniques:**
- Golden Ticket with realistic lifetime (not 10 years)
- Silver Ticket for specific services
- Diamond Ticket (PAC manipulation)
- Kerberos Ticket Lifetime validation
- SID History injection detection bypass
- Event ID 4768/4769 evasion
- Rubeus vs Mimikatz comparison
- Ticket renewal strategies
- OPSEC-safe ticket usage patterns

**Difficulty:** Advanced
**OSCP Relevance:** High (Active Directory is core OSCP content)
**Time to Implement:** 15-20 hours
**References:** PEN-300 AD section, Red Team Field Manual

---

#### 13. **NTLM Relay Protection Bypass** (SMB Signing Evasion)
**Rationale:** SMB signing and EPA block NTLM relay. Bypass techniques enable relay attacks.
**Estimated Commands:** 8-10
**Techniques:**
- SMB signing status enumeration
- Drop-the-MIC attack (CVE-2019-1040)
- WebDAV relay (bypass SMB signing)
- HTTP→LDAP relay (LDAP signing bypass)
- NTLM relay via IPv6
- Cross-protocol relay chains
- SMB relay with Responder + ntlmrelayx
- PrinterBug + relay combination
- PetitPotam + relay

**Difficulty:** Intermediate
**OSCP Relevance:** High (relay attacks common in AD pentests)
**Time to Implement:** 12-15 hours
**References:** PEN-300, Impacket documentation

---

### Phase 4: Network Evasion (Priority: MEDIUM)

#### 14. **Firewall & IDS Evasion** (Network-Level Bypass)
**Rationale:** Bypass network monitoring, egress filtering, IPS signatures.
**Estimated Commands:** 12-15
**Techniques:**
- Domain fronting (CDN abuse)
- DNS tunneling (iodine, dnscat2)
- ICMP tunneling (ptunnel, icmpsh)
- HTTP/HTTPS C2 blending (Cobalt Strike malleable profiles)
- Port knocking sequences
- IPv6 tunneling over IPv4
- Encrypted payloads (SSL/TLS pinning bypass)
- User-Agent/JA3 fingerprint randomization
- Traffic fragmentation (nmap --mtu)
- Protocol misuse (HTTP over port 53, SSH over port 443)

**Difficulty:** Intermediate
**OSCP Relevance:** Low-Medium (basic firewall bypass needed, not advanced)
**Time to Implement:** 15-20 hours
**References:** Network pentesting books, C2 framework docs

---

#### 15. **Proxy & Pivoting Evasion** (Egress Restriction Bypass)
**Rationale:** Corporate proxies block outbound connections. Bypass techniques restore C2.
**Estimated Commands:** 10-12
**Techniques:**
- SOCKS proxy tunneling (chisel, ligolo)
- HTTP proxy authentication bypass
- NTLM proxy authentication relay
- SSH dynamic port forwarding (-D flag)
- DNS over HTTPS (DoH) for C2
- WebSockets for firewall bypass
- QUIC protocol for UDP→TCP conversion
- Meek domain fronting (Tor technique)
- VPN over DNS/ICMP

**Difficulty:** Intermediate
**OSCP Relevance:** Medium (pivoting is OSCP core skill)
**Time to Implement:** 12-15 hours
**References:** PEN-200 pivoting, Red Team infrastructure guides

---

### Phase 5: Linux Evasion (Priority: MEDIUM)

#### 16. **Linux AV Evasion** (ClamAV, ESET, Sophos)
**Rationale:** Linux servers increasingly monitored. Need evasion for persistence.
**Estimated Commands:** 10-12
**Techniques:**
- ELF binary obfuscation (UPX, custom packers)
- Bash obfuscation (base64, variable indirection)
- Python bytecode compilation (.pyc persistence)
- LD_PRELOAD hooking for rootkits
- Shared library injection (.so hijacking)
- Cron job obfuscation
- Systemd service evasion
- auditd log evasion
- SELinux/AppArmor bypass techniques
- Container escape detection bypass

**Difficulty:** Intermediate
**OSCP Relevance:** Medium (Linux privilege escalation common)
**Time to Implement:** 15-20 hours
**References:** Linux malware analysis, rootkit development

---

#### 17. **Linux Memory-Only Execution** (Fileless Malware)
**Rationale:** Avoid disk writes for stealth. Memory-only payloads harder to detect.
**Estimated Commands:** 8-10
**Techniques:**
- memfd_create (in-memory file descriptor)
- Shared memory execution (/dev/shm)
- /proc/self/mem injection
- Bash process substitution (<(command))
- Reflective ELF loading
- Python exec() from memory
- Perl/Ruby in-memory execution
- LD_AUDIT abuse for preloading

**Difficulty:** Advanced
**OSCP Relevance:** Low (interesting but not exam-critical)
**Time to Implement:** 15-20 hours
**References:** Malware research, Linux internals

---

### Phase 6: Web Application Evasion (Priority: HIGH)

#### 18. **WAF Bypass Techniques** (ModSecurity, Cloudflare, etc.)
**Rationale:** WAFs block SQLi, XSS, command injection. Bypass critical for web pentesting.
**Estimated Commands:** 15-20
**Techniques:**
- SQLi filter bypass (whitespace alternatives, encoding)
- XSS filter bypass (event handlers, polyglots)
- Command injection bypass (IFS, ${IFS}, separator alternatives)
- Path traversal encoding (double encoding, Unicode)
- IP whitelisting bypass (X-Forwarded-For spoofing)
- HTTP parameter pollution (HPP)
- HTTP verb tampering (POST→GET conversion)
- Content-Type mismatch exploitation
- Chunked encoding abuse
- Case variation bypass
- NULL byte injection (historical but still relevant)

**Difficulty:** Intermediate
**OSCP Relevance:** Very High (web exploitation is core OSCP)
**Time to Implement:** 20-25 hours
**References:** Web Application Hacker's Handbook, OWASP guides

---

#### 19. **API Security Evasion** (REST/GraphQL/SOAP)
**Rationale:** APIs increasingly common. Need techniques for rate limiting, auth bypass.
**Estimated Commands:** 12-15
**Techniques:**
- JWT manipulation (alg:none, key confusion)
- OAuth token theft and replay
- API rate limit bypass (header manipulation)
- GraphQL introspection bypass
- SOAP XXE exploitation
- API versioning abuse (v1 vs v2 endpoints)
- Mass assignment vulnerabilities
- IDOR via API parameter tampering
- API key exposure (GitHub, config files)
- CORS misconfiguration exploitation

**Difficulty:** Intermediate
**OSCP Relevance:** Medium-High (API pentesting growing in OSCP)
**Time to Implement:** 15-20 hours
**References:** API security guides, HackerOne reports

---

### Phase 7: Cloud Evasion (Priority: MEDIUM)

#### 20. **AWS/Azure/GCP Evasion** (Cloud Security Bypass)
**Rationale:** Cloud-native protections differ from on-prem. Need cloud-specific evasion.
**Estimated Commands:** 15-18
**Techniques:**
- IMDS v2 bypass (metadata service)
- S3 bucket enumeration without logging
- Lambda function persistence
- CloudTrail log evasion
- GuardDuty alert suppression
- Azure Managed Identity token theft
- GCP service account key abuse
- Container escape in ECS/AKS/GKE
- Serverless function injection
- Cloud storage ACL bypass

**Difficulty:** Intermediate-Advanced
**OSCP Relevance:** Low (traditional OSCP is on-prem focused)
**Time to Implement:** 20-25 hours
**References:** Cloud security courses, AWS/Azure pentesting guides

---

### Phase 8: Mobile & IoT (Priority: LOW)

#### 21. **Android Evasion** (Mobile Malware Techniques)
**Rationale:** Mobile pentesting growing. Need app repackaging, root detection bypass.
**Estimated Commands:** 12-15
**Techniques:**
- APK decompilation and repackaging
- SSL pinning bypass (Frida, objection)
- Root detection bypass (Magisk Hide)
- Play Protect evasion
- SafetyNet attestation bypass
- Obfuscation (ProGuard, DexGuard)
- Native library hooking
- Intent injection
- Broadcast receiver abuse

**Difficulty:** Intermediate
**OSCP Relevance:** None (OSCP doesn't cover mobile)
**Time to Implement:** 20-25 hours
**References:** Mobile Security Testing Guide (OWASP)

---

#### 22. **iOS Evasion** (iPhone/iPad Exploitation)
**Rationale:** iOS security is strong. Evasion techniques rare but valuable.
**Estimated Commands:** 10-12
**Techniques:**
- Jailbreak detection bypass
- SSL pinning bypass (Frida, SSL Kill Switch)
- IPA repackaging
- Keychain extraction
- Runtime hooking with Frida
- Objective-C method swizzling
- Code signing bypass (FairPlay DRM)
- XProtect evasion (macOS but related)

**Difficulty:** Advanced
**OSCP Relevance:** None
**Time to Implement:** 25-30 hours
**References:** iOS pentesting courses

---

### Phase 9: Hardware & Physical (Priority: LOW)

#### 23. **USB/BadUSB Evasion** (Physical Attack Vectors)
**Rationale:** USB attacks blocked by endpoint protection. Need bypass techniques.
**Estimated Commands:** 8-10
**Techniques:**
- Rubber Ducky payload encoding
- USB Armory stealth mode
- HID keyboard emulation detection bypass
- USB device whitelisting bypass
- Driver signature enforcement bypass
- Autorun.inf obfuscation
- U3 drive exploitation
- USB network adapter abuse

**Difficulty:** Intermediate
**OSCP Relevance:** None (OSCP is remote exploitation)
**Time to Implement:** 12-15 hours
**References:** Physical pentesting books

---

### Phase 10: OSINT & Recon Evasion (Priority: MEDIUM)

#### 24. **Passive Reconnaissance Without Attribution** (OPSEC for Recon)
**Rationale:** Recon activities leave traces. Need techniques to avoid attribution.
**Estimated Commands:** 12-15
**Techniques:**
- Tor + VPN chaining
- Residential proxy rotation
- User-Agent randomization
- Certificate transparency log queries (passive SSL enum)
- Shodan/Censys API usage without accounts
- Google dorking without Google (alternatives)
- DNS queries via DoH/DoT
- Passive subdomain enumeration (crt.sh, VirusTotal)
- GitHub API scraping without rate limits
- Wayback Machine historical data mining

**Difficulty:** Beginner-Intermediate
**OSCP Relevance:** Low (OSCP is technical exploitation, not OSINT)
**Time to Implement:** 10-15 hours
**References:** OSINT Framework, Red Team OPSEC

---

## Priority Matrix

### Immediate (Next 6 months)
1. **ETW Bypass** - Critical for modern Windows evasion
2. **Process Injection** - Fundamental technique, high reuse value
3. **Kerberos Evasion** - OSCP/OSWE Active Directory focus
4. **WAF Bypass** - Web exploitation core skill

### Short-Term (6-12 months)
5. **NTLM Relay Protection Bypass** - Active Directory attacks
6. **DLL Unhooking** - Advanced but increasingly necessary
7. **API Security Evasion** - Growing relevance in exams
8. **Linux AV Evasion** - Linux servers common in OSCP

### Medium-Term (12-24 months)
9. **Firewall & IDS Evasion** - Network-level techniques
10. **Proxy & Pivoting Evasion** - Enhance existing pivoting skills
11. **Linux Memory-Only Execution** - Advanced Linux techniques
12. **AWS/Azure/GCP Evasion** - Cloud skills future-proofing

### Long-Term (24+ months)
13. **Android Evasion** - Mobile pentesting expansion
14. **iOS Evasion** - Complete mobile coverage
15. **USB/BadUSB Evasion** - Physical security completeness
16. **OSINT Evasion** - OPSEC fundamentals

---

## Implementation Estimates

### Time Investment by Phase

| Phase | Modules | Commands | Est. Hours | Priority |
|-------|---------|----------|------------|----------|
| Phase 1 (COMPLETE) | 8 | 48 | ~80 | ⭐⭐⭐⭐⭐ |
| Phase 2 | 3 | 30 | ~70 | ⭐⭐⭐⭐⭐ |
| Phase 3 | 2 | 20 | ~35 | ⭐⭐⭐⭐⭐ |
| Phase 4 | 2 | 25 | ~35 | ⭐⭐⭐ |
| Phase 5 | 2 | 20 | ~35 | ⭐⭐⭐ |
| Phase 6 | 2 | 30 | ~40 | ⭐⭐⭐⭐⭐ |
| Phase 7 | 1 | 15 | ~25 | ⭐⭐ |
| Phase 8 | 2 | 25 | ~50 | ⭐ |
| Phase 9 | 1 | 10 | ~15 | ⭐ |
| Phase 10 | 1 | 12 | ~12 | ⭐⭐ |

**Total Proposed:** 16 new modules, 187 commands, ~317 hours

**Complete System:** 24 modules, 235 commands

---

## ROI Analysis (OSCP/OSWE Perspective)

### High ROI (Implement First)
- **WAF Bypass:** Direct exam applicability, high point value
- **Kerberos Evasion:** Active Directory is 40% of OSCP points
- **Process Injection:** Reusable across multiple machines
- **ETW Bypass:** Increasingly common in modern Windows targets

### Medium ROI (Implement After Core Complete)
- **API Security:** Growing relevance, moderate complexity
- **NTLM Relay:** Useful but situational
- **Linux Evasion:** Covers 30% of OSCP machines

### Low ROI (Nice-to-Have)
- **Cloud Evasion:** Not exam-relevant currently
- **Mobile Evasion:** No mobile in OSCP/OSWE
- **Hardware Evasion:** Physical access not tested remotely

---

## Community Feedback Requested

### Questions for Users

1. **Which 3 modules would be most valuable to you?**
2. **Are you interested in advanced techniques (ETW, DLL unhooking) or breadth (cloud, mobile)?**
3. **Would you prefer deep dives (15+ commands per module) or quick references (5-8 commands)?**
4. **Linux evasion priority: High or Medium?**
5. **Should we focus on OSCP-relevant only, or include OSWE/OSED techniques?**

### Contribution Opportunities

**Community can help by:**
- Testing proposed commands in lab environments
- Documenting success/failure rates
- Suggesting additional techniques
- Creating example workflows
- Reporting which modules save the most time in exams

---

## Versioning Strategy

### v1.0 (Current)
- **Status:** Complete
- **Modules:** 8 (AV evasion focus)
- **Commands:** 48
- **Target:** PEN-300, OSCP post-exploitation

### v1.1 (Proposed)
- **Timeline:** 3-6 months
- **Modules:** +4 (ETW, Process Injection, Kerberos, WAF)
- **Commands:** +50
- **Target:** Advanced Windows + Web exploitation

### v2.0 (Future)
- **Timeline:** 12-18 months
- **Modules:** +12 (remaining proposals)
- **Commands:** +137
- **Target:** Comprehensive evasion coverage (Windows, Linux, Web, Cloud)

---

## Maintenance Plan

### Ongoing Updates

1. **Quarterly Reviews:** Update for new Windows patches, AV signatures
2. **Technique Deprecation:** Remove obsolete methods (e.g., MS08-067)
3. **Tool Updates:** Track msfvenom changes, new Frida versions
4. **Community Feedback:** Incorporate user-reported successes/failures
5. **Exam Relevance:** Adjust priorities based on OSCP/OSWE changes

### Sustainability

- **Modular Design:** Each module self-contained, can be updated independently
- **Version Tags:** Git tags for stable releases
- **Testing Matrix:** Automated JSON validation, manual technique testing
- **Documentation:** Markdown guides for each module
- **CI/CD:** Automated testing on Windows 10/11, Server 2019/2022

---

## Conclusion

The AV evasion cheatsheet system provides a strong foundation (48 commands across 8 modules). Proposed expansions would add 187 commands across 16 modules, creating a comprehensive evasion reference with 235 total commands.

**Recommended Next Steps:**

1. **Immediate:** Implement Phase 2 (ETW, Process Injection, DLL Unhooking)
2. **Short-Term:** Add Phase 3 (Kerberos, NTLM Relay)
3. **Medium-Term:** Complete Phase 6 (WAF, API Security)
4. **Long-Term:** Evaluate community demand for cloud/mobile phases

**Success Metrics:**

- 90%+ JSON validation pass rate
- <5 minutes average command lookup time
- 85%+ technique success rate in lab testing
- Positive user feedback from OSCP/OSWE candidates

---

**Document Version:** 1.0
**Last Updated:** 2025
**Maintained By:** CRACK Toolkit Development Team
**Feedback:** Submit proposals via GitHub Issues or direct contribution
