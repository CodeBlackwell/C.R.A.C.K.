# SCAN PROFILES CHANGELOG - Chapter 7 Performance Optimizations

**Date:** 2025-10-08
**Source:** Nmap Cookbook Chapter 7 Mining Report
**Mining Agent:** CrackPot v1.0

---

## Summary

Extracted and implemented **8 performance-optimized scan profiles** from Nmap Cookbook Chapter 7: "Scanning Large Networks". These profiles add advanced timing, rate control, and two-phase scanning strategies for OSCP lab time optimization.

---

## Files Modified

1. **/home/kali/OSCP/crack/track/data/scan_profiles.json**
   - Added `performance_optimized_profiles` array (8 profiles)
   - Updated `meta.lab_recommended` (4 new profiles)
   - Updated `meta.exam_recommended` (3 new profiles)

2. **/home/kali/OSCP/crack/track/core/command_builder.py**
   - Enhanced `_get_rate_limiting()` method with 12 new performance flags

---

## Profiles Added

### 1. lab-speed-optimized (OSCP:HIGH)
- **Time:** 2-5 minutes for 100 hosts
- **Command:** `nmap -T4 -n -Pn --min-hostgroup 100 --max-hostgroup 500`
- **Use Case:** OSCP lab subnet sweeps (192.168.x.0/24)

### 2. lab-retry-optimized (OSCP:HIGH)
- **Time:** 3-7 minutes
- **Command:** `nmap -p- --max-retries 2 --min-rate 1000`
- **Use Case:** Stable lab networks (NOT for exam unless verified)

### 3. lab-rate-limited (OSCP:HIGH)
- **Time:** 10-15 minutes
- **Command:** `nmap -p- --max-rate 500 --max-retries 6`
- **Use Case:** OSCP exam when firewall/IDS suspected

### 4. lab-parallelism-controlled (OSCP:MEDIUM)
- **Time:** 5-10 minutes
- **Command:** `nmap -p- --min-parallelism 10 --max-parallelism 250`
- **Use Case:** Advanced - unstable networks only

### 5. lab-rtt-optimized (OSCP:MEDIUM)
- **Time:** 4-8 minutes
- **Command:** `nmap -p- --initial-rtt-timeout 150ms --max-rtt-timeout 600ms --min-rtt-timeout 50ms`
- **Use Case:** Low-latency local lab networks (requires RTT measurement)

### 6. lab-scan-delay (OSCP:LOW)
- **Time:** 20-30 minutes
- **Command:** `nmap -p- --scan-delay 1s --max-scan-delay 10s`
- **Use Case:** IDS evasion (NOT practical for OSCP exam)

### 7. lab-discovery-only (OSCP:HIGH, QUICK_WIN)
- **Time:** 1-3 minutes
- **Command:** `nmap -p- -n -Pn -T4`
- **Use Case:** Two-phase Phase 1: Fast port discovery

### 8. lab-service-detect-targeted (OSCP:HIGH)
- **Time:** 2-5 minutes
- **Command:** `nmap -sV -sC -n`
- **Use Case:** Two-phase Phase 2: Targeted service detection

---

## Command Builder Enhancements

Added support for 12 new performance flags:

**Retry/Timeout Control:**
- `--max-retries`, `--host-timeout`
- `--initial-rtt-timeout`, `--max-rtt-timeout`, `--min-rtt-timeout`

**Parallelism Control:**
- `--min-hostgroup`, `--max-hostgroup`
- `--min-parallelism`, `--max-parallelism`

**IDS Evasion:**
- `--scan-delay`, `--max-scan-delay`

---

## Usage Examples

### Two-Phase Scanning (60% time savings)
```bash
# Phase 1: Fast port discovery (1-3 minutes)
nmap -p- -n -Pn -T4 -oA discovery 192.168.45.100

# Phase 2: Targeted service detection (2-5 minutes)
nmap -sV -sC -n -p 22,80,445,3306 -oA services 192.168.45.100

# Total: 5-8 minutes vs 12+ for combined -sV -p-
```

### Lab Subnet Sweep (50% time savings)
```bash
# Hostgroup optimization for multiple targets
nmap -T4 -n -Pn --min-hostgroup 100 --max-hostgroup 500 192.168.120.0/24 -oA lab_sweep

# Time: 5-10 minutes vs 15-20 for default grouping
```

### Exam-Safe Conservative Scan
```bash
# When firewall suspected
nmap -p- --max-rate 500 --max-retries 6 192.168.45.100 -oA exam_safe

# Time: 10-15 minutes (avoids IDS triggers)
```

---

## OSCP Recommendations

**Lab Practice:**
- Use `lab-speed-optimized` for subnet sweeps
- Use two-phase strategy for time savings
- Experiment with retry optimization

**Exam Strategy:**
- Start with `lab-rate-limited` (conservative)
- Use two-phase scanning if time-critical
- Avoid `lab-retry-optimized` (risk missing ports)
- Never use `lab-scan-delay` (too slow)

---

## Time Savings Summary

| Profile | Time | Savings | Relevance |
|---------|------|---------|-----------|
| lab-speed-optimized | 2-5 min | 50%+ | Lab sweeps |
| lab-retry-optimized | 3-7 min | 30-40% | Stable labs only |
| lab-discovery-only | 1-3 min | 60% | Two-phase Phase 1 |
| lab-service-detect-targeted | 2-5 min | 40-60% | Two-phase Phase 2 |

**Total Potential Savings:** 30-60% on OSCP lab enumeration

---

## References

- **Source:** `crack/.references/nmap_cookbook_chapters/chapter_07_scanning_large_networks.txt`
- **Mining Report:** `crack/track/services/plugin_docs/NMAP_CH07_LARGE_NETWORKS_MINING_REPORT.md`

---

**Total System Profiles:** 30+ (base + HTTP + database + mail + OS + performance)
**New Capabilities:** Multi-target optimization, retry control, two-phase workflows
