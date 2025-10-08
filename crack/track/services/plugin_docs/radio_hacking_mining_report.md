# Radio Hacking Mining Report

**Agent:** Phase 3 Agent 10
**Date:** 2025-10-07
**Source Directory:** `/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/`
**Total Lines:** ~1,131 lines across 16 markdown files

---

## Decision: SKIP - NOT OSCP RELEVANT

**Conclusion:** Radio-hacking content is NOT suitable for CRACK Track OSCP preparation. No plugin will be created.

---

## Content Analysis

### Files Found

**Main Directory (10 files):**
- `README.md` (69 bytes - empty placeholder)
- `pentesting-rfid.md` (12KB - RFID 125kHz/13.56MHz attacks)
- `pentesting-ble-bluetooth-low-energy.md` (9.7KB - BLE sniffing/GATT attacks)
- `sub-ghz-rf.md` (7.2KB - Car/garage door RF attacks, 315/433MHz)
- `low-power-wide-area-network.md` (5.3KB - LoRaWAN/LoRa attacks)
- `fissure-the-rf-framework.md` (13KB - FISSURE SDR framework)
- `proxmark-3.md` (4.9KB - Proxmark3 RFID cloning)
- `infrared.md` (8.1KB - IR remote attacks)
- `ibutton.md` (2.7KB - iButton physical access attacks)
- `maxiprox-mobile-cloner.md` (5.4KB - HID MaxiProx cloner build guide)

**Flipper Zero Subdirectory (6 files):**
- `fz-125khz-rfid.md` (1.7KB)
- `fz-nfc.md` (4.5KB)
- `fz-sub-ghz.md` (5.8KB)
- `fz-infrared.md` (2.6KB)
- `fz-ibutton.md` (1.4KB)
- `README.md` (751 bytes)

---

## Technology Categories

### 1. RFID/NFC (Low & High Frequency)

**Low-Frequency (125kHz):**
- EM-Marin, HID Prox II, Indala protocols
- Used for: Building access, gym cards, car parking
- Attack: Clone with Flipper Zero, Proxmark3
- Range: Up to 1 meter

**High-Frequency (13.56MHz):**
- ISO 14443-A/B, Mifare Classic/Ultralight, EMV
- Used for: Bank cards, public transport, secure passes
- Attack: Crypto1 broken (Mifare Classic), value tampering
- Tools: Proxmark3 (`hf mf autopwn`, UID cloning)

**OSCP Relevance:** NONE (physical access control, not network pentesting)

### 2. Bluetooth Low Energy (BLE)

**Techniques:**
- Beacon sniffing (advertising packets)
- GATT enumeration (characteristics/services)
- Unauthenticated write attacks
- Sniffing unpaired devices with Sniffle (CC26x2/CC1352)
- Active control via Nordic nRF Connect

**Tools:**
- `gatttool`, `bettercap`
- Sniffle (NCC Group firmware for CC1352 dongles)
- Nordic nRF Sniffer, blatann Python library

**OSCP Relevance:** VERY LOW (rare in OSCP lab environment, requires specialized hardware)

### 3. Sub-GHz RF Attacks

**Frequencies:**
- 300-390 MHz (garage doors)
- 315 MHz (US/Japan car key fobs)
- 433.92 MHz (Europe car key fobs)

**Attacks:**
- Replay attacks (capture & retransmit)
- Brute-force attacks (De Bruijn Sequence optimization: 8 seconds)
- Rolling code bypass:
  - Missing Link Attack (capture out-of-range signal)
  - Full Link Jamming Attack (jam receiver, capture code)
  - RollJam (stealthy jamming + dual code capture)
  - Alarm Sounding Jamming Attack (DoS via code replay)

**Tools:**
- Flipper Zero (`fz-sub-ghz.md`)
- HackRF One, SDR (GNU Radio)
- OpenSesame (De Bruijn attack implementation)

**OSCP Relevance:** NONE (physical proximity required, specialized hardware)

### 4. LoRaWAN / LPWAN

**Technology:**
- Long-range (>6 miles), low-power IoT communication
- LoRa physical layer (proprietary Chirp Spread Spectrum)
- LoRaWAN MAC layer (open spec, versions 1.0.x/1.1)

**Attacks:**
- Sniff & decrypt traffic (weak AppKey brute-force)
- OTAA join-replay (DevNonce reuse)
- ADR downgrading (force SF12 to exhaust duty-cycle)
- Reactive jamming (GNU Radio flowgraph, HackRF)
- Gateway exploits (CVE-2024-29862 ChirpStack, Dragino CVEs)

**Tools:**
- LoRaWAN Auditing Framework (LAF)
- LoRaPWN (Trend Micro)
- LoRAttack (USRP multi-channel sniffer)
- GNU Radio (gr-lora/gr-lorawan)

**OSCP Relevance:** NONE (IoT/OT security, not in OSCP scope)

### 5. FISSURE Framework

**Description:**
- Frequency Independent SDR-based Signal Understanding & Reverse Engineering
- Open-source RF framework for signal detection, classification, attack execution
- Python/PyQt UI, GNU Radio integration
- Supports Ubuntu 18.04-22.04, requires SDR hardware

**OSCP Relevance:** NONE (research/educational framework, not pentesting tool)

### 6. Infrared & iButton

**Infrared:**
- IR remote control capture/replay (TV, AC, etc.)
- Tools: Flipper Zero IR module

**iButton (Dallas Semiconductor 1-Wire):**
- Physical access tokens
- Tools: Flipper Zero, iButton readers

**OSCP Relevance:** NONE (physical security, not network attacks)

---

## Overlap with Existing Plugins

### WiFi Attack Plugin (`wifi_attack.py`)

**Overlap:** <5%

**WiFi plugin covers:**
- 802.11 WiFi attacks (WPA/WPA2/WPS)
- Monitor mode, handshake capture, PMKID attacks
- Evil twin, KARMA/MANA attacks
- Deauthentication, PCAP analysis

**Radio-hacking covers:**
- Physical RF (RFID, BLE, Sub-GHz, LoRa)
- Different frequency bands (125kHz, 13.56MHz, 315/433MHz, 868MHz)
- Hardware-dependent attacks (Flipper Zero, Proxmark3, SDR)

**Conclusion:** Minimal overlap - WiFi is network-layer 802.11, radio-hacking is physical-layer RF.

---

## OSCP Relevance Assessment

### Why Radio-Hacking is NOT OSCP Relevant

1. **Hardware Dependency**
   - Requires: Flipper Zero ($169), Proxmark3 ($300+), HackRF One ($300+), SDR dongles
   - OSCP exam: No physical access, no RF hardware allowed
   - OSCP labs: Network-only access (VPN connection)

2. **Physical Proximity Required**
   - RFID/NFC: <15cm range
   - BLE: <10 meters
   - Sub-GHz: <50 meters (line-of-sight)
   - OSCP: Remote network access only

3. **Scope Mismatch**
   - Radio-hacking: Physical access control (doors, vehicles, smart cards)
   - OSCP: Network pentesting (web apps, Active Directory, Linux/Windows privilege escalation)

4. **Tool Availability**
   - Radio tools: NOT pre-installed on Kali Linux (require firmware flashing, drivers)
   - OSCP tools: Standard Kali tools (nmap, gobuster, metasploit, etc.)

5. **Skill Domain**
   - Radio-hacking: RF engineering, signal processing, hardware exploitation
   - OSCP: Network enumeration, web exploitation, privilege escalation

---

## Recommendations

### For OSCP Preparation
**SKIP radio-hacking content entirely.**

Focus on:
- Network services enumeration (SMB, HTTP, FTP, SSH, SQL)
- Web application attacks (SQLi, XSS, file upload, LFI/RFI)
- Active Directory attacks (Kerberoasting, AS-REP roasting, DCSync)
- Linux/Windows privilege escalation
- Buffer overflow exploitation

### For Physical Pentesting / Red Team
Radio-hacking content is valuable for:
- Physical penetration testing engagements
- Red team operations (badge cloning, vehicle access)
- IoT/embedded security research
- Hardware security assessments

**Consider separate track:** "CRACK Physical" for RF/hardware attacks (future expansion, not OSCP-focused).

---

## Decision Summary

| Criteria | Assessment |
|----------|------------|
| **OSCP Relevance** | VERY LOW (0/10) |
| **Overlap with WiFi Plugin** | <5% |
| **Hardware Requirements** | HIGH (Flipper Zero, Proxmark3, SDR) |
| **Physical Access Required** | YES |
| **Exam Applicability** | NONE |
| **Plugin Priority** | SKIP |

**Final Action:** NO PLUGIN CREATED. Source files will be deleted from TODO directory.

---

## Files to Delete

```bash
# Main radio-hacking directory
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/README.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/pentesting-rfid.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/pentesting-ble-bluetooth-low-energy.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/sub-ghz-rf.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/low-power-wide-area-network.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/fissure-the-rf-framework.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/proxmark-3.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/infrared.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/ibutton.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/maxiprox-mobile-cloner.md

# Flipper Zero subdirectory
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/flipper-zero/README.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/flipper-zero/fz-125khz-rfid.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/flipper-zero/fz-nfc.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/flipper-zero/fz-sub-ghz.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/flipper-zero/fz-infrared.md
/home/kali/OSCP/crack/.references/hacktricks/src/todo/radio-hacking/flipper-zero/fz-ibutton.md

# Total: 16 files (~1,131 lines)
```

**Deletion Status:** Pending (will execute after report generation)

---

## Alternative Use Cases (Non-OSCP)

If CRACK expands beyond OSCP in the future, radio-hacking content could support:

1. **Physical Security Track**
   - RFID/NFC cloning workflows
   - Badge access attack chains
   - BLE device enumeration

2. **IoT Security Track**
   - LoRaWAN network attacks
   - Smart home device exploitation
   - RF jamming/replay detection

3. **Red Team Operations Track**
   - Vehicle access methods
   - Physical reconnaissance
   - Covert entry techniques

**Current Priority:** NONE (maintain OSCP focus)

---

## Mining Metadata

- **Agent:** Phase 3 Agent 10
- **Source:** HackTricks TODO directory (`radio-hacking/`)
- **Lines Analyzed:** 1,131
- **Files Analyzed:** 16
- **Time Spent:** ~15 minutes
- **Decision:** SKIP (OSCP:VERY_LOW relevance)
- **Plugin Created:** NO
- **Files Deleted:** Pending

---

## References

- HackTricks Radio Hacking: https://book.hacktricks.xyz/todo/radio-hacking/
- Flipper Zero Docs: https://docs.flipper.net/
- Proxmark3 RRG: https://github.com/RfidResearchGroup/proxmark3
- FISSURE Framework: https://github.com/ainfosec/FISSURE
- LoRaWAN Security: https://github.com/IOActive/laf
- Sniffle BLE Sniffer: https://github.com/nccgroup/Sniffle

---

**Report Generated:** 2025-10-07
**Status:** COMPLETE - Radio-hacking content assessed as NOT OSCP-relevant. No plugin created.
