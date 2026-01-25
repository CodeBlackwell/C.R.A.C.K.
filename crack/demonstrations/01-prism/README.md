# Video 01: PRISM (Credential Parser)

**Duration:** 8-12 min | **Focus:** Post-exploitation credential parsing

## Sample Files Inventory

| File | Parser | Contents | Demo Value |
|------|--------|----------|------------|
| `mimikatz_logonpasswords.txt` | mimikatz | 4 sessions: machine acct, admin (cleartext!), jsmith (credman), LOCAL SERVICE | Shows cleartext extraction |
| `secretsdump_output.txt` | secretsdump | SAM hashes, DCC2 cached, LSA secrets, NTDS dump, Kerberos keys | Domain compromise scenario |
| `kerberoast_getuserspns.txt` | kerberoast | 3 service accounts with TGS hashes | Hashcat-ready output |
| `kerberoast_asrep.txt` | kerberoast | 3 AS-REP roastable users | Pre-auth disabled accounts |
| `Groups.xml` | gpp | 2 local admin accounts with cpassword | Auto-decryption demo! |
| `Services.xml` | gpp | 2 service accounts with cpassword | Service account passwords |
| `ldap_dump.txt` | ldap | Domain info, users, computers, groups | Kerberoastable/AS-REP user detection |
| `nmap_scan.nmap` | nmap | 4 hosts: DC, workstation, webserver, SSH host | Network recon to parsed hosts |
| `smbmap_enum.txt` | smbmap | 14 shares, 4 high-value files (SAM.bak, passwords.txt) | Share enumeration with attack ideas |

## Demo Command Sequence

```bash
cd /home/kali/Desktop/KaliBackup/OSCP/crack/video-production/01-prism

# === CREDENTIAL PARSERS ===

# 1. Mimikatz - Show cleartext password extraction
crack prism samples/mimikatz_logonpasswords.txt
# Highlight: Yellow tables = cleartext passwords (SuperSecretP@ss!, MailP@ssw0rd!)

# 2. Secretsdump - Domain compromise data
crack prism samples/secretsdump_output.txt
# Highlight: SAM hashes, DCC2, NTDS dump, service passwords

# 3. GPP Auto-Decryption (THE WOW MOMENT)
crack prism samples/Groups.xml
# Highlight: cpassword automatically decrypted to plaintext!

# 4. GPP Services
crack prism samples/Services.xml
# Highlight: Service account credentials exposed

# 5. Kerberoast - Hashcat-ready output
crack prism samples/kerberoast_getuserspns.txt
# Highlight: $krb5tgs$ hashes ready for hashcat mode 13100

# 6. AS-REP Roast
crack prism samples/kerberoast_asrep.txt
# Highlight: $krb5asrep$ hashes ready for hashcat mode 18200

# === RECON PARSERS ===

# 7. Nmap - Network reconnaissance
crack prism samples/nmap_scan.nmap
# Highlight: Domain controllers detected, port summary, host inventory

# 8. SMBMap - Share enumeration with attack ideas
crack prism samples/smbmap_enum.txt
# Highlight: High-value files detected (SAM.bak, passwords.txt), writable shares

# === LDAP PARSER ===

# 9. LDAP Enumeration
crack prism samples/ldap_dump.txt
# Highlight: Identifies Kerberoastable users, AS-REP roastable users, password in description!

# === OUTPUT FORMATS ===

# 10. JSON Output for Piping
crack prism samples/mimikatz_logonpasswords.txt -f json | jq '.credentials[] | select(.high_value==true)'

# 11. Markdown for Reporting
crack prism samples/nmap_scan.nmap -f markdown

# 12. Stats Only (Quick Overview)
crack prism samples/smbmap_enum.txt --stats-only
```

## Key Demo Moments

### Moment 1: The Wall of Text Problem (30 sec)
```bash
cat samples/mimikatz_logonpasswords.txt | head -50
# "Where are the actual passwords in this mess?"
```

### Moment 2: PRISM Magic (1 min)
```bash
crack prism samples/mimikatz_logonpasswords.txt
# Clean, color-coded tables appear
# Yellow = HIGH VALUE (cleartext)
# Blue = NTLM hashes
```

### Moment 3: GPP Auto-Decrypt (WOW moment)
```bash
crack prism samples/Groups.xml
# Show: cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
# Becomes: Password123! (decrypted automatically)
```

### Moment 4: Nmap Network Intelligence
```bash
crack prism samples/nmap_scan.nmap
# Shows: Domain controllers highlighted, port summary across all hosts
# "PRISM doesn't just parse credentials - it understands your network"
```

### Moment 5: SMBMap Attack Surface
```bash
crack prism samples/smbmap_enum.txt
# Shows: High-value files (SAM.bak, passwords.txt), writable shares with attack ideas
# "Every share is an opportunity - PRISM shows you which ones matter"
```

### Moment 6: Multi-Format Support
```bash
# Show all parsers work with same interface
crack prism samples/mimikatz_logonpasswords.txt --stats-only
crack prism samples/nmap_scan.nmap --stats-only
crack prism samples/smbmap_enum.txt --stats-only
crack prism samples/ldap_dump.txt --stats-only
```

## Scripts

Place in `scripts/`:

- [ ] `talking_points.md` - Section-by-section narration
- [ ] `commands.sh` - Exact commands to run in order

## Assets

Place in `assets/`:

- [ ] Thumbnail image
- [ ] Before/after comparison graphic

## Key Talking Points

1. **The Problem**: Raw tool output is hard to parse visually
2. **The Solution**: PRISM auto-detects format and extracts credentials
3. **8 Parsers**: mimikatz, secretsdump, gpp, kerberoast, ldap, nmap, smbmap, responder
4. **Auto-Detection**: Just point at a file, PRISM figures out the format
5. **GPP Decryption**: Microsoft published the AES key - PRISM uses it automatically
6. **Neo4j Integration**: Credentials stored in graph for correlation
7. **Output Formats**: Table (default), JSON (piping), Markdown (reporting)

## Sample Credential Highlights

### From mimikatz_logonpasswords.txt:
- `administrator:CORP` - Cleartext: `SuperSecretP@ss!`
- `jsmith@corp.local:mail.corp.local` - Credman: `MailP@ssw0rd!`
- `DESKTOP-ABC123$:CORP` - Machine account NTLM

### From secretsdump_output.txt:
- Domain admin: `32ed87bdb5fdc5e9cba88547376818d4`
- krbtgt hash (golden ticket material)
- Service passwords in LSA secrets

### From Groups.xml:
- `localadmin` - GPP decrypted password
- `backup_admin` - GPP decrypted password

### From ldap_dump.txt:
- `sqlsvc` - Kerberoastable (has SPN)
- `nopreauth` - AS-REP roastable (UAC 4260352)
- `jsmith` - Password hint in description field!

### From nmap_scan.nmap:
- DC01 (192.168.1.1) - Domain Controller with Kerberos, LDAP, SMB
- webserver01 (192.168.1.50) - Apache + MySQL (potential SQLi)
- Port summary across 4 hosts

### From smbmap_enum.txt:
- `IT_Share` - Writable, contains passwords.txt
- `Backups` - Contains SAM.bak, SYSTEM.bak (hash extraction!)
- 4 high-value files auto-detected with attack rationale

## Thumbnail Concept

Split screen:
- Left: Messy raw mimikatz output (gray, overwhelming)
- Right: Clean PRISM table output (colorized, organized)
- Text overlay: "Parse Everything"
