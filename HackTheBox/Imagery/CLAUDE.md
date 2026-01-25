# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Target Overview

- **Machine:** Imagery (HackTheBox)
- **IP:** 10.10.11.88
- **Hostname:** imagery.htb
- **OS:** Ubuntu Linux

## Discovered Services

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 22 | SSH | OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 | Standard SSH, requires creds |
| 8000 | HTTP | Werkzeug 3.1.3 (Python 3.12.7) | Flask/Python web app - "Image Gallery" |

## Current Artifacts

- `nmap.*` - Initial port scan results
- `signed.cookie` - Captured session cookie with JSON payload: `{"displayId":"3ff42c50","isAdmin":false,"isTestuser":false}`

## Attack Surface Notes

### Web Application (Port 8000)
- Python Flask application (Werkzeug)
- Session cookie appears to be signed JSON (Flask itsdangerous style)
- Cookie contains `isAdmin:false` and `isTestuser:false` flags - potential privilege escalation vector
- `displayId` field may be user-controllable or predictable

### Potential Vectors to Investigate
1. **Cookie tampering** - Flask session cookie forgery if secret key is weak/leaked
2. **IDOR** - `displayId` parameter manipulation
3. **Image upload vulnerabilities** - "Image Gallery" suggests file upload functionality
4. **SSTI** - Common in Flask/Jinja2 applications
5. **Path traversal** - Image retrieval endpoints

## Documentation Structure

Create these files as investigation progresses:
- `enumeration.md` - Web enumeration, directory discovery
- `investigation_checklist.md` - Attack vectors being tested
- `failed_attempts.md` - What didn't work
- `vulnerability_research.md` - Flask cookie forgery, relevant CVEs
- `breakthrough.md` - Successful exploitation
- `exploitation.md` - Step-by-step attack chain
- `post_exploitation.md` - Privilege escalation, flags
- `EDUCATIONAL_WRITEUP.md` - Final comprehensive guide

## Useful Commands for This Target

```bash
# Add hostname to /etc/hosts
echo "10.10.11.88 imagery.htb" | sudo tee -a /etc/hosts

# Web enumeration
gobuster dir -u http://imagery.htb:8000 -w /usr/share/wordlists/dirb/common.txt -t 50
feroxbuster -u http://imagery.htb:8000 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Flask cookie decode (base64 + zlib)
flask-unsign --decode --cookie '<cookie_value>'

# Attempt to brute force Flask secret key
flask-unsign --unsign --cookie '<cookie_value>' --wordlist /usr/share/wordlists/rockyou.txt

# Forge admin cookie (if secret found)
flask-unsign --sign --cookie '{"displayId":"3ff42c50","isAdmin":true,"isTestuser":false}' --secret '<SECRET>'
```

## Inherits From

See `/home/kali/Desktop/OSCP/CLAUDE.md` for:
- Interaction rules (EXECUTE vs TEACH)
- Documentation templates
- Command format standards
- Learning methodology
