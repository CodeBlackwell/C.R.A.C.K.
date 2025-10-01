# Enumeration Progress Log - Chapter 10 Capstone 2
**Date**: 2025-10-01
**Target**: 192.168.145.48
**Session Start**: Initial reconnaissance

---

## Phase 1: Initial Port Scan Results

### Open Ports Discovered:
- **Port 22**: OpenSSH 7.9p1 Debian 10+deb10u2
- **Port 80**: Nginx 1.14.2 (PHP application)
- **Port 3306**: MySQL (remote access blocked)
- **Port 33060**: MySQL X Protocol

### Key Technologies:
- **Web Server**: Nginx 1.14.2
- **Backend**: PHP
- **Database**: MySQL
- **Framework**: Bootstrap
- **jQuery**: 3.4.1
- **Email Found**: lab@forestsave.lab

---

## Phase 2: Web Application Discovery

### Directories Found:
```
/css/       (301 redirect)
/images/    (301 redirect)
/js/        (301 redirect)
```

### PHP Files Identified:
```
/index.php   (200 OK) - Main page with subscription form
/about.php   (200 OK) - About page
/donate.php  (200 OK) - Donation page
```

### Gobuster Results:
- No backup files found (.bak, .old, .zip, .sql)
- No config files exposed
- Limited directory structure suggests small application

---

## Phase 3: Form Discovery

### Forms Found on index.php:
1. **Search Form**
   - Type: GET
   - Input: `type="search"` (no name attribute)
   - No parameter name identified

2. **Email Subscription Form** ⚠️ **VULNERABLE**
   - Method: POST
   - Parameter: `mail-list`
   - Input type: email
   - Location: Footer section

3. **Empty Action Form**
   - Near Google Maps reference
   - Purpose unclear

---

## Phase 4: MySQL Remote Access Test

### Attempt:
```bash
mysql -h 192.168.145.48 -u root
```

### Result:
```
ERROR 2002 (HY000): TLS handshake incomplete
ERROR 1130: Host '192.168.45.179' is not allowed to connect
```

### Analysis:
- MySQL is running and responding
- Configured to reject remote connections
- Only localhost access permitted
- **Conclusion**: Need web-based attack vector

---

## Phase 5: CVE Research

### CVE-2019-20372 (Nginx HTTP Request Smuggling)
- **Affects**: Nginx before 1.17.7
- **Target Version**: 1.14.2 (vulnerable)
- **Requirements**: Specific error_page configuration
- **Likelihood**: Low - requires specific setup
- **Decision**: Deprioritized in favor of SQLi

---

## Phase 6: SQL Injection Discovery 🎯

### Discovery Method:
```bash
curl -X POST http://192.168.145.48/index.php -d "mail-list=test@test.com'"
```

### MySQL Error Exposed:
```
You have an error in your SQL syntax; check the manual that corresponds
to your MySQL server version for the right syntax to use near ''test@test.com'''
```

### Vulnerability Confirmed:
- **Type**: Error-based SQL Injection
- **Parameter**: mail-list (POST)
- **Page**: index.php
- **Error Display**: Full MySQL errors shown
- **Input Validation**: None
- **Likely Query**: INSERT INTO table VALUES ('$input')

---

## Current Status

### Completed:
✅ Full port enumeration
✅ Web directory discovery
✅ Form parameter identification
✅ MySQL remote access testing
✅ CVE research for Nginx
✅ SQL injection vulnerability confirmed

### In Progress:
🔄 SQL injection exploitation
🔄 Column count determination
🔄 Database enumeration

### Not Started:
⏳ Credential extraction
⏳ File system access via SQLi
⏳ Shell upload attempts
⏳ Privilege escalation

---

## Key Findings Summary

1. **Primary Attack Vector**: SQL Injection in mail-list parameter
2. **Attack Surface**: Limited to 3 PHP pages
3. **Security Misconfigurations**:
   - No input sanitization
   - MySQL errors displayed
   - Verbose error messages

---

## Time Invested
- Initial enumeration: 15 minutes
- Web discovery: 10 minutes
- SQLi discovery: 5 minutes
- Total elapsed: ~30 minutes

---

## Next Actions Required
1. Determine exact column count
2. Extract database name
3. Enumerate tables
4. Find user credentials
5. Attempt file read/write
6. Gain shell access