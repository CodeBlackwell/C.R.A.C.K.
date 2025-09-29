# OSCP Module 10: SQL Theory and Databases - Lab Exercises

## Table of Contents
1. [Overview](#overview)
2. [MySQL Enumeration - VM #1](#mysql-enumeration---vm-1)
3. [MSSQL Enumeration - VM #2](#mssql-enumeration---vm-2)
4. [MySQL Flag Retrieval - VM #3](#mysql-flag-retrieval---vm-3)
5. [Key Commands Reference](#key-commands-reference)
6. [OSCP Exam Tips](#oscp-exam-tips)

---

## Overview

This documentation covers SQL database enumeration techniques for both MySQL and Microsoft SQL Server (MSSQL), demonstrating essential skills for the OSCP exam including remote database connections, enumeration, and data extraction.

**Lab Targets:**
- **192.168.229.16** - MySQL Server (VM #1 and VM #3)
- **192.168.229.18** - MSSQL Server (VM #2)

**Key Learning Objectives:**
- Remote database connection techniques
- Database enumeration methodology
- User privilege inspection
- Data extraction from tables
- Authentication mechanism identification

---

## MySQL Enumeration - VM #1

### Target: 192.168.229.16
**Objective**: Enumerate MySQL database and identify the authentication plugin for user `offsec`

### Connection Method
```bash
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl
# Purpose: Connect to remote MySQL instance
# -u root: Username
# -p'root': Password (no space after -p)
# -h: Target host IP
# -P 3306: MySQL port (default)
# --skip-ssl: Skip SSL verification for lab environment
```

### Enumeration Commands

#### 1. Version Discovery
```bash
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl -e "SELECT version();"
# Result: 8.0.21
```

#### 2. Current User Context
```bash
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl -e "SELECT system_user();"
# Result: root@192.168.45.243 (shows we're connected as root from our IP)
```

#### 3. Database Listing
```bash
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl -e "SHOW DATABASES;"
# Databases found:
# - information_schema
# - mysql (system database)
# - performance_schema
# - sys
# - test (custom database)
```

#### 4. User Enumeration
```bash
# Query all fields for offsec user with vertical format for readability
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl -e "SELECT * FROM mysql.user WHERE user = 'offsec'\G"
```

### Key Findings
- **User**: offsec
- **Host**: localhost
- **Plugin**: `caching_sha2_password` ✅ (Answer)
- **Authentication String**: `$A$005$?qvorPp8#lTKH1j54xuw4C5VsXe5IAa1cFUYdQMiBxQVEzZG9XWd/e6`
- **Password Last Changed**: 2022-05-06 11:47:11

**Note**: The `caching_sha2_password` plugin is MySQL 8.0's default authentication method, using SHA-256 hashing with caching for improved security over the legacy `mysql_native_password`.

---

## MSSQL Enumeration - VM #2

### Target: 192.168.229.18
**Objective**: Enumerate MSSQL master database and identify the first user in sysusers table

### Connection Method
```bash
impacket-mssqlclient Administrator:Lab123@192.168.229.18 -windows-auth
# Purpose: Connect to MSSQL using Windows authentication
# Administrator:Lab123: Windows credentials
# -windows-auth: Force NTLM authentication
```

### Enumeration Commands

#### 1. Version Discovery
```sql
SELECT @@version;
-- Result: Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
-- Windows Server 2022 Standard
```

#### 2. Database Listing
```sql
SELECT name FROM sys.databases;
-- Databases found:
-- - master (system)
-- - tempdb (system)
-- - model (system)
-- - msdb (system)
-- - offsec (custom)
```

#### 3. Sysusers Table Enumeration
```sql
-- Query all users in master database
SELECT * FROM master.dbo.sysusers ORDER BY uid;

-- Get first user by UID
SELECT name FROM master.dbo.sysusers WHERE uid = 0;
```

### Key Findings
The sysusers table entries ordered by uid:
- **uid 0**: `public` ✅ (Answer - First user)
- **uid 1**: dbo
- **uid 2**: guest
- **uid 3**: INFORMATION_SCHEMA
- **uid 4**: sys

**Note**: The `public` role is a special database role that every user automatically belongs to in SQL Server. It has uid=0, making it the first entry in the sysusers table.

### Common MSSQL Enumeration Queries
```sql
-- Current database
SELECT DB_NAME();

-- Current user
SELECT USER_NAME();
SELECT SYSTEM_USER;

-- List all tables in current database
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;

-- List all logins (requires proper permissions)
SELECT name FROM master.sys.sql_logins;
```

---

## MySQL Flag Retrieval - VM #3

### Target: 192.168.229.16
**Objective**: Find and retrieve the flag from the users table

### Enumeration Process

#### 1. Database Discovery
```bash
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl -e "SHOW DATABASES;"
# Found: test database (custom, worth investigating)
```

#### 2. Table Discovery
```bash
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl -e "USE test; SHOW TABLES;"
# Found: users table
```

#### 3. Data Extraction
```bash
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl -e "SELECT * FROM test.users;"
```

### Results
| id | username |
|----|----------|
| 1  | yoshi |
| 2  | luigi |
| 3  | wario |
| 4  | **OS{c55489128e35a5cdbc0fd722ba63338f}** |
| 5  | mario |

**Flag Found**: `OS{c55489128e35a5cdbc0fd722ba63338f}`

### Alternative Query Methods
```bash
# Get specific columns
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl -e "SELECT username FROM test.users WHERE username LIKE 'OS{%';"

# Get table structure
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl -e "DESCRIBE test.users;"

# Count records
mysql -u root -p'root' -h 192.168.229.16 -P 3306 --skip-ssl -e "SELECT COUNT(*) FROM test.users;"
```

---

## Key Commands Reference

### MySQL Commands
```bash
# Basic connection
mysql -u <user> -p'<pass>' -h <host> -P <port>

# With SSL issues
mysql -u <user> -p'<pass>' -h <host> -P <port> --skip-ssl

# Execute inline query
mysql -u <user> -p'<pass>' -h <host> -e "QUERY;"

# Common enumeration queries
SHOW DATABASES;                          # List all databases
USE <database>;                          # Select database
SHOW TABLES;                             # List tables in current database
DESCRIBE <table>;                        # Show table structure
SELECT * FROM <table>;                   # Dump table contents
SELECT user,host FROM mysql.user;       # List all users
SELECT @@version;                        # Get MySQL version
SELECT database();                       # Current database name
SELECT user();                          # Current user
```

### MSSQL Commands
```bash
# Impacket connection
impacket-mssqlclient <user>:<pass>@<host> -windows-auth

# Common MSSQL queries
SELECT @@version;                        # SQL Server version
SELECT name FROM sys.databases;          # List databases
SELECT DB_NAME();                        # Current database
SELECT * FROM <db>.INFORMATION_SCHEMA.TABLES;  # List tables
SELECT * FROM <db>.dbo.<table>;         # Query table
SELECT name FROM master.dbo.sysusers;   # List users
SELECT name FROM master.sys.sql_logins; # List SQL logins
```

---

## OSCP Exam Tips

### Database Enumeration Strategy

1. **Initial Reconnaissance**
   - Always check version first (potential CVEs)
   - Identify authentication mechanisms
   - List all databases (focus on non-system DBs)

2. **Systematic Enumeration**
   ```
   Databases → Tables → Columns → Data
   ```

3. **Priority Targets**
   - User tables (credentials)
   - Configuration tables (settings, paths)
   - Custom application tables (business data)
   - Backup tables (often contain sensitive data)

### Common Pitfalls & Solutions

#### MySQL Issues
- **SSL/TLS Errors**: Use `--skip-ssl` in lab environments
- **Access Denied**: Check port, credentials, and host permissions
- **Empty Results**: Verify database and table names are correct

#### MSSQL Issues
- **Authentication Failed**: Ensure `-windows-auth` flag is used
- **Query Syntax**: MSSQL uses different syntax than MySQL
  - MySQL: `SHOW DATABASES;`
  - MSSQL: `SELECT name FROM sys.databases;`

### Quick Win Queries

#### For MySQL
```bash
# Check for password hashes
mysql -u root -p'root' -h <IP> --skip-ssl -e "SELECT user,authentication_string FROM mysql.user;"

# Search for flags/passwords in all tables (if you have privileges)
mysql -u root -p'root' -h <IP> --skip-ssl -e "SELECT TABLE_SCHEMA,TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys');"
```

#### For MSSQL
```sql
-- Check for linked servers (lateral movement)
SELECT * FROM master.sys.servers;

-- List all user tables in all databases
SELECT '[' + DB_NAME(database_id) + '].[' + SCHEMA_NAME(schema_id) + '].[' + name + ']'
FROM sys.tables
WHERE type = 'U';

-- Search for interesting column names
SELECT TABLE_NAME, COLUMN_NAME
FROM INFORMATION_SCHEMA.COLUMNS
WHERE COLUMN_NAME LIKE '%pass%'
   OR COLUMN_NAME LIKE '%user%'
   OR COLUMN_NAME LIKE '%flag%';
```

### Authentication Methods

#### MySQL Authentication Plugins
- `caching_sha2_password` - Default in MySQL 8.0+ (SHA-256)
- `mysql_native_password` - Legacy method (SHA-1)
- `auth_socket` - Unix socket authentication
- `sha256_password` - SHA-256 without caching

#### MSSQL Authentication Modes
- **Windows Authentication** - Uses domain credentials
- **SQL Server Authentication** - Database-specific credentials
- **Mixed Mode** - Supports both methods

### Documentation During Exam
Always document:
1. Connection strings that worked
2. Database and table names discovered
3. Credentials found
4. Interesting data locations
5. Failed attempts (saves time on retries)

---

## Summary

This module covered essential SQL database enumeration techniques for both MySQL and MSSQL systems. Key takeaways:

1. **MySQL**: Default port 3306, use `--skip-ssl` for lab environments, `caching_sha2_password` is the modern auth plugin
2. **MSSQL**: Use Impacket for Linux-to-Windows connections, remember `-windows-auth` flag, different syntax from MySQL
3. **Enumeration Flow**: Version → Databases → Tables → Data
4. **Flag Location**: Custom databases and tables often contain flags/credentials

Remember: In the OSCP exam, database services might be accessible after initial compromise or through default/weak credentials. Always enumerate thoroughly!

---

*Last Updated: Module 10 SQL Theory and Databases Exercises*