# Configuration Management

The CRACK Reference System includes a powerful configuration management system that allows you to set commonly used variables once and have them automatically filled in commands.

## Quick Start

### Auto-Configure
Automatically detect and set common variables:
```bash
crack reference --config auto
```
This will detect:
- `LHOST`: Your IP address (from active network interface)
- `INTERFACE`: Your active network interface (prefers VPN interfaces)

### Set Variables
```bash
# Set target IP
crack reference --set TARGET 192.168.45.100

# Set local host (attacker IP)
crack reference --set LHOST 10.10.14.5

# Auto-detect LHOST
crack reference --set LHOST auto

# Set wordlist path
crack reference --set WORDLIST /usr/share/seclists/Discovery/Web-Content/big.txt
```

### View Configuration
```bash
# List all configured variables
crack reference --config list

# Get specific variable
crack reference --get LHOST
```

### Edit Config File
```bash
# Open config in default editor
crack reference --config edit
```

## Configuration File

The configuration is stored in `~/.crack/config.json` and contains:

- **Variables**: Your configured values
- **Sessions**: Named configuration sets (coming soon)
- **Settings**: System preferences

### Default Variables

| Variable | Default Value | Description |
|----------|--------------|-------------|
| `LHOST` | (not set) | Local/attacker IP address |
| `LPORT` | 4444 | Local port for listener |
| `TARGET` | (not set) | Target IP address |
| `TARGET_SUBNET` | (not set) | Target subnet in CIDR |
| `WORDLIST` | /usr/share/wordlists/rockyou.txt | Default wordlist |
| `THREADS` | 10 | Thread count |
| `INTERFACE` | tun0 | Network interface |
| `OUTPUT_DIR` | ./scans | Output directory |

## Auto-Fill Behavior

When using `crack reference --fill <command>` or interactive mode:

1. **Configured values show as defaults**:
   ```
   Enter value for <LHOST> [config: 10.10.14.5]:
   ```

2. **Press Enter to use configured value**:
   - Just press Enter to accept the configured value
   - Type a new value to override for this command only

3. **Example workflow**:
   ```bash
   # Set your common values once
   crack reference --set LHOST 10.10.14.5
   crack reference --set TARGET 192.168.45.100

   # Now commands auto-fill these values
   crack reference --fill bash-reverse-shell
   # LHOST and LPORT are auto-filled

   crack reference --fill nmap-service-scan
   # TARGET is auto-filled
   ```

## Advanced Usage

### Environment Variable Integration

The config system checks environment variables as fallback:
```bash
export LHOST=10.10.14.5
crack reference --fill bash-reverse-shell
# Will use environment variable if not configured
```

### Custom Variables

You can add any custom variable:
```bash
crack reference --set DOMAIN example.local
crack reference --set API_KEY abc123xyz
```

### Clear Configuration

```bash
# Clear all variables (keeps defaults)
crack reference --clear-config

# Edit config.json directly for more control
nano ~/.crack/config.json
```

## Workflow Examples

### OSCP Lab Session
```bash
# Start of session - configure once
crack reference --config auto           # Auto-detect interface and IP
crack reference --set TARGET 192.168.45.100

# Throughout session - values auto-fill
crack reference --fill nmap-quick-scan  # TARGET auto-filled
crack reference --fill bash-reverse-shell # LHOST, LPORT auto-filled
crack reference --fill gobuster-dir     # Can still override per-command
```

### CTF/Competition
```bash
# Set competition-specific values
crack reference --set LHOST 10.10.14.5
crack reference --set WORDLIST /opt/custom-wordlist.txt
crack reference --set THREADS 50

# All commands use these values
crack reference --fill hydra-ssh        # Uses configured threads
crack reference --fill gobuster-dir     # Uses custom wordlist
```

### Multiple Targets
```bash
# Target 1
crack reference --set TARGET 192.168.1.100
crack reference --fill nmap-service-scan

# Target 2
crack reference --set TARGET 192.168.1.101
crack reference --fill nmap-service-scan
```

## Integration with Commands

All placeholder-based commands benefit from configuration:

- **Network**: `<TARGET>`, `<TARGET_SUBNET>`
- **Reverse Shells**: `<LHOST>`, `<LPORT>`
- **Web Testing**: `<URL>`, `<WORDLIST>`
- **Performance**: `<THREADS>`, `<RATE>`, `<DELAY>`
- **Output**: `<OUTPUT>`, `<OUTPUT_DIR>`

## Best Practices

1. **Run auto-config at session start**:
   ```bash
   crack reference --config auto
   ```

2. **Set TARGET when focusing on a host**:
   ```bash
   crack reference --set TARGET 192.168.45.100
   ```

3. **Use environment for sensitive values**:
   ```bash
   export API_KEY=secret123
   ```

4. **Keep wordlists updated**:
   ```bash
   crack reference --set WORDLIST /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
   ```

5. **Adjust threads based on network**:
   ```bash
   # Lab environment - aggressive
   crack reference --set THREADS 50

   # Production - careful
   crack reference --set THREADS 5
   ```

## Troubleshooting

### Config not loading
- Check file permissions: `ls -la ~/.crack/config.json`
- Validate JSON: `python3 -m json.tool ~/.crack/config.json`

### Auto-detect fails
- Check network interfaces: `ip addr`
- Manually set: `crack reference --set LHOST <your-ip>`

### Values not filling
- Verify config: `crack reference --config list`
- Check placeholder names match exactly (case-sensitive)

---

*Part of the [CRACK Reference System](./index.md)*