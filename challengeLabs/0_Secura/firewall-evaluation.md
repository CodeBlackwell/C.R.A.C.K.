# Firewall Evaluation Cheatsheet

## Windows Firewall

### Status Check
```powershell
# All profiles status
netsh advfirewall show allprofiles state

# Detailed profile info
netsh advfirewall show allprofiles
```

### List Rules
```powershell
# All rules
netsh advfirewall firewall show rule name=all

# Inbound only
netsh advfirewall firewall show rule name=all dir=in

# Outbound only
netsh advfirewall firewall show rule name=all dir=out

# Enabled + Allow only
netsh advfirewall firewall show rule name=all dir=in enabled=yes action=allow
```

### PowerShell Methods
```powershell
# All rules (structured)
Get-NetFirewallRule | Select Name,Enabled,Direction,Action

# Inbound Allow rules with port info
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
  Get-NetFirewallPortFilter | Select InstanceID,Protocol,LocalPort

# Rules for specific port
Get-NetFirewallRule | Get-NetFirewallPortFilter | Where LocalPort -eq 445
```

### Connectivity Testing
```powershell
Test-NetConnection <TARGET> -Port <PORT>
Test-NetConnection 192.168.1.10 -Port 445,5985,3389
```

---

## Linux iptables

### View Rules
```bash
# All rules with line numbers
iptables -L -n -v --line-numbers

# NAT table
iptables -t nat -L -n -v

# Specific chain
iptables -L INPUT -n -v
iptables -L OUTPUT -n -v
iptables -L FORWARD -n -v
```

### Save/Export
```bash
iptables-save > rules.txt
```

---

## Linux nftables
```bash
nft list ruleset
nft list table inet filter
```

---

## Rule Components to Analyze

| Field | Question |
|-------|----------|
| Direction | Inbound (attack surface) or Outbound (exfil)? |
| Action | Allow or Block? |
| Protocol | TCP/UDP/ICMP? |
| LocalPort | What's exposed? |
| RemoteIP | Who can connect? Any = open |
| Profile | Domain/Private/Public? |

---

## Pentest Analysis Checklist

- [ ] Is outbound filtered? (affects reverse shells)
- [ ] What inbound ports are open? (attack surface)
- [ ] Are 445/5985/3389 reachable between hosts? (lateral movement)
- [ ] Is ICMP allowed? (host discovery)
- [ ] What egress ports work? (80/443 usually allowed)

---

## Common Egress Bypass

If outbound filtered, try:
- Port 80/443 (HTTP/HTTPS)
- Port 53 (DNS)
- Port 25/587 (SMTP)
- ICMP tunneling (if allowed)
