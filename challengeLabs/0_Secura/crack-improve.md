# Crack Tool Improvement Notes

## bloodtrail

### Issue: --local-auth flag not accounted for

When spraying credentials found via Mimikatz credential manager, bloodtrail should attempt both domain and local authentication.

**Problem encountered:**
- Credential `apache:New2Era4.!` found in credman with domain `era.secura.local`
- Domain auth failed: `crackmapexec winrm 192.168.179.96 -u apache -p 'New2Era4.!'` → FAILED
- Local auth succeeded: `crackmapexec winrm 192.168.179.96 -u apache -p 'New2Era4.!' --local-auth` → Pwn3d!

**Recommendation:**
When spraying credentials, bloodtrail should:
1. Try domain authentication first (default behavior)
2. If domain auth fails, automatically retry with `--local-auth` flag
3. Parse credman domain hints (e.g., `era.secura.local` suggests local account on host `era`)

**Detection logic:**
- If credman domain contains hostname (not domain FQDN), prioritize `--local-auth`
- If credman domain format is `hostname.domain.tld`, extract hostname and try local auth against that host
