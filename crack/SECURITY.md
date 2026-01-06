# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

CRACK is a security tool, so we take security issues seriously.

### For Security Vulnerabilities

**Do not open public GitHub issues for security vulnerabilities.**

Instead:
1. Email the maintainer directly (see repository for contact)
2. Include "CRACK Security" in the subject line
3. Provide detailed reproduction steps
4. Allow reasonable time for response (typically 48-72 hours)

### What to Report

- Authentication/authorization bypasses
- Arbitrary code execution vulnerabilities
- Credential exposure risks
- Injection vulnerabilities in the tool itself

### What Not to Report

- Security "issues" that are intentional features (e.g., executing user-provided commands)
- Theoretical attacks without proof of concept
- Issues in dependencies (report upstream instead)

## Security Considerations

### Credential Handling

CRACK handles sensitive credentials. Best practices:

1. **Never commit credentials** - Use environment variables
2. **Set NEO4J_PASSWORD** via environment, not config files
3. **Review `.gitignore`** - Ensure sensitive files are excluded
4. **Use `.env` files** - Copy from `.env.example`, never commit

### Shell Command Execution

Some tools execute shell commands. Users should:

1. Review commands before execution
2. Use in isolated environments when testing
3. Never run against systems without authorization

### BloodHound Data

BloodHound data contains sensitive AD information:

1. Store data securely
2. Don't commit BloodHound ZIPs to version control
3. Clear data after engagements

## Responsible Use

This tool is intended for:
- OSCP exam preparation
- Authorized penetration testing
- Security research in controlled environments

Unauthorized use against systems you don't own or have permission to test is illegal.
