# 🎯 C.R.A.C.K. - Comprehensive Recon & Attack Creation Kit

**C.R.A.C.K.**
**C**omprehensive **R**econ & **A**ttack **C**reation **K**it

A professional penetration testing toolkit designed for OSCP preparation and web application security testing.

## Documentation Map

**You are here:** Project Overview - Installation, quick start, and tool descriptions

**Quick Links:**
- 📚 [**Master Documentation Index**](docs/master-index.md) - Complete documentation catalog (302 files)
- 📋 [**Quick Navigation**](docs/master-index.md#quick-navigation) - One-page command reference

**Related Documentation:**
- [Architecture & Development](CLAUDE.md) - Development patterns, CLI architecture, testing philosophy
- [Track Module](track/README.md) - Enumeration system with 235+ service plugins
- [Reference System](reference/README.md) - Command lookup with 70+ OSCP commands
- [Testing Guide](tests/README.md) - Test suite documentation and patterns

## Features

### 🎯 Scan Analyzer (`crack scan-analyze`)
- Parse nmap output to identify attack vectors
- Classify ports as standard vs unusual for target OS
- Priority scoring based on multiple factors
- Extract unique banner terms for searchsploit
- Generate specific enumeration commands
- Educational output explaining methodology

### 🔍 HTML Enumeration (`crack html-enum`)
- Extract and analyze HTML forms with all input fields
- Discover hidden comments in HTML and JavaScript
- Find all endpoints (links, AJAX calls, API endpoints)
- Recursive crawling with depth control
- Identify interesting patterns (emails, IPs, sensitive paths)
- Smart categorization of findings (admin panels, upload endpoints, API routes)

### 🎯 Parameter Discovery (`crack param-discover`)
- Intelligently fuzz for hidden GET/POST parameters
- Context-aware payload selection based on parameter names
- Confidence scoring for discovered parameters
- Quick mode for high-value parameters only
- Batch processing for multiple URLs
- Integration with HTML enumeration output

### 💉 SQL Injection Scanner (`crack sqli-scan`)
- Multiple SQLi detection techniques (error-based, boolean, time-based, union)
- Smart payload selection based on database context
- Educational mode with detailed explanations
- Support for both GET and POST methods
- Comprehensive reporting with exploitation guidance
- Manual testing instructions for OSCP exam scenarios

## Installation

### Quick Install (Development Mode)
```bash
# Clone or navigate to the OSCP directory
cd /home/kali/OSCP

# Install in editable mode (allows code modifications)
pip install -e .

# Or install normally
pip install .
```

### Install Dependencies Only
```bash
pip install -r requirements.txt
```

## Usage

### Main Command Interface
```bash
# Show help and available tools
crack --help

# Show version
crack --version

# Suppress banner
crack --no-banner <tool> <args>
```

### Scan Analyzer
```bash
# Analyze nmap scan output
crack scan-analyze scan.nmap

# Specify OS type (auto-detects by default)
crack scan-analyze scan.xml --os windows

# Works with different formats
crack scan-analyze scan.gnmap

# Direct from nmap
nmap -sV -sC target -oA scan && crack scan-analyze scan.nmap
```

### HTML Enumeration
```bash
# Basic enumeration
crack html-enum http://target.com

# Recursive crawling with depth control
crack html-enum http://target.com -r -d 3

# From saved HTML file
crack html-enum -f saved_page.html

# With authentication
crack html-enum http://target.com -c "session=abc123"

# Full output (no truncation)
crack html-enum http://target.com --full

# Direct shortcut
crack-html http://target.com
```

### Parameter Discovery
```bash
# Discover GET parameters
crack param-discover http://target.com/page.php

# Test POST method
crack param-discover http://target.com/form.php -m POST

# Quick scan (high-value params only)
crack param-discover http://target.com/*.php -q

# Custom wordlist
crack param-discover http://target.com -w custom_params.txt

# Batch processing
crack param-discover http://target.com/page1.php http://target.com/page2.php

# Direct shortcut
crack-param http://target.com/page.php

# Pipeline from HTML enumeration
crack html-enum http://target.com -r | crack param-discover
```

### SQL Injection Scanner
```bash
# Basic scan
crack sqli-scan http://target.com/page.php?id=1

# Test specific parameter
crack sqli-scan http://target.com/page.php?id=1 -p id

# POST method with data
crack sqli-scan http://target.com/login.php -m POST -d "user=admin&pass=test"

# Specific technique
crack sqli-scan http://target.com/page.php?id=1 -t union

# Quick scan mode
crack sqli-scan http://target.com/page.php?id=1 -q

# Direct shortcut
crack-sqli http://target.com/page.php?id=1
```

## Tool Chaining

The tools are designed to work together in a pipeline:

```bash
# Full reconnaissance workflow
# 1. Enumerate all pages
crack html-enum http://target.com -r > pages.txt

# 2. Discover parameters on found pages
cat pages.txt | crack param-discover -m GET

# 3. Test discovered parameters for SQLi
crack param-discover http://target.com/*.php | \
  grep "High Confidence" | \
  xargs -I {} crack sqli-scan {}
```

## OSCP Exam Tips

### Manual Testing Fallbacks
All tools include manual testing instructions in their output for scenarios where automation is restricted:
- SQL injection manual payloads and techniques
- Parameter discovery without tools
- HTML analysis using browser developer tools

### Time Management
- Use quick modes (`-q`) for initial sweeps
- Focus on high-confidence findings
- Each tool estimates time requirements

### Documentation
All tools provide:
- Command syntax for documentation
- Manual exploitation methods
- Alternative approaches
- Detailed explanations for learning

## Development

### Package Structure
```
crack/
├── __init__.py              # Package initialization
├── cli.py                   # Main CLI interface
├── enumeration/
│   ├── __init__.py
│   ├── html_enum.py        # HTML enumeration tool
│   ├── param_discover.py   # Parameter discovery tool
│   ├── sqli_scanner.py     # SQLi scanner (legacy - use sqli module)
│   ├── sqli_scanner_new.py # Wrapper for modular version
│   └── sqli/              # Modularized SQLi scanner
│       ├── __init__.py
│       ├── scanner.py      # Core orchestration
│       ├── techniques.py   # Testing techniques
│       ├── databases.py    # DB-specific enumeration
│       └── reporter.py     # Reporting & output
└── utils/
    ├── __init__.py
    └── colors.py           # Shared color utilities
```

### Adding New Tools

1. Create your tool in the appropriate category directory
2. Import it in the category's `__init__.py`
3. Add a command function in `cli.py`
4. Update `setup.py` and `pyproject.toml` with new entry points

### Running Without Installation
```bash
# Tools can still be run directly
python3 crack/enumeration/html_enum.py http://target.com
```

## Requirements

- Python 3.8+
- requests
- beautifulsoup4
- urllib3

## License

MIT License - See LICENSE file for details

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Disclaimer

This toolkit is for authorized security testing only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this program.

## Support

For issues, questions, or suggestions, please open an issue on the GitHub repository.