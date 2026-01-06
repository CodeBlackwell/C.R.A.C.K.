# Contributing to CRACK

Thank you for your interest in contributing to CRACK! This document provides guidelines for contributions.

## Code of Conduct

Be respectful and constructive. This is an educational security tool - contributions should focus on legitimate pentesting and security assessments.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/crack.git
   cd crack
   ```
3. Install in development mode:
   ```bash
   pip install -e ".[dev]"
   ```
4. Create a branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Requirements
- Python 3.8+
- Neo4j (optional, for graph features)
- Node.js 18+ (for Electron apps)

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=crack

# Run specific module tests
pytest tests/reference/
```

## Contributing Commands

Commands are the core knowledge unit. To add a new command:

1. Find the appropriate file in `db/data/commands/{category}/`
2. Add your command following the schema:
   ```json
   {
     "id": "tool-action-target",
     "name": "Human Readable Name",
     "category": "enumeration",
     "command": "tool -flag <PLACEHOLDER>",
     "description": "What this command does",
     "tags": ["LINUX", "ENUMERATION"],
     "variables": [
       {"name": "PLACEHOLDER", "description": "What to put here", "example": "10.10.10.1"}
     ],
     "flag_explanations": {
       "-flag": "Why this flag matters"
     }
   }
   ```
3. Validate your addition:
   ```bash
   crack reference --validate
   ```

### Command Quality Guidelines
- Include all flags with explanations
- Provide realistic examples
- Add troubleshooting for common errors
- Tag with appropriate category tags (LINUX, WINDOWS, WEB, AD, etc.)

## Contributing Tools

Tools live in `tools/{category}/`. Each tool should:

1. Have clear single responsibility
2. Include docstrings and type hints
3. Handle errors gracefully
4. Log appropriately using the logging module

### Tool Structure
```python
"""
Tool description.

Usage:
    crack tool-name <args>
"""

import logging

logger = logging.getLogger(__name__)

def main(args):
    """Entry point."""
    # Implementation
```

## Pull Request Process

1. Update documentation if adding features
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG if applicable
5. Submit PR with clear description

### PR Title Format
- `feat: Add new feature`
- `fix: Fix specific bug`
- `docs: Update documentation`
- `refactor: Code improvement`
- `test: Add or update tests`

## Reporting Issues

When reporting bugs:
1. Describe the expected vs actual behavior
2. Include reproduction steps
3. Provide environment details (Python version, OS)
4. Include relevant error messages

## Security Issues

**Do not open public issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for responsible disclosure process.

## Questions?

Open a discussion on GitHub or check existing issues for similar questions.
