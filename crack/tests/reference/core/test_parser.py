"""
Tests for Markdown Command Parser

Business Value Focus:
- Parse commands from markdown documentation
- Extract placeholders and generate variables
- Generate markdown from Command objects

Test Priority: TIER 2 - HIGH (Documentation System)
"""

import pytest
from pathlib import Path
from reference.core.parser import MarkdownCommandParser, MarkdownGenerator
from reference.core.registry import Command, CommandVariable


# =============================================================================
# Sample Markdown Content
# =============================================================================

SIMPLE_MARKDOWN = """
# Commands

## Nmap Scan

```bash
nmap -sV -p <PORT> <TARGET>
```

Some description here.

```bash
gobuster dir -u <URL> -w <WORDLIST>
```
"""

MARKDOWN_WITH_COMMENT = """
# Commands

```bash
# This is a comment
nmap -sV <TARGET>
```
"""

MARKDOWN_NO_COMMANDS = """
# Documentation

Some text without any commands.

```python
print("This is Python, not bash")
```
"""

MARKDOWN_LONG_BLOCK = """
# Script

```bash
#!/bin/bash
# Long script
echo "Line 1"
echo "Line 2"
echo "Line 3"
echo "Line 4"
echo "Line 5"
echo "Line 6"
echo "Line 7"
echo "Line 8"
echo "Line 9"
echo "Line 10"
echo "Line 11"
```
"""


# =============================================================================
# MarkdownCommandParser Tests
# =============================================================================

class TestMarkdownCommandParser:
    """Tests for MarkdownCommandParser"""

    def test_parse_simple_commands(self):
        """
        BV: Parse commands from markdown

        Scenario:
          Given: Markdown with bash code blocks
          When: parse_content() is called
          Then: Commands extracted
        """
        parser = MarkdownCommandParser()
        commands = parser.parse_content(SIMPLE_MARKDOWN, 'test')

        assert len(commands) >= 1

    def test_extract_nmap_command(self):
        """
        BV: Extract nmap command

        Scenario:
          Given: Markdown with nmap command
          When: parse_content() is called
          Then: nmap command extracted
        """
        parser = MarkdownCommandParser()
        commands = parser.parse_content(SIMPLE_MARKDOWN, 'test')

        nmap_cmds = [c for c in commands if 'nmap' in c.command]
        assert len(nmap_cmds) >= 1

    def test_extract_placeholders(self):
        """
        BV: Extract placeholders as variables

        Scenario:
          Given: Command with <TARGET> placeholder
          When: parse_content() is called
          Then: Variable created for placeholder
        """
        parser = MarkdownCommandParser()
        commands = parser.parse_content(SIMPLE_MARKDOWN, 'test')

        # Find command with TARGET
        has_target = False
        for cmd in commands:
            for var in cmd.variables:
                if var.name == '<TARGET>':
                    has_target = True
                    break
        assert has_target

    def test_skip_comments(self):
        """
        BV: Skip comment lines

        Scenario:
          Given: Code block with comment line
          When: parse_content() is called
          Then: Comment line not extracted as command
        """
        parser = MarkdownCommandParser()
        commands = parser.parse_content(MARKDOWN_WITH_COMMENT, 'test')

        # Should have the nmap command but not the comment
        for cmd in commands:
            assert not cmd.command.startswith('#')

    def test_skip_long_blocks(self):
        """
        BV: Skip long code blocks

        Scenario:
          Given: Code block with 11+ lines
          When: parse_content() is called
          Then: Block skipped
        """
        parser = MarkdownCommandParser()
        commands = parser.parse_content(MARKDOWN_LONG_BLOCK, 'test')

        # Long blocks should be skipped
        assert len(commands) == 0

    def test_no_commands_returns_empty(self):
        """
        BV: No commands returns empty list

        Scenario:
          Given: Markdown without bash commands
          When: parse_content() is called
          Then: Returns empty list
        """
        parser = MarkdownCommandParser()
        commands = parser.parse_content(MARKDOWN_NO_COMMANDS, 'test')

        assert commands == []


# =============================================================================
# Command Recognition Tests
# =============================================================================

class TestCommandRecognition:
    """Tests for command recognition"""

    def test_looks_like_nmap(self):
        """
        BV: Recognize nmap commands

        Scenario:
          Given: Line starting with 'nmap'
          When: _looks_like_command() is called
          Then: Returns True
        """
        parser = MarkdownCommandParser()

        assert parser._looks_like_command('nmap -sV target') is True

    def test_looks_like_gobuster(self):
        """
        BV: Recognize gobuster commands

        Scenario:
          Given: Line starting with 'gobuster'
          When: _looks_like_command() is called
          Then: Returns True
        """
        parser = MarkdownCommandParser()

        assert parser._looks_like_command('gobuster dir -u http://target') is True

    def test_looks_like_sqlmap(self):
        """
        BV: Recognize sqlmap commands

        Scenario:
          Given: Line starting with 'sqlmap'
          When: _looks_like_command() is called
          Then: Returns True
        """
        parser = MarkdownCommandParser()

        assert parser._looks_like_command('sqlmap -u http://target') is True

    def test_does_not_recognize_echo(self):
        """
        BV: Don't recognize generic commands

        Scenario:
          Given: Line starting with 'echo'
          When: _looks_like_command() is called
          Then: Returns False
        """
        parser = MarkdownCommandParser()

        assert parser._looks_like_command('echo hello') is False

    def test_skip_comment_lines(self):
        """
        BV: Skip lines starting with #

        Scenario:
          Given: Comment line
          When: _looks_like_command() is called
          Then: Returns False
        """
        parser = MarkdownCommandParser()

        assert parser._looks_like_command('# nmap scan') is False


# =============================================================================
# Placeholder Guessing Tests
# =============================================================================

class TestPlaceholderGuessing:
    """Tests for placeholder description/example guessing"""

    def test_guess_target_description(self):
        """
        BV: Guess TARGET description

        Scenario:
          Given: <TARGET> placeholder
          When: _guess_placeholder_description() is called
          Then: Returns appropriate description
        """
        parser = MarkdownCommandParser()
        desc = parser._guess_placeholder_description('<TARGET>')

        assert 'IP' in desc or 'hostname' in desc

    def test_guess_lhost_description(self):
        """
        BV: Guess LHOST description

        Scenario:
          Given: <LHOST> placeholder
          When: _guess_placeholder_description() is called
          Then: Returns attacker IP description
        """
        parser = MarkdownCommandParser()
        desc = parser._guess_placeholder_description('<LHOST>')

        assert 'IP' in desc or 'attacker' in desc.lower() or 'local' in desc.lower()

    def test_guess_unknown_placeholder(self):
        """
        BV: Handle unknown placeholders

        Scenario:
          Given: Unknown placeholder
          When: _guess_placeholder_description() is called
          Then: Returns generic description
        """
        parser = MarkdownCommandParser()
        desc = parser._guess_placeholder_description('<CUSTOM>')

        assert '<CUSTOM>' in desc or 'Value for' in desc

    def test_guess_target_example(self):
        """
        BV: Guess TARGET example

        Scenario:
          Given: <TARGET> placeholder
          When: _guess_placeholder_example() is called
          Then: Returns IP example
        """
        parser = MarkdownCommandParser()
        example = parser._guess_placeholder_example('<TARGET>')

        assert '192.168' in example or '10.' in example

    def test_guess_port_example(self):
        """
        BV: Guess PORT example

        Scenario:
          Given: <PORT> placeholder
          When: _guess_placeholder_example() is called
          Then: Returns port number
        """
        parser = MarkdownCommandParser()
        example = parser._guess_placeholder_example('<PORT>')

        assert example.isdigit()


# =============================================================================
# Tag Guessing Tests
# =============================================================================

class TestTagGuessing:
    """Tests for command tag guessing"""

    def test_nmap_gets_enum_tag(self):
        """
        BV: nmap commands get ENUM tag

        Scenario:
          Given: nmap command
          When: _guess_tags_from_command() is called
          Then: ENUM tag added
        """
        parser = MarkdownCommandParser()
        tags = parser._guess_tags_from_command('nmap -sV target')

        assert 'ENUM' in tags

    def test_gobuster_gets_web_tag(self):
        """
        BV: gobuster commands get WEB tag

        Scenario:
          Given: gobuster command
          When: _guess_tags_from_command() is called
          Then: WEB tag added
        """
        parser = MarkdownCommandParser()
        tags = parser._guess_tags_from_command('gobuster dir -u http://target')

        assert 'WEB' in tags

    def test_sqlmap_gets_sqli_tag(self):
        """
        BV: sqlmap commands get SQLI tag

        Scenario:
          Given: sqlmap command
          When: _guess_tags_from_command() is called
          Then: SQLI tag added
        """
        parser = MarkdownCommandParser()
        tags = parser._guess_tags_from_command('sqlmap -u http://target')

        assert 'SQLI' in tags

    def test_hydra_gets_bruteforce_tag(self):
        """
        BV: hydra commands get BRUTEFORCE tag

        Scenario:
          Given: hydra command
          When: _guess_tags_from_command() is called
          Then: BRUTEFORCE tag added
        """
        parser = MarkdownCommandParser()
        tags = parser._guess_tags_from_command('hydra -l admin -P wordlist.txt target ssh')

        assert 'BRUTEFORCE' in tags

    def test_netcat_gets_transfer_tag(self):
        """
        BV: netcat commands get TRANSFER tag

        Scenario:
          Given: nc command
          When: _guess_tags_from_command() is called
          Then: TRANSFER tag added
        """
        parser = MarkdownCommandParser()
        tags = parser._guess_tags_from_command('nc -lvnp 4444')

        assert 'TRANSFER' in tags or 'REVERSE_SHELL' in tags


# =============================================================================
# MarkdownGenerator Tests
# =============================================================================

class TestMarkdownGenerator:
    """Tests for MarkdownGenerator"""

    def test_generate_command_md_basic(self):
        """
        BV: Generate markdown for command

        Scenario:
          Given: Command object
          When: generate_command_md() is called
          Then: Markdown generated with name and command
        """
        generator = MarkdownGenerator()
        cmd = Command(
            id='test-cmd',
            name='Test Command',
            category='test',
            command='nmap -sV <TARGET>',
            description='Test description'
        )

        md = generator.generate_command_md(cmd)

        assert 'Test Command' in md
        assert 'nmap -sV <TARGET>' in md

    def test_generate_command_md_with_variables(self):
        """
        BV: Generate markdown with variables section

        Scenario:
          Given: Command with variables
          When: generate_command_md() is called
          Then: Variables section included
        """
        generator = MarkdownGenerator()
        cmd = Command(
            id='test-cmd',
            name='Test Command',
            category='test',
            command='nmap -p <PORT> <TARGET>',
            description='Test description',
            variables=[
                CommandVariable(name='<TARGET>', description='Target IP', example='192.168.1.1', required=True),
                CommandVariable(name='<PORT>', description='Port', example='80', required=True)
            ]
        )

        md = generator.generate_command_md(cmd)

        assert 'Variables' in md
        assert '<TARGET>' in md
        assert '<PORT>' in md

    def test_generate_command_md_with_tags(self):
        """
        BV: Generate markdown with tags

        Scenario:
          Given: Command with tags
          When: generate_command_md() is called
          Then: Tags section included
        """
        generator = MarkdownGenerator()
        cmd = Command(
            id='test-cmd',
            name='Test Command',
            category='test',
            command='nmap <TARGET>',
            description='Test description',
            tags=['ENUM', 'NOISY']
        )

        md = generator.generate_command_md(cmd)

        assert 'Tags' in md
        assert 'ENUM' in md
        assert 'NOISY' in md

    def test_generate_category_md(self):
        """
        BV: Generate category markdown

        Scenario:
          Given: Category with commands
          When: generate_category_md() is called
          Then: Category header and commands included
        """
        generator = MarkdownGenerator()
        commands = [
            Command(
                id='cmd1',
                name='Command 1',
                category='recon',
                command='nmap <TARGET>',
                description='First command',
                oscp_relevance='high'
            ),
            Command(
                id='cmd2',
                name='Command 2',
                category='recon',
                command='gobuster <URL>',
                description='Second command',
                oscp_relevance='medium'
            )
        ]

        md = generator.generate_category_md('recon', commands)

        assert 'Recon Commands' in md
        assert 'High OSCP Relevance' in md
        assert 'Medium OSCP Relevance' in md


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_empty_content(self):
        """
        BV: Handle empty content

        Scenario:
          Given: Empty string
          When: parse_content() is called
          Then: Returns empty list
        """
        parser = MarkdownCommandParser()
        commands = parser.parse_content('', 'test')

        assert commands == []

    def test_command_without_placeholders(self):
        """
        BV: Handle commands without placeholders

        Scenario:
          Given: Command with no placeholders
          When: extracting command
          Then: Empty variables list
        """
        parser = MarkdownCommandParser()
        cmd = parser._extract_command_from_line('nmap 192.168.1.1', 'test', 0)

        assert cmd is not None
        assert cmd.variables == []

    def test_generator_with_alternatives(self):
        """
        BV: Generate markdown with alternatives

        Scenario:
          Given: Command with alternatives
          When: generate_command_md() is called
          Then: Alternatives section included
        """
        generator = MarkdownGenerator()
        cmd = Command(
            id='test-cmd',
            name='Test Command',
            category='test',
            command='nmap <TARGET>',
            description='Test',
            alternatives=['masscan', 'rustscan']
        )

        md = generator.generate_command_md(cmd)

        assert 'Alternative' in md
        assert 'masscan' in md

    def test_generator_with_notes(self):
        """
        BV: Generate markdown with notes

        Scenario:
          Given: Command with notes
          When: generate_command_md() is called
          Then: Notes section included
        """
        generator = MarkdownGenerator()
        cmd = Command(
            id='test-cmd',
            name='Test Command',
            category='test',
            command='nmap <TARGET>',
            description='Test',
            notes='Important note here'
        )

        md = generator.generate_command_md(cmd)

        assert 'Notes' in md
        assert 'Important note' in md
