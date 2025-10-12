#!/usr/bin/env python3
"""
Tag Enhancement Script for CRACK Reference System

Systematically analyzes all commands and adds comprehensive tags based on:
- Command text and functionality
- Description content
- Category/subcategory
- Technology mentioned
- Attack technique used
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Set, Any
from collections import Counter


class TagEnhancer:
    """Enhances commands with comprehensive tags"""

    def __init__(self):
        self.commands_dir = Path(__file__).parent.parent / "data" / "commands"

        # Tag mapping rules - keyword patterns to tags
        self.tag_rules = self._initialize_tag_rules()

        # Statistics
        self.stats = {
            'files_processed': 0,
            'commands_modified': 0,
            'tags_added': Counter(),
            'before': {'total_tags': 0, 'unique_tags': set(), 'avg_tags': 0},
            'after': {'total_tags': 0, 'unique_tags': set(), 'avg_tags': 0}
        }

    def _initialize_tag_rules(self) -> Dict[str, List[str]]:
        """Initialize comprehensive tag mapping rules"""
        return {
            # Functionality tags
            'ENUMERATION': [
                r'\bnmap\b', r'\benum', r'\bscan', r'\bdiscov', r'\blist',
                r'\blinpeas\b', r'\bwinpeas\b', r'\bpspy\b', r'\blinenum\b',
                r'\bgobuster\b', r'\bdirb\b', r'\bffuf\b', r'\bwfuzz\b',
                r'\bnikto\b', r'\bwhatweb\b', r'\bwpscan\b', r'\benum4linux\b',
                r'\bsmbmap\b', r'\bsmbclient\b', r'\bfind\b', r'\bgrep\b',
                r'\bbrute[\s-]?force\b', r'\benumerat', r'\brecon'
            ],
            'EXPLOITATION': [
                r'\bexploit\b', r'\bpayload\b', r'\bmsfvenom\b', r'\bmetasploit\b',
                r'\bshell\b', r'\brevshell\b', r'\breverse shell\b', r'\bexecute\b',
                r'\battack\b', r'\binject\b', r'\bsqli\b'
            ],
            'POST_EXPLOITATION': [
                r'\bpost[\s-]?exploit\b', r'\bpersist', r'\blateral',
                r'\bpivot', r'\btunnel', r'\bproxy\b', r'\bbackdoor\b'
            ],
            'PRIVILEGE_ESCALATION': [
                r'\bprivesc\b', r'\bprivilege', r'\belevat', r'\bescape\b',
                r'\broot\b', r'\badmin\b', r'\bsuid\b', r'\bsudo\b',
                r'\bcapabilit', r'\bsetuid\b', r'\bkern.*exploit\b'
            ],
            'CREDENTIAL_ACCESS': [
                r'\bpassword\b', r'\bhash\b', r'\bcred', r'\bmimikatz\b',
                r'\bdump', r'\bextract.*pass', r'\bcrack', r'\bjohn\b',
                r'\bhydra\b', r'\bhashcat\b', r'\bkerberos\b', r'\bntlm\b'
            ],
            'LATERAL_MOVEMENT': [
                r'\blateral\b', r'\bpivot', r'\bpsexec\b', r'\bwmi\b',
                r'\bremote.*exec', r'\bpass.*the.*hash\b'
            ],
            'RECONNAISSANCE': [
                r'\brecon', r'\binform.*gather', r'\bfootprint',
                r'\bosint\b', r'\bwhois\b', r'\bdns\b'
            ],
            'WEAPONIZATION': [
                r'\bmsfvenom\b', r'\bpayload.*generat', r'\bshellcode\b',
                r'\bcreate.*payload\b', r'\bgenerate.*shell\b'
            ],
            'INITIAL_ACCESS': [
                r'\binitial.*access\b', r'\bentry.*point\b', r'\bphish',
                r'\bexploit.*public\b', r'\bdefault.*cred\b'
            ],

            # Technology tags
            'APACHE': [r'\bapache\b', r'\bhttpd\b'],
            'NGINX': [r'\bnginx\b'],
            'IIS': [r'\biis\b', r'\bmicrosoft.*web\b'],
            'MYSQL': [r'\bmysql\b', r'\bmariadb\b'],
            'POSTGRESQL': [r'\bpostgres', r'\bpgsql\b'],
            'MSSQL': [r'\bmssql\b', r'\bsql.*server\b'],
            'ORACLE': [r'\boracle\b', r'\bora\d+\b'],
            'WORDPRESS': [r'\bwordpress\b', r'\bwp[\s-]', r'\bwpscan\b'],
            'JOOMLA': [r'\bjoomla\b'],
            'DRUPAL': [r'\bdrupal\b'],
            'ACTIVE_DIRECTORY': [r'\bactive.*directory\b', r'\bad\b', r'\bldap\b', r'\bkerberos\b'],
            'LDAP': [r'\bldap\b'],
            'SAMBA': [r'\bsmb\b', r'\bsamba\b', r'\bcifs\b', r'\bnetbios\b'],
            'SSH': [r'\bssh\b', r'\bopenssh\b'],
            'FTP': [r'\bftp\b'],
            'TELNET': [r'\btelnet\b'],
            'RDP': [r'\brdp\b', r'\bremote.*desktop\b'],
            'VNC': [r'\bvnc\b'],

            # Technique tags
            'INJECTION': [
                r'\binject', r'\bsqli\b', r'\bsql.*inject', r'\bcommand.*inject',
                r'\bldap.*inject', r'\btemplate.*inject', r'\bwildcard.*inject',
                r'\bos.*command\b', r'\bcode.*inject'
            ],
            'SQL_INJECTION': [
                r'\bsqli\b', r'\bsql.*inject', r'\bsqlmap\b', r'\bunion.*select\b',
                r'\bblind.*sql\b', r'\berror.*based.*sql\b'
            ],
            'COMMAND_INJECTION': [
                r'\bcommand.*inject', r'\bos.*command\b', r'\bshell.*inject',
                r'\bwildcard.*inject', r'\bremote.*code.*exec'
            ],
            'DIRECTORY_ENUMERATION': [
                r'\bdir.*enum', r'\bdir.*brute', r'\bdir.*scan', r'\bfile.*discov',
                r'\bgobuster\b', r'\bdirb\b', r'\bffuf\b', r'\bwfuzz\b',
                r'\bfuzz.*dir', r'\bfuzz.*file', r'\bhidden.*dir', r'\bhidden.*file'
            ],
            'DIRECTORY_TRAVERSAL': [
                r'\btraversal\b', r'\bpath.*travers', r'\blfi\b', r'\brfi\b',
                r'\bfile.*inclus', r'\b\.\./\.\.\b', r'\bdir.*travers'
            ],
            'FILE_UPLOAD': [
                r'\bfile.*upload\b', r'\bupload.*vuln', r'\bupload.*bypass',
                r'\bupload.*shell\b', r'\bwebshell.*upload\b'
            ],
            'FILE_INCLUSION': [
                r'\blfi\b', r'\brfi\b', r'\bfile.*inclus', r'\binclude.*vuln',
                r'\bremote.*file\b', r'\blocal.*file\b'
            ],
            'REMOTE_CODE_EXECUTION': [
                r'\brce\b', r'\bremote.*code', r'\bremote.*exec', r'\bcode.*exec',
                r'\bexec.*code\b', r'\bshell.*exec'
            ],
            'CROSS_SITE_SCRIPTING': [
                r'\bxss\b', r'\bcross.*site', r'\bscript.*inject',
                r'\breflected.*xss\b', r'\bstored.*xss\b', r'\bdom.*xss\b'
            ],
            'BUFFER_OVERFLOW': [
                r'\bbuffer.*overflow\b', r'\bbof\b', r'\bstack.*overflow\b',
                r'\bheap.*overflow\b', r'\bmemory.*corrupt'
            ],
            'REVERSE_ENGINEERING': [
                r'\breverse.*eng', r'\bdecompil', r'\bdisassembl',
                r'\bbinary.*analy', r'\bgdb\b', r'\bghost\b'
            ],

            # Tool tags
            'NMAP': [r'\bnmap\b', r'\bnse\b'],
            'METASPLOIT': [r'\bmetasploit\b', r'\bmsfvenom\b', r'\bmsfconsole\b', r'\bmsf\b'],
            'BURP': [r'\bburp\b', r'\bburpsuite\b'],
            'SQLMAP': [r'\bsqlmap\b'],
            'GOBUSTER': [r'\bgobuster\b'],
            'DIRB': [r'\bdirb\b'],
            'FFUF': [r'\bffuf\b'],
            'WFUZZ': [r'\bwfuzz\b'],
            'ENUM4LINUX': [r'\benum4linux\b'],
            'SMBCLIENT': [r'\bsmbclient\b'],
            'SMBMAP': [r'\bsmbmap\b'],
            'CRACKMAPEXEC': [r'\bcrackmapexec\b', r'\bcme\b'],
            'LINPEAS': [r'\blinpeas\b'],
            'WINPEAS': [r'\bwinpeas\b'],
            'PSPY': [r'\bpspy\b'],
            'LINENUM': [r'\blinenum\b'],
            'NIKTO': [r'\bnikto\b'],
            'WHATWEB': [r'\bwhatweb\b'],
            'WPSCAN': [r'\bwpscan\b'],
            'HYDRA': [r'\bhydra\b'],
            'JOHN': [r'\bjohn\b', r'\bjtr\b'],
            'HASHCAT': [r'\bhashcat\b'],
            'MIMIKATZ': [r'\bmimikatz\b'],
            'BLOODHOUND': [r'\bbloodhound\b'],
            'POWERSHELL': [r'\bpowershell\b', r'\bps1\b', r'\bpowersploit\b'],
            'PYTHON': [r'\bpython\b', r'\bpy\b'],
            'NETCAT': [r'\bnetcat\b', r'\bnc\b'],
            'SOCAT': [r'\bsocat\b'],
            'CURL': [r'\bcurl\b'],
            'WGET': [r'\bwget\b'],

            # Methodology tags
            'STARTER': [
                r'\bfirst.*command\b', r'\binitial.*scan\b', r'\bbasic.*enum',
                r'\bquick.*scan\b', r'\bping.*sweep\b'
            ],
            'STEALTHY': [r'\bstealth', r'\bquiet\b', r'\bpassive\b', r'\bcovert\b'],
            'NOISY': [r'\bnoisy\b', r'\baggressive\b', r'\bfull.*scan\b'],

            # Additional context tags
            'DATABASE': [
                r'\bdb\b', r'\bdatabase\b', r'\bsql\b', r'\btable\b',
                r'\bquery\b', r'\bselect\b', r'\bmysql\b', r'\bpostgres',
                r'\bmssql\b', r'\boracle\b'
            ],
            'NETWORK': [
                r'\bnetwork\b', r'\bping\b', r'\barp\b', r'\broute\b',
                r'\btcp\b', r'\budp\b', r'\bport\b', r'\bsocket\b'
            ],
            'FILE_TRANSFER': [
                r'\btransfer\b', r'\bdownload\b', r'\bupload\b', r'\bexfil',
                r'\bfetch\b', r'\bsend.*file\b', r'\bget.*file\b'
            ],
            'PERSISTENCE': [
                r'\bpersist', r'\bcron\b', r'\bstartup\b', r'\bservice\b',
                r'\bscheduled.*task\b', r'\bautorun\b', r'\bregistry.*run\b'
            ],
            'DEFENSE_EVASION': [
                r'\bevasi', r'\bbypass\b', r'\bobfuscat', r'\bencode\b',
                r'\bhide\b', r'\bstealth\b', r'\bdisable.*av\b', r'\bdisable.*firewall\b'
            ],
            'DISCOVERY': [
                r'\bdiscov', r'\bfind\b', r'\bsearch\b', r'\blocate\b',
                r'\benumerat', r'\blist\b'
            ],
        }

    def analyze_command(self, cmd: Dict[str, Any]) -> Set[str]:
        """Analyze command and determine which tags should be added"""
        new_tags = set()

        # Combine all text fields for analysis
        text_to_analyze = ' '.join([
            cmd.get('name', ''),
            cmd.get('description', ''),
            cmd.get('command', ''),
            cmd.get('category', ''),
            cmd.get('subcategory', ''),
            ' '.join(cmd.get('tags', []))
        ]).lower()

        # Apply tag rules
        for tag, patterns in self.tag_rules.items():
            for pattern in patterns:
                if re.search(pattern, text_to_analyze, re.IGNORECASE):
                    new_tags.add(tag)
                    break  # One match per tag is enough

        # Remove tags that are already present
        existing_tags = set(cmd.get('tags', []))
        tags_to_add = new_tags - existing_tags

        return tags_to_add

    def enhance_file(self, file_path: Path) -> int:
        """Enhance all commands in a JSON file"""
        print(f"\nProcessing: {file_path.relative_to(self.commands_dir.parent.parent)}")

        with open(file_path, 'r') as f:
            data = json.load(f)

        commands = data.get('commands', [])
        modified_count = 0

        for cmd in commands:
            # Collect before stats
            self.stats['before']['total_tags'] += len(cmd.get('tags', []))
            self.stats['before']['unique_tags'].update(cmd.get('tags', []))

            # Analyze and add tags
            tags_to_add = self.analyze_command(cmd)

            if tags_to_add:
                cmd['tags'] = sorted(set(cmd.get('tags', [])) | tags_to_add)
                modified_count += 1

                # Track which tags were added
                for tag in tags_to_add:
                    self.stats['tags_added'][tag] += 1

                print(f"  Enhanced: {cmd['id']}")
                print(f"    Added tags: {', '.join(sorted(tags_to_add))}")

            # Collect after stats
            self.stats['after']['total_tags'] += len(cmd.get('tags', []))
            self.stats['after']['unique_tags'].update(cmd.get('tags', []))

        # Write back to file (2-space indent for consistency)
        if modified_count > 0:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"  Modified {modified_count} commands in this file")
        else:
            print(f"  No changes needed")

        self.stats['files_processed'] += 1
        self.stats['commands_modified'] += modified_count

        return modified_count

    def enhance_all(self):
        """Enhance all command files"""
        print("=" * 80)
        print("TAG ENHANCEMENT PROCESS")
        print("=" * 80)

        # Find all JSON files
        json_files = list(self.commands_dir.glob('**/*.json'))
        print(f"\nFound {len(json_files)} JSON files to process\n")

        # Process each file
        for json_file in sorted(json_files):
            self.enhance_file(json_file)

        # Calculate averages
        total_commands = (self.stats['commands_modified'] +
                         (self.stats['files_processed'] * 10))  # Rough estimate

        self.stats['before']['avg_tags'] = (
            self.stats['before']['total_tags'] / total_commands
            if total_commands > 0 else 0
        )
        self.stats['after']['avg_tags'] = (
            self.stats['after']['total_tags'] / total_commands
            if total_commands > 0 else 0
        )

    def print_report(self):
        """Print comprehensive statistics report"""
        print("\n" + "=" * 80)
        print("ENHANCEMENT REPORT")
        print("=" * 80)

        print("\n### FILES PROCESSED")
        print(f"Total files: {self.stats['files_processed']}")
        print(f"Commands modified: {self.stats['commands_modified']}")

        print("\n### BEFORE ENHANCEMENT")
        print(f"Total tags: {self.stats['before']['total_tags']}")
        print(f"Unique tags: {len(self.stats['before']['unique_tags'])}")
        print(f"Average tags per command: {self.stats['before']['avg_tags']:.2f}")

        print("\n### AFTER ENHANCEMENT")
        print(f"Total tags: {self.stats['after']['total_tags']}")
        print(f"Unique tags: {len(self.stats['after']['unique_tags'])}")
        print(f"Average tags per command: {self.stats['after']['avg_tags']:.2f}")

        print("\n### CHANGES")
        tags_added_total = sum(self.stats['tags_added'].values())
        print(f"Total tag instances added: {tags_added_total}")
        print(f"New unique tags: {len(self.stats['after']['unique_tags'] - self.stats['before']['unique_tags'])}")

        print("\n### TOP 20 NEW TAGS ADDED")
        for tag, count in self.stats['tags_added'].most_common(20):
            print(f"  {tag}: {count} commands")

        print("\n### ALL NEW TAGS")
        new_tags = sorted(self.stats['after']['unique_tags'] - self.stats['before']['unique_tags'])
        print(f"Added {len(new_tags)} new tags:")
        for tag in new_tags:
            print(f"  {tag}")


def main():
    enhancer = TagEnhancer()
    enhancer.enhance_all()
    enhancer.print_report()

    print("\n" + "=" * 80)
    print("Enhancement complete! Run validation to verify JSON integrity.")
    print("=" * 80)


if __name__ == '__main__':
    main()
