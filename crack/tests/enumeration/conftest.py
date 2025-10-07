"""
Shared fixtures for enumeration tests
Real-world scenario data based on OSCP lab boxes
"""

import pytest
import tempfile
import shutil
import os
from pathlib import Path
from crack.enumeration.core.state import TargetProfile
from crack.enumeration.core.storage import Storage


@pytest.fixture
def temp_crack_home(monkeypatch):
    """Temporary ~/.crack directory for isolated testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        crack_dir = Path(tmpdir) / '.crack' / 'targets'
        crack_dir.mkdir(parents=True)

        # Directly override Storage.DEFAULT_DIR to ensure it uses temp directory
        from crack.enumeration.core.storage import Storage
        monkeypatch.setattr(Storage, 'DEFAULT_DIR', crack_dir)

        yield crack_dir


@pytest.fixture
def clean_profile(temp_crack_home):
    """Fresh target profile for testing"""
    def _create_profile(target="192.168.45.100"):
        return TargetProfile(target)
    return _create_profile


@pytest.fixture
def typical_oscp_nmap_xml(tmp_path):
    """
    Realistic nmap XML from a typical OSCP box
    Services: SSH (22), HTTP (80), SMB (445)
    """
    xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -sC -p- 192.168.45.100" start="1699564800" version="7.94">
<host starttime="1699564800" endtime="1699565000">
<address addr="192.168.45.100" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10">
<cpe>cpe:/o:linux:linux_kernel</cpe>
</service>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10">
<cpe>cpe:/a:apache:http_server:2.4.41</cpe>
</service>
</port>
<port protocol="tcp" portid="445">
<state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="microsoft-ds" product="Samba smbd" version="4.13.13-Ubuntu" method="probed" conf="10">
</service>
</port>
</ports>
<os>
<osmatch name="Linux 5.0 - 5.4" accuracy="95">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="95">
<cpe>cpe:/o:linux:linux_kernel:5</cpe>
</osclass>
</osmatch>
</os>
</host>
</nmaprun>
'''
    xml_file = tmp_path / "typical_oscp.xml"
    xml_file.write_text(xml_content)
    return str(xml_file)


@pytest.fixture
def web_heavy_nmap_xml(tmp_path):
    """
    Target with multiple web services on different ports
    Ports: 80 (Apache), 443 (nginx), 8080 (Tomcat), 8443 (Node.js)
    """
    xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p- 192.168.45.101" start="1699564800" version="7.94">
<host>
<address addr="192.168.45.101" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="Apache httpd" version="2.4.41"/>
</port>
<port protocol="tcp" portid="443">
<state state="open"/>
<service name="https" product="nginx" version="1.18.0" tunnel="ssl"/>
</port>
<port protocol="tcp" portid="8080">
<state state="open"/>
<service name="http" product="Apache Tomcat" version="9.0.31"/>
</port>
<port protocol="tcp" portid="8443">
<state state="open"/>
<service name="https" product="Node.js" tunnel="ssl"/>
</port>
</ports>
</host>
</nmaprun>
'''
    xml_file = tmp_path / "web_heavy.xml"
    xml_file.write_text(xml_content)
    return str(xml_file)


@pytest.fixture
def vulnerable_smb_nmap_xml(tmp_path):
    """
    Target with old vulnerable Samba version (CVE-2007-2447)
    Port: 139, 445 (Samba 3.0.20)
    """
    xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p139,445 192.168.45.102" start="1699564800" version="7.94">
<host>
<address addr="192.168.45.102" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="139">
<state state="open"/>
<service name="netbios-ssn" product="Samba smbd" version="3.0.20-Debian"/>
</port>
<port protocol="tcp" portid="445">
<state state="open"/>
<service name="microsoft-ds" product="Samba smbd" version="3.0.20-Debian"/>
</port>
</ports>
</host>
</nmaprun>
'''
    xml_file = tmp_path / "vulnerable_smb.xml"
    xml_file.write_text(xml_content)
    return str(xml_file)


@pytest.fixture
def minimal_linux_nmap_xml(tmp_path):
    """
    Minimal Linux box - only SSH and HTTP
    Requires thorough web enumeration to find attack vector
    """
    xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p- 192.168.45.103" start="1699564800" version="7.94">
<host>
<address addr="192.168.45.103" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh" product="OpenSSH" version="8.9p1"/>
</port>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="nginx" version="1.20.1"/>
</port>
</ports>
</host>
</nmaprun>
'''
    xml_file = tmp_path / "minimal_linux.xml"
    xml_file.write_text(xml_content)
    return str(xml_file)


@pytest.fixture
def windows_dc_nmap_xml(tmp_path):
    """
    Windows Domain Controller
    Ports: 53, 88, 135, 139, 389, 445, 3389
    """
    xml_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p- 192.168.45.200" start="1699564800" version="7.94">
<host>
<address addr="192.168.45.200" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="53">
<state state="open"/>
<service name="domain" product="Microsoft DNS"/>
</port>
<port protocol="tcp" portid="88">
<state state="open"/>
<service name="kerberos-sec" product="Microsoft Windows Kerberos"/>
</port>
<port protocol="tcp" portid="135">
<state state="open"/>
<service name="msrpc" product="Microsoft Windows RPC"/>
</port>
<port protocol="tcp" portid="139">
<state state="open"/>
<service name="netbios-ssn" product="Microsoft Windows netbios-ssn"/>
</port>
<port protocol="tcp" portid="389">
<state state="open"/>
<service name="ldap" product="Microsoft Windows Active Directory LDAP"/>
</port>
<port protocol="tcp" portid="445">
<state state="open"/>
<service name="microsoft-ds" product="Microsoft Windows Server 2019"/>
</port>
<port protocol="tcp" portid="3389">
<state state="open"/>
<service name="ms-wbt-server" product="Microsoft Terminal Services"/>
</port>
</ports>
<os>
<osmatch name="Microsoft Windows Server 2019" accuracy="100"/>
</os>
</host>
</nmaprun>
'''
    xml_file = tmp_path / "windows_dc.xml"
    xml_file.write_text(xml_content)
    return str(xml_file)


@pytest.fixture
def nmap_gnmap_typical(tmp_path):
    """Greppable nmap output for typical OSCP box"""
    gnmap_content = '''# Nmap 7.94 scan initiated
Host: 192.168.45.100 ()	Status: Up	Ports: 22/open/tcp//ssh//OpenSSH 8.2p1 Ubuntu/, 80/open/tcp//http//Apache httpd 2.4.41/, 445/open/tcp//microsoft-ds//Samba smbd 4.13.13/
# Nmap done at Mon Nov  6 12:00:00 2023 -- 1 IP address (1 host up) scanned in 120.00 seconds
'''
    gnmap_file = tmp_path / "typical.gnmap"
    gnmap_file.write_text(gnmap_content)
    return str(gnmap_file)
