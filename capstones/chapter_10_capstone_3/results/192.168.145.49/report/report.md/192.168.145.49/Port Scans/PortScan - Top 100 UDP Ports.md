```bash
nmap -T4 --min-rate 1000 -sU -A --top-ports 100 -oN "/home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/_top_100_udp_nmap.txt" -oX "/home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/xml/_top_100_udp_nmap.xml" 192.168.145.49
```

[/home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/_top_100_udp_nmap.txt](file:///home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/_top_100_udp_nmap.txt):

```
# Nmap 7.95 scan initiated Wed Oct  1 17:50:21 2025 as: /usr/lib/nmap/nmap -T4 --min-rate 1000 -sU -A --top-ports 100 -oN /home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/_top_100_udp_nmap.txt -oX /home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/xml/_top_100_udp_nmap.xml 192.168.145.49
Nmap scan report for offsecatk.com (192.168.145.49)
Host is up (0.061s latency).
Not shown: 95 open|filtered udp ports (no-response)
PORT     STATE  SERVICE      VERSION
17/udp   closed qotd
162/udp  closed snmptrap
623/udp  closed asf-rmcp
1030/udp closed iad1
2222/udp closed msantipiracy
Too many fingerprints match this host to give specific OS details
Network Distance: 4 hops

TRACEROUTE (using port 1030/udp)
HOP RTT      ADDRESS
1   66.90 ms 192.168.45.1
2   58.26 ms 192.168.45.254
3   58.32 ms 192.168.251.1
4   58.41 ms offsecatk.com (192.168.145.49)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct  1 17:58:51 2025 -- 1 IP address (1 host up) scanned in 509.97 seconds

```
