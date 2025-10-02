```bash
nmap -T4 --min-rate 1000 -sV -sC --version-all -A --osscan-guess -p- -oN "/home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/_full_tcp_nmap.txt" -oX "/home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/xml/_full_tcp_nmap.xml" 192.168.145.49
```

[/home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/_full_tcp_nmap.txt](file:///home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/_full_tcp_nmap.txt):

```
# Nmap 7.95 scan initiated Wed Oct  1 17:50:21 2025 as: /usr/lib/nmap/nmap -T4 --min-rate 1000 -sV -sC --version-all -A --osscan-guess -p- -oN /home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/_full_tcp_nmap.txt -oX /home/kali/OSCP/capstones/chapter_10_capstone_3/results/192.168.145.49/scans/xml/_full_tcp_nmap.xml 192.168.145.49
Nmap scan report for offsecatk.com (192.168.145.49)
Host is up (0.058s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 ba:e4:27:d5:f4:ac:2c:97:91:7a:21:39:bc:2b:3e:48 (RSA)
|   256 5b:df:7f:2e:d5:c8:f6:9f:05:98:b9:44:bb:79:d5:c6 (ECDSA)
|_  256 29:7c:e6:4a:ee:04:ae:d0:dc:e5:07:3c:0f:64:f1:4e (ED25519)
80/tcp   open  http       Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Golden Glove Gym
5432/tcp open  postgresql PostgreSQL DB 13.5 - 13.9
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=debian11temp
| Subject Alternative Name: DNS:debian11temp
| Not valid before: 2022-07-18T15:19:49
|_Not valid after:  2032-07-15T15:19:49
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT      ADDRESS
1   62.55 ms 192.168.45.1
2   62.53 ms 192.168.45.254
3   62.57 ms 192.168.251.1
4   62.61 ms offsecatk.com (192.168.145.49)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct  1 17:50:57 2025 -- 1 IP address (1 host up) scanned in 35.18 seconds

```
