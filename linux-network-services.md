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

IPTables is a stateless firewall, by default. This can be changed to stateful, if desired.

`sudo iptables -L`

Configure DROP for the FORWARD chain, because we don't configure a linux router

`sudo iptables -P FORWARD DROP`

Append 192.168.1.0/24 on all protocols to INPUT chain

`sudo iptables -s 192.168.1.0/24 -p all -A INPUT`

Append 127.0.0.1 (IPv4 localhost) and delete it again

```
sudo iptables -s 127.0.0.1 -d 127.0.0.1 -p all -A INPUT
sudo iptables - 127.0.0.1 -D INPUT
```

Delete INPUT rule by line number

```
sudo iptables -L --line-numbers
sudo iptables -D INPUT 2
```

Insert INPUT rule by line number

```
sudo -s 192.168.1.37 -I INPUT 1
sudo iptables -L --line-numbers
```