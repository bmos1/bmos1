# Information Gathering

## Passive

Passive information gathering allows normal interaction with application and targets, without vulnerability review. Anyways, whenever possible a pentester want to enumerate without target interaction.

### Whois

* forward search
* option -h IP address of WHOIS server

```bash
whois megacorpone.com -h 192.168.50.251
...
Domain Name: MEGACORPONE.COM
Registrant Name: Alan Grofield
...
Name Server: NS1.MEGACORPONE.COM
Name Server: NS2.MEGACORPONE.COM
Name Server: NS3.MEGACORPONE.COM
```

* reverse search
* option -h IP address of WHOIS serve

```bash
whois 38.100.193.70 -h 192.168.50.251
...
NetRange:       38.0.0.0 - 38.255.255.255
CIDR:           38.0.0.0/8

```

### Google Hacking

* search for TXT find robots.txt(crawler exclusion)
* search for XML extension to find XML pages
* search for directory listings using in intitle
* -inurl:"heise.de" exclude string search

```plain
site:heise.de filetype:txt
site:heise.de ext:xml
site:heise.de inurl:security
site:heise.de intext:"@heise.de"
site:heise.de intitle:"index of"
index of: "parent directory"
```

URLs:

<https://www.exploit-db.com/google-hacking-database>
<https://dorksearch.com/>

| ![Google Hacking Operators](/img/google-hacking.png) |
| :---: |
| *Google Hacking Operators* |

### Netcraft

* netcraft online enumeration of public targets
* offers an extensive site report including client side technologies and SSL security
* see DNS search `https://searchdns.netcraft.com/`
* see sitereport `https://sitereport.netcraft.com/?url=https://ssl.netcraft.com`

### Open Source Information

* GitHub / Ghist / GitLab / SourceForge
* Search for usernames and crendentials leaks
* Search if leaked private keys are used in the public
* GitHub makes the users public key
* `https://github.com/streaak/keyhacks`
* `https://github.com/trufflesecurity/driftwood`
* `https://github.com/trufflesecurity/trufflehog`
* `https://github.com/gitleaks/gitleaks` (search git log/diff)
* `https://github.com/michenriksen/gitrob` (public GitHub only)

*ATTENTION:* Git Repos make public SSH and GPG keys available to the public for transparency reasons

GitHub
<https://github.com/username.keys>
<https://gitlab.com/username.gpg>

GitLab:
<https://gitlab.com/username.keys>
<https://gitlab.com/username.gpg>

### More on Passive Enumeration

Shodan

`https://shodan.io` to find device that expose valuable information
`https://www.shodan.io/host/193.99.144.80` works without login
`https://www.shodan.io/search?query=hostname%3A+heise.de` search filter requires login

* shows vulnerabilities
* shows web technologies

`https://securityheaders.com/` to check HTTP security header configuration
`https://www.ssllabs.com/` to check TLS security

## Active

### DNS

Record types

* NS Nameserver
* A IPv4
* AAAA IPv6
* MX Mailserver Exchange
* TXT Arbitrary description
* PTR Pointer records used in revers lookup
* CNAME Canonical Names used to create alias

Lookup types

* Forward Lookup = search IP by Domain
* Reverse Lookup = search Domain by IP (requires PTR entries)

Host Lookup lists

```bash
# install /usr/share/seclists
sudo apt -y install seclists` 
# 1.2GB!
git clone https://github.com/danielmiessler/SecLists.git` 
```

Kali Linux DNS enumeration

* DNS Recon `https:/github.com/darkoperator/dnsrecon`
* DNS Enum `https://github.com/SparrowOchon/dnsenum2`

```bash
# default
dnsrecon -d heise.de -t std
# brute-force with a hostname list
dnsrecon -d heise.de -D hostname.txt -t brt
# more information
dnsenum heise.de
```

Linux

```bash
host heise.de
# IP Address
host -t mx heise.de
# Mail Servers
# Lowest Priority first
# heise.de mail is handled by 10 relay.heise.de.
host -t txt heise.de
# heise.de descriptive text "apple-domain-verification=m53iQZB4O1uMxDGR"
host invalid.heise.de
# Host invalid.heise.de not found: 3(NXDOMAIN)

# Allows to automate valid hostnames lookup using oneliner 
for ip in $(cat hostnames.txt); do host $ip.heise.de; done
for ip in $(seq 85 100); do host 193.99.144.$ip; done
```

Windows

Connect to Windows `xfreerdp /u:username /p:password /v:IP`

```powershell
nslookup /help
nslookup [-opt ...] host # just look up 'host' using default
nslookup [-opt ...] host server # just look up 'host' using 'server'
```

```powershell
nslookup exchange.heise.de
nslookup -type=MX heise.de
nslookup -type=TXT heise.de

# Allows to automate valid hostnames lookup using oneliner 
Get-Content .\hostnames.txt | ForEach-Object { nslookup "$_.heise.de" 2> $null | Select-String "Name:" 
85..100 | ForEach-Object { nslookup "193.99.144.$_" } 
85..100 | ForEach-Object -Parallel { nslookup "193.99.144.$_" } -ThrottleLimit 4
```

### TCP / UDP

* use netcat a basic scanner
* -z zero I/O mode (scanning)
* -w timeout in 1 second(s)
* -v verbose level 2
* -n numeric IPs only
* -u UDP scanning

```bash
# TCP
nc -nv -z -w 1 192.168.1.2 7-80
(UNKNOWN) [192.168.1.2] 53 (domain) open
# UDP
nc -nv -u -z -w 1 192.168.1.3 120-123
(UNKNOWN) [192.168.1.3] 123 (ntp) open
```

Remember: UDP scans are usefull, but sometimes unreliable. The reason is that Firewall or Router often suppress/drop `ICMP port unreachable` packet. This may result in open port report, when they are filtered.

### Nmap Scan

* -sT TCP Connect - no data (default TCP)
* -sS TCP SynScan - no handshake (sudo)
* -sU UDP RawScan - raw socket (sudo)
* -sV ServiceScan

```bash
#TCP Connect
nmap -sT 192.168.1.2
#TCP SynScan 
sudo nmap -sS 192.168.1.2
#UDP RawScan 
sudo nmap -sU 192.168.1.2
```

Network ping sweeping

* -sn Ping Sweeping on multiple hosts
* -oG Grepable output
* -p Scan specific ports
* -O OS Fingerprinting only
* -A OS Fingerprinting, script scan and tracerout (all)
* --top-ports= Most use ports scan `cat /usr/share/nmap/nmap-services`
* --osscan-guessing forces nmap to print all os guessing results (no accurate)

```bash
#Ping sweeping 
nmap -v -sn 192.168.1.2-253 -oG ping-sweep.txt
grep 'Up' ping-sweep.txt | cut -d " " -f 2
#HTTP sweeping on specific ports
nmap -p 80,443 192.168.1.2-253 -oG web-sweep.txt
grep 'open' web-sweep.txt | cut -d" " -f2
#TOP20 port sweeping with OS and traceroute
nmap -sT -A --top-ports=20 192.168.1.2-253 -oG port-sweep.txt
grep 'open' port-sweep.txt | cut -d" " -f2
```

Ping Host Discovery

* -PE Echo Ping
* -PP ICMP Ping
* -PS SYN Ping
* -PA ACK Ping
* -PU UDP Ping
* -PO Protocol Ping
* -PY SCTP INIT Ping

```bash
# default
nmap -PE -PS443 -PA80 -PP 192.168.1.2-253
# example
nmap -PE -PU120,121 192.168.1.2-253
```

### Nmap Scripting Engine (NSE)

* allows script user defined scans
* lookup existing scripts `ll /usr/share/nmap/scripts`

```bash
# run default scripts
nmap -sV -sC 192.168.1.2
# Prove HTTP title
nmap --script http-title 192.168.1.2
# Probe HTTP headers
nmap --script http-headers 192.168.1.2
nmap --script-help http-headers
```

### PS Port-Scan (Windows)

```powershell
#TCP Scan 
Test-NetConnection -Port 80 192.168.1.2
#TCP Scan using ForEach-Object loop
1..1024 | % { echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.1.2", $_)) "TCP port $_ is open" } 2> $null
```
