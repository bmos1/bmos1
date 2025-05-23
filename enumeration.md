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

### Google Dorks Hacking

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

### NC Port Sweeping TCP / UDP

* use netcat as basic scanner
* -z zero I/O mode (scanning)
* -w timeout in 1 second(s)
* -v verbose level 2
* -n numeric IPs only
* -u UDP scanning

```bash
# TCP
nc -nvv -z -w 1 192.168.1.2 7-80
(UNKNOWN) [192.168.1.2] 53 (domain) open
# UDP
nc -nvv -u -z -w 1 192.168.1.3 120-123
(UNKNOWN) [192.168.1.3] 123 (ntp) open

# Automate Port Sweeping
for i in $(seq 1 254); do nc -zv -w 1 172.16.187.$i 445; done

nc: connect to 172.16.187.216 port 445 (tcp) timed out: Operation now in progress
Connection to 172.16.187.217 445 port [tcp/microsoft-ds] succeeded!
```

Remember: UDP scans are usefull, but sometimes unreliable. The reason is that Firewall or Router often suppress/drop `ICMP port unreachable` packet. This may result in open port report, when they are filtered.

### Nmap Scan

* -sT TCP Connect - no data (default TCP)
* -sS TCP SynScan - no handshake (sudo)
* -sU UDP RawScan - raw socket (sudo)
* -sV ServiceScan
* -A OS Fingerprinting, script scan and tracerout (all)
* -O OS Fingerprinting only
* --osscan-guessing forces nmap to print all os guessing results (no accurate)

```bash
#TCP Connect
nmap -sT 192.168.1.2
#TCP SynScan 
sudo nmap -sS 192.168.1.2
#UDP RawScan 
sudo nmap -sU 192.168.1.2
#OSS guessing
nmap -O 192.168.1.2 --osscan-guessing
#Service scanning
nmap -sV -sT -A 192.168.1.2
```

Network ping sweeping

* -sn Ping Sweeping on multiple hosts
* -oG Grepable output
* -p Scan specific ports
* --top-ports= Most use ports scan `cat /usr/share/nmap/nmap-services`

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
Test-NetConnection 192.168.1.2 -Port 80
#TCP Scan using ForEach loop
foreach($port in 1..2024) { If (($a=Test-NetConnection 192.168.1.2 -Port $port -WarningAction SilentlyContinue).tcpTestSucceeded -eq $true){ "TCP port $port is open"}} 
#TCP Scan using ForEach-Object loop
1..1024 | % { echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.1.2", $_)) "TCP port $_ is open" } 2> $null
```

### SMB Enum

* UDP 137 NetBios (-r option)
* TCP 139 Netbios
* TCP 445 SMB

```bash
#NBT SMB enumeration using UDP 137
sudo nbtscan -r 192.168.50.0/24

#NMAP SMB enumeration
nmap -v -p 139,445 -oG smb.txt 192.168.1.2-254
grep "open" smb.txt | cut -d" " -f2 > hosts.txt
```

Enum 4 Linux

```bash
#ENUM SMB local users
for ip in $(cat hosts.txt); do enum4linux -r $ip; done

#ENUM SMV all
enum4linux -a 192.168.1.2
```

SMB 1.0 (legacy)

Use nmap script `smb-os-discovery` to list domain, forest, computers and NetBIOS name.

```bash
SMB 1.0 (legacy)
nmap -v -p 139,445 --script smb-os-discovery 192.168.1.2
```

### SMB Scan (Windows)

Use `net view` to list resources, computers and domains.

```powershell
# \\dc domain controller
# /all lists administrative share ($)
net view \\dc /all
```

### SMTP Scan

* Command Reference `https://www.samlogic.net/articles/smtp-commands-reference.htm`
* Auth Mechanism `https://www.samlogic.net/articles/smtp-commands-reference-auth.htm`
* EHLO or HELO
* AUTH LOGIN
* VRFY check if email address exists
* EXPN list mailbox users
* 2XX OK
* 5XX Error

```bash
nc -nv 192.168.1.2 25
VRFY Smith
250 Fred Smith <Smith@USC-ISIF.ARPA>
EXPN maillinglist
250 Fred Smith <Smith@USC-ISIF.ARPA>
^C
```

Non-interactive Probing for Users

```bash
echo "VRFY root \r\n QUIT"  | nc 192.168.192.8 25
220 mail ESMTP Postfix (Ubuntu)
252 2.0.0 root
221 2.0.0 Bye

echo "VRFY invaliduser \r\n QUIT"  | nc 192.168.1.2 25
220 mail ESMTP Postfix (Ubuntu)
550 5.1.1 <invaliduser>: Recipient address rejected: User unknown in local recipient table
221 2.0.0 Bye
echo "VRFY notexists \r\n QUIT"  | nc 192.168.1.2 25

```

### SMTP Scan (Windows)

Use `telnet` to interact with SMPT on Port 25.

* Install `dism /online /Enable-Feature /FeatureName:TelnetClient`
* Location `c:\windows\system32\telnet.exe`

```powershell
Test-NetConnection 192.168.1.2 -Port 25
telnet 192.168.1.2 25
VRFY username 
EXPN maillinglist 
^C
```

### SNMP Scan

* Use `nmap` to filter for open SNMP ports only

```bash
sudo nmap -sU -p 161 192.168.50.1-254 -oG snmp.txt
grep "open" snmp.txt | cut -d" " -f2 > hosts.txt
for ip in $(seq 1 254); do echo 192.168.1.$ip; done > hosts.txt
```

* Use `onesixtyone` for brute-force community strings
* -c list of community string (e.g. public, private, managed)
* -i list of IPs

```bash
echo "public" > community.txt
echo "private" >> community.txt
onesixtyone -c community.txt -i hosts.txt
```

* Use `snmpwalk` to query information
* -c community string (e.g. public, private, managed)
* -t 10 seconds timeout
* -Oa Output Ascii
* -v1 Version

```bash
snmpwalk -c public -v1 -Oa -t 10 192.168.1.2
# Enum user account
snmpwalk -c public -v2c 192.168.1.2 1.3.6.1.4.1.77.1.2.25
# Enum installed software 
snmpwalk -c public -v2c 192.168.1.2 1.3.6.1.2.1.25.6.3.1.2
# Enum running processes
snmpwalk -c public -v2c 192.168.1.2 1.3.6.1.2.1.25.4.2.1.2
# Enum listening TCP ports
snmpwalk -c public -v2c 192.168.1.2 1.3.6.1.2.1.6.13.1.3
```

 Management Information Base(MIB) Tables

| OID Values | Windows System Information |
| :---: | :-------: |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts      |
| 1.3.6.1.2.1.25.6.3.1.2 | Installed Software |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs   |
| 1.3.6.1.2.1.25.1.6.0   | System Processes   |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path     |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units      |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports    |
